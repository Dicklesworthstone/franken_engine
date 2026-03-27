//! Batched zero-copy hostcall transport with credit-based flow control,
//! backpressure, and authenticated sequencing.
//!
//! This module builds on [`hostcall_session_protocol`] (formal protocol
//! definitions) and [`session_hostcall_channel`] (runtime channel) to
//! provide batch-level atomicity, shared-memory region descriptors for
//! zero-copy payload transport, and a credit pool governing send/receive
//! throughput.
//!
//! The safety membrane validates every envelope against the session protocol
//! state before dispatch: checking phase legality, anti-replay, epoch
//! validity, and degraded-mode policy.
//!
//! Plan references: Section 6.5 (RGC-505B).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::hostcall_session_protocol::{
    DegradedOperationKind, ProtocolError, SessionPhaseTag, SessionProtocolState,
};
use crate::security_epoch::SecurityEpoch;
use crate::session_hostcall_channel::BackpressureSignal;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the batched transport layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchTransportConfig {
    /// Maximum envelopes in a single batch.
    pub max_batch_size: usize,
    /// Maximum total payload bytes across all envelopes in a batch.
    pub max_batch_payload_bytes: u64,
    /// Initial credits granted to a sender on establishment.
    pub initial_credits: u64,
    /// Maximum credits that can accumulate.
    pub max_credits: u64,
    /// Maximum simultaneously active shared memory regions.
    pub max_active_regions: usize,
    /// Maximum size in bytes of a single shared memory region.
    pub max_region_size_bytes: u64,
    /// Whether to require MAC authentication on every entry.
    pub require_per_entry_mac: bool,
    /// Whether to compute a batch-level MAC over all entries.
    pub compute_batch_mac: bool,
    /// Tick timeout for batch assembly before forced flush.
    pub batch_assembly_timeout_ticks: u64,
}

impl Default for BatchTransportConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 64,
            max_batch_payload_bytes: 4_194_304, // 4 MiB
            initial_credits: 256,
            max_credits: 1024,
            max_active_regions: 16,
            max_region_size_bytes: 1_048_576, // 1 MiB
            require_per_entry_mac: false,
            compute_batch_mac: true,
            batch_assembly_timeout_ticks: 500,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared memory region
// ---------------------------------------------------------------------------

/// Lifecycle state of a shared memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionState {
    Allocated,
    Writing,
    Sealed,
    Released,
    Revoked,
}

impl RegionState {
    pub const ALL: &'static [RegionState] = &[
        RegionState::Allocated,
        RegionState::Writing,
        RegionState::Sealed,
        RegionState::Released,
        RegionState::Revoked,
    ];
}

impl fmt::Display for RegionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Allocated => "allocated",
            Self::Writing => "writing",
            Self::Sealed => "sealed",
            Self::Released => "released",
            Self::Revoked => "revoked",
        };
        f.write_str(s)
    }
}

/// Descriptor for a zero-copy shared memory region.
///
/// This is a logical descriptor — the engine tracks region lifecycle
/// deterministically without any `unsafe` code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedMemoryRegion {
    pub region_id: u64,
    pub session_id: String,
    pub capacity_bytes: u64,
    pub occupied_bytes: u64,
    pub state: RegionState,
    pub content_hash: Option<ContentHash>,
    pub allocated_at_tick: u64,
    pub sealed_at_tick: Option<u64>,
}

// ---------------------------------------------------------------------------
// Credit pool
// ---------------------------------------------------------------------------

/// Credit-based flow control pool.
///
/// The sender must hold credits to send envelopes. The receiver grants
/// credits back after processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreditPool {
    session_id: String,
    available: u64,
    max_credits: u64,
    total_granted: u64,
    total_consumed: u64,
    total_returned: u64,
    total_revoked: u64,
    high_water_mark: u64,
}

impl CreditPool {
    pub fn new(session_id: String, initial_credits: u64, max_credits: u64) -> Self {
        let available = initial_credits.min(max_credits);
        Self {
            session_id,
            available,
            max_credits,
            total_granted: initial_credits,
            total_consumed: 0,
            total_returned: 0,
            total_revoked: 0,
            high_water_mark: available,
        }
    }

    /// Attempt to consume credits. Fails if insufficient.
    pub fn try_consume(&mut self, amount: u64) -> Result<(), BatchTransportError> {
        if amount > self.available {
            return Err(BatchTransportError::InsufficientCredits {
                requested: amount,
                available: self.available,
            });
        }
        self.available = self.available.saturating_sub(amount);
        self.total_consumed = self.total_consumed.saturating_add(amount);
        Ok(())
    }

    /// Grant credits back, capped at max_credits.
    pub fn grant(&mut self, amount: u64) {
        let new_available = self.available.saturating_add(amount);
        self.available = new_available.min(self.max_credits);
        self.total_returned = self.total_returned.saturating_add(amount);
        if self.available > self.high_water_mark {
            self.high_water_mark = self.available;
        }
    }

    /// Revoke credits (e.g., on region revocation).
    pub fn revoke(&mut self, amount: u64) {
        self.available = self.available.saturating_sub(amount);
        self.total_revoked = self.total_revoked.saturating_add(amount);
    }

    pub fn available(&self) -> u64 {
        self.available
    }

    pub fn is_exhausted(&self) -> bool {
        self.available == 0
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn total_consumed(&self) -> u64 {
        self.total_consumed
    }

    pub fn total_returned(&self) -> u64 {
        self.total_returned
    }

    pub fn high_water_mark(&self) -> u64 {
        self.high_water_mark
    }

    pub fn state_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"franken::credit_pool::");
        buf.extend_from_slice(self.session_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.available.to_le_bytes());
        buf.extend_from_slice(&self.total_consumed.to_le_bytes());
        buf.extend_from_slice(&self.total_returned.to_le_bytes());
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// Batch payload / entry / envelope
// ---------------------------------------------------------------------------

/// Payload carried by a batch entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchPayload {
    /// Inline byte payload (copied into the batch).
    Inline(Vec<u8>),
    /// Reference to a sealed shared memory region (zero-copy).
    SharedRegion {
        region_id: u64,
        offset: u64,
        length: u64,
        payload_hash: ContentHash,
    },
    /// Backpressure signal embedded in the batch.
    Backpressure(BackpressureSignal),
}

impl fmt::Display for BatchPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline(data) => write!(f, "inline({} bytes)", data.len()),
            Self::SharedRegion {
                region_id, length, ..
            } => {
                write!(f, "shared(region={region_id}, {length} bytes)")
            }
            Self::Backpressure(sig) => {
                write!(f, "backpressure({}/{})", sig.pending_messages, sig.limit)
            }
        }
    }
}

/// A single entry within a batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchEntry {
    pub sequence: u64,
    pub payload: BatchPayload,
    pub content_hash: ContentHash,
    pub entry_mac: Option<AuthenticityHash>,
    pub trace_id: String,
}

/// A batch of hostcall envelopes processed atomically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchEnvelope {
    pub batch_id: u64,
    pub session_id: String,
    pub entries: Vec<BatchEntry>,
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub credits_consumed: u64,
    pub total_payload_bytes: u64,
    pub batch_mac: AuthenticityHash,
    pub sealed_at_tick: u64,
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Membrane rejection / audit
// ---------------------------------------------------------------------------

/// Reason the safety membrane rejected a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembraneRejectionReason {
    PhaseBlocked,
    EpochMismatch,
    ReplayDetected,
    DegradedBlocked,
    InsufficientCredits,
    BatchSizeExceeded,
    InvalidRegion,
    MacVerificationFailed,
    SequenceGap,
}

impl fmt::Display for MembraneRejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PhaseBlocked => "phase_blocked",
            Self::EpochMismatch => "epoch_mismatch",
            Self::ReplayDetected => "replay_detected",
            Self::DegradedBlocked => "degraded_blocked",
            Self::InsufficientCredits => "insufficient_credits",
            Self::BatchSizeExceeded => "batch_size_exceeded",
            Self::InvalidRegion => "invalid_region",
            Self::MacVerificationFailed => "mac_verification_failed",
            Self::SequenceGap => "sequence_gap",
        };
        f.write_str(s)
    }
}

impl MembraneRejectionReason {
    pub const ALL: &'static [MembraneRejectionReason] = &[
        MembraneRejectionReason::PhaseBlocked,
        MembraneRejectionReason::EpochMismatch,
        MembraneRejectionReason::ReplayDetected,
        MembraneRejectionReason::DegradedBlocked,
        MembraneRejectionReason::InsufficientCredits,
        MembraneRejectionReason::BatchSizeExceeded,
        MembraneRejectionReason::InvalidRegion,
        MembraneRejectionReason::MacVerificationFailed,
        MembraneRejectionReason::SequenceGap,
    ];
}

/// Audit entry for a membrane decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembraneAuditEntry {
    pub batch_id: u64,
    pub accepted: bool,
    pub rejection_reason: Option<MembraneRejectionReason>,
    pub tick: u64,
    pub envelope_count: usize,
}

/// Verdict from membrane validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MembraneVerdict {
    Accept {
        envelope_count: usize,
    },
    Reject {
        reason: MembraneRejectionReason,
        detail: String,
    },
}

impl MembraneVerdict {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accept { .. })
    }
}

// ---------------------------------------------------------------------------
// Safety membrane
// ---------------------------------------------------------------------------

/// Validates batches against the session protocol state before dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyMembrane {
    session_id: String,
    current_epoch: SecurityEpoch,
    total_accepted_batches: u64,
    total_rejected_batches: u64,
    total_accepted_envelopes: u64,
    total_rejected_envelopes: u64,
    rejection_counts: BTreeMap<MembraneRejectionReason, u64>,
    audit_trail: Vec<MembraneAuditEntry>,
    max_audit_entries: usize,
}

impl SafetyMembrane {
    pub fn new(session_id: String, current_epoch: SecurityEpoch, max_audit_entries: usize) -> Self {
        Self {
            session_id,
            current_epoch,
            total_accepted_batches: 0,
            total_rejected_batches: 0,
            total_accepted_envelopes: 0,
            total_rejected_envelopes: 0,
            rejection_counts: BTreeMap::new(),
            audit_trail: Vec::new(),
            max_audit_entries,
        }
    }

    /// Validate a batch against the protocol state.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_batch(
        &mut self,
        batch: &BatchEnvelope,
        protocol_state: &mut SessionProtocolState,
        session_key: &[u8; 32],
        credit_pool: &CreditPool,
        regions: &BTreeMap<u64, SharedMemoryRegion>,
        config: &BatchTransportConfig,
        tick: u64,
    ) -> MembraneVerdict {
        // 1. Phase check
        if !protocol_state.phase.permits_data() {
            return self.record_rejection(
                batch,
                MembraneRejectionReason::PhaseBlocked,
                format!("phase {} does not permit data", protocol_state.phase),
                tick,
            );
        }

        // 2. Epoch check
        if protocol_state.validate_epoch(self.current_epoch).is_err() {
            return self.record_rejection(
                batch,
                MembraneRejectionReason::EpochMismatch,
                "key schedule epoch mismatch".into(),
                tick,
            );
        }

        // 2a. MAC Verification
        let expected_mac = crate::hostcall_batch_transport::compute_batch_mac(
            session_key,
            batch.batch_id,
            &batch.entries,
            batch.epoch,
        );
        if expected_mac != batch.batch_mac {
            return self.record_rejection(
                batch,
                MembraneRejectionReason::MacVerificationFailed,
                "batch MAC mismatch".into(),
                tick,
            );
        }

        // 2b. Replay Protection
        if let Err(e) = protocol_state.check_replay(batch.sequence_start, tick, None) {
            return self.record_rejection(
                batch,
                MembraneRejectionReason::ReplayDetected,
                format!("replay detected: {e}"),
                tick,
            );
        }

        // 3. Batch size check
        if batch.entries.len() > config.max_batch_size {
            return self.record_rejection(
                batch,
                MembraneRejectionReason::BatchSizeExceeded,
                format!("{} > max {}", batch.entries.len(), config.max_batch_size),
                tick,
            );
        }

        // 4. Payload size check
        if batch.total_payload_bytes > config.max_batch_payload_bytes {
            return self.record_rejection(
                batch,
                MembraneRejectionReason::BatchSizeExceeded,
                format!(
                    "{} bytes > max {}",
                    batch.total_payload_bytes, config.max_batch_payload_bytes
                ),
                tick,
            );
        }

        // 5. Sequence contiguity check
        if !batch.entries.is_empty() {
            let mut expected = batch.sequence_start;
            for entry in &batch.entries {
                if entry.sequence != expected {
                    return self.record_rejection(
                        batch,
                        MembraneRejectionReason::SequenceGap,
                        format!("expected seq {expected}, got {}", entry.sequence),
                        tick,
                    );
                }
                expected += 1;
            }
        }

        // 6. Credit check
        if batch.credits_consumed > credit_pool.available() {
            return self.record_rejection(
                batch,
                MembraneRejectionReason::InsufficientCredits,
                format!(
                    "need {}, have {}",
                    batch.credits_consumed,
                    credit_pool.available()
                ),
                tick,
            );
        }

        // 7. Degraded-mode check
        if protocol_state.phase == SessionPhaseTag::DegradedOpen
            && protocol_state
                .check_operation(DegradedOperationKind::WriteHostcall, tick)
                .is_err()
        {
            return self.record_rejection(
                batch,
                MembraneRejectionReason::DegradedBlocked,
                "write operation blocked in degraded mode".into(),
                tick,
            );
        }

        // 8. Region validation for shared-region payloads
        for entry in &batch.entries {
            if let BatchPayload::SharedRegion {
                region_id,
                offset,
                length,
                ..
            } = &entry.payload
            {
                match regions.get(region_id) {
                    None => {
                        return self.record_rejection(
                            batch,
                            MembraneRejectionReason::InvalidRegion,
                            format!("region {region_id} not found"),
                            tick,
                        );
                    }
                    Some(region) if region.state != RegionState::Sealed => {
                        return self.record_rejection(
                            batch,
                            MembraneRejectionReason::InvalidRegion,
                            format!("region {region_id} is {}, not sealed", region.state),
                            tick,
                        );
                    }
                    Some(region) => {
                        // Validate that offset + length does not exceed
                        // the region's occupied bytes (bounds check).
                        let end = offset.saturating_add(*length);
                        if end > region.occupied_bytes {
                            return self.record_rejection(
                                batch,
                                MembraneRejectionReason::InvalidRegion,
                                format!(
                                    "region {region_id} access out of bounds: \
                                     offset({offset})+length({length})={end} > \
                                     occupied({})",
                                    region.occupied_bytes
                                ),
                                tick,
                            );
                        }
                    }
                }
            }
        }

        // All checks passed.
        self.record_accept(batch, tick)
    }

    pub fn update_epoch(&mut self, epoch: SecurityEpoch) {
        self.current_epoch = epoch;
    }

    pub fn total_accepted_batches(&self) -> u64 {
        self.total_accepted_batches
    }

    pub fn total_rejected_batches(&self) -> u64 {
        self.total_rejected_batches
    }

    pub fn total_accepted_envelopes(&self) -> u64 {
        self.total_accepted_envelopes
    }

    pub fn rejection_count(&self, reason: MembraneRejectionReason) -> u64 {
        self.rejection_counts.get(&reason).copied().unwrap_or(0)
    }

    pub fn audit_trail(&self) -> &[MembraneAuditEntry] {
        &self.audit_trail
    }

    fn record_rejection(
        &mut self,
        batch: &BatchEnvelope,
        reason: MembraneRejectionReason,
        detail: String,
        tick: u64,
    ) -> MembraneVerdict {
        self.total_rejected_batches += 1;
        self.total_rejected_envelopes += batch.entries.len() as u64;
        *self.rejection_counts.entry(reason).or_insert(0) += 1;
        self.push_audit(
            batch.batch_id,
            false,
            Some(reason),
            tick,
            batch.entries.len(),
        );
        MembraneVerdict::Reject { reason, detail }
    }

    fn record_accept(&mut self, batch: &BatchEnvelope, tick: u64) -> MembraneVerdict {
        let count = batch.entries.len();
        self.total_accepted_batches += 1;
        self.total_accepted_envelopes += count as u64;
        self.push_audit(batch.batch_id, true, None, tick, count);
        MembraneVerdict::Accept {
            envelope_count: count,
        }
    }

    fn push_audit(
        &mut self,
        batch_id: u64,
        accepted: bool,
        rejection_reason: Option<MembraneRejectionReason>,
        tick: u64,
        envelope_count: usize,
    ) {
        self.audit_trail.push(MembraneAuditEntry {
            batch_id,
            accepted,
            rejection_reason,
            tick,
            envelope_count,
        });
        if self.audit_trail.len() > self.max_audit_entries {
            self.audit_trail.remove(0);
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from batch transport operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchTransportError {
    BatchTooLarge {
        size: usize,
        max: usize,
    },
    PayloadTooLarge {
        bytes: u64,
        max: u64,
    },
    InsufficientCredits {
        requested: u64,
        available: u64,
    },
    TooManyRegions {
        active: usize,
        max: usize,
    },
    RegionNotFound {
        region_id: u64,
    },
    InvalidRegionState {
        region_id: u64,
        expected: RegionState,
        actual: RegionState,
    },
    RegionCapacityExceeded {
        region_id: u64,
        capacity: u64,
        requested: u64,
    },
    NonContiguousSequences {
        expected: u64,
        actual: u64,
    },
    EmptyBatch,
    BatchMacMismatch {
        batch_id: u64,
    },
    Protocol(ProtocolError),
    MembraneRejection {
        reason: MembraneRejectionReason,
        detail: String,
    },
}

impl fmt::Display for BatchTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BatchTooLarge { size, max } => write!(f, "batch too large: {size} > {max}"),
            Self::PayloadTooLarge { bytes, max } => write!(f, "payload too large: {bytes} > {max}"),
            Self::InsufficientCredits {
                requested,
                available,
            } => {
                write!(
                    f,
                    "insufficient credits: need {requested}, have {available}"
                )
            }
            Self::TooManyRegions { active, max } => {
                write!(f, "too many active regions: {active} >= {max}")
            }
            Self::RegionNotFound { region_id } => write!(f, "region {region_id} not found"),
            Self::InvalidRegionState {
                region_id,
                expected,
                actual,
            } => {
                write!(f, "region {region_id}: expected {expected}, got {actual}")
            }
            Self::RegionCapacityExceeded {
                region_id,
                capacity,
                requested,
            } => {
                write!(
                    f,
                    "region {region_id}: capacity {capacity}, requested {requested}"
                )
            }
            Self::NonContiguousSequences { expected, actual } => {
                write!(
                    f,
                    "non-contiguous sequences: expected {expected}, got {actual}"
                )
            }
            Self::EmptyBatch => write!(f, "empty batch"),
            Self::BatchMacMismatch { batch_id } => {
                write!(f, "batch MAC mismatch for batch {batch_id}")
            }
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::MembraneRejection { reason, detail } => {
                write!(f, "membrane rejection ({reason}): {detail}")
            }
        }
    }
}

impl std::error::Error for BatchTransportError {}

impl From<ProtocolError> for BatchTransportError {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

// ---------------------------------------------------------------------------
// Batch receipt
// ---------------------------------------------------------------------------

/// Receipt generated for each accepted batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchReceipt {
    pub batch_id: u64,
    pub session_id: String,
    pub sequence_start: u64,
    pub sequence_end: u64,
    pub envelope_count: usize,
    pub credits_consumed: u64,
    pub batch_content_hash: ContentHash,
    pub accepted_at_tick: u64,
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

/// Compute the content hash for a batch entry.
pub fn compute_entry_content_hash(
    sequence: u64,
    payload: &BatchPayload,
    trace_id: &str,
) -> ContentHash {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"franken::batch_transport::entry::");
    buf.extend_from_slice(&sequence.to_le_bytes());
    match payload {
        BatchPayload::Inline(data) => {
            buf.push(1);
            buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
            buf.extend_from_slice(data);
        }
        BatchPayload::SharedRegion {
            region_id,
            offset,
            length,
            payload_hash,
        } => {
            buf.push(2);
            buf.extend_from_slice(&region_id.to_le_bytes());
            buf.extend_from_slice(&offset.to_le_bytes());
            buf.extend_from_slice(&length.to_le_bytes());
            buf.extend_from_slice(payload_hash.as_bytes());
        }
        BatchPayload::Backpressure(sig) => {
            buf.push(3);
            buf.extend_from_slice(&(sig.pending_messages as u64).to_le_bytes());
            buf.extend_from_slice(&(sig.limit as u64).to_le_bytes());
        }
    }
    buf.extend_from_slice(trace_id.as_bytes());
    ContentHash::compute(&buf)
}

/// Compute the batch-level MAC over all entries.
pub fn compute_batch_mac(
    session_key: &[u8; 32],
    batch_id: u64,
    entries: &[BatchEntry],
    epoch: SecurityEpoch,
) -> AuthenticityHash {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"franken::batch_transport::batch_mac::");
    buf.extend_from_slice(&batch_id.to_le_bytes());
    buf.extend_from_slice(&epoch.as_u64().to_le_bytes());
    for entry in entries {
        buf.extend_from_slice(&entry.sequence.to_le_bytes());
        buf.extend_from_slice(entry.content_hash.as_bytes());
    }
    AuthenticityHash::compute_keyed(session_key, &buf)
}

// ---------------------------------------------------------------------------
// Batch transport state
// ---------------------------------------------------------------------------

/// The combined state machine for batched hostcall transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTransportState {
    pub session_id: String,
    pub config: BatchTransportConfig,
    pub credit_pool: CreditPool,
    pub regions: BTreeMap<u64, SharedMemoryRegion>,
    pub next_region_id: u64,
    pub next_batch_id: u64,
    pub membrane: SafetyMembrane,
    pub accepted_batches: Vec<BatchReceipt>,
    pub total_shared_bytes: u64,
    pub total_inline_bytes: u64,
    pub total_envelopes: u64,
}

impl BatchTransportState {
    pub fn new(session_id: String, config: BatchTransportConfig, epoch: SecurityEpoch) -> Self {
        let credit_pool = CreditPool::new(
            session_id.clone(),
            config.initial_credits,
            config.max_credits,
        );
        let membrane = SafetyMembrane::new(session_id.clone(), epoch, 100);
        Self {
            session_id,
            config,
            credit_pool,
            regions: BTreeMap::new(),
            next_region_id: 1,
            next_batch_id: 1,
            membrane,
            accepted_batches: Vec::new(),
            total_shared_bytes: 0,
            total_inline_bytes: 0,
            total_envelopes: 0,
        }
    }

    /// Allocate a new shared memory region. Returns the region ID.
    pub fn allocate_region(
        &mut self,
        capacity_bytes: u64,
        tick: u64,
    ) -> Result<u64, BatchTransportError> {
        let active_count = self
            .regions
            .values()
            .filter(|r| {
                matches!(
                    r.state,
                    RegionState::Allocated | RegionState::Writing | RegionState::Sealed
                )
            })
            .count();
        if active_count >= self.config.max_active_regions {
            return Err(BatchTransportError::TooManyRegions {
                active: active_count,
                max: self.config.max_active_regions,
            });
        }
        if capacity_bytes > self.config.max_region_size_bytes {
            return Err(BatchTransportError::RegionCapacityExceeded {
                region_id: self.next_region_id,
                capacity: self.config.max_region_size_bytes,
                requested: capacity_bytes,
            });
        }
        let region_id = self.next_region_id;
        self.next_region_id = self.next_region_id.saturating_add(1);
        let region = SharedMemoryRegion {
            region_id,
            session_id: self.session_id.clone(),
            capacity_bytes,
            occupied_bytes: 0,
            state: RegionState::Allocated,
            content_hash: None,
            allocated_at_tick: tick,
            sealed_at_tick: None,
        };
        self.regions.insert(region_id, region);
        Ok(region_id)
    }

    /// Seal a region with its payload content hash.
    pub fn seal_region(
        &mut self,
        region_id: u64,
        payload_bytes: u64,
        tick: u64,
    ) -> Result<ContentHash, BatchTransportError> {
        let region = self
            .regions
            .get_mut(&region_id)
            .ok_or(BatchTransportError::RegionNotFound { region_id })?;
        if region.state != RegionState::Allocated && region.state != RegionState::Writing {
            return Err(BatchTransportError::InvalidRegionState {
                region_id,
                expected: RegionState::Allocated,
                actual: region.state,
            });
        }
        if payload_bytes > region.capacity_bytes {
            return Err(BatchTransportError::RegionCapacityExceeded {
                region_id,
                capacity: region.capacity_bytes,
                requested: payload_bytes,
            });
        }
        let hash = ContentHash::compute(&payload_bytes.to_le_bytes());
        region.occupied_bytes = payload_bytes;
        region.state = RegionState::Sealed;
        region.content_hash = Some(hash);
        region.sealed_at_tick = Some(tick);
        self.total_shared_bytes = self.total_shared_bytes.saturating_add(payload_bytes);
        Ok(hash)
    }

    /// Release a sealed region.
    pub fn release_region(&mut self, region_id: u64) -> Result<(), BatchTransportError> {
        let region = self
            .regions
            .get_mut(&region_id)
            .ok_or(BatchTransportError::RegionNotFound { region_id })?;
        if region.state != RegionState::Sealed {
            return Err(BatchTransportError::InvalidRegionState {
                region_id,
                expected: RegionState::Sealed,
                actual: region.state,
            });
        }
        region.state = RegionState::Released;
        Ok(())
    }

    /// Revoke a region (error or timeout).
    pub fn revoke_region(&mut self, region_id: u64) -> Result<(), BatchTransportError> {
        let region = self
            .regions
            .get_mut(&region_id)
            .ok_or(BatchTransportError::RegionNotFound { region_id })?;
        region.state = RegionState::Revoked;
        Ok(())
    }

    /// Build a batch from entries, computing MAC and assigning batch_id.
    pub fn build_batch(
        &mut self,
        entries: Vec<BatchEntry>,
        session_key: &[u8; 32],
        epoch: SecurityEpoch,
        tick: u64,
    ) -> Result<BatchEnvelope, BatchTransportError> {
        if entries.is_empty() {
            return Err(BatchTransportError::EmptyBatch);
        }
        if entries.len() > self.config.max_batch_size {
            return Err(BatchTransportError::BatchTooLarge {
                size: entries.len(),
                max: self.config.max_batch_size,
            });
        }

        let sequence_start = entries[0].sequence;
        let sequence_end = entries[entries.len() - 1].sequence;

        // Verify contiguity.
        for (i, entry) in entries.iter().enumerate() {
            let expected = sequence_start + i as u64;
            if entry.sequence != expected {
                return Err(BatchTransportError::NonContiguousSequences {
                    expected,
                    actual: entry.sequence,
                });
            }
        }

        let mut total_payload_bytes: u64 = 0;
        for entry in &entries {
            match &entry.payload {
                BatchPayload::Inline(data) => {
                    total_payload_bytes = total_payload_bytes.saturating_add(data.len() as u64);
                }
                BatchPayload::SharedRegion { length, .. } => {
                    total_payload_bytes = total_payload_bytes.saturating_add(*length);
                }
                BatchPayload::Backpressure(_) => {}
            }
        }

        if total_payload_bytes > self.config.max_batch_payload_bytes {
            return Err(BatchTransportError::PayloadTooLarge {
                bytes: total_payload_bytes,
                max: self.config.max_batch_payload_bytes,
            });
        }

        let batch_id = self.next_batch_id;
        self.next_batch_id = self.next_batch_id.saturating_add(1);

        let batch_mac = compute_batch_mac(session_key, batch_id, &entries, epoch);
        let credits_consumed = entries.len() as u64;

        Ok(BatchEnvelope {
            batch_id,
            session_id: self.session_id.clone(),
            entries,
            sequence_start,
            sequence_end,
            credits_consumed,
            total_payload_bytes,
            batch_mac,
            sealed_at_tick: tick,
            epoch,
        })
    }

    /// Submit a batch: validate via membrane, consume credits, record receipt.
    pub fn submit_batch(
        &mut self,
        batch: BatchEnvelope,
        protocol_state: &mut SessionProtocolState,
        session_key: &[u8; 32],
        tick: u64,
    ) -> Result<BatchReceipt, BatchTransportError> {
        // Pre-validate credits to prevent state corruption on failure
        if self.credit_pool.available() < batch.credits_consumed {
            return Err(BatchTransportError::InsufficientCredits {
                requested: batch.credits_consumed,
                available: self.credit_pool.available(),
            });
        }

        // Membrane validation.
        let verdict = self.membrane.validate_batch(
            &batch,
            protocol_state,
            session_key,
            &self.credit_pool,
            &self.regions,
            &self.config,
            tick,
        );

        match verdict {
            MembraneVerdict::Reject { reason, detail } => {
                Err(BatchTransportError::MembraneRejection { reason, detail })
            }
            MembraneVerdict::Accept { envelope_count } => {
                // Consume credits.
                self.credit_pool.try_consume(batch.credits_consumed)?;

                // Tally inline bytes.
                for entry in &batch.entries {
                    if let BatchPayload::Inline(data) = &entry.payload {
                        self.total_inline_bytes =
                            self.total_inline_bytes.saturating_add(data.len() as u64);
                    }
                }

                self.total_envelopes = self.total_envelopes.saturating_add(envelope_count as u64);

                // Build receipt.
                let receipt_hash = {
                    let mut buf = Vec::new();
                    buf.extend_from_slice(b"franken::batch_receipt::");
                    buf.extend_from_slice(&batch.batch_id.to_le_bytes());
                    buf.extend_from_slice(batch.session_id.as_bytes());
                    buf.extend_from_slice(&batch.sequence_start.to_le_bytes());
                    buf.extend_from_slice(&batch.sequence_end.to_le_bytes());
                    buf.extend_from_slice(batch.batch_mac.as_bytes());
                    ContentHash::compute(&buf)
                };

                let receipt = BatchReceipt {
                    batch_id: batch.batch_id,
                    session_id: batch.session_id,
                    sequence_start: batch.sequence_start,
                    sequence_end: batch.sequence_end,
                    envelope_count,
                    credits_consumed: batch.credits_consumed,
                    batch_content_hash: receipt_hash,
                    accepted_at_tick: tick,
                };
                self.accepted_batches.push(receipt.clone());
                Ok(receipt)
            }
        }
    }

    /// Grant credits back to the sender.
    pub fn grant_credits(&mut self, amount: u64) {
        self.credit_pool.grant(amount);
    }

    /// Compute a state hash for checkpointing.
    pub fn state_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"franken::batch_transport_state::");
        buf.extend_from_slice(self.session_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.next_batch_id.to_le_bytes());
        buf.extend_from_slice(&self.next_region_id.to_le_bytes());
        buf.extend_from_slice(&self.total_envelopes.to_le_bytes());
        buf.extend_from_slice(self.credit_pool.state_hash().as_bytes());
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// Corpus / runner / evidence bundle
// ---------------------------------------------------------------------------

/// A specimen from the batch transport corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTransportSpecimen {
    pub name: String,
    pub family: BatchTransportSpecimenFamily,
    pub verdict: BatchTransportVerdict,
    pub content_hash: ContentHash,
}

/// Specimen family discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchTransportSpecimenFamily {
    HappyPath,
    CreditExhaustion,
    BatchSizeLimits,
    SharedRegionLifecycle,
    MembranePhaseRejection,
    MembraneReplayRejection,
    DegradedModeHandling,
    BatchMacVerification,
    SequenceContiguity,
    RegionCapacityEnforcement,
    CreditGrantAndReturn,
    EmptyBatchRejection,
}

impl BatchTransportSpecimenFamily {
    pub const ALL: &'static [BatchTransportSpecimenFamily] = &[
        BatchTransportSpecimenFamily::HappyPath,
        BatchTransportSpecimenFamily::CreditExhaustion,
        BatchTransportSpecimenFamily::BatchSizeLimits,
        BatchTransportSpecimenFamily::SharedRegionLifecycle,
        BatchTransportSpecimenFamily::MembranePhaseRejection,
        BatchTransportSpecimenFamily::MembraneReplayRejection,
        BatchTransportSpecimenFamily::DegradedModeHandling,
        BatchTransportSpecimenFamily::BatchMacVerification,
        BatchTransportSpecimenFamily::SequenceContiguity,
        BatchTransportSpecimenFamily::RegionCapacityEnforcement,
        BatchTransportSpecimenFamily::CreditGrantAndReturn,
        BatchTransportSpecimenFamily::EmptyBatchRejection,
    ];
}

impl fmt::Display for BatchTransportSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::HappyPath => "happy_path",
            Self::CreditExhaustion => "credit_exhaustion",
            Self::BatchSizeLimits => "batch_size_limits",
            Self::SharedRegionLifecycle => "shared_region_lifecycle",
            Self::MembranePhaseRejection => "membrane_phase_rejection",
            Self::MembraneReplayRejection => "membrane_replay_rejection",
            Self::DegradedModeHandling => "degraded_mode_handling",
            Self::BatchMacVerification => "batch_mac_verification",
            Self::SequenceContiguity => "sequence_contiguity",
            Self::RegionCapacityEnforcement => "region_capacity_enforcement",
            Self::CreditGrantAndReturn => "credit_grant_and_return",
            Self::EmptyBatchRejection => "empty_batch_rejection",
        };
        f.write_str(s)
    }
}

/// Verdict for a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchTransportVerdict {
    Pass,
    Fail,
}

impl fmt::Display for BatchTransportVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => f.write_str("pass"),
            Self::Fail => f.write_str("fail"),
        }
    }
}

fn specimen_hash(name: &str, verdict: BatchTransportVerdict) -> ContentHash {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"franken::batch_transport_specimen::");
    buf.extend_from_slice(name.as_bytes());
    buf.push(0);
    buf.push(if matches!(verdict, BatchTransportVerdict::Pass) {
        1
    } else {
        0
    });
    ContentHash::compute(&buf)
}

fn make_established_protocol_state() -> SessionProtocolState {
    use crate::hostcall_session_protocol::TransitionTrigger;
    let mut state = SessionProtocolState::new(
        "corpus-sess".into(),
        "corpus-ext".into(),
        "corpus-host".into(),
        64,
        50,
    );
    state
        .transition(
            SessionPhaseTag::Negotiating,
            TransitionTrigger::HandshakeInitiated,
            1,
        )
        .unwrap();
    state
        .transition(
            SessionPhaseTag::Established,
            TransitionTrigger::HandshakeCompleted,
            2,
        )
        .unwrap();
    state
}

fn make_entry(seq: u64, data: &[u8]) -> BatchEntry {
    let payload = BatchPayload::Inline(data.to_vec());
    let content_hash = compute_entry_content_hash(seq, &payload, "trace");
    BatchEntry {
        sequence: seq,
        payload,
        content_hash,
        entry_mac: None,
        trace_id: "trace".into(),
    }
}

/// Build the batch transport corpus.
pub fn batch_transport_corpus() -> Vec<BatchTransportSpecimen> {
    let session_key: [u8; 32] = [0xAB; 32];
    let epoch = SecurityEpoch::from_raw(1);
    let mut corpus = Vec::new();

    // 1. Happy path
    {
        let config = BatchTransportConfig::default();
        let mut ts = BatchTransportState::new("s1".into(), config, epoch);
        let mut protocol = make_established_protocol_state();
        let entries = vec![make_entry(1, b"hello"), make_entry(2, b"world")];
        let batch = ts.build_batch(entries, &session_key, epoch, 100).unwrap();
        let result = ts.submit_batch(batch, &mut protocol, &session_key, 100);
        let v = if result.is_ok() {
            BatchTransportVerdict::Pass
        } else {
            BatchTransportVerdict::Fail
        };
        corpus.push(BatchTransportSpecimen {
            name: "happy_path".into(),
            family: BatchTransportSpecimenFamily::HappyPath,
            verdict: v,
            content_hash: specimen_hash("happy_path", v),
        });
    }

    // 2. Credit exhaustion
    {
        let config = BatchTransportConfig {
            initial_credits: 1,
            max_credits: 1,
            ..Default::default()
        };
        let mut ts = BatchTransportState::new("s2".into(), config, epoch);
        let mut protocol = make_established_protocol_state();
        let entries = vec![make_entry(1, b"a"), make_entry(2, b"b")];
        let batch = ts.build_batch(entries, &session_key, epoch, 100).unwrap();
        let result = ts.submit_batch(batch, &mut protocol, &[0; 32], 100);
        let v = if result.is_err() {
            BatchTransportVerdict::Pass
        } else {
            BatchTransportVerdict::Fail
        };
        corpus.push(BatchTransportSpecimen {
            name: "credit_exhaustion".into(),
            family: BatchTransportSpecimenFamily::CreditExhaustion,
            verdict: v,
            content_hash: specimen_hash("credit_exhaustion", v),
        });
    }

    // 3. Batch size limits
    {
        let config = BatchTransportConfig {
            max_batch_size: 1,
            ..Default::default()
        };
        let mut ts = BatchTransportState::new("s3".into(), config, epoch);
        let entries = vec![make_entry(1, b"a"), make_entry(2, b"b")];
        let result = ts.build_batch(entries, &session_key, epoch, 100);
        let v = if result.is_err() {
            BatchTransportVerdict::Pass
        } else {
            BatchTransportVerdict::Fail
        };
        corpus.push(BatchTransportSpecimen {
            name: "batch_size_limits".into(),
            family: BatchTransportSpecimenFamily::BatchSizeLimits,
            verdict: v,
            content_hash: specimen_hash("batch_size_limits", v),
        });
    }

    // 4. Shared region lifecycle
    {
        let config = BatchTransportConfig::default();
        let mut ts = BatchTransportState::new("s4".into(), config, epoch);
        let rid = ts.allocate_region(1024, 10).unwrap();
        let hash = ts.seal_region(rid, 100, 20).unwrap();
        ts.release_region(rid).unwrap();
        let region = &ts.regions[&rid];
        let v = if region.state == RegionState::Released
            && region.content_hash.as_ref() == Some(&hash)
        {
            BatchTransportVerdict::Pass
        } else {
            BatchTransportVerdict::Fail
        };
        corpus.push(BatchTransportSpecimen {
            name: "shared_region_lifecycle".into(),
            family: BatchTransportSpecimenFamily::SharedRegionLifecycle,
            verdict: v,
            content_hash: specimen_hash("shared_region_lifecycle", v),
        });
    }

    // 5. Membrane phase rejection
    {
        let config = BatchTransportConfig::default();
        let mut ts = BatchTransportState::new("s5".into(), config, epoch);
        let mut protocol =
            SessionProtocolState::new("s5".into(), "ext".into(), "host".into(), 64, 50); // Uninit phase
        let entries = vec![make_entry(1, b"data")];
        let batch = ts.build_batch(entries, &session_key, epoch, 100).unwrap();
        let result = ts.submit_batch(batch, &mut protocol, &[0; 32], 100);
        let v = if result.is_err() {
            BatchTransportVerdict::Pass
        } else {
            BatchTransportVerdict::Fail
        };
        corpus.push(BatchTransportSpecimen {
            name: "membrane_phase_rejection".into(),
            family: BatchTransportSpecimenFamily::MembranePhaseRejection,
            verdict: v,
            content_hash: specimen_hash("membrane_phase_rejection", v),
        });
    }

    // 6. Membrane replay rejection — tested via duplicate batch
    {
        let config = BatchTransportConfig::default();
        let mut ts = BatchTransportState::new("s6".into(), config, epoch);
        let mut protocol = make_established_protocol_state();
        let entries1 = vec![make_entry(1, b"a")];
        let batch1 = ts.build_batch(entries1, &session_key, epoch, 100).unwrap();
        // Pre-register sequence 1 in protocol replay ledger
        protocol.check_replay(1, 100, None).unwrap();
        let result = ts.submit_batch(batch1, &mut protocol, &session_key, 100);
        // Membrane calls check_replay, which detects the duplicate sequence,
        // so the submit should be rejected with ReplayDetected.
        let v = if result.is_err() {
            BatchTransportVerdict::Pass
        } else {
            BatchTransportVerdict::Fail
        };
        corpus.push(BatchTransportSpecimen {
            name: "membrane_replay_scenario".into(),
            family: BatchTransportSpecimenFamily::MembraneReplayRejection,
            verdict: v,
            content_hash: specimen_hash("membrane_replay_scenario", v),
        });
    }

    // 7. Degraded mode handling
    {
        use crate::hostcall_session_protocol::DegradedSeverity;
        let config = BatchTransportConfig::default();
        let mut ts = BatchTransportState::new("s7".into(), config, epoch);
        let mut protocol = make_established_protocol_state();
        protocol
            .enter_degraded(DegradedSeverity::IdentityCompromised, "bad".into(), 50)
            .unwrap();
        let entries = vec![make_entry(1, b"data")];
        let batch = ts.build_batch(entries, &session_key, epoch, 100).unwrap();
        let result = ts.submit_batch(batch, &mut protocol, &[0; 32], 100);
        let v = if result.is_err() {
            BatchTransportVerdict::Pass
        } else {
            BatchTransportVerdict::Fail
        };
        corpus.push(BatchTransportSpecimen {
            name: "degraded_mode_handling".into(),
            family: BatchTransportSpecimenFamily::DegradedModeHandling,
            verdict: v,
            content_hash: specimen_hash("degraded_mode_handling", v),
        });
    }

    // 8. Batch MAC verification
    {
        let entries = vec![make_entry(1, b"mac-test")];
        let mac1 = compute_batch_mac(&session_key, 1, &entries, epoch);
        let mac2 = compute_batch_mac(&[0xFF; 32], 1, &entries, epoch);
        let v = if mac1 != mac2 {
            BatchTransportVerdict::Pass
        } else {
            BatchTransportVerdict::Fail
        };
        corpus.push(BatchTransportSpecimen {
            name: "batch_mac_verification".into(),
            family: BatchTransportSpecimenFamily::BatchMacVerification,
            verdict: v,
            content_hash: specimen_hash("batch_mac_verification", v),
        });
    }

    // 9. Sequence contiguity
    {
        let config = BatchTransportConfig::default();
        let mut ts = BatchTransportState::new("s9".into(), config, epoch);
        let entries = vec![make_entry(1, b"a"), make_entry(3, b"c")]; // gap at 2
        let result = ts.build_batch(entries, &session_key, epoch, 100);
        let v = if result.is_err() {
            BatchTransportVerdict::Pass
        } else {
            BatchTransportVerdict::Fail
        };
        corpus.push(BatchTransportSpecimen {
            name: "sequence_contiguity".into(),
            family: BatchTransportSpecimenFamily::SequenceContiguity,
            verdict: v,
            content_hash: specimen_hash("sequence_contiguity", v),
        });
    }

    // 10. Region capacity enforcement
    {
        let config = BatchTransportConfig {
            max_region_size_bytes: 100,
            ..Default::default()
        };
        let mut ts = BatchTransportState::new("s10".into(), config, epoch);
        let result = ts.allocate_region(200, 10);
        let v = if result.is_err() {
            BatchTransportVerdict::Pass
        } else {
            BatchTransportVerdict::Fail
        };
        corpus.push(BatchTransportSpecimen {
            name: "region_capacity_enforcement".into(),
            family: BatchTransportSpecimenFamily::RegionCapacityEnforcement,
            verdict: v,
            content_hash: specimen_hash("region_capacity_enforcement", v),
        });
    }

    // 11. Credit grant and return
    {
        let config = BatchTransportConfig {
            initial_credits: 10,
            max_credits: 100,
            ..Default::default()
        };
        let mut ts = BatchTransportState::new("s11".into(), config, epoch);
        let mut protocol = make_established_protocol_state();
        let entries = vec![make_entry(1, b"a"), make_entry(2, b"b")];
        let batch = ts.build_batch(entries, &session_key, epoch, 100).unwrap();
        ts.submit_batch(batch, &mut protocol, &session_key, 100)
            .unwrap();
        let before = ts.credit_pool.available();
        ts.grant_credits(5);
        let after = ts.credit_pool.available();
        let v = if after == before + 5 {
            BatchTransportVerdict::Pass
        } else {
            BatchTransportVerdict::Fail
        };
        corpus.push(BatchTransportSpecimen {
            name: "credit_grant_and_return".into(),
            family: BatchTransportSpecimenFamily::CreditGrantAndReturn,
            verdict: v,
            content_hash: specimen_hash("credit_grant_and_return", v),
        });
    }

    // 12. Empty batch rejection
    {
        let config = BatchTransportConfig::default();
        let mut ts = BatchTransportState::new("s12".into(), config, epoch);
        let result = ts.build_batch(Vec::new(), &session_key, epoch, 100);
        let v = if result.is_err() {
            BatchTransportVerdict::Pass
        } else {
            BatchTransportVerdict::Fail
        };
        corpus.push(BatchTransportSpecimen {
            name: "empty_batch_rejection".into(),
            family: BatchTransportSpecimenFamily::EmptyBatchRejection,
            verdict: v,
            content_hash: specimen_hash("empty_batch_rejection", v),
        });
    }

    corpus
}

/// Runner result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchTransportRunnerResult {
    pub specimen_count: usize,
    pub families_covered: Vec<BatchTransportSpecimenFamily>,
    pub all_pass: bool,
    pub pass_count: usize,
    pub fail_count: usize,
    pub content_hash: ContentHash,
}

/// Run the corpus and produce a runner result.
pub fn run_batch_transport_corpus() -> BatchTransportRunnerResult {
    let corpus = batch_transport_corpus();
    let specimen_count = corpus.len();

    let mut families: std::collections::BTreeSet<BatchTransportSpecimenFamily> =
        std::collections::BTreeSet::new();
    let mut pass_count = 0;
    let mut fail_count = 0;

    let mut hash_buf = Vec::new();
    hash_buf.extend_from_slice(b"franken::batch_transport_runner::");

    for spec in &corpus {
        families.insert(spec.family);
        match spec.verdict {
            BatchTransportVerdict::Pass => pass_count += 1,
            BatchTransportVerdict::Fail => fail_count += 1,
        }
        hash_buf.extend_from_slice(spec.content_hash.as_bytes());
    }

    BatchTransportRunnerResult {
        specimen_count,
        families_covered: families.into_iter().collect(),
        all_pass: fail_count == 0,
        pass_count,
        fail_count,
        content_hash: ContentHash::compute(&hash_buf),
    }
}

/// Write evidence bundle to directory.
pub fn write_batch_transport_evidence_bundle(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;

    let corpus = batch_transport_corpus();
    let result = run_batch_transport_corpus();

    let inventory: Vec<serde_json::Value> = corpus
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.name,
                "family": s.family.to_string(),
                "verdict": s.verdict.to_string(),
                "content_hash": s.content_hash.to_hex(),
            })
        })
        .collect();
    let inv_json = serde_json::to_string_pretty(&inventory).map_err(std::io::Error::other)?;
    std::fs::write(dir.join("batch_transport_inventory.json"), inv_json)?;

    let manifest = serde_json::json!({
        "schema": "batch_transport_evidence_v1",
        "specimen_count": result.specimen_count,
        "families_covered": result.families_covered.iter().map(|f| f.to_string()).collect::<Vec<_>>(),
        "all_pass": result.all_pass,
        "pass_count": result.pass_count,
        "content_hash": result.content_hash.to_hex(),
    });
    let man_json = serde_json::to_string_pretty(&manifest).map_err(std::io::Error::other)?;
    std::fs::write(dir.join("batch_transport_manifest.json"), man_json)?;

    let mut events = String::new();
    for spec in &corpus {
        let line = serde_json::json!({
            "event": "specimen_evaluated",
            "name": spec.name,
            "family": spec.family.to_string(),
            "verdict": spec.verdict.to_string(),
        });
        events.push_str(&serde_json::to_string(&line).map_err(std::io::Error::other)?);
        events.push('\n');
    }
    std::fs::write(dir.join("batch_transport_events.jsonl"), events)?;

    let mut cmds = String::new();
    cmds.push_str("# Batch Transport Evidence Commands\n");
    cmds.push_str("cargo test -p frankenengine-engine hostcall_batch_transport\n");
    cmds.push_str(
        "cargo test -p frankenengine-engine --test hostcall_batch_transport_integration\n",
    );
    std::fs::write(dir.join("batch_transport_commands.txt"), cmds)?;

    Ok(())
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

    fn session_key() -> [u8; 32] {
        [0xAB; 32]
    }

    fn default_state() -> BatchTransportState {
        BatchTransportState::new(
            "test-sess".into(),
            BatchTransportConfig::default(),
            test_epoch(),
        )
    }

    fn established_protocol() -> SessionProtocolState {
        make_established_protocol_state()
    }

    // --- Config tests ---

    #[test]
    fn config_default_values() {
        let c = BatchTransportConfig::default();
        assert_eq!(c.max_batch_size, 64);
        assert_eq!(c.initial_credits, 256);
        assert!(c.compute_batch_mac);
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = BatchTransportConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: BatchTransportConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- CreditPool tests ---

    #[test]
    fn credit_pool_initial_credits() {
        let pool = CreditPool::new("s".into(), 100, 200);
        assert_eq!(pool.available(), 100);
        assert!(!pool.is_exhausted());
    }

    #[test]
    fn credit_pool_consume_success() {
        let mut pool = CreditPool::new("s".into(), 100, 200);
        pool.try_consume(50).unwrap();
        assert_eq!(pool.available(), 50);
        assert_eq!(pool.total_consumed(), 50);
    }

    #[test]
    fn credit_pool_consume_insufficient() {
        let mut pool = CreditPool::new("s".into(), 10, 200);
        let err = pool.try_consume(20);
        assert!(err.is_err());
        assert_eq!(pool.available(), 10);
    }

    #[test]
    fn credit_pool_grant_caps_at_max() {
        let mut pool = CreditPool::new("s".into(), 10, 20);
        pool.grant(50);
        assert_eq!(pool.available(), 20);
    }

    #[test]
    fn credit_pool_revoke() {
        let mut pool = CreditPool::new("s".into(), 100, 200);
        pool.revoke(30);
        assert_eq!(pool.available(), 70);
    }

    #[test]
    fn credit_pool_state_hash_deterministic() {
        let p1 = CreditPool::new("s".into(), 100, 200);
        let p2 = CreditPool::new("s".into(), 100, 200);
        assert_eq!(p1.state_hash(), p2.state_hash());
    }

    #[test]
    fn credit_pool_serde_roundtrip() {
        let pool = CreditPool::new("s".into(), 100, 200);
        let json = serde_json::to_string(&pool).unwrap();
        let back: CreditPool = serde_json::from_str(&json).unwrap();
        assert_eq!(pool.available(), back.available());
        assert_eq!(pool.session_id(), back.session_id());
    }

    // --- Region tests ---

    #[test]
    fn region_allocate_success() {
        let mut ts = default_state();
        let rid = ts.allocate_region(1024, 10).unwrap();
        assert_eq!(rid, 1);
        assert_eq!(ts.regions[&rid].state, RegionState::Allocated);
    }

    #[test]
    fn region_allocate_too_many() {
        let config = BatchTransportConfig {
            max_active_regions: 1,
            ..Default::default()
        };
        let mut ts = BatchTransportState::new("s".into(), config, test_epoch());
        ts.allocate_region(100, 10).unwrap();
        let err = ts.allocate_region(100, 20);
        assert!(err.is_err());
    }

    #[test]
    fn region_seal_success() {
        let mut ts = default_state();
        let rid = ts.allocate_region(1024, 10).unwrap();
        let hash = ts.seal_region(rid, 500, 20).unwrap();
        assert_eq!(ts.regions[&rid].state, RegionState::Sealed);
        assert_eq!(ts.regions[&rid].content_hash, Some(hash));
    }

    #[test]
    fn region_seal_wrong_state() {
        let mut ts = default_state();
        let rid = ts.allocate_region(1024, 10).unwrap();
        ts.seal_region(rid, 500, 20).unwrap();
        let err = ts.seal_region(rid, 500, 30);
        assert!(err.is_err());
    }

    #[test]
    fn region_release_success() {
        let mut ts = default_state();
        let rid = ts.allocate_region(1024, 10).unwrap();
        ts.seal_region(rid, 500, 20).unwrap();
        ts.release_region(rid).unwrap();
        assert_eq!(ts.regions[&rid].state, RegionState::Released);
    }

    #[test]
    fn region_revoke() {
        let mut ts = default_state();
        let rid = ts.allocate_region(1024, 10).unwrap();
        ts.revoke_region(rid).unwrap();
        assert_eq!(ts.regions[&rid].state, RegionState::Revoked);
    }

    #[test]
    fn region_state_display() {
        assert_eq!(RegionState::Allocated.to_string(), "allocated");
        assert_eq!(RegionState::Sealed.to_string(), "sealed");
        assert_eq!(RegionState::Released.to_string(), "released");
    }

    #[test]
    fn region_serde_roundtrip() {
        let r = SharedMemoryRegion {
            region_id: 1,
            session_id: "s".into(),
            capacity_bytes: 1024,
            occupied_bytes: 0,
            state: RegionState::Allocated,
            content_hash: None,
            allocated_at_tick: 10,
            sealed_at_tick: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: SharedMemoryRegion = serde_json::from_str(&json).unwrap();
        assert_eq!(r.region_id, back.region_id);
    }

    // --- Batch build tests ---

    #[test]
    fn batch_build_success() {
        let mut ts = default_state();
        let entries = vec![make_entry(1, b"hello"), make_entry(2, b"world")];
        let batch = ts
            .build_batch(entries, &session_key(), test_epoch(), 100)
            .unwrap();
        assert_eq!(batch.batch_id, 1);
        assert_eq!(batch.sequence_start, 1);
        assert_eq!(batch.sequence_end, 2);
        assert_eq!(batch.entries.len(), 2);
    }

    #[test]
    fn batch_build_empty_rejected() {
        let mut ts = default_state();
        let err = ts.build_batch(Vec::new(), &session_key(), test_epoch(), 100);
        assert!(err.is_err());
    }

    #[test]
    fn batch_build_too_large() {
        let config = BatchTransportConfig {
            max_batch_size: 1,
            ..Default::default()
        };
        let mut ts = BatchTransportState::new("s".into(), config, test_epoch());
        let entries = vec![make_entry(1, b"a"), make_entry(2, b"b")];
        let err = ts.build_batch(entries, &session_key(), test_epoch(), 100);
        assert!(err.is_err());
    }

    #[test]
    fn batch_build_non_contiguous_rejected() {
        let mut ts = default_state();
        let entries = vec![make_entry(1, b"a"), make_entry(3, b"c")];
        let err = ts.build_batch(entries, &session_key(), test_epoch(), 100);
        assert!(err.is_err());
    }

    // --- MAC tests ---

    #[test]
    fn batch_mac_deterministic() {
        let entries = vec![make_entry(1, b"test")];
        let m1 = compute_batch_mac(&session_key(), 1, &entries, test_epoch());
        let m2 = compute_batch_mac(&session_key(), 1, &entries, test_epoch());
        assert_eq!(m1, m2);
    }

    #[test]
    fn batch_mac_key_sensitive() {
        let entries = vec![make_entry(1, b"test")];
        let m1 = compute_batch_mac(&[0xAA; 32], 1, &entries, test_epoch());
        let m2 = compute_batch_mac(&[0xBB; 32], 1, &entries, test_epoch());
        assert_ne!(m1, m2);
    }

    #[test]
    fn entry_content_hash_deterministic() {
        let p = BatchPayload::Inline(b"data".to_vec());
        let h1 = compute_entry_content_hash(1, &p, "t");
        let h2 = compute_entry_content_hash(1, &p, "t");
        assert_eq!(h1, h2);
    }

    // --- Submit tests ---

    #[test]
    fn submit_batch_success() {
        let mut ts = default_state();
        let mut protocol = established_protocol();
        let entries = vec![make_entry(1, b"data")];
        let batch = ts
            .build_batch(entries, &session_key(), test_epoch(), 100)
            .unwrap();
        let receipt = ts
            .submit_batch(batch, &mut protocol, &session_key(), 100)
            .unwrap();
        assert_eq!(receipt.envelope_count, 1);
        assert_eq!(ts.accepted_batches.len(), 1);
    }

    #[test]
    fn submit_batch_consumes_credits() {
        let mut ts = default_state();
        let mut protocol = established_protocol();
        let before = ts.credit_pool.available();
        let entries = vec![make_entry(1, b"a"), make_entry(2, b"b")];
        let batch = ts
            .build_batch(entries, &session_key(), test_epoch(), 100)
            .unwrap();
        ts.submit_batch(batch, &mut protocol, &session_key(), 100)
            .unwrap();
        assert_eq!(ts.credit_pool.available(), before - 2);
    }

    #[test]
    fn submit_batch_uninit_rejected() {
        let mut ts = default_state();
        let mut protocol = SessionProtocolState::new("s".into(), "e".into(), "h".into(), 64, 50);
        let entries = vec![make_entry(1, b"data")];
        let batch = ts
            .build_batch(entries, &session_key(), test_epoch(), 100)
            .unwrap();
        let err = ts.submit_batch(batch, &mut protocol, &[0; 32], 100);
        assert!(err.is_err());
    }

    // --- Membrane tests ---

    #[test]
    fn membrane_tracks_stats() {
        let membrane = SafetyMembrane::new("s".into(), test_epoch(), 50);
        assert_eq!(membrane.total_accepted_batches(), 0);
        assert_eq!(membrane.total_rejected_batches(), 0);
    }

    #[test]
    fn membrane_rejection_reason_display() {
        assert_eq!(
            MembraneRejectionReason::PhaseBlocked.to_string(),
            "phase_blocked"
        );
        assert_eq!(
            MembraneRejectionReason::EpochMismatch.to_string(),
            "epoch_mismatch"
        );
    }

    #[test]
    fn membrane_rejection_reason_serde() {
        for r in MembraneRejectionReason::ALL {
            let json = serde_json::to_string(r).unwrap();
            let back: MembraneRejectionReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*r, back);
        }
    }

    // --- Error tests ---

    #[test]
    fn error_display() {
        let e = BatchTransportError::EmptyBatch;
        assert_eq!(e.to_string(), "empty batch");
        let e2 = BatchTransportError::InsufficientCredits {
            requested: 10,
            available: 5,
        };
        assert!(e2.to_string().contains("10"));
    }

    #[test]
    fn error_serde_roundtrip() {
        let errors = vec![
            BatchTransportError::EmptyBatch,
            BatchTransportError::BatchTooLarge { size: 100, max: 64 },
            BatchTransportError::RegionNotFound { region_id: 42 },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: BatchTransportError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, back);
        }
    }

    // --- State hash ---

    #[test]
    fn state_hash_deterministic() {
        let s1 = default_state();
        let s2 = default_state();
        assert_eq!(s1.state_hash(), s2.state_hash());
    }

    // --- Corpus/runner tests ---

    #[test]
    fn corpus_produces_specimens() {
        let corpus = batch_transport_corpus();
        assert!(corpus.len() >= 12);
    }

    #[test]
    fn corpus_all_pass() {
        let corpus = batch_transport_corpus();
        for spec in &corpus {
            assert_eq!(
                spec.verdict,
                BatchTransportVerdict::Pass,
                "specimen {} failed",
                spec.name
            );
        }
    }

    #[test]
    fn runner_all_pass() {
        let result = run_batch_transport_corpus();
        assert!(result.all_pass);
        assert_eq!(result.fail_count, 0);
    }

    #[test]
    fn runner_hash_deterministic() {
        let r1 = run_batch_transport_corpus();
        let r2 = run_batch_transport_corpus();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn batch_payload_display() {
        let p = BatchPayload::Inline(b"test".to_vec());
        assert!(p.to_string().contains("4 bytes"));
    }

    #[test]
    fn membrane_verdict_is_accept() {
        let v = MembraneVerdict::Accept { envelope_count: 5 };
        assert!(v.is_accept());
        let r = MembraneVerdict::Reject {
            reason: MembraneRejectionReason::PhaseBlocked,
            detail: "x".into(),
        };
        assert!(!r.is_accept());
    }

    #[test]
    fn grant_credits_after_consumption() {
        let mut ts = default_state();
        let mut protocol = established_protocol();
        let entries = vec![make_entry(1, b"a")];
        let batch = ts
            .build_batch(entries, &session_key(), test_epoch(), 100)
            .unwrap();
        ts.submit_batch(batch, &mut protocol, &session_key(), 100)
            .unwrap();
        let before = ts.credit_pool.available();
        ts.grant_credits(10);
        assert_eq!(ts.credit_pool.available(), before + 10);
    }

    // ===================================================================
    // Deep unit tests: enum serde roundtrips, Display/as_str consistency,
    // error Display formatting, edge cases, state machine transitions,
    // canonical hash determinism
    // ===================================================================

    #[test]
    fn region_state_serde_roundtrip_all_variants() {
        for variant in RegionState::ALL {
            let json = serde_json::to_string(variant).unwrap();
            let back: RegionState = serde_json::from_str(&json).unwrap();
            assert_eq!(
                *variant, back,
                "RegionState serde roundtrip failed for {variant}"
            );
        }
    }

    #[test]
    fn region_state_display_all_variants_consistency() {
        let expected = [
            (RegionState::Allocated, "allocated"),
            (RegionState::Writing, "writing"),
            (RegionState::Sealed, "sealed"),
            (RegionState::Released, "released"),
            (RegionState::Revoked, "revoked"),
        ];
        for (variant, label) in expected {
            assert_eq!(variant.to_string(), label);
        }
        // ALL slice covers exactly 5 variants
        assert_eq!(RegionState::ALL.len(), 5);
    }

    #[test]
    fn batch_transport_specimen_family_serde_roundtrip_all() {
        for family in BatchTransportSpecimenFamily::ALL {
            let json = serde_json::to_string(family).unwrap();
            let back: BatchTransportSpecimenFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(*family, back, "Family serde roundtrip failed for {family}");
        }
    }

    #[test]
    fn batch_transport_specimen_family_display_all_consistency() {
        let expected = [
            (BatchTransportSpecimenFamily::HappyPath, "happy_path"),
            (
                BatchTransportSpecimenFamily::CreditExhaustion,
                "credit_exhaustion",
            ),
            (
                BatchTransportSpecimenFamily::BatchSizeLimits,
                "batch_size_limits",
            ),
            (
                BatchTransportSpecimenFamily::SharedRegionLifecycle,
                "shared_region_lifecycle",
            ),
            (
                BatchTransportSpecimenFamily::MembranePhaseRejection,
                "membrane_phase_rejection",
            ),
            (
                BatchTransportSpecimenFamily::MembraneReplayRejection,
                "membrane_replay_rejection",
            ),
            (
                BatchTransportSpecimenFamily::DegradedModeHandling,
                "degraded_mode_handling",
            ),
            (
                BatchTransportSpecimenFamily::BatchMacVerification,
                "batch_mac_verification",
            ),
            (
                BatchTransportSpecimenFamily::SequenceContiguity,
                "sequence_contiguity",
            ),
            (
                BatchTransportSpecimenFamily::RegionCapacityEnforcement,
                "region_capacity_enforcement",
            ),
            (
                BatchTransportSpecimenFamily::CreditGrantAndReturn,
                "credit_grant_and_return",
            ),
            (
                BatchTransportSpecimenFamily::EmptyBatchRejection,
                "empty_batch_rejection",
            ),
        ];
        for (variant, label) in expected {
            assert_eq!(variant.to_string(), label);
        }
        assert_eq!(BatchTransportSpecimenFamily::ALL.len(), 12);
    }

    #[test]
    fn membrane_rejection_reason_display_all_variants() {
        let expected = [
            (MembraneRejectionReason::PhaseBlocked, "phase_blocked"),
            (MembraneRejectionReason::EpochMismatch, "epoch_mismatch"),
            (MembraneRejectionReason::ReplayDetected, "replay_detected"),
            (MembraneRejectionReason::DegradedBlocked, "degraded_blocked"),
            (
                MembraneRejectionReason::InsufficientCredits,
                "insufficient_credits",
            ),
            (
                MembraneRejectionReason::BatchSizeExceeded,
                "batch_size_exceeded",
            ),
            (MembraneRejectionReason::InvalidRegion, "invalid_region"),
            (
                MembraneRejectionReason::MacVerificationFailed,
                "mac_verification_failed",
            ),
            (MembraneRejectionReason::SequenceGap, "sequence_gap"),
        ];
        for (variant, label) in expected {
            assert_eq!(variant.to_string(), label);
        }
        assert_eq!(MembraneRejectionReason::ALL.len(), 9);
    }

    #[test]
    fn batch_transport_verdict_serde_roundtrip() {
        let pass = BatchTransportVerdict::Pass;
        let fail = BatchTransportVerdict::Fail;
        let pass_json = serde_json::to_string(&pass).unwrap();
        let fail_json = serde_json::to_string(&fail).unwrap();
        assert_eq!(
            serde_json::from_str::<BatchTransportVerdict>(&pass_json).unwrap(),
            pass
        );
        assert_eq!(
            serde_json::from_str::<BatchTransportVerdict>(&fail_json).unwrap(),
            fail
        );
        // Different serialized forms
        assert_ne!(pass_json, fail_json);
    }

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<(BatchTransportError, &str)> = vec![
            (
                BatchTransportError::BatchTooLarge { size: 100, max: 64 },
                "batch too large: 100 > 64",
            ),
            (
                BatchTransportError::PayloadTooLarge {
                    bytes: 5000,
                    max: 4096,
                },
                "payload too large: 5000 > 4096",
            ),
            (
                BatchTransportError::InsufficientCredits {
                    requested: 10,
                    available: 3,
                },
                "insufficient credits: need 10, have 3",
            ),
            (
                BatchTransportError::TooManyRegions {
                    active: 16,
                    max: 16,
                },
                "too many active regions: 16 >= 16",
            ),
            (
                BatchTransportError::RegionNotFound { region_id: 99 },
                "region 99 not found",
            ),
            (
                BatchTransportError::InvalidRegionState {
                    region_id: 5,
                    expected: RegionState::Sealed,
                    actual: RegionState::Allocated,
                },
                "region 5: expected sealed, got allocated",
            ),
            (
                BatchTransportError::RegionCapacityExceeded {
                    region_id: 3,
                    capacity: 1024,
                    requested: 2048,
                },
                "region 3: capacity 1024, requested 2048",
            ),
            (
                BatchTransportError::NonContiguousSequences {
                    expected: 2,
                    actual: 5,
                },
                "non-contiguous sequences: expected 2, got 5",
            ),
            (BatchTransportError::EmptyBatch, "empty batch"),
            (
                BatchTransportError::BatchMacMismatch { batch_id: 7 },
                "batch MAC mismatch for batch 7",
            ),
            (
                BatchTransportError::MembraneRejection {
                    reason: MembraneRejectionReason::PhaseBlocked,
                    detail: "not ready".into(),
                },
                "membrane rejection (phase_blocked): not ready",
            ),
        ];
        for (err, expected_msg) in &errors {
            assert_eq!(
                err.to_string(),
                *expected_msg,
                "Display mismatch for {err:?}"
            );
        }
    }

    #[test]
    fn error_serde_roundtrip_all_variants() {
        let errors = vec![
            BatchTransportError::BatchTooLarge { size: 10, max: 5 },
            BatchTransportError::PayloadTooLarge {
                bytes: 999,
                max: 100,
            },
            BatchTransportError::InsufficientCredits {
                requested: 50,
                available: 2,
            },
            BatchTransportError::TooManyRegions { active: 8, max: 8 },
            BatchTransportError::RegionNotFound { region_id: 1 },
            BatchTransportError::InvalidRegionState {
                region_id: 2,
                expected: RegionState::Writing,
                actual: RegionState::Revoked,
            },
            BatchTransportError::RegionCapacityExceeded {
                region_id: 3,
                capacity: 500,
                requested: 600,
            },
            BatchTransportError::NonContiguousSequences {
                expected: 1,
                actual: 3,
            },
            BatchTransportError::EmptyBatch,
            BatchTransportError::BatchMacMismatch { batch_id: 42 },
            BatchTransportError::MembraneRejection {
                reason: MembraneRejectionReason::SequenceGap,
                detail: "gap at 5".into(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: BatchTransportError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back, "serde roundtrip failed for {err:?}");
        }
    }

    #[test]
    fn batch_payload_display_shared_region() {
        let payload = BatchPayload::SharedRegion {
            region_id: 42,
            offset: 0,
            length: 256,
            payload_hash: ContentHash::compute(b"test"),
        };
        let display = payload.to_string();
        assert!(display.contains("shared"));
        assert!(display.contains("42"));
        assert!(display.contains("256 bytes"));
    }

    #[test]
    fn batch_payload_display_backpressure() {
        let payload = BatchPayload::Backpressure(BackpressureSignal {
            pending_messages: 75,
            limit: 100,
        });
        let display = payload.to_string();
        assert!(display.contains("backpressure"));
        assert!(display.contains("75"));
        assert!(display.contains("100"));
    }

    #[test]
    fn batch_payload_inline_empty() {
        let payload = BatchPayload::Inline(Vec::new());
        let display = payload.to_string();
        assert!(display.contains("0 bytes"));
    }

    #[test]
    fn batch_payload_serde_roundtrip_all_variants() {
        let payloads = vec![
            BatchPayload::Inline(b"hello world".to_vec()),
            BatchPayload::Inline(Vec::new()),
            BatchPayload::SharedRegion {
                region_id: 1,
                offset: 64,
                length: 128,
                payload_hash: ContentHash::compute(b"region-data"),
            },
            BatchPayload::Backpressure(BackpressureSignal {
                pending_messages: 10,
                limit: 50,
            }),
        ];
        for p in &payloads {
            let json = serde_json::to_string(p).unwrap();
            let back: BatchPayload = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, back);
        }
    }

    #[test]
    fn credit_pool_consume_exact_amount_exhausts() {
        let mut pool = CreditPool::new("s".into(), 10, 100);
        pool.try_consume(10).unwrap();
        assert!(pool.is_exhausted());
        assert_eq!(pool.available(), 0);
        assert_eq!(pool.total_consumed(), 10);
    }

    #[test]
    fn credit_pool_consume_zero_is_noop() {
        let mut pool = CreditPool::new("s".into(), 50, 100);
        pool.try_consume(0).unwrap();
        assert_eq!(pool.available(), 50);
        assert_eq!(pool.total_consumed(), 0);
    }

    #[test]
    fn credit_pool_grant_tracks_high_water_mark() {
        let mut pool = CreditPool::new("s".into(), 10, 100);
        assert_eq!(pool.high_water_mark(), 10);
        pool.grant(20);
        assert_eq!(pool.high_water_mark(), 30);
        pool.try_consume(25).unwrap();
        assert_eq!(pool.high_water_mark(), 30); // stays at previous high
        pool.grant(50);
        assert_eq!(pool.high_water_mark(), 55);
    }

    #[test]
    fn credit_pool_revoke_below_zero_saturates() {
        let mut pool = CreditPool::new("s".into(), 5, 100);
        pool.revoke(100);
        assert_eq!(pool.available(), 0);
        assert!(pool.is_exhausted());
    }

    #[test]
    fn credit_pool_initial_capped_at_max() {
        let pool = CreditPool::new("s".into(), 999, 10);
        assert_eq!(pool.available(), 10);
    }

    #[test]
    fn credit_pool_state_hash_differs_after_mutation() {
        let mut pool = CreditPool::new("s".into(), 100, 200);
        let hash_before = pool.state_hash();
        pool.try_consume(1).unwrap();
        let hash_after = pool.state_hash();
        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn credit_pool_state_hash_differs_by_session_id() {
        let p1 = CreditPool::new("session-a".into(), 100, 200);
        let p2 = CreditPool::new("session-b".into(), 100, 200);
        assert_ne!(p1.state_hash(), p2.state_hash());
    }

    #[test]
    fn region_full_lifecycle_allocated_to_revoked() {
        let mut ts = default_state();
        let rid = ts.allocate_region(512, 10).unwrap();
        assert_eq!(ts.regions[&rid].state, RegionState::Allocated);

        ts.seal_region(rid, 256, 20).unwrap();
        assert_eq!(ts.regions[&rid].state, RegionState::Sealed);
        assert!(ts.regions[&rid].sealed_at_tick.is_some());
        assert_eq!(ts.regions[&rid].occupied_bytes, 256);

        ts.release_region(rid).unwrap();
        assert_eq!(ts.regions[&rid].state, RegionState::Released);

        // Cannot release again (already released, not sealed)
        let err = ts.release_region(rid);
        assert!(err.is_err());
    }

    #[test]
    fn region_seal_with_zero_bytes() {
        let mut ts = default_state();
        let rid = ts.allocate_region(1024, 10).unwrap();
        let hash = ts.seal_region(rid, 0, 20).unwrap();
        assert_eq!(ts.regions[&rid].occupied_bytes, 0);
        assert_eq!(ts.regions[&rid].content_hash, Some(hash));
    }

    #[test]
    fn region_seal_at_capacity_boundary() {
        let mut ts = default_state();
        let rid = ts.allocate_region(100, 10).unwrap();
        // Exact capacity should succeed
        ts.seal_region(rid, 100, 20).unwrap();
        assert_eq!(ts.regions[&rid].occupied_bytes, 100);
    }

    #[test]
    fn region_seal_exceeds_capacity() {
        let mut ts = default_state();
        let rid = ts.allocate_region(100, 10).unwrap();
        let err = ts.seal_region(rid, 101, 20);
        assert!(matches!(
            err,
            Err(BatchTransportError::RegionCapacityExceeded { .. })
        ));
    }

    #[test]
    fn region_not_found_errors() {
        let mut ts = default_state();
        assert!(matches!(
            ts.seal_region(999, 10, 20),
            Err(BatchTransportError::RegionNotFound { region_id: 999 })
        ));
        assert!(matches!(
            ts.release_region(999),
            Err(BatchTransportError::RegionNotFound { region_id: 999 })
        ));
        assert!(matches!(
            ts.revoke_region(999),
            Err(BatchTransportError::RegionNotFound { region_id: 999 })
        ));
    }

    #[test]
    fn region_revoke_from_any_state() {
        // Revoke should work from any state, not just Sealed
        let mut ts = default_state();
        let r1 = ts.allocate_region(100, 10).unwrap();
        ts.revoke_region(r1).unwrap();
        assert_eq!(ts.regions[&r1].state, RegionState::Revoked);

        let r2 = ts.allocate_region(100, 20).unwrap();
        ts.seal_region(r2, 50, 30).unwrap();
        ts.revoke_region(r2).unwrap();
        assert_eq!(ts.regions[&r2].state, RegionState::Revoked);
    }

    #[test]
    fn membrane_audit_trail_truncation() {
        let epoch = test_epoch();
        let mut membrane = SafetyMembrane::new("s".into(), epoch, 3);
        let config = BatchTransportConfig::default();
        let mut protocol = established_protocol();
        let credit_pool = CreditPool::new("s".into(), 1000, 2000);
        let regions = BTreeMap::new();

        // Submit 5 batches so the audit trail must truncate to 3
        for i in 1..=5u64 {
            let entries = vec![make_entry(i, b"data")];
            let batch_mac = compute_batch_mac(&session_key(), i, &entries, epoch);
            let batch = BatchEnvelope {
                batch_id: i,
                session_id: "s".into(),
                entries,
                sequence_start: i,
                sequence_end: i,
                credits_consumed: 1,
                total_payload_bytes: 4,
                batch_mac,
                sealed_at_tick: 100 + i,
                epoch,
            };
            membrane.validate_batch(
                &batch,
                &mut protocol,
                &session_key(),
                &credit_pool,
                &regions,
                &config,
                100 + i,
            );
        }
        assert_eq!(membrane.audit_trail().len(), 3);
        // Oldest entries were removed; latest batch_ids remain
        assert_eq!(membrane.audit_trail()[0].batch_id, 3);
        assert_eq!(membrane.audit_trail()[2].batch_id, 5);
    }

    #[test]
    fn membrane_update_epoch() {
        let mut membrane = SafetyMembrane::new("s".into(), SecurityEpoch::from_raw(1), 10);
        membrane.update_epoch(SecurityEpoch::from_raw(42));
        // Verify via a batch that would fail epoch mismatch against epoch 1
        // but we can't directly read current_epoch, so we test indirectly by
        // checking that the membrane's epoch was updated.
        let config = BatchTransportConfig::default();
        let mut protocol = established_protocol();
        let credit_pool = CreditPool::new("s".into(), 100, 200);
        let regions = BTreeMap::new();

        let entries = vec![make_entry(1, b"test")];
        let epoch42 = SecurityEpoch::from_raw(42);
        let batch_mac = compute_batch_mac(&session_key(), 1, &entries, epoch42);
        let batch = BatchEnvelope {
            batch_id: 1,
            session_id: "s".into(),
            entries,
            sequence_start: 1,
            sequence_end: 1,
            credits_consumed: 1,
            total_payload_bytes: 4,
            batch_mac,
            sealed_at_tick: 100,
            epoch: epoch42,
        };
        let verdict = membrane.validate_batch(
            &batch,
            &mut protocol,
            &session_key(),
            &credit_pool,
            &regions,
            &config,
            100,
        );
        assert!(verdict.is_accept());
    }

    #[test]
    fn membrane_rejection_count_tracking() {
        let epoch = test_epoch();
        let mut membrane = SafetyMembrane::new("s".into(), epoch, 50);
        let config = BatchTransportConfig {
            max_batch_size: 1,
            ..Default::default()
        };
        let mut protocol = established_protocol();
        let credit_pool = CreditPool::new("s".into(), 100, 200);
        let regions = BTreeMap::new();

        // Submit a batch with 2 entries to a config that only allows 1 -> BatchSizeExceeded
        let entries = vec![make_entry(1, b"a"), make_entry(2, b"b")];
        let batch_mac = compute_batch_mac(&session_key(), 1, &entries, epoch);
        let batch = BatchEnvelope {
            batch_id: 1,
            session_id: "s".into(),
            entries,
            sequence_start: 1,
            sequence_end: 2,
            credits_consumed: 2,
            total_payload_bytes: 2,
            batch_mac,
            sealed_at_tick: 100,
            epoch,
        };
        let verdict = membrane.validate_batch(
            &batch,
            &mut protocol,
            &session_key(),
            &credit_pool,
            &regions,
            &config,
            100,
        );
        assert!(!verdict.is_accept());
        assert_eq!(
            membrane.rejection_count(MembraneRejectionReason::BatchSizeExceeded),
            1
        );
        assert_eq!(membrane.total_rejected_batches(), 1);
        assert_eq!(membrane.total_accepted_batches(), 0);
    }

    #[test]
    fn entry_content_hash_varies_by_sequence() {
        let payload = BatchPayload::Inline(b"same-data".to_vec());
        let h1 = compute_entry_content_hash(1, &payload, "t");
        let h2 = compute_entry_content_hash(2, &payload, "t");
        assert_ne!(h1, h2);
    }

    #[test]
    fn entry_content_hash_varies_by_trace_id() {
        let payload = BatchPayload::Inline(b"data".to_vec());
        let h1 = compute_entry_content_hash(1, &payload, "trace-a");
        let h2 = compute_entry_content_hash(1, &payload, "trace-b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn entry_content_hash_shared_region_variant() {
        let payload = BatchPayload::SharedRegion {
            region_id: 1,
            offset: 0,
            length: 100,
            payload_hash: ContentHash::compute(b"region-payload"),
        };
        let h1 = compute_entry_content_hash(1, &payload, "t");
        let h2 = compute_entry_content_hash(1, &payload, "t");
        assert_eq!(h1, h2);

        // Different region_id produces different hash
        let payload2 = BatchPayload::SharedRegion {
            region_id: 2,
            offset: 0,
            length: 100,
            payload_hash: ContentHash::compute(b"region-payload"),
        };
        let h3 = compute_entry_content_hash(1, &payload2, "t");
        assert_ne!(h1, h3);
    }

    #[test]
    fn entry_content_hash_backpressure_variant() {
        let payload = BatchPayload::Backpressure(BackpressureSignal {
            pending_messages: 10,
            limit: 50,
        });
        let h1 = compute_entry_content_hash(1, &payload, "t");
        let h2 = compute_entry_content_hash(1, &payload, "t");
        assert_eq!(h1, h2);
    }

    #[test]
    fn batch_mac_varies_by_epoch() {
        let entries = vec![make_entry(1, b"data")];
        let m1 = compute_batch_mac(&session_key(), 1, &entries, SecurityEpoch::from_raw(1));
        let m2 = compute_batch_mac(&session_key(), 1, &entries, SecurityEpoch::from_raw(2));
        assert_ne!(m1, m2);
    }

    #[test]
    fn batch_mac_varies_by_batch_id() {
        let entries = vec![make_entry(1, b"data")];
        let m1 = compute_batch_mac(&session_key(), 1, &entries, test_epoch());
        let m2 = compute_batch_mac(&session_key(), 2, &entries, test_epoch());
        assert_ne!(m1, m2);
    }

    #[test]
    fn batch_build_payload_too_large() {
        let config = BatchTransportConfig {
            max_batch_payload_bytes: 5,
            ..Default::default()
        };
        let mut ts = BatchTransportState::new("s".into(), config, test_epoch());
        let entries = vec![make_entry(1, b"abcdef")]; // 6 bytes > 5
        let err = ts.build_batch(entries, &session_key(), test_epoch(), 100);
        assert!(matches!(
            err,
            Err(BatchTransportError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn batch_build_increments_batch_id() {
        let mut ts = default_state();
        let b1 = ts
            .build_batch(vec![make_entry(1, b"a")], &session_key(), test_epoch(), 100)
            .unwrap();
        let b2 = ts
            .build_batch(vec![make_entry(2, b"b")], &session_key(), test_epoch(), 200)
            .unwrap();
        assert_eq!(b1.batch_id, 1);
        assert_eq!(b2.batch_id, 2);
    }

    #[test]
    fn state_hash_differs_after_batch_submission() {
        let mut ts = default_state();
        let hash_before = ts.state_hash();
        let mut protocol = established_protocol();
        let entries = vec![make_entry(1, b"data")];
        let batch = ts
            .build_batch(entries, &session_key(), test_epoch(), 100)
            .unwrap();
        ts.submit_batch(batch, &mut protocol, &session_key(), 100)
            .unwrap();
        let hash_after = ts.state_hash();
        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn state_hash_differs_by_session_id() {
        let s1 = BatchTransportState::new(
            "alpha".into(),
            BatchTransportConfig::default(),
            test_epoch(),
        );
        let s2 =
            BatchTransportState::new("beta".into(), BatchTransportConfig::default(), test_epoch());
        assert_ne!(s1.state_hash(), s2.state_hash());
    }

    #[test]
    fn specimen_hash_determinism() {
        let h1 = specimen_hash("test-specimen", BatchTransportVerdict::Pass);
        let h2 = specimen_hash("test-specimen", BatchTransportVerdict::Pass);
        assert_eq!(h1, h2);

        let h3 = specimen_hash("test-specimen", BatchTransportVerdict::Fail);
        assert_ne!(h1, h3);
    }

    #[test]
    fn membrane_audit_entry_serde_roundtrip() {
        let entry = MembraneAuditEntry {
            batch_id: 42,
            accepted: true,
            rejection_reason: None,
            tick: 999,
            envelope_count: 3,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: MembraneAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);

        let entry_reject = MembraneAuditEntry {
            batch_id: 7,
            accepted: false,
            rejection_reason: Some(MembraneRejectionReason::ReplayDetected),
            tick: 500,
            envelope_count: 1,
        };
        let json2 = serde_json::to_string(&entry_reject).unwrap();
        let back2: MembraneAuditEntry = serde_json::from_str(&json2).unwrap();
        assert_eq!(entry_reject, back2);
    }

    #[test]
    fn membrane_verdict_serde_roundtrip() {
        let accept = MembraneVerdict::Accept { envelope_count: 5 };
        let reject = MembraneVerdict::Reject {
            reason: MembraneRejectionReason::MacVerificationFailed,
            detail: "bad mac".into(),
        };
        for v in [&accept, &reject] {
            let json = serde_json::to_string(v).unwrap();
            let back: MembraneVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn batch_receipt_serde_roundtrip() {
        let receipt = BatchReceipt {
            batch_id: 1,
            session_id: "s".into(),
            sequence_start: 10,
            sequence_end: 15,
            envelope_count: 6,
            credits_consumed: 6,
            batch_content_hash: ContentHash::compute(b"receipt"),
            accepted_at_tick: 300,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let back: BatchReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn batch_envelope_serde_roundtrip() {
        let entries = vec![make_entry(1, b"test")];
        let mac = compute_batch_mac(&session_key(), 1, &entries, test_epoch());
        let envelope = BatchEnvelope {
            batch_id: 1,
            session_id: "sess".into(),
            entries,
            sequence_start: 1,
            sequence_end: 1,
            credits_consumed: 1,
            total_payload_bytes: 4,
            batch_mac: mac,
            sealed_at_tick: 100,
            epoch: test_epoch(),
        };
        let json = serde_json::to_string(&envelope).unwrap();
        let back: BatchEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(envelope, back);
    }

    #[test]
    fn batch_entry_serde_roundtrip() {
        let entry = make_entry(42, b"serde-check");
        let json = serde_json::to_string(&entry).unwrap();
        let back: BatchEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn runner_result_families_covers_all() {
        let result = run_batch_transport_corpus();
        // Runner should cover all 12 families
        assert_eq!(result.families_covered.len(), 12);
        for family in BatchTransportSpecimenFamily::ALL {
            assert!(
                result.families_covered.contains(family),
                "missing family: {family}"
            );
        }
    }

    #[test]
    fn released_region_does_not_count_as_active() {
        let config = BatchTransportConfig {
            max_active_regions: 1,
            ..Default::default()
        };
        let mut ts = BatchTransportState::new("s".into(), config, test_epoch());
        let r1 = ts.allocate_region(100, 10).unwrap();
        ts.seal_region(r1, 50, 20).unwrap();
        ts.release_region(r1).unwrap();
        // Released region should not count as active, so we can allocate another
        let r2 = ts.allocate_region(100, 30);
        assert!(r2.is_ok());
    }

    #[test]
    fn revoked_region_does_not_count_as_active() {
        let config = BatchTransportConfig {
            max_active_regions: 1,
            ..Default::default()
        };
        let mut ts = BatchTransportState::new("s".into(), config, test_epoch());
        let r1 = ts.allocate_region(100, 10).unwrap();
        ts.revoke_region(r1).unwrap();
        let r2 = ts.allocate_region(100, 20);
        assert!(r2.is_ok());
    }
}
