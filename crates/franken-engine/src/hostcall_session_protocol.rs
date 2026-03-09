//! Typestate session protocol, key schedule, anti-replay ledger, and degraded-mode semantics
//! for hostcall sessions.
//!
//! This module formalizes the session lifecycle as a compile-time-checked typestate
//! machine, defines the key schedule for session key derivation, provides a persistent
//! anti-replay ledger, and specifies the degraded-mode policy when full authentication
//! cannot be maintained.
//!
//! The existing [`session_hostcall_channel`] module provides the runtime implementation;
//! this module provides the formal protocol definitions that constrain and document its
//! behavior.
//!
//! Plan references: Section 6.5 (RGC-505A), 9E.6 (session-authenticated hostcall channel).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Typestate session phases
// ---------------------------------------------------------------------------

/// Session lifecycle phase discriminant for runtime tracking.
///
/// The compile-time typestate is modeled by the `SessionPhaseTag` enum, while
/// the zero-sized marker types (`PhaseUninit`, `PhaseNegotiating`, etc.) exist
/// for documentation and protocol specification.  Runtime code uses `SessionPhaseTag`
/// for dynamic dispatch and serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SessionPhaseTag {
    /// No handshake has been initiated.  The only legal transition is to
    /// `Negotiating` via `initiate_handshake`.
    Uninit,

    /// A handshake request has been sent; awaiting the peer's response.
    /// Transitions: `Established` on valid response, `Closed` on timeout
    /// or rejection.
    Negotiating,

    /// Mutual authentication succeeded and a session key has been derived.
    /// Data-plane envelopes may flow.  Transitions: `DegradedOpen` on
    /// partial failure, `Closing` on explicit close, `Closed` on expiry.
    Established,

    /// The session is still open but operating with reduced security
    /// guarantees.  The `DegradedModePolicy` governs which operations
    /// are permitted.  Transitions: `Established` on recovery,
    /// `Closing` on operator decision.
    DegradedOpen,

    /// A close has been initiated; draining in-flight messages.
    /// Transitions: `Closed` once drain completes or timeout fires.
    Closing,

    /// Terminal state.  No further transitions are legal.
    Closed,
}

impl SessionPhaseTag {
    /// Whether the session is in a terminal state from which no transitions
    /// are possible.
    pub fn is_terminal(self) -> bool {
        self == Self::Closed
    }

    /// Whether data-plane envelopes may be sent in this phase.
    pub fn permits_data(self) -> bool {
        matches!(self, Self::Established | Self::DegradedOpen)
    }

    /// All variants, for exhaustive iteration.
    pub const ALL: &'static [SessionPhaseTag] = &[
        SessionPhaseTag::Uninit,
        SessionPhaseTag::Negotiating,
        SessionPhaseTag::Established,
        SessionPhaseTag::DegradedOpen,
        SessionPhaseTag::Closing,
        SessionPhaseTag::Closed,
    ];
}

impl fmt::Display for SessionPhaseTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Uninit => "uninit",
            Self::Negotiating => "negotiating",
            Self::Established => "established",
            Self::DegradedOpen => "degraded_open",
            Self::Closing => "closing",
            Self::Closed => "closed",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// Phase transition specification
// ---------------------------------------------------------------------------

/// A valid transition in the session typestate machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseTransition {
    pub from: SessionPhaseTag,
    pub to: SessionPhaseTag,
    pub trigger: TransitionTrigger,
}

/// Events that cause phase transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionTrigger {
    /// Extension initiates a handshake request.
    HandshakeInitiated,
    /// Peer responds with a valid handshake response.
    HandshakeCompleted,
    /// Handshake times out or peer rejects.
    HandshakeRejected,
    /// Security degradation detected (e.g. key rotation mid-session).
    SecurityDegradation { reason: String },
    /// Recovery from degraded mode (e.g. successful re-key).
    DegradedRecovery,
    /// Explicit close initiated by either party.
    CloseInitiated,
    /// Session lifetime or message budget exhausted.
    SessionExpired { reason: String },
    /// Drain completed after close initiation.
    DrainCompleted,
    /// Anti-replay threshold breach.
    ReplayThresholdBreached { drop_count: u64, window_ticks: u64 },
}

impl fmt::Display for TransitionTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandshakeInitiated => write!(f, "handshake_initiated"),
            Self::HandshakeCompleted => write!(f, "handshake_completed"),
            Self::HandshakeRejected => write!(f, "handshake_rejected"),
            Self::SecurityDegradation { reason } => {
                write!(f, "security_degradation: {reason}")
            }
            Self::DegradedRecovery => write!(f, "degraded_recovery"),
            Self::CloseInitiated => write!(f, "close_initiated"),
            Self::SessionExpired { reason } => write!(f, "session_expired: {reason}"),
            Self::DrainCompleted => write!(f, "drain_completed"),
            Self::ReplayThresholdBreached {
                drop_count,
                window_ticks,
            } => write!(
                f,
                "replay_threshold_breached: drops={drop_count}, window={window_ticks}"
            ),
        }
    }
}

/// The complete transition table for the session typestate machine.
///
/// Every valid `(from, to)` pair is listed; any pair NOT in this table
/// is a protocol violation and must be rejected.
pub fn valid_transitions() -> Vec<PhaseTransition> {
    vec![
        // Uninit → Negotiating: handshake sent
        PhaseTransition {
            from: SessionPhaseTag::Uninit,
            to: SessionPhaseTag::Negotiating,
            trigger: TransitionTrigger::HandshakeInitiated,
        },
        // Negotiating → Established: peer accepted
        PhaseTransition {
            from: SessionPhaseTag::Negotiating,
            to: SessionPhaseTag::Established,
            trigger: TransitionTrigger::HandshakeCompleted,
        },
        // Negotiating → Closed: peer rejected or timeout
        PhaseTransition {
            from: SessionPhaseTag::Negotiating,
            to: SessionPhaseTag::Closed,
            trigger: TransitionTrigger::HandshakeRejected,
        },
        // Established → DegradedOpen: key rotation, epoch change, etc.
        PhaseTransition {
            from: SessionPhaseTag::Established,
            to: SessionPhaseTag::DegradedOpen,
            trigger: TransitionTrigger::SecurityDegradation {
                reason: String::new(),
            },
        },
        // Established → Closing: explicit close
        PhaseTransition {
            from: SessionPhaseTag::Established,
            to: SessionPhaseTag::Closing,
            trigger: TransitionTrigger::CloseInitiated,
        },
        // Established → Closed: expiry (lifetime or message budget)
        PhaseTransition {
            from: SessionPhaseTag::Established,
            to: SessionPhaseTag::Closed,
            trigger: TransitionTrigger::SessionExpired {
                reason: String::new(),
            },
        },
        // Established → Closed: replay threshold breach
        PhaseTransition {
            from: SessionPhaseTag::Established,
            to: SessionPhaseTag::Closed,
            trigger: TransitionTrigger::ReplayThresholdBreached {
                drop_count: 0,
                window_ticks: 0,
            },
        },
        // DegradedOpen → Established: recovery
        PhaseTransition {
            from: SessionPhaseTag::DegradedOpen,
            to: SessionPhaseTag::Established,
            trigger: TransitionTrigger::DegradedRecovery,
        },
        // DegradedOpen → Closing: operator closes degraded session
        PhaseTransition {
            from: SessionPhaseTag::DegradedOpen,
            to: SessionPhaseTag::Closing,
            trigger: TransitionTrigger::CloseInitiated,
        },
        // DegradedOpen → Closed: expiry
        PhaseTransition {
            from: SessionPhaseTag::DegradedOpen,
            to: SessionPhaseTag::Closed,
            trigger: TransitionTrigger::SessionExpired {
                reason: String::new(),
            },
        },
        // Closing → Closed: drain done
        PhaseTransition {
            from: SessionPhaseTag::Closing,
            to: SessionPhaseTag::Closed,
            trigger: TransitionTrigger::DrainCompleted,
        },
        // Closing → Closed: drain timeout (treated as expiry)
        PhaseTransition {
            from: SessionPhaseTag::Closing,
            to: SessionPhaseTag::Closed,
            trigger: TransitionTrigger::SessionExpired {
                reason: String::new(),
            },
        },
    ]
}

/// Check whether a given phase transition is valid per the protocol spec.
pub fn is_valid_transition(from: SessionPhaseTag, to: SessionPhaseTag) -> bool {
    // Closed is terminal — nothing can leave it.
    if from == SessionPhaseTag::Closed {
        return false;
    }
    // Self-loops are never valid transitions.
    if from == to {
        return false;
    }
    // Check against the canonical table.  We match on discriminant only,
    // not on trigger payload, since the trigger data varies per instance.
    valid_transitions()
        .iter()
        .any(|t| t.from == from && t.to == to)
}

// ---------------------------------------------------------------------------
// Key schedule
// ---------------------------------------------------------------------------

/// The key schedule defines how session keys are derived from handshake
/// material.  Each stage produces a distinct key bound to the session
/// identity, the epoch, and the stage purpose.
///
/// Stage 0 (handshake): Master secret derived from request+response transcripts.
/// Stage 1 (data-plane MAC): Derived from master secret + direction tag.
/// Stage 2 (AEAD encryption): Derived from master secret + "encrypt" tag.
/// Stage 3 (backpressure signing): Derived from master secret + "bp-sign" tag.
///
/// Each derived key is epoch-scoped: if the security epoch advances
/// mid-session, the session must re-key or transition to degraded mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionKeySchedule {
    /// The security epoch at which this key schedule was derived.
    pub epoch: SecurityEpoch,

    /// The session ID bound into each key derivation.
    pub session_id: String,

    /// Extension identity bound into each key derivation.
    pub extension_id: String,

    /// Host identity bound into each key derivation.
    pub host_id: String,

    /// Stages that have been derived.
    pub derived_stages: Vec<KeyScheduleStage>,

    /// Content hash of the handshake transcript that seeded stage 0.
    pub handshake_transcript_hash: ContentHash,
}

/// A single stage in the key schedule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyScheduleStage {
    /// Stage number (0 = master, 1 = MAC, 2 = encrypt, 3 = bp-sign).
    pub stage: u32,

    /// Human-readable purpose for auditing.
    pub purpose: KeyStagePurpose,

    /// Domain separation label used in derivation.
    pub domain_label: String,

    /// Hash of the derived key material (NOT the key itself).
    /// Used for audit without leaking key bytes.
    pub key_fingerprint: ContentHash,

    /// The epoch in which this stage was derived.
    pub epoch: SecurityEpoch,
}

/// Purpose discriminant for key schedule stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum KeyStagePurpose {
    /// Stage 0: master secret from handshake transcript.
    MasterSecret,
    /// Stage 1: per-message MAC key.
    DataPlaneMac,
    /// Stage 2: AEAD encryption key.
    DataPlaneEncrypt,
    /// Stage 3: backpressure signing key.
    BackpressureSign,
}

impl KeyStagePurpose {
    pub fn domain_label(self) -> &'static str {
        match self {
            Self::MasterSecret => "franken::hsp::master",
            Self::DataPlaneMac => "franken::hsp::mac",
            Self::DataPlaneEncrypt => "franken::hsp::encrypt",
            Self::BackpressureSign => "franken::hsp::bp-sign",
        }
    }

    pub const ALL: &'static [KeyStagePurpose] = &[
        KeyStagePurpose::MasterSecret,
        KeyStagePurpose::DataPlaneMac,
        KeyStagePurpose::DataPlaneEncrypt,
        KeyStagePurpose::BackpressureSign,
    ];
}

impl fmt::Display for KeyStagePurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::MasterSecret => "master_secret",
            Self::DataPlaneMac => "data_plane_mac",
            Self::DataPlaneEncrypt => "data_plane_encrypt",
            Self::BackpressureSign => "backpressure_sign",
        };
        f.write_str(s)
    }
}

impl SessionKeySchedule {
    /// Create a new key schedule from handshake material.
    pub fn new(
        epoch: SecurityEpoch,
        session_id: String,
        extension_id: String,
        host_id: String,
        handshake_transcript_hash: ContentHash,
    ) -> Self {
        Self {
            epoch,
            session_id,
            extension_id,
            host_id,
            derived_stages: Vec::new(),
            handshake_transcript_hash,
        }
    }

    /// Record that a key stage has been derived.
    pub fn record_stage(&mut self, purpose: KeyStagePurpose, key_fingerprint: ContentHash) {
        let stage = KeyScheduleStage {
            stage: purpose as u32,
            purpose,
            domain_label: purpose.domain_label().to_string(),
            key_fingerprint,
            epoch: self.epoch,
        };
        self.derived_stages.push(stage);
    }

    /// Whether all 4 stages have been derived.
    pub fn is_complete(&self) -> bool {
        self.derived_stages.len() == KeyStagePurpose::ALL.len()
    }

    /// Whether the schedule is valid for the given epoch.
    pub fn is_valid_for_epoch(&self, current_epoch: SecurityEpoch) -> bool {
        self.epoch == current_epoch
    }

    /// Compute a binding hash that covers all derivation inputs.
    pub fn binding_hash(&self) -> ContentHash {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"franken::key_schedule::");
        preimage.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        preimage.extend_from_slice(self.session_id.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(self.extension_id.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(self.host_id.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(self.handshake_transcript_hash.as_bytes());
        ContentHash::compute(&preimage)
    }
}

// ---------------------------------------------------------------------------
// Anti-replay ledger
// ---------------------------------------------------------------------------

/// Anti-replay verdict for an incoming message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayVerdict {
    /// First time this sequence has been seen — accept.
    Accept,
    /// This exact sequence was already processed — reject.
    Replay,
    /// Sequence is below the window floor — reject (expired window).
    BelowFloor,
    /// Sequence is above the window ceiling — reject (too far ahead).
    AboveCeiling,
}

impl fmt::Display for ReplayVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Accept => "accept",
            Self::Replay => "replay",
            Self::BelowFloor => "below_floor",
            Self::AboveCeiling => "above_ceiling",
        };
        f.write_str(s)
    }
}

/// A single entry in the anti-replay ledger recording a processed message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayLedgerEntry {
    /// The session this entry belongs to.
    pub session_id: String,
    /// The sequence number of the processed message.
    pub sequence: u64,
    /// Content hash of the envelope for audit.
    pub envelope_hash: ContentHash,
    /// Tick at which the message was accepted.
    pub accepted_at_tick: u64,
    /// MAC of the envelope (for retroactive verification).
    pub mac: AuthenticityHash,
}

/// Persistent anti-replay ledger with sliding window.
///
/// Maintains a bitmap-style sliding window over sequence numbers.
/// The window has a floor (the lowest sequence that can still be checked)
/// and a ceiling (the highest sequence we've ever seen).  Sequences below
/// the floor are unconditionally rejected — the window has moved past them.
///
/// The ledger is append-only for audit purposes: every accept/reject
/// decision is recorded in `audit_trail`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiReplayLedger {
    /// Session this ledger belongs to.
    session_id: String,

    /// The lowest sequence number still inside the window.
    window_floor: u64,

    /// The highest sequence number seen so far.
    window_ceiling: u64,

    /// Maximum window width.  If `ceiling - floor > window_width`,
    /// the floor advances to `ceiling - window_width`.
    window_width: u64,

    /// Set of accepted sequence numbers within the window.
    /// Uses BTreeMap<u64, ()> for deterministic serialization.
    accepted_sequences: BTreeMap<u64, ()>,

    /// Running count of replays detected.
    total_replay_count: u64,

    /// Running count of below-floor rejections.
    total_below_floor_count: u64,

    /// Running count of above-ceiling rejections.
    total_above_ceiling_count: u64,

    /// Total accepted messages.
    total_accepted: u64,

    /// Audit trail of recent decisions (bounded by `max_audit_entries`).
    audit_trail: Vec<ReplayAuditEntry>,

    /// Maximum audit trail length before oldest entries are evicted.
    max_audit_entries: usize,
}

/// An audit entry recording a replay-check decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayAuditEntry {
    pub sequence: u64,
    pub verdict: ReplayVerdict,
    pub checked_at_tick: u64,
    pub envelope_hash: Option<ContentHash>,
}

impl AntiReplayLedger {
    /// Create a new anti-replay ledger for a session.
    pub fn new(session_id: String, window_width: u64, max_audit_entries: usize) -> Self {
        Self {
            session_id,
            window_floor: 0,
            window_ceiling: 0,
            window_width: window_width.max(1),
            accepted_sequences: BTreeMap::new(),
            total_replay_count: 0,
            total_below_floor_count: 0,
            total_above_ceiling_count: 0,
            total_accepted: 0,
            audit_trail: Vec::new(),
            max_audit_entries,
        }
    }

    /// Check and record a sequence number.
    ///
    /// Returns `Accept` if the sequence is new and within the window.
    /// Advances the window if necessary.  All decisions are recorded
    /// in the audit trail.
    pub fn check_and_record(
        &mut self,
        sequence: u64,
        tick: u64,
        envelope_hash: Option<ContentHash>,
    ) -> ReplayVerdict {
        let verdict = self.check_sequence(sequence);

        if verdict == ReplayVerdict::Accept {
            self.accepted_sequences.insert(sequence, ());
            self.total_accepted += 1;

            // Advance ceiling if necessary.
            if sequence > self.window_ceiling {
                self.window_ceiling = sequence;
            }

            // Advance floor if window has grown past width.
            if self.window_ceiling > self.window_width {
                let new_floor = self.window_ceiling - self.window_width;
                if new_floor > self.window_floor {
                    // Evict sequences below new floor.
                    let old_floor = self.window_floor;
                    self.window_floor = new_floor;
                    // Remove entries that fell below the floor.
                    let to_remove: Vec<u64> = self
                        .accepted_sequences
                        .range(old_floor..new_floor)
                        .map(|(&seq, _)| seq)
                        .collect();
                    for seq in to_remove {
                        self.accepted_sequences.remove(&seq);
                    }
                }
            }
        } else {
            match verdict {
                ReplayVerdict::Replay => self.total_replay_count += 1,
                ReplayVerdict::BelowFloor => self.total_below_floor_count += 1,
                ReplayVerdict::AboveCeiling => self.total_above_ceiling_count += 1,
                ReplayVerdict::Accept => {}
            }
        }

        // Record in audit trail.
        let entry = ReplayAuditEntry {
            sequence,
            verdict,
            checked_at_tick: tick,
            envelope_hash,
        };
        self.audit_trail.push(entry);
        if self.audit_trail.len() > self.max_audit_entries {
            self.audit_trail.remove(0);
        }

        verdict
    }

    fn check_sequence(&self, sequence: u64) -> ReplayVerdict {
        // Below floor — unconditionally reject.
        if sequence < self.window_floor {
            return ReplayVerdict::BelowFloor;
        }

        // Above ceiling + window_width — too far ahead, reject.
        if self.window_ceiling > 0
            && sequence > self.window_ceiling.saturating_add(self.window_width)
        {
            return ReplayVerdict::AboveCeiling;
        }

        // Already seen — replay.
        if self.accepted_sequences.contains_key(&sequence) {
            return ReplayVerdict::Replay;
        }

        ReplayVerdict::Accept
    }

    /// The current window floor.
    pub fn window_floor(&self) -> u64 {
        self.window_floor
    }

    /// The current window ceiling.
    pub fn window_ceiling(&self) -> u64 {
        self.window_ceiling
    }

    /// Total accepted messages.
    pub fn total_accepted(&self) -> u64 {
        self.total_accepted
    }

    /// Total replays detected.
    pub fn total_replays(&self) -> u64 {
        self.total_replay_count
    }

    /// Total below-floor rejections.
    pub fn total_below_floor(&self) -> u64 {
        self.total_below_floor_count
    }

    /// Total messages checked (accepted + all rejections).
    pub fn total_checked(&self) -> u64 {
        self.total_accepted
            + self.total_replay_count
            + self.total_below_floor_count
            + self.total_above_ceiling_count
    }

    /// The session ID this ledger belongs to.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Number of sequences currently in the window.
    pub fn window_size(&self) -> usize {
        self.accepted_sequences.len()
    }

    /// The audit trail (most recent `max_audit_entries` decisions).
    pub fn audit_trail(&self) -> &[ReplayAuditEntry] {
        &self.audit_trail
    }

    /// Compute a summary hash of the ledger state for checkpointing.
    pub fn state_hash(&self) -> ContentHash {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"franken::replay_ledger::");
        preimage.extend_from_slice(self.session_id.as_bytes());
        preimage.push(0);
        preimage.extend_from_slice(&self.window_floor.to_le_bytes());
        preimage.extend_from_slice(&self.window_ceiling.to_le_bytes());
        preimage.extend_from_slice(&self.total_accepted.to_le_bytes());
        preimage.extend_from_slice(&self.total_replay_count.to_le_bytes());
        ContentHash::compute(&preimage)
    }
}

// ---------------------------------------------------------------------------
// Degraded-mode policy
// ---------------------------------------------------------------------------

/// Degraded-mode severity levels.
///
/// When a session cannot maintain full security guarantees, the degraded-mode
/// policy governs what operations are permitted and what must be blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DegradedSeverity {
    /// MAC verification still passes but epoch has advanced (stale key).
    /// Data can flow but must be re-keyed before new sensitive operations.
    StaleKey,

    /// MAC verification failed on a subset of messages.  Data flow is
    /// paused for affected messages; non-affected messages may continue.
    PartialMacFailure,

    /// The session key is compromised or the peer's identity cannot be
    /// verified.  All data flow is blocked; only close operations permitted.
    IdentityCompromised,
}

impl fmt::Display for DegradedSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::StaleKey => "stale_key",
            Self::PartialMacFailure => "partial_mac_failure",
            Self::IdentityCompromised => "identity_compromised",
        };
        f.write_str(s)
    }
}

/// Policy governing what operations are allowed in degraded mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DegradedModePolicy {
    /// The severity level that triggered degraded mode.
    pub severity: DegradedSeverity,

    /// Whether read-only hostcalls (queries) are permitted.
    pub allow_readonly_hostcalls: bool,

    /// Whether write hostcalls (mutations) are permitted.
    pub allow_write_hostcalls: bool,

    /// Whether new extension lifecycle operations are permitted.
    pub allow_lifecycle_operations: bool,

    /// Maximum number of messages permitted in degraded mode before
    /// forced close.
    pub max_degraded_messages: u64,

    /// Maximum ticks in degraded mode before forced close.
    pub max_degraded_ticks: u64,

    /// Whether the session should attempt automatic re-key.
    pub auto_rekey: bool,

    /// Whether to emit evidence entries for degraded-mode operation.
    pub emit_evidence: bool,
}

impl DegradedModePolicy {
    /// Strict policy: no data flow permitted, evidence required.
    pub fn strict(severity: DegradedSeverity) -> Self {
        Self {
            severity,
            allow_readonly_hostcalls: false,
            allow_write_hostcalls: false,
            allow_lifecycle_operations: false,
            max_degraded_messages: 0,
            max_degraded_ticks: 0,
            auto_rekey: false,
            emit_evidence: true,
        }
    }

    /// Permissive policy: read-only hostcalls allowed, writes blocked.
    pub fn permissive(severity: DegradedSeverity) -> Self {
        Self {
            severity,
            allow_readonly_hostcalls: true,
            allow_write_hostcalls: false,
            allow_lifecycle_operations: false,
            max_degraded_messages: 100,
            max_degraded_ticks: 5_000,
            auto_rekey: true,
            emit_evidence: true,
        }
    }

    /// Default policy for a given severity.
    pub fn for_severity(severity: DegradedSeverity) -> Self {
        match severity {
            DegradedSeverity::StaleKey => Self {
                severity,
                allow_readonly_hostcalls: true,
                allow_write_hostcalls: true,
                allow_lifecycle_operations: false,
                max_degraded_messages: 1_000,
                max_degraded_ticks: 10_000,
                auto_rekey: true,
                emit_evidence: true,
            },
            DegradedSeverity::PartialMacFailure => Self::permissive(severity),
            DegradedSeverity::IdentityCompromised => Self::strict(severity),
        }
    }

    /// Whether any data-plane operation is permitted under this policy.
    pub fn permits_any_data(&self) -> bool {
        self.allow_readonly_hostcalls || self.allow_write_hostcalls
    }

    /// Check whether a specific operation kind is allowed.
    pub fn is_operation_allowed(&self, op: DegradedOperationKind) -> bool {
        match op {
            DegradedOperationKind::ReadHostcall => self.allow_readonly_hostcalls,
            DegradedOperationKind::WriteHostcall => self.allow_write_hostcalls,
            DegradedOperationKind::LifecycleOperation => self.allow_lifecycle_operations,
            DegradedOperationKind::Close => true, // Always allowed
        }
    }
}

/// Kind of operation that may be attempted in degraded mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DegradedOperationKind {
    ReadHostcall,
    WriteHostcall,
    LifecycleOperation,
    Close,
}

impl fmt::Display for DegradedOperationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ReadHostcall => "read_hostcall",
            Self::WriteHostcall => "write_hostcall",
            Self::LifecycleOperation => "lifecycle_operation",
            Self::Close => "close",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// Protocol error
// ---------------------------------------------------------------------------

/// Errors from protocol-level session operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolError {
    /// Attempted an illegal phase transition.
    IllegalTransition {
        from: SessionPhaseTag,
        to: SessionPhaseTag,
    },
    /// Key schedule is not valid for the current epoch.
    EpochMismatch {
        schedule_epoch: SecurityEpoch,
        current_epoch: SecurityEpoch,
    },
    /// Key schedule is incomplete (not all stages derived).
    IncompleteKeySchedule { stages_derived: usize },
    /// Anti-replay check failed.
    ReplayRejected {
        sequence: u64,
        verdict: ReplayVerdict,
    },
    /// Operation not permitted in degraded mode.
    DegradedModeBlocked {
        operation: DegradedOperationKind,
        severity: DegradedSeverity,
    },
    /// Session has exceeded degraded-mode budget.
    DegradedBudgetExhausted {
        messages_used: u64,
        messages_limit: u64,
    },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IllegalTransition { from, to } => {
                write!(f, "illegal session transition: {from} -> {to}")
            }
            Self::EpochMismatch {
                schedule_epoch,
                current_epoch,
            } => write!(
                f,
                "key schedule epoch {} != current epoch {}",
                schedule_epoch.as_u64(),
                current_epoch.as_u64()
            ),
            Self::IncompleteKeySchedule { stages_derived } => {
                write!(f, "key schedule incomplete: {stages_derived}/4 stages")
            }
            Self::ReplayRejected { sequence, verdict } => {
                write!(f, "replay rejected: seq={sequence}, verdict={verdict}")
            }
            Self::DegradedModeBlocked {
                operation,
                severity,
            } => {
                write!(
                    f,
                    "operation {operation} blocked in degraded mode (severity={severity})"
                )
            }
            Self::DegradedBudgetExhausted {
                messages_used,
                messages_limit,
            } => write!(
                f,
                "degraded-mode budget exhausted: {messages_used}/{messages_limit}"
            ),
        }
    }
}

impl std::error::Error for ProtocolError {}

// ---------------------------------------------------------------------------
// Protocol state machine
// ---------------------------------------------------------------------------

/// The session protocol state machine combining typestate, key schedule,
/// anti-replay ledger, and degraded-mode policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProtocolState {
    /// Current phase.
    pub phase: SessionPhaseTag,

    /// Session identity.
    pub session_id: String,

    /// Extension identity.
    pub extension_id: String,

    /// Host identity.
    pub host_id: String,

    /// The key schedule (populated after handshake).
    pub key_schedule: Option<SessionKeySchedule>,

    /// The anti-replay ledger.
    pub replay_ledger: AntiReplayLedger,

    /// Degraded-mode policy (populated when entering degraded mode).
    pub degraded_policy: Option<DegradedModePolicy>,

    /// Messages sent/received in degraded mode (for budget enforcement).
    pub degraded_messages: u64,

    /// Tick at which degraded mode was entered.
    pub degraded_entered_tick: Option<u64>,

    /// History of phase transitions.
    pub transition_history: Vec<TransitionRecord>,
}

/// A recorded phase transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionRecord {
    pub from: SessionPhaseTag,
    pub to: SessionPhaseTag,
    pub trigger: TransitionTrigger,
    pub tick: u64,
}

impl SessionProtocolState {
    /// Create a new protocol state in the `Uninit` phase.
    pub fn new(
        session_id: String,
        extension_id: String,
        host_id: String,
        replay_window_width: u64,
        max_audit_entries: usize,
    ) -> Self {
        let replay_ledger =
            AntiReplayLedger::new(session_id.clone(), replay_window_width, max_audit_entries);

        Self {
            phase: SessionPhaseTag::Uninit,
            session_id,
            extension_id,
            host_id,
            key_schedule: None,
            replay_ledger,
            degraded_policy: None,
            degraded_messages: 0,
            degraded_entered_tick: None,
            transition_history: Vec::new(),
        }
    }

    /// Attempt a phase transition.
    pub fn transition(
        &mut self,
        to: SessionPhaseTag,
        trigger: TransitionTrigger,
        tick: u64,
    ) -> Result<(), ProtocolError> {
        if !is_valid_transition(self.phase, to) {
            return Err(ProtocolError::IllegalTransition {
                from: self.phase,
                to,
            });
        }

        let record = TransitionRecord {
            from: self.phase,
            to,
            trigger,
            tick,
        };
        self.transition_history.push(record);
        self.phase = to;

        // Clear degraded state on recovery.
        if to == SessionPhaseTag::Established {
            self.degraded_policy = None;
            self.degraded_messages = 0;
            self.degraded_entered_tick = None;
        }

        Ok(())
    }

    /// Attach a key schedule after handshake completion.
    pub fn attach_key_schedule(
        &mut self,
        schedule: SessionKeySchedule,
    ) -> Result<(), ProtocolError> {
        if !schedule.is_complete() {
            return Err(ProtocolError::IncompleteKeySchedule {
                stages_derived: schedule.derived_stages.len(),
            });
        }
        self.key_schedule = Some(schedule);
        Ok(())
    }

    /// Enter degraded mode with the specified severity.
    pub fn enter_degraded(
        &mut self,
        severity: DegradedSeverity,
        reason: String,
        tick: u64,
    ) -> Result<(), ProtocolError> {
        let policy = DegradedModePolicy::for_severity(severity);
        self.degraded_policy = Some(policy);
        self.degraded_messages = 0;
        self.degraded_entered_tick = Some(tick);
        self.transition(
            SessionPhaseTag::DegradedOpen,
            TransitionTrigger::SecurityDegradation { reason },
            tick,
        )
    }

    /// Check whether an operation is permitted in the current phase.
    pub fn check_operation(
        &self,
        op: DegradedOperationKind,
        tick: u64,
    ) -> Result<(), ProtocolError> {
        match self.phase {
            SessionPhaseTag::Established => Ok(()),
            SessionPhaseTag::DegradedOpen => {
                let fallback = DegradedModePolicy::strict(DegradedSeverity::IdentityCompromised);
                let policy = self.degraded_policy.as_ref().unwrap_or(&fallback);

                if !policy.is_operation_allowed(op) {
                    return Err(ProtocolError::DegradedModeBlocked {
                        operation: op,
                        severity: policy.severity,
                    });
                }

                // Close is always allowed and bypasses budget checks.
                if matches!(op, DegradedOperationKind::Close) {
                    return Ok(());
                }

                // Check message budget.
                if self.degraded_messages >= policy.max_degraded_messages {
                    return Err(ProtocolError::DegradedBudgetExhausted {
                        messages_used: self.degraded_messages,
                        messages_limit: policy.max_degraded_messages,
                    });
                }

                // Check time budget.
                if let Some(entered) = self.degraded_entered_tick
                    && tick.saturating_sub(entered) > policy.max_degraded_ticks
                {
                    return Err(ProtocolError::DegradedBudgetExhausted {
                        messages_used: self.degraded_messages,
                        messages_limit: policy.max_degraded_messages,
                    });
                }

                Ok(())
            }
            _ => Err(ProtocolError::IllegalTransition {
                from: self.phase,
                to: self.phase,
            }),
        }
    }

    /// Check a sequence number against the anti-replay ledger.
    pub fn check_replay(
        &mut self,
        sequence: u64,
        tick: u64,
        envelope_hash: Option<ContentHash>,
    ) -> Result<(), ProtocolError> {
        let verdict = self
            .replay_ledger
            .check_and_record(sequence, tick, envelope_hash);
        if verdict != ReplayVerdict::Accept {
            return Err(ProtocolError::ReplayRejected { sequence, verdict });
        }
        Ok(())
    }

    /// Record a data-plane message in degraded mode (for budget tracking).
    pub fn record_degraded_message(&mut self) {
        if self.phase == SessionPhaseTag::DegradedOpen {
            self.degraded_messages += 1;
        }
    }

    /// Validate that the key schedule matches the current epoch.
    pub fn validate_epoch(&self, current_epoch: SecurityEpoch) -> Result<(), ProtocolError> {
        if let Some(ref schedule) = self.key_schedule
            && !schedule.is_valid_for_epoch(current_epoch)
        {
            return Err(ProtocolError::EpochMismatch {
                schedule_epoch: schedule.epoch,
                current_epoch,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Corpus / runner / evidence bundle
// ---------------------------------------------------------------------------

/// A specimen from the hostcall-session-protocol corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HspSpecimen {
    /// Human-readable name for this specimen.
    pub name: String,
    /// Category of the specimen.
    pub family: HspSpecimenFamily,
    /// The session protocol state after applying the specimen's scenario.
    pub final_state: SessionProtocolState,
    /// Transition count observed during the scenario.
    pub transition_count: usize,
    /// Whether the scenario completed without protocol errors.
    pub clean_completion: bool,
    /// Content hash of the specimen for reproducibility.
    pub content_hash: ContentHash,
}

/// Specimen family discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HspSpecimenFamily {
    /// Normal handshake → established → close lifecycle.
    HappyPath,
    /// Handshake rejection scenario.
    HandshakeRejection,
    /// Degraded-mode entry and recovery.
    DegradedRecovery,
    /// Degraded-mode budget exhaustion.
    DegradedBudgetExhaustion,
    /// Anti-replay window scenarios.
    AntiReplay,
    /// Epoch mismatch scenarios.
    EpochMismatch,
    /// Invalid transition rejection.
    InvalidTransition,
    /// Full lifecycle with key schedule.
    FullLifecycle,
}

impl fmt::Display for HspSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::HappyPath => "happy_path",
            Self::HandshakeRejection => "handshake_rejection",
            Self::DegradedRecovery => "degraded_recovery",
            Self::DegradedBudgetExhaustion => "degraded_budget_exhaustion",
            Self::AntiReplay => "anti_replay",
            Self::EpochMismatch => "epoch_mismatch",
            Self::InvalidTransition => "invalid_transition",
            Self::FullLifecycle => "full_lifecycle",
        };
        f.write_str(s)
    }
}

impl HspSpecimenFamily {
    pub const ALL: &'static [HspSpecimenFamily] = &[
        HspSpecimenFamily::HappyPath,
        HspSpecimenFamily::HandshakeRejection,
        HspSpecimenFamily::DegradedRecovery,
        HspSpecimenFamily::DegradedBudgetExhaustion,
        HspSpecimenFamily::AntiReplay,
        HspSpecimenFamily::EpochMismatch,
        HspSpecimenFamily::InvalidTransition,
        HspSpecimenFamily::FullLifecycle,
    ];
}

fn specimen_hash(name: &str, phase: SessionPhaseTag, transitions: usize) -> ContentHash {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"franken::hsp_specimen::");
    buf.extend_from_slice(name.as_bytes());
    buf.push(0);
    buf.extend_from_slice(phase.to_string().as_bytes());
    buf.push(0);
    buf.extend_from_slice(&transitions.to_le_bytes());
    ContentHash::compute(&buf)
}

/// Build the hostcall session protocol corpus.
pub fn hsp_corpus() -> Vec<HspSpecimen> {
    let mut corpus = Vec::new();

    // 1. Happy path: uninit → negotiating → established → closing → closed
    {
        let mut state =
            SessionProtocolState::new("spec-happy".into(), "ext-a".into(), "host-b".into(), 64, 50);
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
            .transition(
                SessionPhaseTag::Closing,
                TransitionTrigger::CloseInitiated,
                3,
            )
            .unwrap();
        state
            .transition(
                SessionPhaseTag::Closed,
                TransitionTrigger::DrainCompleted,
                4,
            )
            .unwrap();
        let tc = state.transition_history.len();
        corpus.push(HspSpecimen {
            name: "happy_path_full".into(),
            family: HspSpecimenFamily::HappyPath,
            content_hash: specimen_hash("happy_path_full", state.phase, tc),
            transition_count: tc,
            clean_completion: true,
            final_state: state,
        });
    }

    // 2. Handshake rejection
    {
        let mut state = SessionProtocolState::new(
            "spec-reject".into(),
            "ext-a".into(),
            "host-b".into(),
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
                SessionPhaseTag::Closed,
                TransitionTrigger::HandshakeRejected,
                2,
            )
            .unwrap();
        let tc = state.transition_history.len();
        corpus.push(HspSpecimen {
            name: "handshake_rejected".into(),
            family: HspSpecimenFamily::HandshakeRejection,
            content_hash: specimen_hash("handshake_rejected", state.phase, tc),
            transition_count: tc,
            clean_completion: true,
            final_state: state,
        });
    }

    // 3. Degraded recovery: established → degraded → established
    {
        let mut state = SessionProtocolState::new(
            "spec-degraded-recovery".into(),
            "ext-a".into(),
            "host-b".into(),
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
            .enter_degraded(DegradedSeverity::StaleKey, "epoch_advanced".into(), 3)
            .unwrap();
        state
            .transition(
                SessionPhaseTag::Established,
                TransitionTrigger::DegradedRecovery,
                4,
            )
            .unwrap();
        let tc = state.transition_history.len();
        corpus.push(HspSpecimen {
            name: "degraded_recovery".into(),
            family: HspSpecimenFamily::DegradedRecovery,
            content_hash: specimen_hash("degraded_recovery", state.phase, tc),
            transition_count: tc,
            clean_completion: true,
            final_state: state,
        });
    }

    // 4. Degraded budget exhaustion
    {
        let mut state = SessionProtocolState::new(
            "spec-degraded-budget".into(),
            "ext-a".into(),
            "host-b".into(),
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
            .enter_degraded(DegradedSeverity::PartialMacFailure, "mac_fail".into(), 3)
            .unwrap();
        let limit = state
            .degraded_policy
            .as_ref()
            .map_or(0, |p| p.max_degraded_messages);
        for _ in 0..limit {
            state.record_degraded_message();
        }
        let exhausted = state
            .check_operation(DegradedOperationKind::ReadHostcall, 4)
            .is_err();
        let tc = state.transition_history.len();
        corpus.push(HspSpecimen {
            name: "degraded_budget_exhausted".into(),
            family: HspSpecimenFamily::DegradedBudgetExhaustion,
            content_hash: specimen_hash("degraded_budget_exhausted", state.phase, tc),
            transition_count: tc,
            clean_completion: exhausted,
            final_state: state,
        });
    }

    // 5. Anti-replay: sequential + replay detection
    {
        let mut state = SessionProtocolState::new(
            "spec-replay".into(),
            "ext-a".into(),
            "host-b".into(),
            32,
            50,
        );
        for seq in 1..=10 {
            state.check_replay(seq, seq * 10, None).unwrap();
        }
        let replay_err = state.check_replay(5, 110, None).is_err();
        let tc = state.transition_history.len();
        corpus.push(HspSpecimen {
            name: "anti_replay_detection".into(),
            family: HspSpecimenFamily::AntiReplay,
            content_hash: specimen_hash("anti_replay_detection", state.phase, tc),
            transition_count: tc,
            clean_completion: replay_err,
            final_state: state,
        });
    }

    // 6. Anti-replay: window advance
    {
        let mut state = SessionProtocolState::new(
            "spec-replay-window".into(),
            "ext-a".into(),
            "host-b".into(),
            4,
            50,
        );
        for seq in 1..=20 {
            let _ = state.check_replay(seq, seq, None);
        }
        let below_floor = state.check_replay(1, 21, None).is_err();
        let tc = state.transition_history.len();
        corpus.push(HspSpecimen {
            name: "anti_replay_window_advance".into(),
            family: HspSpecimenFamily::AntiReplay,
            content_hash: specimen_hash("anti_replay_window_advance", state.phase, tc),
            transition_count: tc,
            clean_completion: below_floor,
            final_state: state,
        });
    }

    // 7. Epoch mismatch
    {
        let mut state =
            SessionProtocolState::new("spec-epoch".into(), "ext-a".into(), "host-b".into(), 64, 50);
        let epoch = SecurityEpoch::from_raw(1);
        let mut ks = SessionKeySchedule::new(
            epoch,
            "spec-epoch".into(),
            "ext-a".into(),
            "host-b".into(),
            ContentHash::compute(b"epoch-test"),
        );
        for purpose in KeyStagePurpose::ALL {
            ks.record_stage(
                *purpose,
                ContentHash::compute(purpose.domain_label().as_bytes()),
            );
        }
        state.attach_key_schedule(ks).unwrap();
        let mismatch = state.validate_epoch(SecurityEpoch::from_raw(99)).is_err();
        let tc = state.transition_history.len();
        corpus.push(HspSpecimen {
            name: "epoch_mismatch".into(),
            family: HspSpecimenFamily::EpochMismatch,
            content_hash: specimen_hash("epoch_mismatch", state.phase, tc),
            transition_count: tc,
            clean_completion: mismatch,
            final_state: state,
        });
    }

    // 8. Invalid transition rejection
    {
        let mut state = SessionProtocolState::new(
            "spec-invalid".into(),
            "ext-a".into(),
            "host-b".into(),
            64,
            50,
        );
        let err = state
            .transition(
                SessionPhaseTag::Established,
                TransitionTrigger::HandshakeCompleted,
                1,
            )
            .is_err();
        let tc = state.transition_history.len();
        corpus.push(HspSpecimen {
            name: "invalid_transition".into(),
            family: HspSpecimenFamily::InvalidTransition,
            content_hash: specimen_hash("invalid_transition", state.phase, tc),
            transition_count: tc,
            clean_completion: err,
            final_state: state,
        });
    }

    // 9. Full lifecycle with key schedule, replay, degraded, close
    {
        let epoch = SecurityEpoch::from_raw(1);
        let mut state =
            SessionProtocolState::new("spec-full".into(), "ext-a".into(), "host-b".into(), 64, 50);
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
        let mut ks = SessionKeySchedule::new(
            epoch,
            "spec-full".into(),
            "ext-a".into(),
            "host-b".into(),
            ContentHash::compute(b"full-test"),
        );
        for purpose in KeyStagePurpose::ALL {
            ks.record_stage(
                *purpose,
                ContentHash::compute(purpose.domain_label().as_bytes()),
            );
        }
        state.attach_key_schedule(ks).unwrap();
        state.check_replay(1, 10, None).unwrap();
        state.check_replay(2, 20, None).unwrap();
        state
            .enter_degraded(DegradedSeverity::StaleKey, "rekey".into(), 30)
            .unwrap();
        state
            .transition(
                SessionPhaseTag::Established,
                TransitionTrigger::DegradedRecovery,
                40,
            )
            .unwrap();
        state
            .transition(
                SessionPhaseTag::Closing,
                TransitionTrigger::CloseInitiated,
                50,
            )
            .unwrap();
        state
            .transition(
                SessionPhaseTag::Closed,
                TransitionTrigger::DrainCompleted,
                60,
            )
            .unwrap();
        let tc = state.transition_history.len();
        corpus.push(HspSpecimen {
            name: "full_lifecycle".into(),
            family: HspSpecimenFamily::FullLifecycle,
            content_hash: specimen_hash("full_lifecycle", state.phase, tc),
            transition_count: tc,
            clean_completion: true,
            final_state: state,
        });
    }

    // 10. Expiry from established
    {
        let mut state = SessionProtocolState::new(
            "spec-expiry".into(),
            "ext-a".into(),
            "host-b".into(),
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
            .transition(
                SessionPhaseTag::Closed,
                TransitionTrigger::SessionExpired {
                    reason: "ttl".into(),
                },
                3,
            )
            .unwrap();
        let tc = state.transition_history.len();
        corpus.push(HspSpecimen {
            name: "session_expiry".into(),
            family: HspSpecimenFamily::HappyPath,
            content_hash: specimen_hash("session_expiry", state.phase, tc),
            transition_count: tc,
            clean_completion: true,
            final_state: state,
        });
    }

    // 11. Degraded close (without recovery)
    {
        let mut state = SessionProtocolState::new(
            "spec-degraded-close".into(),
            "ext-a".into(),
            "host-b".into(),
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
            .enter_degraded(
                DegradedSeverity::IdentityCompromised,
                "compromised".into(),
                3,
            )
            .unwrap();
        state
            .transition(
                SessionPhaseTag::Closing,
                TransitionTrigger::CloseInitiated,
                4,
            )
            .unwrap();
        state
            .transition(
                SessionPhaseTag::Closed,
                TransitionTrigger::DrainCompleted,
                5,
            )
            .unwrap();
        let tc = state.transition_history.len();
        corpus.push(HspSpecimen {
            name: "degraded_close".into(),
            family: HspSpecimenFamily::DegradedRecovery,
            content_hash: specimen_hash("degraded_close", state.phase, tc),
            transition_count: tc,
            clean_completion: true,
            final_state: state,
        });
    }

    // 12. Replay threshold breach
    {
        let mut state = SessionProtocolState::new(
            "spec-replay-breach".into(),
            "ext-a".into(),
            "host-b".into(),
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
            .transition(
                SessionPhaseTag::Closed,
                TransitionTrigger::ReplayThresholdBreached {
                    drop_count: 50,
                    window_ticks: 100,
                },
                3,
            )
            .unwrap();
        let tc = state.transition_history.len();
        corpus.push(HspSpecimen {
            name: "replay_threshold_breach".into(),
            family: HspSpecimenFamily::AntiReplay,
            content_hash: specimen_hash("replay_threshold_breach", state.phase, tc),
            transition_count: tc,
            clean_completion: true,
            final_state: state,
        });
    }

    corpus
}

/// Runner result from the corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HspRunnerResult {
    pub specimen_count: usize,
    pub families_covered: Vec<HspSpecimenFamily>,
    pub all_clean: bool,
    pub terminal_count: usize,
    pub content_hash: ContentHash,
}

/// Run the corpus and produce a runner result.
pub fn run_hsp_corpus() -> HspRunnerResult {
    let corpus = hsp_corpus();
    let specimen_count = corpus.len();

    let mut families: std::collections::BTreeSet<HspSpecimenFamily> =
        std::collections::BTreeSet::new();
    let mut all_clean = true;
    let mut terminal_count = 0;

    let mut hash_preimage = Vec::new();
    hash_preimage.extend_from_slice(b"franken::hsp_runner::");

    for spec in &corpus {
        families.insert(spec.family);
        if !spec.clean_completion {
            all_clean = false;
        }
        if spec.final_state.phase.is_terminal() {
            terminal_count += 1;
        }
        hash_preimage.extend_from_slice(spec.content_hash.as_bytes());
    }

    HspRunnerResult {
        specimen_count,
        families_covered: families.into_iter().collect(),
        all_clean,
        terminal_count,
        content_hash: ContentHash::compute(&hash_preimage),
    }
}

/// Write evidence bundle to directory.
pub fn write_hsp_evidence_bundle(dir: &std::path::Path) -> std::io::Result<()> {
    let corpus = hsp_corpus();
    let result = run_hsp_corpus();

    // 1. Inventory JSON
    let inventory: Vec<serde_json::Value> = corpus
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.name,
                "family": s.family.to_string(),
                "final_phase": s.final_state.phase.to_string(),
                "transition_count": s.transition_count,
                "clean_completion": s.clean_completion,
                "content_hash": format!("{:?}", s.content_hash),
            })
        })
        .collect();
    let inv_json = serde_json::to_string_pretty(&inventory).map_err(std::io::Error::other)?;
    std::fs::write(dir.join("hsp_inventory.json"), inv_json)?;

    // 2. Manifest JSON
    let manifest = serde_json::json!({
        "schema": "hostcall_session_protocol_evidence_v1",
        "specimen_count": result.specimen_count,
        "families_covered": result.families_covered.iter().map(|f| f.to_string()).collect::<Vec<_>>(),
        "all_clean": result.all_clean,
        "terminal_count": result.terminal_count,
        "content_hash": format!("{:?}", result.content_hash),
    });
    let man_json = serde_json::to_string_pretty(&manifest).map_err(std::io::Error::other)?;
    std::fs::write(dir.join("hsp_manifest.json"), man_json)?;

    // 3. Events JSONL
    let mut events = String::new();
    for spec in &corpus {
        let line = serde_json::json!({
            "event": "specimen_evaluated",
            "name": spec.name,
            "family": spec.family.to_string(),
            "phase": spec.final_state.phase.to_string(),
            "transitions": spec.transition_count,
            "clean": spec.clean_completion,
        });
        events.push_str(&serde_json::to_string(&line).map_err(std::io::Error::other)?);
        events.push('\n');
    }
    std::fs::write(dir.join("hsp_events.jsonl"), events)?;

    // 4. Commands TXT
    let mut cmds = String::new();
    cmds.push_str("# Hostcall Session Protocol Evidence Commands\n");
    cmds.push_str("cargo test -p frankenengine-engine hostcall_session_protocol\n");
    cmds.push_str(
        "cargo test -p frankenengine-engine --test hostcall_session_protocol_integration\n",
    );
    std::fs::write(dir.join("hsp_commands.txt"), cmds)?;

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

    fn test_hash() -> ContentHash {
        ContentHash::compute(b"test-transcript")
    }

    fn make_state() -> SessionProtocolState {
        SessionProtocolState::new(
            "sess-001".into(),
            "ext-alpha".into(),
            "host-bravo".into(),
            64,
            100,
        )
    }

    fn make_key_schedule() -> SessionKeySchedule {
        let mut ks = SessionKeySchedule::new(
            test_epoch(),
            "sess-001".into(),
            "ext-alpha".into(),
            "host-bravo".into(),
            test_hash(),
        );
        for purpose in KeyStagePurpose::ALL {
            ks.record_stage(
                *purpose,
                ContentHash::compute(purpose.domain_label().as_bytes()),
            );
        }
        ks
    }

    // --- SessionPhaseTag tests ---

    #[test]
    fn phase_tag_terminal() {
        assert!(SessionPhaseTag::Closed.is_terminal());
        assert!(!SessionPhaseTag::Established.is_terminal());
        assert!(!SessionPhaseTag::DegradedOpen.is_terminal());
    }

    #[test]
    fn phase_tag_permits_data() {
        assert!(SessionPhaseTag::Established.permits_data());
        assert!(SessionPhaseTag::DegradedOpen.permits_data());
        assert!(!SessionPhaseTag::Uninit.permits_data());
        assert!(!SessionPhaseTag::Negotiating.permits_data());
        assert!(!SessionPhaseTag::Closing.permits_data());
        assert!(!SessionPhaseTag::Closed.permits_data());
    }

    #[test]
    fn phase_tag_all_variants() {
        assert_eq!(SessionPhaseTag::ALL.len(), 6);
    }

    #[test]
    fn phase_tag_display() {
        assert_eq!(SessionPhaseTag::Uninit.to_string(), "uninit");
        assert_eq!(SessionPhaseTag::DegradedOpen.to_string(), "degraded_open");
        assert_eq!(SessionPhaseTag::Closed.to_string(), "closed");
    }

    #[test]
    fn phase_tag_serde_roundtrip() {
        for tag in SessionPhaseTag::ALL {
            let json = serde_json::to_string(tag).unwrap();
            let back: SessionPhaseTag = serde_json::from_str(&json).unwrap();
            assert_eq!(*tag, back);
        }
    }

    // --- Transition table tests ---

    #[test]
    fn valid_transition_uninit_to_negotiating() {
        assert!(is_valid_transition(
            SessionPhaseTag::Uninit,
            SessionPhaseTag::Negotiating
        ));
    }

    #[test]
    fn valid_transition_negotiating_to_established() {
        assert!(is_valid_transition(
            SessionPhaseTag::Negotiating,
            SessionPhaseTag::Established
        ));
    }

    #[test]
    fn valid_transition_negotiating_to_closed() {
        assert!(is_valid_transition(
            SessionPhaseTag::Negotiating,
            SessionPhaseTag::Closed
        ));
    }

    #[test]
    fn valid_transition_established_to_degraded() {
        assert!(is_valid_transition(
            SessionPhaseTag::Established,
            SessionPhaseTag::DegradedOpen
        ));
    }

    #[test]
    fn valid_transition_established_to_closing() {
        assert!(is_valid_transition(
            SessionPhaseTag::Established,
            SessionPhaseTag::Closing
        ));
    }

    #[test]
    fn valid_transition_degraded_to_established() {
        assert!(is_valid_transition(
            SessionPhaseTag::DegradedOpen,
            SessionPhaseTag::Established
        ));
    }

    #[test]
    fn valid_transition_closing_to_closed() {
        assert!(is_valid_transition(
            SessionPhaseTag::Closing,
            SessionPhaseTag::Closed
        ));
    }

    #[test]
    fn invalid_transition_closed_to_anything() {
        for tag in SessionPhaseTag::ALL {
            assert!(!is_valid_transition(SessionPhaseTag::Closed, *tag));
        }
    }

    #[test]
    fn invalid_transition_self_loops() {
        for tag in SessionPhaseTag::ALL {
            assert!(!is_valid_transition(*tag, *tag));
        }
    }

    #[test]
    fn invalid_transition_uninit_to_established() {
        assert!(!is_valid_transition(
            SessionPhaseTag::Uninit,
            SessionPhaseTag::Established
        ));
    }

    #[test]
    fn invalid_transition_negotiating_to_degraded() {
        assert!(!is_valid_transition(
            SessionPhaseTag::Negotiating,
            SessionPhaseTag::DegradedOpen
        ));
    }

    #[test]
    fn valid_transitions_table_not_empty() {
        let table = valid_transitions();
        assert!(table.len() >= 10);
    }

    // --- TransitionTrigger tests ---

    #[test]
    fn trigger_display() {
        let t = TransitionTrigger::HandshakeInitiated;
        assert_eq!(t.to_string(), "handshake_initiated");

        let t2 = TransitionTrigger::ReplayThresholdBreached {
            drop_count: 10,
            window_ticks: 500,
        };
        assert!(t2.to_string().contains("10"));
    }

    #[test]
    fn trigger_serde_roundtrip() {
        let triggers = vec![
            TransitionTrigger::HandshakeInitiated,
            TransitionTrigger::HandshakeCompleted,
            TransitionTrigger::HandshakeRejected,
            TransitionTrigger::SecurityDegradation {
                reason: "epoch_advanced".into(),
            },
            TransitionTrigger::DegradedRecovery,
            TransitionTrigger::CloseInitiated,
            TransitionTrigger::DrainCompleted,
        ];
        for t in &triggers {
            let json = serde_json::to_string(t).unwrap();
            let back: TransitionTrigger = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, back);
        }
    }

    // --- Key schedule tests ---

    #[test]
    fn key_schedule_new_is_incomplete() {
        let ks = SessionKeySchedule::new(
            test_epoch(),
            "s1".into(),
            "e1".into(),
            "h1".into(),
            test_hash(),
        );
        assert!(!ks.is_complete());
        assert!(ks.derived_stages.is_empty());
    }

    #[test]
    fn key_schedule_complete_after_all_stages() {
        let ks = make_key_schedule();
        assert!(ks.is_complete());
        assert_eq!(ks.derived_stages.len(), 4);
    }

    #[test]
    fn key_schedule_epoch_validation() {
        let ks = make_key_schedule();
        assert!(ks.is_valid_for_epoch(test_epoch()));
        assert!(!ks.is_valid_for_epoch(SecurityEpoch::from_raw(99)));
    }

    #[test]
    fn key_schedule_binding_hash_deterministic() {
        let ks1 = make_key_schedule();
        let ks2 = make_key_schedule();
        assert_eq!(ks1.binding_hash(), ks2.binding_hash());
    }

    #[test]
    fn key_schedule_binding_hash_varies_with_session() {
        let ks1 = make_key_schedule();
        let mut ks2 = make_key_schedule();
        ks2.session_id = "sess-002".into();
        assert_ne!(ks1.binding_hash(), ks2.binding_hash());
    }

    #[test]
    fn key_stage_purpose_domain_labels_unique() {
        let labels: Vec<&str> = KeyStagePurpose::ALL
            .iter()
            .map(|p| p.domain_label())
            .collect();
        let unique: std::collections::BTreeSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), unique.len());
    }

    #[test]
    fn key_stage_purpose_display() {
        assert_eq!(KeyStagePurpose::MasterSecret.to_string(), "master_secret");
        assert_eq!(KeyStagePurpose::DataPlaneMac.to_string(), "data_plane_mac");
    }

    #[test]
    fn key_schedule_serde_roundtrip() {
        let ks = make_key_schedule();
        let json = serde_json::to_string(&ks).unwrap();
        let back: SessionKeySchedule = serde_json::from_str(&json).unwrap();
        assert_eq!(ks.session_id, back.session_id);
        assert_eq!(ks.derived_stages.len(), back.derived_stages.len());
    }

    // --- Anti-replay ledger tests ---

    #[test]
    fn ledger_accepts_first_sequence() {
        let mut ledger = AntiReplayLedger::new("sess".into(), 64, 100);
        let v = ledger.check_and_record(1, 100, None);
        assert_eq!(v, ReplayVerdict::Accept);
        assert_eq!(ledger.total_accepted(), 1);
    }

    #[test]
    fn ledger_rejects_replay() {
        let mut ledger = AntiReplayLedger::new("sess".into(), 64, 100);
        ledger.check_and_record(1, 100, None);
        let v = ledger.check_and_record(1, 101, None);
        assert_eq!(v, ReplayVerdict::Replay);
        assert_eq!(ledger.total_replays(), 1);
    }

    #[test]
    fn ledger_accepts_monotonic_sequences() {
        let mut ledger = AntiReplayLedger::new("sess".into(), 64, 100);
        for seq in 1..=10 {
            let v = ledger.check_and_record(seq, seq * 10, None);
            assert_eq!(v, ReplayVerdict::Accept);
        }
        assert_eq!(ledger.total_accepted(), 10);
    }

    #[test]
    fn ledger_accepts_out_of_order_within_window() {
        let mut ledger = AntiReplayLedger::new("sess".into(), 64, 100);
        ledger.check_and_record(5, 100, None);
        let v = ledger.check_and_record(3, 101, None);
        assert_eq!(v, ReplayVerdict::Accept);
        assert_eq!(ledger.total_accepted(), 2);
    }

    #[test]
    fn ledger_rejects_below_floor() {
        let mut ledger = AntiReplayLedger::new("sess".into(), 4, 100);
        // Push ceiling far enough that floor advances.
        for seq in 1..=10 {
            ledger.check_and_record(seq, seq, None);
        }
        // Window floor should be at least 6 (ceiling=10, width=4).
        let v = ledger.check_and_record(1, 11, None);
        assert_eq!(v, ReplayVerdict::BelowFloor);
        assert_eq!(ledger.total_below_floor(), 1);
    }

    #[test]
    fn ledger_rejects_above_ceiling() {
        let mut ledger = AntiReplayLedger::new("sess".into(), 4, 100);
        ledger.check_and_record(1, 1, None);
        // Way above ceiling + window_width.
        let v = ledger.check_and_record(100, 2, None);
        assert_eq!(v, ReplayVerdict::AboveCeiling);
    }

    #[test]
    fn ledger_window_advances() {
        let mut ledger = AntiReplayLedger::new("sess".into(), 4, 100);
        for seq in 1..=10 {
            ledger.check_and_record(seq, seq, None);
        }
        assert!(ledger.window_floor() >= 6);
        assert_eq!(ledger.window_ceiling(), 10);
    }

    #[test]
    fn ledger_audit_trail_bounded() {
        let mut ledger = AntiReplayLedger::new("sess".into(), 1000, 5);
        for seq in 1..=20 {
            ledger.check_and_record(seq, seq, None);
        }
        assert!(ledger.audit_trail().len() <= 5);
    }

    #[test]
    fn ledger_state_hash_deterministic() {
        let mut l1 = AntiReplayLedger::new("sess".into(), 64, 100);
        let mut l2 = AntiReplayLedger::new("sess".into(), 64, 100);
        for seq in 1..=5 {
            l1.check_and_record(seq, seq, None);
            l2.check_and_record(seq, seq, None);
        }
        assert_eq!(l1.state_hash(), l2.state_hash());
    }

    #[test]
    fn ledger_state_hash_varies_on_divergence() {
        let mut l1 = AntiReplayLedger::new("sess".into(), 64, 100);
        let mut l2 = AntiReplayLedger::new("sess".into(), 64, 100);
        l1.check_and_record(1, 1, None);
        l2.check_and_record(2, 1, None);
        assert_ne!(l1.state_hash(), l2.state_hash());
    }

    #[test]
    fn ledger_total_checked() {
        let mut ledger = AntiReplayLedger::new("sess".into(), 64, 100);
        ledger.check_and_record(1, 1, None);
        ledger.check_and_record(1, 2, None); // replay
        ledger.check_and_record(2, 3, None);
        assert_eq!(ledger.total_checked(), 3);
        assert_eq!(ledger.total_accepted(), 2);
        assert_eq!(ledger.total_replays(), 1);
    }

    #[test]
    fn ledger_serde_roundtrip() {
        let mut ledger = AntiReplayLedger::new("sess".into(), 64, 100);
        ledger.check_and_record(1, 1, None);
        ledger.check_and_record(2, 2, None);
        let json = serde_json::to_string(&ledger).unwrap();
        let back: AntiReplayLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_accepted(), 2);
        assert_eq!(back.session_id(), "sess");
    }

    #[test]
    fn ledger_window_size_within_bounds() {
        let mut ledger = AntiReplayLedger::new("sess".into(), 4, 100);
        for seq in 1..=20 {
            ledger.check_and_record(seq, seq, None);
        }
        // Window should contain at most window_width entries.
        assert!(ledger.window_size() <= 5);
    }

    // --- ReplayVerdict tests ---

    #[test]
    fn replay_verdict_display() {
        assert_eq!(ReplayVerdict::Accept.to_string(), "accept");
        assert_eq!(ReplayVerdict::Replay.to_string(), "replay");
        assert_eq!(ReplayVerdict::BelowFloor.to_string(), "below_floor");
        assert_eq!(ReplayVerdict::AboveCeiling.to_string(), "above_ceiling");
    }

    #[test]
    fn replay_verdict_serde() {
        for v in &[
            ReplayVerdict::Accept,
            ReplayVerdict::Replay,
            ReplayVerdict::BelowFloor,
            ReplayVerdict::AboveCeiling,
        ] {
            let json = serde_json::to_string(v).unwrap();
            let back: ReplayVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // --- Degraded-mode policy tests ---

    #[test]
    fn strict_policy_blocks_all_data() {
        let p = DegradedModePolicy::strict(DegradedSeverity::IdentityCompromised);
        assert!(!p.permits_any_data());
        assert!(!p.is_operation_allowed(DegradedOperationKind::ReadHostcall));
        assert!(!p.is_operation_allowed(DegradedOperationKind::WriteHostcall));
        assert!(p.is_operation_allowed(DegradedOperationKind::Close));
    }

    #[test]
    fn permissive_policy_allows_reads() {
        let p = DegradedModePolicy::permissive(DegradedSeverity::PartialMacFailure);
        assert!(p.permits_any_data());
        assert!(p.is_operation_allowed(DegradedOperationKind::ReadHostcall));
        assert!(!p.is_operation_allowed(DegradedOperationKind::WriteHostcall));
    }

    #[test]
    fn stale_key_policy_allows_writes() {
        let p = DegradedModePolicy::for_severity(DegradedSeverity::StaleKey);
        assert!(p.allow_write_hostcalls);
        assert!(p.auto_rekey);
    }

    #[test]
    fn degraded_severity_ordering() {
        assert!(DegradedSeverity::StaleKey < DegradedSeverity::PartialMacFailure);
        assert!(DegradedSeverity::PartialMacFailure < DegradedSeverity::IdentityCompromised);
    }

    #[test]
    fn degraded_severity_display() {
        assert_eq!(DegradedSeverity::StaleKey.to_string(), "stale_key");
        assert_eq!(
            DegradedSeverity::IdentityCompromised.to_string(),
            "identity_compromised"
        );
    }

    #[test]
    fn degraded_operation_display() {
        assert_eq!(
            DegradedOperationKind::ReadHostcall.to_string(),
            "read_hostcall"
        );
        assert_eq!(DegradedOperationKind::Close.to_string(), "close");
    }

    #[test]
    fn degraded_policy_serde_roundtrip() {
        let p = DegradedModePolicy::permissive(DegradedSeverity::PartialMacFailure);
        let json = serde_json::to_string(&p).unwrap();
        let back: DegradedModePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p.severity, back.severity);
        assert_eq!(p.allow_readonly_hostcalls, back.allow_readonly_hostcalls);
    }

    // --- ProtocolError tests ---

    #[test]
    fn protocol_error_display() {
        let e = ProtocolError::IllegalTransition {
            from: SessionPhaseTag::Uninit,
            to: SessionPhaseTag::Established,
        };
        assert!(e.to_string().contains("illegal"));

        let e2 = ProtocolError::EpochMismatch {
            schedule_epoch: SecurityEpoch::from_raw(1),
            current_epoch: SecurityEpoch::from_raw(2),
        };
        assert!(e2.to_string().contains("epoch"));
    }

    #[test]
    fn protocol_error_serde_roundtrip() {
        let errors = vec![
            ProtocolError::IllegalTransition {
                from: SessionPhaseTag::Uninit,
                to: SessionPhaseTag::Closed,
            },
            ProtocolError::IncompleteKeySchedule { stages_derived: 2 },
            ProtocolError::ReplayRejected {
                sequence: 42,
                verdict: ReplayVerdict::Replay,
            },
            ProtocolError::DegradedModeBlocked {
                operation: DegradedOperationKind::WriteHostcall,
                severity: DegradedSeverity::PartialMacFailure,
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: ProtocolError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, back);
        }
    }

    // --- Protocol state machine tests ---

    #[test]
    fn state_machine_initial_phase() {
        let state = make_state();
        assert_eq!(state.phase, SessionPhaseTag::Uninit);
    }

    #[test]
    fn state_machine_valid_transition_sequence() {
        let mut state = make_state();
        state
            .transition(
                SessionPhaseTag::Negotiating,
                TransitionTrigger::HandshakeInitiated,
                1,
            )
            .unwrap();
        assert_eq!(state.phase, SessionPhaseTag::Negotiating);

        state
            .transition(
                SessionPhaseTag::Established,
                TransitionTrigger::HandshakeCompleted,
                2,
            )
            .unwrap();
        assert_eq!(state.phase, SessionPhaseTag::Established);
    }

    #[test]
    fn state_machine_invalid_transition_rejected() {
        let mut state = make_state();
        let result = state.transition(
            SessionPhaseTag::Established,
            TransitionTrigger::HandshakeCompleted,
            1,
        );
        assert!(result.is_err());
        assert_eq!(state.phase, SessionPhaseTag::Uninit);
    }

    #[test]
    fn state_machine_degraded_flow() {
        let mut state = make_state();
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
            .enter_degraded(DegradedSeverity::StaleKey, "epoch_advanced".into(), 3)
            .unwrap();
        assert_eq!(state.phase, SessionPhaseTag::DegradedOpen);
        assert!(state.degraded_policy.is_some());

        // Recovery
        state
            .transition(
                SessionPhaseTag::Established,
                TransitionTrigger::DegradedRecovery,
                4,
            )
            .unwrap();
        assert_eq!(state.phase, SessionPhaseTag::Established);
        assert!(state.degraded_policy.is_none());
    }

    #[test]
    fn state_machine_transition_history() {
        let mut state = make_state();
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
        assert_eq!(state.transition_history.len(), 2);
        assert_eq!(state.transition_history[0].from, SessionPhaseTag::Uninit);
        assert_eq!(state.transition_history[1].to, SessionPhaseTag::Established);
    }

    #[test]
    fn state_machine_attach_key_schedule() {
        let mut state = make_state();
        let ks = make_key_schedule();
        state.attach_key_schedule(ks).unwrap();
        assert!(state.key_schedule.is_some());
    }

    #[test]
    fn state_machine_reject_incomplete_key_schedule() {
        let mut state = make_state();
        let ks = SessionKeySchedule::new(
            test_epoch(),
            "s".into(),
            "e".into(),
            "h".into(),
            test_hash(),
        );
        let result = state.attach_key_schedule(ks);
        assert!(result.is_err());
    }

    #[test]
    fn state_machine_epoch_validation() {
        let mut state = make_state();
        let ks = make_key_schedule();
        state.attach_key_schedule(ks).unwrap();

        assert!(state.validate_epoch(test_epoch()).is_ok());
        assert!(state.validate_epoch(SecurityEpoch::from_raw(99)).is_err());
    }

    #[test]
    fn state_machine_check_operation_established() {
        let mut state = make_state();
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
        assert!(
            state
                .check_operation(DegradedOperationKind::WriteHostcall, 3)
                .is_ok()
        );
    }

    #[test]
    fn state_machine_check_operation_degraded_blocked() {
        let mut state = make_state();
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
            .enter_degraded(
                DegradedSeverity::IdentityCompromised,
                "compromised".into(),
                3,
            )
            .unwrap();
        let result = state.check_operation(DegradedOperationKind::ReadHostcall, 4);
        assert!(result.is_err());
    }

    #[test]
    fn state_machine_check_operation_degraded_allowed() {
        let mut state = make_state();
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
            .enter_degraded(DegradedSeverity::StaleKey, "stale".into(), 3)
            .unwrap();
        assert!(
            state
                .check_operation(DegradedOperationKind::ReadHostcall, 4)
                .is_ok()
        );
        assert!(
            state
                .check_operation(DegradedOperationKind::WriteHostcall, 4)
                .is_ok()
        );
    }

    #[test]
    fn state_machine_replay_check_integration() {
        let mut state = make_state();
        assert!(state.check_replay(1, 1, None).is_ok());
        assert!(state.check_replay(2, 2, None).is_ok());
        assert!(state.check_replay(1, 3, None).is_err());
    }

    #[test]
    fn state_machine_degraded_budget_exhaustion() {
        let mut state = make_state();
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
            .enter_degraded(DegradedSeverity::PartialMacFailure, "mac_fail".into(), 3)
            .unwrap();

        // Exhaust the budget.
        let policy = state.degraded_policy.as_ref().unwrap();
        let limit = policy.max_degraded_messages;
        for _ in 0..limit {
            state.record_degraded_message();
        }

        let result = state.check_operation(DegradedOperationKind::ReadHostcall, 4);
        assert!(result.is_err());
    }

    #[test]
    fn state_machine_serde_roundtrip() {
        let mut state = make_state();
        state
            .transition(
                SessionPhaseTag::Negotiating,
                TransitionTrigger::HandshakeInitiated,
                1,
            )
            .unwrap();
        let json = serde_json::to_string(&state).unwrap();
        let back: SessionProtocolState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.phase, SessionPhaseTag::Negotiating);
        assert_eq!(back.session_id, "sess-001");
    }

    #[test]
    fn state_machine_close_from_established() {
        let mut state = make_state();
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
            .transition(
                SessionPhaseTag::Closing,
                TransitionTrigger::CloseInitiated,
                3,
            )
            .unwrap();
        state
            .transition(
                SessionPhaseTag::Closed,
                TransitionTrigger::DrainCompleted,
                4,
            )
            .unwrap();
        assert!(state.phase.is_terminal());
    }

    #[test]
    fn state_machine_no_transition_from_closed() {
        let mut state = make_state();
        state
            .transition(
                SessionPhaseTag::Negotiating,
                TransitionTrigger::HandshakeInitiated,
                1,
            )
            .unwrap();
        state
            .transition(
                SessionPhaseTag::Closed,
                TransitionTrigger::HandshakeRejected,
                2,
            )
            .unwrap();
        let result = state.transition(
            SessionPhaseTag::Negotiating,
            TransitionTrigger::HandshakeInitiated,
            3,
        );
        assert!(result.is_err());
    }

    #[test]
    fn state_machine_degraded_time_budget_exhaustion() {
        let mut state = make_state();
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
            .enter_degraded(DegradedSeverity::StaleKey, "stale".into(), 100)
            .unwrap();

        let policy = state.degraded_policy.as_ref().unwrap();
        let max_ticks = policy.max_degraded_ticks;

        // Within budget.
        assert!(
            state
                .check_operation(DegradedOperationKind::ReadHostcall, 100 + max_ticks)
                .is_ok()
        );

        // Exceeds budget.
        assert!(
            state
                .check_operation(DegradedOperationKind::ReadHostcall, 100 + max_ticks + 1)
                .is_err()
        );
    }
}
