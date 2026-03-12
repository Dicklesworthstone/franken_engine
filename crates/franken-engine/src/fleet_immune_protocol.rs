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

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;

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
    pub const CURRENT: Self = Self { major: 1, minor: 0 };

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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
        if self.end >= self.start {
            self.end - self.start + 1
        } else {
            0
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
            Self::Checkpoint(_) => {
                // Checkpoints are collective; no single origin.
                // Returning first participating node is a deterministic fallback.
                panic!("checkpoints have no single originator; use participating_nodes")
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
    /// Returns `Err` if insufficient healthy nodes for quorum.
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

        self.last_checkpoint_seq = self.last_checkpoint_seq.saturating_add(1);

        // Resolve containment decisions for all extensions with pending intents.
        let mut decisions = Vec::new();
        for (ext_id, intents) in &self.pending_intents {
            if let Some(winner) = DeterministicPrecedence::resolve_all(intents) {
                decisions.push(ResolvedContainmentDecision {
                    extension_id: ext_id.clone(),
                    resolved_action: winner.proposed_action,
                    contributing_intent_ids: intents.iter().map(|i| i.intent_id.clone()).collect(),
                    epoch: self.current_epoch,
                });
            }
        }

        let mut quorum_sigs = BTreeMap::new();
        quorum_sigs.insert(self.local_node_id.clone(), local_signature);

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
            7,
            "all 7 variants produce distinct messages"
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
}
