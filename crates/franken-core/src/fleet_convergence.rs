//! Deterministic convergence engine and degraded partition policy for fleet
//! containment actions.
//!
//! This module is the enforcement layer that converts fleet-wide evidence into
//! deterministic containment outcomes. Each node independently computes
//! containment decisions using identical deterministic rules applied to
//! accumulated evidence, even under network partition or partial node failure.
//!
//! Key invariants:
//! - Higher severity containment always wins (monotonic escalation).
//! - Containment actions are never auto-reversed by evidence from another
//!   partition; relaxation requires explicit quorum decision.
//! - Actions are idempotent: duplicate intents produce no duplicate receipts.
//! - Under minority partition, thresholds tighten conservatively.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for deterministic arithmetic.
//! All collections use `BTreeMap`/`BTreeSet` for deterministic iteration.
//!
//! Plan references: Section 10.12 item 6, 9H.2, 9F.2.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::fleet_immune_protocol::{
    ContainmentAction, FleetProtocolState, NodeId, ProtocolError, QuorumCheckpoint,
    ResolvedContainmentDecision,
};
use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;
use crate::spectral_fleet_convergence::{ConvergenceCertificate, GossipTopology, SpectralAnalyzer};

// ---------------------------------------------------------------------------
// ContainmentThresholds — policy-defined decision thresholds
// ---------------------------------------------------------------------------

/// Policy-defined thresholds for containment decisions.
///
/// Each threshold is expressed in fixed-point millionths of accumulated
/// posterior log-likelihood. When a node's local view of an extension's
/// posterior crosses a threshold, the corresponding containment action is
/// triggered.
///
/// Thresholds must be strictly ordered: sandbox < suspend < terminate < quarantine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentThresholds {
    /// Posterior threshold for sandboxing (millionths).
    pub sandbox_threshold: i64,
    /// Posterior threshold for suspension (millionths).
    pub suspend_threshold: i64,
    /// Posterior threshold for termination (millionths).
    pub terminate_threshold: i64,
    /// Posterior threshold for quarantine (millionths).
    pub quarantine_threshold: i64,
}

impl ContainmentThresholds {
    /// Validate that thresholds are strictly ordered.
    pub fn is_valid(&self) -> bool {
        self.sandbox_threshold < self.suspend_threshold
            && self.suspend_threshold < self.terminate_threshold
            && self.terminate_threshold < self.quarantine_threshold
    }

    /// Determine the containment action for a given posterior delta.
    ///
    /// Returns `ContainmentAction::Allow` if no threshold is crossed.
    pub fn evaluate(&self, posterior_delta: i64) -> ContainmentAction {
        if posterior_delta >= self.quarantine_threshold {
            ContainmentAction::Quarantine
        } else if posterior_delta >= self.terminate_threshold {
            ContainmentAction::Terminate
        } else if posterior_delta >= self.suspend_threshold {
            ContainmentAction::Suspend
        } else if posterior_delta >= self.sandbox_threshold {
            ContainmentAction::Sandbox
        } else {
            ContainmentAction::Allow
        }
    }

    /// Apply conservative tightening factor for degraded partition mode.
    ///
    /// `tightening_factor_millionths` is applied as a multiplier:
    /// new_threshold = threshold * factor / 1_000_000.
    /// Factor < 1_000_000 tightens (lowers thresholds); > 1_000_000 loosens.
    pub fn tighten(&self, tightening_factor_millionths: u64) -> Self {
        let apply = |threshold: i64| -> i64 {
            let wide = threshold as i128 * tightening_factor_millionths as i128;
            (wide / 1_000_000) as i64
        };
        Self {
            sandbox_threshold: apply(self.sandbox_threshold),
            suspend_threshold: apply(self.suspend_threshold),
            terminate_threshold: apply(self.terminate_threshold),
            quarantine_threshold: apply(self.quarantine_threshold),
        }
    }
}

impl Default for ContainmentThresholds {
    fn default() -> Self {
        Self {
            sandbox_threshold: 200_000,    // 0.2
            suspend_threshold: 500_000,    // 0.5
            terminate_threshold: 800_000,  // 0.8
            quarantine_threshold: 950_000, // 0.95
        }
    }
}

// ---------------------------------------------------------------------------
// PartitionMode — partition state machine
// ---------------------------------------------------------------------------

/// Partition operational mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionMode {
    /// Normal operation: quorum is reachable.
    Normal,
    /// Degraded: this node is in a minority partition.
    Degraded(PartitionInfo),
    /// Healing: partitions reconnecting, reconciliation in progress.
    Healing(HealingInfo),
}

/// Information about the current partition state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionInfo {
    /// Timestamp when partition was detected (nanoseconds).
    pub detected_at_ns: u64,
    /// Nodes suspected to be in the other partition.
    pub unreachable_nodes: BTreeSet<NodeId>,
    /// Number of healthy nodes in this partition.
    pub local_partition_size: usize,
    /// Total known fleet size at partition detection time.
    pub total_fleet_size: usize,
}

impl PartitionInfo {
    /// True if this partition has fewer than quorum nodes.
    pub fn is_minority(&self, quorum_threshold_millionths: u64) -> bool {
        if self.total_fleet_size == 0 {
            return true;
        }
        let required = (quorum_threshold_millionths as u128 * self.total_fleet_size as u128)
            .div_ceil(1_000_000) as usize;
        self.local_partition_size < required
    }
}

/// Information about partition healing in progress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealingInfo {
    /// Timestamp when healing started (nanoseconds).
    pub heal_started_ns: u64,
    /// Nodes being reconciled.
    pub reconciling_nodes: BTreeSet<NodeId>,
    /// Number of reconciliation conflicts encountered.
    pub conflict_count: u64,
    /// Number of evidence items merged during reconciliation.
    pub merged_evidence_count: u64,
}

// ---------------------------------------------------------------------------
// ConvergenceConfig — configurable convergence parameters
// ---------------------------------------------------------------------------

/// Configuration for the convergence engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceConfig {
    /// Base containment thresholds.
    pub thresholds: ContainmentThresholds,
    /// Tightening factor for degraded partition mode (millionths).
    /// Default: 750_000 (0.75x, i.e. thresholds become 75% of normal).
    pub degraded_tightening_factor: u64,
    /// Maximum time to wait for convergence after threshold crossing (ns).
    /// Default: 1_000_000_000 (1 second).
    pub convergence_timeout_ns: u64,
    /// Signing key material for containment receipts.
    pub signing_key: Vec<u8>,
    /// Maximum escalation depth before refusing further escalation.
    pub max_escalation_depth: u32,
}

impl Default for ConvergenceConfig {
    fn default() -> Self {
        Self {
            thresholds: ContainmentThresholds::default(),
            degraded_tightening_factor: 750_000,
            convergence_timeout_ns: 1_000_000_000,
            signing_key: b"default-convergence-key".to_vec(),
            max_escalation_depth: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// ContainmentReceipt — signed audit receipt for executed actions
// ---------------------------------------------------------------------------

/// Signed receipt for an executed containment action.
///
/// Each receipt is a cryptographic proof that a specific containment action
/// was executed at a specific time by a specific node, with supporting
/// evidence chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentReceipt {
    /// Unique action identifier.
    pub action_id: String,
    /// Target extension.
    pub extension_id: String,
    /// Containment action that was executed.
    pub action_type: ContainmentAction,
    /// Evidence trace IDs supporting this action.
    pub evidence_ids: Vec<String>,
    /// Posterior delta at time of action (millionths).
    pub posterior_snapshot: i64,
    /// Policy version under which the action was taken.
    pub policy_version: u64,
    /// Node that executed the action.
    pub node_id: NodeId,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Execution timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Whether this action was taken under degraded partition mode.
    pub degraded_mode: bool,
    /// Escalation depth (0 = initial action, 1+ = escalated).
    pub escalation_depth: u32,
    /// Cryptographic signature over the receipt.
    pub signature: AuthenticityHash,
}

impl ContainmentReceipt {
    /// Compute the signing preimage for this receipt.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(self.action_id.as_bytes());
        preimage.extend_from_slice(self.extension_id.as_bytes());
        preimage.extend_from_slice(&[self.action_type.severity()]);
        // Sort evidence_ids for determinism before signing.
        let mut sorted_evidence = self.evidence_ids.clone();
        sorted_evidence.sort();
        for eid in &sorted_evidence {
            preimage.extend_from_slice(eid.as_bytes());
        }
        preimage.extend_from_slice(&self.posterior_snapshot.to_le_bytes());
        preimage.extend_from_slice(&self.policy_version.to_le_bytes());
        preimage.extend_from_slice(self.node_id.as_str().as_bytes());
        preimage.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        preimage.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        preimage.push(u8::from(self.degraded_mode));
        preimage.extend_from_slice(&self.escalation_depth.to_le_bytes());
        preimage
    }

    /// Verify the receipt signature against a key.
    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let expected = AuthenticityHash::compute_keyed(key, &self.signing_preimage());
        self.signature == expected
    }
}

// ---------------------------------------------------------------------------
// ConvergenceDecision — result of convergence computation
// ---------------------------------------------------------------------------

/// Result of evaluating convergence for a single extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceDecision {
    /// Target extension.
    pub extension_id: String,
    /// Computed containment action.
    pub action: ContainmentAction,
    /// Current posterior delta (millionths).
    pub posterior_delta: i64,
    /// Threshold that was crossed (millionths), or None if Allow.
    pub crossed_threshold: Option<i64>,
    /// Whether this was decided under degraded partition mode.
    pub degraded_mode: bool,
    /// Evidence count used in the decision.
    pub evidence_count: u64,
}

// ---------------------------------------------------------------------------
// ConvergenceEvent — structured telemetry
// ---------------------------------------------------------------------------

/// Structured convergence event for telemetry and audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergenceEvent {
    /// Event type.
    pub event_type: ConvergenceEventType,
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Node emitting the event.
    pub node_id: NodeId,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Structured fields.
    pub fields: BTreeMap<String, String>,
}

/// Types of convergence events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConvergenceEventType {
    /// Threshold crossed for an extension.
    ThresholdCrossed,
    /// Containment action executed.
    ActionExecuted,
    /// Partition detected.
    PartitionEntered,
    /// Partition healed.
    PartitionExited,
    /// Reconciliation conflict during healing.
    ReconciliationConflict,
    /// Convergence verified against quorum checkpoint.
    ConvergenceVerified,
    /// Convergence divergence detected (self-correction needed).
    ConvergenceDiverged,
    /// Containment escalation triggered.
    EscalationTriggered,
    /// Evidence lag detected.
    EvidenceLag,
    /// Spectral connectivity health snapshot computed.
    SpectralHealthComputed,
}

impl fmt::Display for ConvergenceEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThresholdCrossed => write!(f, "threshold_crossed"),
            Self::ActionExecuted => write!(f, "action_executed"),
            Self::PartitionEntered => write!(f, "partition_entered"),
            Self::PartitionExited => write!(f, "partition_exited"),
            Self::ReconciliationConflict => write!(f, "reconciliation_conflict"),
            Self::ConvergenceVerified => write!(f, "convergence_verified"),
            Self::ConvergenceDiverged => write!(f, "convergence_diverged"),
            Self::EscalationTriggered => write!(f, "escalation_triggered"),
            Self::EvidenceLag => write!(f, "evidence_lag"),
            Self::SpectralHealthComputed => write!(f, "spectral_health_computed"),
        }
    }
}

// ---------------------------------------------------------------------------
// ActionRegistry — idempotent action tracking
// ---------------------------------------------------------------------------

/// Tracks executed containment actions for idempotency.
///
/// Ensures that the same containment intent does not produce duplicate
/// actions or receipts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionRegistry {
    /// Map from (extension_id, action_type_severity) to receipt.
    /// Key: `"{extension_id}:{severity}"`.
    executed: BTreeMap<String, ContainmentReceipt>,
    /// Escalation depth per extension.
    escalation_depth: BTreeMap<String, u32>,
}

impl ActionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn action_key(extension_id: &str, action: ContainmentAction) -> String {
        format!("{extension_id}:{}", action.severity())
    }

    /// Check if an action has already been executed for this extension at
    /// this severity level.
    pub fn is_executed(&self, extension_id: &str, action: ContainmentAction) -> bool {
        self.executed
            .contains_key(&Self::action_key(extension_id, action))
    }

    /// Record an executed action with its receipt.
    pub fn record(&mut self, receipt: ContainmentReceipt) {
        let key = Self::action_key(&receipt.extension_id, receipt.action_type);
        self.executed.insert(key, receipt);
    }

    /// Get the current escalation depth for an extension.
    pub fn escalation_depth(&self, extension_id: &str) -> u32 {
        self.escalation_depth
            .get(extension_id)
            .copied()
            .unwrap_or(0)
    }

    /// Increment and return the escalation depth for an extension.
    pub fn increment_escalation(&mut self, extension_id: &str) -> u32 {
        let depth = self
            .escalation_depth
            .entry(extension_id.to_string())
            .or_insert(0);
        *depth = depth.saturating_add(1);
        *depth
    }

    /// Get the receipt for an executed action, if any.
    pub fn get_receipt(
        &self,
        extension_id: &str,
        action: ContainmentAction,
    ) -> Option<&ContainmentReceipt> {
        self.executed.get(&Self::action_key(extension_id, action))
    }

    /// Get the highest severity action executed for an extension.
    pub fn highest_executed_action(&self, extension_id: &str) -> ContainmentAction {
        for severity in (0..=4).rev() {
            let key = format!("{extension_id}:{severity}");
            if self.executed.contains_key(&key) {
                return match severity {
                    4 => ContainmentAction::Quarantine,
                    3 => ContainmentAction::Terminate,
                    2 => ContainmentAction::Suspend,
                    1 => ContainmentAction::Sandbox,
                    _ => ContainmentAction::Allow,
                };
            }
        }
        ContainmentAction::Allow
    }

    /// All receipts for an extension, ordered by severity.
    pub fn receipts_for_extension(&self, extension_id: &str) -> Vec<&ContainmentReceipt> {
        (0..=4u8)
            .filter_map(|severity| {
                let key = format!("{extension_id}:{severity}");
                self.executed.get(&key)
            })
            .collect()
    }

    /// Total number of executed actions across all extensions.
    pub fn total_actions(&self) -> usize {
        self.executed.len()
    }
}

// ---------------------------------------------------------------------------
// ConvergenceEngine — main convergence engine
// ---------------------------------------------------------------------------

/// Deterministic convergence engine for fleet containment.
///
/// Each node runs an identical instance of this engine. Given the same
/// evidence stream, all nodes produce the same containment decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceEngine {
    /// This node's identity.
    pub node_id: NodeId,
    /// Convergence configuration.
    pub config: ConvergenceConfig,
    /// Current partition mode.
    pub partition_mode: PartitionMode,
    /// Action registry for idempotency.
    pub action_registry: ActionRegistry,
    /// Current policy version.
    pub policy_version: u64,
    /// Current security epoch.
    pub current_epoch: SecurityEpoch,
    /// Monotonic action counter for unique IDs.
    action_counter: u64,
    /// Event log for telemetry.
    pub events: Vec<ConvergenceEvent>,
    /// Maximum events to retain (ring buffer semantics).
    max_events: usize,
    /// Trace counter for unique trace IDs.
    trace_counter: u64,
}

impl ConvergenceEngine {
    /// Create a new convergence engine for the given node.
    pub fn new(node_id: NodeId, config: ConvergenceConfig) -> Self {
        Self {
            node_id,
            config,
            partition_mode: PartitionMode::Normal,
            action_registry: ActionRegistry::new(),
            policy_version: 1,
            current_epoch: SecurityEpoch::GENESIS,
            action_counter: 0,
            events: Vec::new(),
            max_events: 10_000,
            trace_counter: 0,
        }
    }

    fn next_action_id(&mut self) -> String {
        self.action_counter = self.action_counter.saturating_add(1);
        format!("action-{}-{}", self.node_id, self.action_counter)
    }

    fn next_trace_id(&mut self) -> String {
        self.trace_counter = self.trace_counter.saturating_add(1);
        format!("trace-{}-{}", self.node_id, self.trace_counter)
    }

    fn emit_event(
        &mut self,
        event_type: ConvergenceEventType,
        timestamp_ns: u64,
        fields: BTreeMap<String, String>,
    ) {
        let event = ConvergenceEvent {
            event_type,
            trace_id: self.next_trace_id(),
            node_id: self.node_id.clone(),
            timestamp_ns,
            epoch: self.current_epoch,
            fields,
        };
        self.events.push(event);
        if self.events.len() > self.max_events {
            self.events.remove(0);
        }
    }

    /// Get the effective thresholds, accounting for partition mode.
    pub fn effective_thresholds(&self) -> ContainmentThresholds {
        match &self.partition_mode {
            PartitionMode::Normal => self.config.thresholds.clone(),
            PartitionMode::Degraded(info) => {
                if info.is_minority(500_000) {
                    self.config
                        .thresholds
                        .tighten(self.config.degraded_tightening_factor)
                } else {
                    self.config.thresholds.clone()
                }
            }
            PartitionMode::Healing(_) => {
                // During healing, use tightened thresholds as a conservative
                // measure until reconciliation completes.
                self.config
                    .thresholds
                    .tighten(self.config.degraded_tightening_factor)
            }
        }
    }

    /// Evaluate convergence for a single extension given its posterior delta.
    ///
    /// Returns the convergence decision including the determined action.
    pub fn evaluate_extension(
        &self,
        extension_id: &str,
        posterior_delta: i64,
        evidence_count: u64,
    ) -> ConvergenceDecision {
        let thresholds = self.effective_thresholds();
        let action = thresholds.evaluate(posterior_delta);
        let degraded = !matches!(self.partition_mode, PartitionMode::Normal);

        let crossed_threshold = match action {
            ContainmentAction::Quarantine => Some(thresholds.quarantine_threshold),
            ContainmentAction::Terminate => Some(thresholds.terminate_threshold),
            ContainmentAction::Suspend => Some(thresholds.suspend_threshold),
            ContainmentAction::Sandbox => Some(thresholds.sandbox_threshold),
            ContainmentAction::Allow => None,
        };

        ConvergenceDecision {
            extension_id: extension_id.to_string(),
            action,
            posterior_delta,
            crossed_threshold,
            degraded_mode: degraded,
            evidence_count,
        }
    }

    /// Evaluate all extensions in the fleet protocol state and produce
    /// convergence decisions.
    pub fn evaluate_all(&self, fleet_state: &FleetProtocolState) -> Vec<ConvergenceDecision> {
        let mut decisions = Vec::new();
        for ext_id in fleet_state.evidence.extensions() {
            let posterior = fleet_state.evidence.posterior_delta(&ext_id);
            let count = fleet_state.evidence.evidence_count(&ext_id);
            decisions.push(self.evaluate_extension(&ext_id, posterior, count));
        }
        decisions
    }

    /// Execute a containment decision, producing a signed receipt.
    ///
    /// Returns `None` if the action has already been executed (idempotent)
    /// or if the action is `Allow` (no action needed).
    pub fn execute_decision(
        &mut self,
        decision: &ConvergenceDecision,
        timestamp_ns: u64,
    ) -> Option<ContainmentReceipt> {
        if decision.action == ContainmentAction::Allow {
            return None;
        }

        // Idempotency: skip if already executed at this severity.
        if self
            .action_registry
            .is_executed(&decision.extension_id, decision.action)
        {
            return None;
        }

        // Monotonic escalation: never execute a lower severity than already executed.
        let highest = self
            .action_registry
            .highest_executed_action(&decision.extension_id);
        if !decision.action.at_least_as_severe_as(highest) {
            return None;
        }

        let action_id = self.next_action_id();
        let degraded = !matches!(self.partition_mode, PartitionMode::Normal);
        let escalation_depth = self
            .action_registry
            .escalation_depth(&decision.extension_id);

        let mut receipt = ContainmentReceipt {
            action_id,
            extension_id: decision.extension_id.clone(),
            action_type: decision.action,
            evidence_ids: Vec::new(),
            posterior_snapshot: decision.posterior_delta,
            policy_version: self.policy_version,
            node_id: self.node_id.clone(),
            epoch: self.current_epoch,
            timestamp_ns,
            degraded_mode: degraded,
            escalation_depth,
            signature: AuthenticityHash::compute_keyed(b"placeholder", b"placeholder"),
        };

        // Sign the receipt.
        receipt.signature =
            AuthenticityHash::compute_keyed(&self.config.signing_key, &receipt.signing_preimage());

        // Record for idempotency.
        self.action_registry.record(receipt.clone());

        // Emit telemetry.
        let mut fields = BTreeMap::new();
        fields.insert("extension_id".into(), decision.extension_id.clone());
        fields.insert("action".into(), decision.action.to_string());
        fields.insert(
            "posterior_delta".into(),
            decision.posterior_delta.to_string(),
        );
        fields.insert("degraded_mode".into(), degraded.to_string());
        self.emit_event(ConvergenceEventType::ActionExecuted, timestamp_ns, fields);

        Some(receipt)
    }

    /// Process all extensions in fleet state: evaluate + execute decisions.
    ///
    /// Returns all newly produced receipts (excludes idempotent duplicates).
    pub fn process_fleet_state(
        &mut self,
        fleet_state: &FleetProtocolState,
        timestamp_ns: u64,
    ) -> Vec<ContainmentReceipt> {
        let decisions = self.evaluate_all(fleet_state);
        let mut receipts = Vec::new();
        for decision in &decisions {
            if let Some(receipt) = self.execute_decision(decision, timestamp_ns) {
                receipts.push(receipt);
            }
        }
        receipts
    }

    fn emit_spectral_health(&mut self, fleet_state: &FleetProtocolState, timestamp_ns: u64) {
        let healthy_nodes = fleet_state
            .health
            .healthy_nodes(timestamp_ns, fleet_state.config.partition_timeout_ns);
        let n = healthy_nodes.len();
        if n < 2 {
            return;
        }

        let mut topology = match GossipTopology::new(
            healthy_nodes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        ) {
            Ok(topology) => topology,
            Err(_) => return,
        };

        let edge_weight = 1_000_000;
        if n == 2 {
            if topology.add_edge(0, 1, edge_weight).is_err() {
                return;
            }
        } else {
            for i in 0..(n - 1) {
                if topology.add_edge(i, i + 1, edge_weight).is_err() {
                    return;
                }
            }
            if topology.add_edge(n - 1, 0, edge_weight).is_err() {
                return;
            }
        }

        let analyzer = SpectralAnalyzer::default();
        let analysis = match analyzer.analyze(&topology) {
            Ok(analysis) => analysis,
            Err(_) => return,
        };
        let cert = ConvergenceCertificate::from_analysis(&analysis, self.current_epoch);

        let mut fields = BTreeMap::new();
        fields.insert("healthy_nodes".to_string(), n.to_string());
        fields.insert(
            "spectral_gap_millionths".to_string(),
            cert.spectral_gap_millionths.to_string(),
        );
        fields.insert(
            "mixing_time_rounds".to_string(),
            cert.mixing_time_rounds.to_string(),
        );
        fields.insert(
            "lambda_max_millionths".to_string(),
            cert.lambda_max_millionths.to_string(),
        );
        fields.insert(
            "fiedler_iterations".to_string(),
            cert.fiedler_iterations.to_string(),
        );
        fields.insert(
            "fiedler_residual_millionths".to_string(),
            cert.fiedler_residual_millionths.to_string(),
        );
        fields.insert(
            "has_partition".to_string(),
            cert.has_natural_partition.to_string(),
        );
        self.emit_event(
            ConvergenceEventType::SpectralHealthComputed,
            timestamp_ns,
            fields,
        );
    }

    /// Detect and update partition state.
    ///
    /// Compares healthy nodes against total known fleet to determine
    /// partition mode transitions.
    pub fn update_partition_state(
        &mut self,
        fleet_state: &FleetProtocolState,
        current_time_ns: u64,
    ) {
        let partitioned_nodes = fleet_state.partitioned_nodes(current_time_ns);
        let total_known = fleet_state.health.known_node_count();
        let healthy_count = total_known.saturating_sub(partitioned_nodes.len());

        match &self.partition_mode {
            PartitionMode::Normal => {
                if !partitioned_nodes.is_empty() {
                    let info = PartitionInfo {
                        detected_at_ns: current_time_ns,
                        unreachable_nodes: partitioned_nodes.clone(),
                        local_partition_size: healthy_count,
                        total_fleet_size: total_known,
                    };

                    let mut fields = BTreeMap::new();
                    fields.insert(
                        "unreachable_count".into(),
                        partitioned_nodes.len().to_string(),
                    );
                    fields.insert("local_size".into(), healthy_count.to_string());
                    fields.insert("total_size".into(), total_known.to_string());
                    self.emit_event(
                        ConvergenceEventType::PartitionEntered,
                        current_time_ns,
                        fields,
                    );

                    self.partition_mode = PartitionMode::Degraded(info);
                }
            }
            PartitionMode::Degraded(_) => {
                if partitioned_nodes.is_empty() {
                    // All nodes reachable again — begin healing.
                    let healing = HealingInfo {
                        heal_started_ns: current_time_ns,
                        reconciling_nodes: BTreeSet::new(),
                        conflict_count: 0,
                        merged_evidence_count: 0,
                    };
                    self.partition_mode = PartitionMode::Healing(healing);
                }
            }
            PartitionMode::Healing(_) => {
                if partitioned_nodes.is_empty() {
                    // Healing complete — transition to normal.
                    let mut fields = BTreeMap::new();
                    fields.insert("total_nodes".into(), total_known.to_string());
                    self.emit_event(
                        ConvergenceEventType::PartitionExited,
                        current_time_ns,
                        fields,
                    );
                    self.partition_mode = PartitionMode::Normal;
                } else {
                    // Re-partition during healing — back to degraded.
                    let info = PartitionInfo {
                        detected_at_ns: current_time_ns,
                        unreachable_nodes: partitioned_nodes,
                        local_partition_size: healthy_count,
                        total_fleet_size: total_known,
                    };
                    self.partition_mode = PartitionMode::Degraded(info);
                }
            }
        }

        // Emit an independent spectral-health snapshot over the currently
        // healthy nodes. This supplements threshold logic with topological
        // convergence evidence for auditability.
        self.emit_spectral_health(fleet_state, current_time_ns);
    }

    /// Escalate containment for an extension to the next severity level.
    ///
    /// Called when initial containment fails (e.g. sandbox escape detected).
    /// Returns the new receipt if escalation is possible, or a
    /// `ConvergenceError` if max escalation depth is reached.
    pub fn escalate(
        &mut self,
        extension_id: &str,
        current_posterior: i64,
        evidence_count: u64,
        timestamp_ns: u64,
    ) -> Result<ContainmentReceipt, ConvergenceError> {
        let current_depth = self.action_registry.escalation_depth(extension_id);
        if current_depth >= self.config.max_escalation_depth {
            return Err(ConvergenceError::MaxEscalationReached {
                extension_id: extension_id.to_string(),
                depth: current_depth,
            });
        }

        let highest = self.action_registry.highest_executed_action(extension_id);
        let next_action = match highest {
            ContainmentAction::Allow => ContainmentAction::Sandbox,
            ContainmentAction::Sandbox => ContainmentAction::Suspend,
            ContainmentAction::Suspend => ContainmentAction::Terminate,
            ContainmentAction::Terminate => ContainmentAction::Quarantine,
            ContainmentAction::Quarantine => {
                return Err(ConvergenceError::AlreadyAtMaxSeverity {
                    extension_id: extension_id.to_string(),
                });
            }
        };

        self.action_registry.increment_escalation(extension_id);

        let decision = ConvergenceDecision {
            extension_id: extension_id.to_string(),
            action: next_action,
            posterior_delta: current_posterior,
            crossed_threshold: None, // Escalation bypasses thresholds.
            degraded_mode: !matches!(self.partition_mode, PartitionMode::Normal),
            evidence_count,
        };

        // Emit escalation telemetry.
        let mut fields = BTreeMap::new();
        fields.insert("extension_id".into(), extension_id.to_string());
        fields.insert("from_action".into(), highest.to_string());
        fields.insert("to_action".into(), next_action.to_string());
        fields.insert("depth".into(), (current_depth + 1).to_string());
        self.emit_event(
            ConvergenceEventType::EscalationTriggered,
            timestamp_ns,
            fields,
        );

        self.execute_decision(&decision, timestamp_ns).ok_or(
            ConvergenceError::ActionAlreadyExecuted {
                extension_id: extension_id.to_string(),
                action: next_action,
            },
        )
    }

    /// Verify local convergence state against a quorum checkpoint.
    ///
    /// If the local evidence summary diverges from the checkpoint, emits
    /// a divergence event and returns the discrepancy.
    pub fn verify_against_checkpoint(
        &mut self,
        fleet_state: &FleetProtocolState,
        checkpoint: &QuorumCheckpoint,
        timestamp_ns: u64,
    ) -> ConvergenceVerification {
        let local_hash = fleet_state.evidence.summary_hash();
        let checkpoint_hash = &checkpoint.evidence_summary_hash;

        if local_hash == *checkpoint_hash {
            let mut fields = BTreeMap::new();
            fields.insert(
                "checkpoint_seq".into(),
                checkpoint.checkpoint_seq.to_string(),
            );
            self.emit_event(
                ConvergenceEventType::ConvergenceVerified,
                timestamp_ns,
                fields,
            );
            ConvergenceVerification::Converged {
                checkpoint_seq: checkpoint.checkpoint_seq,
            }
        } else {
            let mut fields = BTreeMap::new();
            fields.insert(
                "checkpoint_seq".into(),
                checkpoint.checkpoint_seq.to_string(),
            );
            fields.insert("local_hash".into(), local_hash.to_hex());
            self.emit_event(
                ConvergenceEventType::ConvergenceDiverged,
                timestamp_ns,
                fields,
            );
            ConvergenceVerification::Diverged {
                checkpoint_seq: checkpoint.checkpoint_seq,
                local_summary_hash: local_hash,
                checkpoint_summary_hash: *checkpoint_hash,
            }
        }
    }

    /// Apply resolved containment decisions from a quorum checkpoint.
    ///
    /// Split-brain prevention: containment actions from the checkpoint are
    /// applied locally, but existing higher-severity actions are never
    /// downgraded.
    pub fn apply_checkpoint_decisions(
        &mut self,
        decisions: &[ResolvedContainmentDecision],
        timestamp_ns: u64,
    ) -> Vec<ContainmentReceipt> {
        let mut receipts = Vec::new();
        for resolved in decisions {
            let decision = ConvergenceDecision {
                extension_id: resolved.extension_id.clone(),
                action: resolved.resolved_action,
                posterior_delta: 0, // Checkpoint-driven, not threshold-driven.
                crossed_threshold: None,
                degraded_mode: false,
                evidence_count: 0,
            };
            if let Some(receipt) = self.execute_decision(&decision, timestamp_ns) {
                receipts.push(receipt);
            }
        }
        receipts
    }

    /// Record reconciliation conflict during partition healing.
    pub fn record_reconciliation_conflict(
        &mut self,
        conflicting_extension: &str,
        local_action: ContainmentAction,
        remote_action: ContainmentAction,
        timestamp_ns: u64,
    ) {
        if let PartitionMode::Healing(ref mut info) = self.partition_mode {
            info.conflict_count = info.conflict_count.saturating_add(1);
        }

        let mut fields = BTreeMap::new();
        fields.insert("extension_id".into(), conflicting_extension.to_string());
        fields.insert("local_action".into(), local_action.to_string());
        fields.insert("remote_action".into(), remote_action.to_string());
        // Higher severity wins per deterministic precedence.
        let resolved = if remote_action.at_least_as_severe_as(local_action) {
            remote_action
        } else {
            local_action
        };
        fields.insert("resolved_action".into(), resolved.to_string());
        self.emit_event(
            ConvergenceEventType::ReconciliationConflict,
            timestamp_ns,
            fields,
        );
    }

    /// Get all events of a specific type.
    pub fn events_of_type(&self, event_type: &ConvergenceEventType) -> Vec<&ConvergenceEvent> {
        self.events
            .iter()
            .filter(|e| &e.event_type == event_type)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ConvergenceVerification — checkpoint verification result
// ---------------------------------------------------------------------------

/// Result of verifying local state against a quorum checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConvergenceVerification {
    /// Local state matches the checkpoint.
    Converged { checkpoint_seq: u64 },
    /// Local state diverges from the checkpoint.
    Diverged {
        checkpoint_seq: u64,
        local_summary_hash: ContentHash,
        checkpoint_summary_hash: ContentHash,
    },
}

// ---------------------------------------------------------------------------
// ConvergenceError — convergence-specific errors
// ---------------------------------------------------------------------------

/// Errors specific to the convergence engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConvergenceError {
    /// Maximum escalation depth reached.
    MaxEscalationReached { extension_id: String, depth: u32 },
    /// Extension is already at maximum severity (quarantine).
    AlreadyAtMaxSeverity { extension_id: String },
    /// Action was already executed (idempotent rejection).
    ActionAlreadyExecuted {
        extension_id: String,
        action: ContainmentAction,
    },
    /// Invalid threshold configuration.
    InvalidThresholds,
    /// Protocol error from underlying fleet protocol.
    Protocol(ProtocolError),
}

impl fmt::Display for ConvergenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaxEscalationReached {
                extension_id,
                depth,
            } => {
                write!(f, "max escalation depth {depth} reached for {extension_id}")
            }
            Self::AlreadyAtMaxSeverity { extension_id } => {
                write!(
                    f,
                    "extension {extension_id} already at maximum severity (quarantine)"
                )
            }
            Self::ActionAlreadyExecuted {
                extension_id,
                action,
            } => {
                write!(f, "action {action} already executed for {extension_id}")
            }
            Self::InvalidThresholds => write!(f, "invalid threshold configuration"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
        }
    }
}

impl std::error::Error for ConvergenceError {}

impl From<ProtocolError> for ConvergenceError {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_immune_protocol::{
        EvidencePacket, GossipConfig, HeartbeatLiveness, MessageSignature, ProtocolVersion,
    };

    // -- Test helpers --

    fn test_node(name: &str) -> NodeId {
        NodeId::new(name)
    }

    fn test_config() -> ConvergenceConfig {
        ConvergenceConfig {
            thresholds: ContainmentThresholds {
                sandbox_threshold: 200_000,
                suspend_threshold: 500_000,
                terminate_threshold: 800_000,
                quarantine_threshold: 950_000,
            },
            degraded_tightening_factor: 750_000,
            convergence_timeout_ns: 1_000_000_000,
            signing_key: b"test-key".to_vec(),
            max_escalation_depth: 3,
        }
    }

    fn test_engine(name: &str) -> ConvergenceEngine {
        ConvergenceEngine::new(test_node(name), test_config())
    }

    fn test_fleet_state(node: &str) -> FleetProtocolState {
        FleetProtocolState::new(NodeId::new(node), GossipConfig::default())
    }

    fn test_signature(node: &str) -> MessageSignature {
        MessageSignature {
            signer: NodeId::new(node),
            hash: AuthenticityHash::compute_keyed(node.as_bytes(), b"test"),
        }
    }

    fn test_evidence(node: &str, ext: &str, seq: u64, delta: i64) -> EvidencePacket {
        EvidencePacket {
            trace_id: format!("trace-{node}-{ext}-{seq}"),
            extension_id: ext.to_string(),
            evidence_hash: ContentHash::compute(format!("ev-{node}-{ext}-{seq}").as_bytes()),
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

    fn make_checkpoint(
        seq: u64,
        summary_hash: ContentHash,
        decisions: Vec<ResolvedContainmentDecision>,
    ) -> QuorumCheckpoint {
        QuorumCheckpoint {
            checkpoint_seq: seq,
            epoch: SecurityEpoch::from_raw(1),
            participating_nodes: BTreeSet::new(),
            evidence_summary_hash: summary_hash,
            containment_decisions: decisions,
            quorum_signatures: BTreeMap::new(),
            timestamp_ns: 10_000_000_000,
            protocol_version: ProtocolVersion::CURRENT,
            extensions: BTreeMap::new(),
        }
    }

    // -- ContainmentThresholds tests --

    #[test]
    fn thresholds_default_is_valid() {
        assert!(ContainmentThresholds::default().is_valid());
    }

    #[test]
    fn thresholds_invalid_ordering() {
        let bad = ContainmentThresholds {
            sandbox_threshold: 500_000,
            suspend_threshold: 200_000,
            terminate_threshold: 800_000,
            quarantine_threshold: 950_000,
        };
        assert!(!bad.is_valid());
    }

    #[test]
    fn thresholds_evaluate_allow() {
        let t = ContainmentThresholds::default();
        assert_eq!(t.evaluate(100_000), ContainmentAction::Allow);
    }

    #[test]
    fn thresholds_evaluate_sandbox() {
        let t = ContainmentThresholds::default();
        assert_eq!(t.evaluate(200_000), ContainmentAction::Sandbox);
        assert_eq!(t.evaluate(300_000), ContainmentAction::Sandbox);
    }

    #[test]
    fn thresholds_evaluate_suspend() {
        let t = ContainmentThresholds::default();
        assert_eq!(t.evaluate(500_000), ContainmentAction::Suspend);
        assert_eq!(t.evaluate(700_000), ContainmentAction::Suspend);
    }

    #[test]
    fn thresholds_evaluate_terminate() {
        let t = ContainmentThresholds::default();
        assert_eq!(t.evaluate(800_000), ContainmentAction::Terminate);
        assert_eq!(t.evaluate(900_000), ContainmentAction::Terminate);
    }

    #[test]
    fn thresholds_evaluate_quarantine() {
        let t = ContainmentThresholds::default();
        assert_eq!(t.evaluate(950_000), ContainmentAction::Quarantine);
        assert_eq!(t.evaluate(1_000_000), ContainmentAction::Quarantine);
    }

    #[test]
    fn thresholds_evaluate_negative_allows() {
        let t = ContainmentThresholds::default();
        assert_eq!(t.evaluate(-500_000), ContainmentAction::Allow);
    }

    #[test]
    fn thresholds_tighten_75_percent() {
        let t = ContainmentThresholds::default();
        let tightened = t.tighten(750_000); // 0.75x
        assert_eq!(tightened.sandbox_threshold, 150_000);
        assert_eq!(tightened.suspend_threshold, 375_000);
        assert_eq!(tightened.terminate_threshold, 600_000);
        assert_eq!(tightened.quarantine_threshold, 712_500);
    }

    #[test]
    fn thresholds_tighten_identity() {
        let t = ContainmentThresholds::default();
        let same = t.tighten(1_000_000); // 1.0x
        assert_eq!(same, t);
    }

    #[test]
    fn thresholds_serde_round_trip() {
        let t = ContainmentThresholds::default();
        let json = serde_json::to_string(&t).unwrap();
        let decoded: ContainmentThresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(t, decoded);
    }

    // -- PartitionInfo tests --

    #[test]
    fn partition_info_is_minority() {
        let info = PartitionInfo {
            detected_at_ns: 0,
            unreachable_nodes: BTreeSet::new(),
            local_partition_size: 2,
            total_fleet_size: 5,
        };
        // 50% quorum: need 3, have 2 → minority.
        assert!(info.is_minority(500_000));
    }

    #[test]
    fn partition_info_is_majority() {
        let info = PartitionInfo {
            detected_at_ns: 0,
            unreachable_nodes: BTreeSet::new(),
            local_partition_size: 3,
            total_fleet_size: 5,
        };
        // 50% quorum: need 3, have 3 → not minority.
        assert!(!info.is_minority(500_000));
    }

    #[test]
    fn partition_info_zero_fleet_is_minority() {
        let info = PartitionInfo {
            detected_at_ns: 0,
            unreachable_nodes: BTreeSet::new(),
            local_partition_size: 0,
            total_fleet_size: 0,
        };
        assert!(info.is_minority(500_000));
    }

    // -- ActionRegistry tests --

    #[test]
    fn action_registry_initially_empty() {
        let reg = ActionRegistry::new();
        assert_eq!(reg.total_actions(), 0);
        assert!(!reg.is_executed("ext-1", ContainmentAction::Sandbox));
    }

    #[test]
    fn action_registry_record_and_query() {
        let mut reg = ActionRegistry::new();
        let receipt = ContainmentReceipt {
            action_id: "a1".into(),
            extension_id: "ext-1".into(),
            action_type: ContainmentAction::Sandbox,
            evidence_ids: vec![],
            posterior_snapshot: 300_000,
            policy_version: 1,
            node_id: test_node("local"),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: 1_000_000_000,
            degraded_mode: false,
            escalation_depth: 0,
            signature: AuthenticityHash::compute_keyed(b"k", b"v"),
        };
        reg.record(receipt);

        assert!(reg.is_executed("ext-1", ContainmentAction::Sandbox));
        assert!(!reg.is_executed("ext-1", ContainmentAction::Suspend));
        assert_eq!(reg.total_actions(), 1);
    }

    #[test]
    fn action_registry_highest_executed() {
        let mut reg = ActionRegistry::new();

        assert_eq!(
            reg.highest_executed_action("ext-1"),
            ContainmentAction::Allow
        );

        let receipt = ContainmentReceipt {
            action_id: "a1".into(),
            extension_id: "ext-1".into(),
            action_type: ContainmentAction::Suspend,
            evidence_ids: vec![],
            posterior_snapshot: 600_000,
            policy_version: 1,
            node_id: test_node("local"),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: 1_000_000_000,
            degraded_mode: false,
            escalation_depth: 0,
            signature: AuthenticityHash::compute_keyed(b"k", b"v"),
        };
        reg.record(receipt);

        assert_eq!(
            reg.highest_executed_action("ext-1"),
            ContainmentAction::Suspend
        );
    }

    #[test]
    fn action_registry_escalation_depth() {
        let mut reg = ActionRegistry::new();
        assert_eq!(reg.escalation_depth("ext-1"), 0);
        assert_eq!(reg.increment_escalation("ext-1"), 1);
        assert_eq!(reg.increment_escalation("ext-1"), 2);
        assert_eq!(reg.escalation_depth("ext-1"), 2);
    }

    #[test]
    fn action_registry_receipts_for_extension() {
        let mut reg = ActionRegistry::new();
        for (sev, action) in [
            (ContainmentAction::Sandbox, "a1"),
            (ContainmentAction::Terminate, "a2"),
        ] {
            reg.record(ContainmentReceipt {
                action_id: action.into(),
                extension_id: "ext-1".into(),
                action_type: sev,
                evidence_ids: vec![],
                posterior_snapshot: 0,
                policy_version: 1,
                node_id: test_node("local"),
                epoch: SecurityEpoch::GENESIS,
                timestamp_ns: 0,
                degraded_mode: false,
                escalation_depth: 0,
                signature: AuthenticityHash::compute_keyed(b"k", b"v"),
            });
        }

        let receipts = reg.receipts_for_extension("ext-1");
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].action_type, ContainmentAction::Sandbox);
        assert_eq!(receipts[1].action_type, ContainmentAction::Terminate);
    }

    // -- ContainmentReceipt tests --

    #[test]
    fn receipt_signing_and_verification() {
        let key = b"test-signing-key";
        let mut receipt = ContainmentReceipt {
            action_id: "action-1".into(),
            extension_id: "ext-1".into(),
            action_type: ContainmentAction::Sandbox,
            evidence_ids: vec!["trace-1".into()],
            posterior_snapshot: 300_000,
            policy_version: 1,
            node_id: test_node("local"),
            epoch: SecurityEpoch::from_raw(1),
            timestamp_ns: 1_000_000_000,
            degraded_mode: false,
            escalation_depth: 0,
            signature: AuthenticityHash::compute_keyed(b"placeholder", b"placeholder"),
        };

        receipt.signature = AuthenticityHash::compute_keyed(key, &receipt.signing_preimage());

        assert!(receipt.verify_signature(key));
        assert!(!receipt.verify_signature(b"wrong-key"));
    }

    #[test]
    fn receipt_serde_round_trip() {
        let receipt = ContainmentReceipt {
            action_id: "action-1".into(),
            extension_id: "ext-1".into(),
            action_type: ContainmentAction::Terminate,
            evidence_ids: vec!["trace-1".into(), "trace-2".into()],
            posterior_snapshot: 850_000,
            policy_version: 2,
            node_id: test_node("node-x"),
            epoch: SecurityEpoch::from_raw(3),
            timestamp_ns: 5_000_000_000,
            degraded_mode: true,
            escalation_depth: 1,
            signature: AuthenticityHash::compute_keyed(b"k", b"v"),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let decoded: ContainmentReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, decoded);
    }

    // -- ConvergenceEngine: threshold evaluation tests --

    #[test]
    fn engine_evaluate_extension_allow() {
        let engine = test_engine("local");
        let decision = engine.evaluate_extension("ext-1", 100_000, 5);
        assert_eq!(decision.action, ContainmentAction::Allow);
        assert!(decision.crossed_threshold.is_none());
    }

    #[test]
    fn engine_evaluate_extension_sandbox() {
        let engine = test_engine("local");
        let decision = engine.evaluate_extension("ext-1", 300_000, 10);
        assert_eq!(decision.action, ContainmentAction::Sandbox);
        assert_eq!(decision.crossed_threshold, Some(200_000));
    }

    #[test]
    fn engine_evaluate_extension_quarantine() {
        let engine = test_engine("local");
        let decision = engine.evaluate_extension("ext-1", 1_000_000, 50);
        assert_eq!(decision.action, ContainmentAction::Quarantine);
        assert_eq!(decision.crossed_threshold, Some(950_000));
    }

    // -- ConvergenceEngine: execution tests --

    #[test]
    fn engine_execute_allow_produces_no_receipt() {
        let mut engine = test_engine("local");
        let decision = engine.evaluate_extension("ext-1", 50_000, 1);
        assert!(engine.execute_decision(&decision, 1_000_000_000).is_none());
    }

    #[test]
    fn engine_execute_sandbox_produces_receipt() {
        let mut engine = test_engine("local");
        let decision = engine.evaluate_extension("ext-1", 300_000, 5);
        let receipt = engine
            .execute_decision(&decision, 1_000_000_000)
            .expect("should produce receipt");

        assert_eq!(receipt.action_type, ContainmentAction::Sandbox);
        assert_eq!(receipt.extension_id, "ext-1");
        assert!(receipt.verify_signature(&engine.config.signing_key));
    }

    #[test]
    fn engine_idempotent_execution() {
        let mut engine = test_engine("local");
        let decision = engine.evaluate_extension("ext-1", 300_000, 5);

        let first = engine.execute_decision(&decision, 1_000_000_000);
        assert!(first.is_some());

        let second = engine.execute_decision(&decision, 2_000_000_000);
        assert!(second.is_none()); // Idempotent.
    }

    #[test]
    fn engine_monotonic_escalation_prevents_downgrade() {
        let mut engine = test_engine("local");

        // Execute terminate first.
        let terminate = ConvergenceDecision {
            extension_id: "ext-1".into(),
            action: ContainmentAction::Terminate,
            posterior_delta: 850_000,
            crossed_threshold: Some(800_000),
            degraded_mode: false,
            evidence_count: 20,
        };
        engine.execute_decision(&terminate, 1_000_000_000).unwrap();

        // Attempt sandbox (lower severity) — should be rejected.
        let sandbox = ConvergenceDecision {
            extension_id: "ext-1".into(),
            action: ContainmentAction::Sandbox,
            posterior_delta: 250_000,
            crossed_threshold: Some(200_000),
            degraded_mode: false,
            evidence_count: 5,
        };
        assert!(engine.execute_decision(&sandbox, 2_000_000_000).is_none());
    }

    // -- ConvergenceEngine: fleet state processing --

    #[test]
    fn engine_process_fleet_state_no_evidence() {
        let mut engine = test_engine("local");
        let fleet = test_fleet_state("local");
        let receipts = engine.process_fleet_state(&fleet, 1_000_000_000);
        assert!(receipts.is_empty());
    }

    #[test]
    fn engine_process_fleet_state_threshold_crossing() {
        let mut engine = test_engine("local");
        let mut fleet = test_fleet_state("local");

        // Inject evidence exceeding sandbox threshold (200_000).
        fleet
            .process_evidence(&test_evidence("remote-1", "ext-1", 1, 300_000))
            .unwrap();

        let receipts = engine.process_fleet_state(&fleet, 1_000_000_000);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].action_type, ContainmentAction::Sandbox);
        assert_eq!(receipts[0].extension_id, "ext-1");
    }

    #[test]
    fn engine_process_fleet_state_multiple_extensions() {
        let mut engine = test_engine("local");
        let mut fleet = test_fleet_state("local");

        fleet
            .process_evidence(&test_evidence("remote-1", "ext-1", 1, 300_000))
            .unwrap();
        fleet
            .process_evidence(&test_evidence("remote-1", "ext-2", 2, 600_000))
            .unwrap();

        let receipts = engine.process_fleet_state(&fleet, 1_000_000_000);
        assert_eq!(receipts.len(), 2);

        let actions: BTreeSet<_> = receipts.iter().map(|r| r.action_type).collect();
        assert!(actions.contains(&ContainmentAction::Sandbox));
        assert!(actions.contains(&ContainmentAction::Suspend));
    }

    // -- ConvergenceEngine: partition tests --

    #[test]
    fn engine_partition_detection_normal_to_degraded() {
        let mut engine = test_engine("local");
        let mut fleet = test_fleet_state("local");

        // Register heartbeats from two remote nodes.
        fleet
            .process_heartbeat(&test_heartbeat("remote-1", 1, 1_000_000_000))
            .unwrap();
        fleet
            .process_heartbeat(&test_heartbeat("remote-2", 1, 1_000_000_000))
            .unwrap();

        // At time 20s with 15s timeout, both are partitioned.
        engine.update_partition_state(&fleet, 20_000_000_000);
        assert!(matches!(engine.partition_mode, PartitionMode::Degraded(_)));

        if let PartitionMode::Degraded(info) = &engine.partition_mode {
            assert_eq!(info.unreachable_nodes.len(), 2);
        }
    }

    #[test]
    fn engine_partition_healing_to_normal() {
        let mut engine = test_engine("local");
        let mut fleet = test_fleet_state("local");

        // Register heartbeats.
        fleet
            .process_heartbeat(&test_heartbeat("remote-1", 1, 1_000_000_000))
            .unwrap();

        // Trigger partition.
        engine.update_partition_state(&fleet, 20_000_000_000);
        assert!(matches!(engine.partition_mode, PartitionMode::Degraded(_)));

        // Update heartbeat to be recent.
        fleet
            .process_heartbeat(&test_heartbeat("remote-1", 2, 19_000_000_000))
            .unwrap();

        // Heal: nodes are reachable again.
        engine.update_partition_state(&fleet, 20_000_000_000);
        assert!(matches!(engine.partition_mode, PartitionMode::Healing(_)));

        // Still all reachable → transition to normal.
        engine.update_partition_state(&fleet, 20_000_000_001);
        assert!(matches!(engine.partition_mode, PartitionMode::Normal));
    }

    #[test]
    fn engine_degraded_mode_tightens_thresholds() {
        let mut engine = test_engine("local");
        engine.partition_mode = PartitionMode::Degraded(PartitionInfo {
            detected_at_ns: 0,
            unreachable_nodes: {
                let mut s = BTreeSet::new();
                s.insert(test_node("n1"));
                s.insert(test_node("n2"));
                s.insert(test_node("n3"));
                s
            },
            local_partition_size: 1,
            total_fleet_size: 4,
        });

        let effective = engine.effective_thresholds();
        // 200_000 * 0.75 = 150_000
        assert_eq!(effective.sandbox_threshold, 150_000);
        // 500_000 * 0.75 = 375_000
        assert_eq!(effective.suspend_threshold, 375_000);
    }

    #[test]
    fn engine_normal_mode_uses_base_thresholds() {
        let engine = test_engine("local");
        let effective = engine.effective_thresholds();
        assert_eq!(effective, engine.config.thresholds);
    }

    // -- ConvergenceEngine: escalation tests --

    #[test]
    fn engine_escalation_from_sandbox_to_suspend() {
        let mut engine = test_engine("local");

        // First action: sandbox.
        let decision = ConvergenceDecision {
            extension_id: "ext-1".into(),
            action: ContainmentAction::Sandbox,
            posterior_delta: 300_000,
            crossed_threshold: Some(200_000),
            degraded_mode: false,
            evidence_count: 5,
        };
        engine.execute_decision(&decision, 1_000_000_000).unwrap();

        // Escalate due to sandbox failure.
        let receipt = engine.escalate("ext-1", 300_000, 5, 2_000_000_000).unwrap();
        assert_eq!(receipt.action_type, ContainmentAction::Suspend);
        assert_eq!(receipt.escalation_depth, 1);
    }

    #[test]
    fn engine_escalation_max_depth_error() {
        let mut engine = test_engine("local");
        engine.config.max_escalation_depth = 1;

        // Execute sandbox.
        let sandbox = ConvergenceDecision {
            extension_id: "ext-1".into(),
            action: ContainmentAction::Sandbox,
            posterior_delta: 300_000,
            crossed_threshold: Some(200_000),
            degraded_mode: false,
            evidence_count: 5,
        };
        engine.execute_decision(&sandbox, 1_000_000_000).unwrap();

        // First escalation succeeds.
        engine.escalate("ext-1", 300_000, 5, 2_000_000_000).unwrap();

        // Second escalation exceeds max depth.
        let err = engine
            .escalate("ext-1", 300_000, 5, 3_000_000_000)
            .unwrap_err();
        assert!(matches!(err, ConvergenceError::MaxEscalationReached { .. }));
    }

    #[test]
    fn engine_escalation_at_quarantine_errors() {
        let mut engine = test_engine("local");

        // Execute quarantine directly.
        let quarantine = ConvergenceDecision {
            extension_id: "ext-1".into(),
            action: ContainmentAction::Quarantine,
            posterior_delta: 1_000_000,
            crossed_threshold: Some(950_000),
            degraded_mode: false,
            evidence_count: 50,
        };
        engine.execute_decision(&quarantine, 1_000_000_000).unwrap();

        let err = engine
            .escalate("ext-1", 1_000_000, 50, 2_000_000_000)
            .unwrap_err();
        assert!(matches!(err, ConvergenceError::AlreadyAtMaxSeverity { .. }));
    }

    // -- ConvergenceEngine: checkpoint verification --

    #[test]
    fn engine_verify_converged_checkpoint() {
        let mut engine = test_engine("local");
        let mut fleet = test_fleet_state("local");

        fleet
            .process_evidence(&test_evidence("remote-1", "ext-1", 1, 300_000))
            .unwrap();

        let summary_hash = fleet.evidence.summary_hash();
        let checkpoint = make_checkpoint(1, summary_hash, vec![]);

        let result = engine.verify_against_checkpoint(&fleet, &checkpoint, 5_000_000_000);
        assert!(matches!(result, ConvergenceVerification::Converged { .. }));
    }

    #[test]
    fn engine_verify_diverged_checkpoint() {
        let mut engine = test_engine("local");
        let fleet = test_fleet_state("local");

        // Checkpoint has a different hash.
        let different_hash = ContentHash::compute(b"different-state");
        let checkpoint = make_checkpoint(1, different_hash, vec![]);

        let result = engine.verify_against_checkpoint(&fleet, &checkpoint, 5_000_000_000);
        assert!(matches!(result, ConvergenceVerification::Diverged { .. }));
    }

    // -- ConvergenceEngine: checkpoint decisions --

    #[test]
    fn engine_apply_checkpoint_decisions() {
        let mut engine = test_engine("local");

        let decisions = vec![
            ResolvedContainmentDecision {
                extension_id: "ext-1".into(),
                resolved_action: ContainmentAction::Terminate,
                contributing_intent_ids: vec!["i1".into()],
                epoch: SecurityEpoch::from_raw(1),
            },
            ResolvedContainmentDecision {
                extension_id: "ext-2".into(),
                resolved_action: ContainmentAction::Sandbox,
                contributing_intent_ids: vec!["i2".into()],
                epoch: SecurityEpoch::from_raw(1),
            },
        ];

        let receipts = engine.apply_checkpoint_decisions(&decisions, 5_000_000_000);
        assert_eq!(receipts.len(), 2);

        // Verify the actions are now registered.
        assert!(
            engine
                .action_registry
                .is_executed("ext-1", ContainmentAction::Terminate)
        );
        assert!(
            engine
                .action_registry
                .is_executed("ext-2", ContainmentAction::Sandbox)
        );
    }

    #[test]
    fn engine_checkpoint_decisions_split_brain_prevention() {
        let mut engine = test_engine("local");

        // Local partition already executed quarantine.
        let quarantine = ConvergenceDecision {
            extension_id: "ext-1".into(),
            action: ContainmentAction::Quarantine,
            posterior_delta: 1_000_000,
            crossed_threshold: Some(950_000),
            degraded_mode: true,
            evidence_count: 50,
        };
        engine.execute_decision(&quarantine, 1_000_000_000).unwrap();

        // Checkpoint from other partition says sandbox.
        let decisions = vec![ResolvedContainmentDecision {
            extension_id: "ext-1".into(),
            resolved_action: ContainmentAction::Sandbox,
            contributing_intent_ids: vec!["i1".into()],
            epoch: SecurityEpoch::from_raw(1),
        }];

        // Should not produce receipt (lower severity than existing).
        let receipts = engine.apply_checkpoint_decisions(&decisions, 5_000_000_000);
        assert!(receipts.is_empty());

        // Quarantine still holds.
        assert_eq!(
            engine.action_registry.highest_executed_action("ext-1"),
            ContainmentAction::Quarantine
        );
    }

    // -- ConvergenceEngine: reconciliation --

    #[test]
    fn engine_reconciliation_conflict_recording() {
        let mut engine = test_engine("local");
        engine.partition_mode = PartitionMode::Healing(HealingInfo {
            heal_started_ns: 10_000_000_000,
            reconciling_nodes: BTreeSet::new(),
            conflict_count: 0,
            merged_evidence_count: 0,
        });

        engine.record_reconciliation_conflict(
            "ext-1",
            ContainmentAction::Sandbox,
            ContainmentAction::Terminate,
            11_000_000_000,
        );

        if let PartitionMode::Healing(info) = &engine.partition_mode {
            assert_eq!(info.conflict_count, 1);
        } else {
            panic!("expected healing mode");
        }

        let conflicts = engine.events_of_type(&ConvergenceEventType::ReconciliationConflict);
        assert_eq!(conflicts.len(), 1);
    }

    // -- ConvergenceEngine: telemetry --

    #[test]
    fn engine_emits_action_executed_events() {
        let mut engine = test_engine("local");
        let decision = engine.evaluate_extension("ext-1", 300_000, 5);
        engine.execute_decision(&decision, 1_000_000_000);

        let events = engine.events_of_type(&ConvergenceEventType::ActionExecuted);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fields.get("extension_id").unwrap(), "ext-1");
        assert_eq!(events[0].fields.get("action").unwrap(), "sandbox");
    }

    #[test]
    fn engine_emits_partition_events() {
        let mut engine = test_engine("local");
        let mut fleet = test_fleet_state("local");

        fleet
            .process_heartbeat(&test_heartbeat("remote-1", 1, 1_000_000_000))
            .unwrap();

        // Trigger partition.
        engine.update_partition_state(&fleet, 20_000_000_000);
        let entered = engine.events_of_type(&ConvergenceEventType::PartitionEntered);
        assert_eq!(entered.len(), 1);

        // Heal.
        fleet
            .process_heartbeat(&test_heartbeat("remote-1", 2, 19_000_000_000))
            .unwrap();
        engine.update_partition_state(&fleet, 20_000_000_000);
        // Healing state, then normal.
        engine.update_partition_state(&fleet, 20_000_000_001);

        let exited = engine.events_of_type(&ConvergenceEventType::PartitionExited);
        assert_eq!(exited.len(), 1);
    }

    #[test]
    fn engine_emits_spectral_health_events() {
        let mut engine = test_engine("local");
        let mut fleet = test_fleet_state("local");

        fleet
            .process_heartbeat(&test_heartbeat("remote-1", 1, 10_000_000_000))
            .unwrap();
        fleet
            .process_heartbeat(&test_heartbeat("remote-2", 1, 10_000_000_000))
            .unwrap();
        fleet
            .process_heartbeat(&test_heartbeat("remote-3", 1, 10_000_000_000))
            .unwrap();

        engine.update_partition_state(&fleet, 10_000_000_000);

        let events = engine.events_of_type(&ConvergenceEventType::SpectralHealthComputed);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fields.get("healthy_nodes").unwrap(), "3");
        assert!(events[0].fields.contains_key("spectral_gap_millionths"));
        assert!(events[0].fields.contains_key("lambda_max_millionths"));
        assert!(events[0].fields.contains_key("fiedler_iterations"));
        assert!(events[0].fields.contains_key("fiedler_residual_millionths"));
    }

    // -- ConvergenceEvent serde --

    #[test]
    fn convergence_event_serde_round_trip() {
        let event = ConvergenceEvent {
            event_type: ConvergenceEventType::ThresholdCrossed,
            trace_id: "trace-1".into(),
            node_id: test_node("local"),
            timestamp_ns: 5_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            fields: {
                let mut m = BTreeMap::new();
                m.insert("extension_id".into(), "ext-1".into());
                m
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: ConvergenceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, decoded);
    }

    #[test]
    fn convergence_event_type_display() {
        assert_eq!(
            ConvergenceEventType::ThresholdCrossed.to_string(),
            "threshold_crossed"
        );
        assert_eq!(
            ConvergenceEventType::EscalationTriggered.to_string(),
            "escalation_triggered"
        );
        assert_eq!(
            ConvergenceEventType::SpectralHealthComputed.to_string(),
            "spectral_health_computed"
        );
    }

    // -- ConvergenceError tests --

    #[test]
    fn convergence_error_display() {
        let err = ConvergenceError::MaxEscalationReached {
            extension_id: "ext-1".into(),
            depth: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("max escalation depth"));
        assert!(msg.contains("ext-1"));
    }

    #[test]
    fn convergence_error_serde_round_trip() {
        let err = ConvergenceError::AlreadyAtMaxSeverity {
            extension_id: "ext-1".into(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: ConvergenceError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }

    #[test]
    fn convergence_error_from_protocol_error() {
        let proto_err = ProtocolError::EmptyIntents;
        let conv_err: ConvergenceError = proto_err.into();
        assert!(matches!(conv_err, ConvergenceError::Protocol(_)));
    }

    // -- ConvergenceVerification serde --

    #[test]
    fn convergence_verification_serde_round_trip() {
        let v = ConvergenceVerification::Converged { checkpoint_seq: 42 };
        let json = serde_json::to_string(&v).unwrap();
        let decoded: ConvergenceVerification = serde_json::from_str(&json).unwrap();
        assert_eq!(v, decoded);
    }

    // -- ConvergenceConfig serde --

    #[test]
    fn convergence_config_serde_round_trip() {
        let config = ConvergenceConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let decoded: ConvergenceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.thresholds, decoded.thresholds);
        assert_eq!(
            config.degraded_tightening_factor,
            decoded.degraded_tightening_factor
        );
    }

    // -- Full integration: evidence → decision → receipt → verify --

    #[test]
    fn integration_evidence_to_verified_receipt() {
        let mut engine = test_engine("local");
        let mut fleet = test_fleet_state("local");

        // Accumulate evidence past suspend threshold (500_000).
        fleet
            .process_evidence(&test_evidence("node-a", "ext-1", 1, 300_000))
            .unwrap();
        fleet
            .process_evidence(&test_evidence("node-b", "ext-1", 1, 250_000))
            .unwrap();

        // Process fleet state.
        let receipts = engine.process_fleet_state(&fleet, 5_000_000_000);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].action_type, ContainmentAction::Suspend);
        assert!(receipts[0].verify_signature(&engine.config.signing_key));

        // Idempotent reprocessing produces no new receipts.
        let again = engine.process_fleet_state(&fleet, 6_000_000_000);
        assert!(again.is_empty());
    }

    #[test]
    fn integration_partition_tightens_then_heals() {
        let mut engine = test_engine("local");
        let mut fleet = test_fleet_state("local");

        // Register 3 heartbeats.
        for (i, name) in ["n1", "n2", "n3"].iter().enumerate() {
            fleet
                .process_heartbeat(&test_heartbeat(name, (i + 1) as u64, 1_000_000_000))
                .unwrap();
        }

        // Partition: only n1 still alive.
        fleet
            .process_heartbeat(&test_heartbeat("n1", 4, 19_000_000_000))
            .unwrap();
        engine.update_partition_state(&fleet, 20_000_000_000);
        assert!(matches!(engine.partition_mode, PartitionMode::Degraded(_)));

        // Under degraded mode, sandbox threshold is 150_000 (tightened from 200_000).
        let effective = engine.effective_thresholds();
        assert_eq!(effective.sandbox_threshold, 150_000);

        // Evidence at 170_000 would NOT trigger sandbox in normal mode,
        // but DOES trigger in degraded mode.
        fleet
            .process_evidence(&test_evidence("n1", "ext-1", 5, 170_000))
            .unwrap();
        let receipts = engine.process_fleet_state(&fleet, 20_000_000_001);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].action_type, ContainmentAction::Sandbox);
        assert!(receipts[0].degraded_mode);

        // Heal: all nodes send fresh heartbeats.
        for (i, name) in ["n1", "n2", "n3"].iter().enumerate() {
            fleet
                .process_heartbeat(&test_heartbeat(name, (i + 10) as u64, 25_000_000_000))
                .unwrap();
        }
        engine.update_partition_state(&fleet, 26_000_000_000);
        // Healing.
        engine.update_partition_state(&fleet, 26_000_000_001);
        assert!(matches!(engine.partition_mode, PartitionMode::Normal));
    }

    #[test]
    fn integration_escalation_chain() {
        let mut engine = test_engine("local");
        engine.config.max_escalation_depth = 4;

        // Initial sandbox.
        let sandbox = ConvergenceDecision {
            extension_id: "ext-1".into(),
            action: ContainmentAction::Sandbox,
            posterior_delta: 300_000,
            crossed_threshold: Some(200_000),
            degraded_mode: false,
            evidence_count: 5,
        };
        let r0 = engine.execute_decision(&sandbox, 1_000_000_000).unwrap();
        assert_eq!(r0.action_type, ContainmentAction::Sandbox);

        // Escalate: sandbox → suspend.
        let r1 = engine.escalate("ext-1", 300_000, 5, 2_000_000_000).unwrap();
        assert_eq!(r1.action_type, ContainmentAction::Suspend);

        // Escalate: suspend → terminate.
        let r2 = engine.escalate("ext-1", 300_000, 5, 3_000_000_000).unwrap();
        assert_eq!(r2.action_type, ContainmentAction::Terminate);

        // Escalate: terminate → quarantine.
        let r3 = engine.escalate("ext-1", 300_000, 5, 4_000_000_000).unwrap();
        assert_eq!(r3.action_type, ContainmentAction::Quarantine);

        // No further escalation possible.
        let err = engine
            .escalate("ext-1", 300_000, 5, 5_000_000_000)
            .unwrap_err();
        assert!(matches!(err, ConvergenceError::AlreadyAtMaxSeverity { .. }));
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn partition_info_serde_roundtrip() {
        let info = PartitionInfo {
            detected_at_ns: 42_000_000_000,
            unreachable_nodes: {
                let mut s = BTreeSet::new();
                s.insert(test_node("n1"));
                s.insert(test_node("n2"));
                s
            },
            local_partition_size: 3,
            total_fleet_size: 5,
        };
        let json = serde_json::to_string(&info).unwrap();
        let decoded: PartitionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, decoded);
    }

    #[test]
    fn healing_info_serde_roundtrip() {
        let info = HealingInfo {
            heal_started_ns: 99_000_000_000,
            reconciling_nodes: {
                let mut s = BTreeSet::new();
                s.insert(test_node("n1"));
                s
            },
            conflict_count: 7,
            merged_evidence_count: 42,
        };
        let json = serde_json::to_string(&info).unwrap();
        let decoded: HealingInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, decoded);
    }

    #[test]
    fn partition_mode_all_variants_serde_roundtrip() {
        let normal = PartitionMode::Normal;
        let degraded = PartitionMode::Degraded(PartitionInfo {
            detected_at_ns: 1,
            unreachable_nodes: BTreeSet::new(),
            local_partition_size: 1,
            total_fleet_size: 2,
        });
        let healing = PartitionMode::Healing(HealingInfo {
            heal_started_ns: 2,
            reconciling_nodes: BTreeSet::new(),
            conflict_count: 0,
            merged_evidence_count: 0,
        });
        for mode in [normal, degraded, healing] {
            let json = serde_json::to_string(&mode).unwrap();
            let decoded: PartitionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, decoded);
        }
    }

    #[test]
    fn convergence_decision_serde_roundtrip() {
        let decision = ConvergenceDecision {
            extension_id: "ext-abc".into(),
            action: ContainmentAction::Terminate,
            posterior_delta: 850_000,
            crossed_threshold: Some(800_000),
            degraded_mode: true,
            evidence_count: 20,
        };
        let json = serde_json::to_string(&decision).unwrap();
        let decoded: ConvergenceDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, decoded);
    }

    #[test]
    fn action_registry_serde_roundtrip() {
        let mut reg = ActionRegistry::new();
        reg.record(ContainmentReceipt {
            action_id: "a1".into(),
            extension_id: "ext-1".into(),
            action_type: ContainmentAction::Suspend,
            evidence_ids: vec!["e1".into()],
            posterior_snapshot: 600_000,
            policy_version: 1,
            node_id: test_node("local"),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: 1_000,
            degraded_mode: false,
            escalation_depth: 0,
            signature: AuthenticityHash::compute_keyed(b"k", b"v"),
        });
        reg.increment_escalation("ext-1");

        let json = serde_json::to_string(&reg).unwrap();
        let decoded: ActionRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.total_actions(), 1);
        assert!(decoded.is_executed("ext-1", ContainmentAction::Suspend));
        assert_eq!(decoded.escalation_depth("ext-1"), 1);
    }

    #[test]
    fn convergence_event_type_display_all_variants_distinct() {
        let variants = [
            ConvergenceEventType::ThresholdCrossed,
            ConvergenceEventType::ActionExecuted,
            ConvergenceEventType::PartitionEntered,
            ConvergenceEventType::PartitionExited,
            ConvergenceEventType::ReconciliationConflict,
            ConvergenceEventType::ConvergenceVerified,
            ConvergenceEventType::ConvergenceDiverged,
            ConvergenceEventType::EscalationTriggered,
            ConvergenceEventType::EvidenceLag,
            ConvergenceEventType::SpectralHealthComputed,
        ];
        let mut seen = BTreeSet::new();
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty());
            assert!(seen.insert(s.clone()), "duplicate Display: {s}");
        }
        assert_eq!(seen.len(), variants.len());
    }

    #[test]
    fn convergence_error_display_all_variants_distinct() {
        let variants: Vec<ConvergenceError> = vec![
            ConvergenceError::MaxEscalationReached {
                extension_id: "ext-1".into(),
                depth: 3,
            },
            ConvergenceError::AlreadyAtMaxSeverity {
                extension_id: "ext-1".into(),
            },
            ConvergenceError::ActionAlreadyExecuted {
                extension_id: "ext-1".into(),
                action: ContainmentAction::Sandbox,
            },
            ConvergenceError::InvalidThresholds,
            ConvergenceError::Protocol(ProtocolError::EmptyIntents),
        ];
        let mut seen = BTreeSet::new();
        for e in &variants {
            let s = e.to_string();
            assert!(!s.is_empty());
            assert!(seen.insert(s.clone()), "duplicate Display: {s}");
        }
        assert_eq!(seen.len(), variants.len());
    }

    #[test]
    fn receipt_preimage_sensitive_to_action_type() {
        let base = ContainmentReceipt {
            action_id: "a1".into(),
            extension_id: "ext-1".into(),
            action_type: ContainmentAction::Sandbox,
            evidence_ids: vec![],
            posterior_snapshot: 300_000,
            policy_version: 1,
            node_id: test_node("local"),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: 1_000,
            degraded_mode: false,
            escalation_depth: 0,
            signature: AuthenticityHash::compute_keyed(b"k", b"v"),
        };
        let mut other = base.clone();
        other.action_type = ContainmentAction::Terminate;
        assert_ne!(base.signing_preimage(), other.signing_preimage());
    }

    #[test]
    fn receipt_preimage_sensitive_to_extension_id() {
        let base = ContainmentReceipt {
            action_id: "a1".into(),
            extension_id: "ext-1".into(),
            action_type: ContainmentAction::Sandbox,
            evidence_ids: vec![],
            posterior_snapshot: 300_000,
            policy_version: 1,
            node_id: test_node("local"),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: 1_000,
            degraded_mode: false,
            escalation_depth: 0,
            signature: AuthenticityHash::compute_keyed(b"k", b"v"),
        };
        let mut other = base.clone();
        other.extension_id = "ext-2".into();
        assert_ne!(base.signing_preimage(), other.signing_preimage());
    }

    #[test]
    fn tighten_with_zero_factor_zeroes_thresholds() {
        let t = ContainmentThresholds::default();
        let zeroed = t.tighten(0);
        assert_eq!(zeroed.sandbox_threshold, 0);
        assert_eq!(zeroed.suspend_threshold, 0);
        assert_eq!(zeroed.terminate_threshold, 0);
        assert_eq!(zeroed.quarantine_threshold, 0);
    }

    #[test]
    fn evaluate_extension_in_healing_mode_sets_degraded() {
        let mut engine = test_engine("local");
        engine.partition_mode = PartitionMode::Healing(HealingInfo {
            heal_started_ns: 1,
            reconciling_nodes: BTreeSet::new(),
            conflict_count: 0,
            merged_evidence_count: 0,
        });
        let decision = engine.evaluate_extension("ext-1", 300_000, 5);
        assert!(decision.degraded_mode);
        // Healing uses tightened thresholds, so sandbox threshold = 150_000.
        assert_eq!(decision.action, ContainmentAction::Sandbox);
    }

    #[test]
    fn action_registry_get_receipt_returns_recorded() {
        let mut reg = ActionRegistry::new();
        assert!(
            reg.get_receipt("ext-1", ContainmentAction::Sandbox)
                .is_none()
        );

        let receipt = ContainmentReceipt {
            action_id: "a1".into(),
            extension_id: "ext-1".into(),
            action_type: ContainmentAction::Sandbox,
            evidence_ids: vec![],
            posterior_snapshot: 300_000,
            policy_version: 1,
            node_id: test_node("local"),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: 1_000,
            degraded_mode: false,
            escalation_depth: 0,
            signature: AuthenticityHash::compute_keyed(b"k", b"v"),
        };
        reg.record(receipt.clone());

        let got = reg
            .get_receipt("ext-1", ContainmentAction::Sandbox)
            .unwrap();
        assert_eq!(got.action_id, "a1");
    }

    #[test]
    fn thresholds_equal_values_are_invalid() {
        let t = ContainmentThresholds {
            sandbox_threshold: 500_000,
            suspend_threshold: 500_000,
            terminate_threshold: 800_000,
            quarantine_threshold: 950_000,
        };
        assert!(!t.is_valid());
    }

    #[test]
    fn partition_info_is_minority_with_full_quorum() {
        // 100% quorum threshold: everyone must be present.
        let info = PartitionInfo {
            detected_at_ns: 0,
            unreachable_nodes: BTreeSet::new(),
            local_partition_size: 4,
            total_fleet_size: 5,
        };
        // Need 5 out of 5, have 4 → minority.
        assert!(info.is_minority(1_000_000));
    }

    #[test]
    fn convergence_engine_serde_roundtrip() {
        let engine = test_engine("local");
        let json = serde_json::to_string(&engine).unwrap();
        let decoded: ConvergenceEngine = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.node_id, engine.node_id);
        assert_eq!(decoded.policy_version, engine.policy_version);
        assert_eq!(decoded.config.thresholds, engine.config.thresholds);
        assert!(matches!(decoded.partition_mode, PartitionMode::Normal));
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn config_default_exact_values() {
        let cfg = ConvergenceConfig::default();
        assert_eq!(cfg.degraded_tightening_factor, 750_000);
        assert_eq!(cfg.convergence_timeout_ns, 1_000_000_000);
        assert_eq!(cfg.signing_key, b"default-convergence-key".to_vec());
        assert_eq!(cfg.max_escalation_depth, 3);
        assert!(cfg.thresholds.is_valid());
    }

    #[test]
    fn convergence_verification_diverged_serde_roundtrip() {
        let v = ConvergenceVerification::Diverged {
            checkpoint_seq: 7,
            local_summary_hash: ContentHash::compute(b"local"),
            checkpoint_summary_hash: ContentHash::compute(b"remote"),
        };
        let json = serde_json::to_string(&v).unwrap();
        let decoded: ConvergenceVerification = serde_json::from_str(&json).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn convergence_error_serde_all_5_variants() {
        let variants: Vec<ConvergenceError> = vec![
            ConvergenceError::MaxEscalationReached {
                extension_id: "ext-1".into(),
                depth: 3,
            },
            ConvergenceError::AlreadyAtMaxSeverity {
                extension_id: "ext-2".into(),
            },
            ConvergenceError::ActionAlreadyExecuted {
                extension_id: "ext-3".into(),
                action: ContainmentAction::Terminate,
            },
            ConvergenceError::InvalidThresholds,
            ConvergenceError::Protocol(ProtocolError::EmptyIntents),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let decoded: ConvergenceError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, decoded);
        }
    }

    #[test]
    fn convergence_error_source_returns_none() {
        use std::error::Error;
        let err = ConvergenceError::MaxEscalationReached {
            extension_id: "ext-1".into(),
            depth: 2,
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn convergence_error_display_exact_formats() {
        assert_eq!(
            ConvergenceError::MaxEscalationReached {
                extension_id: "ext-a".into(),
                depth: 5,
            }
            .to_string(),
            "max escalation depth 5 reached for ext-a"
        );
        assert_eq!(
            ConvergenceError::AlreadyAtMaxSeverity {
                extension_id: "ext-b".into(),
            }
            .to_string(),
            "extension ext-b already at maximum severity (quarantine)"
        );
        assert_eq!(
            ConvergenceError::ActionAlreadyExecuted {
                extension_id: "ext-c".into(),
                action: ContainmentAction::Suspend,
            }
            .to_string(),
            "action suspend already executed for ext-c"
        );
        assert_eq!(
            ConvergenceError::InvalidThresholds.to_string(),
            "invalid threshold configuration"
        );
        let proto_msg = ConvergenceError::Protocol(ProtocolError::EmptyIntents).to_string();
        assert!(proto_msg.starts_with("protocol error: "));
    }

    #[test]
    fn event_ring_buffer_eviction() {
        let mut engine = test_engine("local");
        engine.max_events = 5;

        // Generate 7 events — only last 5 should survive.
        for i in 0..7u64 {
            let decision = engine.evaluate_extension(&format!("ext-{i}"), 300_000, 5);
            engine.execute_decision(&decision, i * 1_000_000_000);
        }

        assert_eq!(engine.events.len(), 5);
        // The first events should have been evicted.
        assert!(engine.events[0].fields.get("extension_id").unwrap() != "ext-0");
    }

    #[test]
    fn effective_thresholds_degraded_majority_uses_base() {
        let mut engine = test_engine("local");
        // Degraded but majority (local=4 out of 5, need 3 for 50% quorum).
        engine.partition_mode = PartitionMode::Degraded(PartitionInfo {
            detected_at_ns: 0,
            unreachable_nodes: {
                let mut s = BTreeSet::new();
                s.insert(test_node("n1"));
                s
            },
            local_partition_size: 4,
            total_fleet_size: 5,
        });

        let effective = engine.effective_thresholds();
        // Majority partition → base thresholds, NOT tightened.
        assert_eq!(effective, engine.config.thresholds);
    }

    #[test]
    fn evaluate_all_returns_decisions_for_all_extensions() {
        let engine = test_engine("local");
        let mut fleet = test_fleet_state("local");

        fleet
            .process_evidence(&test_evidence("n1", "ext-1", 1, 300_000))
            .unwrap();
        fleet
            .process_evidence(&test_evidence("n1", "ext-2", 2, 100_000))
            .unwrap();

        let decisions = engine.evaluate_all(&fleet);
        assert_eq!(decisions.len(), 2);

        let ext_ids: BTreeSet<_> = decisions.iter().map(|d| d.extension_id.as_str()).collect();
        assert!(ext_ids.contains("ext-1"));
        assert!(ext_ids.contains("ext-2"));
    }

    #[test]
    fn reconciliation_conflict_in_normal_mode_emits_event_but_no_increment() {
        let mut engine = test_engine("local");
        // Engine is in Normal mode (default).
        engine.record_reconciliation_conflict(
            "ext-1",
            ContainmentAction::Sandbox,
            ContainmentAction::Terminate,
            1_000_000_000,
        );

        let conflicts = engine.events_of_type(&ConvergenceEventType::ReconciliationConflict);
        assert_eq!(conflicts.len(), 1);
        // No HealingInfo to increment — no panic.
        assert!(matches!(engine.partition_mode, PartitionMode::Normal));
    }

    #[test]
    fn reconciliation_conflict_resolved_action_is_higher_severity() {
        let mut engine = test_engine("local");
        engine.partition_mode = PartitionMode::Healing(HealingInfo {
            heal_started_ns: 1,
            reconciling_nodes: BTreeSet::new(),
            conflict_count: 0,
            merged_evidence_count: 0,
        });

        engine.record_reconciliation_conflict(
            "ext-1",
            ContainmentAction::Sandbox,
            ContainmentAction::Terminate,
            2_000_000_000,
        );

        let conflicts = engine.events_of_type(&ConvergenceEventType::ReconciliationConflict);
        assert_eq!(
            conflicts[0].fields.get("resolved_action").unwrap(),
            "terminate"
        );
        assert_eq!(conflicts[0].fields.get("local_action").unwrap(), "sandbox");
        assert_eq!(
            conflicts[0].fields.get("remote_action").unwrap(),
            "terminate"
        );
    }

    #[test]
    fn re_partition_during_healing_reverts_to_degraded() {
        let mut engine = test_engine("local");
        let mut fleet = test_fleet_state("local");

        fleet
            .process_heartbeat(&test_heartbeat("remote-1", 1, 1_000_000_000))
            .unwrap();

        // Trigger partition.
        engine.update_partition_state(&fleet, 20_000_000_000);
        assert!(matches!(engine.partition_mode, PartitionMode::Degraded(_)));

        // Heal: fresh heartbeat.
        fleet
            .process_heartbeat(&test_heartbeat("remote-1", 2, 19_000_000_000))
            .unwrap();
        engine.update_partition_state(&fleet, 20_000_000_000);
        assert!(matches!(engine.partition_mode, PartitionMode::Healing(_)));

        // Re-partition: remote-1 goes stale again, remote-2 also stale.
        fleet
            .process_heartbeat(&test_heartbeat("remote-2", 1, 1_000_000_000))
            .unwrap();
        engine.update_partition_state(&fleet, 40_000_000_000);
        // Should revert from Healing to Degraded.
        assert!(matches!(engine.partition_mode, PartitionMode::Degraded(_)));
    }

    #[test]
    fn verify_converged_emits_event_with_checkpoint_seq() {
        let mut engine = test_engine("local");
        let fleet = test_fleet_state("local");

        let summary_hash = fleet.evidence.summary_hash();
        let checkpoint = make_checkpoint(42, summary_hash, vec![]);

        engine.verify_against_checkpoint(&fleet, &checkpoint, 5_000_000_000);

        let events = engine.events_of_type(&ConvergenceEventType::ConvergenceVerified);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fields.get("checkpoint_seq").unwrap(), "42");
    }

    #[test]
    fn verify_diverged_emits_event_with_hash_info() {
        let mut engine = test_engine("local");
        let fleet = test_fleet_state("local");

        let different_hash = ContentHash::compute(b"different-state");
        let checkpoint = make_checkpoint(99, different_hash, vec![]);

        engine.verify_against_checkpoint(&fleet, &checkpoint, 5_000_000_000);

        let events = engine.events_of_type(&ConvergenceEventType::ConvergenceDiverged);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fields.get("checkpoint_seq").unwrap(), "99");
        assert!(events[0].fields.contains_key("local_hash"));
    }

    #[test]
    fn action_ids_are_unique_across_executions() {
        let mut engine = test_engine("local");

        let d1 = engine.evaluate_extension("ext-1", 300_000, 5);
        let r1 = engine.execute_decision(&d1, 1_000_000_000).unwrap();

        let d2 = engine.evaluate_extension("ext-2", 600_000, 10);
        let r2 = engine.execute_decision(&d2, 2_000_000_000).unwrap();

        assert_ne!(r1.action_id, r2.action_id);
        assert!(r1.action_id.contains("local"));
        assert!(r2.action_id.contains("local"));
    }

    #[test]
    fn escalation_emits_escalation_triggered_event() {
        let mut engine = test_engine("local");

        let sandbox = ConvergenceDecision {
            extension_id: "ext-1".into(),
            action: ContainmentAction::Sandbox,
            posterior_delta: 300_000,
            crossed_threshold: Some(200_000),
            degraded_mode: false,
            evidence_count: 5,
        };
        engine.execute_decision(&sandbox, 1_000_000_000).unwrap();

        engine.escalate("ext-1", 300_000, 5, 2_000_000_000).unwrap();

        let events = engine.events_of_type(&ConvergenceEventType::EscalationTriggered);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fields.get("extension_id").unwrap(), "ext-1");
        assert_eq!(events[0].fields.get("from_action").unwrap(), "sandbox");
        assert_eq!(events[0].fields.get("to_action").unwrap(), "suspend");
        assert_eq!(events[0].fields.get("depth").unwrap(), "1");
    }

    #[test]
    fn engine_new_starts_with_expected_initial_state() {
        let engine = test_engine("local");
        assert!(matches!(engine.partition_mode, PartitionMode::Normal));
        assert_eq!(engine.current_epoch, SecurityEpoch::GENESIS);
        assert_eq!(engine.policy_version, 1);
        assert_eq!(engine.action_registry.total_actions(), 0);
        assert!(engine.events.is_empty());
    }

    #[test]
    fn escalation_from_allow_to_sandbox() {
        let mut engine = test_engine("local");
        // No prior action — escalation from Allow to Sandbox.
        let receipt = engine.escalate("ext-1", 100_000, 2, 1_000_000_000).unwrap();
        assert_eq!(receipt.action_type, ContainmentAction::Sandbox);
        assert_eq!(receipt.escalation_depth, 1);
    }

    #[test]
    fn receipt_signing_preimage_sensitive_to_degraded_mode() {
        let base = ContainmentReceipt {
            action_id: "a1".into(),
            extension_id: "ext-1".into(),
            action_type: ContainmentAction::Sandbox,
            evidence_ids: vec![],
            posterior_snapshot: 300_000,
            policy_version: 1,
            node_id: test_node("local"),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: 1_000,
            degraded_mode: false,
            escalation_depth: 0,
            signature: AuthenticityHash::compute_keyed(b"k", b"v"),
        };
        let mut degraded = base.clone();
        degraded.degraded_mode = true;
        assert_ne!(base.signing_preimage(), degraded.signing_preimage());
    }

    #[test]
    fn receipt_signing_preimage_sensitive_to_escalation_depth() {
        let base = ContainmentReceipt {
            action_id: "a1".into(),
            extension_id: "ext-1".into(),
            action_type: ContainmentAction::Sandbox,
            evidence_ids: vec![],
            posterior_snapshot: 300_000,
            policy_version: 1,
            node_id: test_node("local"),
            epoch: SecurityEpoch::GENESIS,
            timestamp_ns: 1_000,
            degraded_mode: false,
            escalation_depth: 0,
            signature: AuthenticityHash::compute_keyed(b"k", b"v"),
        };
        let mut escalated = base.clone();
        escalated.escalation_depth = 2;
        assert_ne!(base.signing_preimage(), escalated.signing_preimage());
    }
}
