//! Quarantine propagation protocol for fleet-wide containment decisions.
//!
//! Implements broadcast, causal ordering, acknowledgment, and convergence tracking
//! for quarantine decisions across fleet instances. Builds on fleet_simulator.rs
//! infrastructure for deterministic message delivery and state synchronization.
//!
//! Plan reference: bd-6a61n.5.2

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::fleet_convergence::{ContainmentThresholds, PartitionMode};
use crate::fleet_immune_protocol::{NodeId, QuorumCheckpoint};
use crate::fleet_simulator::{FleetSimulator, MessagePayload, SimulationEvent};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Core quarantine message types
// ---------------------------------------------------------------------------

/// Quarantine decision message broadcast to fleet instances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineDecision {
    /// Extension being quarantined.
    pub extension_id: String,
    /// Human-readable reason for quarantine.
    pub reason: String,
    /// Evidence hash for deduplication and verification.
    pub evidence_hash: ContentHash,
    /// Instance that originated the decision.
    pub originator_instance: NodeId,
    /// Lamport timestamp for causal ordering.
    pub lamport_timestamp: u64,
    /// Security epoch for version consistency.
    pub security_epoch: SecurityEpoch,
    /// Decision timestamp for timeout tracking. Not serialized — `Instant`
    /// is monotonic and only meaningful within a single process.
    #[serde(skip, default = "Instant::now")]
    pub decision_timestamp: Instant,
}

impl QuarantineDecision {
    /// Create a new quarantine decision.
    pub fn new(
        extension_id: String,
        reason: String,
        originator_instance: NodeId,
        lamport_timestamp: u64,
        security_epoch: SecurityEpoch,
    ) -> Self {
        let content = format!(
            "{}:{}:{}:{}",
            extension_id, reason, originator_instance.0, lamport_timestamp
        );
        let evidence_hash = ContentHash::compute(content.as_bytes());

        Self {
            extension_id,
            reason,
            evidence_hash,
            originator_instance,
            lamport_timestamp,
            security_epoch,
            decision_timestamp: Instant::now(),
        }
    }

    /// Get decision age since creation.
    pub fn age(&self) -> Duration {
        self.decision_timestamp.elapsed()
    }
}

/// Acknowledgment of quarantine enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineAck {
    /// Evidence hash of the decision being acknowledged.
    pub decision_evidence_hash: ContentHash,
    /// Instance sending the acknowledgment.
    pub acknowledging_instance: NodeId,
    /// Lamport timestamp of acknowledgment.
    pub ack_timestamp: u64,
    /// Whether enforcement was successful.
    pub enforcement_successful: bool,
    /// Optional enforcement details.
    pub enforcement_details: Option<String>,
}

impl QuarantineAck {
    /// Create a new quarantine acknowledgment.
    pub fn new(
        decision_evidence_hash: ContentHash,
        acknowledging_instance: NodeId,
        ack_timestamp: u64,
        enforcement_successful: bool,
        enforcement_details: Option<String>,
    ) -> Self {
        Self {
            decision_evidence_hash,
            acknowledging_instance,
            ack_timestamp,
            enforcement_successful,
            enforcement_details,
        }
    }
}

/// Quarantine enforcement state for an instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineState {
    /// Set of quarantined extension IDs.
    pub quarantined_extensions: BTreeSet<String>,
    /// Pending decisions awaiting acknowledgment.
    pub pending_decisions: BTreeMap<ContentHash, QuarantineDecision>,
    /// Track acknowledgments received per decision.
    pub acknowledgments: BTreeMap<ContentHash, BTreeSet<NodeId>>,
    /// Decisions seen (for idempotency).
    pub seen_decisions: BTreeSet<ContentHash>,
}

impl QuarantineState {
    /// Create a new empty quarantine state.
    pub fn new() -> Self {
        Self {
            quarantined_extensions: BTreeSet::new(),
            pending_decisions: BTreeMap::new(),
            acknowledgments: BTreeMap::new(),
            seen_decisions: BTreeSet::new(),
        }
    }

    /// Check if an extension is quarantined.
    pub fn is_quarantined(&self, extension_id: &str) -> bool {
        self.quarantined_extensions.contains(extension_id)
    }

    /// Add a quarantine decision if not already seen.
    pub fn add_decision(&mut self, decision: QuarantineDecision) -> bool {
        if self.seen_decisions.contains(&decision.evidence_hash) {
            return false; // Duplicate decision
        }

        let evidence_hash = decision.evidence_hash;
        self.seen_decisions.insert(evidence_hash);
        self.quarantined_extensions
            .insert(decision.extension_id.clone());
        self.pending_decisions.insert(evidence_hash, decision);
        self.acknowledgments
            .insert(evidence_hash, BTreeSet::new());
        true
    }

    /// Record an acknowledgment for a decision.
    pub fn add_acknowledgment(&mut self, ack: QuarantineAck) -> bool {
        if let Some(ack_set) = self.acknowledgments.get_mut(&ack.decision_evidence_hash) {
            ack_set.insert(ack.acknowledging_instance);
            true
        } else {
            false // Unknown decision
        }
    }

    /// Check if a decision has converged (all instances acknowledged).
    pub fn is_converged(&self, evidence_hash: &ContentHash, total_instances: usize) -> bool {
        if let Some(acks) = self.acknowledgments.get(evidence_hash) {
            acks.len() >= total_instances.saturating_sub(1) // Exclude originator
        } else {
            false
        }
    }

    /// Get convergence progress for a decision.
    pub fn convergence_progress(&self, evidence_hash: &ContentHash) -> Option<(usize, usize)> {
        self.acknowledgments
            .get(evidence_hash)
            .map(|acks| (acks.len(), acks.len()))
    }
}

impl Default for QuarantineState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Quarantine protocol manager
// ---------------------------------------------------------------------------

/// Manages quarantine propagation protocol for a fleet.
#[derive(Debug)]
pub struct QuarantineProtocolManager {
    /// Fleet simulator for message delivery.
    pub fleet_simulator: FleetSimulator,
    /// Quarantine states per instance.
    pub instance_states: BTreeMap<NodeId, QuarantineState>,
    /// Global Lamport clock.
    pub lamport_clock: u64,
    /// Current security epoch.
    pub security_epoch: SecurityEpoch,
    /// Convergence timeout configuration.
    pub convergence_timeout: Duration,
    /// Protocol statistics.
    pub stats: ProtocolStats,
}

/// Protocol operation statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolStats {
    /// Total quarantine decisions issued.
    pub decisions_issued: u64,
    /// Total acknowledgments received.
    pub acknowledgments_received: u64,
    /// Total decisions that converged.
    pub decisions_converged: u64,
    /// Total duplicate decisions ignored.
    pub duplicates_ignored: u64,
    /// Total messages sent.
    pub messages_sent: u64,
}

/// Errors that can occur during quarantine protocol operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum QuarantineProtocolError {
    #[error("Instance not found: {instance_id}")]
    InstanceNotFound { instance_id: NodeId },
    #[error("Decision not found: {evidence_hash:?}")]
    DecisionNotFound { evidence_hash: ContentHash },
    #[error("Fleet simulation error: {error}")]
    FleetSimulationError { error: String },
    #[error("Message delivery failed: {reason}")]
    MessageDeliveryFailed { reason: String },
    #[error("Convergence timeout for decision: {evidence_hash:?}")]
    ConvergenceTimeout { evidence_hash: ContentHash },
}

impl QuarantineProtocolManager {
    /// Create a new quarantine protocol manager.
    pub fn new(
        fleet_simulator: FleetSimulator,
        security_epoch: SecurityEpoch,
        convergence_timeout: Duration,
    ) -> Self {
        let instance_ids = fleet_simulator.instance_ids();
        let mut instance_states = BTreeMap::new();

        for node_id in instance_ids {
            instance_states.insert(node_id, QuarantineState::new());
        }

        Self {
            fleet_simulator,
            instance_states,
            lamport_clock: 0,
            security_epoch,
            convergence_timeout,
            stats: ProtocolStats::default(),
        }
    }

    /// Issue a quarantine decision from an originating instance.
    pub fn issue_quarantine_decision(
        &mut self,
        originator: &NodeId,
        extension_id: String,
        reason: String,
    ) -> Result<ContentHash, QuarantineProtocolError> {
        self.lamport_clock += 1;

        let decision = QuarantineDecision::new(
            extension_id.clone(),
            reason,
            originator.clone(),
            self.lamport_clock,
            self.security_epoch,
        );

        let evidence_hash = decision.evidence_hash;

        // Record decision in originator's state
        if let Some(originator_state) = self.instance_states.get_mut(originator) {
            originator_state.add_decision(decision.clone());
        } else {
            return Err(QuarantineProtocolError::InstanceNotFound {
                instance_id: originator.clone(),
            });
        }

        // Broadcast decision to all other instances
        self.broadcast_quarantine_decision(originator, decision)?;

        self.stats.decisions_issued += 1;
        Ok(evidence_hash)
    }

    /// Broadcast a quarantine decision to all fleet instances.
    fn broadcast_quarantine_decision(
        &mut self,
        originator: &NodeId,
        decision: QuarantineDecision,
    ) -> Result<(), QuarantineProtocolError> {
        let mut intent_extensions = BTreeMap::new();
        intent_extensions.insert("reason".to_string(), decision.reason.clone());
        let payload = MessagePayload::Protocol(crate::fleet_immune_protocol::FleetMessage::Intent(
            crate::fleet_immune_protocol::ContainmentIntent {
                intent_id: format!(
                    "quarantine-{}-{}",
                    decision.extension_id, decision.lamport_timestamp
                ),
                extension_id: decision.extension_id.clone(),
                proposed_action: crate::fleet_immune_protocol::ContainmentAction::Quarantine,
                confidence_millionths: 1_000_000,
                supporting_evidence_ids: vec![decision.evidence_hash.to_hex()],
                policy_version: 1,
                epoch: decision.security_epoch,
                node_id: originator.clone(),
                sequence: decision.lamport_timestamp,
                timestamp_ns: decision.lamport_timestamp,
                signature: crate::fleet_immune_protocol::MessageSignature {
                    signer: originator.clone(),
                    hash: crate::hash_tiers::AuthenticityHash([0u8; 32]),
                },
                protocol_version: crate::fleet_immune_protocol::ProtocolVersion::CURRENT,
                extensions: intent_extensions,
            },
        ));

        self.fleet_simulator
            .send_message(originator, None, payload) // None = broadcast
            .map_err(|e| QuarantineProtocolError::FleetSimulationError {
                error: format!("{}", e),
            })?;

        self.stats.messages_sent += 1;
        Ok(())
    }

    /// Process incoming quarantine decision message.
    pub fn process_quarantine_decision(
        &mut self,
        target_instance: &NodeId,
        decision: QuarantineDecision,
    ) -> Result<bool, QuarantineProtocolError> {
        let instance_state = self
            .instance_states
            .get_mut(target_instance)
            .ok_or_else(|| QuarantineProtocolError::InstanceNotFound {
                instance_id: target_instance.clone(),
            })?;

        let is_new = instance_state.add_decision(decision.clone());

        if is_new {
            // Send acknowledgment back to originator
            self.send_acknowledgment(target_instance, &decision)?;
        } else {
            self.stats.duplicates_ignored += 1;
        }

        Ok(is_new)
    }

    /// Send acknowledgment for a quarantine decision.
    fn send_acknowledgment(
        &mut self,
        acknowledging_instance: &NodeId,
        decision: &QuarantineDecision,
    ) -> Result<(), QuarantineProtocolError> {
        self.lamport_clock += 1;

        let ack = QuarantineAck::new(
            decision.evidence_hash,
            acknowledging_instance.clone(),
            self.lamport_clock,
            true, // Assume successful enforcement
            Some(format!("Quarantined extension: {}", decision.extension_id)),
        );

        // Send ack to originator
        let payload = MessagePayload::StateChange {
            old_state: crate::fleet_simulator::InstanceState::Healthy,
            new_state: crate::fleet_simulator::InstanceState::Healthy,
            reason: format!("Quarantine ack: {}", decision.extension_id),
        };

        self.fleet_simulator
            .send_message(
                acknowledging_instance,
                Some(&decision.originator_instance),
                payload,
            )
            .map_err(|e| QuarantineProtocolError::FleetSimulationError {
                error: format!("{}", e),
            })?;

        self.stats.messages_sent += 1;
        Ok(())
    }

    /// Process incoming acknowledgment.
    pub fn process_acknowledgment(
        &mut self,
        ack: QuarantineAck,
    ) -> Result<bool, QuarantineProtocolError> {
        // Record acknowledgment in originator's state
        let total_instances = self.instance_states.len();

        if let Some(originator_state) = self.instance_states.get_mut(&ack.acknowledging_instance) {
            let recorded = originator_state.add_acknowledgment(ack.clone());

            if recorded {
                self.stats.acknowledgments_received += 1;

                // Check if decision has converged
                if originator_state.is_converged(&ack.decision_evidence_hash, total_instances) {
                    self.stats.decisions_converged += 1;
                    return Ok(true); // Converged
                }
            }
        }

        Ok(false) // Not converged
    }

    /// Check if a specific decision has converged.
    pub fn is_decision_converged(&self, evidence_hash: &ContentHash) -> bool {
        let total_instances = self.instance_states.len();

        for state in self.instance_states.values() {
            if state.is_converged(evidence_hash, total_instances) {
                return true;
            }
        }
        false
    }

    /// Get list of all quarantined extensions across all instances.
    pub fn get_quarantined_extensions(&self) -> BTreeSet<String> {
        let mut all_quarantined = BTreeSet::new();

        for state in self.instance_states.values() {
            all_quarantined.extend(state.quarantined_extensions.iter().cloned());
        }

        all_quarantined
    }

    /// Run protocol simulation steps.
    pub fn run_protocol_steps(&mut self, steps: u64) -> Result<(), QuarantineProtocolError> {
        self.fleet_simulator
            .run_simulation_steps(steps)
            .map_err(|e| QuarantineProtocolError::FleetSimulationError {
                error: format!("{}", e),
            })?;
        Ok(())
    }

    /// Get protocol statistics.
    pub fn get_stats(&self) -> ProtocolStats {
        self.stats.clone()
    }

    /// Export protocol state as JSON for analysis.
    pub fn export_protocol_state(&self) -> String {
        serde_json::to_string_pretty(&self.instance_states).unwrap_or_else(|_| "{}".to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_convergence::ContainmentThresholds;

    fn test_thresholds() -> ContainmentThresholds {
        ContainmentThresholds {
            sandbox_threshold: 1_000_000,
            suspend_threshold: 5_000_000,
            terminate_threshold: 10_000_000,
            quarantine_threshold: 20_000_000,
        }
    }

    fn test_security_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    #[test]
    fn test_quarantine_decision_creation() {
        let node_id = NodeId("test-instance".to_string());
        let decision = QuarantineDecision::new(
            "malicious-extension".to_string(),
            "Suspicious behavior detected".to_string(),
            node_id,
            1,
            test_security_epoch(),
        );

        assert_eq!(decision.extension_id, "malicious-extension");
        assert_eq!(decision.reason, "Suspicious behavior detected");
        assert_eq!(decision.lamport_timestamp, 1);
        assert!(decision.age() >= Duration::from_millis(0));
    }

    #[test]
    fn test_quarantine_state_operations() {
        let mut state = QuarantineState::new();

        let decision = QuarantineDecision::new(
            "test-extension".to_string(),
            "Test quarantine".to_string(),
            NodeId("originator".to_string()),
            1,
            test_security_epoch(),
        );

        let evidence_hash = decision.evidence_hash;

        // Add decision
        assert!(state.add_decision(decision));
        assert!(state.is_quarantined("test-extension"));
        assert!(!state.is_converged(&evidence_hash, 3));

        // Duplicate decision should be ignored
        let duplicate = QuarantineDecision::new(
            "test-extension".to_string(),
            "Test quarantine".to_string(),
            NodeId("originator".to_string()),
            1,
            test_security_epoch(),
        );
        assert!(!state.add_decision(duplicate));

        // Add acknowledgments
        let ack1 = QuarantineAck::new(
            evidence_hash,
            NodeId("instance-1".to_string()),
            2,
            true,
            None,
        );
        let ack2 = QuarantineAck::new(
            evidence_hash,
            NodeId("instance-2".to_string()),
            3,
            true,
            None,
        );

        assert!(state.add_acknowledgment(ack1));
        assert!(!state.is_converged(&evidence_hash, 3)); // Need 2 acks for 3 instances

        assert!(state.add_acknowledgment(ack2));
        assert!(state.is_converged(&evidence_hash, 3)); // Now converged
    }

    #[test]
    fn test_protocol_manager_initialization() {
        let fleet = FleetSimulator::new(5, test_thresholds()).unwrap();
        let manager =
            QuarantineProtocolManager::new(fleet, test_security_epoch(), Duration::from_secs(30));

        assert_eq!(manager.instance_states.len(), 5);
        assert_eq!(manager.lamport_clock, 0);
        assert_eq!(manager.stats.decisions_issued, 0);
    }

    #[test]
    fn test_issue_quarantine_decision() {
        let fleet = FleetSimulator::new(3, test_thresholds()).unwrap();
        let mut manager =
            QuarantineProtocolManager::new(fleet, test_security_epoch(), Duration::from_secs(30));

        let instance_ids = manager.fleet_simulator.instance_ids();
        let originator = &instance_ids[0];

        let evidence_hash = manager
            .issue_quarantine_decision(
                originator,
                "suspicious-extension".to_string(),
                "Malware detected".to_string(),
            )
            .unwrap();

        assert_eq!(manager.stats.decisions_issued, 1);
        assert_eq!(manager.stats.messages_sent, 1);

        // Check that originator has the decision
        let originator_state = &manager.instance_states[originator];
        assert!(originator_state.is_quarantined("suspicious-extension"));
        assert!(originator_state.seen_decisions.contains(&evidence_hash));
    }

    #[test]
    fn test_process_quarantine_decision() {
        let fleet = FleetSimulator::new(2, test_thresholds()).unwrap();
        let mut manager =
            QuarantineProtocolManager::new(fleet, test_security_epoch(), Duration::from_secs(30));

        let instance_ids = manager.fleet_simulator.instance_ids();
        let target = &instance_ids[0];

        let decision = QuarantineDecision::new(
            "test-extension".to_string(),
            "Test reason".to_string(),
            NodeId("other-instance".to_string()),
            1,
            test_security_epoch(),
        );

        let is_new = manager
            .process_quarantine_decision(target, decision)
            .unwrap();
        assert!(is_new);
        assert_eq!(manager.stats.messages_sent, 1); // Acknowledgment sent

        // Process same decision again (duplicate)
        let duplicate = QuarantineDecision::new(
            "test-extension".to_string(),
            "Test reason".to_string(),
            NodeId("other-instance".to_string()),
            1,
            test_security_epoch(),
        );

        let is_new_duplicate = manager
            .process_quarantine_decision(target, duplicate)
            .unwrap();
        assert!(!is_new_duplicate);
        assert_eq!(manager.stats.duplicates_ignored, 1);
    }

    #[test]
    fn test_get_quarantined_extensions() {
        let fleet = FleetSimulator::new(2, test_thresholds()).unwrap();
        let mut manager =
            QuarantineProtocolManager::new(fleet, test_security_epoch(), Duration::from_secs(30));

        let instance_ids = manager.fleet_simulator.instance_ids();

        // Add quarantine to first instance
        let decision1 = QuarantineDecision::new(
            "extension-1".to_string(),
            "Reason 1".to_string(),
            NodeId("originator".to_string()),
            1,
            test_security_epoch(),
        );
        manager
            .process_quarantine_decision(&instance_ids[0], decision1)
            .unwrap();

        // Add quarantine to second instance
        let decision2 = QuarantineDecision::new(
            "extension-2".to_string(),
            "Reason 2".to_string(),
            NodeId("originator".to_string()),
            2,
            test_security_epoch(),
        );
        manager
            .process_quarantine_decision(&instance_ids[1], decision2)
            .unwrap();

        let quarantined = manager.get_quarantined_extensions();
        assert_eq!(quarantined.len(), 2);
        assert!(quarantined.contains("extension-1"));
        assert!(quarantined.contains("extension-2"));
    }

    #[test]
    fn test_convergence_detection() {
        let fleet = FleetSimulator::new(3, test_thresholds()).unwrap();
        let mut manager =
            QuarantineProtocolManager::new(fleet, test_security_epoch(), Duration::from_secs(30));

        let decision = QuarantineDecision::new(
            "test-extension".to_string(),
            "Test reason".to_string(),
            NodeId("originator".to_string()),
            1,
            test_security_epoch(),
        );

        let evidence_hash = decision.evidence_hash;

        // Add decision to originator state manually for testing
        manager
            .instance_states
            .get_mut(&NodeId("originator".to_string()))
            .unwrap()
            .add_decision(decision);

        // Should not be converged initially
        assert!(!manager.is_decision_converged(&evidence_hash));

        // Add acknowledgments
        let ack1 = QuarantineAck::new(
            evidence_hash,
            NodeId("instance-1".to_string()),
            2,
            true,
            None,
        );
        let ack2 = QuarantineAck::new(
            evidence_hash,
            NodeId("instance-2".to_string()),
            3,
            true,
            None,
        );

        manager.process_acknowledgment(ack1).unwrap();
        assert!(!manager.is_decision_converged(&evidence_hash)); // Not yet converged

        let converged = manager.process_acknowledgment(ack2).unwrap();
        assert!(converged); // Should be converged now
        assert!(manager.is_decision_converged(&evidence_hash));
    }
}
