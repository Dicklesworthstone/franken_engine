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

use crate::fleet_immune_protocol::NodeId;
use crate::fleet_simulator::{FleetSimulator, MessagePayload};
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
        self.acknowledgments.insert(evidence_hash, BTreeSet::new());
        true
    }

    /// Record an acknowledgment for a decision.
    pub fn add_acknowledgment(&mut self, ack: QuarantineAck) -> bool {
        if !ack.enforcement_successful {
            return false;
        }

        if let Some(ack_set) = self.acknowledgments.get_mut(&ack.decision_evidence_hash) {
            ack_set.insert(ack.acknowledging_instance)
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
        if !self.instance_states.contains_key(originator) {
            return Err(QuarantineProtocolError::InstanceNotFound {
                instance_id: originator.clone(),
            });
        }

        self.lamport_clock = self.lamport_clock.saturating_add(1);

        let decision = QuarantineDecision::new(
            extension_id.clone(),
            reason,
            originator.clone(),
            self.lamport_clock,
            self.security_epoch,
        );

        let evidence_hash = decision.evidence_hash;

        // Record decision in originator's state
        let originator_state = self
            .instance_states
            .get_mut(originator)
            .expect("originator existence checked before issuing quarantine decision");
        originator_state.add_decision(decision.clone());

        // Broadcast decision to all other instances
        self.broadcast_quarantine_decision(originator, decision)?;

        self.stats.decisions_issued = self.stats.decisions_issued.saturating_add(1);
        Ok(evidence_hash)
    }

    /// Broadcast a quarantine decision to all fleet instances.
    fn broadcast_quarantine_decision(
        &mut self,
        originator: &NodeId,
        decision: QuarantineDecision,
    ) -> Result<(), QuarantineProtocolError> {
        let payload = MessagePayload::QuarantineDecision {
            extension_id: decision.extension_id.clone(),
            reason: decision.reason.clone(),
            evidence_hash: decision.evidence_hash.to_hex(),
            originator_instance: originator.clone(),
            lamport_timestamp: decision.lamport_timestamp,
        };

        self.fleet_simulator
            .send_message(originator, None, payload) // None = broadcast
            .map_err(|e| QuarantineProtocolError::FleetSimulationError {
                error: format!("{}", e),
            })?;

        self.stats.messages_sent = self.stats.messages_sent.saturating_add(1);
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
            self.stats.duplicates_ignored = self.stats.duplicates_ignored.saturating_add(1);
        }

        Ok(is_new)
    }

    /// Send acknowledgment for a quarantine decision.
    ///
    /// Emits a `MessagePayload::QuarantineAck` back to the decision originator so
    /// `process_acknowledgment` on the originator side records convergence.
    /// Previously this site constructed a `QuarantineAck`, dropped it, and sent a
    /// `StateChange` instead — the ack was silently lost.
    fn send_acknowledgment(
        &mut self,
        acknowledging_instance: &NodeId,
        decision: &QuarantineDecision,
    ) -> Result<(), QuarantineProtocolError> {
        self.lamport_clock = self.lamport_clock.saturating_add(1);

        let payload = MessagePayload::QuarantineAck {
            extension_id: decision.extension_id.clone(),
            evidence_hash: decision.evidence_hash.to_hex(),
            acknowledging_instance: acknowledging_instance.clone(),
            originator_instance: decision.originator_instance.clone(),
            lamport_timestamp: self.lamport_clock,
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

        self.stats.messages_sent = self.stats.messages_sent.saturating_add(1);
        Ok(())
    }

    /// Process incoming acknowledgment.
    pub fn process_acknowledgment(
        &mut self,
        ack: QuarantineAck,
    ) -> Result<bool, QuarantineProtocolError> {
        let total_instances = self.instance_states.len();
        if !self
            .instance_states
            .contains_key(&ack.acknowledging_instance)
        {
            return Ok(false);
        }

        let originator_instance = self.instance_states.iter().find_map(|(node_id, state)| {
            state
                .pending_decisions
                .get(&ack.decision_evidence_hash)
                .filter(|decision| &decision.originator_instance == node_id)
                .map(|_| node_id.clone())
        });

        if let Some(originator_instance) = originator_instance {
            if ack.acknowledging_instance == originator_instance {
                return Ok(false);
            }

            let originator_state = self
                .instance_states
                .get_mut(&originator_instance)
                .expect("originator was selected from instance_states");
            let recorded = originator_state.add_acknowledgment(ack.clone());

            if recorded {
                self.stats.acknowledgments_received =
                    self.stats.acknowledgments_received.saturating_add(1);

                // Check if decision has converged
                if originator_state.is_converged(&ack.decision_evidence_hash, total_instances) {
                    self.stats.decisions_converged =
                        self.stats.decisions_converged.saturating_add(1);
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
        let duplicate_ack = QuarantineAck::new(
            evidence_hash,
            NodeId("instance-1".to_string()),
            4,
            true,
            None,
        );
        assert!(!state.add_acknowledgment(duplicate_ack));
        assert!(!state.is_converged(&evidence_hash, 3)); // Need 2 acks for 3 instances

        assert!(state.add_acknowledgment(ack2));
        assert!(state.is_converged(&evidence_hash, 3)); // Now converged

        let failed_ack = QuarantineAck::new(
            evidence_hash,
            NodeId("instance-3".to_string()),
            5,
            false,
            Some("local enforcement failed".to_string()),
        );
        assert!(!state.add_acknowledgment(failed_ack));
    }

    #[test]
    fn test_protocol_manager_initialization() {
        // SAFETY: FleetSimulator::new with valid count and test thresholds should succeed
        let fleet = FleetSimulator::new(5, test_thresholds()).expect("serde deserialization should succeed");
        let manager =
            QuarantineProtocolManager::new(fleet, test_security_epoch(), Duration::from_secs(30));

        assert_eq!(manager.instance_states.len(), 5);
        assert_eq!(manager.lamport_clock, 0);
        assert_eq!(manager.stats.decisions_issued, 0);
    }

    #[test]
    fn test_issue_quarantine_decision() {
        // SAFETY: FleetSimulator::new with valid count and test thresholds should succeed
        let fleet = FleetSimulator::new(3, test_thresholds()).expect("serde deserialization should succeed");
        let mut manager =
            QuarantineProtocolManager::new(fleet, test_security_epoch(), Duration::from_secs(30));

        let instance_ids = manager.fleet_simulator.instance_ids();
        let originator = &instance_ids[0];

        // SAFETY: issue_quarantine_decision with valid originator and reason should succeed
        let evidence_hash = manager
            .issue_quarantine_decision(
                originator,
                "suspicious-extension".to_string(),
                "Malware detected".to_string(),
            )
            .expect("serde deserialization should succeed");

        assert_eq!(manager.stats.decisions_issued, 1);
        assert_eq!(manager.stats.messages_sent, 1);

        // Check that originator has the decision
        let originator_state = &manager.instance_states[originator];
        assert!(originator_state.is_quarantined("suspicious-extension"));
        assert!(originator_state.seen_decisions.contains(&evidence_hash));
    }

    #[test]
    fn test_issued_quarantine_broadcast_runs_through_fleet_simulator() {
        let fleet = FleetSimulator::new(3, test_thresholds()).expect("serde deserialization should succeed");
        let mut manager =
            QuarantineProtocolManager::new(fleet, test_security_epoch(), Duration::from_secs(30));

        let instance_ids = manager.fleet_simulator.instance_ids();
        let originator = instance_ids[0].clone();
        manager
            .issue_quarantine_decision(
                &originator,
                "simulated-extension".to_string(),
                "Simulation propagation".to_string(),
            )
            .expect("serde deserialization should succeed");

        manager
            .run_protocol_steps(1)
            .expect("quarantine decision payload should be supported by the fleet simulator");
    }

    #[test]
    fn test_process_quarantine_decision() {
        let fleet = FleetSimulator::new(2, test_thresholds()).expect("serde deserialization should succeed");
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
            .expect("serde deserialization should succeed");
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
            .expect("serde deserialization should succeed");
        assert!(!is_new_duplicate);
        assert_eq!(manager.stats.duplicates_ignored, 1);
    }

    #[test]
    fn test_get_quarantined_extensions() {
        let fleet = FleetSimulator::new(2, test_thresholds()).expect("serde deserialization should succeed");
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
            .expect("serde deserialization should succeed");

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
            .expect("serde deserialization should succeed");

        let quarantined = manager.get_quarantined_extensions();
        assert_eq!(quarantined.len(), 2);
        assert!(quarantined.contains("extension-1"));
        assert!(quarantined.contains("extension-2"));
    }

    #[test]
    fn test_convergence_detection() {
        let fleet = FleetSimulator::new(3, test_thresholds()).expect("serde deserialization should succeed");
        let mut manager =
            QuarantineProtocolManager::new(fleet, test_security_epoch(), Duration::from_secs(30));
        let instance_ids = manager.fleet_simulator.instance_ids();
        let originator = instance_ids[0].clone();
        let acking_one = instance_ids[1].clone();
        let acking_two = instance_ids[2].clone();

        let decision = QuarantineDecision::new(
            "test-extension".to_string(),
            "Test reason".to_string(),
            originator.clone(),
            1,
            test_security_epoch(),
        );

        let evidence_hash = decision.evidence_hash;

        // Add decision to originator state manually for testing
        manager
            .instance_states
            .get_mut(&originator)
            .expect("serde deserialization should succeed")
            .add_decision(decision);

        // Should not be converged initially
        assert!(!manager.is_decision_converged(&evidence_hash));

        // Add acknowledgments
        let ack1 = QuarantineAck::new(evidence_hash, acking_one.clone(), 2, true, None);
        let ack2 = QuarantineAck::new(evidence_hash, acking_two, 3, true, None);

        manager.process_acknowledgment(ack1).expect("serde deserialization should succeed");
        assert!(!manager.is_decision_converged(&evidence_hash)); // Not yet converged
        assert!(
            manager.instance_states[&originator].acknowledgments[&evidence_hash]
                .contains(&acking_one)
        );
        let duplicate_ack = QuarantineAck::new(evidence_hash, acking_one.clone(), 4, true, None);
        assert!(!manager.process_acknowledgment(duplicate_ack).expect("serde deserialization should succeed"));
        let originator_ack = QuarantineAck::new(evidence_hash, originator.clone(), 5, true, None);
        assert!(!manager.process_acknowledgment(originator_ack).expect("serde deserialization should succeed"));
        assert_eq!(
            manager.instance_states[&originator].acknowledgments[&evidence_hash].len(),
            1
        );

        let converged = manager.process_acknowledgment(ack2).expect("serde deserialization should succeed");
        assert!(converged); // Should be converged now
        assert!(manager.is_decision_converged(&evidence_hash));
    }
}
