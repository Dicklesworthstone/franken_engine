//! Fleet simulator — N in-process engine instances with deterministic message bus.
//!
//! Builds on existing fleet convergence infrastructure to simulate multi-instance
//! behavior for quarantine propagation, SLO measurement, and TEE substrate testing.
//!
//! Key design decisions:
//! - Reuses existing fleet_convergence.rs, fleet_immune_protocol.rs infrastructure
//! - Deterministic message ordering via Lamport timestamps
//! - Structured JSONL logging of all state transitions
//! - In-process simulation for deterministic testing
//!
//! Plan reference: bd-6a61n.5.1

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::fleet_convergence::{
    ConvergenceEngine, ConvergenceEvent, ContainmentThresholds, PartitionInfo, PartitionMode,
};
use crate::fleet_immune_protocol::{
    ContainmentAction, FleetProtocolState, NodeId, ProtocolMessage, QuorumCheckpoint,
};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// A single engine instance within the fleet simulation.
#[derive(Debug, Clone)]
pub struct EngineInstance {
    /// Unique node identifier.
    pub node_id: NodeId,
    /// Convergence engine for this instance.
    pub convergence_engine: ConvergenceEngine,
    /// Current partition info for this instance.
    pub partition_info: PartitionInfo,
    /// Fleet protocol state.
    pub protocol_state: FleetProtocolState,
    /// Instance creation timestamp for deterministic ordering.
    pub created_at: u64, // Lamport timestamp
    /// Current instance state.
    pub state: InstanceState,
}

/// Instance lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceState {
    /// Instance is healthy and processing normally.
    Healthy,
    /// Instance is sandboxed with restricted capabilities.
    Sandboxed,
    /// Instance is suspended pending review.
    Suspended,
    /// Instance is terminated.
    Terminated,
    /// Instance is quarantined.
    Quarantined,
}

impl From<ContainmentAction> for InstanceState {
    fn from(action: ContainmentAction) -> Self {
        match action {
            ContainmentAction::Allow => InstanceState::Healthy,
            ContainmentAction::Sandbox => InstanceState::Sandboxed,
            ContainmentAction::Suspend => InstanceState::Suspended,
            ContainmentAction::Terminate => InstanceState::Terminated,
            ContainmentAction::Quarantine => InstanceState::Quarantined,
        }
    }
}

/// Deterministic message for fleet communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetMessage {
    /// Lamport timestamp for deterministic ordering.
    pub timestamp: u64,
    /// Source node ID.
    pub from: NodeId,
    /// Target node ID (None for broadcast).
    pub to: Option<NodeId>,
    /// Message payload.
    pub payload: MessagePayload,
    /// Message ID for deduplication.
    pub message_id: ContentHash,
}

/// Fleet message payload types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    /// Protocol message from fleet immune protocol.
    Protocol(ProtocolMessage),
    /// Convergence event for state synchronization.
    ConvergenceEvent(ConvergenceEvent),
    /// Quorum checkpoint.
    QuorumCheckpoint(QuorumCheckpoint),
    /// Instance state change notification.
    StateChange {
        old_state: InstanceState,
        new_state: InstanceState,
        reason: String,
    },
}

/// Deterministic message bus for fleet communication.
#[derive(Debug)]
pub struct MessageBus {
    /// Message queue ordered by Lamport timestamp.
    message_queue: VecDeque<FleetMessage>,
    /// Current Lamport timestamp.
    current_timestamp: u64,
    /// Partition mode affecting message delivery.
    partition_mode: PartitionMode,
    /// Message delivery success rate (0-100) in degraded mode.
    delivery_success_rate: u8,
    /// Messages delivered count for statistics.
    messages_delivered: u64,
    /// Messages dropped count for statistics.
    messages_dropped: u64,
}

impl MessageBus {
    /// Create a new message bus.
    pub fn new() -> Self {
        Self {
            message_queue: VecDeque::new(),
            current_timestamp: 0,
            partition_mode: PartitionMode::Normal,
            delivery_success_rate: 100,
            messages_delivered: 0,
            messages_dropped: 0,
        }
    }

    /// Set partition mode for network simulation.
    pub fn set_partition_mode(&mut self, mode: PartitionMode, success_rate: u8) {
        self.partition_mode = mode;
        self.delivery_success_rate = success_rate;
    }

    /// Send a message (adds to queue with timestamp).
    pub fn send_message(&mut self, mut message: FleetMessage) -> Result<(), FleetSimulatorError> {
        self.current_timestamp += 1;
        message.timestamp = self.current_timestamp;

        // Simulate message drops in degraded partition mode
        match self.partition_mode {
            PartitionMode::Normal => {
                self.message_queue.push_back(message);
                self.messages_delivered += 1;
            }
            PartitionMode::Degraded => {
                // Simple deterministic "random" based on message hash
                let hash_bytes = message.message_id.as_bytes();
                let pseudo_random = hash_bytes[0] % 100;
                if pseudo_random < self.delivery_success_rate {
                    self.message_queue.push_back(message);
                    self.messages_delivered += 1;
                } else {
                    self.messages_dropped += 1;
                }
            }
            PartitionMode::Healing => {
                // Healing mode has better delivery than degraded
                let hash_bytes = message.message_id.as_bytes();
                let pseudo_random = hash_bytes[0] % 100;
                let healing_rate = (self.delivery_success_rate + 100) / 2; // Better than degraded
                if pseudo_random < healing_rate {
                    self.message_queue.push_back(message);
                    self.messages_delivered += 1;
                } else {
                    self.messages_dropped += 1;
                }
            }
        }

        Ok(())
    }

    /// Receive next message (removes from queue).
    pub fn receive_message(&mut self) -> Option<FleetMessage> {
        self.message_queue.pop_front()
    }

    /// Peek at next message without removing.
    pub fn peek_message(&self) -> Option<&FleetMessage> {
        self.message_queue.front()
    }

    /// Get current queue length.
    pub fn queue_length(&self) -> usize {
        self.message_queue.len()
    }

    /// Get delivery statistics.
    pub fn delivery_stats(&self) -> (u64, u64) {
        (self.messages_delivered, self.messages_dropped)
    }
}

/// Fleet simulator managing N engine instances.
#[derive(Debug)]
pub struct FleetSimulator {
    /// All engine instances indexed by node ID.
    instances: BTreeMap<NodeId, EngineInstance>,
    /// Centralized message bus.
    message_bus: MessageBus,
    /// Containment thresholds for all instances.
    containment_thresholds: ContainmentThresholds,
    /// Simulation start time for relative timestamps.
    start_time: Instant,
    /// Total simulation steps executed.
    simulation_steps: u64,
    /// Event log for structured JSONL output.
    event_log: Vec<SimulationEvent>,
}

/// Simulation event for logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationEvent {
    /// Event timestamp (relative to simulation start).
    pub timestamp_ms: u64,
    /// Node that generated the event.
    pub node_id: NodeId,
    /// Event type.
    pub event_type: SimulationEventType,
    /// Human-readable description.
    pub description: String,
}

/// Types of simulation events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SimulationEventType {
    /// Instance created.
    InstanceCreated,
    /// Instance state changed.
    StateTransition { from: InstanceState, to: InstanceState },
    /// Message sent between instances.
    MessageSent { from: NodeId, to: Option<NodeId> },
    /// Message received by instance.
    MessageReceived { from: NodeId },
    /// Partition mode changed.
    PartitionModeChanged { mode: PartitionMode },
    /// Quorum checkpoint reached.
    QuorumCheckpoint,
    /// Error occurred.
    Error { error: String },
}

/// Fleet simulator errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FleetSimulatorError {
    #[error("Instance not found: {node_id}")]
    InstanceNotFound { node_id: NodeId },
    #[error("Invalid instance count: {count} (must be > 0)")]
    InvalidInstanceCount { count: usize },
    #[error("Message bus error: {message}")]
    MessageBusError { message: String },
    #[error("Convergence error: {error}")]
    ConvergenceError { error: String },
}

impl FleetSimulator {
    /// Create a new fleet simulator with N instances.
    pub fn new(
        instance_count: usize,
        containment_thresholds: ContainmentThresholds,
    ) -> Result<Self, FleetSimulatorError> {
        if instance_count == 0 {
            return Err(FleetSimulatorError::InvalidInstanceCount {
                count: instance_count,
            });
        }

        let mut instances = BTreeMap::new();
        let message_bus = MessageBus::new();
        let start_time = Instant::now();
        let mut event_log = Vec::new();

        // Create N instances
        for i in 0..instance_count {
            let node_id = NodeId(format!("instance-{:03}", i));
            let partition_info = PartitionInfo {
                mode: PartitionMode::Normal,
                total_nodes: instance_count as u32,
                reachable_nodes: instance_count as u32,
                quorum_threshold: (instance_count / 2 + 1) as u32,
                healing_info: None,
            };

            let convergence_engine = ConvergenceEngine::new(
                containment_thresholds.clone(),
                node_id.clone(),
                partition_info.clone(),
            );

            let protocol_state = FleetProtocolState::new(node_id.clone());

            let instance = EngineInstance {
                node_id: node_id.clone(),
                convergence_engine,
                partition_info,
                protocol_state,
                created_at: i as u64, // Deterministic creation timestamp
                state: InstanceState::Healthy,
            };

            // Log instance creation
            event_log.push(SimulationEvent {
                timestamp_ms: 0,
                node_id: node_id.clone(),
                event_type: SimulationEventType::InstanceCreated,
                description: format!("Created instance {} in fleet of {}", i, instance_count),
            });

            instances.insert(node_id, instance);
        }

        Ok(Self {
            instances,
            message_bus,
            containment_thresholds,
            start_time,
            simulation_steps: 0,
            event_log,
        })
    }

    /// Get instance by node ID.
    pub fn get_instance(&self, node_id: &NodeId) -> Option<&EngineInstance> {
        self.instances.get(node_id)
    }

    /// Get mutable instance by node ID.
    pub fn get_instance_mut(&mut self, node_id: &NodeId) -> Option<&mut EngineInstance> {
        self.instances.get_mut(node_id)
    }

    /// Get all instance node IDs.
    pub fn instance_ids(&self) -> Vec<NodeId> {
        self.instances.keys().cloned().collect()
    }

    /// Send message from one instance to another.
    pub fn send_message(
        &mut self,
        from: &NodeId,
        to: Option<&NodeId>,
        payload: MessagePayload,
    ) -> Result<(), FleetSimulatorError> {
        let from_clone = from.clone();
        let to_clone = to.cloned();

        // Generate deterministic message ID
        let message_content = format!("{:?}{:?}{:?}", from, to, payload);
        let message_id = ContentHash::compute(message_content.as_bytes());

        let message = FleetMessage {
            timestamp: 0, // Will be set by message bus
            from: from_clone.clone(),
            to: to_clone.clone(),
            payload: payload.clone(),
            message_id,
        };

        self.message_bus.send_message(message)?;

        // Log message sent
        let timestamp_ms = self.start_time.elapsed().as_millis() as u64;
        self.event_log.push(SimulationEvent {
            timestamp_ms,
            node_id: from_clone,
            event_type: SimulationEventType::MessageSent {
                from: from.clone(),
                to: to_clone,
            },
            description: match to {
                Some(target) => format!("Sent message to {}", target),
                None => "Broadcast message to all instances".to_string(),
            },
        });

        Ok(())
    }

    /// Process next message in the queue.
    pub fn process_next_message(&mut self) -> Result<bool, FleetSimulatorError> {
        if let Some(message) = self.message_bus.receive_message() {
            // Determine target instances
            let targets: Vec<NodeId> = match &message.to {
                Some(target) => vec![target.clone()],
                None => self.instances.keys().cloned().collect(), // Broadcast
            };

            // Deliver message to target instances
            for target_id in targets {
                if target_id == message.from {
                    continue; // Skip self-messages
                }

                if let Some(instance) = self.instances.get_mut(&target_id) {
                    self.handle_message_for_instance(instance, &message)?;

                    // Log message received
                    let timestamp_ms = self.start_time.elapsed().as_millis() as u64;
                    self.event_log.push(SimulationEvent {
                        timestamp_ms,
                        node_id: target_id.clone(),
                        event_type: SimulationEventType::MessageReceived {
                            from: message.from.clone(),
                        },
                        description: format!("Received message from {}", message.from),
                    });
                }
            }

            self.simulation_steps += 1;
            Ok(true)
        } else {
            Ok(false) // No messages to process
        }
    }

    /// Handle a message for a specific instance.
    fn handle_message_for_instance(
        &mut self,
        instance: &mut EngineInstance,
        message: &FleetMessage,
    ) -> Result<(), FleetSimulatorError> {
        match &message.payload {
            MessagePayload::StateChange {
                old_state,
                new_state,
                reason,
            } => {
                self.transition_instance_state(
                    &instance.node_id.clone(),
                    *new_state,
                    reason.clone(),
                )?;
            }
            MessagePayload::Protocol(_protocol_message) => {
                // Handle protocol message (placeholder for now)
            }
            MessagePayload::ConvergenceEvent(_event) => {
                // Handle convergence event (placeholder for now)
            }
            MessagePayload::QuorumCheckpoint(_checkpoint) => {
                // Handle quorum checkpoint (placeholder for now)
            }
        }

        Ok(())
    }

    /// Transition an instance to a new state.
    pub fn transition_instance_state(
        &mut self,
        node_id: &NodeId,
        new_state: InstanceState,
        reason: String,
    ) -> Result<(), FleetSimulatorError> {
        let instance = self
            .instances
            .get_mut(node_id)
            .ok_or_else(|| FleetSimulatorError::InstanceNotFound {
                node_id: node_id.clone(),
            })?;

        let old_state = instance.state;
        instance.state = new_state;

        // Log state transition
        let timestamp_ms = self.start_time.elapsed().as_millis() as u64;
        self.event_log.push(SimulationEvent {
            timestamp_ms,
            node_id: node_id.clone(),
            event_type: SimulationEventType::StateTransition {
                from: old_state,
                to: new_state,
            },
            description: format!(
                "State transition: {:?} → {:?} ({})",
                old_state, new_state, reason
            ),
        });

        Ok(())
    }

    /// Set partition mode for network simulation.
    pub fn set_partition_mode(&mut self, mode: PartitionMode, success_rate: u8) {
        self.message_bus.set_partition_mode(mode, success_rate);

        // Update partition info for all instances
        let total_nodes = self.instances.len() as u32;
        let reachable_nodes = match mode {
            PartitionMode::Normal => total_nodes,
            PartitionMode::Degraded => (total_nodes * success_rate as u32) / 100,
            PartitionMode::Healing => (total_nodes * (success_rate + 100) as u32) / 200,
        };

        for instance in self.instances.values_mut() {
            instance.partition_info.mode = mode;
            instance.partition_info.reachable_nodes = reachable_nodes;
        }

        // Log partition mode change
        let timestamp_ms = self.start_time.elapsed().as_millis() as u64;
        self.event_log.push(SimulationEvent {
            timestamp_ms,
            node_id: NodeId("simulator".to_string()),
            event_type: SimulationEventType::PartitionModeChanged { mode },
            description: format!(
                "Partition mode changed to {:?} with {}% success rate",
                mode, success_rate
            ),
        });
    }

    /// Get simulation statistics.
    pub fn simulation_stats(&self) -> SimulationStats {
        let instance_states: BTreeMap<InstanceState, u32> = self
            .instances
            .values()
            .fold(BTreeMap::new(), |mut acc, instance| {
                *acc.entry(instance.state).or_insert(0) += 1;
                acc
            });

        let (messages_delivered, messages_dropped) = self.message_bus.delivery_stats();

        SimulationStats {
            total_instances: self.instances.len() as u32,
            instance_states,
            simulation_steps: self.simulation_steps,
            messages_delivered,
            messages_dropped,
            events_logged: self.event_log.len() as u32,
            queue_length: self.message_bus.queue_length() as u32,
        }
    }

    /// Export event log as JSON for analysis.
    pub fn export_event_log(&self) -> String {
        self.event_log
            .iter()
            .map(|event| serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string()))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Run simulation for a number of steps.
    pub fn run_simulation_steps(&mut self, steps: u64) -> Result<(), FleetSimulatorError> {
        for _ in 0..steps {
            if !self.process_next_message()? {
                break; // No more messages
            }
        }
        Ok(())
    }
}

/// Simulation statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationStats {
    pub total_instances: u32,
    pub instance_states: BTreeMap<InstanceState, u32>,
    pub simulation_steps: u64,
    pub messages_delivered: u64,
    pub messages_dropped: u64,
    pub events_logged: u32,
    pub queue_length: u32,
}

impl Default for MessageBus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_thresholds() -> ContainmentThresholds {
        ContainmentThresholds {
            sandbox_threshold: 1_000_000,   // 1.0
            suspend_threshold: 5_000_000,   // 5.0
            terminate_threshold: 10_000_000, // 10.0
            quarantine_threshold: 20_000_000, // 20.0
        }
    }

    #[test]
    fn test_create_fleet() {
        let fleet = FleetSimulator::new(10, test_thresholds()).unwrap();
        assert_eq!(fleet.instances.len(), 10);

        // Check all instances start healthy
        for (i, instance) in fleet.instances.values().enumerate() {
            assert_eq!(instance.state, InstanceState::Healthy);
            assert_eq!(instance.node_id.0, format!("instance-{:03}", i));
        }
    }

    #[test]
    fn test_message_delivery() {
        let mut fleet = FleetSimulator::new(5, test_thresholds()).unwrap();
        let instance_ids = fleet.instance_ids();

        // Send message from instance 0 to instance 1
        fleet
            .send_message(
                &instance_ids[0],
                Some(&instance_ids[1]),
                MessagePayload::StateChange {
                    old_state: InstanceState::Healthy,
                    new_state: InstanceState::Sandboxed,
                    reason: "Test state change".to_string(),
                },
            )
            .unwrap();

        // Process the message
        let processed = fleet.process_next_message().unwrap();
        assert!(processed);

        // Check that instance 1 state changed
        let instance = fleet.get_instance(&instance_ids[1]).unwrap();
        assert_eq!(instance.state, InstanceState::Sandboxed);
    }

    #[test]
    fn test_broadcast_message() {
        let mut fleet = FleetSimulator::new(5, test_thresholds()).unwrap();
        let instance_ids = fleet.instance_ids();

        // Broadcast message from instance 0
        fleet
            .send_message(
                &instance_ids[0],
                None, // Broadcast
                MessagePayload::StateChange {
                    old_state: InstanceState::Healthy,
                    new_state: InstanceState::Suspended,
                    reason: "Broadcast state change".to_string(),
                },
            )
            .unwrap();

        // Process all messages (should be 4 messages, excluding sender)
        let mut processed_count = 0;
        while fleet.process_next_message().unwrap() {
            processed_count += 1;
        }
        assert_eq!(processed_count, 1); // One broadcast creates multiple deliveries internally

        // Check that all instances except sender changed state
        for (i, instance_id) in instance_ids.iter().enumerate() {
            let instance = fleet.get_instance(instance_id).unwrap();
            if i == 0 {
                // Sender remains unchanged
                assert_eq!(instance.state, InstanceState::Healthy);
            } else {
                // Recipients changed state
                assert_eq!(instance.state, InstanceState::Suspended);
            }
        }
    }

    #[test]
    fn test_partition_mode_affects_delivery() {
        let mut fleet = FleetSimulator::new(3, test_thresholds()).unwrap();
        let instance_ids = fleet.instance_ids();

        // Set degraded partition mode with 50% success rate
        fleet.set_partition_mode(PartitionMode::Degraded, 50);

        // Send several messages and count successes
        for i in 0..10 {
            fleet
                .send_message(
                    &instance_ids[0],
                    Some(&instance_ids[1]),
                    MessagePayload::StateChange {
                        old_state: InstanceState::Healthy,
                        new_state: InstanceState::Sandboxed,
                        reason: format!("Test message {}", i),
                    },
                )
                .unwrap();
        }

        let stats = fleet.simulation_stats();
        let (delivered, dropped) = fleet.message_bus.delivery_stats();

        // In degraded mode, some messages should be dropped
        // (exact count depends on deterministic "random" based on hash)
        assert!(delivered + dropped == 10);
        assert!(dropped > 0); // At 50% rate, some should be dropped
    }

    #[test]
    fn test_instance_state_transitions() {
        let mut fleet = FleetSimulator::new(2, test_thresholds()).unwrap();
        let instance_ids = fleet.instance_ids();

        let node_id = &instance_ids[0];
        assert_eq!(
            fleet.get_instance(node_id).unwrap().state,
            InstanceState::Healthy
        );

        // Transition through states
        fleet
            .transition_instance_state(
                node_id,
                InstanceState::Sandboxed,
                "Security concern".to_string(),
            )
            .unwrap();
        assert_eq!(
            fleet.get_instance(node_id).unwrap().state,
            InstanceState::Sandboxed
        );

        fleet
            .transition_instance_state(
                node_id,
                InstanceState::Terminated,
                "Critical violation".to_string(),
            )
            .unwrap();
        assert_eq!(
            fleet.get_instance(node_id).unwrap().state,
            InstanceState::Terminated
        );
    }

    #[test]
    fn test_simulation_stats() {
        let mut fleet = FleetSimulator::new(5, test_thresholds()).unwrap();
        let instance_ids = fleet.instance_ids();

        // Change some instance states
        fleet
            .transition_instance_state(
                &instance_ids[0],
                InstanceState::Sandboxed,
                "Test".to_string(),
            )
            .unwrap();
        fleet
            .transition_instance_state(
                &instance_ids[1],
                InstanceState::Terminated,
                "Test".to_string(),
            )
            .unwrap();

        let stats = fleet.simulation_stats();
        assert_eq!(stats.total_instances, 5);
        assert_eq!(stats.instance_states[&InstanceState::Healthy], 3);
        assert_eq!(stats.instance_states[&InstanceState::Sandboxed], 1);
        assert_eq!(stats.instance_states[&InstanceState::Terminated], 1);
    }

    #[test]
    fn test_event_logging() {
        let fleet = FleetSimulator::new(2, test_thresholds()).unwrap();

        // Should have creation events for both instances
        assert_eq!(fleet.event_log.len(), 2);
        assert!(fleet.event_log.iter().all(|e| matches!(
            e.event_type,
            SimulationEventType::InstanceCreated
        )));

        // Export should produce valid JSONL
        let log_json = fleet.export_event_log();
        assert!(log_json.contains("InstanceCreated"));
    }

    #[test]
    fn test_invalid_instance_count() {
        let result = FleetSimulator::new(0, test_thresholds());
        assert!(matches!(
            result,
            Err(FleetSimulatorError::InvalidInstanceCount { count: 0 })
        ));
    }

    #[test]
    fn test_instance_not_found_error() {
        let mut fleet = FleetSimulator::new(2, test_thresholds()).unwrap();
        let nonexistent_id = NodeId("nonexistent".to_string());

        let result = fleet.transition_instance_state(
            &nonexistent_id,
            InstanceState::Terminated,
            "Test".to_string(),
        );

        assert!(matches!(
            result,
            Err(FleetSimulatorError::InstanceNotFound { .. })
        ));
    }
}