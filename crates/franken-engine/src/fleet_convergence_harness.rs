//! Fleet convergence harness for N-node testing.
//!
//! Provides a high-level testing harness that wires together `fleet_simulator.rs`
//! and `fleet_immune_protocol.rs` to enable deterministic testing of fleet-wide
//! convergence behavior under various partition scenarios.
//!
//! Key capabilities:
//! - N in-process nodes with deterministic message ordering
//! - Controllable network partitions with delay/drop simulation
//! - Convergence verification with quorum thresholds
//! - **NEGATIVE test**: REFUSES convergence under permanent partition
//! - Compatible with criterion-style benchmarking
//!
//! Plan reference: bd-cixqu.2.1

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::fleet_checkpoint_v2::{FleetCheckpointQuorumV2, FleetCheckpointV2Error};
use crate::fleet_convergence::{ContainmentThresholds, PartitionMode};
use crate::fleet_immune_protocol::{
    AuthenticatedFleetProtocolStateV2, DurableFleetVerificationRegistry, FleetAuthorityId,
    FleetIdentityError, FleetRegistryAnchorAuthority, FleetRegistryPersistenceError,
    FleetRegistrySnapshotAnchorClaim, FleetSigner, FleetVerificationRegistryPersistence,
    GossipConfig, HeartbeatLiveness, MessageSignature, NodeId, ProtocolError, ProtocolVersion,
};
use crate::fleet_simulator::{FleetSimulator, FleetSimulatorError, QuarantineStats};
use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::SigningKey;
use crate::storage_adapter::{EventContext, InMemoryStorageAdapter};

#[derive(Debug)]
struct HarnessAnchorAuthority {
    authority_id: FleetAuthorityId,
    current: Mutex<Option<FleetRegistrySnapshotAnchorClaim>>,
}

impl HarnessAnchorAuthority {
    fn new(authority_id: FleetAuthorityId) -> Self {
        Self {
            authority_id,
            current: Mutex::new(None),
        }
    }
}

impl FleetRegistryAnchorAuthority for HarnessAnchorAuthority {
    fn fleet_authority_id(&self) -> FleetAuthorityId {
        self.authority_id
    }

    fn authenticate_current_registry_anchor(
        &self,
        claim: &FleetRegistrySnapshotAnchorClaim,
    ) -> Result<String, FleetIdentityError> {
        let guard = self.current.lock().expect("harness anchor lock");
        if guard.as_ref() != Some(claim) {
            return Err(FleetIdentityError::UnverifiedRegistryAnchor {
                detail: "harness anchor is no longer current".to_string(),
            });
        }
        Ok(format!("harness-anchor-{}", claim.generation))
    }

    fn prepare_registry_anchor_advance(
        &self,
        expected: Option<&FleetRegistrySnapshotAnchorClaim>,
        next: &FleetRegistrySnapshotAnchorClaim,
    ) -> Result<Vec<u8>, FleetIdentityError> {
        let guard = self.current.lock().expect("harness anchor lock");
        if guard.as_ref() != expected || next.fleet_authority_id != self.authority_id {
            return Err(FleetIdentityError::UnverifiedRegistryAnchor {
                detail: "harness anchor prepare CAS mismatch".to_string(),
            });
        }
        serde_json::to_vec(&(expected.cloned(), next.clone())).map_err(|error| {
            FleetIdentityError::UnverifiedRegistryAnchor {
                detail: error.to_string(),
            }
        })
    }

    fn finalize_registry_anchor_advance(
        &self,
        permit: &[u8],
        next: &FleetRegistrySnapshotAnchorClaim,
    ) -> Result<String, FleetIdentityError> {
        let (expected, authorized): (
            Option<FleetRegistrySnapshotAnchorClaim>,
            FleetRegistrySnapshotAnchorClaim,
        ) = serde_json::from_slice(permit).map_err(|error| {
            FleetIdentityError::UnverifiedRegistryAnchor {
                detail: error.to_string(),
            }
        })?;
        let mut guard = self.current.lock().expect("harness anchor lock");
        if &authorized != next || (*guard != expected && guard.as_ref() != Some(next)) {
            return Err(FleetIdentityError::UnverifiedRegistryAnchor {
                detail: "harness anchor finalize CAS mismatch".to_string(),
            });
        }
        *guard = Some(next.clone());
        Ok(format!("harness-anchor-finalized-{}", next.generation))
    }
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// High-level fleet convergence harness for testing N-node scenarios.
#[derive(Debug)]
pub struct FleetConvergenceHarness {
    /// Underlying fleet simulator managing instances.
    fleet_simulator: FleetSimulator,
    /// Authenticated protocol-V2 states per node.
    peer_states: Vec<AuthenticatedFleetProtocolStateV2>,
    /// Provisioned Ed25519 signing keys per node.
    signers: BTreeMap<NodeId, FleetSigner>,
    /// Durable externally anchored verification registry.
    registry: DurableFleetVerificationRegistry,
    /// Anchor authority backing `registry`.
    anchor: HarnessAnchorAuthority,
    /// Configured protocol-V2 checkpoint electorate and quorum threshold.
    quorum: FleetCheckpointQuorumV2,
    /// Reachable node count under current simulated partition mode (`None` = uninitialized).
    active_partition_reachability: Option<usize>,
    /// Monotonic heartbeat round counter for deterministic liveness updates.
    heartbeat_round: u64,
    /// Configuration for convergence testing.
    config: ConvergenceHarnessConfig,
    /// Simulation start time for measurements.
    start_time: Instant,
    /// Number of convergence attempts.
    convergence_attempts: u64,
    /// History of convergence results for analysis.
    convergence_history: Vec<ConvergenceAttempt>,
}

/// Configuration for the fleet convergence harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceHarnessConfig {
    /// Default number of nodes (configurable, default 7).
    pub default_node_count: usize,
    /// Containment thresholds for instances.
    pub containment_thresholds: ContainmentThresholds,
    /// Gossip configuration for protocol state.
    pub gossip_config: GossipConfig,
    /// Maximum simulation steps before timeout.
    pub max_simulation_steps: u64,
    /// Convergence verification timeout in milliseconds.
    pub convergence_timeout_ms: u64,
}

impl Default for ConvergenceHarnessConfig {
    fn default() -> Self {
        Self {
            default_node_count: 7,
            containment_thresholds: ContainmentThresholds {
                sandbox_threshold: 1_000_000,     // 1.0
                suspend_threshold: 5_000_000,     // 5.0
                terminate_threshold: 10_000_000,  // 10.0
                quarantine_threshold: 20_000_000, // 20.0
            },
            gossip_config: GossipConfig::default(),
            max_simulation_steps: 1000,
            convergence_timeout_ms: 30_000, // 30 seconds
        }
    }
}

/// Result of a convergence verification attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceAttempt {
    /// Attempt sequence number.
    pub attempt_id: u64,
    /// Timestamp when attempt started (relative to harness start).
    pub timestamp_ms: u64,
    /// Result of the convergence check.
    pub result: ConvergenceResult,
    /// Number of healthy nodes at time of attempt.
    pub healthy_node_count: usize,
    /// Total number of known nodes.
    pub total_node_count: usize,
    /// Quarantine statistics at time of attempt.
    pub quarantine_stats: QuarantineStats,
    /// Simulation steps executed.
    pub simulation_steps: u64,
}

/// Convergence verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConvergenceResult {
    /// Convergence achieved - checkpoint created successfully.
    Converged {
        checkpoint_seq: u64,
        participating_nodes: usize,
        decisions_resolved: usize,
    },
    /// Convergence REFUSED due to insufficient quorum (partition).
    QuorumNotReached {
        required_nodes: usize,
        available_nodes: usize,
        partition_detected: bool,
    },
    /// Convergence blocked due to protocol error.
    ProtocolError { error: String },
    /// Timeout before convergence could be determined.
    Timeout { elapsed_ms: u64 },
}

/// Fleet convergence harness errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConvergenceHarnessError {
    #[error("Fleet simulator error: {0}")]
    FleetSimulator(#[from] FleetSimulatorError),
    #[error("Protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("Invalid node count: {count} (must be > 0)")]
    InvalidNodeCount { count: usize },
    #[error("Convergence timeout after {elapsed_ms}ms")]
    ConvergenceTimeout { elapsed_ms: u64 },
    #[error("No nodes available for convergence verification")]
    NoNodesAvailable,
}

impl FleetConvergenceHarness {
    /// Create a new fleet convergence harness with default configuration.
    pub fn new() -> Result<Self, ConvergenceHarnessError> {
        let config = ConvergenceHarnessConfig::default();
        Self::with_config(config)
    }

    /// Create a new fleet convergence harness with N nodes.
    pub fn with_node_count(node_count: usize) -> Result<Self, ConvergenceHarnessError> {
        let config = ConvergenceHarnessConfig {
            default_node_count: node_count,
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Create a new fleet convergence harness with custom configuration.
    pub fn with_config(config: ConvergenceHarnessConfig) -> Result<Self, ConvergenceHarnessError> {
        if config.default_node_count == 0 {
            return Err(ConvergenceHarnessError::InvalidNodeCount {
                count: config.default_node_count,
            });
        }

        let fleet_simulator = FleetSimulator::new(
            config.default_node_count,
            config.containment_thresholds.clone(),
        )?;

        let node_ids = fleet_simulator.instance_ids();
        let authority_id = FleetAuthorityId::from_provisioned_bytes([0xd4; 32]).map_err(|err| {
            ConvergenceHarnessError::Protocol(ProtocolError::SerializationFailed {
                message_type: "FleetAuthorityId".to_string(),
                detail: err.to_string(),
            })
        })?;
        let anchor = HarnessAnchorAuthority::new(authority_id);
        let mut signers = BTreeMap::new();
        for (idx, node_id) in node_ids.iter().enumerate() {
            let mut seed =
                *ContentHash::compute(format!("harness-v2-signer:{idx}:{node_id}").as_bytes())
                    .as_bytes();
            if seed == [0u8; 32] {
                seed[0] = 1;
            }
            let key = SigningKey::from_bytes(seed).map_err(|err| {
                ConvergenceHarnessError::Protocol(ProtocolError::SerializationFailed {
                    message_type: "SigningKey".to_string(),
                    detail: err.to_string(),
                })
            })?;
            let signer = FleetSigner::new(authority_id, node_id.clone(), 1, key).map_err(|err| {
                ConvergenceHarnessError::Protocol(ProtocolError::SerializationFailed {
                    message_type: "FleetSigner".to_string(),
                    detail: err.to_string(),
                })
            })?;
            signers.insert(node_id.clone(), signer);
        }

        let map_reg_err = |err: FleetRegistryPersistenceError| {
            ConvergenceHarnessError::Protocol(ProtocolError::SerializationFailed {
                message_type: "DurableFleetVerificationRegistry".to_string(),
                detail: err.to_string(),
            })
        };
        let mut storage = InMemoryStorageAdapter::new();
        let context = EventContext::new("harness-trace", "harness-decision", "harness-policy")
            .map_err(|err| {
                ConvergenceHarnessError::Protocol(ProtocolError::SerializationFailed {
                    message_type: "EventContext".to_string(),
                    detail: err.to_string(),
                })
            })?;
        let first_id = &node_ids[0];
        let first_signer = &signers[first_id];
        let mut registry = FleetVerificationRegistryPersistence::new(&mut storage, &context)
            .prepare_initial_registration(
                first_id.clone(),
                1,
                first_signer.verification_key().clone(),
                SecurityEpoch::GENESIS,
                &anchor,
            )
            .map_err(map_reg_err)?
            .finalize_and_publish(&anchor)
            .map_err(map_reg_err)?;
        for node_id in &node_ids[1..] {
            let signer = &signers[node_id];
            registry = FleetVerificationRegistryPersistence::new(&mut storage, &context)
                .prepare_register_node(
                    &registry,
                    node_id.clone(),
                    1,
                    signer.verification_key().clone(),
                    SecurityEpoch::GENESIS,
                    &anchor,
                )
                .map_err(map_reg_err)?
                .finalize_and_publish(&anchor)
                .map_err(map_reg_err)?;
        }

        let peer_states = node_ids
            .iter()
            .map(|node_id| {
                AuthenticatedFleetProtocolStateV2::new(
                    authority_id,
                    node_id.clone(),
                    config.gossip_config.clone(),
                    SecurityEpoch::GENESIS,
                )
                .map_err(|err| {
                    ConvergenceHarnessError::Protocol(ProtocolError::SerializationFailed {
                        message_type: "AuthenticatedFleetProtocolStateV2".to_string(),
                        detail: err.to_string(),
                    })
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let quorum = FleetCheckpointQuorumV2::new(
            node_ids.into_iter().collect::<BTreeSet<_>>(),
            config.gossip_config.quorum_threshold_millionths,
        )
        .map_err(|err| {
            ConvergenceHarnessError::Protocol(ProtocolError::SerializationFailed {
                message_type: "FleetCheckpointQuorumV2".to_string(),
                detail: err.to_string(),
            })
        })?;

        Ok(Self {
            fleet_simulator,
            peer_states,
            signers,
            registry,
            anchor,
            quorum,
            active_partition_reachability: None,
            heartbeat_round: 0,
            config,
            start_time: Instant::now(),
            convergence_attempts: 0,
            convergence_history: Vec::new(),
        })
    }

    /// Get the number of nodes in the fleet.
    pub fn node_count(&self) -> usize {
        self.fleet_simulator.instance_count()
    }

    /// Get all node IDs.
    pub fn node_ids(&self) -> Vec<NodeId> {
        self.fleet_simulator.instance_ids()
    }

    /// Set network partition mode for testing different scenarios.
    pub fn set_partition_mode(&mut self, mode: PartitionMode, success_rate: u8) {
        self.active_partition_reachability = Some(match &mode {
            PartitionMode::Normal => {
                if success_rate == 0 {
                    1
                } else {
                    self.node_count()
                }
            }
            PartitionMode::Degraded(info) => {
                if success_rate == 0 {
                    info.local_partition_size.min(self.node_count())
                } else {
                    info.local_partition_size.max(1).min(self.node_count())
                }
            }
            PartitionMode::Healing(_) => self.node_count(),
        });
        self.fleet_simulator.set_partition_mode(mode, success_rate);
    }

    /// Execute a deterministic simulation step.
    pub fn step(&mut self) -> Result<bool, ConvergenceHarnessError> {
        Ok(self.fleet_simulator.process_next_message()?)
    }

    /// Run the simulation for a specified number of steps.
    pub fn run_steps(&mut self, steps: u64) -> Result<u64, ConvergenceHarnessError> {
        let mut executed: u64 = 0;
        for _ in 0..steps {
            if self.step()? {
                executed = executed.saturating_add(1);
            } else {
                break; // No more messages
            }
        }
        Ok(executed)
    }

    /// Broadcast a quarantine decision to test convergence.
    pub fn broadcast_quarantine_decision(
        &mut self,
        extension_id: String,
        reason: String,
        evidence_hash: String,
        originator_instance: NodeId,
    ) -> Result<(), ConvergenceHarnessError> {
        self.fleet_simulator.broadcast_quarantine_decision(
            extension_id,
            reason,
            evidence_hash,
            originator_instance,
        )?;
        Ok(())
    }

    /// Attempt to verify convergence status.
    ///
    /// This is the core method that implements the convergence check.
    /// Returns `ConvergenceResult::QuorumNotReached` under permanent partition
    /// (negative test as required).
    pub fn verify_convergence(&mut self) -> Result<ConvergenceResult, ConvergenceHarnessError> {
        self.convergence_attempts = self.convergence_attempts.saturating_add(1);
        let attempt_start = self.elapsed_time_ms();
        let base_time_ns = self
            .config
            .gossip_config
            .partition_timeout_ns
            .saturating_mul(2)
            .saturating_add(attempt_start.saturating_mul(1_000_000))
            .saturating_add(self.convergence_attempts.saturating_mul(1_000_000));

        if let Some(reachable_count) = self.active_partition_reachability {
            self.heartbeat_round = self.heartbeat_round.saturating_add(1);
            let round = self.heartbeat_round;
            let node_ids = self.node_ids();
            let stale_ts = 1_000_000;
            for (sender_idx, sender_id) in node_ids.iter().enumerate() {
                let ts_ns = if sender_idx < reachable_count {
                    base_time_ns
                } else {
                    stale_ts
                };
                let hb = HeartbeatLiveness {
                    node_id: sender_id.clone(),
                    policy_version: 1,
                    evidence_frontier_hash: ContentHash::compute(
                        format!("harness-hb:{sender_id}:{round}").as_bytes(),
                    ),
                    local_health: BTreeMap::new(),
                    epoch: SecurityEpoch::GENESIS,
                    sequence: round,
                    timestamp_ns: ts_ns,
                    signature: MessageSignature {
                        signer: sender_id.clone(),
                        hash: AuthenticityHash([0; 32]),
                    },
                    protocol_version: ProtocolVersion::V2,
                    extensions: BTreeMap::new(),
                };
                let sig = self.signers[sender_id]
                    .sign_detached_message_v2(&hb)
                    .map_err(|err| {
                        ConvergenceHarnessError::Protocol(ProtocolError::InvalidSignature {
                            node_id: sender_id.clone(),
                            message_type: err.to_string(),
                        })
                    })?;
                for peer_state in &mut self.peer_states {
                    peer_state
                        .process_heartbeat(&hb, &sig, &self.registry, &self.anchor)
                        .map_err(|err| {
                            ConvergenceHarnessError::Protocol(ProtocolError::InvalidSignature {
                                node_id: sender_id.clone(),
                                message_type: err.to_string(),
                            })
                        })?;
                }
            }
        }

        let quarantine_stats = self.fleet_simulator.get_quarantine_stats();
        let total_node_count = self.fleet_simulator.instance_count();
        let node_ids = self.node_ids();

        let result = match self.peer_states[0].draft_checkpoint_v2(base_time_ns, &self.quorum) {
            Ok(mut draft) => {
                let mut cosign_error: Option<FleetCheckpointV2Error> = None;
                for (peer_idx, peer_id) in node_ids.iter().enumerate() {
                    if !draft.checkpoint().participating_nodes.contains(peer_id) {
                        continue;
                    }
                    let signer = &self.signers[peer_id];
                    let vote_res = if peer_idx == 0 {
                        self.peer_states[0].sign_checkpoint_v2(
                            &draft,
                            &self.quorum,
                            signer,
                            &self.registry,
                            &self.anchor,
                        )
                    } else {
                        self.peer_states[peer_idx]
                            .import_checkpoint_proposal_v2(draft.checkpoint(), &self.quorum)
                            .and_then(|peer_draft| {
                                self.peer_states[peer_idx].sign_checkpoint_v2(
                                    &peer_draft,
                                    &self.quorum,
                                    signer,
                                    &self.registry,
                                    &self.anchor,
                                )
                            })
                    };
                    match vote_res.and_then(|sig| {
                        draft.add_signature(sig, &self.registry, &self.anchor)
                    }) {
                        Ok(()) => {}
                        Err(err) => {
                            cosign_error = Some(err);
                            break;
                        }
                    }
                }

                if let Some(err) = cosign_error {
                    ConvergenceResult::ProtocolError {
                        error: err.to_string(),
                    }
                } else {
                    match self.peer_states[0].finalize_checkpoint_v2(
                        &draft,
                        &self.quorum,
                        base_time_ns,
                        &self.registry,
                        &self.anchor,
                    ) {
                        Ok(signed) => {
                            for peer_state in &mut self.peer_states[1..] {
                                if signed
                                    .checkpoint
                                    .participating_nodes
                                    .contains(&peer_state.state().local_node_id)
                                {
                                    let _ = peer_state.accept_checkpoint_v2(
                                        &signed,
                                        &self.quorum,
                                        base_time_ns,
                                        &self.registry,
                                        &self.anchor,
                                    );
                                }
                            }
                            ConvergenceResult::Converged {
                                checkpoint_seq: signed.checkpoint.checkpoint_seq,
                                participating_nodes: signed.checkpoint.participating_nodes.len(),
                                decisions_resolved: signed.checkpoint.containment_decisions.len(),
                            }
                        }
                        Err(FleetCheckpointV2Error::InsufficientQuorum { required, actual }) => {
                            let partitioned_nodes =
                                self.peer_states[0].state().partitioned_nodes(base_time_ns);
                            ConvergenceResult::QuorumNotReached {
                                required_nodes: required,
                                available_nodes: actual,
                                partition_detected: !partitioned_nodes.is_empty(),
                            }
                        }
                        Err(other) => ConvergenceResult::ProtocolError {
                            error: other.to_string(),
                        },
                    }
                }
            }
            Err(FleetCheckpointV2Error::InsufficientQuorum { required, actual }) => {
                let partitioned_nodes =
                    self.peer_states[0].state().partitioned_nodes(base_time_ns);
                ConvergenceResult::QuorumNotReached {
                    required_nodes: required,
                    available_nodes: actual,
                    partition_detected: !partitioned_nodes.is_empty(),
                }
            }
            Err(other_error) => ConvergenceResult::ProtocolError {
                error: other_error.to_string(),
            },
        };

        let healthy_node_count = match &result {
            ConvergenceResult::Converged {
                participating_nodes,
                ..
            } => *participating_nodes,
            ConvergenceResult::QuorumNotReached {
                available_nodes, ..
            } => *available_nodes,
            _ => 0,
        };

        // Record the attempt
        let attempt = ConvergenceAttempt {
            attempt_id: self.convergence_attempts,
            timestamp_ms: attempt_start,
            result: result.clone(),
            healthy_node_count,
            total_node_count,
            quarantine_stats,
            simulation_steps: self.fleet_simulator.simulation_stats().simulation_steps,
        };
        self.convergence_history.push(attempt);

        Ok(result)
    }

    /// Test convergence under no partition (should succeed).
    pub fn test_convergence_no_partition(
        &mut self,
        extension_id: String,
    ) -> Result<ConvergenceResult, ConvergenceHarnessError> {
        // Ensure normal partition mode
        self.set_partition_mode(PartitionMode::Normal, 100);

        // Broadcast a test quarantine decision
        let node_ids = self.node_ids();
        if node_ids.is_empty() {
            return Err(ConvergenceHarnessError::NoNodesAvailable);
        }

        self.broadcast_quarantine_decision(
            extension_id,
            "Test quarantine for convergence verification".to_string(),
            "test-evidence-no-partition".to_string(),
            node_ids[0].clone(),
        )?;

        // Run simulation steps to propagate messages
        self.run_steps(self.config.max_simulation_steps)?;

        // Verify convergence
        self.verify_convergence()
    }

    /// Test convergence under symmetric partition (may succeed if quorum maintained).
    pub fn test_convergence_symmetric_partition(
        &mut self,
        extension_id: String,
        partition_success_rate: u8,
    ) -> Result<ConvergenceResult, ConvergenceHarnessError> {
        use crate::fleet_convergence::PartitionInfo;

        // Set degraded partition mode
        let partition_info = PartitionInfo {
            detected_at_ns: self.elapsed_time_ms().saturating_mul(1_000_000),
            unreachable_nodes: BTreeSet::new(),
            local_partition_size: self.node_count() / 2, // symmetric split
            total_fleet_size: self.node_count(),
        };
        self.set_partition_mode(
            PartitionMode::Degraded(partition_info),
            partition_success_rate,
        );

        // Broadcast a test quarantine decision
        let node_ids = self.node_ids();
        if node_ids.is_empty() {
            return Err(ConvergenceHarnessError::NoNodesAvailable);
        }

        self.broadcast_quarantine_decision(
            extension_id,
            "Test quarantine under symmetric partition".to_string(),
            "test-evidence-symmetric-partition".to_string(),
            node_ids[0].clone(),
        )?;

        // Run simulation steps to propagate messages
        self.run_steps(self.config.max_simulation_steps)?;

        // Verify convergence
        self.verify_convergence()
    }

    /// Test convergence under permanent partition (MUST refuse convergence).
    ///
    /// This is the critical NEGATIVE test that validates the bead requirement.
    pub fn test_convergence_permanent_partition(
        &mut self,
        extension_id: String,
    ) -> Result<ConvergenceResult, ConvergenceHarnessError> {
        use crate::fleet_convergence::PartitionInfo;

        // Set severe partition mode that breaks quorum
        let partition_info = PartitionInfo {
            detected_at_ns: self.elapsed_time_ms().saturating_mul(1_000_000),
            unreachable_nodes: BTreeSet::new(),
            local_partition_size: 1, // Isolated - cannot reach quorum
            total_fleet_size: self.node_count(),
        };
        self.set_partition_mode(PartitionMode::Degraded(partition_info), 0); // 0% success rate

        // Broadcast a test quarantine decision
        let node_ids = self.node_ids();
        if node_ids.is_empty() {
            return Err(ConvergenceHarnessError::NoNodesAvailable);
        }

        self.broadcast_quarantine_decision(
            extension_id,
            "Test quarantine under permanent partition".to_string(),
            "test-evidence-permanent-partition".to_string(),
            node_ids[0].clone(),
        )?;

        // Run simulation steps - messages should be dropped
        self.run_steps(self.config.max_simulation_steps)?;

        // Verify convergence - MUST refuse due to partition
        self.verify_convergence()
    }

    /// Get convergence attempt history for analysis.
    pub fn convergence_history(&self) -> &[ConvergenceAttempt] {
        &self.convergence_history
    }

    /// Get simulation statistics.
    pub fn simulation_stats(&self) -> crate::fleet_simulator::SimulationStats {
        self.fleet_simulator.simulation_stats()
    }

    /// Get quarantine statistics.
    pub fn quarantine_stats(&self) -> QuarantineStats {
        self.fleet_simulator.get_quarantine_stats()
    }

    /// Export event log as JSONL for analysis.
    pub fn export_event_log(&self) -> String {
        self.fleet_simulator.export_event_log()
    }

    /// Get elapsed time since harness creation.
    fn elapsed_time_ms(&self) -> u64 {
        u64::try_from(self.start_time.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

impl Default for FleetConvergenceHarness {
    fn default() -> Self {
        Self::new().expect("Default fleet convergence harness should create successfully")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_extension_id(test_name: &str) -> String {
        format!("test-extension-{}", test_name)
    }

    fn test_node_count() -> usize {
        3 // Small for faster tests
    }

    #[test]
    fn test_create_harness_default() {
        let harness =
            FleetConvergenceHarness::new().expect("Should create default harness successfully");
        assert_eq!(harness.node_count(), 7);
        assert_eq!(harness.node_ids().len(), 7);
    }

    #[test]
    fn test_create_harness_custom_node_count() {
        let harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness with custom node count");
        assert_eq!(harness.node_count(), test_node_count());
    }

    #[test]
    fn test_invalid_node_count_zero() {
        let result = FleetConvergenceHarness::with_node_count(0);
        assert!(matches!(
            result,
            Err(ConvergenceHarnessError::InvalidNodeCount { count: 0 })
        ));
    }

    #[test]
    fn test_step_execution() {
        let mut harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness");

        // Initial step with no messages should return false
        let had_message = harness.step().expect("Step should succeed");
        assert!(!had_message);
    }

    #[test]
    fn test_partition_mode_setting() {
        let mut harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness");

        // Should not panic when setting partition modes
        harness.set_partition_mode(PartitionMode::Normal, 100);

        use crate::fleet_convergence::PartitionInfo;
        let partition_info = PartitionInfo {
            detected_at_ns: 0,
            unreachable_nodes: BTreeSet::new(),
            local_partition_size: 1,
            total_fleet_size: test_node_count(),
        };
        harness.set_partition_mode(PartitionMode::Degraded(partition_info), 50);
    }

    #[test]
    fn test_convergence_no_partition_succeeds() {
        let mut harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness");

        let result = harness
            .test_convergence_no_partition(test_extension_id("no_partition"))
            .expect("Convergence test should execute");

        assert!(
            matches!(
                result,
                ConvergenceResult::Converged {
                    checkpoint_seq: 1,
                    participating_nodes: 3,
                    ..
                }
            ),
            "expected authenticated V2 quorum convergence under no partition, got {result:?}"
        );
    }

    #[test]
    fn test_convergence_permanent_partition_refuses() {
        let mut harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness");

        let result = harness
            .test_convergence_permanent_partition(test_extension_id("permanent_partition"))
            .expect("Convergence test should execute");

        // CRITICAL TEST: Must refuse convergence under permanent partition
        assert!(
            matches!(
                result,
                ConvergenceResult::QuorumNotReached {
                    required_nodes: 2,
                    available_nodes: 1,
                    partition_detected: true,
                }
            ),
            "expected fail-closed QuorumNotReached under permanent partition, got {result:?}"
        );
    }

    #[test]
    fn test_convergence_symmetric_partition_variable() {
        let mut harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness");

        let result = harness
            .test_convergence_symmetric_partition(
                test_extension_id("symmetric_partition"),
                70, // 70% success rate
            )
            .expect("Convergence test should execute");

        // Under symmetric partition, result depends on whether quorum is maintained
        match result {
            ConvergenceResult::Converged { .. } => {
                // May succeed if enough nodes remain in contact
            }
            ConvergenceResult::QuorumNotReached { .. } => {
                // May fail if partition breaks quorum
            }
            ConvergenceResult::ProtocolError { .. } => {
                // May have protocol issues under partition
            }
            _ => {
                // Other results acceptable
            }
        }
    }

    #[test]
    fn test_convergence_history_tracking() {
        let mut harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness");

        assert_eq!(harness.convergence_history().len(), 0);

        let _result = harness
            .verify_convergence()
            .expect("Convergence verification should execute");

        assert_eq!(harness.convergence_history().len(), 1);
        let attempt = &harness.convergence_history()[0];
        assert_eq!(attempt.attempt_id, 1);
        assert_eq!(attempt.total_node_count, test_node_count());
    }

    #[test]
    fn test_quarantine_decision_broadcast() {
        let mut harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness");

        let node_ids = harness.node_ids();
        harness
            .broadcast_quarantine_decision(
                "test-extension".to_string(),
                "Test broadcast".to_string(),
                "test-evidence".to_string(),
                node_ids[0].clone(),
            )
            .expect("Broadcast should succeed");

        let quarantine_stats = harness.quarantine_stats();
        assert_eq!(quarantine_stats.total_quarantine_decisions, 1);
    }

    #[test]
    fn test_run_steps_execution() {
        let mut harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness");

        let executed = harness.run_steps(10).expect("Run steps should succeed");

        // May execute 0 steps if no messages in queue
        assert!(executed <= 10);
    }

    #[test]
    fn test_statistics_access() {
        let harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness");

        let sim_stats = harness.simulation_stats();
        assert_eq!(sim_stats.total_instances, test_node_count() as u32);

        let quar_stats = harness.quarantine_stats();
        assert_eq!(quar_stats.total_quarantine_decisions, 0);

        let event_log = harness.export_event_log();
        assert!(!event_log.is_empty()); // Should have instance creation events
    }

    #[test]
    fn test_config_serialization() {
        let config = ConvergenceHarnessConfig::default();
        let json = serde_json::to_string(&config).expect("Config should serialize");
        let decoded: ConvergenceHarnessConfig =
            serde_json::from_str(&json).expect("Config should deserialize");
        assert_eq!(decoded.default_node_count, 7);
    }

    #[test]
    fn test_convergence_attempt_serialization() {
        let attempt = ConvergenceAttempt {
            attempt_id: 1,
            timestamp_ms: 1000,
            result: ConvergenceResult::Converged {
                checkpoint_seq: 1,
                participating_nodes: 3,
                decisions_resolved: 1,
            },
            healthy_node_count: 3,
            total_node_count: 3,
            quarantine_stats: QuarantineStats {
                total_quarantine_decisions: 1,
                converged_decisions: 1,
                pending_decisions: 0,
                total_acknowledgments: 3,
            },
            simulation_steps: 10,
        };

        let json = serde_json::to_string(&attempt).expect("ConvergenceAttempt should serialize");
        let decoded: ConvergenceAttempt =
            serde_json::from_str(&json).expect("ConvergenceAttempt should deserialize");
        assert_eq!(decoded.attempt_id, 1);
    }

    // Additional tests for comprehensive coverage

    #[test]
    fn test_convergence_with_multiple_decisions() {
        let mut harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness");

        let node_ids = harness.node_ids();

        // Broadcast multiple quarantine decisions
        for i in 0..3 {
            harness
                .broadcast_quarantine_decision(
                    format!("ext-{}", i),
                    format!("Reason {}", i),
                    format!("evidence-{}", i),
                    node_ids[i % node_ids.len()].clone(),
                )
                .expect("Broadcast should succeed");
        }

        harness.run_steps(20).expect("Steps should execute");

        let stats = harness.quarantine_stats();
        assert_eq!(stats.total_quarantine_decisions, 3);
    }

    #[test]
    fn test_convergence_result_variants() {
        // Test serialization of all ConvergenceResult variants
        let variants = vec![
            ConvergenceResult::Converged {
                checkpoint_seq: 1,
                participating_nodes: 3,
                decisions_resolved: 1,
            },
            ConvergenceResult::QuorumNotReached {
                required_nodes: 3,
                available_nodes: 1,
                partition_detected: true,
            },
            ConvergenceResult::ProtocolError {
                error: "Test error".to_string(),
            },
            ConvergenceResult::Timeout { elapsed_ms: 5000 },
        ];

        for variant in variants {
            let json = serde_json::to_string(&variant).expect("ConvergenceResult should serialize");
            let decoded: ConvergenceResult =
                serde_json::from_str(&json).expect("ConvergenceResult should deserialize");

            // Basic structural equality check
            match (&variant, &decoded) {
                (
                    ConvergenceResult::Converged {
                        checkpoint_seq: a, ..
                    },
                    ConvergenceResult::Converged {
                        checkpoint_seq: b, ..
                    },
                ) => {
                    assert_eq!(a, b);
                }
                (
                    ConvergenceResult::QuorumNotReached {
                        required_nodes: a, ..
                    },
                    ConvergenceResult::QuorumNotReached {
                        required_nodes: b, ..
                    },
                ) => {
                    assert_eq!(a, b);
                }
                (
                    ConvergenceResult::ProtocolError { .. },
                    ConvergenceResult::ProtocolError { .. },
                ) => {}
                (ConvergenceResult::Timeout { .. }, ConvergenceResult::Timeout { .. }) => {}
                _ => panic!("Variant mismatch during roundtrip"),
            }
        }
    }

    #[test]
    fn test_convergence_harness_error_display() {
        let errors = vec![
            ConvergenceHarnessError::InvalidNodeCount { count: 0 },
            ConvergenceHarnessError::ConvergenceTimeout { elapsed_ms: 5000 },
            ConvergenceHarnessError::NoNodesAvailable,
        ];

        for error in errors {
            let msg = error.to_string();
            assert!(!msg.is_empty());
        }
    }

    #[test]
    fn test_node_ids_consistency() {
        let harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness");

        let node_ids_1 = harness.node_ids();
        let node_ids_2 = harness.node_ids();

        assert_eq!(node_ids_1, node_ids_2);
        assert_eq!(node_ids_1.len(), test_node_count());

        // Check that all node IDs are unique
        let mut unique_ids = BTreeSet::new();
        for id in &node_ids_1 {
            assert!(unique_ids.insert(id.clone()), "Duplicate node ID found");
        }
    }

    #[test]
    fn test_elapsed_time_monotonic() {
        let harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness");

        let time_1 = harness.elapsed_time_ms();

        // Small delay
        std::thread::sleep(std::time::Duration::from_millis(1));

        let time_2 = harness.elapsed_time_ms();
        assert!(time_2 >= time_1);
    }

    // Performance/benchmark-oriented tests for criterion compatibility

    #[test]
    fn test_benchmark_compatibility_single_convergence() {
        let mut harness =
            FleetConvergenceHarness::with_node_count(5).expect("Should create harness");

        let start = Instant::now();

        let _result = harness
            .test_convergence_no_partition(test_extension_id("benchmark"))
            .expect("Convergence test should execute");

        let duration = start.elapsed();

        // Should complete within reasonable time for benchmarking
        assert!(
            duration.as_secs() < 10,
            "Convergence test too slow for benchmarking"
        );
    }

    #[test]
    fn test_benchmark_compatibility_multiple_steps() {
        let mut harness =
            FleetConvergenceHarness::with_node_count(5).expect("Should create harness");

        let start = Instant::now();

        let executed = harness.run_steps(100).expect("Steps should execute");

        let duration = start.elapsed();

        // Step execution should be fast
        assert!(duration.as_millis() < 1000, "Step execution too slow");
        assert!(executed <= 100);
    }

    #[test]
    fn test_repeated_convergence_attempts() {
        let mut harness = FleetConvergenceHarness::with_node_count(test_node_count())
            .expect("Should create harness");

        // Multiple convergence attempts should work
        for _ in 0..3 {
            let _result = harness
                .verify_convergence()
                .expect("Convergence verification should work");
        }

        assert_eq!(harness.convergence_history().len(), 3);

        // Attempt IDs should be sequential
        for (i, attempt) in harness.convergence_history().iter().enumerate() {
            assert_eq!(attempt.attempt_id, (i + 1) as u64);
        }
    }
}
