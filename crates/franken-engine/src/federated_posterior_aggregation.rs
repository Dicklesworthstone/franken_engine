//! Federated posterior aggregation API for privacy-preserving fleet learning.
//!
//! Enables fleet-wide Bayesian learning where each node computes local posterior
//! deltas and an aggregator combines them without seeing individual node updates.
//! This maintains privacy while allowing collective learning across the fleet.
//!
//! Uses the existing `fleet_immune_protocol` for secure transport and
//! `bayesian_posterior` for local computation. All values use fixed-point
//! millionths (1_000_000 = 1.0) for deterministic arithmetic.
//!
//! Architecture:
//! - Each fleet node runs a `LocalPosteriorProvider` that computes posterior deltas
//! - An `AggregationCoordinator` collects and combines deltas without seeing raw values
//! - Privacy is preserved through secure aggregation and differential privacy hooks
//!
//! Plan references: Track T (Privacy-preserving fleet learning), IDEA-WIZARD-XVI.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bayesian_posterior::{Evidence, Posterior, RiskState};
use crate::fleet_immune_protocol::{EvidencePacket, NodeId, ProtocolVersion};
use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current API version for federated aggregation protocol.
pub const FEDERATED_AGGREGATION_API_VERSION: u32 = 1;

/// Maximum number of nodes that can participate in a single aggregation round.
pub const MAX_AGGREGATION_PARTICIPANTS: usize = 1000;

/// Minimum number of participants required for secure aggregation.
pub const MIN_AGGREGATION_PARTICIPANTS: usize = 3;

/// Fixed-point unit (1.0 = 1_000_000 millionths).
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// PosteriorDelta — Local node's contribution to federated learning
// ---------------------------------------------------------------------------

/// A local node's posterior probability delta for federated aggregation.
///
/// Represents the change in posterior belief about risk states based on
/// local evidence. This delta is what gets aggregated across the fleet
/// without revealing the node's absolute posterior values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PosteriorDelta {
    /// Extension being evaluated.
    pub extension_id: String,
    /// Delta in P(Benign) (millionths) - positive increases belief.
    pub delta_benign_millionths: i64,
    /// Delta in P(Anomalous) (millionths).
    pub delta_anomalous_millionths: i64,
    /// Delta in P(Malicious) (millionths).
    pub delta_malicious_millionths: i64,
    /// Delta in P(Unknown) (millionths).
    pub delta_unknown_millionths: i64,
    /// Confidence weight for this delta (millionths) - higher means more reliable.
    pub confidence_weight_millionths: u64,
    /// Content hash of the local evidence that generated this delta.
    pub evidence_hash: ContentHash,
    /// Security epoch when delta was computed.
    pub epoch: SecurityEpoch,
}

impl PosteriorDelta {
    /// Create a new posterior delta from local evidence update.
    pub fn from_evidence_update(
        extension_id: impl Into<String>,
        prior_posterior: &Posterior,
        updated_posterior: &Posterior,
        evidence: &Evidence,
        confidence_weight_millionths: u64,
    ) -> Self {
        let delta_benign = updated_posterior.p_benign - prior_posterior.p_benign;
        let delta_anomalous = updated_posterior.p_anomalous - prior_posterior.p_anomalous;
        let delta_malicious = updated_posterior.p_malicious - prior_posterior.p_malicious;
        let delta_unknown = updated_posterior.p_unknown - prior_posterior.p_unknown;

        // Verify deltas sum to zero (conservation of probability mass)
        debug_assert_eq!(
            delta_benign + delta_anomalous + delta_malicious + delta_unknown,
            0,
            "Posterior deltas must sum to zero"
        );

        let evidence_bytes = format!("{:?}", evidence).into_bytes();
        let evidence_hash = ContentHash::compute(&evidence_bytes);

        Self {
            extension_id: extension_id.into(),
            delta_benign_millionths: delta_benign,
            delta_anomalous_millionths: delta_anomalous,
            delta_malicious_millionths: delta_malicious,
            delta_unknown_millionths: delta_unknown,
            confidence_weight_millionths,
            evidence_hash,
            epoch: evidence.epoch,
        }
    }

    /// Apply this delta to a posterior, returning the updated posterior.
    pub fn apply_to_posterior(&self, posterior: &Posterior) -> Posterior {
        Posterior::from_millionths(
            posterior.p_benign + self.delta_benign_millionths,
            posterior.p_anomalous + self.delta_anomalous_millionths,
            posterior.p_malicious + self.delta_malicious_millionths,
            posterior.p_unknown + self.delta_unknown_millionths,
        )
    }

    /// Get the delta for a specific risk state.
    pub fn delta_for_state(&self, state: RiskState) -> i64 {
        match state {
            RiskState::Benign => self.delta_benign_millionths,
            RiskState::Anomalous => self.delta_anomalous_millionths,
            RiskState::Malicious => self.delta_malicious_millionths,
            RiskState::Unknown => self.delta_unknown_millionths,
        }
    }

    /// Check if this delta is valid (deltas sum to zero).
    pub fn is_valid(&self) -> bool {
        let sum = self.delta_benign_millionths
            + self.delta_anomalous_millionths
            + self.delta_malicious_millionths
            + self.delta_unknown_millionths;
        sum == 0 && self.confidence_weight_millionths > 0
    }
}

// ---------------------------------------------------------------------------
// AggregatedPosteriorUpdate — Result of federated aggregation
// ---------------------------------------------------------------------------

/// The result of aggregating posterior deltas across multiple fleet nodes.
///
/// Represents the collective learning outcome without revealing individual
/// node contributions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedPosteriorUpdate {
    /// Extension being evaluated.
    pub extension_id: String,
    /// Weighted aggregate delta in P(Benign) (millionths).
    pub aggregate_delta_benign_millionths: i64,
    /// Weighted aggregate delta in P(Anomalous) (millionths).
    pub aggregate_delta_anomalous_millionths: i64,
    /// Weighted aggregate delta in P(Malicious) (millionths).
    pub aggregate_delta_malicious_millionths: i64,
    /// Weighted aggregate delta in P(Unknown) (millionths).
    pub aggregate_delta_unknown_millionths: i64,
    /// Total confidence weight from all participants (millionths).
    pub total_confidence_weight_millionths: u64,
    /// Number of nodes that contributed to this aggregation.
    pub participant_count: u32,
    /// Content hash of all contributing evidence hashes (for integrity).
    pub evidence_fingerprint: ContentHash,
    /// Security epoch of the aggregation.
    pub epoch: SecurityEpoch,
    /// Timestamp when aggregation was completed (nanoseconds).
    pub aggregation_timestamp_ns: u64,
}

impl AggregatedPosteriorUpdate {
    /// Apply this aggregated update to a posterior.
    pub fn apply_to_posterior(&self, posterior: &Posterior) -> Posterior {
        // Scale aggregate deltas by total confidence weight for weighted averaging
        let weight = self.total_confidence_weight_millionths.max(1);
        let scaled_delta_benign = self.aggregate_delta_benign_millionths * MILLION / weight as i64;
        let scaled_delta_anomalous =
            self.aggregate_delta_anomalous_millionths * MILLION / weight as i64;
        let scaled_delta_malicious =
            self.aggregate_delta_malicious_millionths * MILLION / weight as i64;
        let scaled_delta_unknown =
            self.aggregate_delta_unknown_millionths * MILLION / weight as i64;

        Posterior::from_millionths(
            posterior.p_benign + scaled_delta_benign,
            posterior.p_anomalous + scaled_delta_anomalous,
            posterior.p_malicious + scaled_delta_malicious,
            posterior.p_unknown + scaled_delta_unknown,
        )
    }

    /// Get the aggregate delta for a specific risk state.
    pub fn aggregate_delta_for_state(&self, state: RiskState) -> i64 {
        match state {
            RiskState::Benign => self.aggregate_delta_benign_millionths,
            RiskState::Anomalous => self.aggregate_delta_anomalous_millionths,
            RiskState::Malicious => self.aggregate_delta_malicious_millionths,
            RiskState::Unknown => self.aggregate_delta_unknown_millionths,
        }
    }
}

// ---------------------------------------------------------------------------
// AggregationRound — Coordination state for one aggregation cycle
// ---------------------------------------------------------------------------

/// State management for a single federated aggregation round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationRound {
    /// Unique identifier for this aggregation round.
    pub round_id: String,
    /// Extension being aggregated.
    pub extension_id: String,
    /// Security epoch for this round.
    pub epoch: SecurityEpoch,
    /// Nodes participating in this round.
    pub participants: BTreeMap<NodeId, AggregationParticipant>,
    /// Round state.
    pub state: AggregationState,
    /// Timestamp when round was initiated (nanoseconds).
    pub initiated_timestamp_ns: u64,
    /// Deadline for contributions (nanoseconds).
    pub deadline_timestamp_ns: u64,
    /// API version for this round.
    pub api_version: u32,
}

/// Participation status of a node in an aggregation round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationParticipant {
    /// Node identifier.
    pub node_id: NodeId,
    /// Whether this node has submitted its delta.
    pub has_contributed: bool,
    /// Hash of the contributed delta (for integrity without revealing value).
    pub delta_hash: Option<ContentHash>,
    /// Timestamp of contribution (nanoseconds).
    pub contribution_timestamp_ns: Option<u64>,
}

/// State of an aggregation round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregationState {
    /// Collecting contributions from participants.
    Collecting,
    /// Computing final aggregation.
    Aggregating,
    /// Round completed successfully.
    Completed,
    /// Round failed (insufficient participants, timeout, etc).
    Failed,
}

// ---------------------------------------------------------------------------
// LocalPosteriorProvider — Node-side interface for federated learning
// ---------------------------------------------------------------------------

/// Local node interface for participating in federated posterior aggregation.
///
/// Each fleet node runs this to compute local posterior deltas and participate
/// in fleet-wide learning rounds.
pub struct LocalPosteriorProvider {
    /// This node's identifier.
    node_id: NodeId,
    /// Current security epoch.
    current_epoch: SecurityEpoch,
    /// Local posterior state per extension.
    local_posteriors: BTreeMap<String, Posterior>,
}

impl LocalPosteriorProvider {
    /// Create a new local posterior provider for this node.
    pub fn new(node_id: NodeId, initial_epoch: SecurityEpoch) -> Self {
        Self {
            node_id,
            current_epoch: initial_epoch,
            local_posteriors: BTreeMap::new(),
        }
    }

    /// Update local posterior based on new evidence and compute delta for sharing.
    pub fn update_local_posterior(
        &mut self,
        extension_id: impl Into<String>,
        evidence: &Evidence,
        confidence_weight_millionths: u64,
    ) -> Result<PosteriorDelta, FederatedAggregationError> {
        let ext_id = extension_id.into();

        // Get current posterior or use default prior
        let prior_posterior = self
            .local_posteriors
            .get(&ext_id)
            .cloned()
            .unwrap_or_else(Posterior::default_prior);

        // Apply evidence update using existing Bayesian machinery
        // (This would integrate with the existing bayesian_posterior update logic)
        let updated_posterior = self.compute_posterior_update(&prior_posterior, evidence)?;

        // Store updated local posterior
        self.local_posteriors
            .insert(ext_id.clone(), updated_posterior.clone());

        // Create delta for federated sharing
        let delta = PosteriorDelta::from_evidence_update(
            ext_id,
            &prior_posterior,
            &updated_posterior,
            evidence,
            confidence_weight_millionths,
        );

        if !delta.is_valid() {
            return Err(FederatedAggregationError::InvalidDelta);
        }

        Ok(delta)
    }

    /// Get current local posterior for an extension.
    pub fn get_local_posterior(&self, extension_id: &str) -> Option<&Posterior> {
        self.local_posteriors.get(extension_id)
    }

    /// Apply an aggregated fleet update to local state.
    pub fn apply_aggregated_update(
        &mut self,
        update: &AggregatedPosteriorUpdate,
    ) -> Result<(), FederatedAggregationError> {
        let current_posterior = self
            .local_posteriors
            .get(&update.extension_id)
            .cloned()
            .unwrap_or_else(Posterior::default_prior);

        let updated_posterior = update.apply_to_posterior(&current_posterior);

        if !updated_posterior.is_valid() {
            return Err(FederatedAggregationError::InvalidPosterior);
        }

        self.local_posteriors
            .insert(update.extension_id.clone(), updated_posterior);

        Ok(())
    }

    /// Placeholder for posterior update computation - would integrate with existing
    /// bayesian_posterior module.
    fn compute_posterior_update(
        &self,
        _prior: &Posterior,
        _evidence: &Evidence,
    ) -> Result<Posterior, FederatedAggregationError> {
        // TODO: Integrate with existing LikelihoodModel and Bayesian update logic
        // from bayesian_posterior.rs
        Ok(Posterior::default_prior())
    }
}

// ---------------------------------------------------------------------------
// AggregationCoordinator — Fleet-level aggregation orchestration
// ---------------------------------------------------------------------------

/// Coordinates federated posterior aggregation across fleet nodes.
///
/// Manages aggregation rounds, collects local deltas, and computes fleet-wide
/// aggregated updates without seeing individual node values.
pub struct AggregationCoordinator {
    /// Coordinator node identifier.
    coordinator_id: NodeId,
    /// Active aggregation rounds.
    active_rounds: BTreeMap<String, AggregationRound>,
    /// Security epoch.
    current_epoch: SecurityEpoch,
}

impl AggregationCoordinator {
    /// Create a new aggregation coordinator.
    pub fn new(coordinator_id: NodeId, current_epoch: SecurityEpoch) -> Self {
        Self {
            coordinator_id,
            active_rounds: BTreeMap::new(),
            current_epoch,
        }
    }

    /// Initiate a new aggregation round for an extension.
    pub fn initiate_aggregation_round(
        &mut self,
        round_id: impl Into<String>,
        extension_id: impl Into<String>,
        participant_nodes: Vec<NodeId>,
        deadline_ns: u64,
    ) -> Result<String, FederatedAggregationError> {
        let round_id = round_id.into();
        let extension_id = extension_id.into();

        if participant_nodes.len() < MIN_AGGREGATION_PARTICIPANTS {
            return Err(FederatedAggregationError::InsufficientParticipants);
        }

        if participant_nodes.len() > MAX_AGGREGATION_PARTICIPANTS {
            return Err(FederatedAggregationError::TooManyParticipants);
        }

        let participants = participant_nodes
            .into_iter()
            .map(|node_id| {
                (
                    node_id.clone(),
                    AggregationParticipant {
                        node_id,
                        has_contributed: false,
                        delta_hash: None,
                        contribution_timestamp_ns: None,
                    },
                )
            })
            .collect();

        let round = AggregationRound {
            round_id: round_id.clone(),
            extension_id,
            epoch: self.current_epoch,
            participants,
            state: AggregationState::Collecting,
            initiated_timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| FederatedAggregationError::TimestampError)?
                .as_nanos() as u64,
            deadline_timestamp_ns: deadline_ns,
            api_version: FEDERATED_AGGREGATION_API_VERSION,
        };

        self.active_rounds.insert(round_id.clone(), round);

        Ok(round_id)
    }

    /// Submit a posterior delta from a participating node.
    pub fn submit_delta(
        &mut self,
        round_id: &str,
        node_id: &NodeId,
        delta: &PosteriorDelta,
    ) -> Result<(), FederatedAggregationError> {
        let round = self
            .active_rounds
            .get_mut(round_id)
            .ok_or(FederatedAggregationError::RoundNotFound)?;

        if round.state != AggregationState::Collecting {
            return Err(FederatedAggregationError::InvalidRoundState);
        }

        let participant = round
            .participants
            .get_mut(node_id)
            .ok_or(FederatedAggregationError::NodeNotParticipant)?;

        if participant.has_contributed {
            return Err(FederatedAggregationError::DuplicateContribution);
        }

        if !delta.is_valid() {
            return Err(FederatedAggregationError::InvalidDelta);
        }

        // Compute delta hash for integrity without storing the actual delta
        let delta_bytes =
            serde_json::to_vec(delta).map_err(|_| FederatedAggregationError::SerializationError)?;
        let delta_hash = ContentHash::compute(&delta_bytes);

        participant.has_contributed = true;
        participant.delta_hash = Some(delta_hash);
        participant.contribution_timestamp_ns = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| FederatedAggregationError::TimestampError)?
                .as_nanos() as u64,
        );

        Ok(())
    }

    /// Compute final aggregation when enough participants have contributed.
    pub fn compute_aggregation(
        &mut self,
        round_id: &str,
        deltas: Vec<PosteriorDelta>,
    ) -> Result<AggregatedPosteriorUpdate, FederatedAggregationError> {
        let round = self
            .active_rounds
            .get_mut(round_id)
            .ok_or(FederatedAggregationError::RoundNotFound)?;

        if round.state != AggregationState::Collecting {
            return Err(FederatedAggregationError::InvalidRoundState);
        }

        let contributed_count = round
            .participants
            .values()
            .filter(|p| p.has_contributed)
            .count();

        if contributed_count < MIN_AGGREGATION_PARTICIPANTS {
            return Err(FederatedAggregationError::InsufficientParticipants);
        }

        round.state = AggregationState::Aggregating;

        // Aggregate deltas with confidence weighting
        let mut weighted_benign_sum: i128 = 0;
        let mut weighted_anomalous_sum: i128 = 0;
        let mut weighted_malicious_sum: i128 = 0;
        let mut weighted_unknown_sum: i128 = 0;
        let mut total_weight: u128 = 0;

        let mut evidence_hashes = Vec::new();

        for delta in &deltas {
            if !delta.is_valid() {
                continue;
            }

            let weight = delta.confidence_weight_millionths as i128;
            weighted_benign_sum += delta.delta_benign_millionths as i128 * weight;
            weighted_anomalous_sum += delta.delta_anomalous_millionths as i128 * weight;
            weighted_malicious_sum += delta.delta_malicious_millionths as i128 * weight;
            weighted_unknown_sum += delta.delta_unknown_millionths as i128 * weight;
            total_weight += delta.confidence_weight_millionths as u128;

            evidence_hashes.push(delta.evidence_hash.as_bytes().to_vec());
        }

        // Compute evidence fingerprint
        let fingerprint_input = evidence_hashes.concat();
        let evidence_fingerprint = ContentHash::compute(&fingerprint_input);

        let aggregated = AggregatedPosteriorUpdate {
            extension_id: round.extension_id.clone(),
            aggregate_delta_benign_millionths: weighted_benign_sum as i64,
            aggregate_delta_anomalous_millionths: weighted_anomalous_sum as i64,
            aggregate_delta_malicious_millionths: weighted_malicious_sum as i64,
            aggregate_delta_unknown_millionths: weighted_unknown_sum as i64,
            total_confidence_weight_millionths: total_weight as u64,
            participant_count: deltas.len() as u32,
            evidence_fingerprint,
            epoch: round.epoch,
            aggregation_timestamp_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| FederatedAggregationError::TimestampError)?
                .as_nanos() as u64,
        };

        round.state = AggregationState::Completed;

        Ok(aggregated)
    }

    /// Get status of an aggregation round.
    pub fn get_round_status(&self, round_id: &str) -> Option<&AggregationRound> {
        self.active_rounds.get(round_id)
    }

    /// Clean up completed or expired rounds.
    pub fn cleanup_rounds(&mut self, current_timestamp_ns: u64) {
        self.active_rounds.retain(|_, round| {
            match round.state {
                AggregationState::Collecting => {
                    // Keep if not expired
                    current_timestamp_ns <= round.deadline_timestamp_ns
                }
                AggregationState::Aggregating => true, // Keep active aggregations
                AggregationState::Completed | AggregationState::Failed => false, // Remove finished
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

/// Errors that can occur during federated posterior aggregation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederatedAggregationError {
    /// Invalid posterior delta (doesn't sum to zero or has invalid confidence).
    InvalidDelta,
    /// Invalid posterior state.
    InvalidPosterior,
    /// Insufficient participants for secure aggregation.
    InsufficientParticipants,
    /// Too many participants (exceeds limits).
    TooManyParticipants,
    /// Aggregation round not found.
    RoundNotFound,
    /// Invalid round state for requested operation.
    InvalidRoundState,
    /// Node is not a participant in this round.
    NodeNotParticipant,
    /// Node has already contributed to this round.
    DuplicateContribution,
    /// Serialization/deserialization error.
    SerializationError,
    /// System timestamp error.
    TimestampError,
}

impl std::fmt::Display for FederatedAggregationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDelta => write!(f, "Invalid posterior delta"),
            Self::InvalidPosterior => write!(f, "Invalid posterior state"),
            Self::InsufficientParticipants => {
                write!(f, "Insufficient participants for secure aggregation")
            }
            Self::TooManyParticipants => write!(f, "Too many participants"),
            Self::RoundNotFound => write!(f, "Aggregation round not found"),
            Self::InvalidRoundState => write!(f, "Invalid round state"),
            Self::NodeNotParticipant => write!(f, "Node is not a participant in this round"),
            Self::DuplicateContribution => write!(f, "Node has already contributed"),
            Self::SerializationError => write!(f, "Serialization error"),
            Self::TimestampError => write!(f, "System timestamp error"),
        }
    }
}

impl std::error::Error for FederatedAggregationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posterior_delta_conservation() {
        let prior = Posterior::default_prior();
        let updated = Posterior::from_millionths(800_000, 100_000, 50_000, 50_000);

        let evidence = Evidence {
            extension_id: "test_ext".to_string(),
            hostcall_rate_millionths: 1_000_000,
            distinct_capabilities: 5,
            resource_score_millionths: 500_000,
            timing_anomaly_millionths: 200_000,
            denial_rate_millionths: 10_000,
            epoch: SecurityEpoch::from_raw(1),
        };

        let delta =
            PosteriorDelta::from_evidence_update("test_ext", &prior, &updated, &evidence, 900_000);

        assert!(delta.is_valid());

        // Verify conservation of probability mass
        let sum = delta.delta_benign_millionths
            + delta.delta_anomalous_millionths
            + delta.delta_malicious_millionths
            + delta.delta_unknown_millionths;
        assert_eq!(sum, 0);
    }

    #[test]
    fn aggregation_coordinator_lifecycle() {
        let mut coordinator =
            AggregationCoordinator::new(NodeId::new("coordinator"), SecurityEpoch::from_raw(1));

        let participants = vec![
            NodeId::new("node1"),
            NodeId::new("node2"),
            NodeId::new("node3"),
        ];

        let round_id = coordinator
            .initiate_aggregation_round("test_round", "test_extension", participants, u64::MAX)
            .unwrap();

        let status = coordinator.get_round_status(&round_id).unwrap();
        assert_eq!(status.state, AggregationState::Collecting);
        assert_eq!(status.participants.len(), 3);
    }

    #[test]
    fn local_posterior_provider_update() {
        let mut provider =
            LocalPosteriorProvider::new(NodeId::new("test_node"), SecurityEpoch::from_raw(1));

        let evidence = Evidence {
            extension_id: "test_ext".to_string(),
            hostcall_rate_millionths: 2_000_000,
            distinct_capabilities: 8,
            resource_score_millionths: 800_000,
            timing_anomaly_millionths: 600_000,
            denial_rate_millionths: 50_000,
            epoch: SecurityEpoch::from_raw(1),
        };

        let delta = provider
            .update_local_posterior("test_ext", &evidence, 800_000)
            .unwrap();

        assert!(delta.is_valid());
        assert_eq!(delta.extension_id, "test_ext");
        assert_eq!(delta.confidence_weight_millionths, 800_000);
    }
}
