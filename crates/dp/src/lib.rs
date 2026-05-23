#![forbid(unsafe_code)]
//! Secure aggregation primitive implementing Bonawitz et al. 2017
//! "Practical Secure Aggregation for Privacy-Preserving Machine Learning"
//!
//! This crate provides cryptographic secure aggregation where the aggregator
//! can only see the sum of participant contributions, not individual values.

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub mod error;
pub mod participant;
pub mod protocol;

pub use error::{Result, SecureAggregationError};
pub use participant::{Participant, ParticipantId};
pub use protocol::{AggregationProtocol, AggregationRound, MaskedContribution};

/// A secure aggregation session coordinating multiple participants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureAggregationSession {
    /// Unique session identifier
    pub session_id: String,
    /// Set of participant IDs in this session
    pub participants: BTreeMap<ParticipantId, Participant>,
    /// Current round of the protocol
    pub current_round: AggregationRound,
    /// Aggregated result (only available after successful completion)
    pub aggregated_result: Option<Vec<i64>>,
    /// Session configuration parameters
    pub config: AggregationConfig,
}

/// Configuration parameters for secure aggregation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationConfig {
    /// Minimum number of participants required for aggregation
    pub min_participants: usize,
    /// Maximum number of participants allowed
    pub max_participants: usize,
    /// Dimension of the vectors being aggregated
    pub vector_dimension: usize,
    /// Prime modulus for finite field arithmetic (for overflow protection)
    pub field_modulus: u64,
    /// Drop-out threshold: max participants that can drop out
    pub dropout_threshold: usize,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            min_participants: 2,
            max_participants: 100,
            vector_dimension: 1000,
            // Large prime for secure arithmetic
            field_modulus: 2_147_483_647, // 2^31 - 1, Mersenne prime
            dropout_threshold: 1,
        }
    }
}

impl SecureAggregationSession {
    /// Create a new secure aggregation session
    pub fn new(session_id: String, config: AggregationConfig) -> Self {
        Self {
            session_id,
            participants: BTreeMap::new(),
            current_round: AggregationRound::Setup,
            aggregated_result: None,
            config,
        }
    }

    /// Add a participant to the session
    pub fn add_participant(&mut self, participant: Participant) -> Result<()> {
        if self.participants.len() >= self.config.max_participants {
            return Err(SecureAggregationError::TooManyParticipants);
        }

        if self.current_round != AggregationRound::Setup {
            return Err(SecureAggregationError::InvalidRound);
        }

        self.participants
            .insert(participant.id.clone(), participant);
        Ok(())
    }

    /// Start the aggregation protocol
    pub fn start_aggregation<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<(ParticipantId, Vec<u8>)>> {
        if self.participants.len() < self.config.min_participants {
            return Err(SecureAggregationError::InsufficientParticipants);
        }

        self.current_round = AggregationRound::ShareGeneration;

        // Generate share generation seeds for each participant pair
        let participant_ids: Vec<ParticipantId> = self.participants.keys().cloned().collect();
        let mut share_seeds = Vec::new();

        for participant_id in &participant_ids {
            let seed = self.generate_share_seed(participant_id, &participant_ids, rng)?;
            share_seeds.push((participant_id.clone(), seed));
        }

        Ok(share_seeds)
    }

    /// Process masked contributions from participants
    pub fn aggregate_contributions(
        &mut self,
        contributions: Vec<MaskedContribution>,
    ) -> Result<Vec<i64>> {
        if self.current_round != AggregationRound::ContributionSubmission {
            return Err(SecureAggregationError::InvalidRound);
        }

        // Verify we have enough contributions
        if contributions.len() < self.config.min_participants {
            return Err(SecureAggregationError::InsufficientContributions);
        }

        // Validate contribution dimensions
        for contribution in &contributions {
            if contribution.masked_values.len() != self.config.vector_dimension {
                return Err(SecureAggregationError::InvalidDimension);
            }
        }

        // Aggregate the masked values
        let mut aggregated = vec![0i64; self.config.vector_dimension];
        for contribution in &contributions {
            for (i, &value) in contribution.masked_values.iter().enumerate() {
                // Use modular arithmetic to prevent overflow
                aggregated[i] = (aggregated[i] + value) % self.config.field_modulus as i64;
            }
        }

        self.current_round = AggregationRound::Unmasking;
        self.aggregated_result = Some(aggregated.clone());
        Ok(aggregated)
    }

    /// Complete the aggregation by removing the masks
    pub fn complete_aggregation(
        &mut self,
        unmasking_shares: Vec<(ParticipantId, Vec<i64>)>,
    ) -> Result<Vec<i64>> {
        if self.current_round != AggregationRound::Unmasking {
            return Err(SecureAggregationError::InvalidRound);
        }

        let mut result = self
            .aggregated_result
            .clone()
            .ok_or(SecureAggregationError::InvalidState)?;

        // Remove the accumulated masks
        for (_participant_id, mask) in unmasking_shares {
            if mask.len() != self.config.vector_dimension {
                return Err(SecureAggregationError::InvalidDimension);
            }

            for (i, &mask_value) in mask.iter().enumerate() {
                // Subtract the mask (which is the sum of all secret shares for this participant)
                result[i] = (result[i] - mask_value + self.config.field_modulus as i64)
                    % self.config.field_modulus as i64;
            }
        }

        self.current_round = AggregationRound::Complete;
        self.aggregated_result = Some(result.clone());
        Ok(result)
    }

    /// Generate deterministic share seed for a participant
    fn generate_share_seed<R: RngCore + CryptoRng>(
        &self,
        participant_id: &ParticipantId,
        all_participants: &[ParticipantId],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(&self.session_id);
        hasher.update(&participant_id.0);

        // Include all participant IDs for deterministic ordering
        for pid in all_participants {
            hasher.update(&pid.0);
        }

        // Add entropy from RNG for this session
        let mut entropy = [0u8; 32];
        rng.fill_bytes(&mut entropy);
        hasher.update(&entropy);

        Ok(hasher.finalize().to_vec())
    }

    /// Get the current session status
    pub fn status(&self) -> AggregationStatus {
        AggregationStatus {
            session_id: self.session_id.clone(),
            participant_count: self.participants.len(),
            current_round: self.current_round.clone(),
            is_complete: self.current_round == AggregationRound::Complete,
            has_result: self.aggregated_result.is_some(),
        }
    }
}

/// Status information about an aggregation session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationStatus {
    pub session_id: String,
    pub participant_count: usize,
    pub current_round: AggregationRound,
    pub is_complete: bool,
    pub has_result: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn session_creation() {
        let config = AggregationConfig::default();
        let session = SecureAggregationSession::new("test-session".into(), config.clone());

        assert_eq!(session.session_id, "test-session");
        assert_eq!(session.participants.len(), 0);
        assert_eq!(session.current_round, AggregationRound::Setup);
        assert!(session.aggregated_result.is_none());
        assert_eq!(session.config.min_participants, config.min_participants);
    }

    #[test]
    fn add_participants() {
        let config = AggregationConfig::default();
        let mut session = SecureAggregationSession::new("test-session".into(), config);

        let participant1 = Participant::new(ParticipantId("alice".into()));
        let participant2 = Participant::new(ParticipantId("bob".into()));

        assert!(session.add_participant(participant1).is_ok());
        assert!(session.add_participant(participant2).is_ok());
        assert_eq!(session.participants.len(), 2);
    }

    #[test]
    fn participant_limit_enforcement() {
        let mut config = AggregationConfig::default();
        config.max_participants = 1;

        let mut session = SecureAggregationSession::new("test-session".into(), config);

        let participant1 = Participant::new(ParticipantId("alice".into()));
        let participant2 = Participant::new(ParticipantId("bob".into()));

        assert!(session.add_participant(participant1).is_ok());
        assert!(session.add_participant(participant2).is_err());
    }

    #[test]
    fn aggregation_workflow() {
        let mut config = AggregationConfig::default();
        config.min_participants = 2;
        config.max_participants = 3;
        config.vector_dimension = 5;

        let mut session = SecureAggregationSession::new("test-session".into(), config);
        let mut rng = thread_rng();

        // Add participants
        let participant1 = Participant::new(ParticipantId("alice".into()));
        let participant2 = Participant::new(ParticipantId("bob".into()));
        session.add_participant(participant1).unwrap();
        session.add_participant(participant2).unwrap();

        // Start aggregation
        let share_seeds = session.start_aggregation(&mut rng).unwrap();
        assert_eq!(share_seeds.len(), 2);
        assert_eq!(session.current_round, AggregationRound::ShareGeneration);

        // Simulate masked contributions
        session.current_round = AggregationRound::ContributionSubmission;
        let masked_contributions = vec![
            MaskedContribution {
                participant_id: ParticipantId("alice".into()),
                masked_values: vec![10, 20, 30, 40, 50],
                contribution_hash: vec![0; 32],
            },
            MaskedContribution {
                participant_id: ParticipantId("bob".into()),
                masked_values: vec![5, 15, 25, 35, 45],
                contribution_hash: vec![1; 32],
            },
        ];

        let aggregated = session
            .aggregate_contributions(masked_contributions)
            .unwrap();
        assert_eq!(aggregated, vec![15, 35, 55, 75, 95]);
        assert_eq!(session.current_round, AggregationRound::Unmasking);

        // Simulate unmasking (in practice, these would be computed from secret shares)
        let unmasking_shares = vec![
            (ParticipantId("alice".into()), vec![0, 0, 0, 0, 0]), // No mask for simplicity
            (ParticipantId("bob".into()), vec![0, 0, 0, 0, 0]),   // No mask for simplicity
        ];

        let final_result = session.complete_aggregation(unmasking_shares).unwrap();
        assert_eq!(final_result, vec![15, 35, 55, 75, 95]);
        assert_eq!(session.current_round, AggregationRound::Complete);
    }

    #[test]
    fn insufficient_participants() {
        let config = AggregationConfig::default();
        let mut session = SecureAggregationSession::new("test-session".into(), config);
        let mut rng = thread_rng();

        // Add only one participant when minimum is 2
        let participant = Participant::new(ParticipantId("alice".into()));
        session.add_participant(participant).unwrap();

        let result = session.start_aggregation(&mut rng);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SecureAggregationError::InsufficientParticipants
        ));
    }

    #[test]
    fn status_tracking() {
        let config = AggregationConfig::default();
        let session = SecureAggregationSession::new("test-session".into(), config);

        let status = session.status();
        assert_eq!(status.session_id, "test-session");
        assert_eq!(status.participant_count, 0);
        assert_eq!(status.current_round, AggregationRound::Setup);
        assert!(!status.is_complete);
        assert!(!status.has_result);
    }
}
