#![forbid(unsafe_code)]
//! Core protocol implementation for secure aggregation

use crate::{participant::ParticipantId, Result, SecureAggregationError};
use serde::{Deserialize, Serialize};

/// Phases of the secure aggregation protocol
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregationRound {
    /// Initial setup phase
    Setup,
    /// Participants generate and exchange secret shares
    ShareGeneration,
    /// Participants submit their masked contributions
    ContributionSubmission,
    /// Unmasking phase to reveal the aggregate
    Unmasking,
    /// Protocol completed successfully
    Complete,
    /// Protocol aborted due to error
    Aborted,
}

/// A masked contribution from a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskedContribution {
    /// The participant submitting this contribution
    pub participant_id: ParticipantId,
    /// The masked values (original input + noise from secret shares)
    pub masked_values: Vec<i64>,
    /// Hash of the original contribution for verification
    pub contribution_hash: Vec<u8>,
}

impl MaskedContribution {
    /// Create a new masked contribution
    pub fn new(
        participant_id: ParticipantId,
        masked_values: Vec<i64>,
        contribution_hash: Vec<u8>,
    ) -> Self {
        Self {
            participant_id,
            masked_values,
            contribution_hash,
        }
    }

    /// Verify the contribution has the expected dimension
    pub fn verify_dimension(&self, expected_dimension: usize) -> Result<()> {
        if self.masked_values.len() != expected_dimension {
            return Err(SecureAggregationError::InvalidDimension);
        }
        Ok(())
    }

    /// Check if values are within the expected field modulus
    pub fn verify_field_bounds(&self, field_modulus: u64) -> Result<()> {
        for &value in &self.masked_values {
            if value < 0 || value >= field_modulus as i64 {
                return Err(SecureAggregationError::ProtocolViolation(
                    "Contribution values outside field bounds".into(),
                ));
            }
        }
        Ok(())
    }
}

/// The main aggregation protocol coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationProtocol {
    /// Protocol version for compatibility
    pub version: String,
    /// Current protocol round
    pub current_round: AggregationRound,
    /// Security parameters
    pub security_params: SecurityParameters,
}

/// Security parameters for the aggregation protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityParameters {
    /// Field modulus for arithmetic operations
    pub field_modulus: u64,
    /// Minimum number of participants required
    pub min_participants: usize,
    /// Maximum dropout tolerance
    pub dropout_threshold: usize,
    /// Vector dimension being aggregated
    pub vector_dimension: usize,
}

impl Default for SecurityParameters {
    fn default() -> Self {
        Self {
            field_modulus: 2_147_483_647, // 2^31 - 1
            min_participants: 2,
            dropout_threshold: 1,
            vector_dimension: 1000,
        }
    }
}

impl AggregationProtocol {
    /// Create a new aggregation protocol instance
    pub fn new(security_params: SecurityParameters) -> Self {
        Self {
            version: "1.0".into(),
            current_round: AggregationRound::Setup,
            security_params,
        }
    }

    /// Validate a set of masked contributions
    pub fn validate_contributions(&self, contributions: &[MaskedContribution]) -> Result<()> {
        if contributions.len() < self.security_params.min_participants {
            return Err(SecureAggregationError::InsufficientContributions);
        }

        for contribution in contributions {
            contribution.verify_dimension(self.security_params.vector_dimension)?;
            contribution.verify_field_bounds(self.security_params.field_modulus)?;
        }

        Ok(())
    }

    /// Perform the aggregation of masked contributions
    pub fn aggregate_masked_contributions(
        &self,
        contributions: Vec<MaskedContribution>,
    ) -> Result<Vec<i64>> {
        self.validate_contributions(&contributions)?;

        let mut aggregated = vec![0i64; self.security_params.vector_dimension];

        for contribution in contributions {
            for (i, &value) in contribution.masked_values.iter().enumerate() {
                aggregated[i] = (aggregated[i] + value) % self.security_params.field_modulus as i64;
            }
        }

        Ok(aggregated)
    }

    /// Apply unmasking to reveal the final aggregate
    pub fn apply_unmasking(
        &self,
        masked_aggregate: Vec<i64>,
        unmasking_values: Vec<Vec<i64>>,
    ) -> Result<Vec<i64>> {
        if masked_aggregate.len() != self.security_params.vector_dimension {
            return Err(SecureAggregationError::InvalidDimension);
        }

        let mut result = masked_aggregate;

        for unmasking in unmasking_values {
            if unmasking.len() != self.security_params.vector_dimension {
                return Err(SecureAggregationError::InvalidDimension);
            }

            for (i, &unmask_value) in unmasking.iter().enumerate() {
                result[i] = (result[i] - unmask_value + self.security_params.field_modulus as i64)
                    % self.security_params.field_modulus as i64;
            }
        }

        Ok(result)
    }

    /// Check if the protocol can handle participant dropout
    pub fn can_handle_dropouts(&self, active_participants: usize) -> bool {
        let max_dropouts =
            active_participants.saturating_sub(self.security_params.min_participants);
        max_dropouts <= self.security_params.dropout_threshold
    }

    /// Transition to the next round of the protocol
    pub fn advance_round(&mut self) -> Result<AggregationRound> {
        self.current_round = match self.current_round {
            AggregationRound::Setup => AggregationRound::ShareGeneration,
            AggregationRound::ShareGeneration => AggregationRound::ContributionSubmission,
            AggregationRound::ContributionSubmission => AggregationRound::Unmasking,
            AggregationRound::Unmasking => AggregationRound::Complete,
            AggregationRound::Complete => {
                return Err(SecureAggregationError::InvalidRound);
            }
            AggregationRound::Aborted => {
                return Err(SecureAggregationError::InvalidRound);
            }
        };

        Ok(self.current_round.clone())
    }

    /// Abort the protocol due to error or dropout
    pub fn abort_protocol(&mut self, reason: String) -> SecureAggregationError {
        self.current_round = AggregationRound::Aborted;
        SecureAggregationError::ProtocolViolation(reason)
    }
}

/// Protocol message types for communication between participants and aggregator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolMessage {
    /// Setup message to initialize aggregation
    Setup {
        session_id: String,
        security_params: SecurityParameters,
        participants: Vec<ParticipantId>,
    },
    /// Share generation request
    ShareGenerationRequest {
        session_id: String,
        participant_id: ParticipantId,
        other_participants: Vec<ParticipantId>,
    },
    /// Share generation response
    ShareGenerationResponse {
        session_id: String,
        from_participant: ParticipantId,
        to_participant: ParticipantId,
        share_data: Vec<u8>,
    },
    /// Masked contribution submission
    ContributionSubmission {
        session_id: String,
        contribution: MaskedContribution,
    },
    /// Request for unmasking values
    UnmaskingRequest {
        session_id: String,
        participant_id: ParticipantId,
    },
    /// Unmasking response
    UnmaskingResponse {
        session_id: String,
        participant_id: ParticipantId,
        unmasking_values: Vec<i64>,
    },
    /// Final aggregation result
    AggregationResult {
        session_id: String,
        aggregated_values: Vec<i64>,
        participating_ids: Vec<ParticipantId>,
    },
    /// Error message
    Error {
        session_id: String,
        error: SecureAggregationError,
    },
}

impl ProtocolMessage {
    /// Extract the session ID from any protocol message
    pub fn session_id(&self) -> &str {
        match self {
            Self::Setup { session_id, .. } => session_id,
            Self::ShareGenerationRequest { session_id, .. } => session_id,
            Self::ShareGenerationResponse { session_id, .. } => session_id,
            Self::ContributionSubmission { session_id, .. } => session_id,
            Self::UnmaskingRequest { session_id, .. } => session_id,
            Self::UnmaskingResponse { session_id, .. } => session_id,
            Self::AggregationResult { session_id, .. } => session_id,
            Self::Error { session_id, .. } => session_id,
        }
    }

    /// Check if this message is appropriate for the current protocol round
    pub fn is_valid_for_round(&self, round: &AggregationRound) -> bool {
        match (self, round) {
            (Self::Setup { .. }, AggregationRound::Setup) => true,
            (Self::ShareGenerationRequest { .. }, AggregationRound::ShareGeneration) => true,
            (Self::ShareGenerationResponse { .. }, AggregationRound::ShareGeneration) => true,
            (Self::ContributionSubmission { .. }, AggregationRound::ContributionSubmission) => true,
            (Self::UnmaskingRequest { .. }, AggregationRound::Unmasking) => true,
            (Self::UnmaskingResponse { .. }, AggregationRound::Unmasking) => true,
            (Self::AggregationResult { .. }, AggregationRound::Complete) => true,
            (Self::Error { .. }, _) => true, // Errors can occur in any round
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_creation() {
        let params = SecurityParameters::default();
        let protocol = AggregationProtocol::new(params.clone());

        assert_eq!(protocol.version, "1.0");
        assert_eq!(protocol.current_round, AggregationRound::Setup);
        assert_eq!(protocol.security_params.field_modulus, params.field_modulus);
    }

    #[test]
    fn contribution_validation() {
        let params = SecurityParameters {
            min_participants: 2,
            vector_dimension: 3,
            field_modulus: 1000,
            dropout_threshold: 1,
        };
        let protocol = AggregationProtocol::new(params);

        let contributions = vec![
            MaskedContribution::new(
                ParticipantId("alice".into()),
                vec![100, 200, 300],
                vec![0; 32],
            ),
            MaskedContribution::new(
                ParticipantId("bob".into()),
                vec![150, 250, 350],
                vec![1; 32],
            ),
        ];

        assert!(protocol.validate_contributions(&contributions).is_ok());

        // Test insufficient participants
        let insufficient = vec![contributions[0].clone()];
        assert!(protocol.validate_contributions(&insufficient).is_err());
    }

    #[test]
    fn aggregation_computation() {
        let params = SecurityParameters {
            min_participants: 2,
            vector_dimension: 3,
            field_modulus: 1000,
            dropout_threshold: 1,
        };
        let protocol = AggregationProtocol::new(params);

        let contributions = vec![
            MaskedContribution::new(
                ParticipantId("alice".into()),
                vec![100, 200, 300],
                vec![0; 32],
            ),
            MaskedContribution::new(
                ParticipantId("bob".into()),
                vec![150, 250, 350],
                vec![1; 32],
            ),
        ];

        let result = protocol
            .aggregate_masked_contributions(contributions)
            .unwrap();
        assert_eq!(result, vec![250, 450, 650]);
    }

    #[test]
    fn unmasking_application() {
        let params = SecurityParameters {
            min_participants: 2,
            vector_dimension: 3,
            field_modulus: 1000,
            dropout_threshold: 1,
        };
        let protocol = AggregationProtocol::new(params);

        let masked_aggregate = vec![250, 450, 650];
        let unmasking_values = vec![
            vec![50, 100, 150], // Alice's unmasking
            vec![25, 75, 125],  // Bob's unmasking
        ];

        let result = protocol
            .apply_unmasking(masked_aggregate, unmasking_values)
            .unwrap();

        // 250 - 50 - 25 = 175, etc.
        assert_eq!(result, vec![175, 275, 375]);
    }

    #[test]
    fn round_advancement() {
        let params = SecurityParameters::default();
        let mut protocol = AggregationProtocol::new(params);

        assert_eq!(protocol.current_round, AggregationRound::Setup);

        assert_eq!(
            protocol.advance_round().unwrap(),
            AggregationRound::ShareGeneration
        );
        assert_eq!(
            protocol.advance_round().unwrap(),
            AggregationRound::ContributionSubmission
        );
        assert_eq!(
            protocol.advance_round().unwrap(),
            AggregationRound::Unmasking
        );
        assert_eq!(
            protocol.advance_round().unwrap(),
            AggregationRound::Complete
        );

        // Should not be able to advance beyond complete
        assert!(protocol.advance_round().is_err());
    }

    #[test]
    fn dropout_handling() {
        let params = SecurityParameters {
            min_participants: 3,
            dropout_threshold: 2,
            ..Default::default()
        };
        let protocol = AggregationProtocol::new(params);

        // 5 active participants, min 3, dropout threshold 2
        // Can handle up to 2 dropouts (5 - 3 = 2)
        assert!(protocol.can_handle_dropouts(5));

        // 4 active participants, can handle 1 dropout (4 - 3 = 1 ≤ 2)
        assert!(protocol.can_handle_dropouts(4));

        // 3 active participants, can handle 0 dropouts (3 - 3 = 0 ≤ 2)
        assert!(protocol.can_handle_dropouts(3));

        // 2 active participants, cannot maintain minimum
        assert!(!protocol.can_handle_dropouts(2));
    }

    #[test]
    fn protocol_message_validation() {
        let setup_msg = ProtocolMessage::Setup {
            session_id: "test".into(),
            security_params: SecurityParameters::default(),
            participants: vec![],
        };

        assert!(setup_msg.is_valid_for_round(&AggregationRound::Setup));
        assert!(!setup_msg.is_valid_for_round(&AggregationRound::ShareGeneration));

        assert_eq!(setup_msg.session_id(), "test");
    }
}
