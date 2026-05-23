#![forbid(unsafe_code)]
//! Error types for secure aggregation operations

use serde::{Deserialize, Serialize};
use std::fmt;

/// Result type for secure aggregation operations
pub type Result<T> = std::result::Result<T, SecureAggregationError>;

/// Errors that can occur during secure aggregation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecureAggregationError {
    /// Too many participants for this session
    TooManyParticipants,
    /// Not enough participants to start aggregation
    InsufficientParticipants,
    /// Not enough contributions received
    InsufficientContributions,
    /// Operation attempted in wrong round
    InvalidRound,
    /// Invalid vector dimension
    InvalidDimension,
    /// Invalid session state
    InvalidState,
    /// Participant not found
    ParticipantNotFound,
    /// Invalid share format
    InvalidShare,
    /// Cryptographic error
    CryptographicError(String),
    /// Protocol violation
    ProtocolViolation(String),
    /// Network or communication error
    NetworkError(String),
    /// Timeout waiting for participants
    Timeout,
    /// Participant dropped out unexpectedly
    ParticipantDropout(String),
}

impl fmt::Display for SecureAggregationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyParticipants => {
                write!(f, "Too many participants for this aggregation session")
            }
            Self::InsufficientParticipants => {
                write!(f, "Not enough participants to start secure aggregation")
            }
            Self::InsufficientContributions => {
                write!(f, "Not enough contributions received from participants")
            }
            Self::InvalidRound => {
                write!(f, "Operation not valid for current aggregation round")
            }
            Self::InvalidDimension => {
                write!(f, "Vector dimension does not match session configuration")
            }
            Self::InvalidState => {
                write!(f, "Invalid aggregation session state")
            }
            Self::ParticipantNotFound => {
                write!(f, "Participant not found in this session")
            }
            Self::InvalidShare => {
                write!(f, "Invalid secret share format or value")
            }
            Self::CryptographicError(msg) => {
                write!(f, "Cryptographic operation failed: {}", msg)
            }
            Self::ProtocolViolation(msg) => {
                write!(f, "Secure aggregation protocol violation: {}", msg)
            }
            Self::NetworkError(msg) => {
                write!(f, "Network communication error: {}", msg)
            }
            Self::Timeout => {
                write!(f, "Timeout waiting for participant responses")
            }
            Self::ParticipantDropout(participant_id) => {
                write!(
                    f,
                    "Participant {} dropped out during aggregation",
                    participant_id
                )
            }
        }
    }
}

impl std::error::Error for SecureAggregationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        assert_eq!(
            SecureAggregationError::TooManyParticipants.to_string(),
            "Too many participants for this aggregation session"
        );

        assert_eq!(
            SecureAggregationError::InsufficientParticipants.to_string(),
            "Not enough participants to start secure aggregation"
        );

        assert_eq!(
            SecureAggregationError::CryptographicError("test error".into()).to_string(),
            "Cryptographic operation failed: test error"
        );
    }

    #[test]
    fn error_serialization() {
        let error = SecureAggregationError::InvalidDimension;
        let serialized = serde_json::to_string(&error).unwrap();
        let deserialized: SecureAggregationError = serde_json::from_str(&serialized).unwrap();
        assert_eq!(error, deserialized);
    }
}
