#![forbid(unsafe_code)]
//! Participant management for secure aggregation

use crate::{Result, SecureAggregationError};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Unique identifier for a participant in secure aggregation
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ParticipantId(pub String);

impl ParticipantId {
    pub fn new(id: String) -> Self {
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A participant in the secure aggregation protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    /// Unique participant identifier
    pub id: ParticipantId,
    /// Public key for this participant (simplified representation)
    pub public_key: Vec<u8>,
    /// Status of this participant in the current aggregation
    pub status: ParticipantStatus,
    /// Secret shares this participant has generated for others
    pub generated_shares: BTreeMap<ParticipantId, SecretShare>,
    /// Secret shares this participant has received from others
    pub received_shares: BTreeMap<ParticipantId, SecretShare>,
}

/// Status of a participant in the aggregation protocol
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParticipantStatus {
    /// Participant has joined but not yet started
    Joined,
    /// Participant is generating secret shares
    GeneratingShares,
    /// Participant has submitted their shares
    SharesSubmitted,
    /// Participant has submitted their masked contribution
    ContributionSubmitted,
    /// Participant is ready for unmasking phase
    ReadyToUnmask,
    /// Participant has completed their part
    Complete,
    /// Participant has dropped out
    DroppedOut,
}

/// A secret share used for masking contributions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretShare {
    /// The participant this share is intended for
    pub recipient: ParticipantId,
    /// The masked share value (vector of field elements)
    pub share_values: Vec<i64>,
    /// Hash of the share for integrity verification
    pub share_hash: Vec<u8>,
}

impl Participant {
    /// Create a new participant with a generated public key
    pub fn new(id: ParticipantId) -> Self {
        // In a real implementation, this would generate actual cryptographic keys
        let public_key = Self::generate_public_key(&id);

        Self {
            id,
            public_key,
            status: ParticipantStatus::Joined,
            generated_shares: BTreeMap::new(),
            received_shares: BTreeMap::new(),
        }
    }

    /// Generate secret shares for masking contributions
    pub fn generate_secret_shares<R: RngCore + CryptoRng>(
        &mut self,
        other_participants: &[ParticipantId],
        vector_dimension: usize,
        field_modulus: u64,
        rng: &mut R,
    ) -> Result<Vec<SecretShare>> {
        if self.status != ParticipantStatus::Joined {
            return Err(SecureAggregationError::InvalidState);
        }

        self.status = ParticipantStatus::GeneratingShares;

        let mut shares = Vec::new();
        for other_id in other_participants {
            if other_id == &self.id {
                continue; // Don't generate share for self
            }

            let share_values = self.generate_random_share_values(
                vector_dimension,
                field_modulus,
                &other_id.0,
                rng,
            )?;

            let share = SecretShare {
                recipient: other_id.clone(),
                share_values: share_values.clone(),
                share_hash: self.compute_share_hash(&share_values),
            };

            self.generated_shares
                .insert(other_id.clone(), share.clone());
            shares.push(share);
        }

        self.status = ParticipantStatus::SharesSubmitted;
        Ok(shares)
    }

    /// Receive a secret share from another participant
    pub fn receive_secret_share(
        &mut self,
        from_participant: ParticipantId,
        share: SecretShare,
    ) -> Result<()> {
        // Verify the share is intended for this participant
        if share.recipient != self.id {
            return Err(SecureAggregationError::InvalidShare);
        }

        // Verify the share hash
        let computed_hash = self.compute_share_hash(&share.share_values);
        if computed_hash != share.share_hash {
            return Err(SecureAggregationError::InvalidShare);
        }

        self.received_shares.insert(from_participant, share);
        Ok(())
    }

    /// Create a masked contribution using the participant's input and received shares
    pub fn create_masked_contribution(
        &mut self,
        input_vector: Vec<i64>,
        field_modulus: u64,
    ) -> Result<Vec<i64>> {
        if self.status != ParticipantStatus::SharesSubmitted {
            return Err(SecureAggregationError::InvalidState);
        }

        if input_vector.len() != self.get_expected_dimension()? {
            return Err(SecureAggregationError::InvalidDimension);
        }

        // Start with the input vector
        let mut masked_contribution = input_vector;

        // Add all shares this participant has generated for others (positive mask)
        for share in self.generated_shares.values() {
            for (i, &share_val) in share.share_values.iter().enumerate() {
                masked_contribution[i] =
                    (masked_contribution[i] + share_val) % field_modulus as i64;
            }
        }

        // Subtract all shares this participant has received from others (negative mask)
        for share in self.received_shares.values() {
            for (i, &share_val) in share.share_values.iter().enumerate() {
                masked_contribution[i] = (masked_contribution[i] - share_val
                    + field_modulus as i64)
                    % field_modulus as i64;
            }
        }

        self.status = ParticipantStatus::ContributionSubmitted;
        Ok(masked_contribution)
    }

    /// Get the unmasking values for the final aggregation step
    pub fn get_unmasking_values(&mut self) -> Result<Vec<i64>> {
        if self.status != ParticipantStatus::ContributionSubmitted {
            return Err(SecureAggregationError::InvalidState);
        }

        let dimension = self.get_expected_dimension()?;
        let mut unmasking = vec![0i64; dimension];

        // The unmasking values are the sum of all shares this participant generated
        // These will be subtracted from the final aggregate to remove the masks
        for share in self.generated_shares.values() {
            for (i, &share_val) in share.share_values.iter().enumerate() {
                unmasking[i] += share_val;
            }
        }

        self.status = ParticipantStatus::Complete;
        Ok(unmasking)
    }

    /// Get the expected vector dimension based on received shares
    fn get_expected_dimension(&self) -> Result<usize> {
        if let Some(share) = self.generated_shares.values().next() {
            Ok(share.share_values.len())
        } else if let Some(share) = self.received_shares.values().next() {
            Ok(share.share_values.len())
        } else {
            Err(SecureAggregationError::InvalidState)
        }
    }

    /// Generate random share values for masking
    fn generate_random_share_values<R: RngCore + CryptoRng>(
        &self,
        dimension: usize,
        field_modulus: u64,
        recipient_id: &str,
        rng: &mut R,
    ) -> Result<Vec<i64>> {
        let mut share_values = Vec::with_capacity(dimension);

        // Use deterministic randomness based on participant pair for reproducibility
        let mut seed_hasher = Sha256::new();
        seed_hasher.update(self.id.as_str());
        seed_hasher.update(recipient_id);
        let pair_seed = seed_hasher.finalize();

        // Generate random values in the field
        for i in 0..dimension {
            let mut value_hasher = Sha256::new();
            value_hasher.update(&pair_seed);
            value_hasher.update(&(i as u64).to_le_bytes());

            // Add some randomness from the RNG
            let mut random_bytes = [0u8; 8];
            rng.fill_bytes(&mut random_bytes);
            value_hasher.update(&random_bytes);

            let value_hash = value_hasher.finalize();
            let value = u64::from_le_bytes([
                value_hash[0],
                value_hash[1],
                value_hash[2],
                value_hash[3],
                value_hash[4],
                value_hash[5],
                value_hash[6],
                value_hash[7],
            ]) % field_modulus;

            share_values.push(value as i64);
        }

        Ok(share_values)
    }

    /// Compute hash of share values for integrity verification
    fn compute_share_hash(&self, share_values: &[i64]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_str());
        for &value in share_values {
            hasher.update(&value.to_le_bytes());
        }
        hasher.finalize().to_vec()
    }

    /// Generate a simple public key (in practice, use proper cryptographic keys)
    fn generate_public_key(id: &ParticipantId) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update("public_key_for_");
        hasher.update(id.as_str());
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn participant_creation() {
        let participant = Participant::new(ParticipantId("alice".into()));
        assert_eq!(participant.id.as_str(), "alice");
        assert_eq!(participant.status, ParticipantStatus::Joined);
        assert!(participant.generated_shares.is_empty());
        assert!(participant.received_shares.is_empty());
        assert!(!participant.public_key.is_empty());
    }

    #[test]
    fn secret_share_generation() {
        let mut participant = Participant::new(ParticipantId("alice".into()));
        let other_participants = vec![ParticipantId("bob".into()), ParticipantId("charlie".into())];

        let mut rng = thread_rng();
        let shares = participant
            .generate_secret_shares(&other_participants, 5, 1000000, &mut rng)
            .unwrap();

        assert_eq!(shares.len(), 2); // One for bob, one for charlie
        assert_eq!(participant.status, ParticipantStatus::SharesSubmitted);
        assert_eq!(participant.generated_shares.len(), 2);

        // Verify share dimensions
        for share in shares {
            assert_eq!(share.share_values.len(), 5);
            assert!(!share.share_hash.is_empty());
        }
    }

    #[test]
    fn share_exchange() {
        let mut alice = Participant::new(ParticipantId("alice".into()));
        let mut bob = Participant::new(ParticipantId("bob".into()));

        let mut rng = thread_rng();
        let field_modulus = 1000000u64;

        // Alice generates shares for Bob
        let alice_shares = alice
            .generate_secret_shares(&[ParticipantId("bob".into())], 3, field_modulus, &mut rng)
            .unwrap();

        // Bob generates shares for Alice
        let bob_shares = bob
            .generate_secret_shares(&[ParticipantId("alice".into())], 3, field_modulus, &mut rng)
            .unwrap();

        // Exchange shares
        alice
            .receive_secret_share(ParticipantId("bob".into()), bob_shares[0].clone())
            .unwrap();
        bob.receive_secret_share(ParticipantId("alice".into()), alice_shares[0].clone())
            .unwrap();

        assert_eq!(alice.received_shares.len(), 1);
        assert_eq!(bob.received_shares.len(), 1);
    }

    #[test]
    fn masked_contribution_creation() {
        let mut alice = Participant::new(ParticipantId("alice".into()));
        let mut rng = thread_rng();

        // Generate shares first
        alice
            .generate_secret_shares(&[ParticipantId("bob".into())], 3, 1000000, &mut rng)
            .unwrap();

        // Create a dummy received share
        let dummy_share = SecretShare {
            recipient: alice.id.clone(),
            share_values: vec![10, 20, 30],
            share_hash: alice.compute_share_hash(&[10, 20, 30]),
        };
        alice
            .receive_secret_share(ParticipantId("bob".into()), dummy_share)
            .unwrap();

        // Create masked contribution
        let input = vec![100, 200, 300];
        let masked = alice.create_masked_contribution(input, 1000000).unwrap();

        assert_eq!(masked.len(), 3);
        assert_eq!(alice.status, ParticipantStatus::ContributionSubmitted);
    }

    #[test]
    fn unmasking_values() {
        let mut alice = Participant::new(ParticipantId("alice".into()));
        let mut rng = thread_rng();

        // Set up participant to contribution submitted state
        alice
            .generate_secret_shares(&[ParticipantId("bob".into())], 2, 1000000, &mut rng)
            .unwrap();
        alice.status = ParticipantStatus::ContributionSubmitted;

        let unmasking = alice.get_unmasking_values().unwrap();
        assert_eq!(unmasking.len(), 2);
        assert_eq!(alice.status, ParticipantStatus::Complete);
    }
}
