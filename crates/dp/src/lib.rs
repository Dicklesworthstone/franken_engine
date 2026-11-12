#![forbid(unsafe_code)]
//! Secure aggregation (Bonawitz et al. 2017 pairwise-cancelling masks) and
//! discrete differential-privacy mechanisms (`DiscreteLaplace`, `DiscreteGaussian`).
//!
//! Legacy [`Participant::get_unmasking_values`] is retained only for arithmetic
//! compatibility tests; production callers MUST use [`PairwiseMaskParticipant`]
//! and [`SecureAggregationSession::complete_pairwise_aggregation`], which cancel
//! survivor-to-survivor masks without disclosing any participant's net mask to
//! the coordinator.

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
        if self.config.field_modulus == 0 || self.config.field_modulus > i64::MAX as u64 {
            return Err(SecureAggregationError::ProtocolViolation(
                "Field modulus must fit a positive signed representation".into(),
            ));
        }

        // Verify we have enough contributions
        if contributions.len() < self.config.min_participants {
            return Err(SecureAggregationError::InsufficientContributions);
        }

        // Validate every contribution before changing the session state.
        for contribution in &contributions {
            contribution.verify_dimension(self.config.vector_dimension)?;
            contribution.verify_field_bounds(self.config.field_modulus)?;
        }

        // Aggregate the masked values
        let mut aggregated = vec![0i64; self.config.vector_dimension];
        for contribution in &contributions {
            for (i, &value) in contribution.masked_values.iter().enumerate() {
                // Widen before adding; reduction after i64 addition is too late.
                aggregated[i] = (i128::from(aggregated[i]) + i128::from(value))
                    .rem_euclid(i128::from(self.config.field_modulus))
                    as i64;
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
        if self.config.field_modulus == 0 || self.config.field_modulus > i64::MAX as u64 {
            return Err(SecureAggregationError::ProtocolViolation(
                "Field modulus must fit a positive signed representation".into(),
            ));
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
                // Remove the participant's generated-minus-received net mask.
                result[i] = (i128::from(result[i]) - i128::from(mask_value))
                    .rem_euclid(i128::from(self.config.field_modulus))
                    as i64;
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
        hasher.update(entropy);

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

/// Pairwise seed revealed by a surviving participant ONLY for a peer that
/// dropped out before submitting its masked contribution (`[RC-C2]` / `g2vrp.9`).
/// Survivor-to-survivor seeds are never disclosed to the coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DropoutPairwiseSeed {
    pub survivor: ParticipantId,
    pub dropped_peer: ParticipantId,
    pub shared_seed: [u8; 32],
}

/// Deterministically expand a 32-byte pairwise shared secret into an unbiased
/// vector of `dimension` elements in `0..field_modulus` via domain-separated
/// SHA-256 counter-mode rejection sampling.
pub fn expand_pairwise_mask(
    session_id: &str,
    first: &ParticipantId,
    second: &ParticipantId,
    shared_seed: &[u8; 32],
    dimension: usize,
    field_modulus: u64,
) -> Result<Vec<i64>> {
    if field_modulus == 0 || field_modulus > i64::MAX as u64 {
        return Err(SecureAggregationError::ProtocolViolation(
            "Field modulus must fit a positive signed representation".into(),
        ));
    }
    let (low, high) = if first <= second {
        (first.as_str(), second.as_str())
    } else {
        (second.as_str(), first.as_str())
    };
    let reject_ceiling = u64::MAX - (u64::MAX % field_modulus);
    let mut out = Vec::with_capacity(dimension);
    for coord in 0..dimension {
        let mut counter = 0u64;
        let sample = loop {
            let mut hasher = Sha256::new();
            hasher.update(b"franken-dp.pairwise-prg.v1\0");
            hasher.update((session_id.len() as u64).to_le_bytes());
            hasher.update(session_id.as_bytes());
            hasher.update((low.len() as u64).to_le_bytes());
            hasher.update(low.as_bytes());
            hasher.update((high.len() as u64).to_le_bytes());
            hasher.update(high.as_bytes());
            hasher.update(shared_seed);
            hasher.update((coord as u64).to_le_bytes());
            hasher.update(counter.to_le_bytes());
            let digest = hasher.finalize();
            let candidate = u64::from_le_bytes([
                digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6],
                digest[7],
            ]);
            if candidate < reject_ceiling {
                break (candidate % field_modulus) as i64;
            }
            counter = counter.saturating_add(1);
        };
        out.push(sample);
    }
    Ok(out)
}

/// Participant using Bonawitz et al. 2017 anti-symmetric pairwise PRG masks so
/// surviving peers cancel to 0 in the aggregate sum without disclosing per-user
/// masks to the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairwiseMaskParticipant {
    pub id: ParticipantId,
    pairwise_seeds: BTreeMap<ParticipantId, [u8; 32]>,
    submitted: bool,
}

impl PairwiseMaskParticipant {
    pub fn new(id: ParticipantId) -> Self {
        Self {
            id,
            pairwise_seeds: BTreeMap::new(),
            submitted: false,
        }
    }

    /// Establish a symmetric pairwise seed between `a` and `b`.
    pub fn establish_shared_seed<R: RngCore + CryptoRng>(
        a: &mut Self,
        b: &mut Self,
        rng: &mut R,
    ) -> Result<()> {
        if a.id == b.id {
            return Err(SecureAggregationError::ProtocolViolation(
                "Cannot establish pairwise mask seed with self".into(),
            ));
        }
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        a.pairwise_seeds.insert(b.id.clone(), seed);
        b.pairwise_seeds.insert(a.id.clone(), seed);
        Ok(())
    }

    /// Mask `input_vector` as `x_u + sum_{v > u} PRG(k_{u,v}) - sum_{v < u} PRG(k_{v,u}) mod p`.
    pub fn create_masked_contribution(
        &mut self,
        session_id: &str,
        input_vector: &[i64],
        field_modulus: u64,
    ) -> Result<MaskedContribution> {
        if self.submitted {
            return Err(SecureAggregationError::InvalidState);
        }
        if self.pairwise_seeds.is_empty() {
            return Err(SecureAggregationError::InsufficientParticipants);
        }
        if field_modulus == 0 || field_modulus > i64::MAX as u64 {
            return Err(SecureAggregationError::ProtocolViolation(
                "Field modulus must fit a positive signed representation".into(),
            ));
        }
        let modulus = i128::from(field_modulus);
        let dimension = input_vector.len();
        let mut masked: Vec<i64> = input_vector
            .iter()
            .map(|&v| i128::from(v).rem_euclid(modulus) as i64)
            .collect();

        for (peer_id, seed) in &self.pairwise_seeds {
            let prg = expand_pairwise_mask(
                session_id,
                &self.id,
                peer_id,
                seed,
                dimension,
                field_modulus,
            )?;
            let sign: i128 = if &self.id < peer_id { 1 } else { -1 };
            for (slot, &mask_val) in masked.iter_mut().zip(prg.iter()) {
                *slot =
                    (i128::from(*slot) + sign * i128::from(mask_val)).rem_euclid(modulus) as i64;
            }
        }

        let mut commit_hasher = Sha256::new();
        commit_hasher.update(b"franken-dp.masked-contribution.v1\0");
        commit_hasher.update(self.id.as_str().as_bytes());
        for &val in &masked {
            commit_hasher.update(val.to_le_bytes());
        }
        self.submitted = true;
        Ok(MaskedContribution::new(
            self.id.clone(),
            masked,
            commit_hasher.finalize().to_vec(),
        ))
    }

    /// Reveal pairwise seeds ONLY for peers absent from `survivors`. Refuses to
    /// reveal any seed shared with another surviving participant.
    pub fn reveal_dropout_seeds(
        &self,
        survivors: &[ParticipantId],
    ) -> Result<Vec<DropoutPairwiseSeed>> {
        if !self.submitted {
            return Err(SecureAggregationError::InvalidState);
        }
        if !survivors.contains(&self.id) {
            return Err(SecureAggregationError::ProtocolViolation(
                "Non-surviving participant cannot emit survivor dropout shares".into(),
            ));
        }
        if survivors.len() < 2 {
            return Err(SecureAggregationError::InsufficientParticipants);
        }
        let mut revealed = Vec::new();
        for (peer_id, seed) in &self.pairwise_seeds {
            if !survivors.contains(peer_id) {
                revealed.push(DropoutPairwiseSeed {
                    survivor: self.id.clone(),
                    dropped_peer: peer_id.clone(),
                    shared_seed: *seed,
                });
            }
        }
        Ok(revealed)
    }
}

impl SecureAggregationSession {
    /// Complete aggregation using zero-disclosure pairwise cancellation:
    /// survivor-to-survivor masks cancel automatically in `aggregated_result`,
    /// and only `dropout_seeds` for non-surviving participants are removed.
    pub fn complete_pairwise_aggregation(
        &mut self,
        expected_roster: &[ParticipantId],
        survivors: &[ParticipantId],
        dropout_seeds: &[DropoutPairwiseSeed],
    ) -> Result<Vec<i64>> {
        if self.current_round != AggregationRound::Unmasking {
            return Err(SecureAggregationError::InvalidRound);
        }
        if self.config.field_modulus == 0 || self.config.field_modulus > i64::MAX as u64 {
            return Err(SecureAggregationError::ProtocolViolation(
                "Field modulus must fit a positive signed representation".into(),
            ));
        }
        if survivors.len() < self.config.min_participants {
            return Err(SecureAggregationError::InsufficientParticipants);
        }
        let dropped: Vec<ParticipantId> = expected_roster
            .iter()
            .filter(|pid| !survivors.contains(pid))
            .cloned()
            .collect();
        if dropped.len() > self.config.dropout_threshold {
            return Err(SecureAggregationError::ProtocolViolation(
                "Dropped participants exceed configured dropout_threshold".into(),
            ));
        }

        let mut seed_lookup = BTreeMap::new();
        for item in dropout_seeds {
            if !survivors.contains(&item.survivor) || survivors.contains(&item.dropped_peer) {
                return Err(SecureAggregationError::ProtocolViolation(
                    "Invalid dropout seed disclosure (must be survivor -> dropped_peer only)"
                        .into(),
                ));
            }
            seed_lookup.insert(
                (item.survivor.clone(), item.dropped_peer.clone()),
                item.shared_seed,
            );
        }

        let modulus = i128::from(self.config.field_modulus);
        let mut result = self
            .aggregated_result
            .clone()
            .ok_or(SecureAggregationError::InvalidState)?;

        for survivor in survivors {
            for dropped_peer in &dropped {
                let seed = seed_lookup
                    .get(&(survivor.clone(), dropped_peer.clone()))
                    .ok_or_else(|| {
                        SecureAggregationError::ProtocolViolation(format!(
                            "Missing dropout seed from {} for dropped peer {}",
                            survivor.as_str(),
                            dropped_peer.as_str()
                        ))
                    })?;
                let prg = expand_pairwise_mask(
                    &self.session_id,
                    survivor,
                    dropped_peer,
                    seed,
                    self.config.vector_dimension,
                    self.config.field_modulus,
                )?;
                let sign: i128 = if survivor < dropped_peer { 1 } else { -1 };
                for (slot, &mask_val) in result.iter_mut().zip(prg.iter()) {
                    *slot = (i128::from(*slot) - sign * i128::from(mask_val)).rem_euclid(modulus)
                        as i64;
                }
            }
        }

        self.current_round = AggregationRound::Complete;
        self.aggregated_result = Some(result.clone());
        Ok(result)
    }
}

fn uniform_open01<R: RngCore + CryptoRng>(rng: &mut R) -> f64 {
    // 53-bit dyadic rational strictly in (0, 1) so ln(u) is always finite.
    let raw = (rng.next_u64() >> 11) as f64;
    (raw + 0.5) * (1.0 / ((1u64 << 53) as f64))
}

fn sample_geometric_zero_based<R: RngCore + CryptoRng>(alpha: f64, rng: &mut R) -> Result<i64> {
    if !alpha.is_finite() || alpha <= 0.0 {
        return Err(SecureAggregationError::ProtocolViolation(
            "Discrete DP scale parameter alpha = epsilon / sensitivity must be finite and > 0"
                .into(),
        ));
    }
    let u = uniform_open01(rng);
    // For P[G >= k] = exp(-alpha * k), floor(-ln(u) / alpha) is exact geometric.
    let draw = (-u.ln() / alpha).floor();
    if !draw.is_finite() || draw < 0.0 || draw > (i64::MAX as f64) {
        return Err(SecureAggregationError::ProtocolViolation(
            "Discrete Laplace geometric sample overflowed i64".into(),
        ));
    }
    Ok(draw as i64)
}

/// Sample pure `(epsilon, 0)`-differentially private integer noise from the
/// symmetric Discrete Laplace (`DLap(epsilon / l1_sensitivity)`) distribution
/// via the difference of two i.i.d. geometric variables.
pub fn sample_discrete_laplace<R: RngCore + CryptoRng>(
    epsilon: f64,
    l1_sensitivity: u64,
    rng: &mut R,
) -> Result<i64> {
    if !epsilon.is_finite() || epsilon <= 0.0 || l1_sensitivity == 0 {
        return Err(SecureAggregationError::ProtocolViolation(
            "Discrete Laplace requires finite epsilon > 0 and l1_sensitivity >= 1".into(),
        ));
    }
    let alpha = epsilon / (l1_sensitivity as f64);
    let g1 = sample_geometric_zero_based(alpha, rng)?;
    let g2 = sample_geometric_zero_based(alpha, rng)?;
    Ok(g1 - g2)
}

/// Add independent `DLap(epsilon / l1_sensitivity)` noise to each coordinate
/// (mod `field_modulus` if `Some(modulus)` is provided, or signed integer sum
/// when `field_modulus` is `None`).
pub fn privatize_vector_discrete_laplace<R: RngCore + CryptoRng>(
    values: &[i64],
    epsilon: f64,
    l1_sensitivity: u64,
    field_modulus: Option<u64>,
    rng: &mut R,
) -> Result<Vec<i64>> {
    if let Some(m) = field_modulus
        && (m == 0 || m > i64::MAX as u64)
    {
        return Err(SecureAggregationError::ProtocolViolation(
            "Field modulus must fit a positive signed representation".into(),
        ));
    }
    let mut out = Vec::with_capacity(values.len());
    for &v in values {
        let noise = sample_discrete_laplace(epsilon, l1_sensitivity, rng)?;
        let noisy = match field_modulus {
            Some(m) => (i128::from(v) + i128::from(noise)).rem_euclid(i128::from(m)) as i64,
            None => v.saturating_add(noise),
        };
        out.push(noisy);
    }
    Ok(out)
}

/// Sample integer noise from the Discrete Gaussian `N_Z(0, sigma^2)` via
/// Canonne-Kamath-Steinke rejection sampling against a Discrete Laplace
/// envelope (`rho = l2_sensitivity^2 / (2 * sigma^2)`-zCDP).
pub fn sample_discrete_gaussian<R: RngCore + CryptoRng>(sigma: f64, rng: &mut R) -> Result<i64> {
    if !sigma.is_finite() || sigma <= 0.0 {
        return Err(SecureAggregationError::ProtocolViolation(
            "Discrete Gaussian requires finite sigma > 0".into(),
        ));
    }
    let t = sigma.floor() + 1.0;
    let alpha = 1.0 / t;
    let two_sigma_sq = 2.0 * sigma * sigma;
    loop {
        let y = sample_discrete_laplace(alpha, 1, rng)?;
        let diff = (y.unsigned_abs() as f64) - (sigma * sigma / t);
        let log_accept = -(diff * diff) / two_sigma_sq;
        let u = uniform_open01(rng);
        if u.ln() <= log_accept {
            return Ok(y);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn signed_net_masks_unmask_without_overflow_or_negative_residues() {
        let modulus = (1u64 << 61) - 1;
        let mut session = SecureAggregationSession::new(
            "signed-unmasking".into(),
            AggregationConfig {
                min_participants: 2,
                vector_dimension: 2,
                field_modulus: modulus,
                ..AggregationConfig::default()
            },
        );
        let alice = ParticipantId("alice".into());
        let bob = ParticipantId("bob".into());
        session
            .add_participant(Participant::new(alice.clone()))
            .unwrap();
        session
            .add_participant(Participant::new(bob.clone()))
            .unwrap();
        session.start_aggregation(&mut thread_rng()).unwrap();
        session.current_round = AggregationRound::ContributionSubmission;
        session
            .aggregate_contributions(vec![
                MaskedContribution::new(alice.clone(), vec![4, 8], Vec::new()),
                MaskedContribution::new(bob, vec![6, 12], Vec::new()),
            ])
            .unwrap();
        let three_moduli = 3 * modulus as i64;
        assert_eq!(
            session
                .complete_aggregation(vec![(alice, vec![-three_moduli + 1, three_moduli - 1]),])
                .unwrap(),
            vec![9, 21]
        );
        assert_eq!(session.current_round, AggregationRound::Complete);
    }

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
        let config = AggregationConfig {
            max_participants: 1,
            ..AggregationConfig::default()
        };

        let mut session = SecureAggregationSession::new("test-session".into(), config);

        let participant1 = Participant::new(ParticipantId("alice".into()));
        let participant2 = Participant::new(ParticipantId("bob".into()));

        assert!(session.add_participant(participant1).is_ok());
        assert!(session.add_participant(participant2).is_err());
    }

    #[test]
    fn aggregation_workflow() {
        let config = AggregationConfig {
            min_participants: 2,
            max_participants: 3,
            vector_dimension: 5,
            ..AggregationConfig::default()
        };

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

    #[test]
    fn pairwise_masks_cancel_with_zero_disclosure_and_survive_dropout() {
        let modulus = 2_147_483_647u64;
        let mut rng = thread_rng();

        let alice_id = ParticipantId::new("alice".into());
        let bob_id = ParticipantId::new("bob".into());
        let carol_id = ParticipantId::new("carol".into());
        let roster = vec![alice_id.clone(), bob_id.clone(), carol_id.clone()];

        let mut alice = PairwiseMaskParticipant::new(alice_id.clone());
        let mut bob = PairwiseMaskParticipant::new(bob_id.clone());
        let mut carol = PairwiseMaskParticipant::new(carol_id.clone());
        PairwiseMaskParticipant::establish_shared_seed(&mut alice, &mut bob, &mut rng).unwrap();
        PairwiseMaskParticipant::establish_shared_seed(&mut alice, &mut carol, &mut rng).unwrap();
        PairwiseMaskParticipant::establish_shared_seed(&mut bob, &mut carol, &mut rng).unwrap();

        let c_alice = alice
            .create_masked_contribution("secagg-zero-disc", &[100, 200, 300], modulus)
            .unwrap();
        let c_bob = bob
            .create_masked_contribution("secagg-zero-disc", &[400, 500, 600], modulus)
            .unwrap();
        let c_carol = carol
            .create_masked_contribution("secagg-zero-disc", &[700, 800, 900], modulus)
            .unwrap();

        // individual masked contributions hide raw inputs
        assert_ne!(c_alice.masked_values, vec![100, 200, 300]);
        assert_ne!(c_bob.masked_values, vec![400, 500, 600]);

        // Case 1: all 3 survive -> 0 seeds disclosed to coordinator!
        let mut full_session = SecureAggregationSession::new(
            "secagg-zero-disc".into(),
            AggregationConfig {
                min_participants: 2,
                max_participants: 10,
                vector_dimension: 3,
                field_modulus: modulus,
                dropout_threshold: 1,
            },
        );
        full_session.current_round = AggregationRound::ContributionSubmission;
        full_session
            .aggregate_contributions(vec![c_alice.clone(), c_bob.clone(), c_carol])
            .unwrap();
        let all_revealed = alice.reveal_dropout_seeds(&roster).unwrap();
        assert!(
            all_revealed.is_empty(),
            "no seeds may be revealed when all participants survive"
        );
        let full_sum = full_session
            .complete_pairwise_aggregation(&roster, &roster, &[])
            .unwrap();
        assert_eq!(full_sum, vec![1200, 1500, 1800]);

        // Case 2: Carol drops out -> Alice & Bob reveal ONLY their Carol seed;
        // their Alice<->Bob seed remains secret so coordinator cannot recover
        // Alice's or Bob's individual vector!
        let survivors = vec![alice_id.clone(), bob_id.clone()];
        let mut dropout_seeds = alice.reveal_dropout_seeds(&survivors).unwrap();
        dropout_seeds.extend(bob.reveal_dropout_seeds(&survivors).unwrap());
        assert_eq!(dropout_seeds.len(), 2);
        assert!(dropout_seeds.iter().all(|s| s.dropped_peer == carol_id));

        let mut drop_session = SecureAggregationSession::new(
            "secagg-zero-disc".into(),
            AggregationConfig {
                min_participants: 2,
                max_participants: 10,
                vector_dimension: 3,
                field_modulus: modulus,
                dropout_threshold: 1,
            },
        );
        drop_session.current_round = AggregationRound::ContributionSubmission;
        let raw_survivor_sum = drop_session
            .aggregate_contributions(vec![c_alice.clone(), c_bob])
            .unwrap();
        assert_ne!(raw_survivor_sum, vec![500, 700, 900]);
        let recovered_sum = drop_session
            .complete_pairwise_aggregation(&roster, &survivors, &dropout_seeds)
            .unwrap();
        assert_eq!(recovered_sum, vec![500, 700, 900]);
    }

    #[test]
    fn discrete_laplace_and_gaussian_noise_validate_and_match_moments() {
        let mut rng = thread_rng();
        assert!(sample_discrete_laplace(0.0, 1, &mut rng).is_err());
        assert!(sample_discrete_laplace(1.0, 0, &mut rng).is_err());
        assert!(sample_discrete_gaussian(0.0, &mut rng).is_err());

        let n = 4_000usize;
        let mut lap_sum = 0.0f64;
        let mut lap_sq = 0.0f64;
        for _ in 0..n {
            let x = sample_discrete_laplace(0.5, 1, &mut rng).unwrap() as f64;
            lap_sum += x;
            lap_sq += x * x;
        }
        let lap_mean = lap_sum / (n as f64);
        let lap_var = (lap_sq / (n as f64)) - lap_mean * lap_mean;
        // Theoretical variance for alpha=0.5: 2*exp(-0.5)/(1 - exp(-0.5))^2 ~= 7.83
        assert!(lap_mean.abs() < 0.35, "mean too far from 0: {lap_mean}");
        assert!(
            (4.5..12.0).contains(&lap_var),
            "unexpected discrete Laplace variance: {lap_var}"
        );

        let mut gauss_sum = 0.0f64;
        let mut gauss_sq = 0.0f64;
        for _ in 0..n {
            let g = sample_discrete_gaussian(3.0, &mut rng).unwrap() as f64;
            gauss_sum += g;
            gauss_sq += g * g;
        }
        let gauss_mean = gauss_sum / (n as f64);
        let gauss_var = (gauss_sq / (n as f64)) - gauss_mean * gauss_mean;
        assert!(gauss_mean.abs() < 0.35, "gaussian mean drift: {gauss_mean}");
        assert!(
            (6.5..11.5).contains(&gauss_var),
            "expected variance near sigma^2 = 9.0, got {gauss_var}"
        );
    }
}
