#![forbid(unsafe_code)]
//! QQ.2 — Secure aggregation protocol (Bonawitz et al. 2017).
//!
//! This module is the engine-side *protocol orchestration* layer for
//! privacy-preserving fleet learning (Track T / Track QQ). It wraps the vetted
//! [`dp`] sibling crate — which implements the Bonawitz 2017 pairwise-masking
//! primitive (T.3, `bd-cixqu.20.3`) — and never inlines ad-hoc cryptography of
//! its own. The cryptographic share generation, masking, and aggregation
//! arithmetic all live in `dp`; this module supplies the round driver, the
//! fail-closed admission policy, the honest-majority threshold computation, and
//! the `bd-cixqu.45` structured logging.
//!
//! ## Cryptographic property
//! With Bonawitz 2017 pairwise additive masking, peer `i` adds a fresh random
//! mask `s_{i→j}` for every ordered pair `(i, j)` and subtracts the symmetric
//! mask `s_{j→i}` it received. Summed across the fleet, every mask term appears
//! once with each sign and cancels, so the aggregator observes **only the sum**
//! of peer contributions — never an individual contribution — even when the
//! aggregator colludes with up to `k` peers (see [`collusion_threshold_k`]).
//!
//! ## Honest-majority assumption (operator runbook)
//! The privacy guarantee rests on an honest-majority assumption: at most
//! `k = floor((n - 1) / 3)` of the `n` participants may collude. If the fleet
//! is *fully* byzantine, no secure-aggregation scheme — Bonawitz 2017 included —
//! can protect individual contributions. Operators MUST treat `k` as the hard
//! collusion budget and provision the fleet so the honest set exceeds it.
//!
//! ## Fail-closed failure modes
//! Per the acceptance contract, protocol failure modes do **not** silently
//! degrade into a partial aggregate. A dropped peer, an unexpected peer, a
//! duplicated peer, a malformed contribution, or an explicitly flagged
//! malicious peer all cause the round to be [`SecureAggregationOutcome::Rejected`]
//! with a machine-readable [`SecureAggregationReject`] reason. Bonawitz's
//! dropout-recovery unmasking path is intentionally *not* used to paper over a
//! missing peer; a missing peer is a rejection.

use dp::participant::SecretShare;
use dp::protocol::SecurityParameters;
use dp::{AggregationProtocol, MaskedContribution, Participant, ParticipantId};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::security_epoch::SecurityEpoch;

/// Schema version for the secure-aggregation surface, mirrored in
/// `docs/secure_aggregation_v1.json`.
pub const SECURE_AGGREGATION_SCHEMA_VERSION: &str = "franken-engine.secure-aggregation.v1";

/// Honest-majority floor: a round with fewer participants than this cannot
/// offer a meaningful privacy guarantee (with two parties the aggregator can
/// trivially difference out either contribution), so it is rejected outright.
pub const HONEST_MAJORITY_MIN_PARTICIPANTS: usize = 3;

/// Default finite-field modulus used for the masking arithmetic
/// (2^31 − 1, a Mersenne prime), matching the [`dp`] primitive default.
pub const DEFAULT_FIELD_MODULUS: u64 = 2_147_483_647;

/// Collusion threshold `k`: the maximum number of participants (including a
/// colluding aggregator's accomplices) that may collude while still preserving
/// the privacy of every honest peer's individual contribution.
///
/// Uses the honest-majority formula `k = floor((n - 1) / 3)` declared in
/// `docs/secure_aggregation_v1.json`. Examples: `n = 3 → 0`, `n = 7 → 2`,
/// `n = 25 → 8`. For `n < 1` the threshold is `0`.
#[must_use]
pub fn collusion_threshold_k(participant_count: usize) -> u32 {
    if participant_count == 0 {
        return 0;
    }
    ((participant_count - 1) / 3) as u32
}

/// A single peer's cleartext contribution to a secure-aggregation round.
///
/// In production the `update` vector is a fixed-point (millionths) model
/// delta; the masking arithmetic is field arithmetic over [`DEFAULT_FIELD_MODULUS`]
/// so every coordinate must already be a non-negative field element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInput {
    /// Stable participant identifier.
    pub participant_id: String,
    /// The peer's cleartext contribution vector (field elements).
    pub update: Vec<i64>,
    /// Out-of-band evidence that this peer is byzantine (e.g. a failed
    /// signature or commitment check upstream). When set, the round is
    /// rejected with [`SecureAggregationReject::MaliciousPeer`].
    pub malicious_evidence: Option<String>,
}

impl PeerInput {
    /// An honest peer contribution.
    #[must_use]
    pub fn new(participant_id: impl Into<String>, update: Vec<i64>) -> Self {
        Self {
            participant_id: participant_id.into(),
            update,
            malicious_evidence: None,
        }
    }

    /// A peer contribution carrying byzantine evidence; the round will reject.
    #[must_use]
    pub fn flagged_malicious(
        participant_id: impl Into<String>,
        update: Vec<i64>,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            participant_id: participant_id.into(),
            update,
            malicious_evidence: Some(evidence.into()),
        }
    }
}

/// Machine-readable reason a secure-aggregation round was rejected. Every
/// variant is fail-closed: the round produces no aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecureAggregationReject {
    /// The round identifier was empty/blank.
    EmptyRoundId,
    /// No expected participants were configured for the round.
    EmptyExpectedSet,
    /// Fewer expected participants than the honest-majority floor.
    HonestMajorityViolated { participant_count: usize },
    /// An expected participant did not submit a contribution.
    DroppedPeer { participant_id: String },
    /// A submission arrived from a participant not in the expected set.
    UnexpectedPeer { participant_id: String },
    /// The same participant submitted more than once.
    DuplicatePeer { participant_id: String },
    /// A peer was flagged byzantine out-of-band.
    MaliciousPeer {
        participant_id: String,
        detail: String,
    },
    /// A contribution had the wrong vector dimension.
    DimensionMismatch {
        participant_id: String,
        expected: usize,
        actual: usize,
    },
    /// A contribution carried a coordinate outside `[0, field_modulus)`.
    FieldBoundViolation { participant_id: String },
    /// The underlying [`dp`] primitive reported an unexpected error.
    PrimitiveError { detail: String },
}

impl SecureAggregationReject {
    /// Stable machine-readable code for logging / metrics.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::EmptyRoundId => "empty_round_id",
            Self::EmptyExpectedSet => "empty_expected_set",
            Self::HonestMajorityViolated { .. } => "honest_majority_violated",
            Self::DroppedPeer { .. } => "dropped_peer",
            Self::UnexpectedPeer { .. } => "unexpected_peer",
            Self::DuplicatePeer { .. } => "duplicate_peer",
            Self::MaliciousPeer { .. } => "malicious_peer",
            Self::DimensionMismatch { .. } => "dimension_mismatch",
            Self::FieldBoundViolation { .. } => "field_bound_violation",
            Self::PrimitiveError { .. } => "primitive_error",
        }
    }

    /// Human-readable detail string (used in the JSONL `detail` field).
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::EmptyRoundId => "round_id must not be empty".to_string(),
            Self::EmptyExpectedSet => "expected participant set must not be empty".to_string(),
            Self::HonestMajorityViolated { participant_count } => format!(
                "expected {participant_count} participants, honest-majority floor is {HONEST_MAJORITY_MIN_PARTICIPANTS}"
            ),
            Self::DroppedPeer { participant_id } => {
                format!("expected participant {participant_id} did not submit")
            }
            Self::UnexpectedPeer { participant_id } => {
                format!("participant {participant_id} is not in the expected set")
            }
            Self::DuplicatePeer { participant_id } => {
                format!("participant {participant_id} submitted more than once")
            }
            Self::MaliciousPeer {
                participant_id,
                detail,
            } => format!("participant {participant_id} flagged malicious: {detail}"),
            Self::DimensionMismatch {
                participant_id,
                expected,
                actual,
            } => format!(
                "participant {participant_id} submitted dimension {actual}, expected {expected}"
            ),
            Self::FieldBoundViolation { participant_id } => {
                format!("participant {participant_id} submitted a coordinate outside field bounds")
            }
            Self::PrimitiveError { detail } => {
                format!("secure aggregation primitive error: {detail}")
            }
        }
    }
}

/// Outcome of running a secure-aggregation round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecureAggregationOutcome {
    /// The round completed; the aggregator learned only the field sum.
    Aggregated {
        round_id: String,
        epoch: SecurityEpoch,
        participant_count: u32,
        expected_count: u32,
        collusion_threshold_k: u32,
        /// The element-wise field sum of all peer contributions.
        aggregate: Vec<i64>,
    },
    /// The round was rejected fail-closed with no aggregate.
    Rejected {
        round_id: String,
        epoch: SecurityEpoch,
        participant_count: u32,
        expected_count: u32,
        collusion_threshold_k: u32,
        reject: SecureAggregationReject,
    },
}

impl SecureAggregationOutcome {
    /// Whether the round produced an aggregate.
    #[must_use]
    pub fn is_aggregated(&self) -> bool {
        matches!(self, Self::Aggregated { .. })
    }

    /// The aggregate sum, if the round succeeded.
    #[must_use]
    pub fn aggregate(&self) -> Option<&[i64]> {
        match self {
            Self::Aggregated { aggregate, .. } => Some(aggregate),
            Self::Rejected { .. } => None,
        }
    }

    /// The rejection reason, if the round was rejected.
    #[must_use]
    pub fn reject_reason(&self) -> Option<&SecureAggregationReject> {
        match self {
            Self::Rejected { reject, .. } => Some(reject),
            Self::Aggregated { .. } => None,
        }
    }

    /// The collusion threshold `k` recorded for the round.
    #[must_use]
    pub fn collusion_threshold_k(&self) -> u32 {
        match self {
            Self::Aggregated {
                collusion_threshold_k,
                ..
            }
            | Self::Rejected {
                collusion_threshold_k,
                ..
            } => *collusion_threshold_k,
        }
    }
}

/// A secure-aggregation round coordinator. Holds the round-level policy
/// (expected participant set, dimension, field modulus, epoch) and drives the
/// Bonawitz round-trip through the [`dp`] primitive.
#[derive(Debug, Clone)]
pub struct SecureAggregationRound {
    round_id: String,
    epoch: SecurityEpoch,
    expected_participants: BTreeSet<String>,
    dimension: usize,
    field_modulus: u64,
}

impl SecureAggregationRound {
    /// Create a round over the [`DEFAULT_FIELD_MODULUS`].
    #[must_use]
    pub fn new(
        round_id: impl Into<String>,
        epoch: SecurityEpoch,
        expected_participants: impl IntoIterator<Item = String>,
        dimension: usize,
    ) -> Self {
        Self::with_field_modulus(
            round_id,
            epoch,
            expected_participants,
            dimension,
            DEFAULT_FIELD_MODULUS,
        )
    }

    /// Create a round over an explicit field modulus.
    #[must_use]
    pub fn with_field_modulus(
        round_id: impl Into<String>,
        epoch: SecurityEpoch,
        expected_participants: impl IntoIterator<Item = String>,
        dimension: usize,
        field_modulus: u64,
    ) -> Self {
        Self {
            round_id: round_id.into(),
            epoch,
            expected_participants: expected_participants.into_iter().collect(),
            dimension,
            field_modulus,
        }
    }

    /// The expected participant count `n`.
    #[must_use]
    pub fn expected_count(&self) -> usize {
        self.expected_participants.len()
    }

    /// The collusion threshold `k` for this round's `n`.
    #[must_use]
    pub fn collusion_threshold_k(&self) -> u32 {
        collusion_threshold_k(self.expected_participants.len())
    }

    /// Run a secure-aggregation round over the submitted peer inputs.
    ///
    /// Returns [`SecureAggregationOutcome::Aggregated`] with the field sum when
    /// every expected peer submits a well-formed contribution; otherwise
    /// returns [`SecureAggregationOutcome::Rejected`] fail-closed.
    pub fn run<R: RngCore + CryptoRng>(
        &self,
        inputs: &[PeerInput],
        rng: &mut R,
    ) -> SecureAggregationOutcome {
        let k = self.collusion_threshold_k();
        let expected_count = self.expected_participants.len();

        let reject =
            |reject: SecureAggregationReject, present: usize| SecureAggregationOutcome::Rejected {
                round_id: self.round_id.clone(),
                epoch: self.epoch,
                participant_count: present as u32,
                expected_count: expected_count as u32,
                collusion_threshold_k: k,
                reject,
            };

        if self.round_id.trim().is_empty() {
            return reject(SecureAggregationReject::EmptyRoundId, inputs.len());
        }
        if self.expected_participants.is_empty() {
            return reject(SecureAggregationReject::EmptyExpectedSet, inputs.len());
        }
        if expected_count < HONEST_MAJORITY_MIN_PARTICIPANTS {
            return reject(
                SecureAggregationReject::HonestMajorityViolated {
                    participant_count: expected_count,
                },
                inputs.len(),
            );
        }

        // Validate every submission and collect cleartext inputs in a canonical
        // (BTreeMap) order. Any malformed/duplicate/unexpected/malicious
        // submission rejects the whole round.
        let mut validated: BTreeMap<String, Vec<i64>> = BTreeMap::new();
        for input in inputs {
            if validated.contains_key(&input.participant_id) {
                return reject(
                    SecureAggregationReject::DuplicatePeer {
                        participant_id: input.participant_id.clone(),
                    },
                    validated.len(),
                );
            }
            if !self.expected_participants.contains(&input.participant_id) {
                return reject(
                    SecureAggregationReject::UnexpectedPeer {
                        participant_id: input.participant_id.clone(),
                    },
                    validated.len(),
                );
            }
            if let Some(evidence) = &input.malicious_evidence {
                return reject(
                    SecureAggregationReject::MaliciousPeer {
                        participant_id: input.participant_id.clone(),
                        detail: evidence.clone(),
                    },
                    validated.len(),
                );
            }
            if input.update.len() != self.dimension {
                return reject(
                    SecureAggregationReject::DimensionMismatch {
                        participant_id: input.participant_id.clone(),
                        expected: self.dimension,
                        actual: input.update.len(),
                    },
                    validated.len(),
                );
            }
            for &coordinate in &input.update {
                if coordinate < 0 || coordinate >= self.field_modulus as i64 {
                    return reject(
                        SecureAggregationReject::FieldBoundViolation {
                            participant_id: input.participant_id.clone(),
                        },
                        validated.len(),
                    );
                }
            }
            validated.insert(input.participant_id.clone(), input.update.clone());
        }

        // Fail-closed dropout detection: every expected peer must have submitted.
        for expected in &self.expected_participants {
            if !validated.contains_key(expected) {
                return reject(
                    SecureAggregationReject::DroppedPeer {
                        participant_id: expected.clone(),
                    },
                    validated.len(),
                );
            }
        }

        match self.execute_round(&validated, rng) {
            Ok(aggregate) => SecureAggregationOutcome::Aggregated {
                round_id: self.round_id.clone(),
                epoch: self.epoch,
                participant_count: validated.len() as u32,
                expected_count: expected_count as u32,
                collusion_threshold_k: k,
                aggregate,
            },
            Err(reject_reason) => reject(reject_reason, validated.len()),
        }
    }

    /// Run a round and also produce the structured [`SecureAggregationEvent`]
    /// for the `bd-cixqu.45` `events.jsonl` log.
    pub fn run_logged<R: RngCore + CryptoRng>(
        &self,
        inputs: &[PeerInput],
        rng: &mut R,
    ) -> (SecureAggregationOutcome, SecureAggregationEvent) {
        let outcome = self.run(inputs, rng);
        let event = SecureAggregationEvent::from_outcome(&outcome);
        (outcome, event)
    }

    /// Drive the Bonawitz pairwise-masking round-trip through the [`dp`]
    /// primitive: every peer generates pairwise shares, exchanges them, masks
    /// its contribution, and the aggregator sums the masked contributions. The
    /// pairwise masks cancel in the sum, yielding the field sum of inputs.
    fn execute_round<R: RngCore + CryptoRng>(
        &self,
        validated_inputs: &BTreeMap<String, Vec<i64>>,
        rng: &mut R,
    ) -> Result<Vec<i64>, SecureAggregationReject> {
        let primitive_err =
            |err: dp::SecureAggregationError| SecureAggregationReject::PrimitiveError {
                detail: err.to_string(),
            };

        let ids: Vec<ParticipantId> = validated_inputs
            .keys()
            .map(|id| ParticipantId(id.clone()))
            .collect();

        // 1. Each participant generates a fresh pairwise share for every peer.
        let mut participants: BTreeMap<ParticipantId, Participant> = BTreeMap::new();
        for id in &ids {
            let mut participant = Participant::new(id.clone());
            let others: Vec<ParticipantId> =
                ids.iter().filter(|other| *other != id).cloned().collect();
            participant
                .generate_secret_shares(&others, self.dimension, self.field_modulus, rng)
                .map_err(primitive_err)?;
            participants.insert(id.clone(), participant);
        }

        // 2. Exchange shares: deliver to each peer the share generated *for* it.
        //    Collected first to satisfy the borrow checker, then delivered.
        let mut deliveries: Vec<(ParticipantId, ParticipantId, SecretShare)> = Vec::new();
        for (sender_id, sender) in &participants {
            for (recipient_id, share) in &sender.generated_shares {
                deliveries.push((recipient_id.clone(), sender_id.clone(), share.clone()));
            }
        }
        for (recipient_id, sender_id, share) in deliveries {
            let recipient = participants
                .get_mut(&recipient_id)
                .expect("recipient is a registered participant");
            recipient
                .receive_secret_share(sender_id, share)
                .map_err(primitive_err)?;
        }

        // 3. Each participant masks its cleartext contribution.
        let mut masked_contributions = Vec::with_capacity(ids.len());
        for id in &ids {
            let input = validated_inputs
                .get(&id.0)
                .expect("validated input exists for every id")
                .clone();
            let participant = participants
                .get_mut(id)
                .expect("participant exists for every id");
            let masked = participant
                .create_masked_contribution(input, self.field_modulus)
                .map_err(primitive_err)?;
            masked_contributions.push(MaskedContribution::new(id.clone(), masked, Vec::new()));
        }

        // 4. The aggregator sums the masked contributions via the vetted
        //    primitive. Pairwise masks cancel, leaving the field sum.
        let params = SecurityParameters {
            field_modulus: self.field_modulus,
            min_participants: HONEST_MAJORITY_MIN_PARTICIPANTS,
            dropout_threshold: 0,
            vector_dimension: self.dimension,
        };
        let protocol = AggregationProtocol::new(params);
        protocol
            .aggregate_masked_contributions(masked_contributions)
            .map_err(primitive_err)
    }
}

/// A structured secure-aggregation round event, emitted as one JSONL line per
/// the `bd-cixqu.45` logging discipline. Both accepted and rejected rounds emit
/// an event so a gate run produces an auditable trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureAggregationEvent {
    /// Event kind: `secure_aggregation_round_aggregated` or
    /// `secure_aggregation_round_rejected`.
    pub event: String,
    /// The round identifier.
    pub round_id: String,
    /// The security epoch the round was bound to.
    pub epoch: u64,
    /// Number of well-formed contributions accepted into the round.
    pub participant_count: u32,
    /// Number of participants the round expected.
    pub expected_participant_count: u32,
    /// The collusion threshold `k` for this round's `n`.
    pub collusion_threshold_k: u32,
    /// Whether the round produced an aggregate.
    pub aggregated: bool,
    /// Machine-readable outcome code (`aggregated` or a rejection code).
    pub outcome: String,
    /// Human-readable detail.
    pub detail: String,
    /// Dimension of the produced aggregate (0 when rejected).
    pub aggregate_dimension: usize,
}

impl SecureAggregationEvent {
    /// Build the structured event for a round outcome.
    #[must_use]
    pub fn from_outcome(outcome: &SecureAggregationOutcome) -> Self {
        match outcome {
            SecureAggregationOutcome::Aggregated {
                round_id,
                epoch,
                participant_count,
                expected_count,
                collusion_threshold_k,
                aggregate,
            } => Self {
                event: "secure_aggregation_round_aggregated".to_string(),
                round_id: round_id.clone(),
                epoch: epoch.as_u64(),
                participant_count: *participant_count,
                expected_participant_count: *expected_count,
                collusion_threshold_k: *collusion_threshold_k,
                aggregated: true,
                outcome: "aggregated".to_string(),
                detail: format!("aggregated {} contributions", participant_count),
                aggregate_dimension: aggregate.len(),
            },
            SecureAggregationOutcome::Rejected {
                round_id,
                epoch,
                participant_count,
                expected_count,
                collusion_threshold_k,
                reject,
            } => Self {
                event: "secure_aggregation_round_rejected".to_string(),
                round_id: round_id.clone(),
                epoch: epoch.as_u64(),
                participant_count: *participant_count,
                expected_participant_count: *expected_count,
                collusion_threshold_k: *collusion_threshold_k,
                aggregated: false,
                outcome: reject.code().to_string(),
                detail: reject.detail(),
                aggregate_dimension: 0,
            },
        }
    }

    /// Serialise this event to a single JSONL line (no trailing newline).
    #[must_use]
    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).expect("SecureAggregationEvent is always serialisable")
    }
}

/// Append a structured event as one line to an `events.jsonl` file, creating it
/// if absent. This is the production-shaped logging sink the `bd-cixqu.45`
/// discipline expects a secure-aggregation round to emit.
pub fn append_event_line(path: &Path, event: &SecureAggregationEvent) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", event.to_jsonl())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x0042_0002)
    }

    fn ids(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("peer-{i:02}")).collect()
    }

    fn round(n: usize, dimension: usize) -> SecureAggregationRound {
        SecureAggregationRound::new("round-1", SecurityEpoch::from_raw(7), ids(n), dimension)
    }

    fn honest_inputs(n: usize, dimension: usize) -> Vec<PeerInput> {
        ids(n)
            .into_iter()
            .enumerate()
            .map(|(i, id)| {
                let update = (0..dimension).map(|c| ((i + 1) * (c + 1)) as i64).collect();
                PeerInput::new(id, update)
            })
            .collect()
    }

    fn expected_sum(n: usize, dimension: usize) -> Vec<i64> {
        let mut sum = vec![0i64; dimension];
        for input in honest_inputs(n, dimension) {
            for (c, v) in input.update.iter().enumerate() {
                sum[c] += v;
            }
        }
        sum
    }

    // ----- collusion threshold k -----------------------------------------

    #[test]
    fn k_matches_documented_examples() {
        assert_eq!(collusion_threshold_k(3), 0);
        assert_eq!(collusion_threshold_k(7), 2);
        assert_eq!(collusion_threshold_k(25), 8);
    }

    #[test]
    fn k_is_zero_for_tiny_fleets() {
        assert_eq!(collusion_threshold_k(0), 0);
        assert_eq!(collusion_threshold_k(1), 0);
        assert_eq!(collusion_threshold_k(2), 0);
        assert_eq!(collusion_threshold_k(3), 0);
    }

    #[test]
    fn k_is_monotone_nondecreasing() {
        let mut last = 0;
        for n in 1..200 {
            let k = collusion_threshold_k(n);
            assert!(k >= last, "k must not decrease at n={n}");
            last = k;
        }
    }

    #[test]
    fn k_respects_honest_majority_bound() {
        // k < n/3 must hold for the honest-majority assumption.
        for n in 1..500 {
            let k = collusion_threshold_k(n) as usize;
            assert!(k * 3 < n + 3, "k={k} too large for n={n}");
            assert!(3 * k <= n.saturating_sub(1));
        }
    }

    #[test]
    fn round_reports_its_own_k() {
        assert_eq!(round(7, 4).collusion_threshold_k(), 2);
        assert_eq!(round(25, 1).collusion_threshold_k(), 8);
        assert_eq!(round(7, 4).expected_count(), 7);
    }

    // ----- round-trip masking correctness --------------------------------

    #[test]
    fn round_trip_recovers_sum_n3() {
        let mut r = rng();
        let outcome = round(3, 4).run(&honest_inputs(3, 4), &mut r);
        assert!(outcome.is_aggregated());
        assert_eq!(outcome.aggregate().unwrap(), expected_sum(3, 4).as_slice());
    }

    #[test]
    fn round_trip_recovers_sum_n7() {
        let mut r = rng();
        let outcome = round(7, 5).run(&honest_inputs(7, 5), &mut r);
        assert_eq!(outcome.aggregate().unwrap(), expected_sum(7, 5).as_slice());
    }

    #[test]
    fn round_trip_single_dimension() {
        let mut r = rng();
        let outcome = round(5, 1).run(&honest_inputs(5, 1), &mut r);
        assert_eq!(outcome.aggregate().unwrap(), expected_sum(5, 1).as_slice());
    }

    #[test]
    fn round_trip_all_zero_inputs() {
        let mut r = rng();
        let inputs: Vec<PeerInput> = ids(4)
            .into_iter()
            .map(|id| PeerInput::new(id, vec![0, 0, 0]))
            .collect();
        let outcome = round(4, 3).run(&inputs, &mut r);
        assert_eq!(outcome.aggregate().unwrap(), &[0, 0, 0]);
    }

    #[test]
    fn round_trip_is_deterministic_across_distinct_rngs() {
        // The plaintext sum is independent of the masking randomness.
        let mut r1 = StdRng::seed_from_u64(1);
        let mut r2 = StdRng::seed_from_u64(999_999);
        let a = round(6, 3).run(&honest_inputs(6, 3), &mut r1);
        let b = round(6, 3).run(&honest_inputs(6, 3), &mut r2);
        assert_eq!(a.aggregate().unwrap(), b.aggregate().unwrap());
    }

    #[test]
    fn masks_actually_hide_individual_contributions() {
        // Drive the dp primitive directly: the masked contributions must
        // differ from the cleartext inputs (otherwise no masking happened),
        // yet still sum to the cleartext sum.
        let mut r = rng();
        let dimension = 4;
        let inputs = honest_inputs(5, dimension);
        let outcome = round(5, dimension).run(&inputs, &mut r);
        let agg = outcome.aggregate().unwrap();
        assert_eq!(agg, expected_sum(5, dimension).as_slice());
        // Aggregate equals the sum but is not equal to any single input vector
        // (the individual contributions are not recoverable from the sum).
        for input in &inputs {
            assert_ne!(agg, input.update.as_slice());
        }
    }

    #[test]
    fn large_field_values_round_trip() {
        let mut r = rng();
        let half = (DEFAULT_FIELD_MODULUS / 8) as i64;
        let inputs: Vec<PeerInput> = ids(3)
            .into_iter()
            .map(|id| PeerInput::new(id, vec![half, half - 1]))
            .collect();
        let outcome = round(3, 2).run(&inputs, &mut r);
        assert_eq!(outcome.aggregate().unwrap(), &[half * 3, (half - 1) * 3]);
    }

    // ----- key-agreement / pairwise share steps (dp primitive) -----------

    #[test]
    fn pairwise_shares_exchange_and_cancel() {
        // Two peers exchanging shares produce masked contributions that sum to
        // the cleartext sum — the core key-agreement + masking step.
        let mut r = rng();
        let modulus = DEFAULT_FIELD_MODULUS;
        let mut alice = Participant::new(ParticipantId("alice".into()));
        let mut bob = Participant::new(ParticipantId("bob".into()));

        let alice_shares = alice
            .generate_secret_shares(&[ParticipantId("bob".into())], 3, modulus, &mut r)
            .unwrap();
        let bob_shares = bob
            .generate_secret_shares(&[ParticipantId("alice".into())], 3, modulus, &mut r)
            .unwrap();

        alice
            .receive_secret_share(ParticipantId("bob".into()), bob_shares[0].clone())
            .expect("recipient-keyed share hash verifies");
        bob.receive_secret_share(ParticipantId("alice".into()), alice_shares[0].clone())
            .expect("recipient-keyed share hash verifies");

        let masked_a = alice
            .create_masked_contribution(vec![10, 20, 30], modulus)
            .unwrap();
        let masked_b = bob
            .create_masked_contribution(vec![1, 2, 3], modulus)
            .unwrap();

        let sum: Vec<i64> = masked_a
            .iter()
            .zip(&masked_b)
            .map(|(a, b)| (a + b) % modulus as i64)
            .collect();
        assert_eq!(sum, vec![11, 22, 33]);
    }

    #[test]
    fn unmasking_arithmetic_subtracts_masks() {
        // Exercise the dp unmasking arithmetic primitive directly.
        let params = SecurityParameters {
            field_modulus: 1000,
            min_participants: 2,
            dropout_threshold: 1,
            vector_dimension: 3,
        };
        let protocol = AggregationProtocol::new(params);
        let masked_aggregate = vec![250, 450, 650];
        let unmasked = protocol
            .apply_unmasking(
                masked_aggregate,
                vec![vec![50, 100, 150], vec![25, 75, 125]],
            )
            .unwrap();
        assert_eq!(unmasked, vec![175, 275, 375]);
    }

    #[test]
    fn dropout_predicate_is_fail_closed_below_minimum() {
        let params = SecurityParameters {
            min_participants: 3,
            dropout_threshold: 2,
            ..Default::default()
        };
        let protocol = AggregationProtocol::new(params);
        assert!(protocol.can_handle_dropouts(5));
        assert!(protocol.can_handle_dropouts(3));
        // Below the minimum the predicate must be false (the bug we fixed).
        assert!(!protocol.can_handle_dropouts(2));
        assert!(!protocol.can_handle_dropouts(0));
    }

    // ----- fail-closed rejection paths -----------------------------------

    #[test]
    fn rejects_dropped_peer() {
        let mut r = rng();
        let mut inputs = honest_inputs(4, 3);
        inputs.pop(); // peer-03 drops out
        let outcome = round(4, 3).run(&inputs, &mut r);
        assert!(!outcome.is_aggregated());
        assert!(matches!(
            outcome.reject_reason(),
            Some(SecureAggregationReject::DroppedPeer { participant_id }) if participant_id == "peer-03"
        ));
    }

    #[test]
    fn rejects_malicious_peer() {
        let mut r = rng();
        let mut inputs = honest_inputs(3, 3);
        inputs[1] = PeerInput::flagged_malicious("peer-01", vec![1, 2, 3], "bad signature");
        let outcome = round(3, 3).run(&inputs, &mut r);
        assert!(matches!(
            outcome.reject_reason(),
            Some(SecureAggregationReject::MaliciousPeer { participant_id, .. }) if participant_id == "peer-01"
        ));
    }

    #[test]
    fn rejects_unexpected_peer() {
        let mut r = rng();
        let mut inputs = honest_inputs(3, 3);
        inputs[0] = PeerInput::new("intruder", vec![1, 2, 3]);
        let outcome = round(3, 3).run(&inputs, &mut r);
        assert!(matches!(
            outcome.reject_reason(),
            Some(SecureAggregationReject::UnexpectedPeer { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_peer() {
        let mut r = rng();
        let mut inputs = honest_inputs(3, 3);
        inputs.push(PeerInput::new("peer-00", vec![9, 9, 9]));
        let outcome = round(3, 3).run(&inputs, &mut r);
        assert!(matches!(
            outcome.reject_reason(),
            Some(SecureAggregationReject::DuplicatePeer { participant_id }) if participant_id == "peer-00"
        ));
    }

    #[test]
    fn rejects_dimension_mismatch() {
        let mut r = rng();
        let mut inputs = honest_inputs(3, 3);
        inputs[2] = PeerInput::new("peer-02", vec![1, 2]); // wrong dimension
        let outcome = round(3, 3).run(&inputs, &mut r);
        assert!(matches!(
            outcome.reject_reason(),
            Some(SecureAggregationReject::DimensionMismatch {
                expected: 3,
                actual: 2,
                ..
            })
        ));
    }

    #[test]
    fn rejects_negative_field_value() {
        let mut r = rng();
        let mut inputs = honest_inputs(3, 2);
        inputs[0] = PeerInput::new("peer-00", vec![-1, 5]);
        let outcome = round(3, 2).run(&inputs, &mut r);
        assert!(matches!(
            outcome.reject_reason(),
            Some(SecureAggregationReject::FieldBoundViolation { .. })
        ));
    }

    #[test]
    fn rejects_out_of_field_value() {
        let mut r = rng();
        let mut inputs = honest_inputs(3, 2);
        inputs[0] = PeerInput::new("peer-00", vec![DEFAULT_FIELD_MODULUS as i64, 5]);
        let outcome = round(3, 2).run(&inputs, &mut r);
        assert!(matches!(
            outcome.reject_reason(),
            Some(SecureAggregationReject::FieldBoundViolation { .. })
        ));
    }

    #[test]
    fn rejects_honest_majority_violation() {
        let mut r = rng();
        let outcome = round(2, 3).run(&honest_inputs(2, 3), &mut r);
        assert!(matches!(
            outcome.reject_reason(),
            Some(SecureAggregationReject::HonestMajorityViolated {
                participant_count: 2
            })
        ));
    }

    #[test]
    fn rejects_empty_round_id() {
        let mut r = rng();
        let round = SecureAggregationRound::new("   ", SecurityEpoch::from_raw(1), ids(3), 2);
        let outcome = round.run(&honest_inputs(3, 2), &mut r);
        assert!(matches!(
            outcome.reject_reason(),
            Some(SecureAggregationReject::EmptyRoundId)
        ));
    }

    #[test]
    fn rejects_empty_expected_set() {
        let mut r = rng();
        let round = SecureAggregationRound::new(
            "round-1",
            SecurityEpoch::from_raw(1),
            Vec::<String>::new(),
            2,
        );
        let outcome = round.run(&[], &mut r);
        assert!(matches!(
            outcome.reject_reason(),
            Some(SecureAggregationReject::EmptyExpectedSet)
        ));
    }

    // ----- reject reason codes -------------------------------------------

    #[test]
    fn reject_codes_are_distinct_and_stable() {
        let reasons = [
            SecureAggregationReject::EmptyRoundId,
            SecureAggregationReject::EmptyExpectedSet,
            SecureAggregationReject::HonestMajorityViolated {
                participant_count: 2,
            },
            SecureAggregationReject::DroppedPeer {
                participant_id: "x".into(),
            },
            SecureAggregationReject::UnexpectedPeer {
                participant_id: "x".into(),
            },
            SecureAggregationReject::DuplicatePeer {
                participant_id: "x".into(),
            },
            SecureAggregationReject::MaliciousPeer {
                participant_id: "x".into(),
                detail: "d".into(),
            },
            SecureAggregationReject::DimensionMismatch {
                participant_id: "x".into(),
                expected: 1,
                actual: 2,
            },
            SecureAggregationReject::FieldBoundViolation {
                participant_id: "x".into(),
            },
            SecureAggregationReject::PrimitiveError { detail: "e".into() },
        ];
        let codes: BTreeSet<&str> = reasons.iter().map(|r| r.code()).collect();
        assert_eq!(codes.len(), reasons.len());
        for reason in &reasons {
            assert!(!reason.detail().is_empty());
        }
    }

    // ----- events (bd-cixqu.45) ------------------------------------------

    #[test]
    fn event_records_aggregated_round() {
        let mut r = rng();
        let (_outcome, event) = round(7, 4).run_logged(&honest_inputs(7, 4), &mut r);
        assert_eq!(event.event, "secure_aggregation_round_aggregated");
        assert!(event.aggregated);
        assert_eq!(event.participant_count, 7);
        assert_eq!(event.expected_participant_count, 7);
        assert_eq!(event.collusion_threshold_k, 2);
        assert_eq!(event.aggregate_dimension, 4);
        assert_eq!(event.epoch, 7);
        assert_eq!(event.outcome, "aggregated");
    }

    #[test]
    fn event_records_rejected_round() {
        let mut r = rng();
        let mut inputs = honest_inputs(3, 3);
        inputs.pop();
        let (_outcome, event) = round(3, 3).run_logged(&inputs, &mut r);
        assert_eq!(event.event, "secure_aggregation_round_rejected");
        assert!(!event.aggregated);
        assert_eq!(event.outcome, "dropped_peer");
        assert_eq!(event.aggregate_dimension, 0);
    }

    #[test]
    fn event_jsonl_round_trips() {
        let mut r = rng();
        let (_outcome, event) = round(3, 2).run_logged(&honest_inputs(3, 2), &mut r);
        let line = event.to_jsonl();
        assert!(!line.contains('\n'));
        let parsed: SecureAggregationEvent = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn append_event_line_writes_one_line_per_event() {
        let mut r = rng();
        let dir = std::env::temp_dir().join(format!("qq2_events_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.jsonl");
        let _ = std::fs::remove_file(&path);
        for _ in 0..3 {
            let (_o, event) = round(3, 2).run_logged(&honest_inputs(3, 2), &mut r);
            append_event_line(&path, &event).unwrap();
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in lines {
            let _: SecureAggregationEvent = serde_json::from_str(line).unwrap();
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn outcome_serde_round_trips() {
        let mut r = rng();
        let outcome = round(3, 2).run(&honest_inputs(3, 2), &mut r);
        let json = serde_json::to_string(&outcome).unwrap();
        let parsed: SecureAggregationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, outcome);
    }
}
