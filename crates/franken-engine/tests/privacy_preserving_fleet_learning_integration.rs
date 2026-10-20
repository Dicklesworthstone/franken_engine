#![forbid(unsafe_code)]
//! Composed regression for charged DP updates and the real dp masking APIs.
//!
//! Deterministic noise is deliberately used for reproducible tests. Successful
//! arithmetic does not establish production DP, authenticated transport,
//! threshold recovery, or cryptographic secrecy against an aggregator that
//! receives individual unmasking values.

use dp::{
    AggregationConfig, AggregationRound, MaskedContribution, Participant, ParticipantId,
    SecureAggregationError, SecureAggregationSession,
    protocol::{AggregationProtocol, SecurityParameters},
};
use frankenengine_engine::differential_privacy_posterior::{
    DeterministicTestNoiseGenerator, DifferentialPrivacyError, PrivacyParameters,
    PrivacyPreservingAggregator, PrivatePosteriorDelta,
};
use frankenengine_engine::federated_posterior_aggregation::PosteriorDelta;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::{fleet_immune_protocol::NodeId, security_epoch::SecurityEpoch};
use rand::{SeedableRng, rngs::StdRng};

// Weighted signed deltas exceed the primitive's default 31-bit field. This
// Mersenne prime leaves room for both the weighted sum and its signed decoding.
const FIELD_MODULUS: u64 = (1u64 << 61) - 1;
const DIMENSION: usize = 4;

fn delta(values: [i64; DIMENSION], weight: u64, epoch: SecurityEpoch) -> PosteriorDelta {
    assert_eq!(values.iter().sum::<i64>(), 0);
    PosteriorDelta {
        extension_id: "shared-extension".to_string(),
        delta_benign_millionths: values[0],
        delta_anomalous_millionths: values[1],
        delta_malicious_millionths: values[2],
        delta_unknown_millionths: values[3],
        confidence_weight_millionths: weight,
        evidence_hash: ContentHash::compute(format!("{values:?}:{weight}").as_bytes()),
        epoch,
    }
}

fn weighted_input(private: &PrivatePosteriorDelta) -> Vec<i64> {
    let delta = private.get_noisy_delta();
    let weight = i64::try_from(delta.confidence_weight_millionths).unwrap();
    [
        delta.delta_benign_millionths,
        delta.delta_anomalous_millionths,
        delta.delta_malicious_millionths,
        delta.delta_unknown_millionths,
    ]
    .into_iter()
    .map(|value| value.checked_mul(weight).unwrap())
    .collect()
}

fn decode_field(values: Vec<i64>) -> Vec<i64> {
    let modulus = i64::try_from(FIELD_MODULUS).unwrap();
    values
        .into_iter()
        .map(|value| {
            assert!((0..modulus).contains(&value));
            if value > modulus / 2 {
                value - modulus
            } else {
                value
            }
        })
        .collect()
}

/// Generate and exchange actual shares for all enrolled participants. Entries
/// without an input drop out AFTER exchanging shares. Recovery here reveals
/// active participants' net masks; it is not threshold/collusion privacy proof.
fn aggregate_masked_inputs(inputs: &[Option<Vec<i64>>], minimum: usize) -> dp::Result<Vec<i64>> {
    let config = AggregationConfig {
        min_participants: minimum,
        max_participants: inputs.len(),
        vector_dimension: DIMENSION,
        field_modulus: FIELD_MODULUS,
        dropout_threshold: 1,
    };
    let mut session = SecureAggregationSession::new("composed-api-regression".into(), config);
    let ids: Vec<_> = (0..inputs.len())
        .map(|index| ParticipantId(format!("node-{index}")))
        .collect();
    for id in &ids {
        session.add_participant(Participant::new(id.clone()))?;
    }
    let mut rng = StdRng::seed_from_u64(0x1_2026);
    assert_eq!(session.start_aggregation(&mut rng)?.len(), inputs.len());
    assert_eq!(session.current_round, AggregationRound::ShareGeneration);

    let mut messages = Vec::new();
    for sender in &ids {
        let others: Vec<_> = ids.iter().filter(|id| *id != sender).cloned().collect();
        let shares = session
            .participants
            .get_mut(sender)
            .unwrap()
            .generate_secret_shares(&others, DIMENSION, FIELD_MODULUS, &mut rng)?;
        messages.extend(shares.into_iter().map(|share| (sender.clone(), share)));
    }
    for (sender, share) in messages {
        session
            .participants
            .get_mut(&share.recipient)
            .unwrap()
            .receive_secret_share(sender, share)?;
    }

    let mut contributions = Vec::new();
    let mut unmasking = Vec::new();
    for (id, input) in ids.iter().zip(inputs) {
        let Some(input) = input else { continue };
        let participant = session.participants.get_mut(id).unwrap();
        let encoded: Vec<_> = input
            .iter()
            .map(|value| value.rem_euclid(FIELD_MODULUS as i64))
            .collect();
        let masked = participant.create_masked_contribution(encoded, FIELD_MODULUS)?;
        // This API carries opaque commitment bytes; it does not authenticate
        // them. Do not infer authentication from this arithmetic regression.
        contributions.push(MaskedContribution::new(id.clone(), masked, Vec::new()));
        unmasking.push((id.clone(), participant.get_unmasking_values()?));
    }
    session.current_round = AggregationRound::ContributionSubmission;
    session.aggregate_contributions(contributions)?;
    assert_eq!(session.current_round, AggregationRound::Unmasking);
    let result = session.complete_aggregation(unmasking)?;
    assert_eq!(session.current_round, AggregationRound::Complete);
    Ok(decode_field(result))
}

#[test]
fn end_to_end_privacy_preserving_fleet_learning() {
    let epoch = SecurityEpoch::from_raw(5000);
    let parameters = PrivacyParameters::new(1_000_000, 10).unwrap();
    let mut aggregator = PrivacyPreservingAggregator::new(parameters, epoch);
    let mut noise = DeterministicTestNoiseGenerator::new();
    let local = [
        ([-150_000, -50_000, 400_000, -200_000], 900_000),
        ([450_000, -100_000, -150_000, -200_000], 850_000),
        ([50_000, 250_000, -100_000, -200_000], 700_000),
        ([150_000, 50_000, -50_000, -150_000], 600_000),
    ];
    let mut private = Vec::new();
    for (index, (values, weight)) in local.into_iter().enumerate() {
        let node = NodeId::new(format!("node-{index}"));
        aggregator
            .initialize_node_budget(node.clone(), 2_000_000, 20)
            .unwrap();
        let input = delta(values, weight, epoch);
        private.push(
            aggregator
                .make_delta_private(&node, input, "main-round".into(), &mut noise)
                .unwrap(),
        );
        let budget = aggregator.get_node_budget(&node).unwrap();
        assert_eq!(budget.consumed_epsilon_millionths, 1_000_000);
        assert_eq!(budget.consumed_delta_millionths, 10);
        assert_eq!(budget.round_consumptions.len(), 1);
    }
    let inputs: Vec<_> = private
        .iter()
        .map(|value| Some(weighted_input(value)))
        .collect();
    let reference = aggregator
        .aggregate_private_deltas(private, "main-round".into())
        .unwrap();
    let expected = vec![
        reference.aggregate_delta_benign_millionths,
        reference.aggregate_delta_anomalous_millionths,
        reference.aggregate_delta_malicious_millionths,
        reference.aggregate_delta_unknown_millionths,
    ];
    assert_eq!(reference.extension_id, "shared-extension");
    assert_eq!(reference.participant_count, 4);
    assert_eq!(reference.total_confidence_weight_millionths, 3_050_000);
    assert_eq!(aggregate_masked_inputs(&inputs, 3).unwrap(), expected);

    // A constant-returning stand-in cannot satisfy this changed-input probe.
    let mut changed = inputs.clone();
    let contribution = changed[0].as_mut().unwrap();
    contribution[0] += 123_456;
    contribution[1] -= 123_456;
    let mut expected_changed = expected.clone();
    expected_changed[0] += 123_456;
    expected_changed[1] -= 123_456;
    let actual_changed = aggregate_masked_inputs(&changed, 3).unwrap();
    assert_eq!(actual_changed, expected_changed);
    assert_ne!(actual_changed, expected);
}

#[test]
fn privacy_budget_exhaustion_handling() {
    let epoch = SecurityEpoch::from_raw(1000);
    let parameters = PrivacyParameters::new(2_000_000, 10).unwrap();
    let mut aggregator = PrivacyPreservingAggregator::new(parameters, epoch);
    let node = NodeId::new("budget-node");
    aggregator
        .initialize_node_budget(node.clone(), 3_000_000, 100)
        .unwrap();
    let input = delta([-100_000, 0, 100_000, 0], 800_000, epoch);
    let mut noise = DeterministicTestNoiseGenerator::new();
    aggregator
        .make_delta_private(&node, input.clone(), "first".into(), &mut noise)
        .unwrap();
    let before = aggregator.get_node_budget(&node).unwrap().clone();
    assert_eq!(before.remaining_epsilon(), 1_000_000);
    assert_eq!(before.remaining_delta(), 90);
    assert_eq!(
        aggregator.make_delta_private(&node, input, "second".into(), &mut noise,),
        Err(DifferentialPrivacyError::InsufficientBudget)
    );
    assert_eq!(aggregator.get_node_budget(&node).unwrap(), &before);

    // Delta is a separate composition limit even with epsilon remaining.
    let delta_limited = NodeId::new("delta-limited-node");
    aggregator
        .initialize_node_budget(delta_limited.clone(), 6_000_000, 10)
        .unwrap();
    let input = delta([-100_000, 0, 100_000, 0], 800_000, epoch);
    aggregator
        .make_delta_private(&delta_limited, input.clone(), "first".into(), &mut noise)
        .unwrap();
    let before = aggregator.get_node_budget(&delta_limited).unwrap().clone();
    assert_eq!(before.remaining_epsilon(), 4_000_000);
    assert_eq!(before.remaining_delta(), 0);
    assert_eq!(
        aggregator.make_delta_private(&delta_limited, input, "second".into(), &mut noise),
        Err(DifferentialPrivacyError::InsufficientBudget)
    );
    assert_eq!(aggregator.get_node_budget(&delta_limited).unwrap(), &before);
}

#[test]
fn secure_aggregation_dropout_resilience() {
    let inputs = vec![
        Some(vec![-100_000, 200_000, -300_000, 400_000]),
        Some(vec![150_000, -250_000, 350_000, -450_000]),
        Some(vec![20_000, 30_000, -40_000, -10_000]),
        None,
    ];
    assert_eq!(
        aggregate_masked_inputs(&inputs, 3).unwrap(),
        vec![70_000, -20_000, 10_000, -60_000]
    );
    let mut insufficient = inputs;
    insufficient[2] = None;
    assert_eq!(
        aggregate_masked_inputs(&insufficient, 3),
        Err(SecureAggregationError::InsufficientContributions)
    );
}

#[test]
fn privacy_verification_e2e() {
    // Corrupted exchange data must be rejected by the actual participant API.
    let alice_id = ParticipantId("alice".into());
    let bob_id = ParticipantId("bob".into());
    let mut alice = Participant::new(alice_id.clone());
    let mut bob = Participant::new(bob_id.clone());
    let mut rng = StdRng::seed_from_u64(41);
    let mut share = alice
        .generate_secret_shares(
            std::slice::from_ref(&bob_id),
            DIMENSION,
            FIELD_MODULUS,
            &mut rng,
        )
        .unwrap()
        .remove(0);
    share.share_values[0] ^= 1;
    assert_eq!(
        bob.receive_secret_share(alice_id, share),
        Err(SecureAggregationError::InvalidShare)
    );
    assert!(bob.received_shares.is_empty());
    assert_eq!(
        bob.create_masked_contribution(vec![0; DIMENSION], FIELD_MODULUS),
        Err(SecureAggregationError::InvalidState)
    );

    let protocol = AggregationProtocol::new(SecurityParameters {
        field_modulus: FIELD_MODULUS,
        min_participants: 2,
        dropout_threshold: 1,
        vector_dimension: DIMENSION,
    });
    let malformed = vec![
        MaskedContribution::new(bob_id, vec![1; DIMENSION - 1], Vec::new()),
        MaskedContribution::new(
            ParticipantId("charlie".into()),
            vec![2; DIMENSION],
            Vec::new(),
        ),
    ];
    assert_eq!(
        protocol.validate_contributions(&malformed),
        Err(SecureAggregationError::InvalidDimension)
    );
}

#[test]
fn duplicate_round_is_rejected_without_budget_burn() {
    let epoch = SecurityEpoch::from_raw(3000);
    let parameters = PrivacyParameters::new(1_000_000, 10).unwrap();
    let mut aggregator = PrivacyPreservingAggregator::new(parameters, epoch);
    let node = NodeId::new("sensitive-node");
    let input = delta([-100_000, 0, 100_000, 0], 950_000, epoch);
    let mut noise = DeterministicTestNoiseGenerator::new();
    assert_eq!(
        aggregator.make_delta_private(&node, input.clone(), "once".into(), &mut noise,),
        Err(DifferentialPrivacyError::NodeBudgetNotFound)
    );
    aggregator
        .initialize_node_budget(node.clone(), 3_000_000, 100)
        .unwrap();
    aggregator
        .make_delta_private(&node, input.clone(), "once".into(), &mut noise)
        .unwrap();
    let before = aggregator.get_node_budget(&node).unwrap().clone();
    assert_eq!(
        aggregator.make_delta_private(&node, input, "once".into(), &mut noise,),
        Err(DifferentialPrivacyError::DuplicateRoundAllocation)
    );
    assert_eq!(aggregator.get_node_budget(&node).unwrap(), &before);
}
