#![forbid(unsafe_code)]
//! Reconstruction arithmetic and release-boundary regressions.
//!
//! These tests use actual bounded source deltas, charged releases, public
//! confidence weights and exact weighted subtraction. A zero-noise control
//! demonstrates successful reconstruction without perturbation. The injected
//! deterministic sampler exercises perturbed arithmetic and cannot certify
//! differential privacy, randomness, secure masking or collusion resistance.

use frankenengine_engine::differential_privacy_posterior::{
    DeterministicTestNoiseGenerator, DifferentialPrivacyError, NoiseGenerator, PrivacyParameters,
    PrivacyPreservingAggregator,
};
use frankenengine_engine::federated_posterior_aggregation::PosteriorDelta;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::{fleet_immune_protocol::NodeId, security_epoch::SecurityEpoch};

const AGGREGATION_TIME_NS: u64 = 1_640_995_200_000_000_000;
const EXTENSION_ID: &str = "reconstruction-regression";
const SENSITIVITY_MILLIONTHS: u64 = 4_000_000;

struct ZeroNoise;

impl NoiseGenerator for ZeroNoise {
    fn sample_gaussian(&mut self, scale_millionths: i64) -> i64 {
        assert!(scale_millionths > 0);
        0
    }
}

struct ReconstructionProbe {
    raw_remaining: [i128; 4],
    reconstructed_remaining: [i128; 4],
    noise_scale_millionths: u64,
}

fn source_delta(index: usize, attempt: usize, epoch: SecurityEpoch) -> PosteriorDelta {
    let change = 7_500 * (index % 11 + 1) as i64 + 1_000 * (attempt % 7) as i64;
    let half = change / 2;
    let quarter = change / 4;
    let delta = PosteriorDelta {
        extension_id: EXTENSION_ID.to_string(),
        delta_benign_millionths: change,
        delta_anomalous_millionths: -half,
        delta_malicious_millionths: -quarter,
        delta_unknown_millionths: -change + half + quarter,
        // The roster and weights are public, fixed inputs to each trial.
        confidence_weight_millionths: 600_000 + (index as u64 * 7_919 % 400_001),
        evidence_hash: ContentHash::compute(format!("local-evidence-{attempt}-{index}").as_bytes()),
        epoch,
    };
    assert!(delta.is_valid());
    delta
}

fn coordinates(delta: &PosteriorDelta) -> [i128; 4] {
    [
        i128::from(delta.delta_benign_millionths),
        i128::from(delta.delta_anomalous_millionths),
        i128::from(delta.delta_malicious_millionths),
        i128::from(delta.delta_unknown_millionths),
    ]
}

fn weighted(delta: &PosteriorDelta) -> [i128; 4] {
    coordinates(delta).map(|value| value * i128::from(delta.confidence_weight_millionths))
}

/// Recover the remaining honest subset after subtracting the colluding nodes'
/// actual released weighted contributions. All arithmetic stays in the same
/// units as the aggregate numerator. With one honest node, division by its
/// public weight recovers that node's released coordinates exactly.
fn run_reconstruction_probe(
    parameters: PrivacyParameters,
    fleet_size: usize,
    honest_count: usize,
    attempt: usize,
    noise: &mut dyn NoiseGenerator,
) -> ReconstructionProbe {
    assert!((1..=fleet_size).contains(&honest_count));
    let epoch = SecurityEpoch::from_raw(1000);
    let round_id = format!("reconstruction-round-{attempt}");
    let now_ns = AGGREGATION_TIME_NS + attempt as u64;
    let mut aggregator = PrivacyPreservingAggregator::new(parameters, epoch);
    let mut original = Vec::new();
    let mut released = Vec::new();

    for index in 0..fleet_size {
        let node = NodeId::new(format!("node-{index}"));
        aggregator
            .initialize_node_budget(
                node.clone(),
                parameters.epsilon_millionths,
                parameters.delta_millionths,
            )
            .unwrap();
        let delta = source_delta(index, attempt, epoch);
        let private = aggregator
            .make_delta_private(&node, delta.clone(), round_id.clone(), noise)
            .unwrap();
        let budget = aggregator.get_node_budget(&node).unwrap();
        assert_eq!(
            budget.consumed_epsilon_millionths,
            parameters.epsilon_millionths
        );
        assert_eq!(
            budget.consumed_delta_millionths,
            parameters.delta_millionths
        );
        assert_eq!(budget.remaining_epsilon(), 0);
        assert_eq!(budget.round_consumptions.len(), 1);
        original.push(delta);
        released.push(private);
    }

    let noise_scale = parameters
        .gaussian_noise_scale(SENSITIVITY_MILLIONTHS)
        .unwrap();
    assert!(
        released
            .iter()
            .all(|private| private.noise_scale_millionths == noise_scale)
    );
    let aggregate = aggregator
        .aggregate_private_deltas(released.clone(), round_id, now_ns)
        .unwrap();
    assert_eq!(aggregate.extension_id, EXTENSION_ID);
    assert_eq!(aggregate.epoch, epoch);
    assert_eq!(aggregate.aggregation_timestamp_ns, now_ns);
    assert_eq!(aggregate.participant_count as usize, fleet_size);
    assert_eq!(
        aggregate.total_confidence_weight_millionths,
        original
            .iter()
            .map(|delta| delta.confidence_weight_millionths)
            .sum::<u64>()
    );

    let mut reconstructed = [
        i128::from(aggregate.aggregate_delta_benign_millionths),
        i128::from(aggregate.aggregate_delta_anomalous_millionths),
        i128::from(aggregate.aggregate_delta_malicious_millionths),
        i128::from(aggregate.aggregate_delta_unknown_millionths),
    ];
    for private in &released[honest_count..] {
        for (remaining, known) in reconstructed.iter_mut().zip(weighted(&private.base_delta)) {
            *remaining -= known;
        }
    }

    let mut expected_released = [0i128; 4];
    let mut raw_remaining = [0i128; 4];
    for (delta, private) in original[..honest_count]
        .iter()
        .zip(&released[..honest_count])
    {
        for (index, (raw, noisy)) in weighted(delta)
            .into_iter()
            .zip(weighted(&private.base_delta))
            .enumerate()
        {
            raw_remaining[index] += raw;
            expected_released[index] += noisy;
        }
    }
    assert_eq!(reconstructed, expected_released);
    assert_eq!(reconstructed.iter().sum::<i128>(), 0);
    if honest_count == 1 {
        let weight = i128::from(original[0].confidence_weight_millionths);
        assert_eq!(
            reconstructed.map(|value| value / weight),
            coordinates(&released[0].base_delta)
        );
    }

    ReconstructionProbe {
        raw_remaining,
        reconstructed_remaining: reconstructed,
        noise_scale_millionths: noise_scale,
    }
}

/// Vary supported epsilon values and verify the corresponding release scales.
#[test]
fn reconstruction_attack_with_varying_epsilon() {
    let mut previous_scale = u64::MAX;
    for (epsilon, delta) in [(10_000, 1), (100_000, 10), (1_000_000, 10)] {
        let parameters = PrivacyParameters::new(epsilon, delta).unwrap();
        let probe = run_reconstruction_probe(
            parameters,
            5,
            1,
            0,
            &mut DeterministicTestNoiseGenerator::new(),
        );
        assert_ne!(probe.reconstructed_remaining, probe.raw_remaining);
        assert!(probe.noise_scale_millionths < previous_scale);
        previous_scale = probe.noise_scale_millionths;
    }
    // Epsilon 2 was previously unwrapped as a valid fixture, outside the
    // Gaussian calibration API's supported epsilon <= 1 domain.
    assert_eq!(
        PrivacyParameters::new(2_000_000, 100),
        Err(DifferentialPrivacyError::InvalidEpsilon)
    );
}

/// Fleet size does not change the exact units of the N-1 subtraction attack.
#[test]
fn reconstruction_attack_with_varying_fleet_size() {
    let parameters = PrivacyParameters::new(1_000_000, 10).unwrap();
    for fleet_size in [3, 7, 25, 100] {
        let probe = run_reconstruction_probe(
            parameters,
            fleet_size,
            1,
            fleet_size,
            &mut DeterministicTestNoiseGenerator::new(),
        );
        assert_ne!(probe.reconstructed_remaining, probe.raw_remaining);
    }
}

/// The control must recover raw data; the perturbation probe recovers only
/// the actual noisy release. Neither outcome is a statistical privacy proof.
#[test]
fn reconstruction_attack_against_differential_privacy() {
    let parameters = PrivacyParameters::new(1_000_000, 10).unwrap();
    let control = run_reconstruction_probe(parameters, 10, 1, 0, &mut ZeroNoise);
    assert_eq!(control.reconstructed_remaining, control.raw_remaining);

    let perturbed = run_reconstruction_probe(
        parameters,
        10,
        1,
        0,
        &mut DeterministicTestNoiseGenerator::new(),
    );
    assert_eq!(perturbed.raw_remaining, control.raw_remaining);
    assert_ne!(perturbed.reconstructed_remaining, perturbed.raw_remaining);
}

/// Invalid parameter cases must produce errors, not diagnostic-only warnings.
#[test]
fn weak_privacy_parameters_detected() {
    for (epsilon, delta, expected) in [
        (0, 10, DifferentialPrivacyError::InvalidEpsilon),
        (2_000_000, 100, DifferentialPrivacyError::InvalidEpsilon),
        (100_000_000, 10, DifferentialPrivacyError::InvalidEpsilon),
        (1_000_000, 0, DifferentialPrivacyError::InvalidDelta),
        (1_000_000, 500_000, DifferentialPrivacyError::InvalidDelta),
    ] {
        assert_eq!(PrivacyParameters::new(epsilon, delta), Err(expected));
    }
}

/// Retain the 90%, 50% and 30% honest-cohort scenarios, plus the N-1 case.
/// The assertion is exact residual arithmetic, not a collusion guarantee.
#[test]
fn reconstruction_attack_known_vectors() {
    let parameters = PrivacyParameters::new(500_000, 10).unwrap();
    for (scenario, honest_count) in [
        ("majority_honest", 18),
        ("half_compromised", 10),
        ("minority_honest", 6),
        ("one_honest", 1),
    ] {
        let probe = run_reconstruction_probe(
            parameters,
            20,
            honest_count,
            honest_count,
            &mut DeterministicTestNoiseGenerator::new(),
        );
        assert_ne!(
            probe.reconstructed_remaining, probe.raw_remaining,
            "{scenario}"
        );
    }
}

/// Exercise both the old small-epsilon fixture and the API's smallest
/// positive epsilon, using three participants and a positive minimum delta.
#[test]
fn minimum_privacy_requirements_enforced() {
    for epsilon in [10_000, 1] {
        let parameters = PrivacyParameters::new(epsilon, 1).unwrap();
        let probe = run_reconstruction_probe(
            parameters,
            3,
            1,
            0,
            &mut DeterministicTestNoiseGenerator::new(),
        );
        assert_eq!(
            probe.noise_scale_millionths,
            parameters
                .gaussian_noise_scale(SENSITIVITY_MILLIONTHS)
                .unwrap()
        );
        assert_ne!(probe.reconstructed_remaining, probe.raw_remaining);
    }
    assert_eq!(
        PrivacyParameters::new(0, 1),
        Err(DifferentialPrivacyError::InvalidEpsilon)
    );
}

/// Five releases consume the actual ledger; a sixth must fail atomically.
#[test]
fn privacy_budget_tracking_prevents_leakage() {
    let epoch = SecurityEpoch::from_raw(1000);
    let parameters = PrivacyParameters::new(1_000_000, 10).unwrap();
    let node = NodeId::new("budget-target");
    let mut aggregator = PrivacyPreservingAggregator::new(parameters, epoch);
    aggregator
        .initialize_node_budget(node.clone(), 5_000_000, 50)
        .unwrap();
    let delta = source_delta(0, 0, epoch);
    let mut noise = DeterministicTestNoiseGenerator::new();
    for round in 0..5 {
        aggregator
            .make_delta_private(&node, delta.clone(), format!("charged-{round}"), &mut noise)
            .unwrap();
    }
    let spent = aggregator.get_node_budget(&node).unwrap().clone();
    assert_eq!(spent.consumed_epsilon_millionths, 5_000_000);
    assert_eq!(spent.consumed_delta_millionths, 50);
    assert_eq!(spent.remaining_epsilon(), 0);
    assert_eq!(spent.remaining_delta(), 0);
    assert_eq!(spent.round_consumptions.len(), 5);
    assert_eq!(
        aggregator.make_delta_private(&node, delta, "refused-sixth".into(), &mut noise),
        Err(DifferentialPrivacyError::InsufficientBudget)
    );
    assert_eq!(aggregator.get_node_budget(&node), Some(&spent));
}

/// Retain the parameter, cohort-size and colluding-subset matrix as a
/// functional regression. Passing this suite does not authorize a privacy
/// claim or publication of a production mechanism.
#[test]
fn privacy_gate_comprehensive_validation() {
    for (epsilon, delta) in [(100_000, 1), (1_000_000, 10)] {
        let probe = run_reconstruction_probe(
            PrivacyParameters::new(epsilon, delta).unwrap(),
            10,
            1,
            0,
            &mut DeterministicTestNoiseGenerator::new(),
        );
        assert_ne!(probe.reconstructed_remaining, probe.raw_remaining);
    }
    assert_eq!(
        PrivacyParameters::new(2_000_000, 100),
        Err(DifferentialPrivacyError::InvalidEpsilon)
    );

    let parameters = PrivacyParameters::new(1_000_000, 10).unwrap();
    for fleet_size in [5, 10, 25, 50] {
        let probe = run_reconstruction_probe(
            parameters,
            fleet_size,
            1,
            fleet_size,
            &mut DeterministicTestNoiseGenerator::new(),
        );
        assert_ne!(probe.reconstructed_remaining, probe.raw_remaining);
    }
    let colluding_subset = run_reconstruction_probe(
        parameters,
        20,
        10,
        0,
        &mut DeterministicTestNoiseGenerator::new(),
    );
    assert_ne!(
        colluding_subset.reconstructed_remaining,
        colluding_subset.raw_remaining
    );
}
