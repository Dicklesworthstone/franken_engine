//! Public aggregation boundary and fixed-point regression tests.
//!
//! Handcrafted releases below test aggregation arithmetic and validation. They
//! are not evidence of a noise generator's privacy or randomness guarantees.

use frankenengine_engine::bayesian_posterior::Posterior;
use frankenengine_engine::differential_privacy_posterior::{
    DifferentialPrivacyError, PrivacyParameters, PrivacyPreservingAggregator, PrivatePosteriorDelta,
};
use frankenengine_engine::federated_posterior_aggregation::{
    AggregatedPosteriorUpdate, PosteriorDelta,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn parameters() -> PrivacyParameters {
    PrivacyParameters::new(1_000_000, 10).unwrap()
}

fn aggregator() -> PrivacyPreservingAggregator {
    PrivacyPreservingAggregator::new(parameters(), SecurityEpoch::from_raw(7))
}

fn release(components: [i64; 4], weight: u64) -> PrivatePosteriorDelta {
    let privacy_params = parameters();
    PrivatePosteriorDelta {
        base_delta: PosteriorDelta {
            extension_id: "extension".into(),
            delta_benign_millionths: components[0],
            delta_anomalous_millionths: components[1],
            delta_malicious_millionths: components[2],
            delta_unknown_millionths: components[3],
            confidence_weight_millionths: weight,
            evidence_hash: ContentHash::compute(b"untrusted-provenance-is-not-used"),
            epoch: SecurityEpoch::from_raw(7),
        },
        privacy_params,
        noise_scale_millionths: privacy_params.gaussian_noise_scale(4_000_000).unwrap(),
        round_id: "round-7".into(),
    }
}

fn aggregate(
    releases: Vec<PrivatePosteriorDelta>,
    now_ns: u64,
) -> Result<AggregatedPosteriorUpdate, DifferentialPrivacyError> {
    aggregator().aggregate_private_deltas(releases, "round-7".into(), now_ns)
}

#[test]
fn weighted_releases_apply_the_exact_convex_combination() {
    let result = aggregate(
        vec![
            release([-100_000, 50_000, 30_000, 20_000], 750_000),
            release([0, -50_000, 70_000, -20_000], 250_000),
        ],
        123,
    )
    .unwrap();
    assert_eq!(result.aggregate_delta_benign_millionths, -75_000_000_000);
    assert_eq!(result.aggregate_delta_anomalous_millionths, 25_000_000_000);
    assert_eq!(result.aggregate_delta_malicious_millionths, 40_000_000_000);
    assert_eq!(result.aggregate_delta_unknown_millionths, 10_000_000_000);
    assert_eq!(result.total_confidence_weight_millionths, 1_000_000);
    assert_eq!(result.participant_count, 2);
    assert_eq!(result.aggregation_timestamp_ns, 123);
    assert_eq!(
        result.apply_to_posterior(&Posterior::uniform()),
        Posterior {
            p_benign: 175_000,
            p_anomalous: 275_000,
            p_malicious: 290_000,
            p_unknown: 260_000,
        }
    );
}

#[test]
fn input_permutation_replays_byte_identically() {
    let left = release([-100, 50, 30, 20], 750_000);
    let right = release([0, -50, 70, -20], 250_000);
    let forward = aggregate(vec![left.clone(), right.clone()], 456).unwrap();
    let reverse = aggregate(vec![right, left], 456).unwrap();
    assert_eq!(forward, reverse);
    assert_eq!(
        serde_json::to_vec(&forward).unwrap(),
        serde_json::to_vec(&reverse).unwrap()
    );
}

#[test]
fn fingerprint_binds_released_contents_even_when_aggregate_is_identical() {
    let first = aggregate(
        vec![
            release([100, -100, 0, 0], 500_000),
            release([-100, 100, 0, 0], 500_000),
        ],
        789,
    )
    .unwrap();
    let second = aggregate(
        vec![
            release([200, -200, 0, 0], 500_000),
            release([-200, 200, 0, 0], 500_000),
        ],
        789,
    )
    .unwrap();
    assert_eq!(
        first.aggregate_delta_benign_millionths,
        second.aggregate_delta_benign_millionths
    );
    assert_eq!(
        first.total_confidence_weight_millionths,
        second.total_confidence_weight_millionths
    );
    assert_ne!(first.evidence_fingerprint, second.evidence_fingerprint);
}

#[test]
fn fingerprint_preserves_multiplicity_and_caller_timestamp() {
    let item = release([100, -100, 0, 0], 500_000);
    let single = aggregate(vec![item.clone()], 789).unwrap();
    let repeated = aggregate(vec![item.clone(), item.clone()], 789).unwrap();
    let later = aggregate(vec![item], 790).unwrap();
    assert_ne!(single.evidence_fingerprint, repeated.evidence_fingerprint);
    assert_ne!(single.evidence_fingerprint, later.evidence_fingerprint);
    assert_eq!(repeated.participant_count, 2);
}

#[test]
fn fingerprint_ignores_claimed_raw_evidence_hash() {
    let left = release([100, -100, 0, 0], 500_000);
    let mut right = left.clone();
    right.base_delta.evidence_hash = ContentHash::compute(b"different-secret-evidence");
    assert_eq!(
        aggregate(vec![left], 789).unwrap(),
        aggregate(vec![right], 789).unwrap()
    );
}

#[test]
fn cross_round_extension_and_epoch_releases_are_rejected() {
    let valid = release([100, -100, 0, 0], 500_000);
    let mut wrong_round = valid.clone();
    wrong_round.round_id = "other-round".into();
    let mut wrong_extension = valid.clone();
    wrong_extension.base_delta.extension_id = "other-extension".into();
    let mut wrong_epoch = valid.clone();
    wrong_epoch.base_delta.epoch = SecurityEpoch::from_raw(8);
    for invalid in [wrong_round, wrong_extension, wrong_epoch] {
        assert_eq!(
            aggregate(vec![valid.clone(), invalid], 789),
            Err(DifferentialPrivacyError::InconsistentAggregationMetadata)
        );
    }
    let mut stale = valid;
    stale.base_delta.epoch = SecurityEpoch::from_raw(6);
    assert_eq!(
        aggregate(vec![stale], 789),
        Err(DifferentialPrivacyError::InconsistentAggregationMetadata)
    );
}

#[test]
fn confidence_weights_are_positive_bounded_public_ratios() {
    for weight in [0, 1_000_001, u64::MAX] {
        assert_eq!(
            aggregate(vec![release([100, -100, 0, 0], weight)], 789),
            Err(DifferentialPrivacyError::InvalidConfidenceWeight)
        );
    }
}

#[test]
fn malformed_noise_and_privacy_metadata_are_rejected() {
    let valid = release([100, -100, 0, 0], 500_000);
    let mut wrong_scale = valid.clone();
    wrong_scale.noise_scale_millionths -= 1;
    assert_eq!(
        aggregate(vec![wrong_scale], 789),
        Err(DifferentialPrivacyError::NoiseScaleMismatch)
    );
    let mut invalid_epsilon = valid.clone();
    invalid_epsilon.privacy_params.epsilon_millionths = 0;
    assert_eq!(
        aggregate(vec![invalid_epsilon], 789),
        Err(DifferentialPrivacyError::InvalidEpsilon)
    );
    let mut other_parameters = valid.clone();
    other_parameters.privacy_params = PrivacyParameters::new(500_000, 10).unwrap();
    assert_eq!(
        aggregate(vec![valid, other_parameters], 789),
        Err(DifferentialPrivacyError::InconsistentPrivacyParams)
    );
}

#[test]
fn nonconserving_release_is_rejected_without_wrapping_the_sum() {
    for components in [
        [1, 0, 0, 0],
        [i64::MAX, i64::MAX, i64::MAX, i64::MAX],
        [i64::MIN, i64::MIN, i64::MIN, i64::MIN],
    ] {
        assert_eq!(
            aggregate(vec![release(components, 500_000)], 789),
            Err(DifferentialPrivacyError::InvalidPosteriorDelta)
        );
    }
}

#[test]
fn unrepresentable_weighted_numerators_fail_without_saturation() {
    for components in [[i64::MAX, -i64::MAX, 0, 0], [i64::MIN, i64::MAX, 1, 0]] {
        assert_eq!(
            aggregate(vec![release(components, 1_000_000)], 789),
            Err(DifferentialPrivacyError::AggregationOverflow)
        );
    }
    // The same exact values remain admissible when their weighted numerator
    // fits the transport representation.
    let exact = aggregate(vec![release([i64::MIN, i64::MAX, 1, 0], 1)], 789).unwrap();
    assert_eq!(exact.aggregate_delta_benign_millionths, i64::MIN);
    assert_eq!(exact.aggregate_delta_anomalous_millionths, i64::MAX);
    assert!(exact.apply_to_posterior(&Posterior::uniform()).is_valid());
}

#[test]
fn empty_inputs_and_empty_public_identities_are_rejected() {
    assert_eq!(
        aggregate(Vec::new(), 789),
        Err(DifferentialPrivacyError::EmptyAggregation)
    );
    let valid = release([100, -100, 0, 0], 500_000);
    assert_eq!(
        aggregator().aggregate_private_deltas(vec![valid.clone()], String::new(), 789),
        Err(DifferentialPrivacyError::InconsistentAggregationMetadata)
    );
    let mut anonymous = valid;
    anonymous.base_delta.extension_id.clear();
    assert_eq!(
        aggregate(vec![anonymous], 789),
        Err(DifferentialPrivacyError::InconsistentAggregationMetadata)
    );
}
