#![forbid(unsafe_code)]
//! Public Gaussian calibration, posterior-release and budget lifecycle tests.
//! Deterministic noise makes these reproducible functional regressions, not
//! empirical or cryptographic proof of a production privacy guarantee.

use std::collections::BTreeMap;

use frankenengine_engine::differential_privacy_posterior::{
    DeterministicTestNoiseGenerator, DifferentialPrivacyError, PrivacyBudget, PrivacyParameters,
    PrivacyPreservingAggregator, PrivatePosteriorDelta,
};
use frankenengine_engine::federated_posterior_aggregation::{
    LocalPosteriorProvider, PosteriorDelta,
};
use frankenengine_engine::fleet_immune_protocol::NodeId;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// Temporary type definitions for test compilation
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RiskLevel {
    Benign,
    Anomalous,
    Malicious,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Timestamp(#[allow(dead_code)] u64);

impl Timestamp {
    pub fn from_millis(millis: u64) -> Self {
        Self(millis)
    }
}

/// Exercise charged per-node perturbations and a shared-round aggregation.
#[test]
fn differential_privacy_protects_individual_contributions() {
    let epoch = SecurityEpoch::from_raw(1000);
    let privacy_params = PrivacyParameters::new(1_000_000, 10).unwrap(); // 1.0ε, 1e-5δ in millionths
    let privacy_budget = PrivacyBudget::new(10_000_000, 100, epoch).unwrap(); // 10.0ε, 1e-4δ in millionths
    let mut aggregator = PrivacyPreservingAggregator::new(privacy_params, epoch);

    // Create multiple local posterior providers simulating fleet nodes
    let node1 = NodeId::new("node_1".to_string());
    let node2 = NodeId::new("node_2".to_string());
    let node3 = NodeId::new("node_3".to_string());
    let _timestamp = Timestamp::from_millis(1640995200000);
    for node in [&node1, &node2, &node3] {
        aggregator
            .initialize_node_budget(
                node.clone(),
                privacy_budget.total_epsilon_millionths,
                privacy_budget.total_delta_millionths,
            )
            .unwrap();
    }

    // Node 1: High confidence in malicious classification
    let mut posterior1 = BTreeMap::new();
    posterior1.insert(RiskLevel::Benign, 100_000); // 10%
    posterior1.insert(RiskLevel::Anomalous, 150_000); // 15%
    posterior1.insert(RiskLevel::Malicious, 700_000); // 70%
    posterior1.insert(RiskLevel::Unknown, 50_000); // 5%

    let delta1 = PosteriorDelta {
        extension_id: "test_extension".to_string(),
        // Changes from a public uniform prior, not absolute probabilities.
        delta_benign_millionths: 250_000,
        delta_anomalous_millionths: -50_000,
        delta_malicious_millionths: 0,
        delta_unknown_millionths: -200_000,
        confidence_weight_millionths: 950_000,
        evidence_hash: ContentHash::compute(b"delta1_evidence"),
        epoch,
    };

    // Node 2: Moderate confidence in anomalous classification
    let mut posterior2 = BTreeMap::new();
    posterior2.insert(RiskLevel::Benign, 300_000); // 30%
    posterior2.insert(RiskLevel::Anomalous, 500_000); // 50%
    posterior2.insert(RiskLevel::Malicious, 150_000); // 15%
    posterior2.insert(RiskLevel::Unknown, 50_000); // 5%

    let delta2 = PosteriorDelta {
        extension_id: "test_extension".to_string(),
        delta_benign_millionths: 50_000,
        delta_anomalous_millionths: 250_000,
        delta_malicious_millionths: -100_000,
        delta_unknown_millionths: -200_000,
        confidence_weight_millionths: 750_000,
        evidence_hash: ContentHash::compute(b"delta2_evidence"),
        epoch,
    };

    // Node 3: High confidence in benign classification
    let mut posterior3 = BTreeMap::new();
    posterior3.insert(RiskLevel::Benign, 800_000); // 80%
    posterior3.insert(RiskLevel::Anomalous, 100_000); // 10%
    posterior3.insert(RiskLevel::Malicious, 50_000); // 5%
    posterior3.insert(RiskLevel::Unknown, 50_000); // 5%

    let delta3 = PosteriorDelta {
        extension_id: "test_extension".to_string(),
        delta_benign_millionths: 550_000,
        delta_anomalous_millionths: -150_000,
        delta_malicious_millionths: -180_000,
        delta_unknown_millionths: -220_000,
        confidence_weight_millionths: 900_000,
        evidence_hash: ContentHash::compute(b"delta3_evidence"),
        epoch,
    };

    // Apply differential privacy to individual contributions
    let mut noise_gen = DeterministicTestNoiseGenerator::new();
    let private_delta1 = aggregator
        .make_delta_private(&node1, delta1, "test_round".to_string(), &mut noise_gen)
        .expect("Privacy budget should be sufficient");

    let private_delta2 = aggregator
        .make_delta_private(&node2, delta2, "test_round".to_string(), &mut noise_gen)
        .expect("Privacy budget should be sufficient");

    let private_delta3 = aggregator
        .make_delta_private(&node3, delta3, "test_round".to_string(), &mut noise_gen)
        .expect("Privacy budget should be sufficient");

    // Aggregate using privacy-preserving aggregator
    let private_deltas = vec![private_delta1, private_delta2, private_delta3];
    let aggregated = aggregator
        .aggregate_private_deltas(private_deltas, "test_round".to_string())
        .expect("Aggregation should succeed");

    // Verify the aggregation preserves essential properties
    assert_eq!(aggregated.participant_count, 3);
    assert!(!aggregated.extension_id.is_empty());

    // A probability delta conserves mass exactly; it is not a distribution.
    let total_probability: u64 = (aggregated.aggregate_delta_benign_millionths
        + aggregated.aggregate_delta_anomalous_millionths
        + aggregated.aggregate_delta_malicious_millionths
        + aggregated.aggregate_delta_unknown_millionths)
        .unsigned_abs();
    assert_eq!(total_probability, 0, "Noisy deltas must conserve mass");

    // Verify aggregated deltas are present
    assert_ne!(aggregated.aggregate_delta_benign_millionths, 0);
    assert!(aggregated.total_confidence_weight_millionths > 0);

    // Inspect the actual ledgers charged by the three public API calls.
    for node in [&node1, &node2, &node3] {
        let spent = aggregator.get_node_budget(node).unwrap();
        assert_eq!(spent.consumed_epsilon_millionths, 1_000_000);
        assert_eq!(spent.consumed_delta_millionths, 10);
        assert_eq!(spent.remaining_epsilon(), 9_000_000);
        assert_eq!(spent.round_consumptions.len(), 1);
    }
}

/// Test that privacy budget enforcement prevents excessive consumption
#[test]
fn privacy_budget_enforcement_prevents_excessive_consumption() {
    let epoch = SecurityEpoch::from_raw(1000);
    let parameters = PrivacyParameters::new(1_000_000, 10).unwrap();
    let mut aggregator = PrivacyPreservingAggregator::new(parameters, epoch);
    let node = NodeId::new("budget-node");
    aggregator
        .initialize_node_budget(node.clone(), 3_000_000, 100)
        .unwrap();
    let delta = PosteriorDelta {
        extension_id: "test_extension_budget".to_string(),
        delta_benign_millionths: 350_000,
        delta_anomalous_millionths: 50_000,
        delta_malicious_millionths: -150_000,
        delta_unknown_millionths: -250_000,
        confidence_weight_millionths: 800_000,
        evidence_hash: ContentHash::compute(b"local-budget-evidence"),
        epoch,
    };
    let mut noise = DeterministicTestNoiseGenerator::new();
    for index in 0..3 {
        aggregator
            .make_delta_private(&node, delta.clone(), format!("round-{index}"), &mut noise)
            .unwrap();
    }
    let spent = aggregator.get_node_budget(&node).unwrap().clone();
    assert_eq!(spent.consumed_epsilon_millionths, 3_000_000);
    assert_eq!(spent.consumed_delta_millionths, 30);
    assert_eq!(spent.round_consumptions.len(), 3);
    assert_eq!(
        aggregator.make_delta_private(&node, delta, "refused".into(), &mut noise),
        Err(DifferentialPrivacyError::InsufficientBudget)
    );
    assert_eq!(aggregator.get_node_budget(&node), Some(&spent));
}

/// Test deterministic perturbation, calibration and exact mass conservation.
#[test]
fn noise_injection_maintains_differential_privacy() {
    let epoch = SecurityEpoch::from_raw(1000);
    let privacy_params = PrivacyParameters::new(1_000_000, 10).unwrap(); // 1.0ε, 1e-5δ in millionths
    let _privacy_budget = PrivacyBudget::new(10_000_000, 100, epoch).unwrap(); // 10.0ε, 1e-4δ in millionths

    let node = NodeId::new("test_node".to_string());
    let _timestamp = Timestamp::from_millis(1640995200000);

    // Create a deterministic posterior
    let mut original_posterior = BTreeMap::new();
    original_posterior.insert(RiskLevel::Benign, 600_000); // 60%
    original_posterior.insert(RiskLevel::Malicious, 400_000); // 40%

    let delta = PosteriorDelta {
        extension_id: node.as_str().to_string(),
        delta_benign_millionths: *original_posterior.get(&RiskLevel::Benign).unwrap_or(&0)
            as i64
            - 250_000,
        delta_anomalous_millionths: *original_posterior.get(&RiskLevel::Anomalous).unwrap_or(&0)
            as i64
            - 250_000,
        delta_malicious_millionths: *original_posterior.get(&RiskLevel::Malicious).unwrap_or(&0)
            as i64
            - 250_000,
        delta_unknown_millionths: *original_posterior.get(&RiskLevel::Unknown).unwrap_or(&0)
            as i64
            - 250_000,
        confidence_weight_millionths: 900_000,
        evidence_hash: ContentHash::compute(b"test_evidence_1"),
        epoch,
    };

    // Repeating the same injected sampler sequence reproduces the coordinates.
    let mut noise_generator1 = DeterministicTestNoiseGenerator::new();
    let private_delta1 = PrivatePosteriorDelta::from_delta(
        delta.clone(),
        privacy_params,
        "test_round_1".to_string(),
        &mut noise_generator1,
    )
    .unwrap();

    let mut noise_generator2 = DeterministicTestNoiseGenerator::new();
    let private_delta2 = PrivatePosteriorDelta::from_delta(
        delta.clone(),
        privacy_params,
        "test_round_2".to_string(),
        &mut noise_generator2,
    )
    .unwrap();

    // Verify noise was applied (values should differ from original)
    let benign1 = private_delta1.base_delta.delta_benign_millionths;
    let benign2 = private_delta2.base_delta.delta_benign_millionths;
    let original_benign = delta.delta_benign_millionths;

    // At least one should differ significantly from original due to noise
    let differs1 = (benign1 - original_benign).abs() > 10_000; // >1% difference
    let differs2 = (benign2 - original_benign).abs() > 10_000;
    assert!(
        differs1 || differs2,
        "Noise should cause significant deviation from original values"
    );

    // This is an injected deterministic test sampler, not a randomness test.
    assert_eq!(benign1, benign2);
    assert_eq!(private_delta1.noise_scale_millionths, private_delta2.noise_scale_millionths);
    assert!(private_delta1.noise_scale_millionths >= 19_379_222);

    // Verify probability normalization is maintained
    let total1: u64 = (private_delta1.base_delta.delta_benign_millionths
        + private_delta1.base_delta.delta_anomalous_millionths
        + private_delta1.base_delta.delta_malicious_millionths
        + private_delta1.base_delta.delta_unknown_millionths)
        .unsigned_abs();
    let total2: u64 = (private_delta2.base_delta.delta_benign_millionths
        + private_delta2.base_delta.delta_anomalous_millionths
        + private_delta2.base_delta.delta_malicious_millionths
        + private_delta2.base_delta.delta_unknown_millionths)
        .unsigned_abs();

    assert_eq!(total1, 0, "First noisy delta must conserve mass");
    assert_eq!(total2, 0, "Replayed noisy delta must conserve mass");
}

/// Test integration with federated aggregation pipeline
#[test]
fn integration_with_federated_aggregation_pipeline() {
    let epoch = SecurityEpoch::from_raw(2000);
    let privacy_params = PrivacyParameters::new(500_000, 1).unwrap(); // 0.5ε, 1e-6δ in millionths
    let _privacy_budget = PrivacyBudget::new(5_000_000, 10, epoch).unwrap(); // 5.0ε, 1e-5δ in millionths
    let aggregator = PrivacyPreservingAggregator::new(privacy_params, epoch);
    let from_uniform_prior = |mut delta: PosteriorDelta| {
        delta.delta_benign_millionths -= 250_000;
        delta.delta_anomalous_millionths -= 250_000;
        delta.delta_malicious_millionths -= 250_000;
        delta.delta_unknown_millionths -= 250_000;
        delta
    };

    // Create local providers for different fleet zones
    let _provider_us_east =
        LocalPosteriorProvider::new(NodeId::new("us-east-1".to_string()), epoch);
    let _provider_us_west =
        LocalPosteriorProvider::new(NodeId::new("us-west-2".to_string()), epoch);
    let _provider_eu_central =
        LocalPosteriorProvider::new(NodeId::new("eu-central-1".to_string()), epoch);
    let _timestamp = Timestamp::from_millis(1640995300000);

    // Each provider generates local posterior deltas
    let mut posterior_us_east = BTreeMap::new();
    posterior_us_east.insert(RiskLevel::Benign, 700_000);
    posterior_us_east.insert(RiskLevel::Anomalous, 200_000);
    posterior_us_east.insert(RiskLevel::Malicious, 100_000);

    let delta_us_east = PosteriorDelta {
        extension_id: "shared_extension".to_string(),
        delta_benign_millionths: *posterior_us_east.get(&RiskLevel::Benign).unwrap_or(&0) as i64,
        delta_anomalous_millionths: *posterior_us_east.get(&RiskLevel::Anomalous).unwrap_or(&0)
            as i64,
        delta_malicious_millionths: *posterior_us_east.get(&RiskLevel::Malicious).unwrap_or(&0)
            as i64,
        delta_unknown_millionths: *posterior_us_east.get(&RiskLevel::Unknown).unwrap_or(&0) as i64,
        confidence_weight_millionths: 850_000,
        evidence_hash: ContentHash::compute(b"us_east_evidence"),
        epoch,
    };

    let mut posterior_us_west = BTreeMap::new();
    posterior_us_west.insert(RiskLevel::Benign, 300_000);
    posterior_us_west.insert(RiskLevel::Anomalous, 400_000);
    posterior_us_west.insert(RiskLevel::Malicious, 300_000);

    let delta_us_west = PosteriorDelta {
        extension_id: "shared_extension".to_string(),
        delta_benign_millionths: *posterior_us_west.get(&RiskLevel::Benign).unwrap_or(&0) as i64,
        delta_anomalous_millionths: *posterior_us_west.get(&RiskLevel::Anomalous).unwrap_or(&0)
            as i64,
        delta_malicious_millionths: *posterior_us_west.get(&RiskLevel::Malicious).unwrap_or(&0)
            as i64,
        delta_unknown_millionths: *posterior_us_west.get(&RiskLevel::Unknown).unwrap_or(&0) as i64,
        confidence_weight_millionths: 750_000,
        evidence_hash: ContentHash::compute(b"us_west_evidence"),
        epoch,
    };

    let mut posterior_eu_central = BTreeMap::new();
    posterior_eu_central.insert(RiskLevel::Benign, 800_000);
    posterior_eu_central.insert(RiskLevel::Anomalous, 150_000);
    posterior_eu_central.insert(RiskLevel::Malicious, 50_000);

    let delta_eu_central = PosteriorDelta {
        extension_id: "shared_extension".to_string(),
        delta_benign_millionths: *posterior_eu_central.get(&RiskLevel::Benign).unwrap_or(&0) as i64,
        delta_anomalous_millionths: *posterior_eu_central
            .get(&RiskLevel::Anomalous)
            .unwrap_or(&0) as i64,
        delta_malicious_millionths: *posterior_eu_central
            .get(&RiskLevel::Malicious)
            .unwrap_or(&0) as i64,
        delta_unknown_millionths: *posterior_eu_central.get(&RiskLevel::Unknown).unwrap_or(&0)
            as i64,
        confidence_weight_millionths: 900_000,
        evidence_hash: ContentHash::compute(b"eu_central_evidence"),
        epoch,
    };

    // Convert to private deltas
    let mut noise_gen_east = DeterministicTestNoiseGenerator::new();
    let mut noise_gen_west = DeterministicTestNoiseGenerator::new();
    let mut noise_gen_central = DeterministicTestNoiseGenerator::new();

    let private_deltas = vec![
        PrivatePosteriorDelta::from_delta(
            from_uniform_prior(delta_us_east),
            privacy_params,
            "test_round".to_string(),
            &mut noise_gen_east,
        )
        .unwrap(),
        PrivatePosteriorDelta::from_delta(
            from_uniform_prior(delta_us_west),
            privacy_params,
            "test_round".to_string(),
            &mut noise_gen_west,
        )
        .unwrap(),
        PrivatePosteriorDelta::from_delta(
            from_uniform_prior(delta_eu_central),
            privacy_params,
            "test_round".to_string(),
            &mut noise_gen_central,
        )
        .unwrap(),
    ];

    // Perform privacy-preserving aggregation
    let final_aggregate = aggregator
        .aggregate_private_deltas(private_deltas, "test_round".to_string())
        .expect("Privacy-preserving aggregation should succeed");

    // Verify the aggregated result maintains fleet-wide properties
    assert_eq!(final_aggregate.participant_count, 3);
    assert!(!final_aggregate.extension_id.is_empty());

    // Verify combined confidence reflects weighted average with privacy noise
    assert!(
        final_aggregate.total_confidence_weight_millionths >= 700_000
            && final_aggregate.total_confidence_weight_millionths <= 3_000_000,
        "Aggregated confidence should be reasonable weighted total: {}",
        final_aggregate.total_confidence_weight_millionths
    );

    // Verify probability distribution validity
    let total_probability: u64 = (final_aggregate.aggregate_delta_benign_millionths
        + final_aggregate.aggregate_delta_anomalous_millionths
        + final_aggregate.aggregate_delta_malicious_millionths
        + final_aggregate.aggregate_delta_unknown_millionths)
        .unsigned_abs();
    assert_eq!(total_probability, 0, "Weighted deltas must conserve mass");
    // Noisy deltas need not be positive or bounded by one probability unit.
    // Their application must still produce a normalized posterior.
    let updated = final_aggregate.apply_to_posterior(
        &frankenengine_engine::bayesian_posterior::Posterior::uniform(),
    );
    assert!(updated.is_valid());
}

/// Test privacy parameter validation and error handling
#[test]
fn privacy_parameter_validation_and_error_handling() {
    let epoch = SecurityEpoch::from_raw(1000);
    // Test invalid epsilon (negative - should use 0 since u64 can't be negative)
    assert!(PrivacyParameters::new(0, 10).is_err()); // 0 epsilon is invalid

    // The finite Gaussian mechanism requires positive delta too.
    assert!(PrivacyParameters::new(100_000, 0).is_err());

    // Test invalid delta (too large)
    assert!(PrivacyParameters::new(1_000_000, 2_000_000).is_err()); // >1.0 delta in millionths

    // Test invalid delta (>= 1.0)
    assert!(PrivacyParameters::new(1_000_000, 1_000_000).is_err()); // 1.0 delta
    assert!(PrivacyParameters::new(1_000_000, 1_500_000).is_err()); // 1.5 delta

    // Test valid parameters
    assert!(PrivacyParameters::new(100_000, 1).is_ok()); // 0.1ε, 1e-6δ
    assert!(PrivacyParameters::new(1_000_000, 100).is_ok()); // documented boundary
    assert!(PrivacyParameters::new(10_000_000, 1000).is_err());
    assert!(PrivacyParameters::new(1_000_000, 990_000).is_err());
    // Direct public-field/serde construction must not bypass operation checks.
    let raw: PrivacyParameters = serde_json::from_str(
        r#"{"epsilon_millionths":100000,"delta_millionths":0}"#,
    )
    .unwrap();
    assert_eq!(
        raw.gaussian_noise_scale(1_000_000),
        Err(DifferentialPrivacyError::InvalidDelta)
    );

    // Test budget initialization with invalid total budget
    let _valid_params = PrivacyParameters::new(1_000_000, 10).unwrap();

    // Invalid total epsilon (0)
    assert!(PrivacyBudget::new(0, 100, epoch).is_err());

    // Invalid total delta (too large)
    assert!(PrivacyBudget::new(5_000_000, 2_000_000, epoch).is_err());

    // Valid budget
    let budget = PrivacyBudget::new(5_000_000, 100, epoch).unwrap();
    assert!(budget.remaining_epsilon() > 0);
    assert!(budget.remaining_delta() > 0);
}

/// Test charged repeated releases and aggregation within one authorized epoch.
#[test]
fn noise_preserves_differential_privacy_across_rounds() {
    let epoch = SecurityEpoch::from_raw(3000);
    let parameters = PrivacyParameters::new(1_000_000, 10).unwrap();
    let mut aggregator = PrivacyPreservingAggregator::new(parameters, epoch);
    let nodes = [
        NodeId::new("consistent_node"),
        NodeId::new("varying_node"),
    ];
    for node in &nodes {
        aggregator
            .initialize_node_budget(node.clone(), 6_000_000, 100)
            .unwrap();
    }
    let mut noise = DeterministicTestNoiseGenerator::new();
    for round in 0..5 {
        let round_id = format!("round-{round}");
        let mut private_deltas = Vec::new();
        for (index, node) in nodes.iter().enumerate() {
            let change = if index == 0 { 100_000 } else { round * 20_000 };
            let delta = PosteriorDelta {
                extension_id: "shared-extension".to_string(),
                delta_benign_millionths: change,
                delta_anomalous_millionths: 0,
                delta_malicious_millionths: -change,
                delta_unknown_millionths: 0,
                confidence_weight_millionths: if index == 0 { 800_000 } else { 750_000 },
                evidence_hash: ContentHash::compute(format!("local-{round}-{index}").as_bytes()),
                epoch,
            };
            private_deltas.push(
                aggregator
                    .make_delta_private(node, delta, round_id.clone(), &mut noise)
                    .unwrap(),
            );
        }
        let aggregated = aggregator
            .aggregate_private_deltas(private_deltas, round_id)
            .unwrap();
        assert_eq!(aggregated.participant_count, 2);
        assert_eq!(aggregated.extension_id, "shared-extension");
        assert_eq!(aggregated.epoch, epoch);
        let total = i128::from(aggregated.aggregate_delta_benign_millionths)
            + i128::from(aggregated.aggregate_delta_anomalous_millionths)
            + i128::from(aggregated.aggregate_delta_malicious_millionths)
            + i128::from(aggregated.aggregate_delta_unknown_millionths);
        assert_eq!(total, 0, "round {round} must conserve probability mass");
    }
    for node in &nodes {
        let budget = aggregator.get_node_budget(node).unwrap();
        assert_eq!(budget.consumed_epsilon_millionths, 5_000_000);
        assert_eq!(budget.consumed_delta_millionths, 50);
        assert_eq!(budget.remaining_epsilon(), 1_000_000);
        assert_eq!(budget.round_consumptions.len(), 5);
    }
}
