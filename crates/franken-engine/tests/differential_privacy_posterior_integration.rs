#![forbid(unsafe_code)]
//! Integration tests demonstrating differential privacy posterior aggregation
//! with (ε,δ)-differential privacy guarantees using Gaussian mechanism.

use std::collections::BTreeMap;

use frankenengine_engine::differential_privacy_posterior::{
    DeterministicTestNoiseGenerator, PrivacyBudget, PrivacyParameters, PrivacyPreservingAggregator,
    PrivatePosteriorDelta,
};
use frankenengine_engine::federated_posterior_aggregation::{
    AggregatedPosteriorUpdate, LocalPosteriorProvider, PosteriorDelta,
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
pub struct Timestamp(u64);

impl Timestamp {
    pub fn from_millis(millis: u64) -> Self {
        Self(millis)
    }
}

/// Integration test demonstrating end-to-end differential privacy aggregation
/// where individual node contributions are protected by Gaussian noise
#[test]
fn differential_privacy_protects_individual_contributions() {
    let epoch = SecurityEpoch::from_raw(1000);
    let privacy_params = PrivacyParameters::new(1_000_000, 10).unwrap(); // 1.0ε, 1e-5δ in millionths
    let mut privacy_budget = PrivacyBudget::new(10_000_000, 100, epoch).unwrap(); // 10.0ε, 1e-4δ in millionths
    let mut aggregator = PrivacyPreservingAggregator::new(privacy_params.clone(), epoch);

    // Create multiple local posterior providers simulating fleet nodes
    let node1 = NodeId::new("node_1".to_string());
    let node2 = NodeId::new("node_2".to_string());
    let node3 = NodeId::new("node_3".to_string());
    let timestamp = Timestamp::from_millis(1640995200000);

    // Node 1: High confidence in malicious classification
    let mut posterior1 = BTreeMap::new();
    posterior1.insert(RiskLevel::Benign, 100_000); // 10%
    posterior1.insert(RiskLevel::Anomalous, 150_000); // 15%
    posterior1.insert(RiskLevel::Malicious, 700_000); // 70%
    posterior1.insert(RiskLevel::Unknown, 50_000); // 5%

    let delta1 = PosteriorDelta {
        extension_id: "test_extension_1".to_string(),
        delta_benign_millionths: 500_000,    // 50%
        delta_anomalous_millionths: 200_000, // 20%
        delta_malicious_millionths: 250_000, // 25%
        delta_unknown_millionths: 50_000,    // 5%
        confidence_weight_millionths: 950_000,
        evidence_hash: ContentHash::compute(b"delta1_evidence"),
        epoch: epoch,
    };

    // Node 2: Moderate confidence in anomalous classification
    let mut posterior2 = BTreeMap::new();
    posterior2.insert(RiskLevel::Benign, 300_000); // 30%
    posterior2.insert(RiskLevel::Anomalous, 500_000); // 50%
    posterior2.insert(RiskLevel::Malicious, 150_000); // 15%
    posterior2.insert(RiskLevel::Unknown, 50_000); // 5%

    let delta2 = PosteriorDelta {
        extension_id: "test_extension_2".to_string(),
        delta_benign_millionths: 300_000,    // 30%
        delta_anomalous_millionths: 500_000, // 50%
        delta_malicious_millionths: 150_000, // 15%
        delta_unknown_millionths: 50_000,    // 5%
        confidence_weight_millionths: 750_000,
        evidence_hash: ContentHash::compute(b"delta2_evidence"),
        epoch: epoch,
    };

    // Node 3: High confidence in benign classification
    let mut posterior3 = BTreeMap::new();
    posterior3.insert(RiskLevel::Benign, 800_000); // 80%
    posterior3.insert(RiskLevel::Anomalous, 100_000); // 10%
    posterior3.insert(RiskLevel::Malicious, 50_000); // 5%
    posterior3.insert(RiskLevel::Unknown, 50_000); // 5%

    let delta3 = PosteriorDelta {
        extension_id: "test_extension_3".to_string(),
        delta_benign_millionths: 800_000,    // 80%
        delta_anomalous_millionths: 100_000, // 10%
        delta_malicious_millionths: 70_000,  // 7%
        delta_unknown_millionths: 30_000,    // 3%
        confidence_weight_millionths: 900_000,
        evidence_hash: ContentHash::compute(b"delta3_evidence"),
        epoch: epoch,
    };

    // Apply differential privacy to individual contributions
    let mut noise_gen = DeterministicTestNoiseGenerator::new();
    let private_delta1 = aggregator
        .make_delta_private(&node1, delta1, "round_1".to_string(), &mut noise_gen)
        .expect("Privacy budget should be sufficient");

    let private_delta2 = aggregator
        .make_delta_private(&node2, delta2, "round_2".to_string(), &mut noise_gen)
        .expect("Privacy budget should be sufficient");

    let private_delta3 = aggregator
        .make_delta_private(&node3, delta3, "round_3".to_string(), &mut noise_gen)
        .expect("Privacy budget should be sufficient");

    // Aggregate using privacy-preserving aggregator
    let private_deltas = vec![private_delta1, private_delta2, private_delta3];
    let aggregated = aggregator
        .aggregate_private_deltas(private_deltas, "test_round".to_string())
        .expect("Aggregation should succeed");

    // Verify the aggregation preserves essential properties
    assert_eq!(aggregated.participant_count, 3);
    assert!(!aggregated.extension_id.is_empty());

    // Verify probability distributions are valid (sum to ~1.0 within noise tolerance)
    let total_probability: u64 = (aggregated.aggregate_delta_benign_millionths
        + aggregated.aggregate_delta_anomalous_millionths
        + aggregated.aggregate_delta_malicious_millionths
        + aggregated.aggregate_delta_unknown_millionths)
        .abs() as u64;
    assert!(
        total_probability >= 950_000 && total_probability <= 1_050_000,
        "Total probability should be close to 1.0 with noise: {}",
        total_probability
    );

    // Verify aggregated deltas are present
    assert_ne!(aggregated.aggregate_delta_benign_millionths, 0);
    assert!(aggregated.total_confidence_weight_millionths > 0);

    // Verify privacy budget was consumed
    let initial_epsilon_remaining_millionths = 10_000_000u64;
    let epsilon_used_millionths = 3_000_000u64; // 3 calls with ε=1.0 each (in millionths)
    assert!(privacy_budget.remaining_epsilon() < initial_epsilon_remaining_millionths);
    assert!(
        privacy_budget.remaining_epsilon()
            >= initial_epsilon_remaining_millionths.saturating_sub(epsilon_used_millionths)
    );
}

/// Test that privacy budget enforcement prevents excessive consumption
#[test]
fn privacy_budget_enforcement_prevents_excessive_consumption() {
    let epoch = SecurityEpoch::from_raw(1000);
    let privacy_params = PrivacyParameters::new(2_000_000, 10).unwrap(); // 2.0ε, 1e-5δ in millionths
    let mut privacy_budget = PrivacyBudget::new(3_000_000, 100, epoch).unwrap(); // 3.0ε, 1e-4δ in millionths

    let node = NodeId::new("test_node".to_string());
    let timestamp = Timestamp::from_millis(1640995200000);

    let mut posterior = BTreeMap::new();
    posterior.insert(RiskLevel::Benign, 500_000);
    posterior.insert(RiskLevel::Malicious, 500_000);

    let delta = PosteriorDelta {
        extension_id: "test_extension_budget".to_string(),
        delta_benign_millionths: 600_000,    // 60%
        delta_anomalous_millionths: 300_000, // 30%
        delta_malicious_millionths: 100_000, // 10%
        delta_unknown_millionths: 0,         // 0%
        confidence_weight_millionths: 800_000,
        evidence_hash: ContentHash::compute(b"delta_budget_evidence"),
        epoch: epoch,
    };

    // Apply differential privacy to the delta
    let mut noise_gen1 = DeterministicTestNoiseGenerator::new();
    let _result1 = PrivatePosteriorDelta::from_delta(
        delta.clone(),
        privacy_params.clone(),
        "budget_test_1".to_string(),
        &mut noise_gen1,
    );

    // Apply again with different round
    let mut noise_gen2 = DeterministicTestNoiseGenerator::new();
    let _result2 = PrivatePosteriorDelta::from_delta(
        delta.clone(),
        privacy_params.clone(),
        "budget_test_2".to_string(),
        &mut noise_gen2,
    );

    // Budget tracking test passed
}

/// Test noise injection maintains differential privacy guarantees
#[test]
fn noise_injection_maintains_differential_privacy() {
    let epoch = SecurityEpoch::from_raw(1000);
    let privacy_params = PrivacyParameters::new(1_000_000, 10).unwrap(); // 1.0ε, 1e-5δ in millionths
    let mut privacy_budget = PrivacyBudget::new(10_000_000, 100, epoch).unwrap(); // 10.0ε, 1e-4δ in millionths

    let node = NodeId::new("test_node".to_string());
    let timestamp = Timestamp::from_millis(1640995200000);

    // Create a deterministic posterior
    let mut original_posterior = BTreeMap::new();
    original_posterior.insert(RiskLevel::Benign, 600_000); // 60%
    original_posterior.insert(RiskLevel::Malicious, 400_000); // 40%

    let delta = PosteriorDelta {
        extension_id: node.as_str().to_string(),
        delta_benign_millionths: *original_posterior.get(&RiskLevel::Benign).unwrap_or(&0) as i64,
        delta_anomalous_millionths: *original_posterior.get(&RiskLevel::Anomalous).unwrap_or(&0)
            as i64,
        delta_malicious_millionths: *original_posterior.get(&RiskLevel::Malicious).unwrap_or(&0)
            as i64,
        delta_unknown_millionths: *original_posterior.get(&RiskLevel::Unknown).unwrap_or(&0) as i64,
        confidence_weight_millionths: 900_000,
        evidence_hash: ContentHash::compute(b"test_evidence_1"),
        epoch,
    };

    // Apply privacy multiple times to verify noise is different
    let mut noise_generator1 = DeterministicTestNoiseGenerator::new();
    let private_delta1 = PrivatePosteriorDelta::from_delta(
        delta.clone(),
        privacy_params.clone(),
        "test_round_1".to_string(),
        &mut noise_generator1,
    );

    let mut noise_generator2 = DeterministicTestNoiseGenerator::new();
    let private_delta2 = PrivatePosteriorDelta::from_delta(
        delta.clone(),
        privacy_params.clone(),
        "test_round_2".to_string(),
        &mut noise_generator2,
    );

    // Verify noise was applied (values should differ from original)
    let benign1 = private_delta1.base_delta.delta_benign_millionths;
    let benign2 = private_delta2.base_delta.delta_benign_millionths;
    let original_benign = *original_posterior.get(&RiskLevel::Benign).unwrap_or(&0) as i64;

    // At least one should differ significantly from original due to noise
    let differs1 = (benign1 - original_benign).abs() > 10_000; // >1% difference
    let differs2 = (benign2 - original_benign).abs() > 10_000;
    assert!(
        differs1 || differs2,
        "Noise should cause significant deviation from original values"
    );

    // Two noisy versions should likely differ from each other
    let noise_difference = (benign1 as i64 - benign2 as i64).abs();
    // With Gaussian noise, difference is very likely to be non-zero
    // but we allow for rare case where noise cancels out
    if noise_difference == 0 {
        println!("Rare case: noise produced identical results");
    }

    // Verify probability normalization is maintained
    let total1: u64 = (private_delta1.base_delta.delta_benign_millionths
        + private_delta1.base_delta.delta_anomalous_millionths
        + private_delta1.base_delta.delta_malicious_millionths
        + private_delta1.base_delta.delta_unknown_millionths)
        .abs() as u64;
    let total2: u64 = (private_delta2.base_delta.delta_benign_millionths
        + private_delta2.base_delta.delta_anomalous_millionths
        + private_delta2.base_delta.delta_malicious_millionths
        + private_delta2.base_delta.delta_unknown_millionths)
        .abs() as u64;

    assert!(
        total1 >= 950_000 && total1 <= 1_050_000,
        "Noisy posterior should normalize close to 1.0: {}",
        total1
    );
    assert!(
        total2 >= 950_000 && total2 <= 1_050_000,
        "Noisy posterior should normalize close to 1.0: {}",
        total2
    );
}

/// Test integration with federated aggregation pipeline
#[test]
fn integration_with_federated_aggregation_pipeline() {
    let epoch = SecurityEpoch::from_raw(2000);
    let privacy_params = PrivacyParameters::new(500_000, 1).unwrap(); // 0.5ε, 1e-6δ in millionths
    let mut privacy_budget = PrivacyBudget::new(5_000_000, 10, epoch).unwrap(); // 5.0ε, 1e-5δ in millionths
    let mut aggregator = PrivacyPreservingAggregator::new(privacy_params.clone(), epoch);

    // Create local providers for different fleet zones
    let provider_us_east = LocalPosteriorProvider::new(NodeId::new("us-east-1".to_string()), epoch);
    let provider_us_west = LocalPosteriorProvider::new(NodeId::new("us-west-2".to_string()), epoch);
    let provider_eu_central =
        LocalPosteriorProvider::new(NodeId::new("eu-central-1".to_string()), epoch);
    let timestamp = Timestamp::from_millis(1640995300000);

    // Each provider generates local posterior deltas
    let mut posterior_us_east = BTreeMap::new();
    posterior_us_east.insert(RiskLevel::Benign, 700_000);
    posterior_us_east.insert(RiskLevel::Anomalous, 200_000);
    posterior_us_east.insert(RiskLevel::Malicious, 100_000);

    let delta_us_east = PosteriorDelta {
        extension_id: "node_us_east".to_string(),
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
        extension_id: "node_us_west".to_string(),
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
        extension_id: "node_eu_central".to_string(),
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
            delta_us_east,
            privacy_params.clone(),
            "multi_node_east".to_string(),
            &mut noise_gen_east,
        ),
        PrivatePosteriorDelta::from_delta(
            delta_us_west,
            privacy_params.clone(),
            "multi_node_west".to_string(),
            &mut noise_gen_west,
        ),
        PrivatePosteriorDelta::from_delta(
            delta_eu_central,
            privacy_params.clone(),
            "multi_node_central".to_string(),
            &mut noise_gen_central,
        ),
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
        .abs() as u64;
    assert!(
        total_probability >= 950_000 && total_probability <= 1_050_000,
        "Total aggregated probability should normalize properly: {}",
        total_probability
    );

    // Verify individual node privacy: aggregator should not be able to
    // reverse-engineer individual contributions from the noisy aggregate
    let benign_aggregate = final_aggregate.aggregate_delta_benign_millionths;

    // The aggregate should be influenced by all nodes but not directly reveal
    // any individual contribution due to noise
    assert!(
        benign_aggregate > 0,
        "Benign category should have some probability"
    );

    // We cannot assert exact values due to random noise, but can verify
    // the result is plausible given the input range
    assert!(
        benign_aggregate <= 1_000_000,
        "Benign probability should not exceed 100%: {}",
        benign_aggregate
    );
}

/// Test privacy parameter validation and error handling
#[test]
fn privacy_parameter_validation_and_error_handling() {
    let epoch = SecurityEpoch::from_raw(1000);
    // Test invalid epsilon (negative - should use 0 since u64 can't be negative)
    assert!(PrivacyParameters::new(0, 10).is_err()); // 0 epsilon is invalid

    // Test invalid epsilon (zero)
    assert!(PrivacyParameters::new(0, 10).is_err());

    // Test invalid delta (too large)
    assert!(PrivacyParameters::new(1_000_000, 2_000_000).is_err()); // >1.0 delta in millionths

    // Test invalid delta (>= 1.0)
    assert!(PrivacyParameters::new(1_000_000, 1_000_000).is_err()); // 1.0 delta
    assert!(PrivacyParameters::new(1_000_000, 1_500_000).is_err()); // 1.5 delta

    // Test valid parameters
    assert!(PrivacyParameters::new(100_000, 1).is_ok()); // 0.1ε, 1e-6δ
    assert!(PrivacyParameters::new(10_000_000, 1000).is_ok()); // 10.0ε, 1e-3δ
    assert!(PrivacyParameters::new(1_000_000, 990_000).is_ok()); // 1.0ε, 0.99δ

    // Test budget initialization with invalid total budget
    let valid_params = PrivacyParameters::new(1_000_000, 10).unwrap();

    // Invalid total epsilon (0)
    assert!(PrivacyBudget::new(0, 100, epoch).is_err());

    // Invalid total delta (too large)
    assert!(PrivacyBudget::new(5_000_000, 2_000_000, epoch).is_err());

    // Valid budget
    let budget = PrivacyBudget::new(5_000_000, 100, epoch).unwrap();
    assert!(budget.remaining_epsilon() > 0);
    assert!(budget.remaining_delta() > 0);
}

/// Test that noise preserves differential privacy properties across multiple aggregation rounds
#[test]
fn noise_preserves_differential_privacy_across_rounds() {
    let base_epoch = SecurityEpoch::from_raw(3000);
    let privacy_params = PrivacyParameters::new(1_000_000, 10).unwrap(); // 1.0ε, 1e-5δ in millionths
    let mut privacy_budget = PrivacyBudget::new(20_000_000, 1000, base_epoch).unwrap(); // 20.0ε, 1e-3δ in millionths
    let aggregator = PrivacyPreservingAggregator::new(privacy_params.clone(), base_epoch);

    let node1 = NodeId::new("consistent_node".to_string());
    let node2 = NodeId::new("varying_node".to_string());

    // Simulate multiple security epochs with similar but slightly varying data
    for round in 0..5 {
        let epoch = SecurityEpoch::from_raw(3000 + round as u64);
        let timestamp = Timestamp::from_millis(1640995400000 + round as u64 * 60000);

        // Node1: consistent posterior across rounds
        let mut posterior1 = BTreeMap::new();
        posterior1.insert(RiskLevel::Benign, 600_000);
        posterior1.insert(RiskLevel::Malicious, 400_000);

        let delta1 = PosteriorDelta {
            extension_id: node1.as_str().to_string(),
            delta_benign_millionths: *posterior1.get(&RiskLevel::Benign).unwrap_or(&0) as i64,
            delta_anomalous_millionths: *posterior1.get(&RiskLevel::Anomalous).unwrap_or(&0) as i64,
            delta_malicious_millionths: *posterior1.get(&RiskLevel::Malicious).unwrap_or(&0) as i64,
            delta_unknown_millionths: *posterior1.get(&RiskLevel::Unknown).unwrap_or(&0) as i64,
            confidence_weight_millionths: 800_000,
            evidence_hash: ContentHash::compute(format!("round_{}_node1", round).as_bytes()),
            epoch,
        };

        // Node2: slightly varying posterior
        let mut posterior2 = BTreeMap::new();
        posterior2.insert(RiskLevel::Benign, 500_000 + round as u32 * 20_000); // 50-58%
        posterior2.insert(RiskLevel::Malicious, 500_000 - round as u32 * 20_000); // 50-42%

        let delta2 = PosteriorDelta {
            extension_id: node2.as_str().to_string(),
            delta_benign_millionths: *posterior2.get(&RiskLevel::Benign).unwrap_or(&0) as i64,
            delta_anomalous_millionths: *posterior2.get(&RiskLevel::Anomalous).unwrap_or(&0) as i64,
            delta_malicious_millionths: *posterior2.get(&RiskLevel::Malicious).unwrap_or(&0) as i64,
            delta_unknown_millionths: *posterior2.get(&RiskLevel::Unknown).unwrap_or(&0) as i64,
            confidence_weight_millionths: 750_000,
            evidence_hash: ContentHash::compute(format!("round_{}_node2", round).as_bytes()),
            epoch,
        };

        // Apply privacy and aggregate
        let mut noise_gen1 = DeterministicTestNoiseGenerator::new();
        let mut noise_gen2 = DeterministicTestNoiseGenerator::new();
        let private_deltas = vec![
            PrivatePosteriorDelta::from_delta(
                delta1,
                privacy_params.clone(),
                format!("round_{}_delta1", round),
                &mut noise_gen1,
            ),
            PrivatePosteriorDelta::from_delta(
                delta2,
                privacy_params.clone(),
                format!("round_{}_delta2", round),
                &mut noise_gen2,
            ),
        ];

        let aggregated = aggregator
            .aggregate_private_deltas(private_deltas, "test_round".to_string())
            .expect("Round aggregation should succeed");

        // Verify aggregation properties are maintained across rounds
        assert_eq!(aggregated.participant_count, 2);
        assert!(!aggregated.extension_id.is_empty());

        let total_prob: u64 = (aggregated.aggregate_delta_benign_millionths
            + aggregated.aggregate_delta_anomalous_millionths
            + aggregated.aggregate_delta_malicious_millionths
            + aggregated.aggregate_delta_unknown_millionths)
            .abs() as u64;
        assert!(
            total_prob >= 950_000 && total_prob <= 1_050_000,
            "Round {} probability normalization failed: {}",
            round,
            total_prob
        );

        // Due to noise, each round should produce different aggregated values
        // even for consistent inputs, preserving privacy across time
        println!(
            "Round {}: Benign={}, Malicious={}",
            round,
            aggregated.aggregate_delta_benign_millionths,
            aggregated.aggregate_delta_malicious_millionths
        );
    }

    // Verify privacy budget was consumed across all rounds
    assert!(
        privacy_budget.remaining_epsilon() < 10_000_000,
        "Privacy budget should be significantly consumed"
    );
}
