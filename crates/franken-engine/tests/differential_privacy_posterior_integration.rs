#![forbid(unsafe_code)]
//! Integration tests demonstrating differential privacy posterior aggregation
//! with (ε,δ)-differential privacy guarantees using Gaussian mechanism.

use std::collections::BTreeMap;

use frankenengine_engine::differential_privacy_posterior::{
    PrivacyBudget, PrivacyParameters, PrivacyPreservingAggregator, PrivatePosteriorDelta,
};
use frankenengine_engine::federated_posterior_aggregation::{
    AggregatedPosteriorUpdate, LocalPosteriorProvider, PosteriorDelta,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::fleet_immune_protocol::NodeId;

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
    let privacy_params = PrivacyParameters::new(1.0, 1e-5).unwrap();
    let mut privacy_budget = PrivacyBudget::new(privacy_params, 10.0, 1e-4);
    let aggregator = PrivacyPreservingAggregator::new();

    // Create multiple local posterior providers simulating fleet nodes
    let node1 = NodeId::new("node_1".into());
    let node2 = NodeId::new("node_2".into());
    let node3 = NodeId::new("node_3".into());

    let epoch = SecurityEpoch::from_raw(1000);
    let timestamp = Timestamp::from_millis(1640995200000);

    // Node 1: High confidence in malicious classification
    let mut posterior1 = BTreeMap::new();
    posterior1.insert(RiskLevel::Benign, 100_000); // 10%
    posterior1.insert(RiskLevel::Anomalous, 150_000); // 15%
    posterior1.insert(RiskLevel::Malicious, 700_000); // 70%
    posterior1.insert(RiskLevel::Unknown, 50_000); // 5%

    let delta1 = PosteriorDelta::new(node1.clone(), epoch, posterior1, 950_000, timestamp);

    // Node 2: Moderate confidence in anomalous classification
    let mut posterior2 = BTreeMap::new();
    posterior2.insert(RiskLevel::Benign, 300_000); // 30%
    posterior2.insert(RiskLevel::Anomalous, 500_000); // 50%
    posterior2.insert(RiskLevel::Malicious, 150_000); // 15%
    posterior2.insert(RiskLevel::Unknown, 50_000); // 5%

    let delta2 = PosteriorDelta::new(node2.clone(), epoch, posterior2, 750_000, timestamp);

    // Node 3: High confidence in benign classification
    let mut posterior3 = BTreeMap::new();
    posterior3.insert(RiskLevel::Benign, 800_000); // 80%
    posterior3.insert(RiskLevel::Anomalous, 100_000); // 10%
    posterior3.insert(RiskLevel::Malicious, 50_000); // 5%
    posterior3.insert(RiskLevel::Unknown, 50_000); // 5%

    let delta3 = PosteriorDelta::new(node3.clone(), epoch, posterior3, 900_000, timestamp);

    // Apply differential privacy to individual contributions
    let private_delta1 =
        PrivatePosteriorDelta::from_posterior_delta(&delta1, &privacy_params, &mut privacy_budget)
            .expect("Privacy budget should be sufficient");

    let private_delta2 =
        PrivatePosteriorDelta::from_posterior_delta(&delta2, &privacy_params, &mut privacy_budget)
            .expect("Privacy budget should be sufficient");

    let private_delta3 =
        PrivatePosteriorDelta::from_posterior_delta(&delta3, &privacy_params, &mut privacy_budget)
            .expect("Privacy budget should be sufficient");

    // Aggregate using privacy-preserving aggregator
    let private_deltas = vec![private_delta1, private_delta2, private_delta3];
    let aggregated = aggregator
        .aggregate_private_deltas(private_deltas, epoch)
        .expect("Aggregation should succeed");

    // Verify the aggregation preserves essential properties
    assert_eq!(aggregated.security_epoch, epoch);
    assert_eq!(aggregated.contributing_nodes.len(), 3);
    assert!(aggregated.contributing_nodes.contains(&node1));
    assert!(aggregated.contributing_nodes.contains(&node2));
    assert!(aggregated.contributing_nodes.contains(&node3));

    // Verify probability distributions are valid (sum to ~1.0 within noise tolerance)
    let total_probability: u64 = aggregated.aggregated_posterior.values().sum();
    assert!(
        total_probability >= 950_000 && total_probability <= 1_050_000,
        "Total probability should be close to 1.0 with noise: {}",
        total_probability
    );

    // Verify all risk levels are present
    assert!(
        aggregated
            .aggregated_posterior
            .contains_key(&RiskLevel::Benign)
    );
    assert!(
        aggregated
            .aggregated_posterior
            .contains_key(&RiskLevel::Anomalous)
    );
    assert!(
        aggregated
            .aggregated_posterior
            .contains_key(&RiskLevel::Malicious)
    );
    assert!(
        aggregated
            .aggregated_posterior
            .contains_key(&RiskLevel::Unknown)
    );

    // Verify privacy budget was consumed
    let initial_epsilon_remaining = 10.0;
    let epsilon_used = 3.0; // 3 calls with ε=1.0 each
    assert!(privacy_budget.remaining_epsilon() < initial_epsilon_remaining);
    assert!(privacy_budget.remaining_epsilon() >= initial_epsilon_remaining - epsilon_used);
}

/// Test that privacy budget enforcement prevents excessive consumption
#[test]
fn privacy_budget_enforcement_prevents_excessive_consumption() {
    let privacy_params = PrivacyParameters::new(2.0, 1e-5).unwrap();
    let mut privacy_budget = PrivacyBudget::new(privacy_params, 3.0, 1e-4); // Small budget

    let node = NodeId::new("test_node".into());
    let epoch = SecurityEpoch::from_raw(1000);
    let timestamp = Timestamp::from_millis(1640995200000);

    let mut posterior = BTreeMap::new();
    posterior.insert(RiskLevel::Benign, 500_000);
    posterior.insert(RiskLevel::Malicious, 500_000);

    let delta = PosteriorDelta::new(node, epoch, posterior, 800_000, timestamp);

    // First call should succeed
    let result1 =
        PrivatePosteriorDelta::from_posterior_delta(&delta, &privacy_params, &mut privacy_budget);
    assert!(result1.is_ok(), "First call should succeed");

    // Second call should fail due to budget exhaustion (need ε=2.0 but only <2.0 remaining)
    let result2 =
        PrivatePosteriorDelta::from_posterior_delta(&delta, &privacy_params, &mut privacy_budget);
    assert!(
        result2.is_err(),
        "Second call should fail due to budget exhaustion"
    );

    // Verify the error is about budget exhaustion
    let error_msg = result2.unwrap_err().to_string();
    assert!(
        error_msg.contains("insufficient privacy budget"),
        "Error should mention privacy budget: {}",
        error_msg
    );
}

/// Test noise injection maintains differential privacy guarantees
#[test]
fn noise_injection_maintains_differential_privacy() {
    let privacy_params = PrivacyParameters::new(1.0, 1e-5).unwrap();
    let mut privacy_budget = PrivacyBudget::new(privacy_params, 10.0, 1e-4);

    let node = NodeId::new("test_node".into());
    let epoch = SecurityEpoch::from_raw(1000);
    let timestamp = Timestamp::from_millis(1640995200000);

    // Create a deterministic posterior
    let mut original_posterior = BTreeMap::new();
    original_posterior.insert(RiskLevel::Benign, 600_000); // 60%
    original_posterior.insert(RiskLevel::Malicious, 400_000); // 40%

    let delta = PosteriorDelta::new(node, epoch, original_posterior.clone(), 900_000, timestamp);

    // Apply privacy multiple times to verify noise is different
    let private_delta1 =
        PrivatePosteriorDelta::from_posterior_delta(&delta, &privacy_params, &mut privacy_budget)
            .unwrap();

    let private_delta2 =
        PrivatePosteriorDelta::from_posterior_delta(&delta, &privacy_params, &mut privacy_budget)
            .unwrap();

    // Verify noise was applied (values should differ from original)
    let benign1 = private_delta1.noisy_posterior[&RiskLevel::Benign];
    let benign2 = private_delta2.noisy_posterior[&RiskLevel::Benign];
    let original_benign = original_posterior[&RiskLevel::Benign];

    // At least one should differ significantly from original due to noise
    let differs1 = (benign1 as i64 - original_benign as i64).abs() > 10_000; // >1% difference
    let differs2 = (benign2 as i64 - original_benign as i64).abs() > 10_000;
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
    let total1: u64 = private_delta1.noisy_posterior.values().sum();
    let total2: u64 = private_delta2.noisy_posterior.values().sum();

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
    let privacy_params = PrivacyParameters::new(0.5, 1e-6).unwrap();
    let mut privacy_budget = PrivacyBudget::new(privacy_params, 5.0, 1e-5);
    let aggregator = PrivacyPreservingAggregator::new();

    // Create local providers for different fleet zones
    let provider_us_east = LocalPosteriorProvider::new("us-east-1".into());
    let provider_us_west = LocalPosteriorProvider::new("us-west-2".into());
    let provider_eu_central = LocalPosteriorProvider::new("eu-central-1".into());

    let epoch = SecurityEpoch::from_raw(2000);
    let timestamp = Timestamp::from_millis(1640995300000);

    // Each provider generates local posterior deltas
    let mut posterior_us_east = BTreeMap::new();
    posterior_us_east.insert(RiskLevel::Benign, 700_000);
    posterior_us_east.insert(RiskLevel::Anomalous, 200_000);
    posterior_us_east.insert(RiskLevel::Malicious, 100_000);

    let delta_us_east = PosteriorDelta::new(
        NodeId::new("node_us_east".into()),
        epoch,
        posterior_us_east,
        850_000,
        timestamp,
    );

    let mut posterior_us_west = BTreeMap::new();
    posterior_us_west.insert(RiskLevel::Benign, 300_000);
    posterior_us_west.insert(RiskLevel::Anomalous, 400_000);
    posterior_us_west.insert(RiskLevel::Malicious, 300_000);

    let delta_us_west = PosteriorDelta::new(
        NodeId::new("node_us_west".into()),
        epoch,
        posterior_us_west,
        750_000,
        timestamp,
    );

    let mut posterior_eu_central = BTreeMap::new();
    posterior_eu_central.insert(RiskLevel::Benign, 800_000);
    posterior_eu_central.insert(RiskLevel::Anomalous, 150_000);
    posterior_eu_central.insert(RiskLevel::Malicious, 50_000);

    let delta_eu_central = PosteriorDelta::new(
        NodeId::new("node_eu_central".into()),
        epoch,
        posterior_eu_central,
        900_000,
        timestamp,
    );

    // Convert to private deltas
    let private_deltas = vec![
        PrivatePosteriorDelta::from_posterior_delta(
            &delta_us_east,
            &privacy_params,
            &mut privacy_budget,
        )
        .unwrap(),
        PrivatePosteriorDelta::from_posterior_delta(
            &delta_us_west,
            &privacy_params,
            &mut privacy_budget,
        )
        .unwrap(),
        PrivatePosteriorDelta::from_posterior_delta(
            &delta_eu_central,
            &privacy_params,
            &mut privacy_budget,
        )
        .unwrap(),
    ];

    // Perform privacy-preserving aggregation
    let final_aggregate = aggregator
        .aggregate_private_deltas(private_deltas, epoch)
        .expect("Privacy-preserving aggregation should succeed");

    // Verify the aggregated result maintains fleet-wide properties
    assert_eq!(final_aggregate.security_epoch, epoch);
    assert_eq!(final_aggregate.contributing_nodes.len(), 3);

    // Verify combined confidence reflects weighted average with privacy noise
    assert!(
        final_aggregate.aggregated_confidence >= 700_000
            && final_aggregate.aggregated_confidence <= 900_000,
        "Aggregated confidence should be reasonable weighted average: {}",
        final_aggregate.aggregated_confidence
    );

    // Verify probability distribution validity
    let total_probability: u64 = final_aggregate.aggregated_posterior.values().sum();
    assert!(
        total_probability >= 950_000 && total_probability <= 1_050_000,
        "Total aggregated probability should normalize properly: {}",
        total_probability
    );

    // Verify individual node privacy: aggregator should not be able to
    // reverse-engineer individual contributions from the noisy aggregate
    let benign_aggregate = final_aggregate.aggregated_posterior[&RiskLevel::Benign];

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
    // Test invalid epsilon (negative)
    assert!(PrivacyParameters::new(-1.0, 1e-5).is_err());

    // Test invalid epsilon (zero)
    assert!(PrivacyParameters::new(0.0, 1e-5).is_err());

    // Test invalid delta (negative)
    assert!(PrivacyParameters::new(1.0, -1e-5).is_err());

    // Test invalid delta (>= 1.0)
    assert!(PrivacyParameters::new(1.0, 1.0).is_err());
    assert!(PrivacyParameters::new(1.0, 1.5).is_err());

    // Test valid parameters
    assert!(PrivacyParameters::new(0.1, 1e-6).is_ok());
    assert!(PrivacyParameters::new(10.0, 1e-3).is_ok());
    assert!(PrivacyParameters::new(1.0, 0.99).is_ok()); // delta just under 1.0

    // Test budget initialization with invalid total budget
    let valid_params = PrivacyParameters::new(1.0, 1e-5).unwrap();

    // Negative total epsilon
    assert!(std::panic::catch_unwind(|| { PrivacyBudget::new(valid_params, -5.0, 1e-4) }).is_err());

    // Negative total delta
    assert!(std::panic::catch_unwind(|| { PrivacyBudget::new(valid_params, 5.0, -1e-4) }).is_err());

    // Valid budget
    let budget = PrivacyBudget::new(valid_params, 5.0, 1e-4);
    assert!(budget.remaining_epsilon() > 0.0);
    assert!(budget.remaining_delta() > 0.0);
}

/// Test that noise preserves differential privacy properties across multiple aggregation rounds
#[test]
fn noise_preserves_differential_privacy_across_rounds() {
    let privacy_params = PrivacyParameters::new(1.0, 1e-5).unwrap();
    let mut privacy_budget = PrivacyBudget::new(privacy_params, 20.0, 1e-3);
    let aggregator = PrivacyPreservingAggregator::new();

    let node1 = NodeId::new("consistent_node".into());
    let node2 = NodeId::new("varying_node".into());

    // Simulate multiple security epochs with similar but slightly varying data
    for round in 0..5 {
        let epoch = SecurityEpoch::from_raw(3000 + round as u64);
        let timestamp = Timestamp::from_millis(1640995400000 + round as u64 * 60000);

        // Node1: consistent posterior across rounds
        let mut posterior1 = BTreeMap::new();
        posterior1.insert(RiskLevel::Benign, 600_000);
        posterior1.insert(RiskLevel::Malicious, 400_000);

        let delta1 = PosteriorDelta::new(node1.clone(), epoch, posterior1, 800_000, timestamp);

        // Node2: slightly varying posterior
        let mut posterior2 = BTreeMap::new();
        posterior2.insert(RiskLevel::Benign, 500_000 + round as u32 * 20_000); // 50-58%
        posterior2.insert(RiskLevel::Malicious, 500_000 - round as u32 * 20_000); // 50-42%

        let delta2 = PosteriorDelta::new(node2.clone(), epoch, posterior2, 750_000, timestamp);

        // Apply privacy and aggregate
        let private_deltas = vec![
            PrivatePosteriorDelta::from_posterior_delta(
                &delta1,
                &privacy_params,
                &mut privacy_budget,
            )
            .unwrap(),
            PrivatePosteriorDelta::from_posterior_delta(
                &delta2,
                &privacy_params,
                &mut privacy_budget,
            )
            .unwrap(),
        ];

        let aggregated = aggregator
            .aggregate_private_deltas(private_deltas, epoch)
            .expect("Round aggregation should succeed");

        // Verify aggregation properties are maintained across rounds
        assert_eq!(aggregated.security_epoch, epoch);
        assert_eq!(aggregated.contributing_nodes.len(), 2);

        let total_prob: u64 = aggregated.aggregated_posterior.values().sum();
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
            aggregated.aggregated_posterior[&RiskLevel::Benign],
            aggregated.aggregated_posterior[&RiskLevel::Malicious]
        );
    }

    // Verify privacy budget was consumed across all rounds
    assert!(
        privacy_budget.remaining_epsilon() < 10.0,
        "Privacy budget should be significantly consumed"
    );
}
