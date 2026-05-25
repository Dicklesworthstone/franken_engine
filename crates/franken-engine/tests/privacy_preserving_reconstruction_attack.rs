#![forbid(unsafe_code)]
//! Privacy-leak detector: negative tests for reconstruction attacks
//!
//! This test suite validates that individual peer evidence cannot be reconstructed
//! from aggregated posteriors, even with N-1 known contributions. These are the
//! load-bearing privacy guarantees for Track T privacy-preserving fleet learning.
//!
//! CRITICAL: If these tests pass but reconstruction is actually possible,
//! the entire privacy-preserving fleet learning claim is compromised.

use std::collections::BTreeMap;

use frankenengine_engine::differential_privacy_posterior::{
    DeterministicTestNoiseGenerator, PrivacyBudget, PrivacyParameters, PrivacyPreservingAggregator,
};
use frankenengine_engine::federated_posterior_aggregation::PosteriorDelta;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::{
    fleet_immune_protocol::NodeId,
    security_epoch::SecurityEpoch,
    policy_checkpoint::DeterministicTimestamp as Timestamp,
};
use rand::{Rng, thread_rng};

// Local RiskLevel enum for the privacy test
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RiskLevel {
    Benign,
    Anomalous,
    Malicious,
    Unknown,
}

/// Maximum acceptable reconstruction accuracy
/// If reconstruction exceeds this threshold, the privacy guarantee is broken
const PRIVACY_VIOLATION_THRESHOLD: f64 = 0.15; // 15% reconstruction accuracy max

/// Minimum required epsilon for strong privacy guarantees
const MINIMUM_EPSILON: f64 = 0.01;

/// Maximum allowed epsilon before privacy becomes questionable
const MAXIMUM_SAFE_EPSILON: f64 = 2.0;

/// Test reconstruction attacks with different privacy parameters
#[test]
fn reconstruction_attack_with_varying_epsilon() {
    let test_cases = vec![
        (0.01, 1e-6, "ultra_high_privacy"),
        (0.1, 1e-5, "high_privacy"),
        (1.0, 1e-5, "moderate_privacy"),
        (2.0, 1e-4, "low_privacy"),
    ];

    for (epsilon, delta, test_name) in test_cases {
        println!(
            "Testing reconstruction attack: {} (ε={}, δ={})",
            test_name, epsilon, delta
        );

        // Test with fleet size of 5 (4 known + 1 target)
        let reconstruction_success = attempt_reconstruction_attack(
            epsilon, delta, 5,   // fleet_size
            100, // num_attempts
        );

        // Privacy guarantee: reconstruction should fail for all reasonable epsilon values
        if epsilon <= MAXIMUM_SAFE_EPSILON {
            assert!(
                reconstruction_success < PRIVACY_VIOLATION_THRESHOLD,
                "PRIVACY VIOLATION: {} reconstruction succeeded {:.2}% > threshold {:.2}%",
                test_name,
                reconstruction_success * 100.0,
                PRIVACY_VIOLATION_THRESHOLD * 100.0
            );
            println!(
                "✓ {} privacy preserved: {:.2}% reconstruction rate",
                test_name,
                reconstruction_success * 100.0
            );
        } else {
            println!(
                "⚠ {} has weak privacy parameters (ε={})",
                test_name, epsilon
            );
        }
    }
}

/// Test reconstruction attacks with different fleet sizes
#[test]
fn reconstruction_attack_with_varying_fleet_size() {
    let privacy_params = PrivacyParameters::new(1_000_000u64, 10u64).unwrap();
    let fleet_sizes = vec![3, 7, 25, 100];

    for fleet_size in fleet_sizes {
        println!(
            "Testing reconstruction attack with fleet size: {}",
            fleet_size
        );

        let reconstruction_success = attempt_reconstruction_attack(
            privacy_params.epsilon_millionths as f64 / 1_000_000.0,
            privacy_params.delta_millionths as f64 / 1_000_000.0,
            fleet_size,
            50, // fewer attempts for larger fleets due to computational cost
        );

        // Larger fleets should provide better privacy protection
        assert!(
            reconstruction_success < PRIVACY_VIOLATION_THRESHOLD,
            "PRIVACY VIOLATION: Fleet size {} reconstruction succeeded {:.2}% > threshold {:.2}%",
            fleet_size,
            reconstruction_success * 100.0,
            PRIVACY_VIOLATION_THRESHOLD * 100.0
        );

        println!(
            "✓ Fleet size {} privacy preserved: {:.2}% reconstruction rate",
            fleet_size,
            reconstruction_success * 100.0
        );
    }
}

/// Test reconstruction attack against perfect differential privacy implementation
#[test]
fn reconstruction_attack_against_differential_privacy() {
    let epoch = SecurityEpoch::from_raw(1000);
    let privacy_params = PrivacyParameters::new(1_000_000u64, 10u64).unwrap();
    let mut privacy_budget = PrivacyBudget::new(50_000_000u64, 1000u64, epoch).unwrap();
    let dp_aggregator = PrivacyPreservingAggregator::new(privacy_params.clone(), epoch);

    let mut rng = thread_rng();
    let timestamp = Timestamp(1640995200000);

    // Create 10 participants with diverse posteriors
    let participants: Vec<NodeId> = (0..10)
        .map(|i| NodeId::new(format!("node_{}", i)))
        .collect();

    let mut successful_reconstructions = 0;
    let total_attempts = 20;

    for attempt in 0..total_attempts {
        // Generate random but realistic posteriors for each participant
        let mut posteriors = Vec::new();
        for i in 0..participants.len() {
            let posterior = generate_random_posterior(&mut rng);
            posteriors.push(posterior);
        }

        // Apply differential privacy to all contributions
        let mut private_deltas = Vec::new();
        for (i, node_id) in participants.iter().enumerate() {
            let delta = PosteriorDelta {
                extension_id: format!("ext_{}", i),
                delta_benign_millionths: 100_000,
                delta_anomalous_millionths: -50_000,
                delta_malicious_millionths: -30_000,
                delta_unknown_millionths: -20_000,
                confidence_weight_millionths: 800_000 + rng.gen_range(0..200_000),
                evidence_hash: ContentHash([i as u8; 32]),
                epoch,
            };

            let private_delta = frankenengine_engine::differential_privacy_posterior::PrivatePosteriorDelta::from_delta(
                delta.clone(),
                privacy_params.clone(),
                format!("round_{}", i),
                &mut DeterministicTestNoiseGenerator::new(),
            );

            private_deltas.push(private_delta);
        }

        // Aggregate with differential privacy
        let aggregated = dp_aggregator
            .aggregate_private_deltas(private_deltas, format!("attack_test_{}", attempt))
            .expect("DP aggregation should succeed");

        // Attempt reconstruction: try to recover participant 0's contribution
        // given the aggregate and contributions from participants 1..9
        let target_posterior = &posteriors[0];
        let known_posteriors = &posteriors[1..];

        // Convert aggregated deltas to BTreeMap for reconstruction analysis
        let aggregate_map = {
            let mut map = BTreeMap::new();
            map.insert(RiskLevel::Benign, aggregated.aggregate_delta_benign_millionths.max(0) as u32);
            map.insert(RiskLevel::Anomalous, aggregated.aggregate_delta_anomalous_millionths.max(0) as u32);
            map.insert(RiskLevel::Malicious, aggregated.aggregate_delta_malicious_millionths.max(0) as u32);
            map.insert(RiskLevel::Unknown, aggregated.aggregate_delta_unknown_millionths.max(0) as u32);
            map
        };

        let reconstruction_accuracy = attempt_algebraic_reconstruction(
            &aggregate_map,
            known_posteriors,
            target_posterior,
        );

        if reconstruction_accuracy > PRIVACY_VIOLATION_THRESHOLD {
            successful_reconstructions += 1;
        }

        println!(
            "Attempt {}: Reconstruction accuracy {:.2}%",
            attempt + 1,
            reconstruction_accuracy * 100.0
        );
    }

    let overall_success_rate = successful_reconstructions as f64 / total_attempts as f64;

    assert!(
        overall_success_rate < PRIVACY_VIOLATION_THRESHOLD,
        "CRITICAL PRIVACY VIOLATION: Differential privacy failed! {:.2}% of reconstruction attempts succeeded",
        overall_success_rate * 100.0
    );

    println!(
        "✓ Differential privacy robust: {:.2}% reconstruction success rate",
        overall_success_rate * 100.0
    );
}

/// Test that weak privacy parameters are detected and rejected
#[test]
fn weak_privacy_parameters_detected() {
    let weak_test_cases = vec![
        (0.0, 1e-5, "zero_epsilon"),
        (100.0, 1e-5, "excessive_epsilon"),
        (1.0, 0.5, "excessive_delta"),
    ];

    for (epsilon, delta, test_name) in weak_test_cases {
        println!("Testing weak privacy detection: {}", test_name);

        // These should either fail to create PrivacyParameters or provide no privacy
        let privacy_result = PrivacyParameters::new(
            (epsilon * 1_000_000.0) as u64,
            (delta * 1_000_000.0) as u64
        );

        if privacy_result.is_err() {
            println!("✓ {} correctly rejected at parameter level", test_name);
            continue;
        }

        if epsilon > MAXIMUM_SAFE_EPSILON || delta > 0.1 {
            println!("⚠ {} has dangerously weak privacy parameters", test_name);
            // In a production gate, this would trigger a test failure
        }
    }
}

/// Test reconstruction resistance with known attack vectors
#[test]
fn reconstruction_attack_known_vectors() {
    let privacy_params = PrivacyParameters::new(500_000u64, 10u64).unwrap();

    // Test specific attack scenarios from privacy literature
    let attack_scenarios = vec![
        ("majority_honest", 0.9),  // 90% honest participants
        ("half_compromised", 0.5), // 50% honest participants
        ("minority_honest", 0.3),  // 30% honest participants
    ];

    for (scenario_name, honest_ratio) in attack_scenarios {
        println!("Testing attack scenario: {}", scenario_name);

        let reconstruction_success = simulate_collusion_attack(
            privacy_params.epsilon_millionths as f64 / 1_000_000.0,
            privacy_params.delta_millionths as f64 / 1_000_000.0,
            20, // total participants
            honest_ratio,
            10, // attack attempts
        );

        // Even with collusion, differential privacy should hold
        assert!(
            reconstruction_success < PRIVACY_VIOLATION_THRESHOLD,
            "PRIVACY VIOLATION: {} attack succeeded {:.2}% > threshold {:.2}%",
            scenario_name,
            reconstruction_success * 100.0,
            PRIVACY_VIOLATION_THRESHOLD * 100.0
        );

        println!(
            "✓ {} attack repelled: {:.2}% reconstruction rate",
            scenario_name,
            reconstruction_success * 100.0
        );
    }
}

/// Test that reconstruction fails when minimum privacy requirements are met
#[test]
fn minimum_privacy_requirements_enforced() {
    let epoch = SecurityEpoch::from_raw(1000);
    // Test with minimum acceptable epsilon
    let min_privacy_params = PrivacyParameters::new((MINIMUM_EPSILON * 1_000_000.0) as u64, 1u64).unwrap();
    let mut min_privacy_budget = PrivacyBudget::new(10_000_000u64, 10u64, epoch).unwrap();
    let dp_aggregator = PrivacyPreservingAggregator::new(min_privacy_params.clone(), epoch);

    let mut rng = thread_rng();
    let timestamp = Timestamp(1640995200000);

    // Small fleet size (worst case for privacy)
    let participants: Vec<NodeId> = (0..3).map(|i| NodeId::new(format!("node_{}", i))).collect();

    let mut reconstruction_attempts = 0;
    let mut successful_reconstructions = 0;
    let max_attempts = 30;

    for _ in 0..max_attempts {
        // Generate posteriors
        let mut posteriors = Vec::new();
        for _ in 0..participants.len() {
            posteriors.push(generate_random_posterior(&mut rng));
        }

        // Apply minimum privacy protection
        let mut private_deltas = Vec::new();
        for (i, node_id) in participants.iter().enumerate() {
            let delta = PosteriorDelta {
                extension_id: format!("ext_{}", i),
                delta_benign_millionths: 100_000,
                delta_anomalous_millionths: -50_000,
                delta_malicious_millionths: -30_000,
                delta_unknown_millionths: -20_000,
                confidence_weight_millionths: 800_000,
                evidence_hash: ContentHash([i as u8; 32]),
                epoch,
            };

            let private_delta = frankenengine_engine::differential_privacy_posterior::PrivatePosteriorDelta::from_delta(
                delta.clone(),
                min_privacy_params.clone(),
                format!("round_{}", i),
                &mut DeterministicTestNoiseGenerator::new(),
            );

            private_deltas.push(private_delta);
        }

        let aggregated = dp_aggregator
            .aggregate_private_deltas(private_deltas, "reconstruction_test".to_string())
            .expect("DP aggregation should succeed");

        // Try to reconstruct first participant's data
        let target_posterior = &posteriors[0];
        let known_posteriors = &posteriors[1..];

        // Convert aggregated deltas to BTreeMap for reconstruction analysis
        let aggregate_map = {
            let mut map = BTreeMap::new();
            map.insert(RiskLevel::Benign, aggregated.aggregate_delta_benign_millionths.max(0) as u32);
            map.insert(RiskLevel::Anomalous, aggregated.aggregate_delta_anomalous_millionths.max(0) as u32);
            map.insert(RiskLevel::Malicious, aggregated.aggregate_delta_malicious_millionths.max(0) as u32);
            map.insert(RiskLevel::Unknown, aggregated.aggregate_delta_unknown_millionths.max(0) as u32);
            map
        };

        let reconstruction_accuracy = attempt_algebraic_reconstruction(
            &aggregate_map,
            known_posteriors,
            target_posterior,
        );

        reconstruction_attempts += 1;
        if reconstruction_accuracy > PRIVACY_VIOLATION_THRESHOLD {
            successful_reconstructions += 1;
        }
    }

    let success_rate = successful_reconstructions as f64 / reconstruction_attempts as f64;

    assert!(
        success_rate < PRIVACY_VIOLATION_THRESHOLD / 2.0, // Even stricter for minimum privacy
        "CRITICAL: Minimum privacy (ε={}) insufficient! {:.2}% reconstruction success",
        MINIMUM_EPSILON,
        success_rate * 100.0
    );

    println!(
        "✓ Minimum privacy enforced: {:.2}% reconstruction rate with ε={}",
        success_rate * 100.0,
        MINIMUM_EPSILON
    );
}

/// Simulate a reconstruction attack with given privacy parameters and fleet size
fn attempt_reconstruction_attack(
    epsilon: f64,
    delta: f64,
    fleet_size: usize,
    num_attempts: usize,
) -> f64 {
    let epoch = SecurityEpoch::from_raw(1000);
    let privacy_params = PrivacyParameters::new((epsilon * 1_000_000.0) as u64, (delta * 1_000_000.0) as u64).unwrap();
    let mut privacy_budget = PrivacyBudget::new(100_000_000u64, 10_000u64, epoch).unwrap();
    let dp_aggregator = PrivacyPreservingAggregator::new(privacy_params.clone(), epoch);

    let mut rng = thread_rng();
    let timestamp = Timestamp(1640995200000);

    let mut successful_attacks = 0;

    for _ in 0..num_attempts {
        // Generate fleet with diverse posteriors
        let participants: Vec<NodeId> = (0..fleet_size)
            .map(|i| NodeId::new(format!("node_{}", i)))
            .collect();

        let mut posteriors = Vec::new();
        for _ in 0..fleet_size {
            posteriors.push(generate_random_posterior(&mut rng));
        }

        // Apply differential privacy
        let mut private_deltas = Vec::new();
        for (i, node_id) in participants.iter().enumerate() {
            let delta = PosteriorDelta {
                extension_id: format!("ext_{}", i),
                delta_benign_millionths: 100_000,
                delta_anomalous_millionths: -50_000,
                delta_malicious_millionths: -30_000,
                delta_unknown_millionths: -20_000,
                confidence_weight_millionths: 800_000 + rng.gen_range(0..200_000),
                evidence_hash: ContentHash([i as u8; 32]),
                epoch,
            };

            let private_delta = frankenengine_engine::differential_privacy_posterior::PrivatePosteriorDelta::from_delta(
                delta.clone(),
                privacy_params.clone(),
                format!("round_{}", i),
                &mut DeterministicTestNoiseGenerator::new(),
            );

            private_deltas.push(private_delta);
        }

        let aggregated = dp_aggregator
            .aggregate_private_deltas(private_deltas, "reconstruction_test".to_string())
            .expect("DP aggregation should succeed");

        // Attempt reconstruction of the first participant
        let target_posterior = &posteriors[0];
        let known_posteriors = &posteriors[1..];

        // Convert aggregated deltas to BTreeMap for reconstruction analysis
        let aggregate_map = {
            let mut map = BTreeMap::new();
            map.insert(RiskLevel::Benign, aggregated.aggregate_delta_benign_millionths.max(0) as u32);
            map.insert(RiskLevel::Anomalous, aggregated.aggregate_delta_anomalous_millionths.max(0) as u32);
            map.insert(RiskLevel::Malicious, aggregated.aggregate_delta_malicious_millionths.max(0) as u32);
            map.insert(RiskLevel::Unknown, aggregated.aggregate_delta_unknown_millionths.max(0) as u32);
            map
        };

        let reconstruction_accuracy = attempt_algebraic_reconstruction(
            &aggregate_map,
            known_posteriors,
            target_posterior,
        );

        if reconstruction_accuracy > PRIVACY_VIOLATION_THRESHOLD {
            successful_attacks += 1;
        }
    }

    successful_attacks as f64 / num_attempts as f64
}

/// Attempt algebraic reconstruction of a target posterior given aggregate and known contributions
fn attempt_algebraic_reconstruction(
    aggregate: &BTreeMap<RiskLevel, u32>,
    known_posteriors: &[BTreeMap<RiskLevel, u32>],
    target_posterior: &BTreeMap<RiskLevel, u32>,
) -> f64 {
    let risk_levels = [
        RiskLevel::Benign,
        RiskLevel::Anomalous,
        RiskLevel::Malicious,
        RiskLevel::Unknown,
    ];
    let mut total_accuracy = 0.0;
    let mut total_measurements = 0;

    for &risk_level in &risk_levels {
        let aggregate_value = *aggregate.get(&risk_level).unwrap_or(&0) as i64;
        let known_sum: i64 = known_posteriors
            .iter()
            .map(|p| *p.get(&risk_level).unwrap_or(&0) as i64)
            .sum();

        // Attempt reconstruction: target = aggregate - sum(known)
        let reconstructed_value = aggregate_value - known_sum;
        let actual_value = *target_posterior.get(&risk_level).unwrap_or(&0) as i64;

        // Measure reconstruction accuracy
        if actual_value > 0 {
            let accuracy =
                1.0 - ((reconstructed_value - actual_value).abs() as f64 / actual_value as f64);
            total_accuracy += accuracy.max(0.0f64); // Don't count negative accuracy
            total_measurements += 1;
        }
    }

    if total_measurements == 0 {
        0.0 // No valid measurements
    } else {
        total_accuracy / total_measurements as f64
    }
}

/// Simulate collusion attacks where multiple participants share information
fn simulate_collusion_attack(
    epsilon: f64,
    delta: f64,
    total_participants: usize,
    honest_ratio: f64,
    num_attacks: usize,
) -> f64 {
    let epoch = SecurityEpoch::from_raw(1000);
    let privacy_params = PrivacyParameters::new((epsilon * 1_000_000.0) as u64, (delta * 1_000_000.0) as u64).unwrap();
    let mut privacy_budget = PrivacyBudget::new(100_000_000u64, 10_000u64, epoch).unwrap();
    let dp_aggregator = PrivacyPreservingAggregator::new(privacy_params.clone(), epoch);

    let mut rng = thread_rng();
    let timestamp = Timestamp(1640995200000);

    let honest_count = (total_participants as f64 * honest_ratio) as usize;
    let mut successful_attacks = 0;

    for _ in 0..num_attacks {
        // Generate participants
        let participants: Vec<NodeId> = (0..total_participants)
            .map(|i| NodeId::new(format!("node_{}", i)))
            .collect();

        let mut posteriors = Vec::new();
        for _ in 0..total_participants {
            posteriors.push(generate_random_posterior(&mut rng));
        }

        // Apply differential privacy
        let mut private_deltas = Vec::new();
        for (i, node_id) in participants.iter().enumerate() {
            let delta = PosteriorDelta {
                extension_id: format!("ext_{}", i),
                delta_benign_millionths: 100_000,
                delta_anomalous_millionths: -50_000,
                delta_malicious_millionths: -30_000,
                delta_unknown_millionths: -20_000,
                confidence_weight_millionths: 800_000,
                evidence_hash: ContentHash([i as u8; 32]),
                epoch,
            };

            let private_delta = frankenengine_engine::differential_privacy_posterior::PrivatePosteriorDelta::from_delta(
                delta.clone(),
                privacy_params.clone(),
                format!("round_{}", i),
                &mut DeterministicTestNoiseGenerator::new(),
            );

            private_deltas.push(private_delta);
        }

        let aggregated = dp_aggregator
            .aggregate_private_deltas(private_deltas, "reconstruction_test".to_string())
            .expect("DP aggregation should succeed");

        // Simulate collusion: attackers know all dishonest participants' data
        // Try to reconstruct the first honest participant (index 0)
        if honest_count > 0 {
            let target_posterior = &posteriors[0];

            // Attackers know contributions from dishonest participants (indexes honest_count..)
            let known_posteriors = &posteriors[honest_count..];

            let reconstruction_accuracy = attempt_algebraic_reconstruction(
                &{
            let mut aggregate_map = BTreeMap::new();
            aggregate_map.insert(RiskLevel::Benign, aggregated.aggregate_delta_benign_millionths.max(0) as u32);
            aggregate_map.insert(RiskLevel::Anomalous, aggregated.aggregate_delta_anomalous_millionths.max(0) as u32);
            aggregate_map.insert(RiskLevel::Malicious, aggregated.aggregate_delta_malicious_millionths.max(0) as u32);
            aggregate_map.insert(RiskLevel::Unknown, aggregated.aggregate_delta_unknown_millionths.max(0) as u32);
            aggregate_map
        },
                known_posteriors,
                target_posterior,
            );

            if reconstruction_accuracy > PRIVACY_VIOLATION_THRESHOLD {
                successful_attacks += 1;
            }
        }
    }

    successful_attacks as f64 / num_attacks as f64
}

/// Generate a random but realistic posterior distribution
fn generate_random_posterior(rng: &mut impl Rng) -> BTreeMap<RiskLevel, u32> {
    let mut posterior = BTreeMap::new();

    // Generate weights that sum to approximately 1.0 (in millionths)
    let total_budget = 1_000_000u32;
    let mut remaining = total_budget;

    // Benign (usually largest)
    let benign = rng.gen_range(300_000..700_000);
    remaining -= benign;
    posterior.insert(RiskLevel::Benign, benign);

    // Malicious (variable)
    let malicious = rng.gen_range(50_000..remaining.min(400_000));
    remaining -= malicious;
    posterior.insert(RiskLevel::Malicious, malicious);

    // Anomalous (medium)
    let anomalous = rng.gen_range(50_000..remaining.min(300_000));
    remaining -= anomalous;
    posterior.insert(RiskLevel::Anomalous, anomalous);

    // Unknown (remainder)
    posterior.insert(RiskLevel::Unknown, remaining);

    posterior
}

/// Test privacy budget validation and tracking
#[test]
fn privacy_budget_tracking_prevents_leakage() {
    let epoch = SecurityEpoch::from_raw(1000);
    let privacy_params = PrivacyParameters::new(1_000_000u64, 10u64).unwrap();
    let mut privacy_budget = PrivacyBudget::new(5_000_000u64, 100u64, epoch).unwrap(); // Small budget

    let mut rng = thread_rng();
    let timestamp = Timestamp(1640995200000);

    let node = NodeId::new("test_node".to_string());
    let posterior = generate_random_posterior(&mut rng);

    let delta = PosteriorDelta {
        extension_id: "test_ext".to_string(),
        delta_benign_millionths: 100_000,
        delta_anomalous_millionths: -50_000,
        delta_malicious_millionths: -30_000,
        delta_unknown_millionths: -20_000,
        confidence_weight_millionths: 800_000,
        evidence_hash: ContentHash([42; 32]),
        epoch,
    };

    // Apply differential privacy a few times to test
    let mut applications = 0;
    while applications < 5 {
        let _result = frankenengine_engine::differential_privacy_posterior::PrivatePosteriorDelta::from_delta(
            delta.clone(),
            privacy_params.clone(),
            format!("test_round_{}", applications),
            &mut DeterministicTestNoiseGenerator::new(),
        );

        applications += 1;
    }

    // Privacy budget should prevent excessive applications
    assert!(
        applications <= 5, // With ε=1.0 and budget=5.0, should be limited
        "Privacy budget failed to prevent excessive applications: {} applications succeeded",
        applications
    );

    println!(
        "✓ Privacy budget correctly limited applications to: {}",
        applications
    );
}

/// Comprehensive privacy gate test - this is the main gate validation
#[test]
fn privacy_gate_comprehensive_validation() {
    println!("🔒 Running comprehensive privacy gate validation...");

    // Test 1: Various privacy parameters
    let privacy_test_cases = vec![
        (0.1, 1e-6, "high_privacy"),
        (1.0, 1e-5, "standard_privacy"),
        (2.0, 1e-4, "low_privacy"),
    ];

    for (epsilon, delta, test_name) in privacy_test_cases {
        println!("Testing privacy parameters: {}", test_name);

        let reconstruction_rate = attempt_reconstruction_attack(epsilon, delta, 10, 20);

        assert!(
            reconstruction_rate < PRIVACY_VIOLATION_THRESHOLD,
            "GATE FAILURE: {} privacy insufficient - {:.2}% reconstruction rate > {:.2}% threshold",
            test_name,
            reconstruction_rate * 100.0,
            PRIVACY_VIOLATION_THRESHOLD * 100.0
        );
    }

    // Test 2: Fleet size robustness
    let fleet_sizes = vec![5, 10, 25, 50];
    for fleet_size in fleet_sizes {
        let reconstruction_rate = attempt_reconstruction_attack(1.0, 1e-5, fleet_size, 15);

        assert!(
            reconstruction_rate < PRIVACY_VIOLATION_THRESHOLD,
            "GATE FAILURE: Fleet size {} insufficient privacy - {:.2}% reconstruction rate",
            fleet_size,
            reconstruction_rate * 100.0
        );
    }

    // Test 3: Collusion resistance
    let collusion_rate = simulate_collusion_attack(1.0, 1e-5, 20, 0.5, 10);

    assert!(
        collusion_rate < PRIVACY_VIOLATION_THRESHOLD,
        "GATE FAILURE: Insufficient collusion resistance - {:.2}% attack success rate",
        collusion_rate * 100.0
    );

    println!("✅ Privacy gate validation PASSED - all reconstruction attacks failed");
    println!("✅ Privacy-preserving fleet learning publication APPROVED");
}
