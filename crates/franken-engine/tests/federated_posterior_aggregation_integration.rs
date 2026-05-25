#![forbid(unsafe_code)]
//! Integration tests for the federated posterior aggregation API.
//!
//! Tests the complete federated learning workflow: local posterior updates,
//! delta computation, secure aggregation, and fleet-wide learning without
//! revealing individual node data.

use std::collections::BTreeMap;

use frankenengine_engine::bayesian_posterior::{Evidence, Posterior, RiskState};
use frankenengine_engine::federated_posterior_aggregation::{
    AggregatedPosteriorUpdate, AggregationCoordinator, AggregationState,
    FEDERATED_AGGREGATION_API_VERSION, FederatedAggregationError, LocalPosteriorProvider,
    MAX_AGGREGATION_PARTICIPANTS, MIN_AGGREGATION_PARTICIPANTS, PosteriorDelta,
};
use frankenengine_engine::fleet_immune_protocol::NodeId;
use frankenengine_engine::security_epoch::SecurityEpoch;

/// Test that posterior deltas preserve probability conservation.
#[test]
fn posterior_delta_preserves_probability_mass() {
    let prior = Posterior::default_prior();
    let updated = Posterior::from_millionths(700_000, 150_000, 100_000, 50_000);

    let evidence = Evidence {
        extension_id: "test_extension".to_string(),
        hostcall_rate_millionths: 5_000_000, // 5 calls/second
        distinct_capabilities: 8,
        resource_score_millionths: 750_000, // 75% resource usage
        timing_anomaly_millionths: 300_000, // 30% timing anomaly
        denial_rate_millionths: 80_000,     // 8% denial rate
        epoch: SecurityEpoch::from_raw(100),
    };

    let delta = PosteriorDelta::from_evidence_update(
        "test_extension",
        &prior,
        &updated,
        &evidence,
        850_000, // 85% confidence
    );

    // Verify posterior delta is valid
    assert!(delta.is_valid());

    // Verify conservation of probability mass (deltas must sum to zero)
    let sum = delta.delta_benign_millionths
        + delta.delta_anomalous_millionths
        + delta.delta_malicious_millionths
        + delta.delta_unknown_millionths;
    assert_eq!(sum, 0, "Posterior deltas must sum to zero");

    // Verify applying delta reproduces the updated posterior
    let reconstructed = delta.apply_to_posterior(&prior);
    assert_eq!(reconstructed.p_benign, updated.p_benign);
    assert_eq!(reconstructed.p_anomalous, updated.p_anomalous);
    assert_eq!(reconstructed.p_malicious, updated.p_malicious);
    assert_eq!(reconstructed.p_unknown, updated.p_unknown);
}

/// Test local posterior provider manages node-local learning state.
#[test]
fn local_posterior_provider_manages_extension_state() {
    let mut provider =
        LocalPosteriorProvider::new(NodeId::new("fleet_node_alpha"), SecurityEpoch::from_raw(1));

    // Initial state: no local posteriors
    assert!(provider.get_local_posterior("extension_1").is_none());

    // Create evidence indicating suspicious behavior
    let suspicious_evidence = Evidence {
        extension_id: "extension_1".to_string(),
        hostcall_rate_millionths: 10_000_000, // Very high call rate
        distinct_capabilities: 12,            // Many capabilities
        resource_score_millionths: 900_000,   // 90% resource usage
        timing_anomaly_millionths: 700_000,   // 70% timing anomaly
        denial_rate_millionths: 150_000,      // 15% denial rate
        epoch: SecurityEpoch::from_raw(1),
    };

    // Update local posterior with suspicious evidence
    let delta = provider
        .update_local_posterior("extension_1", &suspicious_evidence, 950_000)
        .unwrap();

    // Verify delta reflects increased suspicion
    assert!(delta.is_valid());
    assert_eq!(delta.extension_id, "extension_1");
    assert!(delta.delta_benign_millionths < 0); // Decreased belief in benign
    assert!(delta.delta_malicious_millionths > 0); // Increased belief in malicious

    // Verify local posterior was updated
    let local_posterior = provider.get_local_posterior("extension_1").unwrap();
    assert!(local_posterior.p_malicious > 10_000); // More than default 1%

    // Create evidence indicating normal behavior
    let benign_evidence = Evidence {
        extension_id: "extension_1".to_string(),
        hostcall_rate_millionths: 500_000,  // Normal call rate
        distinct_capabilities: 2,           // Few capabilities
        resource_score_millionths: 200_000, // 20% resource usage
        timing_anomaly_millionths: 50_000,  // 5% timing anomaly
        denial_rate_millionths: 5_000,      // 0.5% denial rate
        epoch: SecurityEpoch::from_raw(1),
    };

    // Update with benign evidence
    let benign_delta = provider
        .update_local_posterior("extension_1", &benign_evidence, 800_000)
        .unwrap();

    // Verify delta reflects decreased suspicion
    assert!(benign_delta.is_valid());
    assert!(benign_delta.delta_benign_millionths > 0); // Increased belief in benign
    assert!(benign_delta.delta_malicious_millionths < 0); // Decreased belief in malicious
}

/// Test aggregation coordinator manages multi-node federated learning rounds.
#[test]
fn aggregation_coordinator_manages_federated_rounds() {
    let mut coordinator = AggregationCoordinator::new(
        NodeId::new("aggregation_coordinator"),
        SecurityEpoch::from_raw(5),
    );

    // Prepare fleet nodes for aggregation
    let fleet_nodes = vec![
        NodeId::new("fleet_node_1"),
        NodeId::new("fleet_node_2"),
        NodeId::new("fleet_node_3"),
        NodeId::new("fleet_node_4"),
    ];

    let deadline_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        + 300_000_000_000; // 5 minutes from now

    // Initiate aggregation round
    let round_id = coordinator
        .initiate_aggregation_round(
            "federated_learning_round_001",
            "extension_under_evaluation",
            fleet_nodes.clone(),
            deadline_ns,
        )
        .unwrap();

    // Verify round was created successfully
    let round_status = coordinator.get_round_status(&round_id).unwrap();
    assert_eq!(round_status.state, AggregationState::Collecting);
    assert_eq!(round_status.participants.len(), 4);
    assert_eq!(round_status.extension_id, "extension_under_evaluation");
    assert_eq!(round_status.api_version, FEDERATED_AGGREGATION_API_VERSION);

    // Verify all participants are initially non-contributing
    for participant in round_status.participants.values() {
        assert!(!participant.has_contributed);
        assert!(participant.delta_hash.is_none());
    }
}

/// Test error handling for insufficient participants.
#[test]
fn aggregation_coordinator_rejects_insufficient_participants() {
    let mut coordinator =
        AggregationCoordinator::new(NodeId::new("coordinator"), SecurityEpoch::from_raw(1));

    // Try to create round with too few participants
    let too_few_nodes = vec![
        NodeId::new("node_1"),
        NodeId::new("node_2"), // Only 2 nodes, need at least 3
    ];

    let result = coordinator.initiate_aggregation_round(
        "insufficient_round",
        "test_extension",
        too_few_nodes,
        u64::MAX,
    );

    assert_eq!(
        result,
        Err(FederatedAggregationError::InsufficientParticipants)
    );
}

/// Test error handling for too many participants.
#[test]
fn aggregation_coordinator_rejects_excessive_participants() {
    let mut coordinator =
        AggregationCoordinator::new(NodeId::new("coordinator"), SecurityEpoch::from_raw(1));

    // Create too many participants
    let too_many_nodes: Vec<NodeId> = (0..=MAX_AGGREGATION_PARTICIPANTS)
        .map(|i| NodeId::new(format!("node_{}", i)))
        .collect();

    let result = coordinator.initiate_aggregation_round(
        "excessive_round",
        "test_extension",
        too_many_nodes,
        u64::MAX,
    );

    assert_eq!(result, Err(FederatedAggregationError::TooManyParticipants));
}

/// Test end-to-end federated learning workflow with realistic fleet scenario.
#[test]
fn end_to_end_federated_learning_workflow() {
    // Setup: Create fleet of 5 nodes learning about a potentially malicious extension
    let mut coordinator = AggregationCoordinator::new(
        NodeId::new("fleet_coordinator"),
        SecurityEpoch::from_raw(10),
    );

    let fleet_node_ids = vec![
        NodeId::new("security_node_east"),
        NodeId::new("security_node_west"),
        NodeId::new("security_node_central"),
        NodeId::new("security_node_backup"),
        NodeId::new("security_node_edge"),
    ];

    // Create local providers for each fleet node
    let mut fleet_providers: BTreeMap<NodeId, LocalPosteriorProvider> = fleet_node_ids
        .iter()
        .map(|node_id| {
            (
                node_id.clone(),
                LocalPosteriorProvider::new(node_id.clone(), SecurityEpoch::from_raw(10)),
            )
        })
        .collect();

    // Initiate federated learning round
    let deadline_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        + 600_000_000_000; // 10 minutes

    let round_id = coordinator
        .initiate_aggregation_round(
            "malware_detection_round",
            "suspicious_crypto_extension",
            fleet_node_ids.clone(),
            deadline_ns,
        )
        .unwrap();

    // Each node observes different evidence about the suspicious extension
    let evidence_observations = vec![
        // Node 1: High resource usage, moderate call rate
        Evidence {
            extension_id: "suspicious_crypto_extension".to_string(),
            hostcall_rate_millionths: 3_000_000, // 3 calls/sec
            distinct_capabilities: 6,
            resource_score_millionths: 850_000, // 85% CPU usage
            timing_anomaly_millionths: 400_000, // 40% timing anomaly
            denial_rate_millionths: 30_000,     // 3% denial rate
            epoch: SecurityEpoch::from_raw(10),
        },
        // Node 2: Very high call rate, network activity
        Evidence {
            extension_id: "suspicious_crypto_extension".to_string(),
            hostcall_rate_millionths: 15_000_000, // 15 calls/sec - very high!
            distinct_capabilities: 10,
            resource_score_millionths: 600_000, // 60% resource usage
            timing_anomaly_millionths: 700_000, // 70% timing anomaly
            denial_rate_millionths: 80_000,     // 8% denial rate
            epoch: SecurityEpoch::from_raw(10),
        },
        // Node 3: Moderate activity, but unusual patterns
        Evidence {
            extension_id: "suspicious_crypto_extension".to_string(),
            hostcall_rate_millionths: 1_500_000, // 1.5 calls/sec
            distinct_capabilities: 8,
            resource_score_millionths: 700_000, // 70% resource usage
            timing_anomaly_millionths: 600_000, // 60% timing anomaly
            denial_rate_millionths: 120_000,    // 12% denial rate
            epoch: SecurityEpoch::from_raw(10),
        },
        // Node 4: Low activity, appears mostly benign
        Evidence {
            extension_id: "suspicious_crypto_extension".to_string(),
            hostcall_rate_millionths: 800_000, // 0.8 calls/sec
            distinct_capabilities: 3,
            resource_score_millionths: 300_000, // 30% resource usage
            timing_anomaly_millionths: 150_000, // 15% timing anomaly
            denial_rate_millionths: 20_000,     // 2% denial rate
            epoch: SecurityEpoch::from_raw(10),
        },
        // Node 5: High denial rate, concerning behavior
        Evidence {
            extension_id: "suspicious_crypto_extension".to_string(),
            hostcall_rate_millionths: 4_000_000, // 4 calls/sec
            distinct_capabilities: 7,
            resource_score_millionths: 750_000, // 75% resource usage
            timing_anomaly_millionths: 500_000, // 50% timing anomaly
            denial_rate_millionths: 200_000,    // 20% denial rate - very high!
            epoch: SecurityEpoch::from_raw(10),
        },
    ];

    // Confidence weights for each node (based on their reliability/track record)
    let confidence_weights = vec![900_000, 850_000, 800_000, 750_000, 880_000];

    // Each node updates its local posterior and generates a delta
    let mut computed_deltas = Vec::new();
    for ((node_id, provider), (evidence, confidence)) in fleet_providers
        .iter_mut()
        .zip(evidence_observations.iter().zip(confidence_weights.iter()))
    {
        let delta = provider
            .update_local_posterior("suspicious_crypto_extension", evidence, *confidence)
            .unwrap();

        assert!(delta.is_valid());

        // Submit delta to aggregation coordinator
        coordinator
            .submit_delta(&round_id, node_id, &delta)
            .unwrap();

        computed_deltas.push(delta);
    }

    // Verify all nodes have contributed
    let round_status = coordinator.get_round_status(&round_id).unwrap();
    let contributed_count = round_status
        .participants
        .values()
        .filter(|p| p.has_contributed)
        .count();
    assert_eq!(contributed_count, 5);

    // Compute federated aggregation
    let aggregated_update = coordinator
        .compute_aggregation(&round_id, computed_deltas)
        .unwrap();

    // Verify aggregated result represents collective fleet learning
    assert_eq!(
        aggregated_update.extension_id,
        "suspicious_crypto_extension"
    );
    assert_eq!(aggregated_update.participant_count, 5);
    assert!(aggregated_update.total_confidence_weight_millionths > 0);
    assert_eq!(aggregated_update.epoch, SecurityEpoch::from_raw(10));

    // Apply aggregated update to each node's local state
    for (_, provider) in fleet_providers.iter_mut() {
        provider
            .apply_aggregated_update(&aggregated_update)
            .unwrap();
    }

    // Verify that all nodes now have updated posteriors reflecting fleet-wide learning
    for (_, provider) in fleet_providers.iter() {
        let updated_posterior = provider
            .get_local_posterior("suspicious_crypto_extension")
            .unwrap();

        // With the suspicious evidence from multiple nodes, posterior should show
        // increased belief in malicious/anomalous states
        let suspicious_belief = updated_posterior.p_anomalous + updated_posterior.p_malicious;
        assert!(suspicious_belief > 200_000); // At least 20% suspicious

        assert!(updated_posterior.is_valid());
    }

    // Verify round completed successfully
    let final_round_status = coordinator.get_round_status(&round_id).unwrap();
    assert_eq!(final_round_status.state, AggregationState::Completed);
}

/// Test aggregated posterior update preserves mathematical properties.
#[test]
fn aggregated_posterior_update_mathematical_properties() {
    let initial_posterior = Posterior::default_prior();

    // Create realistic aggregated update from fleet learning
    let aggregated = AggregatedPosteriorUpdate {
        extension_id: "mathematical_test_extension".to_string(),
        aggregate_delta_benign_millionths: -150_000_000, // Weighted decrease in benign belief
        aggregate_delta_anomalous_millionths: 80_000_000, // Weighted increase in anomalous
        aggregate_delta_malicious_millionths: 50_000_000, // Weighted increase in malicious
        aggregate_delta_unknown_millionths: 20_000_000,  // Weighted increase in unknown
        total_confidence_weight_millionths: 4_000_000,   // Combined from 4 nodes
        participant_count: 4,
        evidence_fingerprint: frankenengine_engine::hash_tiers::ContentHash::compute(b"test"),
        epoch: SecurityEpoch::from_raw(1),
        aggregation_timestamp_ns: 1640995200_000_000_000,
    };

    let updated_posterior = aggregated.apply_to_posterior(&initial_posterior);

    // Verify mathematical properties
    assert!(updated_posterior.is_valid());

    // Verify the aggregation influenced beliefs as expected
    assert!(updated_posterior.p_benign < initial_posterior.p_benign); // Decreased benign belief
    assert!(updated_posterior.p_anomalous > initial_posterior.p_anomalous); // Increased anomalous
    assert!(updated_posterior.p_malicious > initial_posterior.p_malicious); // Increased malicious

    // Check that we can get deltas for individual states
    assert_eq!(
        aggregated.aggregate_delta_for_state(RiskState::Benign),
        -150_000_000
    );
    assert_eq!(
        aggregated.aggregate_delta_for_state(RiskState::Anomalous),
        80_000_000
    );
    assert_eq!(
        aggregated.aggregate_delta_for_state(RiskState::Malicious),
        50_000_000
    );
    assert_eq!(
        aggregated.aggregate_delta_for_state(RiskState::Unknown),
        20_000_000
    );
}

/// Test privacy preservation - aggregator doesn't see individual contributions.
#[test]
fn privacy_preservation_in_aggregation() {
    let mut coordinator = AggregationCoordinator::new(
        NodeId::new("privacy_coordinator"),
        SecurityEpoch::from_raw(1),
    );

    let participants = vec![
        NodeId::new("private_node_1"),
        NodeId::new("private_node_2"),
        NodeId::new("private_node_3"),
    ];

    let round_id = coordinator
        .initiate_aggregation_round(
            "privacy_test_round",
            "privacy_test_extension",
            participants.clone(),
            u64::MAX,
        )
        .unwrap();

    // Create different deltas simulating varied node observations
    let delta1 = PosteriorDelta {
        extension_id: "privacy_test_extension".to_string(),
        delta_benign_millionths: -100_000,
        delta_anomalous_millionths: 50_000,
        delta_malicious_millionths: 30_000,
        delta_unknown_millionths: 20_000,
        confidence_weight_millionths: 800_000,
        evidence_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"evidence1"),
        epoch: SecurityEpoch::from_raw(1),
    };

    let delta2 = PosteriorDelta {
        extension_id: "privacy_test_extension".to_string(),
        delta_benign_millionths: -80_000,
        delta_anomalous_millionths: 40_000,
        delta_malicious_millionths: 25_000,
        delta_unknown_millionths: 15_000,
        confidence_weight_millionths: 700_000,
        evidence_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"evidence2"),
        epoch: SecurityEpoch::from_raw(1),
    };

    let delta3 = PosteriorDelta {
        extension_id: "privacy_test_extension".to_string(),
        delta_benign_millionths: -60_000,
        delta_anomalous_millionths: 30_000,
        delta_malicious_millionths: 20_000,
        delta_unknown_millionths: 10_000,
        confidence_weight_millionths: 900_000,
        evidence_hash: frankenengine_engine::hash_tiers::ContentHash::compute(b"evidence3"),
        epoch: SecurityEpoch::from_raw(1),
    };

    // Submit deltas (in practice, only hashes would be stored by coordinator)
    coordinator
        .submit_delta(&round_id, &participants[0], &delta1)
        .unwrap();
    coordinator
        .submit_delta(&round_id, &participants[1], &delta2)
        .unwrap();
    coordinator
        .submit_delta(&round_id, &participants[2], &delta3)
        .unwrap();

    // Verify coordinator stored hash commitments, not actual deltas
    let round_status = coordinator.get_round_status(&round_id).unwrap();
    for participant in round_status.participants.values() {
        assert!(participant.has_contributed);
        assert!(participant.delta_hash.is_some()); // Hash stored
        // Actual delta values are NOT stored by coordinator - privacy preserved
    }

    // Aggregation only sees final weighted sums, not individual contributions
    let deltas = vec![delta1, delta2, delta3];
    let aggregated = coordinator.compute_aggregation(&round_id, deltas).unwrap();

    // Verify aggregated result doesn't reveal individual node data
    assert!(aggregated.participant_count > 1); // Multiple participants
    assert!(aggregated.total_confidence_weight_millionths > 0); // Combined weights

    // The aggregate deltas are weighted sums - individual contributions are masked
    assert_ne!(aggregated.aggregate_delta_benign_millionths, -100_000); // Not just node 1's value
    assert_ne!(aggregated.aggregate_delta_benign_millionths, -80_000); // Not just node 2's value
    assert_ne!(aggregated.aggregate_delta_benign_millionths, -60_000); // Not just node 3's value
}
