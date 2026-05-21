//! Integration tests for fleet_convergence_harness.rs
//!
//! These tests verify the full end-to-end behavior of the fleet convergence
//! harness under various scenarios, including the critical NEGATIVE test
//! that ensures convergence is REFUSED under permanent partition.

use frankenengine_engine::fleet_convergence::PartitionMode;
use frankenengine_engine::fleet_convergence_harness::{
    ConvergenceHarnessConfig, ConvergenceResult, FleetConvergenceHarness,
};

// Test utilities

fn create_test_harness(node_count: usize) -> FleetConvergenceHarness {
    FleetConvergenceHarness::with_node_count(node_count).expect("Should create test harness")
}

fn test_extension_id(test_name: &str) -> String {
    format!("integration-test-{}", test_name)
}

// Basic functionality tests

#[test]
fn integration_harness_creation_and_basic_operations() {
    let harness = create_test_harness(5);

    // Verify basic properties
    assert_eq!(harness.node_count(), 5);
    assert_eq!(harness.node_ids().len(), 5);

    // All nodes should have unique IDs
    let node_ids = harness.node_ids();
    for i in 0..node_ids.len() {
        for j in (i + 1)..node_ids.len() {
            assert_ne!(node_ids[i], node_ids[j], "Node IDs should be unique");
        }
    }

    // Should have no convergence history initially
    assert_eq!(harness.convergence_history().len(), 0);

    // Should have empty quarantine stats initially
    let stats = harness.quarantine_stats();
    assert_eq!(stats.total_quarantine_decisions, 0);
}

#[test]
fn integration_step_execution_without_messages() {
    let mut harness = create_test_harness(3);

    // Should be able to step without messages
    let had_message = harness.step().expect("Step should succeed");
    assert!(!had_message, "Should not have messages initially");

    // Should be able to run multiple steps
    let executed = harness.run_steps(10).expect("Run steps should succeed");
    assert_eq!(executed, 0, "Should execute 0 steps when no messages");
}

#[test]
fn integration_quarantine_decision_broadcast_and_propagation() {
    let mut harness = create_test_harness(4);
    let node_ids = harness.node_ids();

    // Broadcast a quarantine decision
    harness
        .broadcast_quarantine_decision(
            test_extension_id("broadcast_test"),
            "Integration test quarantine".to_string(),
            "integration-evidence-001".to_string(),
            node_ids[0].clone(),
        )
        .expect("Broadcast should succeed");

    // Verify the decision was recorded
    let stats = harness.quarantine_stats();
    assert_eq!(stats.total_quarantine_decisions, 1);

    // Run simulation steps to propagate
    let executed = harness.run_steps(20).expect("Run steps should succeed");
    assert!(
        executed > 0,
        "Should have executed steps for message propagation"
    );
}

// Convergence verification tests

#[test]
fn integration_convergence_no_partition_succeeds_or_quorum_fails() {
    let mut harness = create_test_harness(7); // Use default size for better quorum chances

    let result = harness
        .test_convergence_no_partition(test_extension_id("no_partition_integration"))
        .expect("Convergence test should execute");

    // Under no partition, we expect either convergence or quorum failure
    // (quorum failure can happen if nodes haven't exchanged heartbeats yet)
    match result {
        ConvergenceResult::Converged {
            checkpoint_seq,
            participating_nodes,
            decisions_resolved,
        } => {
            assert!(checkpoint_seq > 0, "Checkpoint sequence should be positive");
            assert!(participating_nodes > 0, "Should have participating nodes");
            assert!(
                decisions_resolved >= 0,
                "Decisions resolved should be non-negative"
            );
        }
        ConvergenceResult::QuorumNotReached {
            required_nodes,
            available_nodes,
            ..
        } => {
            assert!(required_nodes > 0, "Required nodes should be positive");
            assert!(
                available_nodes < required_nodes,
                "Available < required for quorum failure"
            );
        }
        other => {
            panic!("Unexpected result under no partition: {:?}", other);
        }
    }

    // Should have recorded the convergence attempt
    assert_eq!(harness.convergence_history().len(), 1);
    let attempt = &harness.convergence_history()[0];
    assert_eq!(attempt.attempt_id, 1);
    assert_eq!(attempt.total_node_count, 7);
}

#[test]
fn integration_convergence_permanent_partition_must_refuse() {
    let mut harness = create_test_harness(5);

    let result = harness
        .test_convergence_permanent_partition(test_extension_id("permanent_partition_integration"))
        .expect("Convergence test should execute");

    // CRITICAL TEST: Must REFUSE convergence under permanent partition
    match result {
        ConvergenceResult::QuorumNotReached {
            required_nodes,
            available_nodes,
            partition_detected,
        } => {
            // This is the expected NEGATIVE result
            assert!(required_nodes > 0, "Required nodes should be positive");
            assert!(
                available_nodes < required_nodes,
                "Partition should break quorum"
            );
            // partition_detected may be true or false depending on timing
        }
        ConvergenceResult::ProtocolError { error } => {
            // Also acceptable - partition can cause protocol errors
            assert!(!error.is_empty(), "Protocol error should have description");
        }
        ConvergenceResult::Timeout { .. } => {
            // Also acceptable - partition can cause timeouts
        }
        ConvergenceResult::Converged { .. } => {
            panic!(
                "CRITICAL FAILURE: Harness incorrectly declared convergence under permanent partition!"
            );
        }
    }

    // Should have recorded the attempt
    assert_eq!(harness.convergence_history().len(), 1);
    let attempt = &harness.convergence_history()[0];
    assert_eq!(attempt.attempt_id, 1);

    // Should have quarantine decision recorded
    let stats = harness.quarantine_stats();
    assert_eq!(stats.total_quarantine_decisions, 1);
}

#[test]
fn integration_convergence_symmetric_partition_variable_outcome() {
    let mut harness = create_test_harness(6); // Even number for symmetric split

    let result = harness
        .test_convergence_symmetric_partition(
            test_extension_id("symmetric_partition_integration"),
            50, // 50% message success rate
        )
        .expect("Convergence test should execute");

    // Under symmetric partition, outcome depends on whether quorum is maintained
    match result {
        ConvergenceResult::Converged { .. } => {
            // May succeed if enough nodes stay connected
        }
        ConvergenceResult::QuorumNotReached { .. } => {
            // May fail if partition breaks quorum
        }
        ConvergenceResult::ProtocolError { .. } => {
            // May have protocol issues under partition stress
        }
        ConvergenceResult::Timeout { .. } => {
            // May timeout under degraded conditions
        }
    }

    // Should have recorded the attempt regardless of outcome
    assert_eq!(harness.convergence_history().len(), 1);
}

// Multiple scenario tests

#[test]
fn integration_multiple_convergence_attempts() {
    let mut harness = create_test_harness(4);

    // Test multiple convergence verification attempts
    for i in 1..=3 {
        let result = harness
            .verify_convergence()
            .expect("Convergence verification should work");

        // Each attempt should be recorded
        assert_eq!(harness.convergence_history().len(), i);

        // Attempt IDs should be sequential
        let attempt = &harness.convergence_history()[i - 1];
        assert_eq!(attempt.attempt_id, i as u64);
        assert_eq!(attempt.total_node_count, 4);
    }
}

#[test]
fn integration_partition_mode_transitions() {
    let mut harness = create_test_harness(5);

    // Test transitioning through different partition modes

    // Normal mode first
    harness.set_partition_mode(PartitionMode::Normal, 100);
    let _result1 = harness
        .verify_convergence()
        .expect("Verification should work in normal mode");

    // Degraded mode
    use frankenengine_engine::fleet_convergence::PartitionInfo;
    let partition_info = PartitionInfo {
        detected_at_ns: 1_000_000_000,
        unreachable_nodes: std::collections::BTreeSet::new(),
        local_partition_size: 2,
        total_fleet_size: 5,
    };
    harness.set_partition_mode(PartitionMode::Degraded(partition_info), 30);
    let _result2 = harness
        .verify_convergence()
        .expect("Verification should work in degraded mode");

    // Should have recorded both attempts
    assert_eq!(harness.convergence_history().len(), 2);
}

#[test]
fn integration_multiple_quarantine_decisions() {
    let mut harness = create_test_harness(4);
    let node_ids = harness.node_ids();

    // Broadcast multiple quarantine decisions from different nodes
    for i in 0..3 {
        harness
            .broadcast_quarantine_decision(
                format!("multi-ext-{}", i),
                format!("Multi-extension test {}", i),
                format!("evidence-{:03}", i),
                node_ids[i % node_ids.len()].clone(),
            )
            .expect("Broadcast should succeed");
    }

    // Run simulation to propagate all messages
    let executed = harness.run_steps(50).expect("Run steps should succeed");
    assert!(
        executed > 0,
        "Should have executed steps for message propagation"
    );

    // Verify all decisions were recorded
    let stats = harness.quarantine_stats();
    assert_eq!(stats.total_quarantine_decisions, 3);

    // Try convergence verification
    let _result = harness
        .verify_convergence()
        .expect("Convergence verification should work with multiple decisions");
}

// Configuration and serialization tests

#[test]
fn integration_custom_configuration() {
    let mut config = ConvergenceHarnessConfig::default();
    config.default_node_count = 8;
    config.max_simulation_steps = 500;
    config.convergence_timeout_ms = 60_000;

    let harness = FleetConvergenceHarness::with_config(config.clone())
        .expect("Should create harness with custom config");

    assert_eq!(harness.node_count(), 8);

    // Should be able to serialize and deserialize config
    let json = serde_json::to_string(&config).expect("Config should serialize");
    let decoded: ConvergenceHarnessConfig =
        serde_json::from_str(&json).expect("Config should deserialize");
    assert_eq!(decoded.default_node_count, 8);
}

#[test]
fn integration_convergence_attempt_serialization() {
    let mut harness = create_test_harness(3);

    // Generate a convergence attempt
    let _result = harness
        .verify_convergence()
        .expect("Convergence verification should work");

    // Get the attempt and test serialization
    let attempt = &harness.convergence_history()[0];
    let json = serde_json::to_string(attempt).expect("ConvergenceAttempt should serialize");

    let decoded = serde_json::from_str(&json).expect("ConvergenceAttempt should deserialize");

    // Verify deserialization preserved key fields
    assert_eq!(decoded.attempt_id, attempt.attempt_id);
    assert_eq!(decoded.total_node_count, attempt.total_node_count);
}

// Statistics and logging tests

#[test]
fn integration_statistics_and_logging() {
    let mut harness = create_test_harness(4);
    let node_ids = harness.node_ids();

    // Generate some activity
    harness
        .broadcast_quarantine_decision(
            test_extension_id("stats_test"),
            "Statistics test".to_string(),
            "stats-evidence".to_string(),
            node_ids[0].clone(),
        )
        .expect("Broadcast should succeed");

    harness.run_steps(10).expect("Run steps should succeed");

    // Test simulation statistics
    let sim_stats = harness.simulation_stats();
    assert_eq!(sim_stats.total_instances, 4);
    assert!(sim_stats.simulation_steps >= 0);

    // Test quarantine statistics
    let quar_stats = harness.quarantine_stats();
    assert_eq!(quar_stats.total_quarantine_decisions, 1);

    // Test event log export
    let event_log = harness.export_event_log();
    assert!(!event_log.is_empty(), "Event log should not be empty");
    assert!(
        event_log.contains("InstanceCreated"),
        "Should contain instance creation events"
    );
}

// Edge cases and error conditions

#[test]
fn integration_harness_with_minimum_nodes() {
    let harness = create_test_harness(1); // Single node

    assert_eq!(harness.node_count(), 1);
    assert_eq!(harness.node_ids().len(), 1);

    // Single node should still be able to attempt convergence verification
    // (though it may fail quorum requirements)
    let mut harness_mut = harness;
    let _result = harness_mut
        .verify_convergence()
        .expect("Verification should work even with single node");
}

#[test]
fn integration_harness_with_large_fleet() {
    let harness = create_test_harness(20); // Larger fleet

    assert_eq!(harness.node_count(), 20);
    assert_eq!(harness.node_ids().len(), 20);

    // All node IDs should be unique
    let node_ids = harness.node_ids();
    let mut unique_check = std::collections::BTreeSet::new();
    for id in &node_ids {
        assert!(
            unique_check.insert(id.clone()),
            "All node IDs should be unique"
        );
    }
}

#[test]
fn integration_error_handling() {
    // Test invalid node count
    let result = FleetConvergenceHarness::with_node_count(0);
    assert!(result.is_err(), "Should fail with zero nodes");

    // Test empty node list scenario
    let mut harness = create_test_harness(1);
    // This should work but may return specific error types
    let _result = harness
        .test_convergence_no_partition(test_extension_id("error_test"))
        .expect("Should handle edge cases gracefully");
}

// Performance and timing tests

#[test]
fn integration_performance_single_convergence_check() {
    let mut harness = create_test_harness(7);

    let start = std::time::Instant::now();

    let _result = harness
        .test_convergence_no_partition(test_extension_id("performance"))
        .expect("Convergence test should execute");

    let duration = start.elapsed();

    // Should complete within reasonable time (benchmark compatibility)
    assert!(
        duration.as_secs() < 30,
        "Convergence check should be fast enough for benchmarking"
    );
}

#[test]
fn integration_performance_multiple_steps() {
    let mut harness = create_test_harness(5);

    let start = std::time::Instant::now();

    let executed = harness.run_steps(100).expect("Steps should execute");

    let duration = start.elapsed();

    // Step execution should be very fast
    assert!(duration.as_millis() < 5000, "Step execution should be fast");
    assert!(
        executed <= 100,
        "Should not execute more steps than requested"
    );
}

// Comprehensive end-to-end test

#[test]
fn integration_comprehensive_fleet_lifecycle() {
    let mut harness = create_test_harness(7);
    let node_ids = harness.node_ids();

    // Phase 1: Normal operation
    harness.set_partition_mode(PartitionMode::Normal, 100);

    harness
        .broadcast_quarantine_decision(
            test_extension_id("lifecycle_normal"),
            "Normal operation test".to_string(),
            "lifecycle-evidence-normal".to_string(),
            node_ids[0].clone(),
        )
        .expect("Broadcast should succeed");

    harness.run_steps(20).expect("Steps should execute");

    let result1 = harness
        .verify_convergence()
        .expect("Verification should work");

    // Phase 2: Degraded operation
    use frankenengine_engine::fleet_convergence::PartitionInfo;
    let partition_info = PartitionInfo {
        detected_at_ns: 2_000_000_000,
        unreachable_nodes: std::collections::BTreeSet::new(),
        local_partition_size: 4,
        total_fleet_size: 7,
    };
    harness.set_partition_mode(PartitionMode::Degraded(partition_info), 60);

    harness
        .broadcast_quarantine_decision(
            test_extension_id("lifecycle_degraded"),
            "Degraded operation test".to_string(),
            "lifecycle-evidence-degraded".to_string(),
            node_ids[1].clone(),
        )
        .expect("Broadcast should succeed");

    harness.run_steps(30).expect("Steps should execute");

    let result2 = harness
        .verify_convergence()
        .expect("Verification should work");

    // Phase 3: Severe partition (should refuse convergence)
    let severe_partition = PartitionInfo {
        detected_at_ns: 3_000_000_000,
        unreachable_nodes: std::collections::BTreeSet::new(),
        local_partition_size: 1, // Isolated
        total_fleet_size: 7,
    };
    harness.set_partition_mode(PartitionMode::Degraded(severe_partition), 0);

    harness
        .broadcast_quarantine_decision(
            test_extension_id("lifecycle_severe"),
            "Severe partition test".to_string(),
            "lifecycle-evidence-severe".to_string(),
            node_ids[2].clone(),
        )
        .expect("Broadcast should succeed");

    harness.run_steps(20).expect("Steps should execute");

    let result3 = harness
        .verify_convergence()
        .expect("Verification should work");

    // Verify lifecycle progression
    assert_eq!(harness.convergence_history().len(), 3);

    // Result 3 should refuse convergence due to severe partition
    match result3 {
        ConvergenceResult::Converged { .. } => {
            panic!("Should not converge under severe partition!");
        }
        ConvergenceResult::QuorumNotReached { .. }
        | ConvergenceResult::ProtocolError { .. }
        | ConvergenceResult::Timeout { .. } => {
            // Expected outcomes under severe partition
        }
    }

    // Should have recorded all quarantine decisions
    let final_stats = harness.quarantine_stats();
    assert_eq!(final_stats.total_quarantine_decisions, 3);
}
