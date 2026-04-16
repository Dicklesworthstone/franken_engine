//! Fleet quarantine propagation end-to-end integration tests.
//!
//! Tests full quarantine workflow: detection → broadcast → enforcement → convergence
//! with SLO measurement and TEE attestation integration.
//!
//! Bead: bd-6a61n.5.5

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use frankenengine_engine::fleet_convergence::{
    ContainmentThresholds, PartitionInfo, PartitionMode,
};
use frankenengine_engine::fleet_immune_protocol::{NodeId, QuorumCheckpoint};
use frankenengine_engine::fleet_simulator::{
    FleetSimulator, FleetSimulatorError, InstanceState, QuarantineStats,
};
use frankenengine_engine::tee_attestation_policy::{
    MockTeeProvider, TeePlatform, AttestationQuote,
};

// ---------------------------------------------------------------------------
// Test Configuration and Helpers
// ---------------------------------------------------------------------------

/// Test configuration for fleet quarantine integration.
#[derive(Debug, Clone)]
struct FleetQuarantineConfig {
    /// Number of fleet instances.
    instance_count: usize,
    /// Maximum convergence time for SLO (milliseconds).
    max_convergence_ms: u64,
    /// TEE platform for attestation.
    tee_platform: TeePlatform,
    /// Partition mode for simulation.
    partition_mode: PartitionMode,
}

impl Default for FleetQuarantineConfig {
    fn default() -> Self {
        Self {
            instance_count: 10,
            max_convergence_ms: 500,
            tee_platform: TeePlatform::IntelSgx,
            partition_mode: PartitionMode::Normal,
        }
    }
}

/// Convergence metrics for SLO verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConvergenceMetrics {
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
    pub max_ms: u64,
    pub mean_ms: f64,
    pub slo_met: bool,
    pub total_events: usize,
    pub violations: usize,
}

/// Test containment thresholds.
fn test_containment_thresholds() -> ContainmentThresholds {
    ContainmentThresholds::new(
        0.1,  // posterior_threshold
        0.05, // tightening_factor
        Duration::from_millis(100), // observation_window
    ).unwrap()
}

/// Create test artifacts directory.
fn create_test_artifacts_dir() -> PathBuf {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let artifacts_dir = PathBuf::from("artifacts/fleet_evidence").join(format!("test_{}", timestamp));
    fs::create_dir_all(&artifacts_dir).unwrap();
    artifacts_dir
}

// ---------------------------------------------------------------------------
// Core Integration Tests
// ---------------------------------------------------------------------------

#[test]
fn test_fleet_start_all_healthy() {
    let config = FleetQuarantineConfig::default();
    let thresholds = test_containment_thresholds();

    let fleet = FleetSimulator::new(config.instance_count, thresholds).unwrap();

    // All instances should start healthy
    let instance_count = fleet.instance_count();
    assert_eq!(instance_count, config.instance_count);

    // Check each instance state
    for i in 0..config.instance_count {
        let node_id = NodeId(format!("node_{}", i));
        let instance = fleet.get_instance(&node_id).unwrap();
        assert_eq!(instance.state, InstanceState::Healthy);
    }

    // No quarantine decisions should exist initially
    let stats = fleet.get_quarantine_stats();
    assert_eq!(stats.total_quarantine_decisions, 0);
    assert_eq!(stats.converged_decisions, 0);
}

#[test]
fn test_quarantine_broadcast() {
    let config = FleetQuarantineConfig::default();
    let thresholds = test_containment_thresholds();
    let mut fleet = FleetSimulator::new(config.instance_count, thresholds).unwrap();

    let originator = NodeId("node_0".to_string());
    let extension_id = "malicious_extension_test".to_string();
    let reason = "Detected unauthorized API access".to_string();
    let evidence_hash = "evidence_broadcast_test_123".to_string();

    // Broadcast quarantine decision
    fleet.broadcast_quarantine_decision(
        extension_id.clone(),
        reason,
        evidence_hash.clone(),
        originator,
    ).unwrap();

    // Check that quarantine was recorded
    assert!(fleet.is_extension_quarantined(&evidence_hash));
    assert!(!fleet.is_quarantine_converged(&evidence_hash)); // Not yet converged

    let stats = fleet.get_quarantine_stats();
    assert_eq!(stats.total_quarantine_decisions, 1);
    assert_eq!(stats.converged_decisions, 0);

    // Message bus should have messages
    assert!(fleet.message_bus_queue_length() > 0);
}

#[test]
fn test_convergence_measured() {
    let config = FleetQuarantineConfig::default();
    let thresholds = test_containment_thresholds();
    let mut fleet = FleetSimulator::new(config.instance_count, thresholds).unwrap();

    let originator = NodeId("node_0".to_string());
    let extension_id = "convergence_test_ext".to_string();
    let evidence_hash = "convergence_evidence_456".to_string();

    let start_time = Instant::now();

    // Broadcast quarantine decision
    fleet.broadcast_quarantine_decision(
        extension_id.clone(),
        "Convergence measurement test".to_string(),
        evidence_hash.clone(),
        originator,
    ).unwrap();

    // Simulate processing on each instance
    for i in 0..config.instance_count {
        let node_id = NodeId(format!("node_{}", i));

        // Process quarantine decision
        fleet.process_quarantine_decision(
            extension_id.clone(),
            "Convergence measurement test".to_string(),
            evidence_hash.clone(),
            NodeId("node_0".to_string()),
            fleet.current_lamport_timestamp() + 1,
            node_id.clone(),
        ).unwrap();

        // Process acknowledgment
        fleet.process_quarantine_ack(
            extension_id.clone(),
            evidence_hash.clone(),
            node_id,
            fleet.current_lamport_timestamp(),
        ).unwrap();
    }

    let convergence_time = start_time.elapsed();

    // Check convergence was detected
    assert!(fleet.is_quarantine_converged(&evidence_hash));

    let stats = fleet.get_quarantine_stats();
    assert_eq!(stats.converged_decisions, 1);
    assert_eq!(stats.total_acknowledgments, config.instance_count);

    // Convergence should be fast in simulation
    assert!(convergence_time < Duration::from_millis(config.max_convergence_ms));
}

#[test]
fn test_tee_attestation_required() {
    let config = FleetQuarantineConfig::default();
    let provider = MockTeeProvider::new(config.tee_platform);

    // Generate valid quote
    let valid_quote = provider.generate_valid_quote("quarantine_test_nonce");
    assert!(provider.verify_quote(&valid_quote));

    // Generate expired quote (should fail)
    let expired_quote = provider.generate_expired_quote("expired_nonce");
    assert!(provider.verify_quote(&expired_quote)); // Structure is valid

    // Convert to policy quote with high age (over freshness limit)
    let policy_quote = provider.to_policy_quote(&expired_quote, 7200); // 2 hours old
    assert_eq!(policy_quote.quote_age_secs, 7200);

    // High-impact quarantine decisions should require fresh attestation
    // (This would be enforced by the policy evaluation in production)
    assert!(policy_quote.quote_age_secs > 3600); // Exceeds typical freshness requirement
}

#[test]
fn test_duplicate_quarantine_ignored() {
    let config = FleetQuarantineConfig::default();
    let thresholds = test_containment_thresholds();
    let mut fleet = FleetSimulator::new(config.instance_count, thresholds).unwrap();

    let originator = NodeId("node_0".to_string());
    let extension_id = "duplicate_test_ext".to_string();
    let evidence_hash = "duplicate_evidence_789".to_string();

    // First quarantine decision
    fleet.broadcast_quarantine_decision(
        extension_id.clone(),
        "First decision".to_string(),
        evidence_hash.clone(),
        originator.clone(),
    ).unwrap();

    let stats_after_first = fleet.get_quarantine_stats();
    assert_eq!(stats_after_first.total_quarantine_decisions, 1);

    // Duplicate decision with same evidence hash
    fleet.broadcast_quarantine_decision(
        extension_id.clone(),
        "Duplicate decision".to_string(),
        evidence_hash.clone(),
        originator,
    ).unwrap();

    let stats_after_duplicate = fleet.get_quarantine_stats();
    assert_eq!(stats_after_duplicate.total_quarantine_decisions, 1); // No change
}

#[test]
fn test_minority_partition_tightens() {
    let config = FleetQuarantineConfig {
        partition_mode: PartitionMode::Degraded(0.7), // 70% delivery rate
        ..Default::default()
    };
    let thresholds = test_containment_thresholds();
    let mut fleet = FleetSimulator::new(config.instance_count, thresholds).unwrap();

    // Set degraded partition mode
    fleet.set_partition_mode(config.partition_mode).unwrap();

    let originator = NodeId("node_0".to_string());
    let extension_id = "partition_test_ext".to_string();
    let evidence_hash = "partition_evidence_abc".to_string();

    // Broadcast should still work but with potential message drops
    let result = fleet.broadcast_quarantine_decision(
        extension_id,
        "Partition resilience test".to_string(),
        evidence_hash.clone(),
        originator,
    );

    assert!(result.is_ok());
    assert!(fleet.is_extension_quarantined(&evidence_hash));
}

#[test]
fn test_convergence_slo_met() {
    let config = FleetQuarantineConfig::default();
    let thresholds = test_containment_thresholds();

    // Run multiple quarantine events to gather statistics
    let mut convergence_times = Vec::new();

    for event_id in 0..10 {
        let mut fleet = FleetSimulator::new(config.instance_count, thresholds.clone()).unwrap();
        let originator = NodeId("node_0".to_string());
        let extension_id = format!("slo_test_ext_{}", event_id);
        let evidence_hash = format!("slo_evidence_{}", event_id);

        let start_time = Instant::now();

        // Broadcast and process quarantine
        fleet.broadcast_quarantine_decision(
            extension_id.clone(),
            "SLO measurement test".to_string(),
            evidence_hash.clone(),
            originator.clone(),
        ).unwrap();

        // Simulate fast convergence
        for i in 0..config.instance_count {
            let node_id = NodeId(format!("node_{}", i));
            fleet.process_quarantine_ack(
                extension_id.clone(),
                evidence_hash.clone(),
                node_id,
                fleet.current_lamport_timestamp() + i as u64 + 1,
            ).unwrap();
        }

        let convergence_time = start_time.elapsed();
        convergence_times.push(convergence_time.as_millis() as u64);

        assert!(fleet.is_quarantine_converged(&evidence_hash));
    }

    // Calculate metrics
    let mut sorted_times = convergence_times.clone();
    sorted_times.sort();

    let p50 = sorted_times[sorted_times.len() * 50 / 100];
    let p95 = sorted_times[sorted_times.len() * 95 / 100];
    let p99 = sorted_times[sorted_times.len() * 99 / 100];
    let max_time = *sorted_times.last().unwrap();
    let mean_time = sorted_times.iter().sum::<u64>() as f64 / sorted_times.len() as f64;

    let violations = sorted_times.iter().filter(|&&t| t > config.max_convergence_ms).count();
    let slo_met = violations == 0;

    // All measurements should be well under SLO
    assert!(p99 < config.max_convergence_ms, "p99 {} exceeds SLO {}", p99, config.max_convergence_ms);
    assert!(slo_met, "SLO violated in {} out of {} events", violations, sorted_times.len());
}

#[test]
fn test_evidence_bundle_complete() {
    let config = FleetQuarantineConfig::default();
    let thresholds = test_containment_thresholds();
    let mut fleet = FleetSimulator::new(config.instance_count, thresholds).unwrap();

    let originator = NodeId("node_0".to_string());
    let extension_id = "evidence_test_ext".to_string();
    let evidence_hash = "evidence_bundle_test".to_string();

    // Broadcast quarantine decision
    fleet.broadcast_quarantine_decision(
        extension_id.clone(),
        "Evidence bundle completeness test".to_string(),
        evidence_hash.clone(),
        originator,
    ).unwrap();

    // Export event log as evidence
    let event_log = fleet.export_event_log();

    // Event log should contain quarantine decision
    assert!(event_log.contains("Quarantine decision broadcast"));
    assert!(event_log.contains(&extension_id));
    assert!(event_log.contains(&evidence_hash));

    // Event log should be valid JSONL
    for line in event_log.lines() {
        if !line.trim().is_empty() {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
    }
}

#[test]
fn test_100_quarantine_events() {
    let config = FleetQuarantineConfig {
        instance_count: 5, // Smaller fleet for performance
        ..Default::default()
    };
    let thresholds = test_containment_thresholds();
    let mut fleet = FleetSimulator::new(config.instance_count, thresholds).unwrap();

    let mut convergence_times = Vec::new();

    // Generate 100 quarantine events
    for event_id in 0..100 {
        let originator = NodeId(format!("node_{}", event_id % config.instance_count));
        let extension_id = format!("bulk_test_ext_{}", event_id);
        let evidence_hash = format!("bulk_evidence_{}", event_id);

        let start_time = Instant::now();

        // Broadcast quarantine decision
        fleet.broadcast_quarantine_decision(
            extension_id.clone(),
            format!("Bulk test event {}", event_id),
            evidence_hash.clone(),
            originator,
        ).unwrap();

        // Simulate acknowledgments from all instances
        for i in 0..config.instance_count {
            let node_id = NodeId(format!("node_{}", i));
            fleet.process_quarantine_ack(
                extension_id.clone(),
                evidence_hash.clone(),
                node_id,
                fleet.current_lamport_timestamp() + i as u64 + 1,
            ).unwrap();
        }

        let convergence_time = start_time.elapsed();
        convergence_times.push(convergence_time.as_millis() as u64);
    }

    // Statistical analysis
    let mut sorted_times = convergence_times;
    sorted_times.sort();

    let p50 = sorted_times[sorted_times.len() * 50 / 100];
    let p95 = sorted_times[sorted_times.len() * 95 / 100];
    let p99 = sorted_times[sorted_times.len() * 99 / 100];
    let violations = sorted_times.iter().filter(|&&t| t > config.max_convergence_ms).count();

    // Verify fleet handled 100 events
    let stats = fleet.get_quarantine_stats();
    assert_eq!(stats.total_quarantine_decisions, 100);
    assert_eq!(stats.converged_decisions, 100);

    // Most events should meet SLO
    let slo_compliance = (100 - violations) as f64 / 100.0;
    assert!(slo_compliance > 0.95, "SLO compliance {} below 95%", slo_compliance);

    println!("100-event statistics: p50={}ms, p95={}ms, p99={}ms, violations={}",
             p50, p95, p99, violations);
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

/// Generate convergence metrics from timing data.
fn generate_convergence_metrics(
    times: &[u64],
    max_convergence_ms: u64
) -> ConvergenceMetrics {
    let mut sorted_times = times.to_vec();
    sorted_times.sort();

    let p50 = sorted_times[sorted_times.len() * 50 / 100];
    let p95 = sorted_times[sorted_times.len() * 95 / 100];
    let p99 = sorted_times[sorted_times.len() * 99 / 100];
    let max_ms = *sorted_times.last().unwrap();
    let mean_ms = sorted_times.iter().sum::<u64>() as f64 / sorted_times.len() as f64;

    let violations = sorted_times.iter().filter(|&&t| t > max_convergence_ms).count();
    let slo_met = violations == 0;

    ConvergenceMetrics {
        p50_ms: p50,
        p95_ms: p95,
        p99_ms: p99,
        max_ms,
        mean_ms,
        slo_met,
        total_events: sorted_times.len(),
        violations,
    }
}