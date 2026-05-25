//! Integration tests for convergence SLO gate negative testing
//! Tests bd-cixqu.2.6 requirement: convergence gate REFUSES claims when partition profile is non-stable

use frankenengine_engine::convergence_slo::{
    ConvergenceGate, ConvergenceGateResult, FleetPartitionProfile, PartitionGateConfig,
    FleetPartitionProfiles,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Test that permanent_split profile results in convergence refusal
#[test]
fn test_permanent_split_profile_refuses_convergence() {
    let profile = FleetPartitionProfile {
        description: "Permanent network partition that prevents quorum".to_string(),
        partition_mode: "degraded".to_string(),
        message_success_rate: 0,
        local_partition_size: Some(1),
        total_fleet_size: Some(7),
        expected_convergence: false,
        convergence_timeout_ms: None,
        convergence_impossible_reason: Some("permanent_network_partition".to_string()),
        failure_mode: Some("quorum_impossible".to_string()),
        gate_verdict: Some("convergence-impossible".to_string()),
    };

    let config = PartitionGateConfig {
        quorum_threshold_percent: 50,
        minimum_required_nodes: 2,
        convergence_impossible_profiles: vec!["permanent_split".to_string()],
        slo_publication_blocked_on_impossible: true,
        manifest_failure_reporting: true,
    };

    let mut profiles_map = BTreeMap::new();
    profiles_map.insert("permanent_split".to_string(), profile);

    let fleet_profiles = FleetPartitionProfiles {
        schema_version: "v1".to_string(),
        description: "Test profiles".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        profiles: profiles_map,
        gate_configuration: config,
    };

    let mut gate = ConvergenceGate {
        partition_profiles: fleet_profiles,
        profiles_file_path: PathBuf::from("/tmp/test_profiles.json"),
        evaluation_history: Vec::new(),
    };
    let result = gate.evaluate_profile("permanent_split").expect("evaluation should succeed");

    assert!(
        !result.convergence_possible,
        "Gate must refuse convergence for permanent split"
    );
    assert_eq!(
        result.gate_verdict, "convergence-impossible",
        "Gate verdict must be convergence-impossible"
    );
    assert_eq!(
        result.slo_publication_status, "blocked",
        "SLO publication must be blocked"
    );
    assert!(
        !result.verdict_reason.is_empty(),
        "Verdict reason must be provided"
    );
    assert!(
        result.verdict_reason.contains("permanent_network_partition"),
        "Verdict reason should contain failure details"
    );
}

/// Test that split_brain profile results in convergence refusal
#[test]
fn test_split_brain_profile_refuses_convergence() {
    let profile = FleetPartitionProfile {
        description: "Even split that breaks quorum".to_string(),
        partition_mode: "degraded".to_string(),
        message_success_rate: 10,
        local_partition_size: Some(3),
        total_fleet_size: Some(6),
        expected_convergence: false,
        convergence_timeout_ms: None,
        convergence_impossible_reason: Some("split_brain_partition".to_string()),
        failure_mode: Some("quorum_impossible".to_string()),
        gate_verdict: Some("convergence-impossible".to_string()),
    };

    let config = PartitionGateConfig {
        quorum_threshold_percent: 50,
        minimum_required_nodes: 2,
        convergence_impossible_profiles: vec!["split_brain".to_string()],
        slo_publication_blocked_on_impossible: true,
        manifest_failure_reporting: true,
    };

    let mut profiles_map = BTreeMap::new();
    profiles_map.insert("split_brain".to_string(), profile);

    let fleet_profiles = FleetPartitionProfiles {
        schema_version: "v1".to_string(),
        description: "Test profiles".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        profiles: profiles_map,
        gate_configuration: config,
    };

    let mut gate = ConvergenceGate {
        partition_profiles: fleet_profiles,
        profiles_file_path: PathBuf::from("/tmp/test_profiles.json"),
        evaluation_history: Vec::new(),
    };
    let result = gate.evaluate_profile("split_brain").expect("evaluation should succeed");

    assert!(
        !result.convergence_possible,
        "Gate must refuse convergence for split brain"
    );
    assert_eq!(
        result.gate_verdict, "convergence-impossible",
        "Gate verdict must be convergence-impossible"
    );
    assert_eq!(
        result.slo_publication_status, "blocked",
        "SLO publication must be blocked"
    );
    assert!(
        !result.verdict_reason.is_empty(),
        "Verdict reason must be provided"
    );
    assert!(
        result.verdict_reason.contains("split_brain_partition"),
        "Verdict reason should contain failure details"
    );
}

/// Test that minority partition correctly allows convergence
#[test]
fn test_minority_partition_allows_convergence() {
    let profile = FleetPartitionProfile {
        description: "Minority partition that should tighten but not prevent convergence"
            .to_string(),
        partition_mode: "degraded".to_string(),
        message_success_rate: 40,
        local_partition_size: Some(3),
        total_fleet_size: Some(7),
        expected_convergence: true,
        convergence_timeout_ms: Some(3000),
        convergence_impossible_reason: None,
        failure_mode: None,
        gate_verdict: None,
    };

    let config = PartitionGateConfig {
        quorum_threshold_percent: 50,
        minimum_required_nodes: 2,
        convergence_impossible_profiles: vec![
            "permanent_split".to_string(),
            "split_brain".to_string(),
        ],
        slo_publication_blocked_on_impossible: true,
        manifest_failure_reporting: true,
    };

    let mut profiles_map = BTreeMap::new();
    profiles_map.insert("minority_partition".to_string(), profile);

    let fleet_profiles = FleetPartitionProfiles {
        schema_version: "v1".to_string(),
        description: "Test profiles".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        profiles: profiles_map,
        gate_configuration: config,
    };

    let mut gate = ConvergenceGate {
        partition_profiles: fleet_profiles,
        profiles_file_path: PathBuf::from("/tmp/test_profiles.json"),
        evaluation_history: Vec::new(),
    };
    let result = gate.evaluate_profile("minority_partition").expect("evaluation should succeed");

    assert!(
        result.convergence_possible,
        "Gate must allow convergence for minority partition"
    );
    assert_eq!(
        result.gate_verdict, "convergence-possible",
        "Gate verdict must be convergence-possible"
    );
    assert_eq!(
        result.slo_publication_status, "allowed",
        "SLO publication must be allowed"
    );
    assert!(
        result.verdict_reason.is_empty() || !result.verdict_reason.contains("failure"),
        "No failure details for successful convergence"
    );
}

/// Test that majority partition correctly allows convergence
#[test]
fn test_majority_partition_allows_convergence() {
    let profile = FleetPartitionProfile {
        description: "Majority partition maintains quorum and should allow convergence".to_string(),
        partition_mode: "degraded".to_string(),
        message_success_rate: 60,
        local_partition_size: Some(4),
        total_fleet_size: Some(7),
        expected_convergence: true,
        convergence_timeout_ms: Some(2500),
        convergence_impossible_reason: None,
        failure_mode: None,
        gate_verdict: None,
    };

    let config = PartitionGateConfig {
        quorum_threshold_percent: 50,
        minimum_required_nodes: 2,
        convergence_impossible_profiles: vec![
            "permanent_split".to_string(),
            "split_brain".to_string(),
        ],
        slo_publication_blocked_on_impossible: true,
        manifest_failure_reporting: true,
    };

    let mut profiles_map = BTreeMap::new();
    profiles_map.insert("majority_partition".to_string(), profile);

    let fleet_profiles = FleetPartitionProfiles {
        schema_version: "v1".to_string(),
        description: "Test profiles".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        profiles: profiles_map,
        gate_configuration: config,
    };

    let mut gate = ConvergenceGate {
        partition_profiles: fleet_profiles,
        profiles_file_path: PathBuf::from("/tmp/test_profiles.json"),
        evaluation_history: Vec::new(),
    };
    let result = gate.evaluate_profile("majority_partition").expect("evaluation should succeed");

    assert!(
        result.convergence_possible,
        "Gate must allow convergence for majority partition"
    );
    assert_eq!(
        result.gate_verdict, "convergence-possible",
        "Gate verdict must be convergence-possible"
    );
    assert_eq!(
        result.slo_publication_status, "allowed",
        "SLO publication must be allowed"
    );
    assert!(
        result.verdict_reason.is_empty() || !result.verdict_reason.contains("failure"),
        "No failure details for successful convergence"
    );
}

/// Test that normal profile correctly allows convergence
#[test]
fn test_normal_profile_allows_convergence() {
    let profile = FleetPartitionProfile {
        description: "Normal operation with no partition faults".to_string(),
        partition_mode: "normal".to_string(),
        message_success_rate: 100,
        local_partition_size: None,
        total_fleet_size: None,
        expected_convergence: true,
        convergence_timeout_ms: Some(500),
        convergence_impossible_reason: None,
        failure_mode: None,
        gate_verdict: None,
    };

    let config = PartitionGateConfig {
        quorum_threshold_percent: 50,
        minimum_required_nodes: 2,
        convergence_impossible_profiles: vec![
            "permanent_split".to_string(),
            "split_brain".to_string(),
        ],
        slo_publication_blocked_on_impossible: true,
        manifest_failure_reporting: true,
    };

    let mut profiles_map = BTreeMap::new();
    profiles_map.insert("normal".to_string(), profile);

    let fleet_profiles = FleetPartitionProfiles {
        schema_version: "v1".to_string(),
        description: "Test profiles".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        profiles: profiles_map,
        gate_configuration: config,
    };

    let mut gate = ConvergenceGate {
        partition_profiles: fleet_profiles,
        profiles_file_path: PathBuf::from("/tmp/test_profiles.json"),
        evaluation_history: Vec::new(),
    };
    let result = gate.evaluate_profile("normal").expect("evaluation should succeed");

    assert!(
        result.convergence_possible,
        "Gate must allow convergence for normal profile"
    );
    assert_eq!(
        result.gate_verdict, "convergence-possible",
        "Gate verdict must be convergence-possible"
    );
    assert!(
        result.slo_publication_status == "allowed",
        "SLO publication must be allowed"
    );
    assert!(
        result.verdict_reason.is_empty() || !result.verdict_reason.contains("failure"),
        "No failure reason for successful convergence"
    );
}

/// Test manifest generation for convergence refusal
#[test]
fn test_manifest_generation_for_refusal() {
    let profile = FleetPartitionProfile {
        description: "Permanent network partition that prevents quorum".to_string(),
        partition_mode: "degraded".to_string(),
        message_success_rate: 0,
        local_partition_size: Some(1),
        total_fleet_size: Some(7),
        expected_convergence: false,
        convergence_timeout_ms: None,
        convergence_impossible_reason: Some("permanent_network_partition".to_string()),
        failure_mode: Some("quorum_impossible".to_string()),
        gate_verdict: Some("convergence-impossible".to_string()),
    };

    let config = PartitionGateConfig {
        quorum_threshold_percent: 50,
        minimum_required_nodes: 2,
        convergence_impossible_profiles: vec!["permanent_split".to_string()],
        slo_publication_blocked_on_impossible: true,
        manifest_failure_reporting: true,
    };

    let mut profiles_map = BTreeMap::new();
    profiles_map.insert("permanent_split".to_string(), profile);

    let fleet_profiles = FleetPartitionProfiles {
        schema_version: "v1".to_string(),
        description: "Test profiles".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        profiles: profiles_map,
        gate_configuration: config,
    };

    let mut gate = ConvergenceGate {
        partition_profiles: fleet_profiles,
        profiles_file_path: PathBuf::from("/tmp/test_profiles.json"),
        evaluation_history: Vec::new(),
    };
    let result = gate.evaluate_profile("permanent_split").expect("evaluation should succeed");
    let manifest_entry = gate.generate_run_manifest_entry("permanent_split")
        .expect("manifest entry should be generated");

    let parsed = manifest_entry.as_object().expect("manifest should be an object");

    assert_eq!(parsed["profile_name"], "permanent_split");
    assert_eq!(parsed["convergence_possible"], false);
    assert_eq!(parsed["gate_verdict"], "convergence-impossible");
    assert_eq!(parsed["slo_publication_status"], "blocked");
    assert!(parsed["verdict_reason"].as_str().unwrap().contains("permanent_network_partition"));
    assert!(parsed.contains_key("partition_details"));

    let partition_details = &parsed["partition_details"];
    assert_eq!(partition_details["local_partition_size"], 1);
    assert_eq!(partition_details["total_fleet_size"], 7);
    assert_eq!(partition_details["message_success_rate"], 0);
}

/// Test quorum calculation logic
#[test]
#[ignore] // TODO: calculate_quorum_threshold method no longer exists in ConvergenceGate API
fn test_quorum_calculation() {
    let config = PartitionGateConfig {
        quorum_threshold_percent: 50,
        minimum_required_nodes: 2,
        convergence_impossible_profiles: vec![],
        slo_publication_blocked_on_impossible: true,
        manifest_failure_reporting: true,
    };

    // NOTE: This test needs to be rewritten for the new ConvergenceGate API
    // The calculate_quorum_threshold method was removed
}

/// Test edge case: exactly at quorum threshold
#[test]
fn test_exactly_at_quorum_threshold() {
    let profile = FleetPartitionProfile {
        description: "Exactly at quorum threshold".to_string(),
        partition_mode: "degraded".to_string(),
        message_success_rate: 50,
        local_partition_size: Some(3), // Exactly 50% of 6
        total_fleet_size: Some(6),
        expected_convergence: true,
        convergence_timeout_ms: Some(2000),
        convergence_impossible_reason: None,
        failure_mode: None,
        gate_verdict: None,
    };

    let config = PartitionGateConfig {
        quorum_threshold_percent: 50,
        minimum_required_nodes: 2,
        convergence_impossible_profiles: vec![],
        slo_publication_blocked_on_impossible: true,
        manifest_failure_reporting: true,
    };

    let mut profiles_map = BTreeMap::new();
    profiles_map.insert("at_threshold".to_string(), profile);

    let fleet_profiles = FleetPartitionProfiles {
        schema_version: "v1".to_string(),
        description: "Test profiles".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        profiles: profiles_map,
        gate_configuration: config,
    };

    let mut gate = ConvergenceGate {
        partition_profiles: fleet_profiles,
        profiles_file_path: PathBuf::from("/tmp/test_profiles.json"),
        evaluation_history: Vec::new(),
    };
    let result = gate.evaluate_profile("at_threshold").expect("evaluation should succeed");

    // At exactly 50%, should still allow convergence (meets threshold)
    assert!(
        result.convergence_possible,
        "Gate should allow convergence at exact threshold"
    );
    assert_eq!(result.gate_verdict, "convergence-possible");
}

/// Test edge case: below minimum required nodes
#[test]
fn test_below_minimum_nodes() {
    let profile = FleetPartitionProfile {
        description: "Below minimum required nodes".to_string(),
        partition_mode: "degraded".to_string(),
        message_success_rate: 90,
        local_partition_size: Some(1), // Below minimum of 2
        total_fleet_size: Some(7),
        expected_convergence: false,
        convergence_timeout_ms: None,
        convergence_impossible_reason: Some("insufficient_nodes".to_string()),
        failure_mode: Some("below_minimum".to_string()),
        gate_verdict: Some("convergence-impossible".to_string()),
    };

    let config = PartitionGateConfig {
        quorum_threshold_percent: 50,
        minimum_required_nodes: 2,
        convergence_impossible_profiles: vec![],
        slo_publication_blocked_on_impossible: true,
        manifest_failure_reporting: true,
    };

    let mut profiles_map = BTreeMap::new();
    profiles_map.insert("insufficient_nodes".to_string(), profile);

    let fleet_profiles = FleetPartitionProfiles {
        schema_version: "v1".to_string(),
        description: "Test profiles".to_string(),
        created_at: "2024-01-01T00:00:00Z".to_string(),
        profiles: profiles_map,
        gate_configuration: config,
    };

    let mut gate = ConvergenceGate {
        partition_profiles: fleet_profiles,
        profiles_file_path: PathBuf::from("/tmp/test_profiles.json"),
        evaluation_history: Vec::new(),
    };
    let result = gate.evaluate_profile("insufficient_nodes").expect("evaluation should succeed");

    assert!(
        !result.convergence_possible,
        "Gate must refuse convergence below minimum nodes"
    );
    assert_eq!(result.gate_verdict, "convergence-impossible");
    assert!(
        result.slo_publication_status != "allowed",
        "SLO publication must be blocked"
    );
}
