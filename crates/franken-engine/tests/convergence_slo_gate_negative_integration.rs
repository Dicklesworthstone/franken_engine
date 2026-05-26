//! Integration tests for convergence SLO gate negative testing
//! Tests bd-cixqu.2.6 requirement: convergence gate REFUSES claims when partition profile is non-stable

use frankenengine_engine::convergence_slo::{
    ConvergenceGate, ConvergenceGateResult, FleetPartitionProfile, FleetPartitionProfiles,
    PartitionGateConfig,
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
    let result = gate
        .evaluate_profile("permanent_split")
        .expect("evaluation should succeed");

    assert!(
        !result.convergence_possible,
        "Gate must refuse convergence for permanent split"
    );
    assert_eq!(
        result.gate_verdict, "convergence-impossible",
        "Gate verdict must be convergence-impossible"
    );
    assert_eq!(
        result.slo_publication_status, "blocked-convergence-impossible",
        "SLO publication must be blocked for convergence-impossible profile"
    );
    assert!(
        !result.verdict_reason.is_empty(),
        "Verdict reason must be provided"
    );
    // local=1 < required 3 (50% of 7), so the quorum check overrides and supplies
    // the verdict reason; the declared "permanent_network_partition" reason is
    // shadowed when quorum also fails. The declared-reason path is exercised by
    // test_split_brain, where quorum is met and the declared reason survives.
    assert!(
        result.verdict_reason.contains("quorum impossible"),
        "Verdict reason should record the quorum failure: {}",
        result.verdict_reason
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
    let result = gate
        .evaluate_profile("split_brain")
        .expect("evaluation should succeed");

    assert!(
        !result.convergence_possible,
        "Gate must refuse convergence for split brain"
    );
    assert_eq!(
        result.gate_verdict, "convergence-impossible",
        "Gate verdict must be convergence-impossible"
    );
    assert_eq!(
        result.slo_publication_status, "blocked-convergence-impossible",
        "SLO publication must be blocked for convergence-impossible profile"
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
    let result = gate
        .evaluate_profile("minority_partition")
        .expect("evaluation should succeed");

    assert!(
        result.convergence_possible,
        "Gate must allow convergence for minority partition"
    );
    // 40% message success rate is below the 50% healthy threshold, so the gate
    // reports convergence as degraded-but-possible (not the clean "possible").
    assert_eq!(
        result.gate_verdict, "convergence-degraded",
        "Gate verdict must be convergence-degraded at 40% message success"
    );
    assert_eq!(
        result.slo_publication_status, "allowed-degraded-conditions",
        "SLO publication must be allowed under degraded conditions"
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
    let result = gate
        .evaluate_profile("majority_partition")
        .expect("evaluation should succeed");

    assert!(
        result.convergence_possible,
        "Gate must allow convergence for majority partition"
    );
    assert_eq!(
        result.gate_verdict, "convergence-possible",
        "Gate verdict must be convergence-possible"
    );
    assert_eq!(
        result.slo_publication_status, "allowed-normal-conditions",
        "SLO publication must be allowed under normal conditions"
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
    let result = gate
        .evaluate_profile("normal")
        .expect("evaluation should succeed");

    assert!(
        result.convergence_possible,
        "Gate must allow convergence for normal profile"
    );
    assert_eq!(
        result.gate_verdict, "convergence-possible",
        "Gate verdict must be convergence-possible"
    );
    assert!(
        result.slo_publication_status == "allowed-normal-conditions",
        "SLO publication must be allowed under normal conditions"
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
    // Populate evaluation_history so the manifest generator has a result to read.
    gate.evaluate_profile("permanent_split")
        .expect("evaluation should succeed");
    let manifest_entry = gate
        .generate_run_manifest_entry("permanent_split")
        .expect("manifest entry should be generated");

    let parsed = manifest_entry
        .as_object()
        .expect("manifest should be an object");

    // The run manifest wraps the gate decision under a "convergence_gate" object.
    let gate_entry = parsed["convergence_gate"]
        .as_object()
        .expect("manifest must contain a convergence_gate object");

    assert_eq!(gate_entry["profile_name"], "permanent_split");
    assert_eq!(gate_entry["convergence_possible"], false);
    assert_eq!(gate_entry["gate_verdict"], "convergence-impossible");
    assert_eq!(
        gate_entry["slo_publication_status"],
        "blocked-convergence-impossible"
    );
    // local=1 < required 3, so the quorum override supplies the verdict reason
    // (see test_permanent_split_profile_refuses_convergence for the same shadowing).
    assert!(
        gate_entry["verdict_reason"]
            .as_str()
            .expect("verdict_reason must be a string")
            .contains("quorum impossible"),
        "manifest verdict_reason must record the quorum failure"
    );
    assert_eq!(gate_entry["failure_mode"], "quorum_impossible");
    // Provenance fields the run manifest must carry for auditability.
    assert!(
        gate_entry.contains_key("evaluation_timestamp"),
        "manifest must record an evaluation timestamp"
    );
    assert!(
        gate_entry.contains_key("partition_profile_file"),
        "manifest must record the partition profile file path"
    );
}

/// Quorum-threshold computation teeth (bd-bg9l1.18).
///
/// The removed `calculate_quorum_threshold` helper is now inlined in
/// `evaluate_profile` (convergence_slo.rs): when both partition sizes are
/// known the gate computes
/// `effective_required = max(total*pct/100, minimum_required_nodes)` using
/// integer (floor) division, and refuses convergence iff
/// `local_partition_size < effective_required`.
///
/// This drives that exact computation through the public `evaluate_profile`
/// API over representative fleet sizes and pins three behaviours the dead
/// `#[ignore]` test stopped covering:
///   * floor (not rounding) of the percentage threshold,
///   * `minimum_required_nodes` dominating a smaller percentage threshold,
///   * the percentage threshold dominating a smaller minimum.
/// For refused cases it asserts the verdict reason echoes the exact computed
/// `required` value, so a regression in the threshold math (off-by-one,
/// rounding, dropping the `.max(min)`) breaks the test rather than silently
/// shifting the boundary.
#[test]
fn test_quorum_calculation() {
    // (local, total, percent, min_nodes, expected_required, expect_possible)
    let cases: &[(usize, usize, u8, usize, usize, bool)] = &[
        // Floor division: 7*50/100 = 3 (NOT 4). 3 meets the threshold; 2 does not.
        (3, 7, 50, 1, 3, true),
        (2, 7, 50, 1, 3, false),
        // minimum_required_nodes dominates: 10*20/100 = 2, floored up to min 4.
        // local=3 meets the 20% bar but is below the node floor → refused.
        (4, 10, 20, 4, 4, true),
        (3, 10, 20, 4, 4, false),
        // Percentage dominates the minimum: 10*70/100 = 7 > min 2.
        // local=6 is above the node floor but below the percentage bar → refused.
        (7, 10, 70, 2, 7, true),
        (6, 10, 70, 2, 7, false),
        // Large fleet floor: 99*50/100 = 49 (NOT 49.5 rounded up).
        (49, 99, 50, 2, 49, true),
        (48, 99, 50, 2, 49, false),
    ];

    for &(local, total, percent, min_nodes, expected_required, expect_possible) in cases {
        // Independently re-derive the documented formula so a drifting case
        // table fails here rather than masking an engine regression.
        let computed = ((total * percent as usize) / 100).max(min_nodes);
        assert_eq!(
            computed, expected_required,
            "case table drift for local={local} total={total} pct={percent} min={min_nodes}"
        );

        let profile = FleetPartitionProfile {
            description: "Quorum threshold computation".to_string(),
            partition_mode: "degraded".to_string(),
            // Healthy links (>=50%) so the base verdict is convergence-possible
            // and ONLY the quorum math can flip it to impossible.
            message_success_rate: 90,
            local_partition_size: Some(local),
            total_fleet_size: Some(total),
            expected_convergence: true,
            convergence_timeout_ms: Some(2000),
            convergence_impossible_reason: None,
            failure_mode: None,
            gate_verdict: None,
        };

        let config = PartitionGateConfig {
            quorum_threshold_percent: percent,
            minimum_required_nodes: min_nodes,
            convergence_impossible_profiles: vec![],
            slo_publication_blocked_on_impossible: true,
            manifest_failure_reporting: true,
        };

        let mut profiles_map = BTreeMap::new();
        profiles_map.insert("quorum".to_string(), profile);

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

        let result = gate
            .evaluate_profile("quorum")
            .expect("evaluation should succeed");

        assert_eq!(
            result.convergence_possible, expect_possible,
            "local={local} total={total} pct={percent} min={min_nodes} \
             (required={expected_required}): convergence_possible mismatch"
        );

        if expect_possible {
            assert_eq!(
                result.gate_verdict, "convergence-possible",
                "local={local} total={total}: at/above quorum must pass"
            );
        } else {
            assert_eq!(
                result.gate_verdict, "convergence-impossible",
                "local={local} total={total}: below quorum must be refused"
            );
            // The reason must report the exact computed threshold, pinning the
            // `max(floor(total*pct/100), min_nodes)` value end-to-end.
            let expected_reason = format!(
                "quorum impossible: local partition {local} < required {expected_required}"
            );
            assert_eq!(
                result.verdict_reason, expected_reason,
                "verdict reason must report the computed required threshold"
            );
        }
    }
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
    let result = gate
        .evaluate_profile("at_threshold")
        .expect("evaluation should succeed");

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
    let result = gate
        .evaluate_profile("insufficient_nodes")
        .expect("evaluation should succeed");

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
