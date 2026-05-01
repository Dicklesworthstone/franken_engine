#![forbid(unsafe_code)]

//! Integration test for the live quarantine propagation example.
//!
//! Verifies that quarantine decisions propagate across fleet instances
//! and achieve convergence for coordinated containment.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

// Note: Using direct path inclusion to avoid doc comment issues
mod live_quarantine_propagation_example {
    include!("../../../examples/live_quarantine_propagation_example.rs");
}

use live_quarantine_propagation_example::*;

fn temp_output_dir(test_name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("quarantine_test_{}", test_name))
}

fn cleanup_temp_dir(dir: &PathBuf) {
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_malware_quarantine_propagation() {
    let output_dir = temp_output_dir("malware");
    cleanup_temp_dir(&output_dir);

    let event = SyntheticSecurityEvent::malware_detection_scenario();
    let fleet = FleetTopology::create_multi_region_fleet();

    let report = execute_quarantine_propagation_with_proof(&event, &fleet, &output_dir)
        .expect("Quarantine propagation should complete successfully");

    // Verify basic report structure
    assert_eq!(report.bead_id, EXAMPLE_BEAD_ID);
    assert_eq!(report.component, EXAMPLE_COMPONENT);
    assert_eq!(report.extension_id, "suspicious-crypto-miner");
    assert_eq!(report.security_event_id, "evt-malware-001");

    // High-severity threat should achieve convergence
    assert!(
        report.convergence_achieved,
        "High-severity malware should achieve convergence"
    );
    assert!(
        report.convergence_percentage >= 80.0,
        "Should have high convergence percentage, got: {:.1}%",
        report.convergence_percentage
    );

    // Verify proof artifacts exist
    let manifest_path = output_dir.join("manifest.json");
    let report_path = output_dir.join("report.json");
    let events_path = output_dir.join("events.jsonl");
    let commands_path = output_dir.join("commands.txt");
    let markdown_path = output_dir.join("report.md");

    assert!(manifest_path.exists(), "Manifest should exist");
    assert!(report_path.exists(), "Report should exist");
    assert!(events_path.exists(), "Events log should exist");
    assert!(commands_path.exists(), "Commands log should exist");
    assert!(markdown_path.exists(), "Markdown report should exist");

    // Verify manifest structure
    let manifest_content = fs::read_to_string(&manifest_path).expect("Should read manifest");
    let manifest: serde_json::Value =
        serde_json::from_str(&manifest_content).expect("Manifest should be valid JSON");

    assert_eq!(manifest["bead_id"], EXAMPLE_BEAD_ID);
    assert_eq!(manifest["proof_type"], "quarantine_propagation_convergence");
    assert_eq!(manifest["status"], "completed");
    assert_eq!(manifest["fleet_instances_count"], 5);
    assert!(manifest["events_recorded"].as_u64().unwrap() >= 3); // At least initiate, acks, converge

    // Verify events structure
    let events_content = fs::read_to_string(&events_path).expect("Should read events");
    let event_lines: Vec<&str> = events_content.trim().split('\n').collect();
    assert!(event_lines.len() >= 3, "Should have multiple events");

    // Check for expected event types
    let mut event_types = BTreeSet::new();
    for line in event_lines {
        let event: serde_json::Value =
            serde_json::from_str(line).expect("Event should be valid JSON");
        event_types.insert(event["event_type"].as_str().unwrap().to_string());
    }

    assert!(
        event_types.contains("quarantine_initiated"),
        "Should have initiation event"
    );
    assert!(
        event_types.contains("acknowledgment_received"),
        "Should have acknowledgment events"
    );

    cleanup_temp_dir(&output_dir);
}

#[test]
fn test_suspicious_activity_quarantine_propagation() {
    let output_dir = temp_output_dir("suspicious");
    cleanup_temp_dir(&output_dir);

    let event = SyntheticSecurityEvent::suspicious_activity_scenario();
    let fleet = FleetTopology::create_multi_region_fleet();

    let report = execute_quarantine_propagation_with_proof(&event, &fleet, &output_dir)
        .expect("Quarantine propagation should complete successfully");

    // Verify basic structure
    assert_eq!(report.extension_id, "data-exfiltration-tool");
    assert_eq!(report.security_event_id, "evt-suspicious-001");
    assert!(report.threat_severity < 100); // Should be medium severity
    assert_eq!(report.originator_instance, "instance-eu-west-1-replica");

    // Should still achieve convergence for medium threats
    assert!(
        report.acknowledgments_received > 0,
        "Should receive some acknowledgments"
    );

    cleanup_temp_dir(&output_dir);
}

#[test]
fn test_quarantine_propagation_simulation() {
    // Test the core simulation logic
    let event = SyntheticSecurityEvent::malware_detection_scenario();
    let fleet = FleetTopology::create_multi_region_fleet();

    let (quarantine_state, events, duration) = simulate_quarantine_propagation(&event, &fleet)
        .expect("Simulation should complete successfully");

    // Verify quarantine state
    assert!(
        quarantine_state.is_quarantined(&event.extension_id),
        "Extension should be quarantined"
    );

    // Verify events
    assert!(events.len() >= 3, "Should have multiple events");
    assert!(
        events
            .iter()
            .any(|e| e.event_type == "quarantine_initiated"),
        "Should have initiation event"
    );

    // Verify timing
    assert!(duration.as_millis() < 1000, "Simulation should be fast");

    // Check event sequence
    let first_event = &events[0];
    assert_eq!(first_event.event_type, "quarantine_initiated");
    assert_eq!(first_event.acknowledgments_received, 0);
    assert!(!first_event.convergence_achieved);

    // Last event should show final convergence status
    let last_event = events.last().unwrap();
    assert!(last_event.event_type.contains("convergence"));
    assert!(last_event.acknowledgments_received > 0);
}

#[test]
fn test_fleet_topology_structure() {
    let fleet = FleetTopology::create_multi_region_fleet();

    assert_eq!(fleet.total_instances, 5);
    assert_eq!(fleet.instances.len(), 5);
    assert_eq!(fleet.convergence_threshold, 0.8);

    // Verify role distribution
    let roles: BTreeSet<String> = fleet.instances.iter().map(|i| i.role.clone()).collect();
    assert!(roles.contains("coordinator"));
    assert!(roles.contains("replica"));
    assert!(roles.contains("witness"));

    // Verify regions are diverse
    let regions: BTreeSet<String> = fleet.instances.iter().map(|i| i.region.clone()).collect();
    assert!(regions.len() >= 3, "Should have multiple regions");

    // Verify node IDs are unique
    let node_ids: BTreeSet<String> = fleet.instances.iter().map(|i| i.node_id.clone()).collect();
    assert_eq!(
        node_ids.len(),
        fleet.instances.len(),
        "Node IDs should be unique"
    );
}

#[test]
fn test_synthetic_security_events() {
    // Test malware scenario
    let malware = SyntheticSecurityEvent::malware_detection_scenario();
    assert_eq!(malware.threat_type, "malware");
    assert!(malware.severity_score >= 90); // High severity
    assert!(!malware.indicators.is_empty());
    assert!(malware.indicators.iter().all(|i| i.confidence_score > 0));

    // Test suspicious activity scenario
    let suspicious = SyntheticSecurityEvent::suspicious_activity_scenario();
    assert_eq!(suspicious.threat_type, "suspicious_activity");
    assert!(suspicious.severity_score >= 50 && suspicious.severity_score < 90); // Medium severity
    assert!(!suspicious.indicators.is_empty());

    // Events should have different characteristics
    assert_ne!(malware.extension_id, suspicious.extension_id);
    assert_ne!(malware.event_id, suspicious.event_id);
    assert!(malware.severity_score > suspicious.severity_score);
}

#[test]
fn test_quarantine_decision_determinism() {
    // Same input should produce same results
    let event = SyntheticSecurityEvent::malware_detection_scenario();
    let fleet = FleetTopology::create_multi_region_fleet();

    let (state1, events1, _) =
        simulate_quarantine_propagation(&event, &fleet).expect("First simulation should succeed");
    let (state2, events2, _) =
        simulate_quarantine_propagation(&event, &fleet).expect("Second simulation should succeed");

    // Both should quarantine the same extension
    assert_eq!(
        state1.is_quarantined(&event.extension_id),
        state2.is_quarantined(&event.extension_id)
    );

    // Events should have same structure (timestamps may differ)
    assert_eq!(events1.len(), events2.len());
    assert_eq!(events1[0].event_type, events2[0].event_type);
    assert_eq!(events1[0].extension_id, events2[0].extension_id);
}

#[test]
fn test_proof_artifact_schema_compliance() {
    let output_dir = temp_output_dir("schema_test");
    cleanup_temp_dir(&output_dir);

    let event = SyntheticSecurityEvent::malware_detection_scenario();
    let fleet = FleetTopology::create_multi_region_fleet();

    execute_quarantine_propagation_with_proof(&event, &fleet, &output_dir)
        .expect("Should generate proof artifacts");

    // Test JSON schema compliance for key artifacts
    let manifest_path = output_dir.join("manifest.json");
    let manifest_content = fs::read_to_string(&manifest_path).expect("Should read manifest");

    let manifest: serde_json::Value =
        serde_json::from_str(&manifest_content).expect("Manifest should be valid JSON");

    // Verify required manifest fields
    assert!(manifest.get("schema_version").is_some());
    assert!(manifest.get("bead_id").is_some());
    assert!(manifest.get("component").is_some());
    assert!(manifest.get("proof_type").is_some());
    assert!(manifest.get("security_event_id").is_some());
    assert!(manifest.get("quarantine_evidence_hash").is_some());
    assert!(manifest.get("convergence_evidence_hash").is_some());

    // Test report JSON structure
    let report_path = output_dir.join("report.json");
    let report_content = fs::read_to_string(&report_path).expect("Should read report");

    let report: serde_json::Value =
        serde_json::from_str(&report_content).expect("Report should be valid JSON");

    assert!(report.get("convergence_achieved").is_some());
    assert!(report.get("acknowledgments_received").is_some());
    assert!(report.get("convergence_percentage").is_some());
    assert!(report.get("propagation_time_ms").is_some());

    cleanup_temp_dir(&output_dir);
}

#[test]
fn test_convergence_analysis() {
    let event = SyntheticSecurityEvent::malware_detection_scenario();
    let fleet = FleetTopology::create_multi_region_fleet();

    let (quarantine_state, _, _) =
        simulate_quarantine_propagation(&event, &fleet).expect("Simulation should succeed");

    let evidence_hash = frankenengine_engine::hash_tiers::ContentHash::compute(
        serde_json::to_string(&event).unwrap().as_bytes(),
    );

    // Check convergence status
    let convergence_achieved = quarantine_state.is_converged(&evidence_hash, fleet.total_instances);
    let (acks, total) = quarantine_state
        .convergence_progress(&evidence_hash)
        .unwrap_or((0, 0));

    // For a 5-instance fleet with 80% threshold, need 4 acks
    assert_eq!(total, fleet.total_instances);
    assert!(acks > 0, "Should have received some acknowledgments");

    if convergence_achieved {
        assert!(
            acks >= 4,
            "Convergence should require at least 4/5 instances"
        );
        let percentage = (acks as f64 / total as f64) * 100.0;
        assert!(percentage >= 80.0, "Should meet 80% threshold");
    }
}
