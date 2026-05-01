#![forbid(unsafe_code)]

//! Integration test for the live IFC declassification runtime example.
//!
//! Tests the actual FrankenEngine declassification pipeline with live
//! source-to-sink flows and proof artifact generation.

use std::fs;
use std::path::PathBuf;

// Note: Using direct path inclusion to avoid doc comment issues
mod live_ifc_declassification_example {
    include!("../../../examples/live_ifc_declassification_example.rs");
}

use live_ifc_declassification_example::*;

fn temp_output_dir(test_name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("ifc_runtime_test_{}", test_name))
}

fn cleanup_temp_dir(dir: &PathBuf) {
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_allowed_declassification_scenario() {
    let output_dir = temp_output_dir("allowed");
    cleanup_temp_dir(&output_dir);

    let signing_key = create_signing_key();
    let policy = create_flow_policy(&signing_key);
    let scenario = IfcFlowScenario::allowed_declassification_scenario();

    let result = execute_ifc_flow_scenario(&scenario, &policy, &signing_key)
        .expect("Allowed flow scenario should complete successfully");

    // Verify result structure
    assert_eq!(result.bead_id, EXAMPLE_BEAD_ID);
    assert_eq!(result.component, EXAMPLE_COMPONENT);
    assert_eq!(result.scenario_id, "allowed-api-metrics-to-incident");
    assert!(result.flow_attempted, "Flow should have been attempted");
    assert!(result.declassification_required, "Flow should require declassification");
    assert!(result.declassification_approved, "Declassification should be approved");
    assert!(result.flow_completed, "Flow should complete successfully");
    assert!(result.receipt_generated, "Receipt should be generated");
    assert!(result.receipt_hash.is_some(), "Receipt hash should be present");
    assert!(result.error_reason.is_none(), "Should have no error");

    // Generate proof artifacts and verify they exist
    let results = vec![result];
    generate_ifc_proof_artifacts(&results, &policy, &output_dir)
        .expect("Should generate proof artifacts");

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
    let manifest_content = fs::read_to_string(&manifest_path)
        .expect("Should read manifest");
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content)
        .expect("Manifest should be valid JSON");

    assert_eq!(manifest["bead_id"], EXAMPLE_BEAD_ID);
    assert_eq!(manifest["component"], EXAMPLE_COMPONENT);
    assert_eq!(manifest["proof_type"], "ifc_declassification_flow_verification");
    assert_eq!(manifest["flow_scenarios_count"], 1);
    assert_eq!(manifest["status"], "completed");
    assert!(manifest["flow_verification_evidence_hash"].as_str().unwrap().len() > 0);

    // Verify report structure
    let report_content = fs::read_to_string(&report_path)
        .expect("Should read report");
    let report: serde_json::Value = serde_json::from_str(&report_content)
        .expect("Report should be valid JSON");

    assert_eq!(report["flow_scenarios_executed"], 1);
    assert_eq!(report["flows_requiring_declassification"], 1);
    assert_eq!(report["declassifications_approved"], 1);
    assert_eq!(report["flows_completed_successfully"], 1);
    assert_eq!(report["receipts_generated"], 1);

    cleanup_temp_dir(&output_dir);
}

#[test]
fn test_denied_flow_scenario() {
    let output_dir = temp_output_dir("denied");
    cleanup_temp_dir(&output_dir);

    let signing_key = create_signing_key();
    let policy = create_flow_policy(&signing_key);
    let scenario = IfcFlowScenario::denied_flow_scenario();

    let result = execute_ifc_flow_scenario(&scenario, &policy, &signing_key)
        .expect("Denied flow scenario should complete successfully");

    // Verify result structure for denied flow
    assert_eq!(result.bead_id, EXAMPLE_BEAD_ID);
    assert_eq!(result.component, EXAMPLE_COMPONENT);
    assert_eq!(result.scenario_id, "denied-debug-to-logs");
    assert!(result.flow_attempted, "Flow should have been attempted");
    assert!(result.declassification_required, "Flow should require declassification");
    assert!(!result.declassification_approved, "Declassification should be denied");
    assert!(!result.flow_completed, "Flow should not complete");
    assert!(!result.receipt_generated, "Receipt should not be generated");
    assert!(result.receipt_hash.is_none(), "Receipt hash should be None");
    assert!(result.error_reason.is_some(), "Should have error reason");

    let error_reason = result.error_reason.as_ref().unwrap();
    assert!(error_reason.contains("No matching") || error_reason.contains("route"),
            "Error should mention missing route, got: {}", error_reason);

    cleanup_temp_dir(&output_dir);
}

#[test]
fn test_complete_ifc_demonstration() {
    let output_dir = temp_output_dir("complete");
    cleanup_temp_dir(&output_dir);

    let signing_key = create_signing_key();
    let policy = create_flow_policy(&signing_key);

    // Test both scenarios
    let scenarios = [
        IfcFlowScenario::allowed_declassification_scenario(),
        IfcFlowScenario::denied_flow_scenario(),
    ];

    let mut results = Vec::new();
    for scenario in &scenarios {
        let result = execute_ifc_flow_scenario(scenario, &policy, &signing_key)
            .expect("Scenario should complete");
        results.push(result);
    }

    assert_eq!(results.len(), 2);

    // Generate combined proof artifacts
    generate_ifc_proof_artifacts(&results, &policy, &output_dir)
        .expect("Should generate proof artifacts");

    // Verify combined results
    let report_path = output_dir.join("report.json");
    let report_content = fs::read_to_string(&report_path)
        .expect("Should read report");
    let report: serde_json::Value = serde_json::from_str(&report_content)
        .expect("Report should be valid JSON");

    assert_eq!(report["flow_scenarios_executed"], 2);
    assert_eq!(report["flows_requiring_declassification"], 2);
    assert_eq!(report["declassifications_approved"], 1); // Only the allowed one
    assert_eq!(report["flows_completed_successfully"], 1); // Only the allowed one
    assert_eq!(report["receipts_generated"], 1); // Only the allowed one

    // Verify events structure
    let events_path = output_dir.join("events.jsonl");
    let events_content = fs::read_to_string(&events_path)
        .expect("Should read events");
    let event_lines: Vec<&str> = events_content.trim().split('\n').collect();
    assert_eq!(event_lines.len(), 2, "Should have two event lines");

    // Verify each event is valid JSON
    for line in event_lines {
        let event: serde_json::Value = serde_json::from_str(line)
            .expect("Event should be valid JSON");
        assert_eq!(event["event_type"], "scenario_execution");
        assert!(event["scenario_id"].as_str().unwrap().len() > 0);
        assert!(event["execution_time_ms"].is_u64());
    }

    cleanup_temp_dir(&output_dir);
}

#[test]
fn test_classified_data_sources() {
    let api_metrics = ClassifiedDataSource::confidential_api_metrics();
    assert_eq!(api_metrics.source_id, "api-metrics-source");
    assert_eq!(api_metrics.label, Label::Confidential);
    assert!(api_metrics.content.contains("API performance metrics"));
    assert!(api_metrics.content.contains("/api/users/list"));
    assert!(!api_metrics.content_hash.is_empty());

    let debug_data = ClassifiedDataSource::internal_debug_data();
    assert_eq!(debug_data.source_id, "debug-data-source");
    assert_eq!(debug_data.label, Label::Internal);
    assert!(debug_data.content.contains("DEBUG:"));
    assert!(debug_data.content.contains("session_token"));
    assert!(!debug_data.content_hash.is_empty());

    // Content hashes should be different
    assert_ne!(api_metrics.content_hash, debug_data.content_hash);
}

#[test]
fn test_data_sinks() {
    let incident_sink = DataSink::public_incident_report();
    assert_eq!(incident_sink.sink_id, "incident-report-sink");
    assert_eq!(incident_sink.clearance, Label::Public);
    assert!(incident_sink.description.contains("incident"));

    let logs_sink = DataSink::public_application_logs();
    assert_eq!(logs_sink.sink_id, "application-logs-sink");
    assert_eq!(logs_sink.clearance, Label::Public);
    assert!(logs_sink.description.contains("logs"));
}

#[test]
fn test_flow_policy_structure() {
    let signing_key = create_signing_key();
    let policy = create_flow_policy(&signing_key);

    assert_eq!(policy.policy_id, "franken-ifc-policy-v1");
    assert_eq!(policy.extension_id, EXAMPLE_COMPONENT);

    // Should have 4 label classes
    assert_eq!(policy.label_classes.len(), 4);
    assert!(policy.label_classes.contains(&Label::Public));
    assert!(policy.label_classes.contains(&Label::Internal));
    assert!(policy.label_classes.contains(&Label::Confidential));
    assert!(policy.label_classes.contains(&Label::Secret));

    // Should have same clearance classes
    assert_eq!(policy.clearance_classes.len(), 4);
    assert!(policy.clearance_classes.contains(&Label::Public));

    // Should have one declassification route
    assert_eq!(policy.declassification_routes.len(), 1);
    let route = &policy.declassification_routes[0];
    assert_eq!(route.route_id, "confidential-to-public-incident");
    assert_eq!(route.source_label, Label::Confidential);
    assert_eq!(route.target_clearance, Label::Public);
    assert_eq!(route.conditions.len(), 3);
    assert!(route.conditions.contains(&"security_review".to_string()));
    assert!(route.conditions.contains(&"pii_scrubbing".to_string()));
    assert!(route.conditions.contains(&"incident_response_approval".to_string()));
}

#[test]
fn test_signing_key_determinism() {
    let key1 = create_signing_key();
    let key2 = create_signing_key();

    // Keys should be identical (deterministic)
    assert_eq!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_flow_verification_result_serde() {
    let result = FlowVerificationResult {
        bead_id: EXAMPLE_BEAD_ID.to_string(),
        component: EXAMPLE_COMPONENT.to_string(),
        scenario_id: "test-scenario".to_string(),
        flow_attempted: true,
        declassification_required: true,
        declassification_approved: false,
        flow_completed: false,
        receipt_generated: false,
        receipt_hash: None,
        error_reason: Some("Test error".to_string()),
        execution_time_ms: 150,
    };

    // Test serialization/deserialization
    let json = serde_json::to_string(&result).expect("Should serialize");
    let parsed: FlowVerificationResult = serde_json::from_str(&json)
        .expect("Should deserialize");

    assert_eq!(result.bead_id, parsed.bead_id);
    assert_eq!(result.scenario_id, parsed.scenario_id);
    assert_eq!(result.flow_attempted, parsed.flow_attempted);
    assert_eq!(result.declassification_required, parsed.declassification_required);
    assert_eq!(result.error_reason, parsed.error_reason);
    assert_eq!(result.execution_time_ms, parsed.execution_time_ms);
}

#[test]
fn test_label_flow_logic() {
    // Test lattice-legal flows (no declassification needed)
    assert!(Label::Public.can_flow_to(&Label::Public));
    assert!(Label::Public.can_flow_to(&Label::Internal));
    assert!(Label::Public.can_flow_to(&Label::Confidential));
    assert!(Label::Public.can_flow_to(&Label::Secret));

    // Test flows requiring declassification
    assert!(!Label::Confidential.can_flow_to(&Label::Public));
    assert!(!Label::Internal.can_flow_to(&Label::Public));
    assert!(!Label::Secret.can_flow_to(&Label::Confidential));
    assert!(!Label::Secret.can_flow_to(&Label::Internal));
    assert!(!Label::Secret.can_flow_to(&Label::Public));

    // Test within-level flows
    assert!(Label::Confidential.can_flow_to(&Label::Confidential));
    assert!(Label::Internal.can_flow_to(&Label::Internal));
}

#[test]
fn test_scenarios_have_different_characteristics() {
    let allowed = IfcFlowScenario::allowed_declassification_scenario();
    let denied = IfcFlowScenario::denied_flow_scenario();

    // Should have different IDs and descriptions
    assert_ne!(allowed.scenario_id, denied.scenario_id);
    assert_ne!(allowed.description, denied.description);

    // Should have different source/sink combinations
    assert_ne!(allowed.source.source_id, denied.source.source_id);
    assert_ne!(allowed.sink.sink_id, denied.sink.sink_id);

    // Should have different expected results
    assert_ne!(allowed.expected_result, denied.expected_result);
    assert_eq!(allowed.expected_result, "allowed");
    assert_eq!(denied.expected_result, "denied");

    // Both should require declassification for the flows we're testing
    assert!(allowed.should_require_declassification);
    assert!(denied.should_require_declassification);
}

#[test]
fn test_proof_artifact_json_schema_compliance() {
    let output_dir = temp_output_dir("schema_test");
    cleanup_temp_dir(&output_dir);

    let signing_key = create_signing_key();
    let policy = create_flow_policy(&signing_key);
    let scenario = IfcFlowScenario::allowed_declassification_scenario();

    let result = execute_ifc_flow_scenario(&scenario, &policy, &signing_key)
        .expect("Should execute scenario");

    let results = vec![result];
    generate_ifc_proof_artifacts(&results, &policy, &output_dir)
        .expect("Should generate artifacts");

    // Test JSON schema compliance for key artifacts
    let manifest_path = output_dir.join("manifest.json");
    let manifest_content = fs::read_to_string(&manifest_path)
        .expect("Should read manifest");

    let manifest: serde_json::Value = serde_json::from_str(&manifest_content)
        .expect("Manifest should be valid JSON");

    // Verify required manifest fields exist and have correct types
    assert!(manifest.get("schema_version").is_some());
    assert!(manifest.get("bead_id").is_some());
    assert!(manifest.get("component").is_some());
    assert!(manifest.get("proof_type").is_some());
    assert!(manifest.get("flow_scenarios_count").is_some());
    assert!(manifest.get("policy_id").is_some());
    assert!(manifest.get("flow_verification_evidence_hash").is_some());
    assert!(manifest.get("policy_evidence_hash").is_some());
    assert!(manifest.get("status").is_some());
    assert!(manifest.get("generated_at_utc").is_some());

    // Test specific values
    assert_eq!(manifest["schema_version"], "cd3d2b4d.franken-engine.ifc-declassification.v1");
    assert_eq!(manifest["bead_id"], EXAMPLE_BEAD_ID);
    assert_eq!(manifest["component"], EXAMPLE_COMPONENT);
    assert_eq!(manifest["proof_type"], "ifc_declassification_flow_verification");
    assert_eq!(manifest["flow_scenarios_count"], 1);
    assert_eq!(manifest["status"], "completed");

    // Test report JSON structure
    let report_path = output_dir.join("report.json");
    let report_content = fs::read_to_string(&report_path)
        .expect("Should read report");

    let report: serde_json::Value = serde_json::from_str(&report_content)
        .expect("Report should be valid JSON");

    assert!(report.get("flow_scenarios_executed").is_some());
    assert!(report.get("flows_requiring_declassification").is_some());
    assert!(report.get("declassifications_approved").is_some());
    assert!(report.get("flows_completed_successfully").is_some());
    assert!(report.get("receipts_generated").is_some());
    assert!(report.get("total_execution_time_ms").is_some());
    assert!(report.get("scenarios").is_some());

    // Scenarios should be an array
    assert!(report["scenarios"].is_array());
    assert_eq!(report["scenarios"].as_array().unwrap().len(), 1);

    cleanup_temp_dir(&output_dir);
}