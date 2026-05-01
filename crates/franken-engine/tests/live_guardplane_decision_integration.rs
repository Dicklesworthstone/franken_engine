#![forbid(unsafe_code)]

//! Integration test for the live guardplane posterior and expected-loss decision example.
//!
//! Verifies that the guardplane can compute Bayesian posteriors and select
//! optimal containment actions using expected-loss minimization.

use std::path::PathBuf;

use serde_json;

// Use relative path to examples since it's outside the crate
include!("../../../examples/live_guardplane_decision_example.rs");

fn temp_output_dir(test_name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("guardplane_test_{}", test_name))
}

fn cleanup_temp_dir(dir: &PathBuf) {
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn test_suspicious_extension_decision() {
    let output_dir = temp_output_dir("suspicious");
    cleanup_temp_dir(&output_dir);

    let input = SyntheticDecisionInput::suspicious_extension_scenario();
    let report = execute_guardplane_decision_with_proof(&input, &output_dir)
        .expect("Guardplane decision should complete successfully");

    // Verify basic report structure
    assert_eq!(report.bead_id, EXAMPLE_BEAD_ID);
    assert_eq!(report.component, EXAMPLE_COMPONENT);
    assert_eq!(report.extension_id, "suspicious-extension-v1.2.3");

    // Suspicious extension should be mitigated, not allowed.
    assert!(
        report.selected_action != "allow",
        "Suspicious extension should not be allowed, got: {}",
        report.selected_action
    );

    // Confidence is derived from decision margin/posterior concentration, not a
    // hardcoded proof score.
    assert!(
        report.confidence_score > 0 && report.confidence_score <= 1_000_000,
        "Confidence should be a valid millionths score, got: {}",
        report.confidence_score
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
    let manifest_content = std::fs::read_to_string(&manifest_path).expect("Should read manifest");
    let manifest: GuardplaneDecisionManifest =
        serde_json::from_str(&manifest_content).expect("Manifest should be valid JSON");

    assert_eq!(manifest.bead_id, EXAMPLE_BEAD_ID);
    assert_eq!(manifest.proof_type, "guardplane_live_decision_example");
    assert_eq!(manifest.status, "completed");
    assert_eq!(manifest.commands_executed, 0);
    assert_eq!(manifest.events_recorded, 1);
    assert!(!manifest.evidence_hash.is_empty());
    assert!(!manifest.decision_hash.is_empty());

    let commands_content = std::fs::read_to_string(&commands_path).expect("Should read commands");
    assert!(
        commands_content.contains("PROVISIONAL: synthetic example for documentation"),
        "Synthetic command evidence should be explicitly marked provisional"
    );
    assert!(
        commands_content.contains("\"exit_code\":null"),
        "Provisional command evidence must not fabricate exit success"
    );

    // Verify events structure
    let events_content = std::fs::read_to_string(&events_path).expect("Should read events");
    let event: GuardplaneDecisionEvent =
        serde_json::from_str(events_content.trim()).expect("Event should be valid JSON");

    assert_eq!(event.component, EXAMPLE_COMPONENT);
    assert_eq!(event.event_type, "guardplane_decision");
    assert_eq!(event.extension_id, "suspicious-extension-v1.2.3");
    assert_eq!(event.loss_matrix_id, "security_focused_v1");

    // Verify posterior probabilities sum to 1.0 (1_000_000 millionths)
    let total_probability: u64 = event.posterior_probabilities.values().sum();
    assert_eq!(
        total_probability, 1_000_000,
        "Posterior probabilities should sum to 1.0"
    );

    // For suspicious extension, P(malicious) should be elevated
    let p_malicious = event.posterior_probabilities.get("malicious").unwrap();
    assert!(
        *p_malicious > 100_000, // Should be > 10% for suspicious extension
        "Suspicious extension should have elevated P(malicious), got: {}",
        p_malicious
    );

    cleanup_temp_dir(&output_dir);
}

#[test]
fn test_benign_extension_decision() {
    let output_dir = temp_output_dir("benign");
    cleanup_temp_dir(&output_dir);

    let input = SyntheticDecisionInput::benign_extension_scenario();
    let report = execute_guardplane_decision_with_proof(&input, &output_dir)
        .expect("Guardplane decision should complete successfully");

    // Verify basic report structure
    assert_eq!(report.extension_id, "trusted-extension-v2.1.0");

    // Benign extension should be allowed or challenged at most.
    assert!(
        report.selected_action == "allow" || report.selected_action == "challenge",
        "Benign extension should not be severely contained, got: {}",
        report.selected_action
    );

    // Verify events structure
    let events_path = output_dir.join("events.jsonl");
    let events_content = std::fs::read_to_string(&events_path).expect("Should read events");
    let event: GuardplaneDecisionEvent =
        serde_json::from_str(events_content.trim()).expect("Event should be valid JSON");

    // For benign extension, P(benign) should remain high
    let p_benign = event.posterior_probabilities.get("benign").unwrap();
    assert!(
        *p_benign > 700_000, // Should remain > 70% for benign extension
        "Benign extension should have high P(benign), got: {}",
        p_benign
    );

    // P(malicious) should be low
    let p_malicious = event.posterior_probabilities.get("malicious").unwrap();
    assert!(
        *p_malicious < 200_000, // Should be < 20% for benign extension
        "Benign extension should have low P(malicious), got: {}",
        p_malicious
    );

    cleanup_temp_dir(&output_dir);
}

#[test]
fn test_posterior_computation_logic() {
    // Test the posterior computation with known inputs
    let suspicious_input = SyntheticDecisionInput {
        extension_id: "test-extension".to_string(),
        operation_type: "test_operation".to_string(),
        hostcall_evidence: vec![HostcallEvidence {
            hostcall_name: "high_risk_call".to_string(),
            frequency: 100,
            anomaly_score_millionths: 900_000, // 90% anomaly
            privilege_level: "elevated".to_string(),
        }],
        prior_violations: 3,         // High number of prior violations
        time_since_install_hours: 1, // Recently installed
    };

    let posterior = compute_evidence_posterior(&suspicious_input);

    // Verify probabilities are valid
    assert!(
        posterior.p_benign >= 10_000,
        "P(benign) should be at least 1%"
    );
    assert!(
        posterior.p_malicious <= 800_000,
        "P(malicious) should be at most 80%"
    );

    let total =
        posterior.p_benign + posterior.p_anomalous + posterior.p_malicious + posterior.p_unknown;
    assert_eq!(total, 1_000_000, "Probabilities should sum to 1.0");

    // High anomaly score and violations should increase P(malicious)
    assert!(
        posterior.p_malicious > 100_000, // Should be > 10%
        "High-risk input should increase P(malicious)"
    );
}

#[test]
fn test_loss_matrix_completeness() {
    let loss_matrix = create_security_loss_matrix();

    // Verify matrix covers all action-state combinations
    assert!(loss_matrix.is_complete(), "Loss matrix should be complete");

    // Verify reasonable loss values
    use frankenengine_engine::bayesian_posterior::RiskState;
    use frankenengine_engine::expected_loss_selector::ContainmentAction;

    // Allow + Malicious should have high loss (security risk)
    let allow_malicious_loss = loss_matrix.loss(ContainmentAction::Allow, RiskState::Malicious);
    assert!(
        allow_malicious_loss > 500_000, // Should be > 50% loss
        "Allowing malicious extension should have high loss"
    );

    // Suspend + Benign should have moderate loss (usability impact)
    let deny_benign_loss = loss_matrix.loss(ContainmentAction::Suspend, RiskState::Benign);
    assert!(
        deny_benign_loss > 100_000, // Should be > 10% loss
        "Suspending benign extension should have some cost"
    );

    // Terminate + Malicious should have low loss (good security decision)
    let kill_malicious_loss = loss_matrix.loss(ContainmentAction::Terminate, RiskState::Malicious);
    assert!(
        kill_malicious_loss < 100_000, // Should be < 10% loss
        "Terminating malicious extension should have low loss"
    );
}

#[test]
fn test_expected_loss_selector_determinism() {
    // Same input should produce same decision
    let input = SyntheticDecisionInput::suspicious_extension_scenario();
    let posterior1 = compute_evidence_posterior(&input);
    let posterior2 = compute_evidence_posterior(&input);

    // Posteriors should be identical
    assert_eq!(posterior1.p_benign, posterior2.p_benign);
    assert_eq!(posterior1.p_malicious, posterior2.p_malicious);

    // Decisions should be identical
    let loss_matrix = create_security_loss_matrix();
    let mut selector1 = ExpectedLossSelector::new(loss_matrix.clone());
    let mut selector2 = ExpectedLossSelector::new(loss_matrix);

    let decision1 = selector1.select(&posterior1);
    let decision2 = selector2.select(&posterior2);

    assert_eq!(decision1.action, decision2.action);
    assert_eq!(
        decision1.expected_loss_millionths,
        decision2.expected_loss_millionths
    );
}

#[test]
fn test_proof_artifact_schema_compliance() {
    let output_dir = temp_output_dir("schema_test");
    cleanup_temp_dir(&output_dir);

    let input = SyntheticDecisionInput::benign_extension_scenario();
    execute_guardplane_decision_with_proof(&input, &output_dir)
        .expect("Should generate proof artifacts");

    // Test JSON schema compliance for key artifacts
    let manifest_path = output_dir.join("manifest.json");
    let manifest_content = std::fs::read_to_string(&manifest_path).expect("Should read manifest");

    let manifest: serde_json::Value =
        serde_json::from_str(&manifest_content).expect("Manifest should be valid JSON");

    // Verify required manifest fields
    assert!(manifest.get("schema_version").is_some());
    assert!(manifest.get("bead_id").is_some());
    assert!(manifest.get("component").is_some());
    assert!(manifest.get("proof_type").is_some());
    assert!(manifest.get("status").is_some());
    assert!(manifest.get("generated_at_utc").is_some());

    // Test report JSON structure
    let report_path = output_dir.join("report.json");
    let report_content = std::fs::read_to_string(&report_path).expect("Should read report");

    let report: serde_json::Value =
        serde_json::from_str(&report_content).expect("Report should be valid JSON");

    assert!(report.get("posterior_risk_assessment").is_some());
    assert!(report.get("expected_losses").is_some());
    assert!(report.get("selected_action").is_some());
    assert!(report.get("confidence_score").is_some());

    cleanup_temp_dir(&output_dir);
}
