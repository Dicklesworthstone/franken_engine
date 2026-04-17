use frankenengine_engine::composable_gate_framework::{
    BEAD_ID, COMPONENT, ExampleEvidence, ExampleGate, ExamplePolicy, Gate, GatePolicy, GateRunner,
    GateSeverity, GateVerdict, GateViolation, MILLIONTHS, SCHEMA_VERSION,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

#[test]
fn test_schema_version_format() {
    assert!(SCHEMA_VERSION.contains("composable-gate-framework"));
    assert!(SCHEMA_VERSION.contains(".v1"));
}

#[test]
fn test_component_name() {
    assert_eq!(COMPONENT, "composable_gate_framework");
}

#[test]
fn test_bead_id() {
    assert_eq!(BEAD_ID, "bd-2737p.3");
}

#[test]
fn test_millionths_constant() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

#[test]
fn test_gate_verdict_complete() {
    let verdicts = [
        GateVerdict::Approved,
        GateVerdict::Conditional,
        GateVerdict::Rejected,
        GateVerdict::Inconclusive,
    ];

    for verdict in verdicts {
        assert!(!verdict.as_str().is_empty());
    }
}

#[test]
fn test_gate_verdict_display_matches_as_str() {
    let verdicts = [
        GateVerdict::Approved,
        GateVerdict::Conditional,
        GateVerdict::Rejected,
        GateVerdict::Inconclusive,
    ];

    for verdict in verdicts {
        assert_eq!(format!("{}", verdict), verdict.as_str());
    }
}

#[test]
fn test_gate_verdict_allows_progression() {
    assert!(GateVerdict::Approved.allows_progression());
    assert!(GateVerdict::Conditional.allows_progression());
    assert!(!GateVerdict::Rejected.allows_progression());
    assert!(!GateVerdict::Inconclusive.allows_progression());
}

#[test]
fn test_gate_severity_complete() {
    let severities = [
        GateSeverity::Advisory,
        GateSeverity::Warning,
        GateSeverity::Error,
        GateSeverity::Critical,
    ];

    for severity in severities {
        assert!(!severity.as_str().is_empty());
    }
}

#[test]
fn test_gate_severity_blocking() {
    assert!(!GateSeverity::Advisory.is_blocking());
    assert!(!GateSeverity::Warning.is_blocking());
    assert!(GateSeverity::Error.is_blocking());
    assert!(GateSeverity::Critical.is_blocking());
}

#[test]
fn test_gate_violation_creation() {
    let violation = GateViolation::new(
        GateSeverity::Error,
        "test-category".to_string(),
        "Test violation description".to_string(),
    );

    assert_eq!(violation.severity, GateSeverity::Error);
    assert_eq!(violation.category, "test-category");
    assert_eq!(violation.description, "Test violation description");
    assert!(violation.recommendations.is_empty());
    assert!(violation.metadata.is_empty());
}

#[test]
fn test_gate_violation_builder_pattern() {
    let violation = GateViolation::new(
        GateSeverity::Warning,
        "builder-test".to_string(),
        "Builder test description".to_string(),
    )
    .with_recommendation("Fix the issue".to_string())
    .with_recommendation("Update documentation".to_string())
    .with_metadata("file".to_string(), "test.rs".to_string())
    .with_metadata("line".to_string(), "42".to_string());

    assert_eq!(violation.recommendations.len(), 2);
    assert_eq!(violation.metadata.len(), 2);
    assert_eq!(violation.metadata.get("file").unwrap(), "test.rs");
    assert_eq!(violation.metadata.get("line").unwrap(), "42");
}

#[test]
fn test_example_policy_implementation() {
    let policy = ExamplePolicy {
        policy_id: "test-policy-123".to_string(),
        max_violations: 10,
        strict_mode: true,
    };

    assert_eq!(policy.policy_id(), "test-policy-123");
    assert!(policy.is_strict());
}

#[test]
fn test_example_policy_non_strict() {
    let policy = ExamplePolicy {
        policy_id: "relaxed-policy".to_string(),
        max_violations: 5,
        strict_mode: false,
    };

    assert!(!policy.is_strict());
}

#[test]
fn test_example_evidence_implementation() {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let evidence = ExampleEvidence {
        evidence_type: "test-evidence-type".to_string(),
        violation_count: 7,
        timestamp: timestamp.clone(),
    };

    assert_eq!(evidence.evidence_type(), "test-evidence-type");
    assert!(evidence.is_sufficient());
    assert!(evidence.timestamp().is_some());
}

#[test]
fn test_example_evidence_insufficient() {
    let evidence = ExampleEvidence {
        evidence_type: String::new(), // Empty type makes evidence insufficient
        violation_count: 0,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    assert!(!evidence.is_sufficient());
}

#[test]
fn test_example_gate_metadata() {
    let gate = ExampleGate;

    assert_eq!(gate.gate_id(), "example-gate");
    assert_eq!(gate.display_name(), "Example Gate");
    assert!(!gate.description().is_empty());
}

#[test]
fn test_example_gate_validation_success() {
    let gate = ExampleGate;

    let policy = ExamplePolicy {
        policy_id: "valid-policy".to_string(),
        max_violations: 5,
        strict_mode: true,
    };

    let evidence = ExampleEvidence {
        evidence_type: "valid-evidence".to_string(),
        violation_count: 3,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    assert!(gate.validate_policy(&policy).is_ok());
    assert!(gate.validate_evidence(&evidence).is_ok());
}

#[test]
fn test_example_gate_validation_failure() {
    let gate = ExampleGate;

    let invalid_evidence = ExampleEvidence {
        evidence_type: String::new(), // Invalid: empty type
        violation_count: 0,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    assert!(gate.validate_evidence(&invalid_evidence).is_err());
}

#[test]
fn test_example_gate_evaluation_scenarios() {
    let gate = ExampleGate;

    // Scenario 1: Approved (violations within limit)
    let policy = ExamplePolicy {
        policy_id: "test".to_string(),
        max_violations: 5,
        strict_mode: true,
    };

    let good_evidence = ExampleEvidence {
        evidence_type: "test".to_string(),
        violation_count: 3,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let result = gate.evaluate(&policy, &good_evidence);
    assert_eq!(result.verdict, GateVerdict::Approved);
    assert!(result.violations.is_empty());

    // Scenario 2: Rejected (strict mode, violations exceed limit)
    let bad_evidence = ExampleEvidence {
        evidence_type: "test".to_string(),
        violation_count: 8,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let result = gate.evaluate(&policy, &bad_evidence);
    assert_eq!(result.verdict, GateVerdict::Rejected);
    assert!(!result.violations.is_empty());

    // Scenario 3: Conditional (non-strict mode, violations exceed limit)
    let relaxed_policy = ExamplePolicy {
        policy_id: "relaxed".to_string(),
        max_violations: 5,
        strict_mode: false,
    };

    let result = gate.evaluate(&relaxed_policy, &bad_evidence);
    assert_eq!(result.verdict, GateVerdict::Conditional);
    assert!(!result.violations.is_empty());
    assert!(!result.conditions.is_empty());
}

#[test]
fn test_gate_runner_creation() {
    let epoch = SecurityEpoch::from_raw(42);
    let runner = GateRunner::new(epoch);

    // Runner should be created successfully
    let _ = runner; // Use runner to avoid unused variable warning
}

#[test]
fn test_gate_runner_single_evaluation() {
    let epoch = SecurityEpoch::from_raw(1);
    let runner = GateRunner::new(epoch);
    let gate = ExampleGate;

    let policy = ExamplePolicy {
        policy_id: "runner-test".to_string(),
        max_violations: 3,
        strict_mode: false,
    };

    let evidence = ExampleEvidence {
        evidence_type: "runner-evidence".to_string(),
        violation_count: 2,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let result = runner.run_gate(&gate, &policy, &evidence);
    assert!(result.is_ok());

    let receipt = result.unwrap();
    assert_eq!(receipt.verdict, GateVerdict::Approved);
    assert_eq!(receipt.gate_id, "example-gate");
    assert_eq!(receipt.security_epoch, epoch);
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.bead_id, BEAD_ID);
    assert!(!receipt.timestamp.is_empty());
}

#[test]
fn test_gate_runner_batch_evaluation() {
    let epoch = SecurityEpoch::from_raw(2);
    let runner = GateRunner::new(epoch);

    let gates = vec![ExampleGate, ExampleGate, ExampleGate];

    let policy = ExamplePolicy {
        policy_id: "batch-test".to_string(),
        max_violations: 10,
        strict_mode: false,
    };

    let evidence = ExampleEvidence {
        evidence_type: "batch-evidence".to_string(),
        violation_count: 5,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let result = runner.run_gate_batch(&gates, &policy, &evidence);
    assert!(result.is_ok());

    let receipts = result.unwrap();
    assert_eq!(receipts.len(), 3);

    // All receipts should have the same basic properties
    for receipt in &receipts {
        assert_eq!(receipt.gate_id, "example-gate");
        assert_eq!(receipt.security_epoch, epoch);
        assert_eq!(receipt.verdict, GateVerdict::Approved);
    }
}

#[test]
fn test_gate_runner_validation_failure() {
    let epoch = SecurityEpoch::from_raw(1);
    let runner = GateRunner::new(epoch);
    let gate = ExampleGate;

    let policy = ExamplePolicy {
        policy_id: "valid".to_string(),
        max_violations: 5,
        strict_mode: true,
    };

    let invalid_evidence = ExampleEvidence {
        evidence_type: String::new(), // Invalid
        violation_count: 0,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let result = runner.run_gate(&gate, &policy, &invalid_evidence);
    assert!(result.is_err());
}

#[test]
fn test_content_hash_consistency() {
    let epoch = SecurityEpoch::from_raw(1);
    let runner = GateRunner::new(epoch);
    let gate = ExampleGate;

    let policy = ExamplePolicy {
        policy_id: "hash-test".to_string(),
        max_violations: 5,
        strict_mode: true,
    };

    let evidence = ExampleEvidence {
        evidence_type: "hash-evidence".to_string(),
        violation_count: 2,
        timestamp: "2024-01-01T12:00:00Z".to_string(), // Fixed for determinism
    };

    let receipt1 = runner.run_gate(&gate, &policy, &evidence).unwrap();
    let receipt2 = runner.run_gate(&gate, &policy, &evidence).unwrap();

    // Content hashes should be equal for identical evaluations
    // (timestamps will differ, but content hashes should be based on evaluation data)
    assert_eq!(receipt1.content_hash, receipt2.content_hash);
}

#[test]
fn test_receipt_serialization_roundtrip() {
    let epoch = SecurityEpoch::from_raw(3);
    let runner = GateRunner::new(epoch);
    let gate = ExampleGate;

    let policy = ExamplePolicy {
        policy_id: "serde-test".to_string(),
        max_violations: 7,
        strict_mode: false,
    };

    let evidence = ExampleEvidence {
        evidence_type: "serde-evidence".to_string(),
        violation_count: 9, // Exceeds limit to trigger conditional
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    let receipt = runner.run_gate(&gate, &policy, &evidence).unwrap();

    // Serialize and deserialize
    let json = serde_json::to_string(&receipt).unwrap();
    let deserialized = serde_json::from_str(&json).unwrap();

    // Compare key fields
    assert_eq!(receipt.verdict, deserialized.verdict);
    assert_eq!(receipt.gate_id, deserialized.gate_id);
    assert_eq!(receipt.security_epoch, deserialized.security_epoch);
    assert_eq!(receipt.content_hash, deserialized.content_hash);
}

#[test]
fn test_framework_extensibility() {
    // This test demonstrates that the framework can be extended
    // with custom policy and evidence types

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct CustomPolicy {
        policy_id: String,
        threshold: f64,
    }

    impl GatePolicy for CustomPolicy {
        fn policy_id(&self) -> &str {
            &self.policy_id
        }
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct CustomEvidence {
        evidence_type: String,
        metric_value: f64,
    }

    impl frankenengine_engine::composable_gate_framework::GateEvidence for CustomEvidence {
        fn evidence_type(&self) -> &str {
            &self.evidence_type
        }
    }

    struct CustomGate;

    impl Gate<CustomPolicy, CustomEvidence> for CustomGate {
        fn gate_id(&self) -> &str {
            "custom-gate"
        }

        fn display_name(&self) -> &str {
            "Custom Gate"
        }

        fn description(&self) -> &str {
            "Custom gate implementation"
        }

        fn evaluate(
            &self,
            policy: &CustomPolicy,
            evidence: &CustomEvidence,
        ) -> frankenengine_engine::composable_gate_framework::GateResult<CustomPolicy, CustomEvidence>
        {
            let verdict = if evidence.metric_value <= policy.threshold {
                GateVerdict::Approved
            } else {
                GateVerdict::Rejected
            };

            frankenengine_engine::composable_gate_framework::GateResult::new(
                verdict,
                policy.clone(),
                evidence.clone(),
            )
        }
    }

    // Test the custom gate
    let runner = GateRunner::new(SecurityEpoch::from_raw(1));
    let gate = CustomGate;

    let policy = CustomPolicy {
        policy_id: "custom-policy".to_string(),
        threshold: 0.5,
    };

    let evidence = CustomEvidence {
        evidence_type: "custom-evidence".to_string(),
        metric_value: 0.3,
    };

    let result = runner.run_gate(&gate, &policy, &evidence);
    assert!(result.is_ok());

    let receipt = result.unwrap();
    assert_eq!(receipt.verdict, GateVerdict::Approved);
    assert_eq!(receipt.gate_id, "custom-gate");
}
