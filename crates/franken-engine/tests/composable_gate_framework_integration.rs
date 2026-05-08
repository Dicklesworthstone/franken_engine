use frankenengine_engine::composable_gate_framework::{
    BEAD_ID, COMPONENT, ExampleEvidence, ExampleGate, ExamplePolicy, Gate, GateEvidence,
    GatePolicy, GateReceipt, GateResult, GateRunner, GateSeverity, GateVerdict, GateViolation,
    MILLIONTHS, SCHEMA_VERSION,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use std::sync::Mutex;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ContractPolicy {
    policy_id: String,
    strict_mode: bool,
    valid: bool,
}

impl GatePolicy for ContractPolicy {
    fn policy_id(&self) -> &str {
        &self.policy_id
    }

    fn is_strict(&self) -> bool {
        self.strict_mode
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ContractEvidence {
    evidence_type: String,
    sufficient: bool,
    timestamp_utc: String,
}

impl GateEvidence for ContractEvidence {
    fn evidence_type(&self) -> &str {
        &self.evidence_type
    }

    fn is_sufficient(&self) -> bool {
        self.sufficient
    }

    fn timestamp(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        chrono::DateTime::parse_from_rfc3339(&self.timestamp_utc)
            .ok()
            .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
    }
}

trait ContractCallLog {
    fn calls(&self) -> Vec<&'static str>;
    fn clear_calls(&self);
}

struct ContractGate {
    gate_id: &'static str,
    dependencies: Vec<String>,
    verdict: GateVerdict,
    calls: Mutex<Vec<&'static str>>,
}

impl ContractGate {
    fn new(gate_id: &'static str, verdict: GateVerdict) -> Self {
        Self {
            gate_id,
            dependencies: Vec::new(),
            verdict,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn with_dependencies(
        gate_id: &'static str,
        verdict: GateVerdict,
        dependencies: &[&str],
    ) -> Self {
        Self {
            gate_id,
            dependencies: dependencies
                .iter()
                .map(|dependency| (*dependency).to_string())
                .collect(),
            verdict,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn record_call(&self, call: &'static str) {
        self.calls
            .lock()
            .expect("contract call log lock should not be poisoned")
            .push(call);
    }
}

impl ContractCallLog for ContractGate {
    fn calls(&self) -> Vec<&'static str> {
        self.calls
            .lock()
            .expect("contract call log lock should not be poisoned")
            .clone()
    }

    fn clear_calls(&self) {
        self.calls
            .lock()
            .expect("contract call log lock should not be poisoned")
            .clear();
    }
}

impl Gate<ContractPolicy, ContractEvidence> for ContractGate {
    fn gate_id(&self) -> &str {
        self.gate_id
    }

    fn dependency_gate_ids(&self) -> Vec<String> {
        self.dependencies.clone()
    }

    fn display_name(&self) -> &str {
        self.gate_id
    }

    fn description(&self) -> &str {
        "contract-test gate implementation"
    }

    fn validate_policy(&self, policy: &ContractPolicy) -> Result<(), String> {
        self.record_call("validate_policy");
        if !policy.valid {
            return Err("contract policy is invalid".to_string());
        }
        Ok(())
    }

    fn validate_evidence(&self, evidence: &ContractEvidence) -> Result<(), String> {
        self.record_call("validate_evidence");
        if !evidence.is_sufficient() {
            return Err("contract evidence is insufficient".to_string());
        }
        Ok(())
    }

    fn evaluate(
        &self,
        policy: &ContractPolicy,
        evidence: &ContractEvidence,
    ) -> GateResult<ContractPolicy, ContractEvidence> {
        self.record_call("evaluate");

        let mut result = GateResult::new(self.verdict, policy.clone(), evidence.clone())
            .with_metadata("policy_id".to_string(), policy.policy_id().to_string())
            .with_metadata(
                "evidence_type".to_string(),
                evidence.evidence_type().to_string(),
            );

        if self.verdict == GateVerdict::Conditional {
            result = result.with_condition("contract condition".to_string());
        }

        if self.verdict == GateVerdict::Rejected {
            result = result.with_violation(GateViolation::new(
                GateSeverity::Error,
                "contract_rejection".to_string(),
                "contract gate rejected the evidence".to_string(),
            ));
        }

        result
    }
}

fn valid_contract_policy() -> ContractPolicy {
    ContractPolicy {
        policy_id: "contract-policy".to_string(),
        strict_mode: true,
        valid: true,
    }
}

fn valid_contract_evidence() -> ContractEvidence {
    ContractEvidence {
        evidence_type: "contract-evidence".to_string(),
        sufficient: true,
        timestamp_utc: "2024-01-01T00:00:00Z".to_string(),
    }
}

fn assert_gate_trait_contract<G>(gate: &G, expected_gate_id: &str)
where
    G: Gate<ContractPolicy, ContractEvidence> + ContractCallLog,
{
    let runner = GateRunner::new(SecurityEpoch::from_raw(7));
    let policy = valid_contract_policy();
    let evidence = valid_contract_evidence();

    let receipt = runner
        .run_gate(gate, &policy, &evidence)
        .expect("valid policy and evidence must pass validation");
    assert_eq!(
        gate.calls(),
        vec!["validate_policy", "validate_evidence", "evaluate"]
    );
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.bead_id, BEAD_ID);
    assert_eq!(receipt.gate_id, expected_gate_id);
    assert_eq!(receipt.security_epoch, SecurityEpoch::from_raw(7));
    assert_eq!(receipt.verdict, GateVerdict::Approved);
    assert_eq!(
        receipt.metadata.get("policy_id").map(String::as_str),
        Some("contract-policy")
    );
    assert_eq!(
        receipt.metadata.get("evidence_type").map(String::as_str),
        Some("contract-evidence")
    );

    gate.clear_calls();
    let repeated_receipt = runner
        .run_gate(gate, &policy, &evidence)
        .expect("identical input must remain evaluable");
    assert_eq!(receipt.content_hash, repeated_receipt.content_hash);
    assert_eq!(
        gate.calls(),
        vec!["validate_policy", "validate_evidence", "evaluate"]
    );

    gate.clear_calls();
    let mut invalid_policy = policy.clone();
    invalid_policy.valid = false;
    let err = runner
        .run_gate(gate, &invalid_policy, &evidence)
        .expect_err("invalid policy must fail closed before evidence validation");
    assert!(err.contains("policy is invalid"));
    assert_eq!(gate.calls(), vec!["validate_policy"]);

    gate.clear_calls();
    let mut insufficient_evidence = evidence;
    insufficient_evidence.sufficient = false;
    let err = runner
        .run_gate(gate, &policy, &insufficient_evidence)
        .expect_err("insufficient evidence must fail closed before evaluation");
    assert!(err.contains("evidence is insufficient"));
    assert_eq!(gate.calls(), vec!["validate_policy", "validate_evidence"]);
}

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
    let deserialized: GateReceipt = serde_json::from_str(&json).unwrap();

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

#[test]
fn gate_trait_contract_harness_enforces_validation_and_receipts() {
    let gate = ContractGate::new("contract-gate", GateVerdict::Approved);

    assert_gate_trait_contract(&gate, "contract-gate");
}

#[test]
fn gate_trait_contract_harness_enforces_dependency_ordering() {
    let runner = GateRunner::new(SecurityEpoch::from_raw(11));
    let policy = valid_contract_policy();
    let evidence = valid_contract_evidence();

    let ordered_gates = vec![
        ContractGate::with_dependencies("contract-parent", GateVerdict::Approved, &[]),
        ContractGate::with_dependencies(
            "contract-child",
            GateVerdict::Conditional,
            &["contract-parent"],
        ),
    ];
    let receipts = runner
        .run_gate_batch(&ordered_gates, &policy, &evidence)
        .expect("declared dependency order must be accepted");
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].gate_id, "contract-parent");
    assert_eq!(receipts[1].gate_id, "contract-child");
    assert_eq!(receipts[1].verdict, GateVerdict::Conditional);
    assert_eq!(receipts[1].conditions, vec!["contract condition"]);
    assert_eq!(
        ordered_gates[0].calls(),
        vec!["validate_policy", "validate_evidence", "evaluate"]
    );
    assert_eq!(
        ordered_gates[1].calls(),
        vec!["validate_policy", "validate_evidence", "evaluate"]
    );

    let out_of_order_gates = vec![
        ContractGate::with_dependencies(
            "contract-child",
            GateVerdict::Approved,
            &["contract-parent"],
        ),
        ContractGate::with_dependencies("contract-parent", GateVerdict::Approved, &[]),
    ];
    let err = runner
        .run_gate_batch(&out_of_order_gates, &policy, &evidence)
        .expect_err("out-of-order dependency must fail closed before evaluation");
    assert!(err.contains("contract-child depends on contract-parent"));
    assert!(out_of_order_gates[0].calls().is_empty());
    assert!(out_of_order_gates[1].calls().is_empty());
}
