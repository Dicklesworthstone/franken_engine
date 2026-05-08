use std::collections::BTreeMap;
use std::sync::Mutex;

use frankenengine_engine::composable_gate_framework::{
    BEAD_ID, COMPONENT, ExampleEvidence, ExampleGate, ExamplePolicy, Gate, GateEvidence,
    GatePolicy, GateReceipt, GateResult, GateRunner, GateSeverity, GateVerdict, GateViolation,
    SCHEMA_VERSION,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use serde::{Deserialize, Serialize};

const FIXED_EVIDENCE_TIMESTAMP: &str = "2024-01-01T00:00:00Z";

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
            .with_metadata(
                "evidence_type".to_string(),
                evidence.evidence_type().to_string(),
            )
            .with_metadata("policy_id".to_string(), policy.policy_id().to_string());

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

#[derive(Debug, PartialEq)]
struct StableReceiptProjection {
    schema_version: String,
    component: String,
    bead_id: String,
    gate_id: String,
    security_epoch: SecurityEpoch,
    verdict: GateVerdict,
    violations: serde_json::Value,
    conditions: Vec<String>,
    metadata: BTreeMap<String, String>,
    content_hash: String,
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
        timestamp_utc: FIXED_EVIDENCE_TIMESTAMP.to_string(),
    }
}

fn expected_contract_metadata() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("evidence_type".to_string(), "contract-evidence".to_string()),
        ("policy_id".to_string(), "contract-policy".to_string()),
    ])
}

fn stable_projection(receipt: &GateReceipt) -> StableReceiptProjection {
    StableReceiptProjection {
        schema_version: receipt.schema_version.clone(),
        component: receipt.component.clone(),
        bead_id: receipt.bead_id.clone(),
        gate_id: receipt.gate_id.clone(),
        security_epoch: receipt.security_epoch,
        verdict: receipt.verdict,
        violations: serde_json::to_value(&receipt.violations)
            .expect("gate violations must serialize for deterministic comparison"),
        conditions: receipt.conditions.clone(),
        metadata: receipt.metadata.clone(),
        content_hash: receipt.content_hash.to_hex(),
    }
}

fn assert_receipt_contract(
    receipt: &GateReceipt,
    expected_gate_id: &str,
    expected_epoch: SecurityEpoch,
    expected_verdict: GateVerdict,
    expected_metadata: BTreeMap<String, String>,
) {
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.bead_id, BEAD_ID);
    assert_eq!(receipt.gate_id, expected_gate_id);
    assert_eq!(receipt.security_epoch, expected_epoch);
    assert_eq!(receipt.verdict, expected_verdict);
    assert_eq!(receipt.metadata, expected_metadata);
    assert_eq!(receipt.content_hash.to_hex().len(), 64);
    chrono::DateTime::parse_from_rfc3339(&receipt.timestamp)
        .expect("receipt timestamp must be RFC3339");
}

fn assert_gate_contract<G>(gate: &G, expected_gate_id: &str)
where
    G: Gate<ContractPolicy, ContractEvidence> + ContractCallLog,
{
    let runner = GateRunner::new(SecurityEpoch::from_raw(7));
    let policy = valid_contract_policy();
    let evidence = valid_contract_evidence();

    assert_eq!(gate.gate_id(), expected_gate_id);
    assert!(!gate.display_name().is_empty());
    assert!(!gate.description().is_empty());

    let receipt = runner
        .run_gate(gate, &policy, &evidence)
        .expect("valid policy and evidence must pass validation");
    assert_eq!(
        gate.calls(),
        vec!["validate_policy", "validate_evidence", "evaluate"]
    );
    assert_receipt_contract(
        &receipt,
        expected_gate_id,
        SecurityEpoch::from_raw(7),
        GateVerdict::Approved,
        expected_contract_metadata(),
    );

    let stable_receipt = stable_projection(&receipt);
    for _ in 0..3 {
        gate.clear_calls();
        let repeated_receipt = runner
            .run_gate(gate, &policy, &evidence)
            .expect("identical input must remain evaluable");
        assert_eq!(stable_projection(&repeated_receipt), stable_receipt);
        assert_eq!(
            gate.calls(),
            vec!["validate_policy", "validate_evidence", "evaluate"]
        );
    }

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
fn gate_contract_harness_enforces_runner_validation_and_receipts() {
    let gate = ContractGate::new("contract-gate", GateVerdict::Approved);

    assert_gate_contract(&gate, "contract-gate");
}

#[test]
fn gate_contract_harness_enforces_batch_dependency_ordering() {
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

#[test]
fn example_gate_satisfies_public_receipt_contract() {
    let runner = GateRunner::new(SecurityEpoch::from_raw(13));
    let gate = ExampleGate;
    let policy = ExamplePolicy {
        policy_id: "example-policy".to_string(),
        max_violations: 2,
        strict_mode: false,
    };
    let evidence = ExampleEvidence {
        evidence_type: "example-evidence".to_string(),
        violation_count: 1,
        timestamp: FIXED_EVIDENCE_TIMESTAMP.to_string(),
    };

    let receipt = runner
        .run_gate(&gate, &policy, &evidence)
        .expect("example gate must accept sufficient evidence");
    assert_receipt_contract(
        &receipt,
        "example-gate",
        SecurityEpoch::from_raw(13),
        GateVerdict::Approved,
        BTreeMap::new(),
    );
    assert!(receipt.violations.is_empty());
    assert!(receipt.conditions.is_empty());

    let repeated_receipt = runner
        .run_gate(&gate, &policy, &evidence)
        .expect("example gate must remain deterministic for fixed input");
    assert_eq!(
        stable_projection(&repeated_receipt),
        stable_projection(&receipt)
    );

    let insufficient_evidence = ExampleEvidence {
        evidence_type: String::new(),
        violation_count: 0,
        timestamp: FIXED_EVIDENCE_TIMESTAMP.to_string(),
    };
    let err = runner
        .run_gate(&gate, &policy, &insufficient_evidence)
        .expect_err("example gate must fail closed on insufficient evidence");
    assert_eq!(err, "Evidence is insufficient for evaluation");
}
