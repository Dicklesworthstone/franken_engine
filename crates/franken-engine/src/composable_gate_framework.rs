//! Composable Gate Framework
//!
//! Bead: bd-2737p.3 - Consolidate 53 gate modules into composable Gate framework
//!
//! Provides a unified framework for implementing governance gates with common
//! patterns for policy definition, evidence collection, and receipt generation.
//! Reduces 53 standalone gate modules to a composable trait-based system.
//!
//! All gates follow the pattern: define policy → collect evidence → evaluate → generate receipt

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for composable gate framework.
pub const SCHEMA_VERSION: &str = "franken-engine.composable-gate-framework.v1";

/// Component name.
pub const COMPONENT: &str = "composable_gate_framework";

/// Bead reference.
pub const BEAD_ID: &str = "bd-2737p.3";

/// Fixed-point unit: 1.0 in millionths.
pub const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Core Gate Trait Framework
// ---------------------------------------------------------------------------

/// Gate verdict classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GateVerdict {
    /// Gate allows progression with no conditions.
    Approved,
    /// Gate allows progression with specific conditions.
    Conditional,
    /// Gate blocks progression due to policy violations.
    Rejected,
    /// Gate cannot evaluate due to insufficient evidence.
    Inconclusive,
}

impl GateVerdict {
    /// Whether this verdict allows progression.
    pub fn allows_progression(self) -> bool {
        matches!(self, GateVerdict::Approved | GateVerdict::Conditional)
    }

    /// Convert to string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            GateVerdict::Approved => "approved",
            GateVerdict::Conditional => "conditional",
            GateVerdict::Rejected => "rejected",
            GateVerdict::Inconclusive => "inconclusive",
        }
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Gate severity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GateSeverity {
    /// Advisory only - violations logged but not blocking.
    Advisory,
    /// Warning - violations noted with recommendations.
    Warning,
    /// Error - blocking violations requiring remediation.
    Error,
    /// Critical - severe violations requiring immediate attention.
    Critical,
}

impl GateSeverity {
    /// Whether this severity is blocking.
    pub fn is_blocking(self) -> bool {
        matches!(self, GateSeverity::Error | GateSeverity::Critical)
    }

    /// Convert to string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            GateSeverity::Advisory => "advisory",
            GateSeverity::Warning => "warning",
            GateSeverity::Error => "error",
            GateSeverity::Critical => "critical",
        }
    }
}

impl fmt::Display for GateSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Gate violation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateViolation {
    /// Violation severity level.
    pub severity: GateSeverity,
    /// Violation category or rule identifier.
    pub category: String,
    /// Human-readable violation description.
    pub description: String,
    /// Recommended remediation actions.
    pub recommendations: Vec<String>,
    /// Additional metadata for the violation.
    pub metadata: BTreeMap<String, String>,
}

impl GateViolation {
    /// Create a new gate violation.
    pub fn new(severity: GateSeverity, category: String, description: String) -> Self {
        Self {
            severity,
            category,
            description,
            recommendations: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Add a recommendation to this violation.
    pub fn with_recommendation(mut self, recommendation: String) -> Self {
        self.recommendations.push(recommendation);
        self
    }

    /// Add metadata to this violation.
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
}

/// Gate evaluation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "P: GatePolicy, E: GateEvidence",
    deserialize = "P: GatePolicy, E: GateEvidence"
))]
pub struct GateResult<P: GatePolicy, E: GateEvidence> {
    /// Gate verdict.
    pub verdict: GateVerdict,
    /// Policy used for evaluation.
    pub policy: P,
    /// Evidence provided for evaluation.
    pub evidence: E,
    /// Violations found during evaluation.
    pub violations: Vec<GateViolation>,
    /// Additional conditions if verdict is Conditional.
    pub conditions: Vec<String>,
    /// Evaluation metadata.
    pub metadata: BTreeMap<String, String>,
}

impl<P: GatePolicy, E: GateEvidence> GateResult<P, E> {
    /// Create a new gate result.
    pub fn new(verdict: GateVerdict, policy: P, evidence: E) -> Self {
        Self {
            verdict,
            policy,
            evidence,
            violations: Vec::new(),
            conditions: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Add a violation to this result.
    pub fn with_violation(mut self, violation: GateViolation) -> Self {
        self.violations.push(violation);
        self
    }

    /// Add a condition to this result.
    pub fn with_condition(mut self, condition: String) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Add metadata to this result.
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Generate a receipt for this gate evaluation.
    pub fn into_receipt(self, security_epoch: SecurityEpoch, gate_id: String) -> GateReceipt {
        let content_hash = self.compute_content_hash();

        GateReceipt {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            bead_id: BEAD_ID.to_string(),
            gate_id,
            security_epoch,
            timestamp: chrono::Utc::now().to_rfc3339(),
            verdict: self.verdict,
            violations: self.violations,
            conditions: self.conditions,
            metadata: self.metadata,
            content_hash,
        }
    }

    /// Compute content hash for this result.
    fn compute_content_hash(&self) -> ContentHash {
        let mut hasher = sha2::Sha256::new();

        // Hash core result data
        hasher.update(self.verdict.as_str().as_bytes());
        hasher.update((self.violations.len() as u64).to_le_bytes());

        // Hash violations in deterministic order
        for violation in &self.violations {
            hasher.update(violation.severity.as_str().as_bytes());
            hasher.update(violation.category.as_bytes());
            hasher.update(violation.description.as_bytes());
        }

        // Hash conditions and metadata
        hasher.update((self.conditions.len() as u64).to_le_bytes());
        for condition in &self.conditions {
            hasher.update(condition.as_bytes());
        }

        for (key, value) in &self.metadata {
            hasher.update(key.as_bytes());
            hasher.update(value.as_bytes());
        }

        let hash_bytes = hasher.finalize();
        ContentHash::from_bytes(hash_bytes.into())
    }
}

/// Gate evaluation receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Component name.
    pub component: String,
    /// Bead ID.
    pub bead_id: String,
    /// Gate identifier.
    pub gate_id: String,
    /// Security epoch.
    pub security_epoch: SecurityEpoch,
    /// Evaluation timestamp (RFC 3339).
    pub timestamp: String,
    /// Gate verdict.
    pub verdict: GateVerdict,
    /// Violations found.
    pub violations: Vec<GateViolation>,
    /// Conditions for conditional approval.
    pub conditions: Vec<String>,
    /// Additional metadata.
    pub metadata: BTreeMap<String, String>,
    /// Content hash for integrity verification.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Gate Framework Traits
// ---------------------------------------------------------------------------

/// Gate policy definition trait.
pub trait GatePolicy: Clone + fmt::Debug + Serialize + for<'de> Deserialize<'de> {
    /// Policy identifier for this gate type.
    fn policy_id(&self) -> &str;

    /// Whether this policy is in strict enforcement mode.
    fn is_strict(&self) -> bool {
        true
    }
}

/// Gate evidence trait.
pub trait GateEvidence: Clone + fmt::Debug + Serialize + for<'de> Deserialize<'de> {
    /// Evidence type identifier.
    fn evidence_type(&self) -> &str;

    /// Whether this evidence is sufficient for evaluation.
    fn is_sufficient(&self) -> bool {
        true
    }

    /// Get evidence timestamp if available.
    fn timestamp(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        None
    }
}

/// Core gate evaluation trait.
pub trait Gate<P: GatePolicy, E: GateEvidence> {
    /// Gate identifier.
    fn gate_id(&self) -> &str;

    /// Gate display name.
    fn display_name(&self) -> &str;

    /// Gate description.
    fn description(&self) -> &str;

    /// Evaluate evidence against policy.
    fn evaluate(&self, policy: &P, evidence: &E) -> GateResult<P, E>;

    /// Validate policy configuration.
    fn validate_policy(&self, policy: &P) -> Result<(), String> {
        let _ = policy; // Default: all policies are valid
        Ok(())
    }

    /// Validate evidence completeness.
    fn validate_evidence(&self, evidence: &E) -> Result<(), String> {
        if !evidence.is_sufficient() {
            return Err("Evidence is insufficient for evaluation".to_string());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Gate Runner
// ---------------------------------------------------------------------------

/// Generic gate runner that can evaluate any gate implementation.
pub struct GateRunner {
    /// Security epoch for evaluations.
    security_epoch: SecurityEpoch,
}

impl GateRunner {
    /// Create a new gate runner.
    pub fn new(security_epoch: SecurityEpoch) -> Self {
        Self { security_epoch }
    }

    /// Run gate evaluation and generate receipt.
    pub fn run_gate<P, E, G>(
        &self,
        gate: &G,
        policy: &P,
        evidence: &E,
    ) -> Result<GateReceipt, String>
    where
        P: GatePolicy,
        E: GateEvidence,
        G: Gate<P, E>,
    {
        // Validate inputs
        gate.validate_policy(policy)?;
        gate.validate_evidence(evidence)?;

        // Run evaluation
        let result = gate.evaluate(policy, evidence);

        // Generate receipt
        let receipt = result.into_receipt(self.security_epoch, gate.gate_id().to_string());

        Ok(receipt)
    }

    /// Batch evaluate multiple gates with the same evidence.
    pub fn run_gate_batch<P, E, G>(
        &self,
        gates: &[G],
        policy: &P,
        evidence: &E,
    ) -> Result<Vec<GateReceipt>, String>
    where
        P: GatePolicy,
        E: GateEvidence,
        G: Gate<P, E>,
    {
        let mut receipts = Vec::new();

        for gate in gates {
            let receipt = self.run_gate(gate, policy, evidence)?;
            receipts.push(receipt);
        }

        Ok(receipts)
    }
}

// ---------------------------------------------------------------------------
// Example Gate Implementations
// ---------------------------------------------------------------------------

/// Example policy for demonstration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExamplePolicy {
    /// Policy identifier.
    pub policy_id: String,
    /// Maximum allowed violations.
    pub max_violations: usize,
    /// Whether to enforce strictly.
    pub strict_mode: bool,
}

impl GatePolicy for ExamplePolicy {
    fn policy_id(&self) -> &str {
        &self.policy_id
    }

    fn is_strict(&self) -> bool {
        self.strict_mode
    }
}

/// Example evidence for demonstration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleEvidence {
    /// Evidence type identifier.
    pub evidence_type: String,
    /// Number of violations detected.
    pub violation_count: usize,
    /// Evidence collection timestamp.
    pub timestamp: String,
}

impl GateEvidence for ExampleEvidence {
    fn evidence_type(&self) -> &str {
        &self.evidence_type
    }

    fn is_sufficient(&self) -> bool {
        !self.evidence_type.is_empty()
    }

    fn timestamp(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        chrono::DateTime::parse_from_rfc3339(&self.timestamp)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    }
}

/// Example gate implementation.
pub struct ExampleGate;

impl Gate<ExamplePolicy, ExampleEvidence> for ExampleGate {
    fn gate_id(&self) -> &str {
        "example-gate"
    }

    fn display_name(&self) -> &str {
        "Example Gate"
    }

    fn description(&self) -> &str {
        "Example gate implementation for demonstration purposes"
    }

    fn evaluate(
        &self,
        policy: &ExamplePolicy,
        evidence: &ExampleEvidence,
    ) -> GateResult<ExamplePolicy, ExampleEvidence> {
        let verdict = if evidence.violation_count <= policy.max_violations {
            GateVerdict::Approved
        } else if policy.strict_mode {
            GateVerdict::Rejected
        } else {
            GateVerdict::Conditional
        };

        let mut result = GateResult::new(verdict, policy.clone(), evidence.clone());

        if evidence.violation_count > policy.max_violations {
            let violation = GateViolation::new(
                GateSeverity::Warning,
                "violation_count_exceeded".to_string(),
                format!(
                    "Found {} violations, policy allows {}",
                    evidence.violation_count, policy.max_violations
                ),
            )
            .with_recommendation("Reduce violation count or adjust policy".to_string());

            result = result.with_violation(violation);
        }

        if verdict == GateVerdict::Conditional {
            result =
                result.with_condition("Monitor violation trends over next 24 hours".to_string());
        }

        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gate_verdict_allows_progression() {
        assert!(GateVerdict::Approved.allows_progression());
        assert!(GateVerdict::Conditional.allows_progression());
        assert!(!GateVerdict::Rejected.allows_progression());
        assert!(!GateVerdict::Inconclusive.allows_progression());
    }

    #[test]
    fn test_gate_verdict_as_str() {
        assert_eq!(GateVerdict::Approved.as_str(), "approved");
        assert_eq!(GateVerdict::Conditional.as_str(), "conditional");
        assert_eq!(GateVerdict::Rejected.as_str(), "rejected");
        assert_eq!(GateVerdict::Inconclusive.as_str(), "inconclusive");
    }

    #[test]
    fn test_gate_severity_is_blocking() {
        assert!(!GateSeverity::Advisory.is_blocking());
        assert!(!GateSeverity::Warning.is_blocking());
        assert!(GateSeverity::Error.is_blocking());
        assert!(GateSeverity::Critical.is_blocking());
    }

    #[test]
    fn test_gate_violation_builder() {
        let violation = GateViolation::new(
            GateSeverity::Error,
            "test-violation".to_string(),
            "Test violation description".to_string(),
        )
        .with_recommendation("Fix the issue".to_string())
        .with_metadata("key".to_string(), "value".to_string());

        assert_eq!(violation.severity, GateSeverity::Error);
        assert_eq!(violation.category, "test-violation");
        assert_eq!(violation.recommendations.len(), 1);
        assert_eq!(violation.metadata.len(), 1);
    }

    #[test]
    fn test_gate_result_builder() {
        let policy = ExamplePolicy {
            policy_id: "test-policy".to_string(),
            max_violations: 5,
            strict_mode: true,
        };

        let evidence = ExampleEvidence {
            evidence_type: "test-evidence".to_string(),
            violation_count: 3,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let violation = GateViolation::new(
            GateSeverity::Warning,
            "test".to_string(),
            "Test violation".to_string(),
        );

        let result = GateResult::new(GateVerdict::Conditional, policy, evidence)
            .with_violation(violation)
            .with_condition("Test condition".to_string())
            .with_metadata("test_key".to_string(), "test_value".to_string());

        assert_eq!(result.verdict, GateVerdict::Conditional);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.conditions.len(), 1);
        assert_eq!(result.metadata.len(), 1);
    }

    #[test]
    fn test_gate_runner_single_gate() {
        let runner = GateRunner::new(SecurityEpoch::from_raw(1));
        let gate = ExampleGate;

        let policy = ExamplePolicy {
            policy_id: "test-policy".to_string(),
            max_violations: 5,
            strict_mode: false,
        };

        let evidence = ExampleEvidence {
            evidence_type: "test-evidence".to_string(),
            violation_count: 3,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let result = runner.run_gate(&gate, &policy, &evidence);
        assert!(result.is_ok());

        let receipt = result.expect("serde deserialization should succeed");
        assert_eq!(receipt.verdict, GateVerdict::Approved);
        assert_eq!(receipt.gate_id, "example-gate");
        assert_eq!(receipt.schema_version, SCHEMA_VERSION);
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.bead_id, BEAD_ID);
    }

    #[test]
    fn test_gate_runner_batch() {
        let runner = GateRunner::new(SecurityEpoch::from_raw(1));
        let gates = vec![ExampleGate, ExampleGate];

        let policy = ExamplePolicy {
            policy_id: "test-policy".to_string(),
            max_violations: 5,
            strict_mode: false,
        };

        let evidence = ExampleEvidence {
            evidence_type: "test-evidence".to_string(),
            violation_count: 3,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let result = runner.run_gate_batch(&gates, &policy, &evidence);
        assert!(result.is_ok());

        let receipts = result.expect("serde deserialization should succeed");
        assert_eq!(receipts.len(), 2);
        assert!(receipts.iter().all(|r| r.verdict == GateVerdict::Approved));
    }

    #[test]
    fn test_example_gate_evaluation_approved() {
        let gate = ExampleGate;

        let policy = ExamplePolicy {
            policy_id: "test-policy".to_string(),
            max_violations: 5,
            strict_mode: true,
        };

        let evidence = ExampleEvidence {
            evidence_type: "test-evidence".to_string(),
            violation_count: 3,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let result = gate.evaluate(&policy, &evidence);
        assert_eq!(result.verdict, GateVerdict::Approved);
        assert!(result.violations.is_empty());
        assert!(result.conditions.is_empty());
    }

    #[test]
    fn test_example_gate_evaluation_rejected() {
        let gate = ExampleGate;

        let policy = ExamplePolicy {
            policy_id: "test-policy".to_string(),
            max_violations: 3,
            strict_mode: true,
        };

        let evidence = ExampleEvidence {
            evidence_type: "test-evidence".to_string(),
            violation_count: 5,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let result = gate.evaluate(&policy, &evidence);
        assert_eq!(result.verdict, GateVerdict::Rejected);
        assert_eq!(result.violations.len(), 1);
        assert!(result.conditions.is_empty());
    }

    #[test]
    fn test_example_gate_evaluation_conditional() {
        let gate = ExampleGate;

        let policy = ExamplePolicy {
            policy_id: "test-policy".to_string(),
            max_violations: 3,
            strict_mode: false, // Non-strict allows conditional
        };

        let evidence = ExampleEvidence {
            evidence_type: "test-evidence".to_string(),
            violation_count: 5,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let result = gate.evaluate(&policy, &evidence);
        assert_eq!(result.verdict, GateVerdict::Conditional);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.conditions.len(), 1);
    }

    #[test]
    fn test_content_hash_deterministic() {
        let policy = ExamplePolicy {
            policy_id: "test-policy".to_string(),
            max_violations: 5,
            strict_mode: true,
        };

        let evidence = ExampleEvidence {
            evidence_type: "test-evidence".to_string(),
            violation_count: 3,
            timestamp: "2024-01-01T00:00:00Z".to_string(), // Fixed timestamp for determinism
        };

        let result1 = GateResult::new(GateVerdict::Approved, policy.clone(), evidence.clone());
        let result2 = GateResult::new(GateVerdict::Approved, policy, evidence);

        let hash1 = result1.compute_content_hash();
        let hash2 = result2.compute_content_hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_serde_roundtrip_gate_verdict() {
        let verdicts = [
            GateVerdict::Approved,
            GateVerdict::Conditional,
            GateVerdict::Rejected,
            GateVerdict::Inconclusive,
        ];

        for verdict in verdicts {
            let json = serde_json::to_string(&verdict).expect("serde deserialization should succeed");
            let deserialized: GateVerdict = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(verdict, deserialized);
        }
    }

    #[test]
    fn test_serde_roundtrip_gate_severity() {
        let severities = [
            GateSeverity::Advisory,
            GateSeverity::Warning,
            GateSeverity::Error,
            GateSeverity::Critical,
        ];

        for severity in severities {
            let json = serde_json::to_string(&severity).expect("serde deserialization should succeed");
            let deserialized: GateSeverity = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(severity, deserialized);
        }
    }
}
