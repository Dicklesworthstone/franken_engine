//! Evidence-and-decision contract template for subsystem proposals.
//!
//! Every major subsystem proposal must satisfy this contract before merge.
//! The template enforces artifact-backed discipline: "no contract, no merge."
//!
//! Plan references: Section 11 (Evidence And Decision Contracts — Mandatory),
//! 5.1 (extreme-software-optimization baseline/profile/prove), 5.2 (alien-
//! artifact-coding expected-loss), 5.3 (alien-graveyard EV threshold).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ContractVersion — schema versioning for backward compatibility
// ---------------------------------------------------------------------------

/// Schema version for the evidence contract format.
///
/// Versioning enables backward-compatible evolution: old contracts remain
/// valid while new required fields can be added in later versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContractVersion {
    pub major: u32,
    pub minor: u32,
}

impl ContractVersion {
    pub const CURRENT: Self = Self { major: 1, minor: 0 };

    pub fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// Whether this version is compatible with the current version.
    pub fn is_compatible(&self) -> bool {
        self.major == Self::CURRENT.major
    }
}

impl fmt::Display for ContractVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

// ---------------------------------------------------------------------------
// EvTier — expected-value assessment tier
// ---------------------------------------------------------------------------

/// EV assessment tier (from alien-graveyard methodology, Section 5.3).
///
/// Proposals must achieve EV >= 2.0 to proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvTier {
    /// EV < 1.0 — net negative, reject.
    Reject,
    /// 1.0 <= EV < 2.0 — marginal, requires exceptional justification.
    Marginal,
    /// 2.0 <= EV < 5.0 — clear positive, standard approval path.
    Positive,
    /// EV >= 5.0 — high-impact, prioritize.
    HighImpact,
}

impl EvTier {
    /// Classify an EV score into a tier.
    pub fn from_score(ev: f64) -> Self {
        if ev < 1.0 {
            Self::Reject
        } else if ev < 2.0 {
            Self::Marginal
        } else if ev < 5.0 {
            Self::Positive
        } else {
            Self::HighImpact
        }
    }

    /// Whether this tier meets the minimum threshold (EV >= 2.0).
    pub fn meets_threshold(&self) -> bool {
        matches!(self, Self::Positive | Self::HighImpact)
    }
}

impl fmt::Display for EvTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Reject => "reject (EV < 1.0)",
            Self::Marginal => "marginal (1.0 <= EV < 2.0)",
            Self::Positive => "positive (2.0 <= EV < 5.0)",
            Self::HighImpact => "high-impact (EV >= 5.0)",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// RolloutStage — staged deployment strategy (Section 8.8)
// ---------------------------------------------------------------------------

/// Staged rollout strategy per Section 8.8.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RolloutStage {
    Shadow,
    Canary,
    Ramp,
    Default,
}

impl fmt::Display for RolloutStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Shadow => "shadow",
            Self::Canary => "canary",
            Self::Ramp => "ramp",
            Self::Default => "default",
        };
        f.write_str(label)
    }
}

// ---------------------------------------------------------------------------
// EvidenceContract — the mandatory contract template
// ---------------------------------------------------------------------------

/// The mandatory evidence-and-decision contract that every major subsystem
/// proposal must satisfy.
///
/// All fields are required.  Validation rejects contracts with any empty
/// or missing field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceContract {
    /// Schema version for backward compatibility.
    pub version: ContractVersion,

    // -- Required fields per Section 11 --
    /// What is being proposed and why.
    pub change_summary: String,

    /// Profile data, threat model, or risk assessment justifying the change.
    pub hotspot_evidence: String,

    /// Expected value score (numeric).
    pub ev_score: f64,

    /// EV tier classification.
    pub ev_tier: EvTier,

    /// Explicit loss matrix for the action space.
    pub expected_loss_model: String,

    /// Conditions under which the change auto-reverts or degrades to safe mode.
    pub fallback_trigger: String,

    /// Staged deployment strategy stages.
    pub rollout_stages: Vec<RolloutStage>,

    /// Exact command(s) to revert the change.
    pub rollback_command: String,

    /// Before/after performance data, golden output checksums, test results.
    pub benchmark_artifacts: String,
}

// ---------------------------------------------------------------------------
// ContractValidationError — typed validation errors
// ---------------------------------------------------------------------------

/// Validation errors for evidence contracts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractValidationError {
    /// A required text field is empty or whitespace-only.
    MissingField { field: String },
    /// The EV score is below the minimum threshold.
    EvBelowThreshold { score_str: String, tier: String },
    /// The EV tier does not match the EV score.
    EvTierMismatch {
        score_str: String,
        declared_tier: String,
        expected_tier: String,
    },
    /// No rollout stages defined.
    EmptyRolloutStages,
    /// Rollout stages are not in the correct order.
    InvalidRolloutOrder { stage: String, position: usize },
    /// Contract version is incompatible.
    IncompatibleVersion { version: String },
    /// EV score is NaN or infinite.
    InvalidEvScore,
}

impl fmt::Display for ContractValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField { field } => {
                write!(f, "evidence contract missing required field: {}", field)
            }
            Self::EvBelowThreshold { score_str, tier } => {
                write!(
                    f,
                    "EV score {} (tier: {}) is below the minimum threshold (>= 2.0)",
                    score_str, tier
                )
            }
            Self::EvTierMismatch {
                score_str,
                declared_tier,
                expected_tier,
            } => write!(
                f,
                "EV tier mismatch: score {} should be tier '{}' but declared as '{}'",
                score_str, expected_tier, declared_tier
            ),
            Self::EmptyRolloutStages => {
                write!(
                    f,
                    "evidence contract must define at least one rollout stage"
                )
            }
            Self::InvalidRolloutOrder { stage, position } => write!(
                f,
                "rollout stage '{}' at position {} violates required ordering (shadow -> canary -> ramp -> default)",
                stage, position
            ),
            Self::IncompatibleVersion { version } => {
                write!(
                    f,
                    "evidence contract version {} is incompatible with current version {}",
                    version,
                    ContractVersion::CURRENT
                )
            }
            Self::InvalidEvScore => write!(f, "EV score must be a finite number"),
        }
    }
}

impl std::error::Error for ContractValidationError {}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

impl EvidenceContract {
    /// Validate the contract, returning all errors found.
    ///
    /// Returns `Ok(())` if the contract satisfies all requirements.
    /// Returns `Err(errors)` with every validation failure.
    pub fn validate(&self) -> Result<(), Vec<ContractValidationError>> {
        let errors = validate_contract(self);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Validate an evidence contract, returning all discovered errors.
pub fn validate_contract(contract: &EvidenceContract) -> Vec<ContractValidationError> {
    let mut errors = Vec::new();

    // Version compatibility.
    if !contract.version.is_compatible() {
        errors.push(ContractValidationError::IncompatibleVersion {
            version: contract.version.to_string(),
        });
    }

    // Required text fields.
    let text_fields = [
        ("change_summary", &contract.change_summary),
        ("hotspot_evidence", &contract.hotspot_evidence),
        ("expected_loss_model", &contract.expected_loss_model),
        ("fallback_trigger", &contract.fallback_trigger),
        ("rollback_command", &contract.rollback_command),
        ("benchmark_artifacts", &contract.benchmark_artifacts),
    ];
    for (name, value) in text_fields {
        if value.trim().is_empty() {
            errors.push(ContractValidationError::MissingField {
                field: name.to_string(),
            });
        }
    }

    // EV score validity.
    if contract.ev_score.is_nan() || contract.ev_score.is_infinite() {
        errors.push(ContractValidationError::InvalidEvScore);
    } else {
        // EV tier consistency.
        let expected_tier = EvTier::from_score(contract.ev_score);
        if contract.ev_tier != expected_tier {
            errors.push(ContractValidationError::EvTierMismatch {
                score_str: format!("{:.2}", contract.ev_score),
                declared_tier: contract.ev_tier.to_string(),
                expected_tier: expected_tier.to_string(),
            });
        }

        // EV threshold check.
        if !contract.ev_tier.meets_threshold() {
            errors.push(ContractValidationError::EvBelowThreshold {
                score_str: format!("{:.2}", contract.ev_score),
                tier: contract.ev_tier.to_string(),
            });
        }
    }

    // Rollout stages.
    if contract.rollout_stages.is_empty() {
        errors.push(ContractValidationError::EmptyRolloutStages);
    } else {
        // Validate ordering: each stage must not precede the previous one.
        fn stage_order(s: &RolloutStage) -> u8 {
            match s {
                RolloutStage::Shadow => 0,
                RolloutStage::Canary => 1,
                RolloutStage::Ramp => 2,
                RolloutStage::Default => 3,
            }
        }
        for i in 1..contract.rollout_stages.len() {
            if stage_order(&contract.rollout_stages[i])
                < stage_order(&contract.rollout_stages[i - 1])
            {
                errors.push(ContractValidationError::InvalidRolloutOrder {
                    stage: contract.rollout_stages[i].to_string(),
                    position: i,
                });
            }
        }
    }

    errors
}

// ---------------------------------------------------------------------------
// Signed Decision Receipt
// ---------------------------------------------------------------------------

/// A signed decision receipt record for externally-verifiable decisions.
///
/// This structure represents a complete receipt artifact that can be verified
/// independently without requiring the original FrankenEngine source code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReceiptRecord {
    /// Schema version for the receipt format.
    pub schema_version: String,
    /// Unique identifier for this receipt.
    pub receipt_id: String,
    /// Unique identifier for the decision being receipted.
    pub decision_id: String,
    /// Policy under which this decision was made.
    pub policy_id: String,
    /// Root hash of the evidence chain supporting this decision.
    pub evidence_hash_chain_root: String,
    /// Posterior distribution snapshot after decision evaluation.
    pub posterior_snapshot: PosteriorSnapshot,
    /// Expected loss values for each outcome scenario.
    pub expected_loss_vector: Vec<ExpectedLossEntry>,
    /// Action taken as a result of this decision.
    pub action: DecisionAction,
    /// Unix timestamp (milliseconds) when receipt was generated.
    pub timestamp: u64,
    /// Cryptographic signature bundle for this receipt.
    pub signature_bundle: SignatureBundle,
    /// Additional metadata for verification (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_metadata: Option<VerificationMetadata>,
}

/// Posterior distribution snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PosteriorSnapshot {
    /// Mean expected loss from posterior distribution.
    pub mean_expected_loss: f64,
    /// 95% confidence interval lower bound.
    pub confidence_interval_95_lower: f64,
    /// 95% confidence interval upper bound.
    pub confidence_interval_95_upper: f64,
    /// Mode (most likely value) of posterior distribution.
    pub posterior_mode: f64,
    /// Number of evaluations in the posterior.
    pub evaluation_count: u32,
}

/// Expected loss entry for a specific scenario.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpectedLossEntry {
    /// Scenario name or identifier.
    pub scenario: String,
    /// Probability of this scenario.
    pub probability: f64,
    /// Expected loss for this scenario.
    pub expected_loss: f64,
}

/// Action taken as a result of a decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionAction {
    /// Type of action taken.
    pub action_type: ActionType,
    /// Parameters specific to the action type.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub action_parameters: BTreeMap<String, String>,
    /// Unix timestamp (milliseconds) when action was executed.
    pub execution_timestamp: u64,
}

/// Type of action taken.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Allow,
    Deny,
    Escalate,
    Quarantine,
    Monitor,
}

/// Cryptographic signature bundle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureBundle {
    /// Signature algorithm used.
    pub signature_algorithm: SignatureAlgorithm,
    /// Signature in hexadecimal format.
    pub signature_hex: String,
    /// Public key in hexadecimal format.
    pub public_key_hex: String,
    /// Whether this uses threshold signature scheme.
    pub threshold_signature: bool,
    /// Number of signers (for threshold signatures).
    #[serde(default = "default_signer_count")]
    pub signer_count: u32,
    /// Threshold required (for threshold signatures).
    #[serde(default = "default_threshold")]
    pub threshold: u32,
}

fn default_signer_count() -> u32 {
    1
}

fn default_threshold() -> u32 {
    1
}

/// Signature algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaP256,
    RsaPssSha256,
}

/// Additional metadata for verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationMetadata {
    /// Version of FrankenEngine that generated this receipt.
    pub generator_version: String,
    /// Security epoch when receipt was generated.
    pub security_epoch: u64,
    /// Trace ID for linking with execution logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

impl ReceiptRecord {
    /// Create a new receipt record with the current schema version.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receipt_id: String,
        decision_id: String,
        policy_id: String,
        evidence_hash_chain_root: String,
        posterior_snapshot: PosteriorSnapshot,
        expected_loss_vector: Vec<ExpectedLossEntry>,
        action: DecisionAction,
        signature_bundle: SignatureBundle,
    ) -> Self {
        Self {
            schema_version: "franken-engine.signed-decision-receipt.v1".to_string(),
            receipt_id,
            decision_id,
            policy_id,
            evidence_hash_chain_root,
            posterior_snapshot,
            expected_loss_vector,
            action,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            signature_bundle,
            verification_metadata: None,
        }
    }

    /// Set verification metadata.
    pub fn with_verification_metadata(mut self, metadata: VerificationMetadata) -> Self {
        self.verification_metadata = Some(metadata);
        self
    }

    /// Validate the receipt record structure.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.receipt_id.is_empty() {
            errors.push("receipt_id cannot be empty".to_string());
        }
        if self.decision_id.is_empty() {
            errors.push("decision_id cannot be empty".to_string());
        }
        if self.policy_id.is_empty() {
            errors.push("policy_id cannot be empty".to_string());
        }
        if self.evidence_hash_chain_root.is_empty() {
            errors.push("evidence_hash_chain_root cannot be empty".to_string());
        }
        if self.expected_loss_vector.is_empty() {
            errors.push("expected_loss_vector cannot be empty".to_string());
        }
        if self.signature_bundle.signature_hex.is_empty() {
            errors.push("signature_hex cannot be empty".to_string());
        }
        if self.signature_bundle.public_key_hex.is_empty() {
            errors.push("public_key_hex cannot be empty".to_string());
        }

        // Validate probabilities sum to approximately 1.0
        let total_probability: f64 = self
            .expected_loss_vector
            .iter()
            .map(|e| e.probability)
            .sum();
        if (total_probability - 1.0).abs() > 0.001 {
            errors.push(format!(
                "expected_loss_vector probabilities sum to {} but should sum to 1.0",
                total_probability
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_contract() -> EvidenceContract {
        EvidenceContract {
            version: ContractVersion::CURRENT,
            change_summary: "Add deterministic GC with per-extension isolation".to_string(),
            hotspot_evidence: "Profile shows GC pauses dominate p99 latency at 15ms".to_string(),
            ev_score: 3.5,
            ev_tier: EvTier::Positive,
            expected_loss_model: "Action: deploy GC, Loss(no-deploy)=high latency, Loss(deploy-bad)=rollback cost ~2h".to_string(),
            fallback_trigger: "p99 GC pause exceeds 10ms for 5 consecutive minutes".to_string(),
            rollout_stages: vec![
                RolloutStage::Shadow,
                RolloutStage::Canary,
                RolloutStage::Ramp,
                RolloutStage::Default,
            ],
            rollback_command: "cargo run -- rollback gc-v1".to_string(),
            benchmark_artifacts: "Before: p99=15ms, After: p99=3ms. Golden hash: abc123".to_string(),
        }
    }

    // -- Valid contract --

    #[test]
    fn valid_contract_passes_validation() {
        let contract = valid_contract();
        assert!(contract.validate().is_ok());
    }

    // -- Missing fields --

    #[test]
    fn missing_change_summary_fails() {
        let mut contract = valid_contract();
        contract.change_summary = "   ".to_string();
        let errors = contract.validate().unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            ContractValidationError::MissingField { field } if field == "change_summary"
        )));
    }

    #[test]
    fn missing_hotspot_evidence_fails() {
        let mut contract = valid_contract();
        contract.hotspot_evidence = String::new();
        let errors = contract.validate().unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            ContractValidationError::MissingField { field } if field == "hotspot_evidence"
        )));
    }

    #[test]
    fn missing_expected_loss_model_fails() {
        let mut contract = valid_contract();
        contract.expected_loss_model = String::new();
        let errors = contract.validate().unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            ContractValidationError::MissingField { field } if field == "expected_loss_model"
        )));
    }

    #[test]
    fn missing_fallback_trigger_fails() {
        let mut contract = valid_contract();
        contract.fallback_trigger = String::new();
        let errors = contract.validate().unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            ContractValidationError::MissingField { field } if field == "fallback_trigger"
        )));
    }

    #[test]
    fn missing_rollback_command_fails() {
        let mut contract = valid_contract();
        contract.rollback_command = String::new();
        let errors = contract.validate().unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            ContractValidationError::MissingField { field } if field == "rollback_command"
        )));
    }

    #[test]
    fn missing_benchmark_artifacts_fails() {
        let mut contract = valid_contract();
        contract.benchmark_artifacts = String::new();
        let errors = contract.validate().unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            ContractValidationError::MissingField { field } if field == "benchmark_artifacts"
        )));
    }

    #[test]
    fn all_fields_empty_produces_multiple_errors() {
        let contract = EvidenceContract {
            version: ContractVersion::CURRENT,
            change_summary: String::new(),
            hotspot_evidence: String::new(),
            ev_score: 3.0,
            ev_tier: EvTier::Positive,
            expected_loss_model: String::new(),
            fallback_trigger: String::new(),
            rollout_stages: vec![RolloutStage::Shadow],
            rollback_command: String::new(),
            benchmark_artifacts: String::new(),
        };
        let errors = contract.validate().unwrap_err();
        // 6 text fields are empty.
        let missing_count = errors
            .iter()
            .filter(|e| matches!(e, ContractValidationError::MissingField { .. }))
            .count();
        assert_eq!(missing_count, 6);
    }

    // -- EV score and tier --

    #[test]
    fn ev_below_threshold_fails() {
        let mut contract = valid_contract();
        contract.ev_score = 1.5;
        contract.ev_tier = EvTier::Marginal;
        let errors = contract.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ContractValidationError::EvBelowThreshold { .. }))
        );
    }

    #[test]
    fn ev_tier_mismatch_fails() {
        let mut contract = valid_contract();
        contract.ev_score = 3.0;
        contract.ev_tier = EvTier::HighImpact; // should be Positive
        let errors = contract.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ContractValidationError::EvTierMismatch { .. }))
        );
    }

    #[test]
    fn ev_reject_tier_fails() {
        let mut contract = valid_contract();
        contract.ev_score = 0.5;
        contract.ev_tier = EvTier::Reject;
        let errors = contract.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ContractValidationError::EvBelowThreshold { .. }))
        );
    }

    #[test]
    fn ev_high_impact_passes() {
        let mut contract = valid_contract();
        contract.ev_score = 7.0;
        contract.ev_tier = EvTier::HighImpact;
        assert!(contract.validate().is_ok());
    }

    #[test]
    fn ev_nan_fails() {
        let mut contract = valid_contract();
        contract.ev_score = f64::NAN;
        let errors = contract.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ContractValidationError::InvalidEvScore))
        );
    }

    #[test]
    fn ev_infinity_fails() {
        let mut contract = valid_contract();
        contract.ev_score = f64::INFINITY;
        let errors = contract.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ContractValidationError::InvalidEvScore))
        );
    }

    // -- Rollout stages --

    #[test]
    fn empty_rollout_stages_fails() {
        let mut contract = valid_contract();
        contract.rollout_stages.clear();
        let errors = contract.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ContractValidationError::EmptyRolloutStages))
        );
    }

    #[test]
    fn single_rollout_stage_passes() {
        let mut contract = valid_contract();
        contract.rollout_stages = vec![RolloutStage::Shadow];
        assert!(contract.validate().is_ok());
    }

    #[test]
    fn out_of_order_rollout_stages_fails() {
        let mut contract = valid_contract();
        contract.rollout_stages = vec![
            RolloutStage::Canary,
            RolloutStage::Shadow, // out of order
        ];
        let errors = contract.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ContractValidationError::InvalidRolloutOrder { .. }))
        );
    }

    #[test]
    fn duplicate_rollout_stages_allowed() {
        let mut contract = valid_contract();
        contract.rollout_stages = vec![RolloutStage::Canary, RolloutStage::Canary];
        assert!(contract.validate().is_ok());
    }

    // -- Version --

    #[test]
    fn incompatible_version_fails() {
        let mut contract = valid_contract();
        contract.version = ContractVersion::new(2, 0);
        let errors = contract.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ContractValidationError::IncompatibleVersion { .. }))
        );
    }

    #[test]
    fn compatible_minor_version_passes() {
        let mut contract = valid_contract();
        contract.version = ContractVersion::new(1, 5);
        assert!(contract.validate().is_ok());
    }

    // -- EvTier classification --

    #[test]
    fn ev_tier_from_score_classification() {
        assert_eq!(EvTier::from_score(0.5), EvTier::Reject);
        assert_eq!(EvTier::from_score(1.0), EvTier::Marginal);
        assert_eq!(EvTier::from_score(1.99), EvTier::Marginal);
        assert_eq!(EvTier::from_score(2.0), EvTier::Positive);
        assert_eq!(EvTier::from_score(4.99), EvTier::Positive);
        assert_eq!(EvTier::from_score(5.0), EvTier::HighImpact);
        assert_eq!(EvTier::from_score(100.0), EvTier::HighImpact);
    }

    #[test]
    fn ev_tier_meets_threshold() {
        assert!(!EvTier::Reject.meets_threshold());
        assert!(!EvTier::Marginal.meets_threshold());
        assert!(EvTier::Positive.meets_threshold());
        assert!(EvTier::HighImpact.meets_threshold());
    }

    // -- Display --

    #[test]
    fn contract_version_display() {
        assert_eq!(ContractVersion::CURRENT.to_string(), "1.0");
        assert_eq!(ContractVersion::new(2, 3).to_string(), "2.3");
    }

    #[test]
    fn rollout_stage_display() {
        assert_eq!(RolloutStage::Shadow.to_string(), "shadow");
        assert_eq!(RolloutStage::Canary.to_string(), "canary");
        assert_eq!(RolloutStage::Ramp.to_string(), "ramp");
        assert_eq!(RolloutStage::Default.to_string(), "default");
    }

    #[test]
    fn validation_error_display() {
        let err = ContractValidationError::MissingField {
            field: "change_summary".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "evidence contract missing required field: change_summary"
        );

        let err = ContractValidationError::EmptyRolloutStages;
        assert_eq!(
            err.to_string(),
            "evidence contract must define at least one rollout stage"
        );
    }

    // -- Serialization --

    #[test]
    fn evidence_contract_serialization_round_trip() {
        let contract = valid_contract();
        let json = serde_json::to_string(&contract).expect("serde deserialization should succeed");
        let restored: EvidenceContract =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(contract, restored);
    }

    // -- Enrichment: serde, Ord, std::error --

    #[test]
    fn contract_validation_error_serde_all_variants() {
        let variants = vec![
            ContractValidationError::MissingField {
                field: "name".to_string(),
            },
            ContractValidationError::EvBelowThreshold {
                score_str: "0.3".to_string(),
                tier: "Positive".to_string(),
            },
            ContractValidationError::EvTierMismatch {
                score_str: "0.8".to_string(),
                declared_tier: "Marginal".to_string(),
                expected_tier: "Positive".to_string(),
            },
            ContractValidationError::EmptyRolloutStages,
            ContractValidationError::InvalidRolloutOrder {
                stage: "Shadow".to_string(),
                position: 2,
            },
            ContractValidationError::IncompatibleVersion {
                version: "3.0".to_string(),
            },
            ContractValidationError::InvalidEvScore,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde deserialization should succeed");
            let restored: ContractValidationError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn contract_validation_error_implements_std_error() {
        let err: &dyn std::error::Error = &ContractValidationError::InvalidEvScore;
        assert!(!format!("{err}").is_empty());
        assert!(err.source().is_none());
    }

    #[test]
    fn ev_tier_serde_all_variants() {
        for tier in [
            EvTier::Reject,
            EvTier::Marginal,
            EvTier::Positive,
            EvTier::HighImpact,
        ] {
            let json = serde_json::to_string(&tier).expect("serde deserialization should succeed");
            let restored: EvTier =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(tier, restored);
        }
    }

    #[test]
    fn rollout_stage_serde_all_variants() {
        for stage in [
            RolloutStage::Shadow,
            RolloutStage::Canary,
            RolloutStage::Ramp,
            RolloutStage::Default,
        ] {
            let json = serde_json::to_string(&stage).expect("serde deserialization should succeed");
            let restored: RolloutStage =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(stage, restored);
        }
    }

    #[test]
    fn contract_version_ordering() {
        let v1_0 = ContractVersion { major: 1, minor: 0 };
        let v1_1 = ContractVersion { major: 1, minor: 1 };
        let v2_0 = ContractVersion { major: 2, minor: 0 };
        assert!(v1_0 < v1_1);
        assert!(v1_1 < v2_0);
    }

    #[test]
    fn contract_version_serialization() {
        let v = ContractVersion::CURRENT;
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let restored: ContractVersion =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(v, restored);
    }

    // ── Enrichment: EV score boundary precision ──────────────────

    #[test]
    fn ev_tier_from_score_exact_boundaries() {
        // Just below 1.0
        assert_eq!(EvTier::from_score(0.999999), EvTier::Reject);
        // Exactly 1.0
        assert_eq!(EvTier::from_score(1.0), EvTier::Marginal);
        // Just below 2.0
        assert_eq!(EvTier::from_score(1.999999), EvTier::Marginal);
        // Exactly 2.0
        assert_eq!(EvTier::from_score(2.0), EvTier::Positive);
        // Just below 5.0
        assert_eq!(EvTier::from_score(4.999999), EvTier::Positive);
        // Exactly 5.0
        assert_eq!(EvTier::from_score(5.0), EvTier::HighImpact);
    }

    #[test]
    fn ev_tier_from_score_negative() {
        assert_eq!(EvTier::from_score(-1.0), EvTier::Reject);
        assert_eq!(EvTier::from_score(-100.0), EvTier::Reject);
    }

    #[test]
    fn ev_tier_from_score_zero() {
        assert_eq!(EvTier::from_score(0.0), EvTier::Reject);
    }

    #[test]
    fn ev_tier_from_score_very_large() {
        assert_eq!(EvTier::from_score(1_000_000.0), EvTier::HighImpact);
    }

    // ── Enrichment: negative infinity ────────────────────────────

    #[test]
    fn ev_negative_infinity_fails() {
        let mut contract = valid_contract();
        contract.ev_score = f64::NEG_INFINITY;
        let errors = contract.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ContractValidationError::InvalidEvScore))
        );
    }

    // ── Enrichment: rollout ordering edge cases ──────────────────

    #[test]
    fn rollout_all_four_stages_in_order_passes() {
        let mut contract = valid_contract();
        contract.rollout_stages = vec![
            RolloutStage::Shadow,
            RolloutStage::Canary,
            RolloutStage::Ramp,
            RolloutStage::Default,
        ];
        assert!(contract.validate().is_ok());
    }

    #[test]
    fn rollout_full_reverse_produces_multiple_ordering_errors() {
        let mut contract = valid_contract();
        contract.rollout_stages = vec![
            RolloutStage::Default,
            RolloutStage::Ramp,
            RolloutStage::Canary,
            RolloutStage::Shadow,
        ];
        let errors = contract.validate().unwrap_err();
        let order_errors = errors
            .iter()
            .filter(|e| matches!(e, ContractValidationError::InvalidRolloutOrder { .. }))
            .count();
        assert_eq!(order_errors, 3); // positions 1, 2, 3 all violate
    }

    #[test]
    fn rollout_single_default_stage_passes() {
        let mut contract = valid_contract();
        contract.rollout_stages = vec![RolloutStage::Default];
        assert!(contract.validate().is_ok());
    }

    #[test]
    fn rollout_canary_then_shadow_fails() {
        let mut contract = valid_contract();
        contract.rollout_stages = vec![RolloutStage::Canary, RolloutStage::Shadow];
        let errors = contract.validate().unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            ContractValidationError::InvalidRolloutOrder { position: 1, .. }
        )));
    }

    // ── Enrichment: version compatibility ────────────────────────

    #[test]
    fn version_0_is_incompatible() {
        let mut contract = valid_contract();
        contract.version = ContractVersion::new(0, 9);
        let errors = contract.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ContractValidationError::IncompatibleVersion { .. }))
        );
    }

    #[test]
    fn version_1_99_is_compatible() {
        let mut contract = valid_contract();
        contract.version = ContractVersion::new(1, 99);
        assert!(contract.validate().is_ok());
    }

    // ── Enrichment: error display completeness ───────────────────

    #[test]
    fn error_display_ev_below_threshold() {
        let err = ContractValidationError::EvBelowThreshold {
            score_str: "1.50".to_string(),
            tier: "marginal".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("1.50"));
        assert!(msg.contains("marginal"));
        assert!(msg.contains("2.0"));
    }

    #[test]
    fn error_display_ev_tier_mismatch() {
        let err = ContractValidationError::EvTierMismatch {
            score_str: "3.00".to_string(),
            declared_tier: "high-impact".to_string(),
            expected_tier: "positive".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("3.00"));
        assert!(msg.contains("high-impact"));
        assert!(msg.contains("positive"));
    }

    #[test]
    fn error_display_invalid_rollout_order() {
        let err = ContractValidationError::InvalidRolloutOrder {
            stage: "shadow".to_string(),
            position: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains("shadow"));
        assert!(msg.contains("3"));
    }

    #[test]
    fn error_display_incompatible_version() {
        let err = ContractValidationError::IncompatibleVersion {
            version: "2.0".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("2.0"));
        assert!(msg.contains("1.0"));
    }

    #[test]
    fn error_display_invalid_ev_score() {
        let err = ContractValidationError::InvalidEvScore;
        assert_eq!(err.to_string(), "EV score must be a finite number");
    }

    // ── Enrichment: EvTier display ───────────────────────────────

    #[test]
    fn ev_tier_display_all_variants() {
        assert!(EvTier::Reject.to_string().contains("reject"));
        assert!(EvTier::Marginal.to_string().contains("marginal"));
        assert!(EvTier::Positive.to_string().contains("positive"));
        assert!(EvTier::HighImpact.to_string().contains("high-impact"));
    }

    // ── Enrichment: contract current version constant ────────────

    #[test]
    fn current_version_is_1_0() {
        assert_eq!(ContractVersion::CURRENT.major, 1);
        assert_eq!(ContractVersion::CURRENT.minor, 0);
    }

    // ── Enrichment: multi-error accumulation ─────────────────────

    #[test]
    fn incompatible_version_plus_missing_fields() {
        let contract = EvidenceContract {
            version: ContractVersion::new(2, 0),
            change_summary: String::new(),
            hotspot_evidence: "exists".to_string(),
            ev_score: 3.0,
            ev_tier: EvTier::Positive,
            expected_loss_model: "exists".to_string(),
            fallback_trigger: "exists".to_string(),
            rollout_stages: vec![RolloutStage::Shadow],
            rollback_command: "cmd".to_string(),
            benchmark_artifacts: "exists".to_string(),
        };
        let errors = contract.validate().unwrap_err();
        // Should have IncompatibleVersion + MissingField(change_summary)
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ContractValidationError::IncompatibleVersion { .. }))
        );
        assert!(errors.iter().any(|e| matches!(
            e,
            ContractValidationError::MissingField { field } if field == "change_summary"
        )));
    }

    // ── Enrichment: whitespace-only fields ───────────────────────

    #[test]
    fn tab_only_field_is_missing() {
        let mut contract = valid_contract();
        contract.change_summary = "\t\n  \r".to_string();
        let errors = contract.validate().unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            ContractValidationError::MissingField { field } if field == "change_summary"
        )));
    }

    // ── Enrichment: Display uniqueness ──────────────────────────

    #[test]
    fn ev_tier_display_all_unique() {
        let displays: std::collections::BTreeSet<String> = [
            EvTier::Reject,
            EvTier::Marginal,
            EvTier::Positive,
            EvTier::HighImpact,
        ]
        .iter()
        .map(|t| t.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn rollout_stage_display_all_unique() {
        let displays: std::collections::BTreeSet<String> = [
            RolloutStage::Shadow,
            RolloutStage::Canary,
            RolloutStage::Ramp,
            RolloutStage::Default,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    // ── Enrichment: validation error Display uniqueness ─────────

    #[test]
    fn contract_validation_error_display_all_unique() {
        let variants = [
            ContractValidationError::MissingField {
                field: "x".to_string(),
            },
            ContractValidationError::EvBelowThreshold {
                score_str: "1.0".to_string(),
                tier: "marginal".to_string(),
            },
            ContractValidationError::EvTierMismatch {
                score_str: "3.0".to_string(),
                declared_tier: "reject".to_string(),
                expected_tier: "positive".to_string(),
            },
            ContractValidationError::EmptyRolloutStages,
            ContractValidationError::InvalidRolloutOrder {
                stage: "shadow".to_string(),
                position: 1,
            },
            ContractValidationError::IncompatibleVersion {
                version: "2.0".to_string(),
            },
            ContractValidationError::InvalidEvScore,
        ];
        let displays: std::collections::BTreeSet<String> =
            variants.iter().map(|v| v.to_string()).collect();
        assert_eq!(displays.len(), 7);
    }

    // ── Enrichment: exact boundary EV 2.0 passes ────────────────

    #[test]
    fn ev_exactly_2_0_passes_validation() {
        let mut contract = valid_contract();
        contract.ev_score = 2.0;
        contract.ev_tier = EvTier::Positive;
        assert!(contract.validate().is_ok());
    }

    // ── Enrichment: contract with high_impact passes ────────────

    #[test]
    fn contract_high_impact_no_errors() {
        let mut contract = valid_contract();
        contract.ev_score = 10.0;
        contract.ev_tier = EvTier::HighImpact;
        assert!(contract.validate().is_ok());
    }

    // ── Enrichment: rollout with skip ───────────────────────────

    #[test]
    fn rollout_shadow_to_default_skipping_middle_passes() {
        let mut contract = valid_contract();
        contract.rollout_stages = vec![RolloutStage::Shadow, RolloutStage::Default];
        assert!(contract.validate().is_ok());
    }

    // ── Enrichment: version 1.0 identity ────────────────────────

    #[test]
    fn contract_version_new_equals_struct() {
        let v = ContractVersion::new(3, 7);
        assert_eq!(v.major, 3);
        assert_eq!(v.minor, 7);
    }

    // ── Enrichment: multiple error accumulation ─────────────────

    #[test]
    fn multiple_different_error_kinds_accumulate() {
        let contract = EvidenceContract {
            version: ContractVersion::new(2, 0), // incompatible
            change_summary: String::new(),       // missing
            hotspot_evidence: "exists".to_string(),
            ev_score: f64::NAN, // invalid
            ev_tier: EvTier::Positive,
            expected_loss_model: "exists".to_string(),
            fallback_trigger: "exists".to_string(),
            rollout_stages: vec![], // empty
            rollback_command: "cmd".to_string(),
            benchmark_artifacts: "exists".to_string(),
        };
        let errors = contract.validate().unwrap_err();
        assert!(
            errors.len() >= 4,
            "should have at least 4 errors: {}",
            errors.len()
        );
    }

    // ── Enrichment batch: clone/eq, JSON fields, validate_contract fn ──

    #[test]
    fn contract_clone_eq() {
        let original = valid_contract();
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn contract_version_clone_eq() {
        let v = ContractVersion::new(1, 5);
        let cloned = v;
        assert_eq!(v, cloned);
    }

    #[test]
    fn contract_validation_error_clone_eq() {
        let err = ContractValidationError::MissingField {
            field: "change_summary".to_string(),
        };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn ev_tier_copy_semantics() {
        let tier = EvTier::Positive;
        let copied = tier;
        assert_eq!(tier, copied);
    }

    #[test]
    fn rollout_stage_copy_semantics() {
        let stage = RolloutStage::Canary;
        let copied = stage;
        assert_eq!(stage, copied);
    }

    #[test]
    fn evidence_contract_json_field_names() {
        let contract = valid_contract();
        let json = serde_json::to_string(&contract).expect("serde deserialization should succeed");
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"change_summary\""));
        assert!(json.contains("\"hotspot_evidence\""));
        assert!(json.contains("\"ev_score\""));
        assert!(json.contains("\"ev_tier\""));
        assert!(json.contains("\"expected_loss_model\""));
        assert!(json.contains("\"fallback_trigger\""));
        assert!(json.contains("\"rollout_stages\""));
        assert!(json.contains("\"rollback_command\""));
        assert!(json.contains("\"benchmark_artifacts\""));
    }

    #[test]
    fn contract_version_json_field_names() {
        let v = ContractVersion::CURRENT;
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        assert!(json.contains("\"major\""));
        assert!(json.contains("\"minor\""));
    }

    #[test]
    fn validate_contract_fn_returns_empty_for_valid() {
        let contract = valid_contract();
        let errors = validate_contract(&contract);
        assert!(errors.is_empty());
    }

    #[test]
    fn validate_contract_fn_returns_errors_for_invalid() {
        let mut contract = valid_contract();
        contract.change_summary = String::new();
        let errors = validate_contract(&contract);
        assert!(!errors.is_empty());
    }

    #[test]
    fn ev_exactly_5_0_is_high_impact_passes() {
        let mut contract = valid_contract();
        contract.ev_score = 5.0;
        contract.ev_tier = EvTier::HighImpact;
        assert!(contract.validate().is_ok());
    }

    #[test]
    fn ev_exactly_1_0_is_marginal_fails_threshold() {
        let mut contract = valid_contract();
        contract.ev_score = 1.0;
        contract.ev_tier = EvTier::Marginal;
        let errors = contract.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ContractValidationError::EvBelowThreshold { .. }))
        );
    }

    #[test]
    fn rollout_ramp_to_canary_invalid() {
        let mut contract = valid_contract();
        contract.rollout_stages = vec![RolloutStage::Ramp, RolloutStage::Canary];
        let errors = contract.validate().unwrap_err();
        assert!(errors.iter().any(|e| matches!(
            e,
            ContractValidationError::InvalidRolloutOrder { position: 1, .. }
        )));
    }

    #[test]
    fn rollout_three_identical_stages_valid() {
        let mut contract = valid_contract();
        contract.rollout_stages = vec![
            RolloutStage::Shadow,
            RolloutStage::Shadow,
            RolloutStage::Shadow,
        ];
        assert!(contract.validate().is_ok());
    }

    #[test]
    fn contract_version_is_compatible_only_for_major_1() {
        assert!(ContractVersion::new(1, 0).is_compatible());
        assert!(ContractVersion::new(1, 99).is_compatible());
        assert!(!ContractVersion::new(0, 1).is_compatible());
        assert!(!ContractVersion::new(2, 0).is_compatible());
        assert!(!ContractVersion::new(3, 0).is_compatible());
    }

    #[test]
    fn ev_tier_display_contains_range_info() {
        assert!(EvTier::Reject.to_string().contains("< 1.0"));
        assert!(EvTier::Marginal.to_string().contains("1.0"));
        assert!(EvTier::Marginal.to_string().contains("2.0"));
        assert!(EvTier::Positive.to_string().contains("2.0"));
        assert!(EvTier::Positive.to_string().contains("5.0"));
        assert!(EvTier::HighImpact.to_string().contains(">= 5.0"));
    }

    #[test]
    fn error_display_missing_field_exact() {
        let err = ContractValidationError::MissingField {
            field: "benchmark_artifacts".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "evidence contract missing required field: benchmark_artifacts"
        );
    }

    #[test]
    fn contract_with_ev_just_below_2_fails() {
        let mut contract = valid_contract();
        contract.ev_score = 1.9999;
        contract.ev_tier = EvTier::Marginal;
        let errors = contract.validate().unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ContractValidationError::EvBelowThreshold { .. }))
        );
    }
}
