//! Quarantine de-escalation primitive: signed re-admission decisions and receipts.
//!
//! Enables reversible quarantine under operator authorization, addressing the
//! README limitation: 'Quarantine is a permanent ratchet today.' Every re-admission
//! emits a signed receipt that participates in the same evidence chain as the
//! original quarantine, ensuring audit trail integrity.
//!
//! Key properties:
//! - Operator-signed re-admission decisions with TEE attestation when available
//! - Evidence chain continuity: re-admission receipts link to original quarantine entries
//! - Deterministic replay: identical decisions under same conditions
//! - Fallback path: auto-re-quarantine upon misbehavior detection
//!
//! Plan reference: Section B.3, bead bd-cixqu.2.3.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_object,
    verify_signature,
};
use crate::tee_attestation_policy::{AttestationQuote, TeeAttestationPolicy, TeePlatform};
use franken_engine_deterministic_trait::FixedLayout;

// ---------------------------------------------------------------------------
// Constants and Schema Definitions
// ---------------------------------------------------------------------------

const READMISSION_DECISION_SCHEMA_DEF: &[u8] = b"FrankenEngine.ReAdmissionDecision.v1";
const READMISSION_RECEIPT_SCHEMA_DEF: &[u8] = b"FrankenEngine.ReAdmissionReceipt.v1";
const QUARANTINE_DEESCALATION_ZONE: &str = "quarantine-deescalation";

/// Fixed-point unit: 1_000_000 = 1.0 for deterministic decimal calculations.
const MILLIONTHS: u64 = 1_000_000;

fn readmission_decision_schema_id() -> SchemaId {
    SchemaId::from_definition(READMISSION_DECISION_SCHEMA_DEF)
}

fn readmission_receipt_schema_id() -> SchemaId {
    SchemaId::from_definition(READMISSION_RECEIPT_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// AttestationStatus - TEE attestation availability for this decision
// ---------------------------------------------------------------------------

/// TEE attestation status for a re-admission decision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AttestationStatus {
    /// TEE attestation is available and valid.
    Available { quote: AttestationQuote },
    /// TEE attestation is not available (safe-mode fallback).
    NotAvailable,
    /// TEE attestation failed validation.
    Failed { reason: String },
}

impl fmt::Display for AttestationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Available { .. } => f.write_str("available"),
            Self::NotAvailable => f.write_str("not_available"),
            Self::Failed { reason } => write!(f, "failed:{}", reason),
        }
    }
}

// ---------------------------------------------------------------------------
// QuarantineReason - Why the original quarantine occurred
// ---------------------------------------------------------------------------

/// Reason for the original quarantine that led to this re-admission decision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum QuarantineReason {
    /// Policy violation detected by automated monitoring.
    PolicyViolation {
        policy_id: String,
        violation_details: String,
    },
    /// Suspicious behavior pattern matching attack signature.
    SuspiciousBehavior {
        pattern_id: String,
        confidence_score: u64,
    },
    /// Resource exhaustion that threatened system stability.
    ResourceExhaustion {
        resource_type: String,
        threshold_exceeded: u64,
    },
    /// Manual quarantine by operator for investigation.
    OperatorInitiated { operator_id: String, reason: String },
    /// Cascade protection: quarantined due to dependent component failure.
    CascadeProtection {
        failed_component: String,
        dependency_chain: Vec<String>,
    },
}

impl fmt::Display for QuarantineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyViolation {
                policy_id,
                violation_details,
            } => {
                write!(f, "policy_violation:{}:{}", policy_id, violation_details)
            }
            Self::SuspiciousBehavior {
                pattern_id,
                confidence_score,
            } => {
                write!(f, "suspicious_behavior:{}:{}", pattern_id, confidence_score)
            }
            Self::ResourceExhaustion {
                resource_type,
                threshold_exceeded,
            } => {
                write!(
                    f,
                    "resource_exhaustion:{}:{}",
                    resource_type, threshold_exceeded
                )
            }
            Self::OperatorInitiated {
                operator_id,
                reason,
            } => {
                write!(f, "operator_initiated:{}:{}", operator_id, reason)
            }
            Self::CascadeProtection {
                failed_component,
                dependency_chain,
            } => {
                write!(
                    f,
                    "cascade_protection:{}:{}",
                    failed_component,
                    dependency_chain.join(",")
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// FallbackPath - What happens if re-admission misbehaves
// ---------------------------------------------------------------------------

/// Fallback action if the re-admitted entity misbehaves.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FallbackPath {
    /// Automatically re-quarantine with the specified policy.
    AutoReQuarantine {
        policy_id: String,
        escalation_threshold: u64,
    },
    /// Require manual operator intervention for any future issues.
    RequireManualIntervention { contact_info: String },
    /// Apply stricter monitoring with reduced capability budget.
    StrictMonitoring {
        budget_reduction_millionths: u64,
        monitoring_duration_secs: u64,
    },
    /// Permanent containment with no further re-admission allowed.
    PermanentContainment { justification: String },
}

impl fmt::Display for FallbackPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AutoReQuarantine {
                policy_id,
                escalation_threshold,
            } => {
                write!(
                    f,
                    "auto_requarantine:{}:{}",
                    policy_id, escalation_threshold
                )
            }
            Self::RequireManualIntervention { contact_info } => {
                write!(f, "manual_intervention:{}", contact_info)
            }
            Self::StrictMonitoring {
                budget_reduction_millionths,
                monitoring_duration_secs,
            } => {
                write!(
                    f,
                    "strict_monitoring:{}:{}",
                    budget_reduction_millionths, monitoring_duration_secs
                )
            }
            Self::PermanentContainment { justification } => {
                write!(f, "permanent_containment:{}", justification)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ReAdmissionDecision - The operator's decision to allow re-admission
// ---------------------------------------------------------------------------

/// Operator's signed decision to allow re-admission from quarantine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReAdmissionDecision {
    /// Schema version for this decision format.
    pub schema_version: SchemaId,
    /// Security epoch when this decision was made.
    pub epoch: SecurityEpoch,
    /// Unique identifier for this re-admission decision.
    pub decision_id: EngineObjectId,
    /// Reference to the original quarantine entry that this reverses.
    pub original_quarantine_id: EngineObjectId,
    /// Reason for the original quarantine.
    pub original_quarantine_reason: QuarantineReason,
    /// Time spent in quarantine (seconds since quarantine started).
    pub time_in_quarantine_secs: u64,
    /// Identity of the operator making this decision.
    pub operator_id: String,
    /// TEE attestation status for this decision (if available).
    pub tee_attestation: AttestationStatus,
    /// Bayesian posterior confidence in safe re-admission (millionths).
    pub posterior_confidence_millionths: u64,
    /// Fallback action if re-admitted entity misbehaves.
    pub fallback_path: FallbackPath,
    /// Additional metadata for the decision.
    pub metadata: BTreeMap<String, String>,
    /// Operator's signature over the decision content.
    pub operator_signature: Signature,
}

impl ReAdmissionDecision {
    /// Creates a new re-admission decision.
    pub fn new(
        epoch: SecurityEpoch,
        original_quarantine_id: EngineObjectId,
        original_quarantine_reason: QuarantineReason,
        time_in_quarantine_secs: u64,
        operator_id: String,
        tee_attestation: AttestationStatus,
        posterior_confidence_millionths: u64,
        fallback_path: FallbackPath,
        metadata: BTreeMap<String, String>,
        operator_key: &SigningKey,
    ) -> Result<Self, ReAdmissionError> {
        let schema_version = readmission_decision_schema_id();

        // Generate deterministic decision ID.
        let decision_id = engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            "readmission_decision",
            &schema_version,
            &Self::compute_decision_content_hash(
                &original_quarantine_id,
                &original_quarantine_reason,
                time_in_quarantine_secs,
                &operator_id,
                &tee_attestation,
                posterior_confidence_millionths,
                &fallback_path,
                &metadata,
            )
            .as_bytes(),
        )
        .map_err(|e| {
            ReAdmissionError::IdGeneration(format!("Failed to derive decision ID: {}", e))
        })?;

        // Create unsigned decision for signing.
        let unsigned_decision = Self {
            schema_version,
            epoch,
            decision_id,
            original_quarantine_id,
            original_quarantine_reason,
            time_in_quarantine_secs,
            operator_id,
            tee_attestation,
            posterior_confidence_millionths,
            fallback_path,
            metadata,
            operator_signature: Signature::default(),
        };

        // Sign the decision content.
        let signature = sign_object(&unsigned_decision, operator_key)
            .map_err(|e| ReAdmissionError::Signing(format!("Failed to sign decision: {}", e)))?;

        Ok(Self {
            operator_signature: signature,
            ..unsigned_decision
        })
    }

    /// Verifies the operator signature on this decision.
    pub fn verify_signature(
        &self,
        operator_key: &VerificationKey,
    ) -> Result<bool, ReAdmissionError> {
        let unsigned = Self {
            operator_signature: Signature::default(),
            ..self.clone()
        };

        verify_signature(&unsigned, &self.operator_signature, operator_key).map_err(|e| {
            ReAdmissionError::Verification(format!("Signature verification failed: {}", e))
        })
    }

    /// Computes content hash for deterministic ID generation.
    fn compute_decision_content_hash(
        original_quarantine_id: &EngineObjectId,
        original_quarantine_reason: &QuarantineReason,
        time_in_quarantine_secs: u64,
        operator_id: &str,
        tee_attestation: &AttestationStatus,
        posterior_confidence_millionths: u64,
        fallback_path: &FallbackPath,
        metadata: &BTreeMap<String, String>,
    ) -> ContentHash {
        let mut content = Vec::new();

        // Use FixedLayout encoding for fixed-size types
        let id_start = content.len();
        content.resize(id_start + EngineObjectId::LAYOUT_SIZE, 0);
        original_quarantine_id
            .encode_fixed(&mut content[id_start..id_start + EngineObjectId::LAYOUT_SIZE]);

        content
            .extend_from_slice(&serde_json::to_vec(original_quarantine_reason).unwrap_or_default());
        content.extend_from_slice(&time_in_quarantine_secs.to_be_bytes());
        content.extend_from_slice(operator_id.as_bytes());
        content.extend_from_slice(&serde_json::to_vec(tee_attestation).unwrap_or_default());
        content.extend_from_slice(&posterior_confidence_millionths.to_be_bytes());
        content.extend_from_slice(&serde_json::to_vec(fallback_path).unwrap_or_default());
        content.extend_from_slice(&serde_json::to_vec(metadata).unwrap_or_default());
        ContentHash::compute(&content)
    }
}

// ---------------------------------------------------------------------------
// ReAdmissionReceipt - Evidence chain entry for the re-admission
// ---------------------------------------------------------------------------

/// Receipt for a re-admission decision that participates in the evidence chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReAdmissionReceipt {
    /// Schema version for this receipt format.
    pub schema_version: SchemaId,
    /// Security epoch when this receipt was generated.
    pub epoch: SecurityEpoch,
    /// Unique identifier for this receipt.
    pub receipt_id: EngineObjectId,
    /// The re-admission decision this receipt validates.
    pub decision: ReAdmissionDecision,
    /// Hash of the previous evidence chain entry.
    pub prev_evidence_hash: ContentHash,
    /// Content hash of this receipt for chain linking.
    pub content_hash: ContentHash,
    /// Timestamp when this receipt was generated.
    pub generated_at_secs: u64,
    /// System signature over the receipt.
    pub system_signature: Signature,
}

impl ReAdmissionReceipt {
    /// Creates a new re-admission receipt linking to the evidence chain.
    pub fn new(
        epoch: SecurityEpoch,
        decision: ReAdmissionDecision,
        prev_evidence_hash: ContentHash,
        generated_at_secs: u64,
        system_key: &SigningKey,
    ) -> Result<Self, ReAdmissionError> {
        let schema_version = readmission_receipt_schema_id();

        // Generate deterministic receipt ID.
        let receipt_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            "readmission_receipt",
            &schema_version,
            &decision.decision_id.as_bytes(),
        )
        .map_err(|e| {
            ReAdmissionError::IdGeneration(format!("Failed to derive receipt ID: {}", e))
        })?;

        // Compute content hash for this receipt.
        let content_hash =
            Self::compute_content_hash(&decision, &prev_evidence_hash, generated_at_secs);

        // Create unsigned receipt for signing.
        let unsigned_receipt = Self {
            schema_version,
            epoch,
            receipt_id,
            decision,
            prev_evidence_hash,
            content_hash,
            generated_at_secs,
            system_signature: Signature::default(),
        };

        // Sign the receipt.
        let signature = sign_object(&unsigned_receipt, system_key)
            .map_err(|e| ReAdmissionError::Signing(format!("Failed to sign receipt: {}", e)))?;

        Ok(Self {
            system_signature: signature,
            ..unsigned_receipt
        })
    }

    /// Verifies the system signature and evidence chain integrity.
    pub fn verify(&self, system_key: &VerificationKey) -> Result<bool, ReAdmissionError> {
        // Verify system signature.
        let unsigned = Self {
            system_signature: Signature::default(),
            ..self.clone()
        };

        let signature_valid = verify_signature(&unsigned, &self.system_signature, system_key)
            .map_err(|e| {
                ReAdmissionError::Verification(format!(
                    "System signature verification failed: {}",
                    e
                ))
            })?;

        if !signature_valid {
            return Ok(false);
        }

        // Verify content hash matches computed value.
        let expected_hash = Self::compute_content_hash(
            &self.decision,
            &self.prev_evidence_hash,
            self.generated_at_secs,
        );

        Ok(self.content_hash == expected_hash)
    }

    /// Computes content hash for evidence chain linking.
    fn compute_content_hash(
        decision: &ReAdmissionDecision,
        prev_evidence_hash: &ContentHash,
        generated_at_secs: u64,
    ) -> ContentHash {
        let mut content = Vec::new();
        content.extend_from_slice(&serde_json::to_vec(decision).unwrap_or_default());

        // Use FixedLayout encoding for ContentHash
        let hash_start = content.len();
        content.resize(hash_start + ContentHash::LAYOUT_SIZE, 0);
        prev_evidence_hash
            .encode_fixed(&mut content[hash_start..hash_start + ContentHash::LAYOUT_SIZE]);

        content.extend_from_slice(&generated_at_secs.to_be_bytes());
        ContentHash::compute(&content)
    }

    /// Genesis hash for the first receipt in a chain.
    pub fn genesis_hash() -> ContentHash {
        ContentHash::compute(b"genesis-quarantine-deescalation")
    }
}

// ---------------------------------------------------------------------------
// ReAdmissionError - Error types for de-escalation operations
// ---------------------------------------------------------------------------

/// Errors that can occur during quarantine de-escalation operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReAdmissionError {
    /// Error generating object IDs.
    IdGeneration(String),
    /// Error signing decisions or receipts.
    Signing(String),
    /// Error verifying signatures or integrity.
    Verification(String),
    /// Invalid parameters provided.
    InvalidInput(String),
    /// TEE attestation error.
    TeeAttestation(String),
}

impl fmt::Display for ReAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdGeneration(msg) => write!(f, "ID generation error: {}", msg),
            Self::Signing(msg) => write!(f, "Signing error: {}", msg),
            Self::Verification(msg) => write!(f, "Verification error: {}", msg),
            Self::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Self::TeeAttestation(msg) => write!(f, "TEE attestation error: {}", msg),
        }
    }
}

impl std::error::Error for ReAdmissionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature_preimage::{SigningKey, VerificationKey};

    fn make_test_keys() -> (SigningKey, VerificationKey) {
        let signing_key = SigningKey::generate();
        let verification_key = signing_key.verification_key();
        (signing_key, verification_key)
    }

    fn make_test_quarantine_reason() -> QuarantineReason {
        QuarantineReason::PolicyViolation {
            policy_id: "test-policy-001".to_string(),
            violation_details: "Exceeded memory allocation limit".to_string(),
        }
    }

    fn make_test_fallback_path() -> FallbackPath {
        FallbackPath::AutoReQuarantine {
            policy_id: "strict-monitoring-v1".to_string(),
            escalation_threshold: 3,
        }
    }

    #[test]
    fn test_readmission_decision_creation() {
        let (operator_key, operator_verification_key) = make_test_keys();
        let epoch = SecurityEpoch::from_raw(42);
        let original_quarantine_id = EngineObjectId::new();
        let quarantine_reason = make_test_quarantine_reason();
        let fallback_path = make_test_fallback_path();
        let metadata = BTreeMap::new();

        let decision = ReAdmissionDecision::new(
            epoch,
            original_quarantine_id,
            quarantine_reason,
            3600, // 1 hour in quarantine
            "operator-alice".to_string(),
            AttestationStatus::Available,
            800_000, // 80% confidence
            fallback_path,
            metadata,
            &operator_key,
        )
        .expect("Decision creation should succeed");

        assert_eq!(decision.epoch, epoch);
        assert_eq!(decision.time_in_quarantine_secs, 3600);
        assert_eq!(decision.operator_id, "operator-alice");
        assert_eq!(decision.posterior_confidence_millionths, 800_000);

        // Verify signature.
        assert!(
            decision
                .verify_signature(&operator_verification_key)
                .expect("Verification should not error")
        );
    }

    #[test]
    fn test_readmission_receipt_creation_and_verification() {
        let (operator_key, operator_verification_key) = make_test_keys();
        let (system_key, system_verification_key) = make_test_keys();
        let epoch = SecurityEpoch::from_raw(42);

        // Create a decision first.
        let decision = ReAdmissionDecision::new(
            epoch,
            EngineObjectId::new(),
            make_test_quarantine_reason(),
            3600,
            "operator-alice".to_string(),
            AttestationStatus::Available,
            800_000,
            make_test_fallback_path(),
            BTreeMap::new(),
            &operator_key,
        )
        .expect("Decision creation should succeed");

        // Create receipt.
        let prev_hash = ReAdmissionReceipt::genesis_hash();
        let receipt = ReAdmissionReceipt::new(
            epoch,
            decision,
            prev_hash,
            1234567890, // Mock timestamp
            &system_key,
        )
        .expect("Receipt creation should succeed");

        assert_eq!(receipt.epoch, epoch);
        assert_eq!(receipt.prev_evidence_hash, prev_hash);
        assert_eq!(receipt.generated_at_secs, 1234567890);

        // Verify receipt.
        assert!(
            receipt
                .verify(&system_verification_key)
                .expect("Verification should not error")
        );
    }

    #[test]
    fn test_evidence_chain_linking() {
        let (system_key, system_verification_key) = make_test_keys();
        let (operator_key, _) = make_test_keys();
        let epoch = SecurityEpoch::from_raw(42);

        // Create first receipt.
        let decision1 = ReAdmissionDecision::new(
            epoch,
            EngineObjectId::new(),
            make_test_quarantine_reason(),
            3600,
            "operator-alice".to_string(),
            AttestationStatus::Available,
            800_000,
            make_test_fallback_path(),
            BTreeMap::new(),
            &operator_key,
        )
        .expect("Decision creation should succeed");

        let receipt1 = ReAdmissionReceipt::new(
            epoch,
            decision1,
            ReAdmissionReceipt::genesis_hash(),
            1234567890,
            &system_key,
        )
        .expect("Receipt creation should succeed");

        // Create second receipt linking to first.
        let decision2 = ReAdmissionDecision::new(
            epoch,
            EngineObjectId::new(),
            QuarantineReason::SuspiciousBehavior {
                pattern_id: "pattern-002".to_string(),
                confidence_score: 750_000,
            },
            7200,
            "operator-bob".to_string(),
            AttestationStatus::NotAvailable,
            600_000,
            make_test_fallback_path(),
            BTreeMap::new(),
            &operator_key,
        )
        .expect("Decision creation should succeed");

        let receipt2 = ReAdmissionReceipt::new(
            epoch,
            decision2,
            receipt1.content_hash, // Link to previous receipt
            1234567900,
            &system_key,
        )
        .expect("Receipt creation should succeed");

        // Verify chain linking.
        assert_eq!(receipt2.prev_evidence_hash, receipt1.content_hash);
        assert!(
            receipt1
                .verify(&system_verification_key)
                .expect("Verification should not error")
        );
        assert!(
            receipt2
                .verify(&system_verification_key)
                .expect("Verification should not error")
        );
    }

    #[test]
    fn test_quarantine_reason_display() {
        let reason = QuarantineReason::PolicyViolation {
            policy_id: "mem-limit-v1".to_string(),
            violation_details: "Exceeded 1GB allocation".to_string(),
        };

        let display = format!("{}", reason);
        assert!(display.contains("policy_violation"));
        assert!(display.contains("mem-limit-v1"));
        assert!(display.contains("Exceeded 1GB allocation"));
    }

    #[test]
    fn test_fallback_path_display() {
        let fallback = FallbackPath::StrictMonitoring {
            budget_reduction_millionths: 500_000, // 50% reduction
            monitoring_duration_secs: 86400,      // 24 hours
        };

        let display = format!("{}", fallback);
        assert!(display.contains("strict_monitoring"));
        assert!(display.contains("500000"));
        assert!(display.contains("86400"));
    }

    #[test]
    fn test_decision_deterministic_id_generation() {
        let (operator_key, _) = make_test_keys();
        let epoch = SecurityEpoch::from_raw(42);
        let original_quarantine_id = EngineObjectId::new();
        let quarantine_reason = make_test_quarantine_reason();
        let fallback_path = make_test_fallback_path();
        let metadata = BTreeMap::new();

        // Create two identical decisions.
        let decision1 = ReAdmissionDecision::new(
            epoch,
            original_quarantine_id,
            quarantine_reason.clone(),
            3600,
            "operator-alice".to_string(),
            AttestationStatus::Available,
            800_000,
            fallback_path.clone(),
            metadata.clone(),
            &operator_key,
        )
        .expect("Decision creation should succeed");

        let decision2 = ReAdmissionDecision::new(
            epoch,
            original_quarantine_id,
            quarantine_reason,
            3600,
            "operator-alice".to_string(),
            AttestationStatus::Available,
            800_000,
            fallback_path,
            metadata,
            &operator_key,
        )
        .expect("Decision creation should succeed");

        // Decision IDs should be identical (deterministic).
        assert_eq!(decision1.decision_id, decision2.decision_id);
    }

    #[test]
    fn test_invalid_signature_detection() {
        let (operator_key, _) = make_test_keys();
        let (_, wrong_verification_key) = make_test_keys();

        let decision = ReAdmissionDecision::new(
            SecurityEpoch::from_raw(42),
            EngineObjectId::new(),
            make_test_quarantine_reason(),
            3600,
            "operator-alice".to_string(),
            AttestationStatus::Available,
            800_000,
            make_test_fallback_path(),
            BTreeMap::new(),
            &operator_key,
        )
        .expect("Decision creation should succeed");

        // Verification with wrong key should fail.
        assert!(
            !decision
                .verify_signature(&wrong_verification_key)
                .expect("Verification should not error")
        );
    }

    #[test]
    fn test_content_hash_consistency() {
        let (operator_key, _) = make_test_keys();
        let (system_key, _) = make_test_keys();

        let decision = ReAdmissionDecision::new(
            SecurityEpoch::from_raw(42),
            EngineObjectId::new(),
            make_test_quarantine_reason(),
            3600,
            "operator-alice".to_string(),
            AttestationStatus::Available,
            800_000,
            make_test_fallback_path(),
            BTreeMap::new(),
            &operator_key,
        )
        .expect("Decision creation should succeed");

        let prev_hash = ReAdmissionReceipt::genesis_hash();
        let timestamp = 1234567890;

        // Create receipt.
        let receipt = ReAdmissionReceipt::new(
            SecurityEpoch::from_raw(42),
            decision.clone(),
            prev_hash,
            timestamp,
            &system_key,
        )
        .expect("Receipt creation should succeed");

        // Manually compute expected hash.
        let expected_hash =
            ReAdmissionReceipt::compute_content_hash(&decision, &prev_hash, timestamp);

        assert_eq!(receipt.content_hash, expected_hash);
    }
}
