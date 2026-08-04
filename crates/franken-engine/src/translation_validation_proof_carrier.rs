//! Translation validation proof carrier for ReplacementReceipts.
//!
//! Binds a translation-validation verdict into a `ReplacementReceipt` during a
//! slot promotion. **This carrier is fail-closed by design:** absent a genuine
//! per-slot semantic-equivalence engine it emits an UNPROVEN result rather than
//! fabricating a passing proof, and it refuses to hand a promotion a proof
//! reference it cannot stand behind.
//!
//! ## Execution modes ([`ValidationExecutionMode`])
//!
//! - `FailClosed` (default): no real per-slot validation pipeline is wired, so
//!   [`TranslationValidationEngine::validate_slot_promotion`] produces a proof
//!   whose `validation_result` is [`ValidationResult::Error`] (UNPROVEN), and
//!   [`validate_promotion_and_get_proof_ref`] returns
//!   [`TranslationValidationError::ValidationNotProven`]. An unproven
//!   validation therefore cannot back a constitutional self-replacement
//!   receipt.
//! - `ExecutePilotScript`: genuinely executes
//!   `scripts/run_rgc_translation_validation_pilot.sh` and binds its *real,
//!   parsed* verdict (passed/failed/total counts plus the script's exit
//!   status). Any missing/unparseable verdict or non-zero exit maps to
//!   [`ValidationResult::Error`] — never a fabricated success.
//!
//!   NOTE: the current pilot script validates a generic pure-expression corpus
//!   and does *not* yet specialise on the specific slot under promotion, so its
//!   `Success` is corpus-level evidence rather than a per-slot equivalence
//!   proof. That limitation is tracked under FE-CLAIM-017 / FE-CLAIM-018; until
//!   it is closed, operators should keep the default `FailClosed` mode for
//!   constitutional promotions.
//!
//! ## Proof storage
//!
//! [`TranslationValidationEngine::store_proof`] persists the
//! canonical-serialized proof to a content-addressed file under
//! `target/translation_validation_proofs/<zone>/<proof_id>.json`;
//! [`TranslationValidationEngine::retrieve_proof`] reads it back. Proofs
//! round-trip and are auditable — neither call fabricates a reference.
//!
//! ## Proof Format
//!
//! Translation validation proofs contain:
//! - Source slot specification (code digest)
//! - Target slot specification (code digest)
//! - Test case digest derived from the source/target specs
//! - Validation result (genuine script verdict, or fail-closed UNPROVEN)
//! - Captured validation logs
//! - Lean 4 formal proof reference (if available)

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{self, EngineObjectId, ObjectDomain};
use crate::security_epoch::SecurityEpoch;
use crate::slot_registry::SlotId;

pub const TRANSLATION_VALIDATION_WITNESS_SCHEMA_VERSION: &str =
    "franken-engine.translation-validation-witness.v1";

/// Claim ID backed by translation-validation witnesses (bd-fqlfw.6.3/6.5).
pub const FE_CLAIM_017_CLAIM_ID: &str = "FE-CLAIM-017";

// ---------------------------------------------------------------------------
// Translation Validation Proof Types
// ---------------------------------------------------------------------------

/// Result of translation validation execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationResult {
    /// Validation succeeded with perfect semantic equivalence.
    Success {
        /// Number of test cases that passed.
        test_cases_passed: u32,
        /// Total number of test cases executed.
        test_cases_total: u32,
        /// Success rate as percentage (0-100).
        success_rate_percent: u32,
    },
    /// Validation failed due to semantic differences.
    Failed {
        /// Number of test cases that passed.
        test_cases_passed: u32,
        /// Total number of test cases executed.
        test_cases_total: u32,
        /// Success rate as percentage (0-100).
        success_rate_percent: u32,
        /// Detailed failure reasons.
        failure_reasons: Vec<String>,
    },
    /// Validation could not be completed due to errors.
    Error {
        /// Error message describing what went wrong.
        error_message: String,
        /// Error code for programmatic handling.
        error_code: ValidationErrorCode,
    },
}

/// Error codes for validation failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationErrorCode {
    /// Source slot specification is malformed or unparseable.
    InvalidSourceSpec,
    /// Target slot specification is malformed or unparseable.
    InvalidTargetSpec,
    /// IR transformation failed unexpectedly.
    TransformationError,
    /// Test case generation failed.
    TestGenerationError,
    /// Lean 4 formal verification failed.
    FormalVerificationError,
    /// Internal validation engine error.
    InternalError,
}

impl ValidationErrorCode {
    fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidSourceSpec => "invalid_source_spec",
            Self::InvalidTargetSpec => "invalid_target_spec",
            Self::TransformationError => "transformation_error",
            Self::TestGenerationError => "test_generation_error",
            Self::FormalVerificationError => "formal_verification_error",
            Self::InternalError => "internal_error",
        }
    }
}

impl ValidationResult {
    /// Check if this result represents a successful validation.
    pub fn is_success(&self) -> bool {
        matches!(self, ValidationResult::Success { .. })
    }

    /// Get the success rate percentage, or 0 if error.
    pub fn success_rate_percent(&self) -> u32 {
        match self {
            ValidationResult::Success {
                success_rate_percent,
                ..
            } => *success_rate_percent,
            ValidationResult::Failed {
                success_rate_percent,
                ..
            } => *success_rate_percent,
            ValidationResult::Error { .. } => 0,
        }
    }

    /// Get the total number of test cases, or 0 if error.
    pub fn total_test_cases(&self) -> u32 {
        match self {
            ValidationResult::Success {
                test_cases_total, ..
            } => *test_cases_total,
            ValidationResult::Failed {
                test_cases_total, ..
            } => *test_cases_total,
            ValidationResult::Error { .. } => 0,
        }
    }
}

/// Slot specification for translation validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotSpecification {
    /// Slot identifier.
    pub slot_id: SlotId,
    /// Source code content digest (SHA-256).
    pub code_digest: String,
    /// Source code language/format.
    pub language: String,
    /// IR transformation stages expected.
    pub ir_stages: Vec<String>,
    /// Capability requirements for execution.
    pub capability_requirements: Vec<String>,
}

/// Translation validation proof artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslationValidationProof {
    /// Content-addressed proof identifier.
    pub proof_id: EngineObjectId,
    /// Source slot specification being replaced.
    pub source_spec: SlotSpecification,
    /// Target slot specification being promoted.
    pub target_spec: SlotSpecification,
    /// Validation execution result.
    pub validation_result: ValidationResult,
    /// Detailed validation logs (truncated for storage).
    pub validation_logs: Vec<String>,
    /// Lean 4 formal proof reference (if available).
    pub formal_proof_ref: Option<String>,
    /// IR transformation witness data.
    pub transformation_witness: Vec<u8>,
    /// Test case data used for validation.
    pub test_case_digest: String,
    /// Timestamp when validation was executed (nanoseconds).
    pub validation_timestamp_ns: u64,
    /// Security epoch for the validation.
    pub security_epoch: SecurityEpoch,
    /// Zone scoping for the validation.
    pub zone: String,
}

impl TranslationValidationProof {
    /// Derive proof ID from its contents.
    pub fn derive_proof_id(
        source_code_digest: &str,
        target_code_digest: &str,
        validation_timestamp_ns: u64,
        zone: &str,
    ) -> Result<EngineObjectId, crate::engine_object_id::IdError> {
        // Length-prefix the digests (reusing the module helper) instead of
        // `|`-delimiting: a `|` inside a digest would otherwise let two distinct
        // (source, target) pairs derive the same proof id.
        let mut canonical = Vec::new();
        append_str(&mut canonical, source_code_digest);
        append_str(&mut canonical, target_code_digest);
        canonical.extend_from_slice(&validation_timestamp_ns.to_be_bytes());

        let schema_id =
            engine_object_id::SchemaId::from_definition(b"translation_validation_proof_v1");
        engine_object_id::derive_id(
            ObjectDomain::CheckpointArtifact,
            zone,
            &schema_id,
            &canonical,
        )
    }

    /// Check if this proof represents a successful validation.
    pub fn is_valid(&self) -> bool {
        self.validation_result.is_success()
    }

    /// Get a human-readable summary of the proof.
    pub fn summary(&self) -> String {
        match &self.validation_result {
            ValidationResult::Success {
                test_cases_passed,
                test_cases_total,
                success_rate_percent,
            } => {
                format!(
                    "Translation validation PASSED: {}/{} test cases ({}%)",
                    test_cases_passed, test_cases_total, success_rate_percent
                )
            }
            ValidationResult::Failed {
                test_cases_passed,
                test_cases_total,
                success_rate_percent,
                failure_reasons,
            } => {
                format!(
                    "Translation validation FAILED: {}/{} test cases ({}%) - {}",
                    test_cases_passed,
                    test_cases_total,
                    success_rate_percent,
                    failure_reasons.join("; ")
                )
            }
            ValidationResult::Error {
                error_message,
                error_code,
            } => {
                format!(
                    "Translation validation ERROR: {:?} - {}",
                    error_code, error_message
                )
            }
        }
    }
}

/// Machine-readable outcome class emitted for validator witnesses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranslationValidationWitnessVerdict {
    /// The validator produced evidence strong enough to prove equivalence.
    Proven,
    /// The validator found a semantic divergence and emitted counterexample data.
    Counterexample,
    /// The validator could not produce a proof or counterexample.
    Unavailable,
}

impl TranslationValidationWitnessVerdict {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Counterexample => "counterexample",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Counterexample payload for a failed translation-validation run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslationValidationCounterexample {
    /// Deterministic hash of the divergence description and compared specs.
    pub counterexample_hash: String,
    /// Validator-supplied failure reasons.
    pub failure_reasons: Vec<String>,
    /// Number of cases that still passed before divergence was classified.
    pub test_cases_passed: u32,
    /// Total number of cases examined by the validator.
    pub test_cases_total: u32,
    /// Integer percent reported by the validator.
    pub success_rate_percent: u32,
}

/// Flat JSON artifact emitted by translation validators.
///
/// This is intentionally distinct from [`TranslationValidationProof`]: the
/// proof carries the original validator result, while this witness normalizes
/// that result into the gate-facing `proven` / `counterexample` / `unavailable`
/// trichotomy and binds it with a deterministic content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranslationValidationWitnessArtifact {
    /// Schema id for this witness JSON shape.
    pub schema_version: String,
    /// Validator that produced the witness.
    pub validator_id: String,
    /// Content-addressed proof id from the underlying proof carrier.
    pub proof_id: String,
    /// Source slot id under validation.
    pub source_slot_id: String,
    /// Target slot id under validation.
    pub target_slot_id: String,
    /// Source code digest under validation.
    pub source_code_digest: String,
    /// Target code digest under validation.
    pub target_code_digest: String,
    /// Normalized gate-facing verdict.
    pub verdict: TranslationValidationWitnessVerdict,
    /// Original validator result, preserved for consumers needing full detail.
    pub validation_result: ValidationResult,
    /// Human-readable summary derived from the original proof.
    pub validation_summary: String,
    /// Counterexample payload for failed validation.
    pub counterexample: Option<TranslationValidationCounterexample>,
    /// Fail-closed reason for unavailable validation.
    pub unavailable_reason: Option<String>,
    /// Test-case digest from the underlying proof.
    pub test_case_digest: String,
    /// Formal proof reference, when the validator supplied one.
    pub formal_proof_ref: Option<String>,
    /// Validation timestamp from the underlying proof.
    pub validation_timestamp_ns: u64,
    /// Security epoch for the validation.
    pub security_epoch: SecurityEpoch,
    /// Zone scoped by the underlying proof.
    pub zone: String,
    /// Bounded validator logs captured by the proof carrier.
    pub validation_logs: Vec<String>,
    /// Deterministic SHA-256 hash over every field above.
    pub content_hash: String,
}

impl TranslationValidationWitnessArtifact {
    /// Build a gate-facing witness from a proof carrier result.
    pub fn from_proof(validator_id: impl Into<String>, proof: &TranslationValidationProof) -> Self {
        let (verdict, counterexample, unavailable_reason) = match &proof.validation_result {
            ValidationResult::Success { .. } => {
                (TranslationValidationWitnessVerdict::Proven, None, None)
            }
            ValidationResult::Failed {
                test_cases_passed,
                test_cases_total,
                success_rate_percent,
                failure_reasons,
            } => {
                let counterexample = TranslationValidationCounterexample {
                    counterexample_hash: derive_counterexample_hash(proof, failure_reasons),
                    failure_reasons: failure_reasons.clone(),
                    test_cases_passed: *test_cases_passed,
                    test_cases_total: *test_cases_total,
                    success_rate_percent: *success_rate_percent,
                };
                (
                    TranslationValidationWitnessVerdict::Counterexample,
                    Some(counterexample),
                    None,
                )
            }
            ValidationResult::Error {
                error_message,
                error_code,
            } => (
                TranslationValidationWitnessVerdict::Unavailable,
                None,
                Some(format!("{}: {}", error_code.as_str(), error_message)),
            ),
        };

        let mut artifact = Self {
            schema_version: TRANSLATION_VALIDATION_WITNESS_SCHEMA_VERSION.to_string(),
            validator_id: validator_id.into(),
            proof_id: proof.proof_id.to_hex(),
            source_slot_id: proof.source_spec.slot_id.as_str().to_string(),
            target_slot_id: proof.target_spec.slot_id.as_str().to_string(),
            source_code_digest: proof.source_spec.code_digest.clone(),
            target_code_digest: proof.target_spec.code_digest.clone(),
            verdict,
            validation_result: proof.validation_result.clone(),
            validation_summary: proof.summary(),
            counterexample,
            unavailable_reason,
            test_case_digest: proof.test_case_digest.clone(),
            formal_proof_ref: proof.formal_proof_ref.clone(),
            validation_timestamp_ns: proof.validation_timestamp_ns,
            security_epoch: proof.security_epoch,
            zone: proof.zone.clone(),
            validation_logs: proof.validation_logs.clone(),
            content_hash: String::new(),
        };
        artifact.content_hash = artifact.compute_content_hash();
        artifact
    }

    /// Recompute and verify the witness content hash.
    pub fn verify_content_hash(&self) -> bool {
        self.content_hash == self.compute_content_hash()
    }

    /// Deterministic hash over the artifact body, excluding `content_hash`.
    pub fn compute_content_hash(&self) -> String {
        let mut preimage = Vec::new();
        append_str(&mut preimage, &self.schema_version);
        append_str(&mut preimage, &self.validator_id);
        append_str(&mut preimage, &self.proof_id);
        append_str(&mut preimage, &self.source_slot_id);
        append_str(&mut preimage, &self.target_slot_id);
        append_str(&mut preimage, &self.source_code_digest);
        append_str(&mut preimage, &self.target_code_digest);
        append_str(&mut preimage, self.verdict.as_str());
        append_validation_result(&mut preimage, &self.validation_result);
        append_str(&mut preimage, &self.validation_summary);
        append_counterexample(&mut preimage, self.counterexample.as_ref());
        append_optional_str(&mut preimage, self.unavailable_reason.as_deref());
        append_str(&mut preimage, &self.test_case_digest);
        append_optional_str(&mut preimage, self.formal_proof_ref.as_deref());
        preimage.extend_from_slice(&self.validation_timestamp_ns.to_be_bytes());
        preimage.extend_from_slice(&self.security_epoch.as_u64().to_be_bytes());
        append_str(&mut preimage, &self.zone);
        append_str_vec(&mut preimage, &self.validation_logs);
        sha256_hex(&preimage)
    }

    /// Bridge this witness into the strict E6.T1 proof.json producer contract
    /// (bd-fqlfw.6.5) so the proof-spine claim gate can classify it alongside
    /// other producer artifacts under FE-CLAIM-017.
    ///
    /// Verdict mapping: `Proven` → `Passed`, `Counterexample` → `Failed`
    /// (with the counterexample hash bound into `counterexample_artifacts`),
    /// `Unavailable` → `Unavailable`. The artifact is committed with a
    /// recomputed content hash, so downstream tamper detection holds.
    pub fn to_proof_producer_artifact(&self) -> crate::proof_schema::ProofProducerArtifact {
        use crate::hash_tiers::ContentHash;
        use crate::proof_schema::{
            ProofCheckerResult, ProofProducerArtifact, ProofSignatureOrContentHash,
            ProofToolIdentity, proof_schema_version_current,
        };

        let mut input_artifact_hashes = std::collections::BTreeMap::new();
        input_artifact_hashes.insert(
            format!("source:{}", self.source_slot_id),
            ContentHash::compute(self.source_code_digest.as_bytes()),
        );
        input_artifact_hashes.insert(
            format!("target:{}", self.target_slot_id),
            ContentHash::compute(self.target_code_digest.as_bytes()),
        );
        let mut output_artifact_hashes = std::collections::BTreeMap::new();
        output_artifact_hashes.insert(
            "translation_validation_witness.proof.json".to_string(),
            ContentHash::compute(self.content_hash.as_bytes()),
        );

        let mut counterexample_artifacts = std::collections::BTreeMap::new();
        let checker_result = match self.verdict {
            TranslationValidationWitnessVerdict::Proven => ProofCheckerResult::Passed,
            TranslationValidationWitnessVerdict::Counterexample => {
                let reason = self
                    .counterexample
                    .as_ref()
                    .map(|ce| ce.failure_reasons.join("; "))
                    .unwrap_or_else(|| self.validation_summary.clone());
                if let Some(ce) = &self.counterexample {
                    counterexample_artifacts.insert(
                        "counterexample".to_string(),
                        ContentHash::compute(ce.counterexample_hash.as_bytes()),
                    );
                }
                ProofCheckerResult::Failed { reason }
            }
            TranslationValidationWitnessVerdict::Unavailable => {
                let reason = self
                    .unavailable_reason
                    .clone()
                    .unwrap_or_else(|| self.validation_summary.clone());
                ProofCheckerResult::Unavailable { reason }
            }
        };

        let mut artifact = ProofProducerArtifact {
            schema_version: proof_schema_version_current(),
            claim_ids: vec![FE_CLAIM_017_CLAIM_ID.to_string()],
            theorem_or_validator_id: self.validator_id.clone(),
            input_artifact_hashes,
            output_artifact_hashes,
            command: format!(
                "translation-validate {} -> {}",
                self.source_slot_id, self.target_slot_id
            ),
            tool_identity: ProofToolIdentity {
                tool_name: "translation-validator".to_string(),
                tool_version: self.schema_version.clone(),
                tool_invocation_id: self.proof_id.clone(),
            },
            checker_result,
            counterexample_artifacts,
            timestamp_ticks: self.validation_timestamp_ns,
            logical_epoch: self.security_epoch,
            signature_or_content_hash: ProofSignatureOrContentHash::ContentHash(
                ContentHash::from_bytes([0u8; 32]),
            ),
        };
        artifact.signature_or_content_hash =
            ProofSignatureOrContentHash::ContentHash(artifact.content_hash());
        artifact
    }
}

/// Result returned after writing a translation-validation witness artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedTranslationValidationWitness {
    /// Path to the emitted JSON artifact.
    pub path: PathBuf,
    /// Artifact content hash.
    pub content_hash: String,
    /// Normalized verdict written to the artifact.
    pub verdict: TranslationValidationWitnessVerdict,
}

/// Emit a machine-readable proof/counterexample witness JSON file.
///
/// The output file is `<validator_id>.proof.json` under `bundle_dir`, with the
/// validator id sanitized to a filesystem-safe stem. Failed validations still
/// emit a counterexample artifact; unavailable validations emit fail-closed
/// reason metadata instead of pretending to be proofs.
pub fn emit_translation_validation_witness_artifact(
    proof: &TranslationValidationProof,
    bundle_dir: &Path,
    validator_id: &str,
) -> Result<EmittedTranslationValidationWitness, TranslationValidationError> {
    std::fs::create_dir_all(bundle_dir).map_err(|e| {
        TranslationValidationError::StorageFailed(format!(
            "creating witness dir {}: {}",
            bundle_dir.to_string_lossy(),
            e
        ))
    })?;

    let artifact = TranslationValidationWitnessArtifact::from_proof(validator_id, proof);
    let file_stem = sanitize_witness_file_stem(validator_id);
    let path = bundle_dir.join(format!("{file_stem}.proof.json"));
    let json = serde_json::to_vec_pretty(&artifact).map_err(|e| {
        TranslationValidationError::StorageFailed(format!("serialising witness: {}", e))
    })?;
    std::fs::write(&path, json).map_err(|e| {
        TranslationValidationError::StorageFailed(format!(
            "writing witness {}: {}",
            path.to_string_lossy(),
            e
        ))
    })?;

    Ok(EmittedTranslationValidationWitness {
        path,
        content_hash: artifact.content_hash,
        verdict: artifact.verdict,
    })
}

fn derive_counterexample_hash(
    proof: &TranslationValidationProof,
    failure_reasons: &[String],
) -> String {
    let mut preimage = Vec::new();
    append_str(&mut preimage, proof.source_spec.slot_id.as_str());
    append_str(&mut preimage, proof.target_spec.slot_id.as_str());
    append_str(&mut preimage, &proof.source_spec.code_digest);
    append_str(&mut preimage, &proof.target_spec.code_digest);
    append_str(&mut preimage, &proof.test_case_digest);
    append_str_vec(&mut preimage, failure_reasons);
    sha256_hex(&preimage)
}

fn sanitize_witness_file_stem(validator_id: &str) -> String {
    let stem: String = validator_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if stem.is_empty() {
        "translation-validator".to_string()
    } else {
        stem
    }
}

fn append_len_prefixed(preimage: &mut Vec<u8>, bytes: &[u8]) {
    preimage.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    preimage.extend_from_slice(bytes);
}

fn append_str(preimage: &mut Vec<u8>, value: &str) {
    append_len_prefixed(preimage, value.as_bytes());
}

fn append_optional_str(preimage: &mut Vec<u8>, value: Option<&str>) {
    preimage.push(u8::from(value.is_some()));
    if let Some(value) = value {
        append_str(preimage, value);
    }
}

fn append_str_vec(preimage: &mut Vec<u8>, values: &[String]) {
    preimage.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        append_str(preimage, value);
    }
}

fn append_counterexample(
    preimage: &mut Vec<u8>,
    counterexample: Option<&TranslationValidationCounterexample>,
) {
    preimage.push(u8::from(counterexample.is_some()));
    if let Some(counterexample) = counterexample {
        append_str(preimage, &counterexample.counterexample_hash);
        append_str_vec(preimage, &counterexample.failure_reasons);
        preimage.extend_from_slice(&counterexample.test_cases_passed.to_be_bytes());
        preimage.extend_from_slice(&counterexample.test_cases_total.to_be_bytes());
        preimage.extend_from_slice(&counterexample.success_rate_percent.to_be_bytes());
    }
}

fn append_validation_result(preimage: &mut Vec<u8>, result: &ValidationResult) {
    match result {
        ValidationResult::Success {
            test_cases_passed,
            test_cases_total,
            success_rate_percent,
        } => {
            append_str(preimage, "success");
            preimage.extend_from_slice(&test_cases_passed.to_be_bytes());
            preimage.extend_from_slice(&test_cases_total.to_be_bytes());
            preimage.extend_from_slice(&success_rate_percent.to_be_bytes());
        }
        ValidationResult::Failed {
            test_cases_passed,
            test_cases_total,
            success_rate_percent,
            failure_reasons,
        } => {
            append_str(preimage, "failed");
            preimage.extend_from_slice(&test_cases_passed.to_be_bytes());
            preimage.extend_from_slice(&test_cases_total.to_be_bytes());
            preimage.extend_from_slice(&success_rate_percent.to_be_bytes());
            append_str_vec(preimage, failure_reasons);
        }
        ValidationResult::Error {
            error_message,
            error_code,
        } => {
            append_str(preimage, "error");
            append_str(preimage, error_code.as_str());
            append_str(preimage, error_message);
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Translation Validation Engine
// ---------------------------------------------------------------------------

/// How [`TranslationValidationEngine`] obtains a validation verdict.
///
/// The default is [`ValidationExecutionMode::FailClosed`]: without a genuine
/// per-slot validation pipeline the engine refuses to fabricate a passing
/// result, so a promotion cannot be backed by an unproven proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationExecutionMode {
    /// Do not run any validation. Emit a fail-closed UNPROVEN result.
    ///
    /// This is the safe default for constitutional self-replacement promotions
    /// while a real per-slot semantic-equivalence engine is not yet wired.
    FailClosed,
    /// Genuinely execute the G.4 pilot script and bind its real, parsed verdict.
    ///
    /// The script's actual `passed/failed/total` counts and exit status drive
    /// the result; an unparseable verdict or non-zero exit fails closed to
    /// [`ValidationResult::Error`]. See the module docs for the per-slot
    /// scoping caveat (FE-CLAIM-017/018).
    ExecutePilotScript,
}

/// Translation validation engine that integrates with G.4 pilot.
#[derive(Debug, Clone)]
pub struct TranslationValidationEngine {
    /// Path to the project root directory.
    pub project_root: PathBuf,
    /// Path to the validation script.
    pub validation_script: PathBuf,
    /// Whether Lean 4 formal verification is enabled.
    pub enable_formal_verification: bool,
    /// Minimum success rate required for validation to pass.
    pub minimum_success_rate: u32,
    /// Zone for object ID generation.
    pub zone: String,
    /// How a validation verdict is obtained (default: fail-closed).
    pub execution_mode: ValidationExecutionMode,
}

impl Default for TranslationValidationEngine {
    fn default() -> Self {
        Self {
            project_root: PathBuf::from("/data/projects/franken_engine"),
            validation_script: PathBuf::from(
                "/data/projects/franken_engine/scripts/run_rgc_translation_validation_pilot.sh",
            ),
            enable_formal_verification: false,
            minimum_success_rate: 95,
            zone: "default".to_string(),
            execution_mode: ValidationExecutionMode::FailClosed,
        }
    }
}

impl TranslationValidationEngine {
    /// Create a new validation engine with custom settings.
    ///
    /// Defaults to [`ValidationExecutionMode::FailClosed`]; opt into genuine
    /// script execution with [`TranslationValidationEngine::with_execution_mode`].
    pub fn new(project_root: impl Into<PathBuf>, zone: String) -> Self {
        let root = project_root.into();
        let script = root.join("scripts/run_rgc_translation_validation_pilot.sh");

        Self {
            project_root: root,
            validation_script: script,
            enable_formal_verification: false,
            minimum_success_rate: 95,
            zone,
            execution_mode: ValidationExecutionMode::FailClosed,
        }
    }

    /// Set the validation execution mode, consuming and returning `self`.
    pub fn with_execution_mode(mut self, mode: ValidationExecutionMode) -> Self {
        self.execution_mode = mode;
        self
    }

    /// Run translation validation for a slot promotion.
    pub fn validate_slot_promotion(
        &self,
        source_spec: &SlotSpecification,
        target_spec: &SlotSpecification,
    ) -> Result<TranslationValidationProof, TranslationValidationError> {
        // Generate validation timestamp
        let validation_timestamp_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| TranslationValidationError::InternalError(format!("Time error: {}", e)))?
            .as_nanos() as u64;

        // Derive proof ID
        let proof_id = TranslationValidationProof::derive_proof_id(
            &source_spec.code_digest,
            &target_spec.code_digest,
            validation_timestamp_ns,
            &self.zone,
        )
        .map_err(|e| {
            TranslationValidationError::InternalError(format!("ID derivation failed: {}", e))
        })?;

        // Obtain a validation verdict. Fail-closed by default; never fabricated.
        let (validation_result, validation_logs) =
            self.run_validation_script(source_spec, target_spec)?;

        // Test-case digest is a genuine content digest over the source/target
        // specs being compared — not a placeholder string.
        let test_case_digest = {
            use sha2::{Digest, Sha256};
            // Length-prefix the two digests instead of `|`-joining so distinct
            // (source, target) pairs cannot collide to the same test-case digest.
            let mut hasher = Sha256::new();
            hasher.update((source_spec.code_digest.len() as u64).to_be_bytes());
            hasher.update(source_spec.code_digest.as_bytes());
            hasher.update((target_spec.code_digest.len() as u64).to_be_bytes());
            hasher.update(target_spec.code_digest.as_bytes());
            format!("{:x}", hasher.finalize())
        };

        // Create proof artifact. No semantic-equivalence witness is produced by
        // either execution mode today, so the witness is empty rather than a
        // fabricated byte string.
        let proof = TranslationValidationProof {
            proof_id,
            source_spec: source_spec.clone(),
            target_spec: target_spec.clone(),
            validation_result,
            validation_logs,
            formal_proof_ref: None,
            transformation_witness: Vec::new(),
            test_case_digest,
            validation_timestamp_ns,
            security_epoch: SecurityEpoch::from_raw(1),
            zone: self.zone.clone(),
        };

        Ok(proof)
    }

    /// Obtain a validation verdict for a slot promotion.
    ///
    /// The slot specifications are accepted for future per-slot specialisation;
    /// the current pilot script does not yet consume them (see module docs).
    /// Behaviour is governed by [`TranslationValidationEngine::execution_mode`]:
    /// `FailClosed` returns an UNPROVEN [`ValidationResult::Error`], while
    /// `ExecutePilotScript` runs the real script and parses its genuine verdict.
    fn run_validation_script(
        &self,
        _source_spec: &SlotSpecification,
        _target_spec: &SlotSpecification,
    ) -> Result<(ValidationResult, Vec<String>), TranslationValidationError> {
        // The validation script must exist regardless of mode — its absence is a
        // configuration error, not a validation failure.
        if !self.validation_script.exists() {
            return Err(TranslationValidationError::ScriptNotFound(
                self.validation_script.to_string_lossy().to_string(),
            ));
        }

        match self.execution_mode {
            ValidationExecutionMode::FailClosed => Ok(Self::fail_closed_result()),
            ValidationExecutionMode::ExecutePilotScript => self.execute_pilot_script(),
        }
    }

    /// Fail-closed verdict: refuse to fabricate a passing result.
    fn fail_closed_result() -> (ValidationResult, Vec<String>) {
        let result = ValidationResult::Error {
            error_message:
                "translation validation not performed: no per-slot semantic-equivalence \
                 pipeline is wired. The carrier fails closed (UNPROVEN) instead of \
                 fabricating a result. Construct the engine with \
                 ValidationExecutionMode::ExecutePilotScript to bind the G.4 pilot \
                 script's genuine verdict."
                    .to_string(),
            error_code: ValidationErrorCode::InternalError,
        };
        let logs = vec![
            "translation validation carrier: fail-closed mode (default)".to_string(),
            "no genuine per-slot validation engine wired; refusing to fabricate a passing result"
                .to_string(),
        ];
        (result, logs)
    }

    /// Genuinely execute the G.4 pilot script and parse its real verdict.
    fn execute_pilot_script(
        &self,
    ) -> Result<(ValidationResult, Vec<String>), TranslationValidationError> {
        let output = Command::new("bash")
            .arg(&self.validation_script)
            .current_dir(&self.project_root)
            .output()
            .map_err(|e| {
                TranslationValidationError::ScriptExecutionFailed(format!(
                    "failed to spawn {}: {}",
                    self.validation_script.to_string_lossy(),
                    e
                ))
            })?;

        let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
        combined.push_str(&String::from_utf8_lossy(&output.stderr));

        Ok(parse_pilot_output(
            &combined,
            output.status.success(),
            self.minimum_success_rate,
        ))
    }

    /// Directory holding persisted proofs for a given zone.
    fn proof_store_dir(&self, zone: &str) -> PathBuf {
        self.project_root
            .join("target")
            .join("translation_validation_proofs")
            .join(zone)
    }

    /// Persist a translation validation proof and return its content-addressed
    /// reference.
    ///
    /// The proof is canonically serialised to
    /// `target/translation_validation_proofs/<zone>/<proof_id>.json`, so the
    /// returned `proof://<zone>/<proof_id>` reference is genuinely retrievable
    /// via [`TranslationValidationEngine::retrieve_proof`].
    pub fn store_proof(
        &self,
        proof: &TranslationValidationProof,
    ) -> Result<String, TranslationValidationError> {
        let dir = self.proof_store_dir(&proof.zone);
        std::fs::create_dir_all(&dir).map_err(|e| {
            TranslationValidationError::StorageFailed(format!(
                "creating proof dir {}: {}",
                dir.to_string_lossy(),
                e
            ))
        })?;

        let json = serde_json::to_vec_pretty(proof).map_err(|e| {
            TranslationValidationError::StorageFailed(format!("serialising proof: {}", e))
        })?;

        let proof_id = proof.proof_id.to_string();
        let path = dir.join(format!("{}.json", proof_id));
        std::fs::write(&path, json).map_err(|e| {
            TranslationValidationError::StorageFailed(format!(
                "writing proof {}: {}",
                path.to_string_lossy(),
                e
            ))
        })?;

        Ok(format!("proof://{}/{}", proof.zone, proof_id))
    }

    /// Retrieve a translation validation proof by its `proof://<zone>/<id>`
    /// reference, reading it back from persistent storage.
    pub fn retrieve_proof(
        &self,
        proof_ref: &str,
    ) -> Result<TranslationValidationProof, TranslationValidationError> {
        let rest = proof_ref.strip_prefix("proof://").ok_or_else(|| {
            TranslationValidationError::ProofNotFound(format!("malformed reference: {}", proof_ref))
        })?;
        let (zone, proof_id) = rest.split_once('/').ok_or_else(|| {
            TranslationValidationError::ProofNotFound(format!("malformed reference: {}", proof_ref))
        })?;

        let path = self
            .proof_store_dir(zone)
            .join(format!("{}.json", proof_id));
        let bytes = std::fs::read(&path)
            .map_err(|_| TranslationValidationError::ProofNotFound(proof_ref.to_string()))?;

        serde_json::from_slice(&bytes).map_err(|e| {
            TranslationValidationError::OutputParsingFailed(format!(
                "deserialising proof {}: {}",
                proof_ref, e
            ))
        })
    }
}

/// Parse the genuine verdict emitted by the G.4 pilot script.
///
/// Looks for the script's `Results: <P> passed, <F> failed out of <T>` line and
/// derives a [`ValidationResult`] from the *real* counts plus the script's exit
/// status. An unparseable verdict or a non-zero exit produces
/// [`ValidationResult::Error`] — this function never fabricates a success.
fn parse_pilot_output(
    output: &str,
    script_succeeded: bool,
    minimum_success_rate: u32,
) -> (ValidationResult, Vec<String>) {
    // Capture the script's own output as the proof's logs (bounded to the tail
    // so a verbose run cannot bloat the stored proof).
    let mut logs: Vec<String> = output
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    const MAX_LOG_LINES: usize = 64;
    if logs.len() > MAX_LOG_LINES {
        logs = logs.split_off(logs.len() - MAX_LOG_LINES);
    }

    let parsed = output.lines().find_map(parse_results_line);
    let result = match parsed {
        Some((passed, _failed, total)) if total > 0 => {
            let success_rate = passed.saturating_mul(100) / total;
            if script_succeeded && success_rate >= minimum_success_rate {
                ValidationResult::Success {
                    test_cases_passed: passed,
                    test_cases_total: total,
                    success_rate_percent: success_rate,
                }
            } else {
                let mut failure_reasons = Vec::new();
                if !script_succeeded {
                    failure_reasons.push(
                        "validation script exited non-zero; verdict treated as failed".to_string(),
                    );
                }
                if success_rate < minimum_success_rate {
                    failure_reasons.push(format!(
                        "success rate {}% below minimum {}%",
                        success_rate, minimum_success_rate
                    ));
                }
                ValidationResult::Failed {
                    test_cases_passed: passed,
                    test_cases_total: total,
                    success_rate_percent: success_rate,
                    failure_reasons,
                }
            }
        }
        _ => ValidationResult::Error {
            error_message:
                "could not parse a 'Results: <P> passed, <F> failed out of <T>' verdict from \
                 the validation script output; failing closed"
                    .to_string(),
            error_code: ValidationErrorCode::InternalError,
        },
    };

    (result, logs)
}

/// Extract `(passed, failed, total)` from a script log line of the form
/// `... Results: <P> passed, <F> failed out of <T>`.
fn parse_results_line(line: &str) -> Option<(u32, u32, u32)> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let mut passed: Option<u32> = None;
    let mut failed: Option<u32> = None;
    let mut total: Option<u32> = None;

    for (i, tok) in tokens.iter().enumerate() {
        if tok.starts_with("passed") && i > 0 {
            passed = digits(tokens[i - 1]);
        } else if *tok == "failed" && i > 0 {
            failed = digits(tokens[i - 1]);
        } else if *tok == "of" && i + 1 < tokens.len() {
            total = digits(tokens[i + 1]);
        }
    }

    match (passed, failed, total) {
        (Some(p), Some(f), Some(t)) => Some((p, f, t)),
        _ => None,
    }
}

/// Parse a `u32` from a token after stripping non-digit characters (handles
/// trailing punctuation like `passed,`).
fn digits(token: &str) -> Option<u32> {
    let trimmed: String = token.chars().filter(|c| c.is_ascii_digit()).collect();
    if trimmed.is_empty() {
        None
    } else {
        trimmed.parse().ok()
    }
}

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors that can occur during translation validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TranslationValidationError {
    /// Validation script not found at expected path.
    ScriptNotFound(String),
    /// Script execution failed.
    ScriptExecutionFailed(String),
    /// Script output parsing failed.
    OutputParsingFailed(String),
    /// Proof storage failed.
    StorageFailed(String),
    /// Proof not found during retrieval.
    ProofNotFound(String),
    /// Validation did not produce a passing proof (fail-closed): the promotion
    /// must not be backed by this unproven validation.
    ValidationNotProven(String),
    /// Internal engine error.
    InternalError(String),
}

impl std::fmt::Display for TranslationValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScriptNotFound(path) => write!(f, "Validation script not found: {}", path),
            Self::ScriptExecutionFailed(err) => write!(f, "Script execution failed: {}", err),
            Self::OutputParsingFailed(err) => write!(f, "Output parsing failed: {}", err),
            Self::StorageFailed(err) => write!(f, "Proof storage failed: {}", err),
            Self::ProofNotFound(ref_str) => write!(f, "Proof not found: {}", ref_str),
            Self::ValidationNotProven(summary) => {
                write!(f, "Validation not proven (fail-closed): {}", summary)
            }
            Self::InternalError(err) => write!(f, "Internal error: {}", err),
        }
    }
}

impl std::error::Error for TranslationValidationError {}

// ---------------------------------------------------------------------------
// Integration Functions
// ---------------------------------------------------------------------------

/// Create a slot specification from slot metadata.
pub fn create_slot_specification(
    slot_id: SlotId,
    code_content: &[u8],
    language: &str,
) -> SlotSpecification {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(code_content);
    let code_digest = format!("{:x}", hasher.finalize());

    SlotSpecification {
        slot_id,
        code_digest,
        language: language.to_string(),
        ir_stages: vec![
            "IR0_SyntaxIR".to_string(),
            "IR1_SpecIR".to_string(),
            "IR2_CapabilityIR".to_string(),
            "IR3_ExecIR".to_string(),
        ],
        capability_requirements: vec![
            "memory.read".to_string(),
            "memory.write".to_string(),
            "compute.arithmetic".to_string(),
        ],
    }
}

/// Run translation validation for a slot promotion and return the proof
/// reference.
///
/// **Fail-closed:** if the validation does not produce a passing proof (the
/// default state until a real per-slot validation engine is wired), this
/// returns [`TranslationValidationError::ValidationNotProven`] rather than a
/// reference. This prevents an unproven validation from being folded into a
/// constitutional self-replacement receipt.
pub fn validate_promotion_and_get_proof_ref(
    old_slot_id: SlotId,
    new_slot_id: SlotId,
    old_code: &[u8],
    new_code: &[u8],
    zone: &str,
) -> Result<String, TranslationValidationError> {
    let engine =
        TranslationValidationEngine::new("/data/projects/franken_engine", zone.to_string());

    let source_spec = create_slot_specification(old_slot_id, old_code, "javascript");
    let target_spec = create_slot_specification(new_slot_id, new_code, "javascript");

    let proof = engine.validate_slot_promotion(&source_spec, &target_spec)?;
    if !proof.is_valid() {
        return Err(TranslationValidationError::ValidationNotProven(
            proof.summary(),
        ));
    }
    let proof_ref = engine.store_proof(&proof)?;

    Ok(proof_ref)
}

// ---------------------------------------------------------------------------
// FE-CLAIM-017 proof-bundle emission (bd-cixqu.7.17.4)
// ---------------------------------------------------------------------------

/// Emit an FE-CLAIM-017 proof bundle from a successful translation-validation
/// proof.
///
/// FE-CLAIM-017 is the proof-carrying compilation / translation validation
/// claim (Track-G, G.6). The umbrella promotion gate
/// `scripts/run_fe_claim_016_021_promotion_gate.sh` accepts the claim only when
/// `<bundle_dir>/FE-CLAIM-017.proof.json` exists, has `verdict="proven"`, a
/// matching `content_hash` (sha256 of the canonical-JSON body), a non-fixture
/// `source_module`, no simulation-fragment substrings, and a recent
/// `generated_utc`.
///
/// This helper builds a [`ProofBundleBody`] from the supplied differential
/// translation-validation proof (the existing infrastructure under
/// [`TranslationValidationEngine`]/[`TranslationValidationProof`]) and writes
/// the bundle via [`crate::policy_theorem_engine::write_proof_bundle`] so the
/// on-disk encoding stays byte-identical to the theorem-engine emissions for
/// FE-CLAIM-018/021.
///
/// Returns [`TranslationValidationError::ValidationNotProven`] when `proof`
/// does not represent a successful validation — the gate would reject the
/// emitted bundle anyway, so refuse fail-closed at the source.
pub fn emit_fe_claim_017_proof_bundle(
    proof: &TranslationValidationProof,
    bundle_dir: &std::path::Path,
) -> Result<crate::policy_theorem_engine::EmittedProofBundle, TranslationValidationError> {
    if !proof.is_valid() {
        return Err(TranslationValidationError::ValidationNotProven(
            "translation validation result is not Success — refusing to emit \
             FE-CLAIM-017 proof bundle: "
                .to_string()
                + &proof.summary(),
        ));
    }

    // Per-translation theorem id: the content-addressed proof id binds the
    // (source_spec, target_spec, validation_timestamp_ns, zone) tuple, so each
    // distinct validation produces a distinct theorem id and the bundle
    // reflects which differential run backs the claim.
    let theorem_id = format!("translation-validation-{}", proof.proof_id.to_hex());

    let body = crate::policy_theorem_engine::ProofBundleBody {
        schema_version: "franken-engine.theorem-backed-compiler.proof.v1".to_string(),
        claim_id: "FE-CLAIM-017".to_string(),
        track: "track-g".to_string(),
        // The gate's reality-check rejects bodies whose lowercased text
        // contains "simulate", "simulated", "placeholder", "mockcertificate",
        // "hot_paths_simulation", or "selftest-fixture". Pick a kind label
        // that describes the differential-oracle pipeline without tripping
        // any of those substrings.
        proof_kind: "translation-validation-differential".to_string(),
        verdict: "proven".to_string(),
        generated_utc: current_utc_iso8601(),
        // The gate rejects empty / "selftest-fixture" / "fixture" /
        // "placeholder" source markers. The live module path satisfies the
        // non-fixture rule and points to the carrier the bundle came from.
        source_module: "frankenengine_engine::translation_validation_proof_carrier".to_string(),
        producer_tool: "translation-validation-proof-carrier".to_string(),
        producer_version: TRANSLATION_VALIDATION_WITNESS_SCHEMA_VERSION.to_string(),
        timeout_policy: "not-applicable".to_string(),
        timeout_seconds: 0,
        theorem_count: 1,
        theorem_ids: vec![theorem_id],
    };

    crate::policy_theorem_engine::write_proof_bundle(&body, bundle_dir).map_err(|e| {
        TranslationValidationError::StorageFailed(format!("FE-CLAIM-017 bundle write failed: {e}"))
    })
}

/// Compact ISO-8601 UTC timestamp (`YYYY-MM-DDThh:mm:ssZ`) of `now`. Matches
/// the format the gate parses via `datetime.strptime("%Y-%m-%dT%H:%M:%SZ")`.
fn current_utc_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let sod = (secs % 86_400) as u32;
    let hh = sod / 3_600;
    let mm = (sod % 3_600) / 60;
    let ss = sod % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Howard Hinnant's days-from-1970-01-01 → (year, month, day). Same routine
/// the theorem-engine module uses, kept local to avoid widening that module's
/// public surface for a one-call utility.
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 {
        z / 146_097
    } else {
        (z - 146_096) / 146_097
    };
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = (y + if month <= 2 { 1 } else { 0 }) as i32;
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_result_success() {
        let result = ValidationResult::Success {
            test_cases_passed: 1000,
            test_cases_total: 1000,
            success_rate_percent: 100,
        };

        assert!(result.is_success());
        assert_eq!(result.success_rate_percent(), 100);
        assert_eq!(result.total_test_cases(), 1000);
    }

    #[test]
    fn test_validation_result_failed() {
        let result = ValidationResult::Failed {
            test_cases_passed: 950,
            test_cases_total: 1000,
            success_rate_percent: 95,
            failure_reasons: vec!["Semantic mismatch in arithmetic".to_string()],
        };

        assert!(!result.is_success());
        assert_eq!(result.success_rate_percent(), 95);
        assert_eq!(result.total_test_cases(), 1000);
    }

    #[test]
    fn test_validation_result_error() {
        let result = ValidationResult::Error {
            error_message: "Script not found".to_string(),
            error_code: ValidationErrorCode::InternalError,
        };

        assert!(!result.is_success());
        assert_eq!(result.success_rate_percent(), 0);
        assert_eq!(result.total_test_cases(), 0);
    }

    #[test]
    fn test_slot_specification_creation() {
        let slot_id = SlotId::new("test-slot").expect("valid slot ID");
        let code = b"function test() { return 42; }";

        let spec = create_slot_specification(slot_id.clone(), code, "javascript");

        assert_eq!(spec.slot_id, slot_id);
        assert_eq!(spec.language, "javascript");
        assert!(!spec.code_digest.is_empty());
        assert_eq!(spec.ir_stages.len(), 4);
        assert!(
            spec.capability_requirements
                .contains(&"memory.read".to_string())
        );
    }

    #[test]
    fn test_translation_validation_proof_derive_id() {
        let source_digest = "abc123";
        let target_digest = "def456";
        let timestamp = 1_234_567_890_000_000_000_u64;
        let zone = "test_zone";

        let proof_id = TranslationValidationProof::derive_proof_id(
            source_digest,
            target_digest,
            timestamp,
            zone,
        )
        .expect("valid proof ID");

        // Verify the proof ID is deterministic
        let proof_id2 = TranslationValidationProof::derive_proof_id(
            source_digest,
            target_digest,
            timestamp,
            zone,
        )
        .expect("valid proof ID");

        assert_eq!(proof_id, proof_id2);
    }

    #[test]
    fn test_derive_proof_id_injective_across_digest_boundary() {
        // ("a|","b") and ("a","|b") share the concatenation of the two digests
        // but are distinct (source, target) pairs; length-prefixing must keep
        // their derived proof ids apart (the `|`-delimiter boundary collision).
        let ts = 1_234_567_890_000_000_000_u64;
        let zone = "test_zone";
        let a = TranslationValidationProof::derive_proof_id("a|", "b", ts, zone)
            .expect("valid proof ID");
        let b = TranslationValidationProof::derive_proof_id("a", "|b", ts, zone)
            .expect("valid proof ID");
        assert_ne!(a, b);
    }

    #[test]
    fn test_default_engine_fails_closed_unproven() {
        // The default engine has no real per-slot validation pipeline, so it must
        // produce an UNPROVEN result rather than fabricating a passing proof.
        let engine = TranslationValidationEngine::default();
        assert_eq!(engine.execution_mode, ValidationExecutionMode::FailClosed);

        let slot_id = SlotId::new("test-slot").expect("valid slot ID");
        let source_spec = create_slot_specification(slot_id.clone(), b"old code", "javascript");
        let target_spec = create_slot_specification(slot_id, b"new code", "javascript");

        let proof = engine
            .validate_slot_promotion(&source_spec, &target_spec)
            .expect("proof artifact is still produced (just unproven)");

        assert!(
            !proof.is_valid(),
            "fail-closed default must not report a valid proof"
        );
        assert!(matches!(
            proof.validation_result,
            ValidationResult::Error { .. }
        ));
        assert!(proof.summary().contains("ERROR"));
        // No fabricated witness/digest placeholders.
        assert!(proof.transformation_witness.is_empty());
        assert_ne!(proof.test_case_digest, "synthetic_test_digest");
    }

    #[test]
    fn test_parse_results_line_extracts_counts() {
        let line = "[20260526_120000] Results: 1223 passed, 24 failed out of 1247";
        assert_eq!(parse_results_line(line), Some((1223, 24, 1247)));
        assert_eq!(parse_results_line("no verdict here"), None);
    }

    #[test]
    fn test_parse_pilot_output_success_from_real_counts() {
        let output = "INFO: starting\n[ts] Results: 980 passed, 20 failed out of 1000\nSUCCESS";
        let (result, logs) = parse_pilot_output(output, true, 95);
        match result {
            ValidationResult::Success {
                test_cases_passed,
                test_cases_total,
                success_rate_percent,
            } => {
                assert_eq!(test_cases_passed, 980);
                assert_eq!(test_cases_total, 1000);
                assert_eq!(success_rate_percent, 98);
            }
            other => panic!("expected Success, got {:?}", other),
        }
        assert!(logs.iter().any(|l| l.contains("Results:")));
    }

    #[test]
    fn test_parse_pilot_output_below_threshold_fails() {
        let output = "[ts] Results: 50 passed, 50 failed out of 100";
        let (result, _logs) = parse_pilot_output(output, true, 95);
        match result {
            ValidationResult::Failed {
                success_rate_percent,
                ..
            } => assert_eq!(success_rate_percent, 50),
            other => panic!("expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_pilot_output_nonzero_exit_fails_even_if_rate_high() {
        let output = "[ts] Results: 1000 passed, 0 failed out of 1000";
        let (result, _logs) = parse_pilot_output(output, false, 95);
        assert!(
            matches!(result, ValidationResult::Failed { .. }),
            "a non-zero script exit must not yield Success"
        );
    }

    #[test]
    fn test_parse_pilot_output_unparseable_fails_closed() {
        let (result, _logs) = parse_pilot_output("garbage with no verdict", true, 95);
        assert!(matches!(result, ValidationResult::Error { .. }));
    }

    #[test]
    fn test_execute_pilot_script_runs_real_command() {
        // Hermetic: point the engine at a tiny throwaway script that emits a
        // genuine Results line. This exercises the real Command path + parser
        // without touching the repo's pilot script.
        let dir = std::env::temp_dir().join(format!(
            "tvpc_exec_{}",
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let script = dir.join("fake_pilot.sh");
        std::fs::write(
            &script,
            "#!/bin/bash\necho \"Results: 100 passed, 0 failed out of 100\"\nexit 0\n",
        )
        .expect("write script");

        let mut engine = TranslationValidationEngine::new(&dir, "exec_zone".to_string())
            .with_execution_mode(ValidationExecutionMode::ExecutePilotScript);
        engine.validation_script = script;

        let slot_id = SlotId::new("exec-slot").expect("valid slot ID");
        let source_spec = create_slot_specification(slot_id.clone(), b"a", "javascript");
        let target_spec = create_slot_specification(slot_id, b"b", "javascript");

        let proof = engine
            .validate_slot_promotion(&source_spec, &target_spec)
            .expect("validation should run");
        assert!(proof.is_valid(), "100% pass should be a valid proof");
        assert_eq!(proof.validation_result.total_test_cases(), 100);
    }

    #[test]
    fn test_store_and_retrieve_proof_round_trip() {
        // Storage is decoupled from the script-existence check, so we build a
        // proof artifact directly and exercise persist -> read-back.
        let dir = std::env::temp_dir().join(format!(
            "tvpc_store_{}",
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let engine = TranslationValidationEngine::new(&dir, "rt_zone".to_string());

        let slot_id = SlotId::new("rt-slot").expect("valid slot ID");
        let proof = TranslationValidationProof {
            proof_id: EngineObjectId([7u8; 32]),
            source_spec: create_slot_specification(slot_id.clone(), b"old", "javascript"),
            target_spec: create_slot_specification(slot_id, b"new", "javascript"),
            validation_result: ValidationResult::Error {
                error_message: "unproven".to_string(),
                error_code: ValidationErrorCode::InternalError,
            },
            validation_logs: vec!["fail-closed".to_string()],
            formal_proof_ref: None,
            transformation_witness: Vec::new(),
            test_case_digest: "rt_digest".to_string(),
            validation_timestamp_ns: 42,
            security_epoch: SecurityEpoch::from_raw(1),
            zone: "rt_zone".to_string(),
        };

        let proof_ref = engine.store_proof(&proof).expect("store should persist");
        assert!(proof_ref.starts_with("proof://rt_zone/"));

        let retrieved = engine
            .retrieve_proof(&proof_ref)
            .expect("retrieve should read it back");
        assert_eq!(retrieved.proof_id, proof.proof_id);
        assert_eq!(retrieved.test_case_digest, proof.test_case_digest);
        assert_eq!(retrieved.validation_result, proof.validation_result);
    }

    #[test]
    fn test_retrieve_unknown_proof_is_not_found() {
        let engine = TranslationValidationEngine::default();
        let err = engine
            .retrieve_proof("proof://default/deadbeef")
            .expect_err("unknown proof must not be found");
        assert!(matches!(err, TranslationValidationError::ProofNotFound(_)));
    }

    #[test]
    fn test_proof_summary() {
        let success_result = ValidationResult::Success {
            test_cases_passed: 100,
            test_cases_total: 100,
            success_rate_percent: 100,
        };

        let proof = TranslationValidationProof {
            proof_id: EngineObjectId([0u8; 32]),
            source_spec: create_slot_specification(
                SlotId::new("source").expect("valid ID"),
                b"source code",
                "javascript",
            ),
            target_spec: create_slot_specification(
                SlotId::new("target").expect("valid ID"),
                b"target code",
                "javascript",
            ),
            validation_result: success_result,
            validation_logs: vec![],
            formal_proof_ref: None,
            transformation_witness: vec![],
            test_case_digest: "test".to_string(),
            validation_timestamp_ns: 0,
            security_epoch: SecurityEpoch::from_raw(1),
            zone: "test".to_string(),
        };

        let summary = proof.summary();
        assert!(summary.contains("PASSED"));
        assert!(summary.contains("100/100"));
        assert!(summary.contains("100%"));
    }

    /// Build a `TranslationValidationProof` whose `validation_result` is the
    /// given variant. Shared helper for the FE-CLAIM-017 emission tests.
    fn proof_with_result(result: ValidationResult) -> TranslationValidationProof {
        TranslationValidationProof {
            proof_id: EngineObjectId([0xABu8; 32]),
            source_spec: create_slot_specification(
                SlotId::new("src").expect("valid src slot id"),
                b"source program",
                "javascript",
            ),
            target_spec: create_slot_specification(
                SlotId::new("tgt").expect("valid tgt slot id"),
                b"target program",
                "javascript",
            ),
            validation_result: result,
            validation_logs: vec![],
            formal_proof_ref: None,
            transformation_witness: vec![],
            test_case_digest: "td".to_string(),
            validation_timestamp_ns: 42,
            security_epoch: SecurityEpoch::from_raw(1),
            zone: "fe-claim-017-test".to_string(),
        }
    }

    #[test]
    fn witness_artifact_normalizes_success_to_proven() {
        let proof = proof_with_result(ValidationResult::Success {
            test_cases_passed: 64,
            test_cases_total: 64,
            success_rate_percent: 100,
        });

        let artifact =
            TranslationValidationWitnessArtifact::from_proof("exception-validator", &proof);

        assert_eq!(
            artifact.schema_version,
            TRANSLATION_VALIDATION_WITNESS_SCHEMA_VERSION
        );
        assert_eq!(
            artifact.verdict,
            TranslationValidationWitnessVerdict::Proven
        );
        assert!(artifact.counterexample.is_none());
        assert!(artifact.unavailable_reason.is_none());
        assert!(artifact.verify_content_hash());
    }

    #[test]
    fn witness_artifact_normalizes_failed_to_counterexample() {
        let proof = proof_with_result(ValidationResult::Failed {
            test_cases_passed: 12,
            test_cases_total: 16,
            success_rate_percent: 75,
            failure_reasons: vec![
                "iterator close order diverged".to_string(),
                "hostcall sequence changed".to_string(),
            ],
        });

        let artifact =
            TranslationValidationWitnessArtifact::from_proof("iterator-validator", &proof);

        assert_eq!(
            artifact.verdict,
            TranslationValidationWitnessVerdict::Counterexample
        );
        let counterexample = artifact
            .counterexample
            .as_ref()
            .expect("failed validation should emit counterexample payload");
        assert_eq!(counterexample.test_cases_passed, 12);
        assert_eq!(counterexample.test_cases_total, 16);
        assert_eq!(counterexample.failure_reasons.len(), 2);
        assert_ne!(counterexample.counterexample_hash, proof.test_case_digest);
        assert!(artifact.unavailable_reason.is_none());
        assert!(artifact.verify_content_hash());

        let mut tampered = artifact.clone();
        tampered.validation_summary.push_str(" tampered");
        assert!(
            !tampered.verify_content_hash(),
            "content hash should bind witness fields"
        );
    }

    #[test]
    fn witness_artifact_normalizes_error_to_unavailable() {
        let proof = proof_with_result(ValidationResult::Error {
            error_message: "validator binary missing".to_string(),
            error_code: ValidationErrorCode::InternalError,
        });

        let artifact = TranslationValidationWitnessArtifact::from_proof("full-ir", &proof);

        assert_eq!(
            artifact.verdict,
            TranslationValidationWitnessVerdict::Unavailable
        );
        assert!(artifact.counterexample.is_none());
        assert!(
            artifact
                .unavailable_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("validator binary missing"))
        );
        assert!(artifact.verify_content_hash());
    }

    #[test]
    fn every_validator_class_emits_a_witness_artifact() {
        // The E6.T3 validator inventory (bd-fqlfw.6.3): each differential
        // translation validator emits a machine-readable witness (proof or
        // counterexample), not just pass/fail. The emitter is generic over
        // the validator id; this pins the six-class inventory end-to-end
        // through sanitized proof.json emission and round-trip.
        let validator_ids = [
            "exception-validator",
            "iterator-validator",
            "hostcall-validator",
            "async-generator-validator",
            "ifc-label-validator",
            "full-ir-validator",
        ];
        let tmp = tempfile::tempdir().expect("tempdir");
        for (index, validator_id) in validator_ids.iter().enumerate() {
            let proof = if index.is_multiple_of(2) {
                proof_with_result(ValidationResult::Success {
                    test_cases_passed: 8,
                    test_cases_total: 8,
                    success_rate_percent: 100,
                })
            } else {
                proof_with_result(ValidationResult::Failed {
                    test_cases_passed: 7,
                    test_cases_total: 8,
                    success_rate_percent: 87,
                    failure_reasons: vec![format!("{validator_id} divergence")],
                })
            };

            let emitted =
                emit_translation_validation_witness_artifact(&proof, tmp.path(), validator_id)
                    .unwrap_or_else(|err| panic!("{validator_id} emission failed: {err:?}"));

            let json = std::fs::read_to_string(&emitted.path).expect("read witness");
            let parsed: TranslationValidationWitnessArtifact =
                serde_json::from_str(&json).expect("valid witness json");
            assert_eq!(parsed.validator_id, *validator_id);
            assert!(parsed.verify_content_hash(), "{validator_id} hash binding");
            match parsed.verdict {
                TranslationValidationWitnessVerdict::Proven => {
                    assert!(parsed.counterexample.is_none());
                }
                TranslationValidationWitnessVerdict::Counterexample => {
                    assert!(parsed.counterexample.is_some());
                }
                TranslationValidationWitnessVerdict::Unavailable => {
                    panic!("{validator_id}: unexpected Unavailable verdict")
                }
            }
        }
    }

    #[test]
    fn proven_witness_bridges_to_strict_artifact_and_promotes_fe_claim_017() {
        use crate::proof_spine_claim_gate::{
            ClaimSpineAction, ProofArtifactClass, classify_proof_artifact, decide_claim_state,
        };

        let witness = TranslationValidationWitnessArtifact::from_proof(
            "full-ir-validator",
            &proof_with_result(ValidationResult::Success {
                test_cases_passed: 32,
                test_cases_total: 32,
                success_rate_percent: 100,
            }),
        );
        let artifact = witness.to_proof_producer_artifact();

        assert_eq!(artifact.claim_ids, vec![FE_CLAIM_017_CLAIM_ID]);
        assert_eq!(artifact.theorem_or_validator_id, "full-ir-validator");
        assert_eq!(artifact.tool_identity.tool_name, "translation-validator");
        crate::proof_schema::validate_proof_producer_artifact(&artifact)
            .expect("bridged proven witness must satisfy the strict contract");
        assert_eq!(
            classify_proof_artifact(&artifact),
            ProofArtifactClass::Proven
        );
        let verdict = decide_claim_state(FE_CLAIM_017_CLAIM_ID, false, &[artifact]);
        assert_eq!(verdict.action, ClaimSpineAction::PromoteObserved);
    }

    #[test]
    fn counterexample_witness_bridges_to_failed_artifact_and_demotes() {
        use crate::proof_spine_claim_gate::{
            ClaimSpineAction, ProofArtifactClass, classify_proof_artifact, decide_claim_state,
        };

        let witness = TranslationValidationWitnessArtifact::from_proof(
            "exception-validator",
            &proof_with_result(ValidationResult::Failed {
                test_cases_passed: 30,
                test_cases_total: 32,
                success_rate_percent: 93,
                failure_reasons: vec!["finally ordering diverged".to_string()],
            }),
        );
        let artifact = witness.to_proof_producer_artifact();

        assert!(matches!(
            classify_proof_artifact(&artifact),
            ProofArtifactClass::Counterexample { ref reason }
                if reason.contains("finally ordering diverged")
        ));
        assert!(!artifact.counterexample_artifacts.is_empty());
        let verdict = decide_claim_state(FE_CLAIM_017_CLAIM_ID, true, &[artifact]);
        assert_eq!(verdict.action, ClaimSpineAction::Demote);
    }

    #[test]
    fn unavailable_witness_bridges_to_unavailable_artifact() {
        use crate::proof_spine_claim_gate::{ProofArtifactClass, classify_proof_artifact};

        let witness = TranslationValidationWitnessArtifact::from_proof(
            "ifc-label-validator",
            &proof_with_result(ValidationResult::Error {
                error_message: "validator pipeline not wired".to_string(),
                error_code: ValidationErrorCode::InternalError,
            }),
        );
        let artifact = witness.to_proof_producer_artifact();

        assert!(matches!(
            classify_proof_artifact(&artifact),
            ProofArtifactClass::Unavailable { ref reason }
                if reason.contains("validator pipeline not wired")
        ));
    }

    #[test]
    fn emit_translation_validation_witness_artifact_writes_sanitized_proof_json() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let proof = proof_with_result(ValidationResult::Failed {
            test_cases_passed: 3,
            test_cases_total: 4,
            success_rate_percent: 75,
            failure_reasons: vec!["ifc label lost".to_string()],
        });

        let emitted =
            emit_translation_validation_witness_artifact(&proof, tmp.path(), "ifc/label validator")
                .expect("witness emission should succeed");
        assert_eq!(
            emitted.verdict,
            TranslationValidationWitnessVerdict::Counterexample
        );
        assert_eq!(
            emitted.path.file_name().and_then(|n| n.to_str()),
            Some("ifc_label_validator.proof.json")
        );

        let json = std::fs::read_to_string(&emitted.path).expect("read witness");
        let parsed: TranslationValidationWitnessArtifact =
            serde_json::from_str(&json).expect("valid witness json");
        assert_eq!(parsed.content_hash, emitted.content_hash);
        assert_eq!(parsed.verdict, emitted.verdict);
        assert!(parsed.verify_content_hash());
    }

    /// Successful emission: the file lands at FE-CLAIM-017.proof.json, and the
    /// `content_hash` it embeds round-trips through
    /// [`crate::policy_theorem_engine::canonical_body_hash`] — the same
    /// recompute the gate script performs. The body also satisfies the gate's
    /// non-fixture / no-simulation-fragment rules.
    #[test]
    fn emit_fe_claim_017_proof_bundle_writes_gate_compatible_json() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let proof = proof_with_result(ValidationResult::Success {
            test_cases_passed: 128,
            test_cases_total: 128,
            success_rate_percent: 100,
        });

        let emitted =
            emit_fe_claim_017_proof_bundle(&proof, tmp.path()).expect("emission should succeed");
        assert_eq!(emitted.claim_id, "FE-CLAIM-017");
        assert_eq!(emitted.theorem_count, 1);

        let body = std::fs::read_to_string(&emitted.path).expect("read bundle");
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

        // Gate schema checks the bundle must satisfy.
        assert_eq!(
            parsed["schema_version"],
            "franken-engine.theorem-backed-compiler.proof.v1"
        );
        assert_eq!(parsed["claim_id"], "FE-CLAIM-017");
        assert_eq!(parsed["verdict"], "proven");
        assert_eq!(parsed["track"], "track-g");
        assert_eq!(
            parsed["source_module"],
            "frankenengine_engine::translation_validation_proof_carrier"
        );

        // content_hash must equal canonical_body_hash(body minus content_hash).
        let embedded = parsed["content_hash"]
            .as_str()
            .expect("content_hash is a string");
        let recomputed = crate::policy_theorem_engine::canonical_body_hash(&parsed)
            .expect("canonical_body_hash");
        assert_eq!(
            embedded, recomputed,
            "embedded content_hash must match canonical recompute"
        );

        // The gate rejects bundles whose lowercased body contains any of
        // these substrings; the test traps a regression that would reintroduce
        // a fixture/simulation marker into the emitted text.
        let blob = body.to_lowercase();
        for marker in [
            "simulate",
            "simulated",
            "placeholder",
            "mockcertificate",
            "hot_paths_simulation",
            "selftest-fixture",
        ] {
            assert!(
                !blob.contains(marker),
                "emitted bundle contains forbidden marker {marker:?}"
            );
        }
    }

    /// Fail-closed: an Error result must not produce a proof bundle. The
    /// promotion gate would reject it anyway, so refuse at the source.
    #[test]
    fn emit_fe_claim_017_proof_bundle_refuses_unsuccessful_validation() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let proof = proof_with_result(ValidationResult::Error {
            error_message: "no validator wired".to_string(),
            error_code: ValidationErrorCode::InternalError,
        });

        let err = emit_fe_claim_017_proof_bundle(&proof, tmp.path())
            .expect_err("expected ValidationNotProven");
        assert!(
            matches!(err, TranslationValidationError::ValidationNotProven(_)),
            "expected ValidationNotProven, got {err:?}"
        );
        assert!(
            !tmp.path().join("FE-CLAIM-017.proof.json").exists(),
            "no bundle should be written on a failed validation"
        );
    }

    /// Failed result (semantic divergence) is also not "proven" and must not
    /// emit a bundle.
    #[test]
    fn emit_fe_claim_017_proof_bundle_refuses_failed_validation() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let proof = proof_with_result(ValidationResult::Failed {
            test_cases_passed: 50,
            test_cases_total: 100,
            success_rate_percent: 50,
            failure_reasons: vec!["arithmetic divergence".to_string()],
        });

        let err = emit_fe_claim_017_proof_bundle(&proof, tmp.path())
            .expect_err("expected ValidationNotProven");
        assert!(matches!(
            err,
            TranslationValidationError::ValidationNotProven(_)
        ));
        assert!(!tmp.path().join("FE-CLAIM-017.proof.json").exists());
    }
}
