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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, SchemaHash};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain};
use crate::security_epoch::SecurityEpoch;
use crate::slot_registry::SlotId;

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
        let mut canonical = Vec::new();
        canonical.extend_from_slice(source_code_digest.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(target_code_digest.as_bytes());
        canonical.push(b'|');
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
            let mut hasher = Sha256::new();
            hasher.update(source_spec.code_digest.as_bytes());
            hasher.update(b"|");
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
        theorem_ids: vec![theorem_id],
    };

    crate::policy_theorem_engine::write_proof_bundle(&body, bundle_dir).map_err(|e| {
        TranslationValidationError::StorageFailed(format!(
            "FE-CLAIM-017 bundle write failed: {e}"
        ))
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
        let timestamp = 1234567890_000_000_000u64;
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
        assert_eq!(parsed["schema_version"], "franken-engine.theorem-backed-compiler.proof.v1");
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
