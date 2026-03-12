//! Unified deterministic verifier pipeline for TEE-bound decision receipts.
//!
//! This module verifies three trust layers in a single pass:
//! 1) receipt signature + canonical preimage + signer revocation status
//! 2) transparency-log inclusion/consistency + signed checkpoint
//! 3) attestation-chain evidence + policy evaluation
//!
//! Output is a deterministic, JSON-serializable verdict suitable for evidence
//! ingestion and offline audit workflows.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::attested_execution_cell::{
    AttestationQuote as CellAttestationQuote, PlatformKind, SoftwareTrustRoot, TrustRootBackend,
    VerificationResult,
};
use crate::engine_object_id::EngineObjectId;
use crate::hash_tiers::ContentHash;
use crate::mmr_proof::{MmrProof, verify_consistency, verify_inclusion};
use crate::proof_schema::OptReceipt;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{Signature, VerificationKey, verify_signature};
use crate::tee_attestation_policy::{
    AttestationQuote as PolicyAttestationQuote, DecisionImpact, MeasurementAlgorithm,
    TeeAttestationPolicy, TeePlatform,
};

const COMPONENT: &str = "receipt_verifier_pipeline";
const CHECKPOINT_SIGNATURE_DOMAIN: &[u8] = b"FrankenEngine.ReceiptTransparencyCheckpoint.v1";

pub const EXIT_CODE_SUCCESS: i32 = 0;
pub const EXIT_CODE_SIGNATURE_FAILURE: i32 = 20;
pub const EXIT_CODE_TRANSPARENCY_FAILURE: i32 = 21;
pub const EXIT_CODE_ATTESTATION_FAILURE: i32 = 22;
pub const EXIT_CODE_STALE_DATA: i32 = 23;

/// Stable structured-log envelope for verifier events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Failure class determining verifier exit-code class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationFailureClass {
    Signature,
    Transparency,
    Attestation,
    StaleData,
}

impl fmt::Display for VerificationFailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signature => f.write_str("signature"),
            Self::Transparency => f.write_str("transparency"),
            Self::Attestation => f.write_str("attestation"),
            Self::StaleData => f.write_str("stale_data"),
        }
    }
}

/// One deterministic check performed in a layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerCheck {
    pub check: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub detail: String,
}

/// Per-layer verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerResult {
    pub passed: bool,
    pub error_code: Option<String>,
    pub checks: Vec<LayerCheck>,
}

impl LayerResult {
    fn pass() -> Self {
        Self {
            passed: true,
            error_code: None,
            checks: Vec::new(),
        }
    }

    fn record_pass(&mut self, check: &str, detail: impl Into<String>) {
        self.checks.push(LayerCheck {
            check: check.to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            detail: detail.into(),
        });
    }

    fn record_fail(&mut self, check: &str, error_code: &str, detail: impl Into<String>) {
        if self.error_code.is_none() {
            self.error_code = Some(error_code.to_string());
        }
        self.passed = false;
        self.checks.push(LayerCheck {
            check: check.to_string(),
            outcome: "fail".to_string(),
            error_code: Some(error_code.to_string()),
            detail: detail.into(),
        });
    }
}

/// Final deterministic verifier verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedReceiptVerificationVerdict {
    pub receipt_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub verification_timestamp_ns: u64,
    pub passed: bool,
    pub failure_class: Option<VerificationFailureClass>,
    pub exit_code: i32,
    pub signature: LayerResult,
    pub transparency: LayerResult,
    pub attestation: LayerResult,
    pub warnings: Vec<String>,
    pub logs: Vec<VerifierLogEvent>,
}

/// CLI input surface: deterministic mapping of receipt IDs to verifier inputs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReceiptVerifierCliInput {
    pub receipts: BTreeMap<String, UnifiedReceiptVerificationRequest>,
}

/// Complete verification request for one receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedReceiptVerificationRequest {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub verification_timestamp_ns: u64,
    pub receipt: OptReceipt,
    pub signature: SignatureLayerInput,
    pub transparency: TransparencyLayerInput,
    pub attestation: AttestationLayerInput,
}

/// Signature-layer verification inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureLayerInput {
    pub expected_preimage_hash: ContentHash,
    pub signing_key_bytes: Vec<u8>,
    pub signer_revocation: SignerRevocationCache,
}

/// Offline signer-revocation cache snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerRevocationCache {
    pub signer_key_id: EngineObjectId,
    pub source: String,
    pub is_revoked: bool,
    pub cache_stale: bool,
}

/// Transparency-layer verification inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyLayerInput {
    pub leaf_hash: ContentHash,
    pub leaf_index: u64,
    pub inclusion_proof: MmrProof,
    pub consistency_proofs: Vec<ConsistencyProofInput>,
    pub checkpoint: SignedLogCheckpoint,
    pub operator_keys: Vec<LogOperatorKey>,
    pub cache_stale: bool,
}

/// One consistency proof from an old root to the current checkpoint root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsistencyProofInput {
    pub from_root: ContentHash,
    pub proof: MmrProof,
}

/// Signed transparency-log checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedLogCheckpoint {
    pub checkpoint_seq: u64,
    pub log_length: u64,
    pub root_hash: ContentHash,
    pub timestamp_ns: u64,
    pub operator_key_id: String,
    pub signature: Signature,
}

/// Known transparency-log operator verification key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogOperatorKey {
    pub key_id: String,
    pub verification_key: VerificationKey,
    pub revoked: bool,
}

/// Attestation-layer verification inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationLayerInput {
    pub attestation_quote: CellAttestationQuote,
    pub policy_quote: PolicyAttestationQuote,
    pub policy: TeeAttestationPolicy,
    pub decision_impact: DecisionImpact,
    pub runtime_epoch: SecurityEpoch,
    pub verification_time_ns: u64,
    pub measurement_zone: String,
    pub trust_roots: Vec<SoftwareTrustRoot>,
    pub policy_cache_stale: bool,
    pub revocation_cache_stale: bool,
}

/// Errors from deterministic verifier orchestration surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptVerifierPipelineError {
    ReceiptNotFound { receipt_id: String },
}

impl fmt::Display for ReceiptVerifierPipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReceiptNotFound { receipt_id } => {
                write!(f, "receipt '{receipt_id}' not found in verifier input")
            }
        }
    }
}

impl std::error::Error for ReceiptVerifierPipelineError {}

/// Verify a receipt entry from the CLI input map by ID.
pub fn verify_receipt_by_id(
    input: &ReceiptVerifierCliInput,
    receipt_id: &str,
) -> Result<UnifiedReceiptVerificationVerdict, ReceiptVerifierPipelineError> {
    let request = input.receipts.get(receipt_id).ok_or_else(|| {
        ReceiptVerifierPipelineError::ReceiptNotFound {
            receipt_id: receipt_id.to_string(),
        }
    })?;
    Ok(verify_receipt_request(receipt_id, request))
}

/// Run the unified deterministic verification pipeline for one receipt.
pub fn verify_receipt_request(
    receipt_id: &str,
    request: &UnifiedReceiptVerificationRequest,
) -> UnifiedReceiptVerificationVerdict {
    let signature = verify_signature_layer(&request.receipt, &request.signature);
    let transparency = verify_transparency_layer(&request.transparency);
    let attestation = verify_attestation_layer(&request.receipt, &request.attestation);

    let mut warnings = Vec::new();
    if request.signature.signer_revocation.cache_stale {
        warnings.push("signature_revocation_cache_stale".to_string());
    }
    if request.transparency.cache_stale {
        warnings.push("transparency_cache_stale".to_string());
    }
    if request.attestation.policy_cache_stale {
        warnings.push("attestation_policy_cache_stale".to_string());
    }
    if request.attestation.revocation_cache_stale {
        warnings.push("attestation_revocation_cache_stale".to_string());
    }

    let stale_data = !warnings.is_empty();
    let failure_class = if !signature.passed {
        Some(VerificationFailureClass::Signature)
    } else if !transparency.passed {
        Some(VerificationFailureClass::Transparency)
    } else if !attestation.passed {
        Some(VerificationFailureClass::Attestation)
    } else if stale_data {
        Some(VerificationFailureClass::StaleData)
    } else {
        None
    };

    let exit_code = failure_class_exit_code(failure_class);
    let passed = failure_class.is_none();

    let logs = vec![
        layer_log(
            request,
            "signature_layer_verified",
            &signature,
            signature.error_code.as_deref(),
        ),
        layer_log(
            request,
            "transparency_layer_verified",
            &transparency,
            transparency.error_code.as_deref(),
        ),
        layer_log(
            request,
            "attestation_layer_verified",
            &attestation,
            attestation.error_code.as_deref(),
        ),
        VerifierLogEvent {
            trace_id: request.trace_id.clone(),
            decision_id: request.decision_id.clone(),
            policy_id: request.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: "receipt_verification_complete".to_string(),
            outcome: if passed {
                "pass".to_string()
            } else if failure_class == Some(VerificationFailureClass::StaleData) {
                "warn".to_string()
            } else {
                "fail".to_string()
            },
            error_code: failure_class.map(|class| class.to_string()),
        },
    ];

    UnifiedReceiptVerificationVerdict {
        receipt_id: receipt_id.to_string(),
        trace_id: request.trace_id.clone(),
        decision_id: request.decision_id.clone(),
        policy_id: request.policy_id.clone(),
        verification_timestamp_ns: request.verification_timestamp_ns,
        passed,
        failure_class,
        exit_code,
        signature,
        transparency,
        attestation,
        warnings,
        logs,
    }
}

/// Render a compact deterministic summary line.
pub fn render_verdict_summary(verdict: &UnifiedReceiptVerificationVerdict) -> String {
    let class = verdict
        .failure_class
        .map(|failure| failure.to_string())
        .unwrap_or_else(|| "none".to_string());
    format!(
        "receipt={} passed={} exit_code={} failure_class={} warnings={}",
        verdict.receipt_id,
        verdict.passed,
        verdict.exit_code,
        class,
        verdict.warnings.len()
    )
}

fn layer_log(
    request: &UnifiedReceiptVerificationRequest,
    event: &str,
    layer: &LayerResult,
    error_code: Option<&str>,
) -> VerifierLogEvent {
    VerifierLogEvent {
        trace_id: request.trace_id.clone(),
        decision_id: request.decision_id.clone(),
        policy_id: request.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: event.to_string(),
        outcome: if layer.passed { "pass" } else { "fail" }.to_string(),
        error_code: error_code.map(std::string::ToString::to_string),
    }
}

fn failure_class_exit_code(class: Option<VerificationFailureClass>) -> i32 {
    match class {
        None => EXIT_CODE_SUCCESS,
        Some(VerificationFailureClass::Signature) => EXIT_CODE_SIGNATURE_FAILURE,
        Some(VerificationFailureClass::Transparency) => EXIT_CODE_TRANSPARENCY_FAILURE,
        Some(VerificationFailureClass::Attestation) => EXIT_CODE_ATTESTATION_FAILURE,
        Some(VerificationFailureClass::StaleData) => EXIT_CODE_STALE_DATA,
    }
}

fn verify_signature_layer(receipt: &OptReceipt, input: &SignatureLayerInput) -> LayerResult {
    let mut result = LayerResult::pass();

    if input.signer_revocation.signer_key_id != receipt.signer_key_id {
        result.record_fail(
            "signer_key_id_matches_receipt",
            "signature_signer_key_mismatch",
            format!(
                "revocation cache signer {} does not match receipt signer {}",
                input.signer_revocation.signer_key_id.to_hex(),
                receipt.signer_key_id.to_hex()
            ),
        );
    } else {
        result.record_pass(
            "signer_key_id_matches_receipt",
            "signer key ID matches receipt",
        );
    }

    let preimage = receipt.signing_preimage();
    let preimage_hash = ContentHash::compute(&preimage);
    if preimage_hash != input.expected_preimage_hash {
        result.record_fail(
            "canonical_preimage_hash_matches",
            "signature_preimage_mismatch",
            format!(
                "expected preimage hash {}, got {}",
                input.expected_preimage_hash.to_hex(),
                preimage_hash.to_hex()
            ),
        );
    } else {
        result.record_pass(
            "canonical_preimage_hash_matches",
            "receipt canonical preimage hash matches expected",
        );
    }

    if receipt.verify_signature(&input.signing_key_bytes) {
        result.record_pass(
            "receipt_signature_valid",
            "receipt signature verification passed",
        );
    } else {
        result.record_fail(
            "receipt_signature_valid",
            "receipt_signature_invalid",
            "receipt signature verification failed",
        );
    }

    if input.signer_revocation.source.trim().is_empty() {
        result.record_fail(
            "revocation_source_present",
            "signature_revocation_source_missing",
            "signer revocation source is empty",
        );
    } else {
        result.record_pass(
            "revocation_source_present",
            format!("revocation source '{}'", input.signer_revocation.source),
        );
    }

    if input.signer_revocation.is_revoked {
        result.record_fail(
            "signer_not_revoked",
            "signature_signer_revoked",
            format!(
                "signer {} is revoked by source {}",
                input.signer_revocation.signer_key_id.to_hex(),
                input.signer_revocation.source
            ),
        );
    } else {
        result.record_pass("signer_not_revoked", "signer revocation check passed");
    }

    result
}

fn verify_transparency_layer(input: &TransparencyLayerInput) -> LayerResult {
    let mut result = LayerResult::pass();

    let operator_key = input
        .operator_keys
        .iter()
        .find(|key| key.key_id == input.checkpoint.operator_key_id);

    let Some(operator_key) = operator_key else {
        result.record_fail(
            "checkpoint_operator_key_found",
            "transparency_operator_key_missing",
            format!(
                "no operator key found for checkpoint key_id '{}'",
                input.checkpoint.operator_key_id
            ),
        );
        return result;
    };
    result.record_pass(
        "checkpoint_operator_key_found",
        format!("found operator key '{}'", operator_key.key_id),
    );

    if operator_key.revoked {
        result.record_fail(
            "checkpoint_operator_key_not_revoked",
            "transparency_operator_key_revoked",
            format!("operator key '{}' is revoked", operator_key.key_id),
        );
    } else {
        result.record_pass(
            "checkpoint_operator_key_not_revoked",
            format!("operator key '{}' is active", operator_key.key_id),
        );
    }

    let checkpoint_preimage = checkpoint_preimage(&input.checkpoint);
    match verify_signature(
        &operator_key.verification_key,
        &checkpoint_preimage,
        &input.checkpoint.signature,
    ) {
        Ok(()) => result.record_pass(
            "checkpoint_signature_valid",
            "checkpoint signature verification passed",
        ),
        Err(err) => result.record_fail(
            "checkpoint_signature_valid",
            "transparency_checkpoint_signature_invalid",
            format!("checkpoint signature invalid: {err}"),
        ),
    }

    match verify_inclusion(&input.leaf_hash, input.leaf_index, &input.inclusion_proof) {
        Ok(()) => result.record_pass("inclusion_proof_valid", "inclusion proof verified"),
        Err(err) => result.record_fail(
            "inclusion_proof_valid",
            "transparency_inclusion_failed",
            format!("inclusion proof verification failed: {err}"),
        ),
    }

    if input.inclusion_proof.root_hash != input.checkpoint.root_hash {
        result.record_fail(
            "inclusion_root_matches_checkpoint_root",
            "transparency_root_mismatch",
            format!(
                "inclusion root {} != checkpoint root {}",
                input.inclusion_proof.root_hash.to_hex(),
                input.checkpoint.root_hash.to_hex()
            ),
        );
    } else {
        result.record_pass(
            "inclusion_root_matches_checkpoint_root",
            "inclusion root matches checkpoint root",
        );
    }

    if input.inclusion_proof.stream_length != input.checkpoint.log_length {
        result.record_fail(
            "checkpoint_log_length_matches_inclusion_stream_length",
            "transparency_log_length_mismatch",
            format!(
                "checkpoint log_length {} != inclusion stream_length {}",
                input.checkpoint.log_length, input.inclusion_proof.stream_length
            ),
        );
    } else {
        result.record_pass(
            "checkpoint_log_length_matches_inclusion_stream_length",
            "checkpoint log length matches inclusion stream length",
        );
    }

    for (idx, link) in input.consistency_proofs.iter().enumerate() {
        let check_name = format!("consistency_proof_{idx}_valid");
        match verify_consistency(&link.from_root, &link.proof) {
            Ok(()) => result.record_pass(&check_name, format!("consistency proof {idx} verified")),
            Err(err) => result.record_fail(
                &check_name,
                "transparency_consistency_failed",
                format!("consistency proof {idx} failed: {err}"),
            ),
        }

        let root_match_name = format!("consistency_proof_{idx}_root_matches_checkpoint");
        if link.proof.root_hash != input.checkpoint.root_hash {
            result.record_fail(
                &root_match_name,
                "transparency_consistency_root_mismatch",
                format!(
                    "consistency proof {idx} root {} != checkpoint root {}",
                    link.proof.root_hash.to_hex(),
                    input.checkpoint.root_hash.to_hex()
                ),
            );
        } else {
            result.record_pass(
                &root_match_name,
                format!("consistency proof {idx} root matches checkpoint"),
            );
        }
    }

    result
}

fn verify_attestation_layer(receipt: &OptReceipt, input: &AttestationLayerInput) -> LayerResult {
    let mut result = LayerResult::pass();

    let Some(bindings) = receipt.attestation_bindings.as_ref() else {
        result.record_fail(
            "receipt_has_attestation_bindings",
            "attestation_bindings_missing",
            "receipt has no attestation bindings",
        );
        return result;
    };
    result.record_pass(
        "receipt_has_attestation_bindings",
        "receipt includes attestation bindings",
    );

    if bindings.attested_signer_key_id != receipt.signer_key_id {
        result.record_fail(
            "attested_signer_matches_receipt_signer",
            "attestation_signer_mismatch",
            format!(
                "attested signer {} != receipt signer {}",
                bindings.attested_signer_key_id.to_hex(),
                receipt.signer_key_id.to_hex()
            ),
        );
    } else {
        result.record_pass(
            "attested_signer_matches_receipt_signer",
            "attested signer key matches receipt signer key",
        );
    }

    match attestation_quote_digest(&input.attestation_quote) {
        Ok(quote_digest) => {
            if quote_digest != bindings.quote_digest {
                result.record_fail(
                    "quote_digest_matches_binding",
                    "attestation_quote_digest_mismatch",
                    format!(
                        "receipt quote_digest {} != actual {}",
                        bindings.quote_digest.to_hex(),
                        quote_digest.to_hex()
                    ),
                );
            } else {
                result.record_pass(
                    "quote_digest_matches_binding",
                    "quote digest matches receipt binding",
                );
            }
        }
        Err(error) => result.record_fail(
            "quote_digest_matches_binding",
            "attestation_quote_digest_unavailable",
            error,
        ),
    }

    match input
        .attestation_quote
        .measurement
        .derive_id(&input.measurement_zone)
    {
        Ok(derived_measurement_id) => {
            if derived_measurement_id != bindings.measurement_id {
                result.record_fail(
                    "measurement_id_matches_binding",
                    "attestation_measurement_id_mismatch",
                    format!(
                        "receipt measurement_id {} != derived {}",
                        bindings.measurement_id.to_hex(),
                        derived_measurement_id.to_hex()
                    ),
                );
            } else {
                result.record_pass(
                    "measurement_id_matches_binding",
                    "measurement ID matches attested quote measurement",
                );
            }
        }
        Err(error) => result.record_fail(
            "measurement_id_matches_binding",
            "attestation_measurement_id_derivation_failed",
            format!("failed to derive measurement ID: {error}"),
        ),
    }

    if input.attestation_quote.nonce != bindings.nonce {
        result.record_fail(
            "quote_nonce_matches_binding",
            "attestation_nonce_mismatch",
            "attestation quote nonce does not match receipt nonce binding",
        );
    } else {
        result.record_pass(
            "quote_nonce_matches_binding",
            "attestation quote nonce matches receipt binding",
        );
    }

    let trust_root = input
        .trust_roots
        .iter()
        .find(|root| root.key_id == input.attestation_quote.signer_key_id);
    let Some(trust_root) = trust_root else {
        result.record_fail(
            "quote_trust_root_available",
            "attestation_trust_root_missing",
            format!(
                "no trust root found for signer key '{}'",
                input.attestation_quote.signer_key_id
            ),
        );
        return result;
    };
    result.record_pass(
        "quote_trust_root_available",
        format!("trust root '{}' found", trust_root.key_id),
    );

    let quote_verification = trust_root.verify(
        &input.attestation_quote,
        &input.attestation_quote.measurement,
        &bindings.nonce,
        input.verification_time_ns,
    );
    if quote_verification != VerificationResult::Valid {
        result.record_fail(
            "quote_signature_and_freshness_valid",
            "attestation_quote_verification_failed",
            format!("trust-root quote verification failed: {quote_verification}"),
        );
    } else {
        result.record_pass(
            "quote_signature_and_freshness_valid",
            "trust-root quote verification passed",
        );
    }

    if input.policy_quote.trust_root_id != input.attestation_quote.signer_key_id {
        result.record_fail(
            "policy_quote_trust_root_matches_attested_signer",
            "attestation_policy_trust_root_mismatch",
            format!(
                "policy trust_root_id '{}' != quote signer '{}'",
                input.policy_quote.trust_root_id, input.attestation_quote.signer_key_id
            ),
        );
    } else {
        result.record_pass(
            "policy_quote_trust_root_matches_attested_signer",
            "policy quote trust root matches attested signer key",
        );
    }

    let expected_age_secs = input
        .verification_time_ns
        .saturating_sub(input.attestation_quote.issued_at_ns)
        / 1_000_000_000;
    if input.policy_quote.quote_age_secs != expected_age_secs {
        result.record_fail(
            "policy_quote_age_matches_quote_timestamp",
            "attestation_policy_quote_age_mismatch",
            format!(
                "policy quote_age_secs {} != computed {}",
                input.policy_quote.quote_age_secs, expected_age_secs
            ),
        );
    } else {
        result.record_pass(
            "policy_quote_age_matches_quote_timestamp",
            "policy quote age matches attestation quote timestamp",
        );
    }

    let expected_measurement_digest = input
        .attestation_quote
        .measurement
        .composite_hash()
        .to_hex();
    if input.policy_quote.measurement.algorithm != MeasurementAlgorithm::Sha256
        || input
            .policy_quote
            .measurement
            .digest_hex
            .to_ascii_lowercase()
            != expected_measurement_digest
    {
        result.record_fail(
            "policy_quote_measurement_matches_attested_measurement",
            "attestation_policy_measurement_mismatch",
            format!(
                "policy measurement ({:?}:{}) != expected (sha256:{})",
                input.policy_quote.measurement.algorithm,
                input.policy_quote.measurement.digest_hex,
                expected_measurement_digest
            ),
        );
    } else {
        result.record_pass(
            "policy_quote_measurement_matches_attested_measurement",
            "policy quote measurement matches attested quote measurement digest",
        );
    }

    if let Some(expected_platform) = map_platform(input.attestation_quote.platform) {
        if input.policy_quote.platform != expected_platform {
            result.record_fail(
                "policy_quote_platform_matches_attested_platform",
                "attestation_policy_platform_mismatch",
                format!(
                    "policy platform '{}' != expected '{}'",
                    input.policy_quote.platform, expected_platform
                ),
            );
        } else {
            result.record_pass(
                "policy_quote_platform_matches_attested_platform",
                "policy quote platform matches attested quote platform",
            );
        }
    } else {
        result.record_pass(
            "policy_quote_platform_matches_attested_platform",
            "software attestation platform has no strict tee-platform mapping",
        );
    }

    match input.policy.validate() {
        Ok(()) => result.record_pass("tee_policy_is_valid", "TEE attestation policy is valid"),
        Err(error) => result.record_fail(
            "tee_policy_is_valid",
            error.error_code(),
            format!("TEE policy validation failed: {error}"),
        ),
    }

    match input.policy.evaluate_quote(
        &input.policy_quote,
        input.decision_impact,
        input.runtime_epoch,
    ) {
        Ok(()) => result.record_pass("policy_quote_evaluation_passes", "policy quote accepted"),
        Err(error) => result.record_fail(
            "policy_quote_evaluation_passes",
            error.error_code(),
            format!("policy quote rejected: {error}"),
        ),
    }

    result
}

fn checkpoint_preimage(checkpoint: &SignedLogCheckpoint) -> Vec<u8> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(CHECKPOINT_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(&checkpoint.checkpoint_seq.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(&checkpoint.log_length.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(checkpoint.root_hash.as_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(&checkpoint.timestamp_ns.to_be_bytes());
    preimage.push(0xff);
    preimage.extend_from_slice(checkpoint.operator_key_id.as_bytes());
    preimage
}

fn attestation_quote_digest(quote: &CellAttestationQuote) -> Result<ContentHash, String> {
    let bytes = serde_json::to_vec(quote).map_err(|error| error.to_string())?;
    Ok(ContentHash::compute(&bytes))
}

fn map_platform(platform: PlatformKind) -> Option<TeePlatform> {
    match platform {
        PlatformKind::IntelSgx => Some(TeePlatform::IntelSgx),
        PlatformKind::ArmCca => Some(TeePlatform::ArmCca),
        PlatformKind::AmdSevSnp => Some(TeePlatform::AmdSev),
        PlatformKind::Software => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::attested_execution_cell::TrustLevel;
    use crate::hash_tiers::AuthenticityHash;
    use crate::mmr_proof::MerkleMountainRange;
    use crate::proof_schema::{
        AttestationValidityWindow, OptimizationClass, ReceiptAttestationBindings,
        proof_schema_version_current,
    };
    use crate::signature_preimage::{SigningKey, sign_preimage};
    use crate::tee_attestation_policy::{
        AttestationFreshnessWindow, MeasurementDigest, PlatformTrustRoot, RevocationFallback,
        RevocationProbeStatus, RevocationSource, RevocationSourceType, TrustRootPinning,
        TrustRootSource,
    };

    fn digest_hex(byte: u8, byte_len: usize) -> String {
        let mut out = String::with_capacity(byte_len * 2);
        for _ in 0..byte_len {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn sample_policy(
        policy_epoch: SecurityEpoch,
        intel_digest_hex: String,
        trust_root_id: &str,
    ) -> TeeAttestationPolicy {
        let mut approved_measurements = BTreeMap::new();
        approved_measurements.insert(
            TeePlatform::IntelSgx,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha256,
                digest_hex: intel_digest_hex,
            }],
        );
        approved_measurements.insert(
            TeePlatform::ArmTrustZone,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha256,
                digest_hex: digest_hex(0x22, 32),
            }],
        );
        approved_measurements.insert(
            TeePlatform::ArmCca,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha256,
                digest_hex: digest_hex(0x44, 32),
            }],
        );
        approved_measurements.insert(
            TeePlatform::AmdSev,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha384,
                digest_hex: digest_hex(0x33, 48),
            }],
        );

        TeeAttestationPolicy {
            schema_version: 1,
            policy_epoch,
            approved_measurements,
            freshness_window: AttestationFreshnessWindow {
                standard_max_age_secs: 120,
                high_impact_max_age_secs: 30,
            },
            revocation_sources: vec![
                RevocationSource {
                    source_id: "intel_pcs".to_string(),
                    source_type: RevocationSourceType::IntelPcs,
                    endpoint: "https://intel.example/pcs".to_string(),
                    on_unavailable: RevocationFallback::TryNextSource,
                },
                RevocationSource {
                    source_id: "internal_ledger".to_string(),
                    source_type: RevocationSourceType::InternalLedger,
                    endpoint: "sqlite://revocations".to_string(),
                    on_unavailable: RevocationFallback::FailClosed,
                },
            ],
            platform_trust_roots: vec![
                PlatformTrustRoot {
                    root_id: trust_root_id.to_string(),
                    platform: TeePlatform::IntelSgx,
                    trust_anchor_pem: "-----BEGIN KEY-----intel-----END KEY-----".to_string(),
                    valid_from_epoch: SecurityEpoch::from_raw(1),
                    valid_until_epoch: None,
                    pinning: TrustRootPinning::Pinned,
                    source: TrustRootSource::Policy,
                },
                PlatformTrustRoot {
                    root_id: "arm-root".to_string(),
                    platform: TeePlatform::ArmTrustZone,
                    trust_anchor_pem: "-----BEGIN KEY-----arm-----END KEY-----".to_string(),
                    valid_from_epoch: SecurityEpoch::from_raw(1),
                    valid_until_epoch: None,
                    pinning: TrustRootPinning::Pinned,
                    source: TrustRootSource::Policy,
                },
                PlatformTrustRoot {
                    root_id: "cca-root".to_string(),
                    platform: TeePlatform::ArmCca,
                    trust_anchor_pem: "-----BEGIN KEY-----cca-----END KEY-----".to_string(),
                    valid_from_epoch: SecurityEpoch::from_raw(1),
                    valid_until_epoch: None,
                    pinning: TrustRootPinning::Pinned,
                    source: TrustRootSource::Policy,
                },
                PlatformTrustRoot {
                    root_id: "amd-root".to_string(),
                    platform: TeePlatform::AmdSev,
                    trust_anchor_pem: "-----BEGIN KEY-----amd-----END KEY-----".to_string(),
                    valid_from_epoch: SecurityEpoch::from_raw(1),
                    valid_until_epoch: None,
                    pinning: TrustRootPinning::Pinned,
                    source: TrustRootSource::Policy,
                },
            ],
        }
    }

    fn build_valid_fixture() -> (String, UnifiedReceiptVerificationRequest) {
        let receipt_id = "rcpt-001".to_string();
        let signer_key_id = EngineObjectId([0x44; 32]);
        let signer_key_bytes = vec![0x55; 32];

        let software_root = SoftwareTrustRoot::new("root-1", 7);
        let measurement = software_root.measure(
            b"code-v1",
            b"cfg-v1",
            b"policy-v1",
            b"schema-v1",
            "runtime-v1",
        );
        let nonce = [7u8; 32];
        let mut attestation_quote =
            software_root.attest(&measurement, nonce, 30_000_000_000, 10_000_000_000);
        attestation_quote.trust_level = TrustLevel::SoftwareOnly;

        let measurement_zone = "measurement-zone-test".to_string();
        let measurement_id = measurement
            .derive_id(&measurement_zone)
            .expect("measurement ID");
        let quote_digest = attestation_quote_digest(&attestation_quote).expect("quote digest");

        let mut replay_compatibility = BTreeMap::new();
        replay_compatibility.insert("arch".to_string(), "x86_64".to_string());
        replay_compatibility.insert("engine".to_string(), "franken-v1".to_string());

        let bindings = ReceiptAttestationBindings {
            quote_digest,
            measurement_id,
            attested_signer_key_id: signer_key_id.clone(),
            nonce,
            validity_window: AttestationValidityWindow {
                start_timestamp_ticks: 100,
                end_timestamp_ticks: 2_000,
            },
        };

        let unsigned_receipt = OptReceipt {
            schema_version: proof_schema_version_current(),
            optimization_id: "opt-01".to_string(),
            optimization_class: OptimizationClass::Superinstruction,
            baseline_ir_hash: ContentHash::compute(b"baseline"),
            candidate_ir_hash: ContentHash::compute(b"candidate"),
            translation_witness_hash: ContentHash::compute(b"translation"),
            invariance_digest: ContentHash::compute(b"invariance"),
            rollback_token_id: "rollback-01".to_string(),
            replay_compatibility,
            policy_epoch: SecurityEpoch::from_raw(5),
            timestamp_ticks: 1_000,
            signer_key_id: signer_key_id.clone(),
            correlation_id: "corr-01".to_string(),
            decision_impact: DecisionImpact::HighImpact,
            attestation_bindings: Some(bindings),
            signature: AuthenticityHash::compute_keyed(b"placeholder", b"placeholder"),
        };
        let receipt = unsigned_receipt.sign(&signer_key_bytes);
        let expected_preimage_hash = ContentHash::compute(&receipt.signing_preimage());

        let receipt_leaf_hash = ContentHash::compute(&receipt.signing_preimage());
        let leaf0 = ContentHash::compute(b"leaf0");
        let leaf1 = ContentHash::compute(b"leaf1");

        let mut old_mmr = MerkleMountainRange::new(5);
        old_mmr.append(leaf0);
        old_mmr.append(leaf1);
        let old_root = old_mmr.root_hash().expect("old root");

        let mut mmr = MerkleMountainRange::new(5);
        mmr.append(leaf0);
        mmr.append(leaf1);
        mmr.append(receipt_leaf_hash);
        let inclusion_proof = mmr.inclusion_proof(2).expect("inclusion");
        let consistency_proof = mmr.consistency_proof(2).expect("consistency");
        let current_root = mmr.root_hash().expect("root");

        let operator_signing_key = SigningKey::from_bytes([9u8; 32]);
        let operator_verification_key = operator_signing_key.verification_key();
        let checkpoint = SignedLogCheckpoint {
            checkpoint_seq: 1,
            log_length: inclusion_proof.stream_length,
            root_hash: current_root,
            timestamp_ns: 20_000_000_000,
            operator_key_id: "operator-1".to_string(),
            signature: sign_preimage(
                &operator_signing_key,
                &checkpoint_preimage(&SignedLogCheckpoint {
                    checkpoint_seq: 1,
                    log_length: inclusion_proof.stream_length,
                    root_hash: mmr.root_hash().expect("root"),
                    timestamp_ns: 20_000_000_000,
                    operator_key_id: "operator-1".to_string(),
                    signature: Signature::from_bytes([0u8; 64]),
                }),
            )
            .expect("checkpoint sign"),
        };

        let measurement_digest_hex = measurement.composite_hash().to_hex();
        let policy = sample_policy(SecurityEpoch::from_raw(5), measurement_digest_hex, "root-1");
        let mut revocation_observations = BTreeMap::new();
        revocation_observations.insert("intel_pcs".to_string(), RevocationProbeStatus::Good);
        revocation_observations.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);
        let policy_quote = PolicyAttestationQuote {
            platform: TeePlatform::IntelSgx,
            measurement: MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha256,
                digest_hex: measurement.composite_hash().to_hex(),
            },
            quote_age_secs: 10,
            trust_root_id: "root-1".to_string(),
            revocation_observations,
        };

        let request = UnifiedReceiptVerificationRequest {
            trace_id: "trace-verify-01".to_string(),
            decision_id: "decision-verify-01".to_string(),
            policy_id: "policy-verify-01".to_string(),
            verification_timestamp_ns: 20_000_000_000,
            receipt,
            signature: SignatureLayerInput {
                expected_preimage_hash,
                signing_key_bytes: signer_key_bytes,
                signer_revocation: SignerRevocationCache {
                    signer_key_id,
                    source: "offline-signer-revocations".to_string(),
                    is_revoked: false,
                    cache_stale: false,
                },
            },
            transparency: TransparencyLayerInput {
                leaf_hash: receipt_leaf_hash,
                leaf_index: 2,
                inclusion_proof,
                consistency_proofs: vec![ConsistencyProofInput {
                    from_root: old_root,
                    proof: consistency_proof,
                }],
                checkpoint,
                operator_keys: vec![LogOperatorKey {
                    key_id: "operator-1".to_string(),
                    verification_key: operator_verification_key,
                    revoked: false,
                }],
                cache_stale: false,
            },
            attestation: AttestationLayerInput {
                attestation_quote,
                policy_quote,
                policy,
                decision_impact: DecisionImpact::HighImpact,
                runtime_epoch: SecurityEpoch::from_raw(5),
                verification_time_ns: 20_000_000_000,
                measurement_zone,
                trust_roots: vec![software_root.clone()],
                policy_cache_stale: false,
                revocation_cache_stale: false,
            },
        };

        (receipt_id, request)
    }

    #[test]
    fn unified_pipeline_passes_for_valid_request() {
        let (receipt_id, request) = build_valid_fixture();
        let verdict = verify_receipt_request(&receipt_id, &request);

        assert!(verdict.passed);
        assert_eq!(verdict.failure_class, None);
        assert_eq!(verdict.exit_code, EXIT_CODE_SUCCESS);
        assert!(verdict.signature.passed);
        assert!(verdict.transparency.passed);
        assert!(verdict.attestation.passed);
        assert!(verdict.warnings.is_empty());
        assert_eq!(verdict.logs.len(), 4);
        assert!(
            verdict
                .logs
                .iter()
                .all(|entry| entry.trace_id == request.trace_id
                    && entry.decision_id == request.decision_id
                    && entry.policy_id == request.policy_id
                    && entry.component == COMPONENT)
        );
    }

    #[test]
    fn signature_failure_has_distinct_exit_code() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.signature.signing_key_bytes = vec![1u8; 32];
        let verdict = verify_receipt_request(&receipt_id, &request);

        assert!(!verdict.passed);
        assert_eq!(
            verdict.failure_class,
            Some(VerificationFailureClass::Signature)
        );
        assert_eq!(verdict.exit_code, EXIT_CODE_SIGNATURE_FAILURE);
        assert_eq!(
            verdict.signature.error_code.as_deref(),
            Some("receipt_signature_invalid")
        );
    }

    #[test]
    fn transparency_failure_has_distinct_exit_code() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.transparency.leaf_hash = ContentHash::compute(b"tampered-leaf");
        let verdict = verify_receipt_request(&receipt_id, &request);

        assert!(!verdict.passed);
        assert_eq!(
            verdict.failure_class,
            Some(VerificationFailureClass::Transparency)
        );
        assert_eq!(verdict.exit_code, EXIT_CODE_TRANSPARENCY_FAILURE);
        assert_eq!(
            verdict.transparency.error_code.as_deref(),
            Some("transparency_inclusion_failed")
        );
    }

    #[test]
    fn attestation_failure_has_distinct_exit_code() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.attestation.policy_quote.quote_age_secs = 1_000;
        let verdict = verify_receipt_request(&receipt_id, &request);

        assert!(!verdict.passed);
        assert_eq!(
            verdict.failure_class,
            Some(VerificationFailureClass::Attestation)
        );
        assert_eq!(verdict.exit_code, EXIT_CODE_ATTESTATION_FAILURE);
        assert_eq!(
            verdict.attestation.error_code.as_deref(),
            Some("attestation_policy_quote_age_mismatch")
        );
    }

    #[test]
    fn stale_cache_warning_has_distinct_exit_code() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.attestation.policy_cache_stale = true;
        let verdict = verify_receipt_request(&receipt_id, &request);

        assert!(!verdict.passed);
        assert_eq!(
            verdict.failure_class,
            Some(VerificationFailureClass::StaleData)
        );
        assert_eq!(verdict.exit_code, EXIT_CODE_STALE_DATA);
        assert_eq!(
            verdict.warnings,
            vec!["attestation_policy_cache_stale".to_string()]
        );
    }

    #[test]
    fn by_id_lookup_returns_error_when_missing() {
        let (_receipt_id, request) = build_valid_fixture();
        let mut input = ReceiptVerifierCliInput::default();
        input.receipts.insert("known".to_string(), request);

        let error = verify_receipt_by_id(&input, "missing").expect_err("missing receipt");
        assert_eq!(
            error,
            ReceiptVerifierPipelineError::ReceiptNotFound {
                receipt_id: "missing".to_string()
            }
        );
    }

    #[test]
    fn map_platform_maps_all_variants_correctly() {
        assert_eq!(
            map_platform(PlatformKind::IntelSgx),
            Some(TeePlatform::IntelSgx)
        );
        assert_eq!(
            map_platform(PlatformKind::ArmCca),
            Some(TeePlatform::ArmCca)
        );
        assert_eq!(
            map_platform(PlatformKind::AmdSevSnp),
            Some(TeePlatform::AmdSev)
        );
        assert_eq!(map_platform(PlatformKind::Software), None);
    }

    // --- ReceiptVerifierPipelineError ---

    #[test]
    fn pipeline_error_display() {
        let e = ReceiptVerifierPipelineError::ReceiptNotFound {
            receipt_id: "rcpt-x".to_string(),
        };
        assert_eq!(
            e.to_string(),
            "receipt 'rcpt-x' not found in verifier input"
        );
    }

    #[test]
    fn pipeline_error_is_std_error() {
        let e: &dyn std::error::Error = &ReceiptVerifierPipelineError::ReceiptNotFound {
            receipt_id: "x".to_string(),
        };
        assert!(!e.to_string().is_empty());
    }

    // --- VerificationFailureClass ---

    #[test]
    fn failure_class_display_all_variants() {
        assert_eq!(VerificationFailureClass::Signature.to_string(), "signature");
        assert_eq!(
            VerificationFailureClass::Transparency.to_string(),
            "transparency"
        );
        assert_eq!(
            VerificationFailureClass::Attestation.to_string(),
            "attestation"
        );
        assert_eq!(
            VerificationFailureClass::StaleData.to_string(),
            "stale_data"
        );
    }

    #[test]
    fn failure_class_serde_round_trip() {
        let classes = [
            VerificationFailureClass::Signature,
            VerificationFailureClass::Transparency,
            VerificationFailureClass::Attestation,
            VerificationFailureClass::StaleData,
        ];
        for class in &classes {
            let json = serde_json::to_string(class).unwrap();
            let back: VerificationFailureClass = serde_json::from_str(&json).unwrap();
            assert_eq!(*class, back);
        }
    }

    #[test]
    fn failure_class_ordering() {
        assert!(VerificationFailureClass::Signature < VerificationFailureClass::Transparency);
        assert!(VerificationFailureClass::Transparency < VerificationFailureClass::Attestation);
        assert!(VerificationFailureClass::Attestation < VerificationFailureClass::StaleData);
    }

    // --- failure_class_exit_code ---

    #[test]
    fn exit_code_for_each_class() {
        assert_eq!(failure_class_exit_code(None), EXIT_CODE_SUCCESS);
        assert_eq!(
            failure_class_exit_code(Some(VerificationFailureClass::Signature)),
            EXIT_CODE_SIGNATURE_FAILURE
        );
        assert_eq!(
            failure_class_exit_code(Some(VerificationFailureClass::Transparency)),
            EXIT_CODE_TRANSPARENCY_FAILURE
        );
        assert_eq!(
            failure_class_exit_code(Some(VerificationFailureClass::Attestation)),
            EXIT_CODE_ATTESTATION_FAILURE
        );
        assert_eq!(
            failure_class_exit_code(Some(VerificationFailureClass::StaleData)),
            EXIT_CODE_STALE_DATA
        );
    }

    // --- LayerResult ---

    #[test]
    fn layer_result_pass_is_true() {
        let r = LayerResult::pass();
        assert!(r.passed);
        assert!(r.error_code.is_none());
        assert!(r.checks.is_empty());
    }

    #[test]
    fn layer_result_record_pass_stays_passed() {
        let mut r = LayerResult::pass();
        r.record_pass("check-1", "detail-1");
        assert!(r.passed);
        assert_eq!(r.checks.len(), 1);
        assert_eq!(r.checks[0].check, "check-1");
        assert_eq!(r.checks[0].outcome, "pass");
        assert!(r.checks[0].error_code.is_none());
    }

    #[test]
    fn layer_result_record_fail_marks_failed() {
        let mut r = LayerResult::pass();
        r.record_fail("check-1", "err-code-1", "detail-1");
        assert!(!r.passed);
        assert_eq!(r.error_code.as_deref(), Some("err-code-1"));
        assert_eq!(r.checks[0].outcome, "fail");
    }

    #[test]
    fn layer_result_first_error_code_wins() {
        let mut r = LayerResult::pass();
        r.record_fail("c1", "first_error", "d1");
        r.record_fail("c2", "second_error", "d2");
        assert_eq!(r.error_code.as_deref(), Some("first_error"));
        assert_eq!(r.checks.len(), 2);
    }

    #[test]
    fn layer_check_serde_round_trip() {
        let check = LayerCheck {
            check: "test_check".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            detail: "detail".to_string(),
        };
        let json = serde_json::to_string(&check).unwrap();
        let back: LayerCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(check, back);
    }

    #[test]
    fn layer_result_serde_round_trip() {
        let mut r = LayerResult::pass();
        r.record_pass("c1", "d1");
        let json = serde_json::to_string(&r).unwrap();
        let back: LayerResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- render_verdict_summary ---

    #[test]
    fn render_verdict_summary_passing() {
        let (receipt_id, request) = build_valid_fixture();
        let verdict = verify_receipt_request(&receipt_id, &request);
        let summary = render_verdict_summary(&verdict);
        assert!(summary.contains("passed=true"));
        assert!(summary.contains("exit_code=0"));
        assert!(summary.contains("failure_class=none"));
        assert!(summary.contains("warnings=0"));
    }

    #[test]
    fn render_verdict_summary_failing() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.signature.signing_key_bytes = vec![1u8; 32];
        let verdict = verify_receipt_request(&receipt_id, &request);
        let summary = render_verdict_summary(&verdict);
        assert!(summary.contains("passed=false"));
        assert!(summary.contains("failure_class=signature"));
    }

    // --- verify_receipt_by_id success ---

    #[test]
    fn by_id_lookup_returns_verdict_when_present() {
        let (receipt_id, request) = build_valid_fixture();
        let mut input = ReceiptVerifierCliInput::default();
        input.receipts.insert(receipt_id.clone(), request);
        let verdict = verify_receipt_by_id(&input, &receipt_id).unwrap();
        assert!(verdict.passed);
        assert_eq!(verdict.receipt_id, receipt_id);
    }

    // --- Signature layer failure modes ---

    #[test]
    fn signature_revoked_signer_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.signature.signer_revocation.is_revoked = true;
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert_eq!(
            verdict.failure_class,
            Some(VerificationFailureClass::Signature)
        );
        assert!(
            verdict
                .signature
                .checks
                .iter()
                .any(|c| c.check == "signer_not_revoked" && c.outcome == "fail")
        );
    }

    #[test]
    fn signature_empty_revocation_source_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.signature.signer_revocation.source = "".to_string();
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(
            verdict
                .signature
                .checks
                .iter()
                .any(|c| c.check == "revocation_source_present" && c.outcome == "fail")
        );
    }

    #[test]
    fn signature_signer_key_id_mismatch_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.signature.signer_revocation.signer_key_id = EngineObjectId([0xAA; 32]);
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(
            verdict
                .signature
                .checks
                .iter()
                .any(|c| c.check == "signer_key_id_matches_receipt" && c.outcome == "fail")
        );
    }

    #[test]
    fn signature_preimage_hash_mismatch_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.signature.expected_preimage_hash = ContentHash::compute(b"wrong");
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(
            verdict
                .signature
                .checks
                .iter()
                .any(|c| c.check == "canonical_preimage_hash_matches" && c.outcome == "fail")
        );
    }

    // --- Transparency layer failure modes ---

    #[test]
    fn transparency_operator_key_revoked_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.transparency.operator_keys[0].revoked = true;
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(
            verdict
                .transparency
                .checks
                .iter()
                .any(|c| c.check == "checkpoint_operator_key_not_revoked" && c.outcome == "fail")
        );
    }

    #[test]
    fn transparency_operator_key_missing_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.transparency.operator_keys.clear();
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(
            verdict
                .transparency
                .checks
                .iter()
                .any(|c| c.check == "checkpoint_operator_key_found" && c.outcome == "fail")
        );
    }

    #[test]
    fn transparency_root_mismatch_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.transparency.inclusion_proof.root_hash = ContentHash::compute(b"wrong-root");
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(verdict
            .transparency
            .checks
            .iter()
            .any(|c| c.check == "inclusion_root_matches_checkpoint_root" && c.outcome == "fail"));
    }

    #[test]
    fn transparency_log_length_mismatch_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.transparency.inclusion_proof.stream_length = 999;
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(verdict.transparency.checks.iter().any(|c| c.check
            == "checkpoint_log_length_matches_inclusion_stream_length"
            && c.outcome == "fail"));
    }

    // --- Attestation layer failure modes ---

    #[test]
    fn attestation_missing_bindings_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.receipt.attestation_bindings = None;
        // Re-sign the receipt since bindings changed
        let signed = request.receipt.sign(&request.signature.signing_key_bytes);
        request.signature.expected_preimage_hash = ContentHash::compute(&signed.signing_preimage());
        request.receipt = signed;
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(
            verdict
                .attestation
                .checks
                .iter()
                .any(|c| c.check == "receipt_has_attestation_bindings" && c.outcome == "fail")
        );
    }

    #[test]
    fn attestation_signer_mismatch_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        if let Some(ref mut bindings) = request.receipt.attestation_bindings {
            bindings.attested_signer_key_id = EngineObjectId([0xBB; 32]);
        }
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(verdict
            .attestation
            .checks
            .iter()
            .any(|c| c.check == "attested_signer_matches_receipt_signer" && c.outcome == "fail"));
    }

    #[test]
    fn attestation_nonce_mismatch_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        if let Some(ref mut bindings) = request.receipt.attestation_bindings {
            bindings.nonce = [0xFF; 32];
        }
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(
            verdict
                .attestation
                .checks
                .iter()
                .any(|c| c.check == "quote_nonce_matches_binding" && c.outcome == "fail")
        );
    }

    #[test]
    fn attestation_trust_root_missing_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.attestation.trust_roots.clear();
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(
            verdict
                .attestation
                .checks
                .iter()
                .any(|c| c.check == "quote_trust_root_available" && c.outcome == "fail")
        );
    }

    #[test]
    fn attestation_policy_trust_root_mismatch_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.attestation.policy_quote.trust_root_id = "wrong-root".to_string();
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(verdict.attestation.checks.iter().any(|c| c.check
            == "policy_quote_trust_root_matches_attested_signer"
            && c.outcome == "fail"));
    }

    #[test]
    fn attestation_measurement_mismatch_blocks() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.attestation.policy_quote.measurement.digest_hex = "aa".repeat(32);
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(verdict.attestation.checks.iter().any(|c| c.check
            == "policy_quote_measurement_matches_attested_measurement"
            && c.outcome == "fail"));
    }

    // --- Stale cache warnings ---

    #[test]
    fn signature_revocation_cache_stale_warning() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.signature.signer_revocation.cache_stale = true;
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert_eq!(
            verdict.failure_class,
            Some(VerificationFailureClass::StaleData)
        );
        assert!(
            verdict
                .warnings
                .contains(&"signature_revocation_cache_stale".to_string())
        );
    }

    #[test]
    fn transparency_cache_stale_warning() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.transparency.cache_stale = true;
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(
            verdict
                .warnings
                .contains(&"transparency_cache_stale".to_string())
        );
    }

    #[test]
    fn attestation_revocation_cache_stale_warning() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.attestation.revocation_cache_stale = true;
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(!verdict.passed);
        assert!(
            verdict
                .warnings
                .contains(&"attestation_revocation_cache_stale".to_string())
        );
    }

    #[test]
    fn multiple_stale_caches_accumulate() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.signature.signer_revocation.cache_stale = true;
        request.transparency.cache_stale = true;
        request.attestation.policy_cache_stale = true;
        request.attestation.revocation_cache_stale = true;
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert_eq!(verdict.warnings.len(), 4);
    }

    // --- Serde round-trips ---

    #[test]
    fn verifier_log_event_serde_round_trip() {
        let e = VerifierLogEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: VerifierLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn verifier_log_event_with_error_code_serde_round_trip() {
        let e = VerifierLogEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("err-1".to_string()),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: VerifierLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn pipeline_error_serde_round_trip() {
        let e = ReceiptVerifierPipelineError::ReceiptNotFound {
            receipt_id: "x".to_string(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: ReceiptVerifierPipelineError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- Verdict structure ---

    #[test]
    fn verdict_logs_have_correct_component() {
        let (receipt_id, request) = build_valid_fixture();
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(verdict.logs.iter().all(|log| log.component == COMPONENT));
    }

    #[test]
    fn verdict_logs_include_completion_event() {
        let (receipt_id, request) = build_valid_fixture();
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert!(
            verdict
                .logs
                .iter()
                .any(|log| log.event == "receipt_verification_complete")
        );
    }

    #[test]
    fn verdict_passing_has_pass_completion_outcome() {
        let (receipt_id, request) = build_valid_fixture();
        let verdict = verify_receipt_request(&receipt_id, &request);
        let complete = verdict
            .logs
            .iter()
            .find(|log| log.event == "receipt_verification_complete")
            .unwrap();
        assert_eq!(complete.outcome, "pass");
        assert!(complete.error_code.is_none());
    }

    #[test]
    fn verdict_stale_has_warn_completion_outcome() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.attestation.policy_cache_stale = true;
        let verdict = verify_receipt_request(&receipt_id, &request);
        let complete = verdict
            .logs
            .iter()
            .find(|log| log.event == "receipt_verification_complete")
            .unwrap();
        assert_eq!(complete.outcome, "warn");
        assert_eq!(complete.error_code.as_deref(), Some("stale_data"));
    }

    #[test]
    fn verdict_hard_failure_has_fail_completion_outcome() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.signature.signing_key_bytes = vec![1u8; 32];
        let verdict = verify_receipt_request(&receipt_id, &request);
        let complete = verdict
            .logs
            .iter()
            .find(|log| log.event == "receipt_verification_complete")
            .unwrap();
        assert_eq!(complete.outcome, "fail");
        assert_eq!(complete.error_code.as_deref(), Some("signature"));
    }

    // --- Constants ---

    #[test]
    fn exit_code_constants_are_distinct() {
        let codes = [
            EXIT_CODE_SUCCESS,
            EXIT_CODE_SIGNATURE_FAILURE,
            EXIT_CODE_TRANSPARENCY_FAILURE,
            EXIT_CODE_ATTESTATION_FAILURE,
            EXIT_CODE_STALE_DATA,
        ];
        for (i, a) in codes.iter().enumerate() {
            for (j, b) in codes.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn component_constant_not_empty() {
        assert!(!COMPONENT.is_empty());
    }

    #[test]
    fn checkpoint_signature_domain_not_empty() {
        assert!(!CHECKPOINT_SIGNATURE_DOMAIN.is_empty());
    }

    // --- checkpoint_preimage ---

    #[test]
    fn checkpoint_preimage_deterministic() {
        let checkpoint = SignedLogCheckpoint {
            checkpoint_seq: 1,
            log_length: 10,
            root_hash: ContentHash::compute(b"root"),
            timestamp_ns: 1000,
            operator_key_id: "op-1".to_string(),
            signature: Signature::from_bytes([0u8; 64]),
        };
        let a = checkpoint_preimage(&checkpoint);
        let b = checkpoint_preimage(&checkpoint);
        assert_eq!(a, b);
    }

    #[test]
    fn checkpoint_preimage_changes_with_fields() {
        let base = SignedLogCheckpoint {
            checkpoint_seq: 1,
            log_length: 10,
            root_hash: ContentHash::compute(b"root"),
            timestamp_ns: 1000,
            operator_key_id: "op-1".to_string(),
            signature: Signature::from_bytes([0u8; 64]),
        };
        let mut modified = base.clone();
        modified.checkpoint_seq = 2;
        assert_ne!(checkpoint_preimage(&base), checkpoint_preimage(&modified));
    }

    // --- attestation_quote_digest ---

    #[test]
    fn attestation_quote_digest_deterministic() {
        let software_root = SoftwareTrustRoot::new("root-1", 7);
        let measurement = software_root.measure(b"a", b"b", b"c", b"d", "e");
        let quote = software_root.attest(&measurement, [0u8; 32], 1000, 0);
        let a = attestation_quote_digest(&quote).unwrap();
        let b = attestation_quote_digest(&quote).unwrap();
        assert_eq!(a, b);
    }

    // --- Verdict fields propagation ---

    #[test]
    fn verdict_propagates_request_ids() {
        let (receipt_id, request) = build_valid_fixture();
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert_eq!(verdict.receipt_id, receipt_id);
        assert_eq!(verdict.trace_id, request.trace_id);
        assert_eq!(verdict.decision_id, request.decision_id);
        assert_eq!(verdict.policy_id, request.policy_id);
        assert_eq!(
            verdict.verification_timestamp_ns,
            request.verification_timestamp_ns
        );
    }

    #[test]
    fn verdict_serde_round_trip() {
        let (receipt_id, request) = build_valid_fixture();
        let verdict = verify_receipt_request(&receipt_id, &request);
        let json = serde_json::to_string(&verdict).unwrap();
        let back: UnifiedReceiptVerificationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(verdict, back);
    }

    // --- Priority of failure classes ---

    #[test]
    fn signature_failure_takes_priority_over_stale() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.signature.signing_key_bytes = vec![1u8; 32];
        request.attestation.policy_cache_stale = true;
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert_eq!(
            verdict.failure_class,
            Some(VerificationFailureClass::Signature)
        );
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn signer_revocation_cache_serde_roundtrip() {
        let cache = SignerRevocationCache {
            signer_key_id: EngineObjectId([0xAA; 32]),
            source: "offline-ledger".to_string(),
            is_revoked: false,
            cache_stale: true,
        };
        let json = serde_json::to_string(&cache).unwrap();
        let back: SignerRevocationCache = serde_json::from_str(&json).unwrap();
        assert_eq!(cache, back);
    }

    #[test]
    fn log_operator_key_serde_roundtrip() {
        let key = LogOperatorKey {
            key_id: "op-key-1".to_string(),
            verification_key: SigningKey::from_bytes([3u8; 32]).verification_key(),
            revoked: false,
        };
        let json = serde_json::to_string(&key).unwrap();
        let back: LogOperatorKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);
    }

    #[test]
    fn signed_log_checkpoint_serde_roundtrip() {
        let checkpoint = SignedLogCheckpoint {
            checkpoint_seq: 42,
            log_length: 100,
            root_hash: ContentHash::compute(b"root"),
            timestamp_ns: 5_000_000_000,
            operator_key_id: "op-1".to_string(),
            signature: Signature::from_bytes([0u8; 64]),
        };
        let json = serde_json::to_string(&checkpoint).unwrap();
        let back: SignedLogCheckpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(checkpoint, back);
    }

    #[test]
    fn consistency_proof_input_serde_roundtrip() {
        let mut mmr = MerkleMountainRange::new(5);
        mmr.append(ContentHash::compute(b"a"));
        mmr.append(ContentHash::compute(b"b"));
        let proof = mmr.consistency_proof(1).expect("consistency proof");
        let input = ConsistencyProofInput {
            from_root: ContentHash::compute(b"old-root"),
            proof,
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: ConsistencyProofInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    #[test]
    fn signature_layer_input_serde_roundtrip() {
        let input = SignatureLayerInput {
            expected_preimage_hash: ContentHash::compute(b"preimage"),
            signing_key_bytes: vec![0x55; 32],
            signer_revocation: SignerRevocationCache {
                signer_key_id: EngineObjectId([0x44; 32]),
                source: "offline".to_string(),
                is_revoked: false,
                cache_stale: false,
            },
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: SignatureLayerInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    #[test]
    fn receipt_verifier_cli_input_default_is_empty() {
        let input = ReceiptVerifierCliInput::default();
        assert!(input.receipts.is_empty());
    }

    #[test]
    fn transparency_failure_takes_priority_over_attestation() {
        let (receipt_id, mut request) = build_valid_fixture();
        // Break transparency
        request.transparency.leaf_hash = ContentHash::compute(b"tampered");
        // Break attestation
        request.attestation.policy_quote.quote_age_secs = 999_999;
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert_eq!(
            verdict.failure_class,
            Some(VerificationFailureClass::Transparency)
        );
    }

    #[test]
    fn attestation_failure_takes_priority_over_stale() {
        let (receipt_id, mut request) = build_valid_fixture();
        // Break attestation
        request.attestation.policy_quote.quote_age_secs = 999_999;
        // Set stale caches
        request.signature.signer_revocation.cache_stale = true;
        request.transparency.cache_stale = true;
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert_eq!(
            verdict.failure_class,
            Some(VerificationFailureClass::Attestation)
        );
    }

    #[test]
    fn layer_result_fail_then_pass_remains_failed() {
        let mut r = LayerResult::pass();
        r.record_fail("c1", "err-1", "failed first");
        r.record_pass("c2", "passed second");
        assert!(!r.passed);
        assert_eq!(r.error_code.as_deref(), Some("err-1"));
        assert_eq!(r.checks.len(), 2);
        assert_eq!(r.checks[1].outcome, "pass");
    }

    #[test]
    fn checkpoint_preimage_includes_domain_separator() {
        let checkpoint = SignedLogCheckpoint {
            checkpoint_seq: 1,
            log_length: 10,
            root_hash: ContentHash::compute(b"root"),
            timestamp_ns: 1000,
            operator_key_id: "op-1".to_string(),
            signature: Signature::from_bytes([0u8; 64]),
        };
        let preimage = checkpoint_preimage(&checkpoint);
        assert!(preimage.starts_with(CHECKPOINT_SIGNATURE_DOMAIN));
    }

    #[test]
    fn render_verdict_summary_stale_data() {
        let (receipt_id, mut request) = build_valid_fixture();
        request.attestation.revocation_cache_stale = true;
        let verdict = verify_receipt_request(&receipt_id, &request);
        let summary = render_verdict_summary(&verdict);
        assert!(summary.contains("passed=false"));
        assert!(summary.contains("failure_class=stale_data"));
        assert!(summary.contains("warnings=1"));
    }

    #[test]
    fn verification_failure_class_display_matches_serde_key() {
        let variants = [
            VerificationFailureClass::Signature,
            VerificationFailureClass::Transparency,
            VerificationFailureClass::Attestation,
            VerificationFailureClass::StaleData,
        ];
        for variant in &variants {
            let display = variant.to_string();
            let json = serde_json::to_string(variant).unwrap();
            // serde JSON wraps in quotes: "signature"
            let serde_key = json.trim_matches('"');
            assert_eq!(display, serde_key);
        }
    }

    #[test]
    fn verdict_always_has_four_log_entries() {
        // Passing case: 3 layer logs + 1 completion
        let (receipt_id, request) = build_valid_fixture();
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert_eq!(verdict.logs.len(), 4);

        // Failing case: still 4 log entries
        let (receipt_id, mut request) = build_valid_fixture();
        request.signature.signing_key_bytes = vec![1u8; 32];
        let verdict = verify_receipt_request(&receipt_id, &request);
        assert_eq!(verdict.logs.len(), 4);
    }

    #[test]
    fn layer_check_with_error_code_serde_roundtrip() {
        let check = LayerCheck {
            check: "some_check".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("some_error_code".to_string()),
            detail: "a detail message".to_string(),
        };
        let json = serde_json::to_string(&check).unwrap();
        let back: LayerCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(check, back);
    }

    #[test]
    fn checkpoint_preimage_sensitive_to_all_fields() {
        let base = SignedLogCheckpoint {
            checkpoint_seq: 1,
            log_length: 10,
            root_hash: ContentHash::compute(b"root"),
            timestamp_ns: 1000,
            operator_key_id: "op-1".to_string(),
            signature: Signature::from_bytes([0u8; 64]),
        };
        let base_preimage = checkpoint_preimage(&base);

        let mut m = base.clone();
        m.log_length = 11;
        assert_ne!(checkpoint_preimage(&m), base_preimage);

        let mut m = base.clone();
        m.root_hash = ContentHash::compute(b"other");
        assert_ne!(checkpoint_preimage(&m), base_preimage);

        let mut m = base.clone();
        m.timestamp_ns = 2000;
        assert_ne!(checkpoint_preimage(&m), base_preimage);

        let mut m = base.clone();
        m.operator_key_id = "op-2".to_string();
        assert_ne!(checkpoint_preimage(&m), base_preimage);
    }
}
