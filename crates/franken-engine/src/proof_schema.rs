//! Proof schema and signer model for optimizer activation witnesses.
//!
//! Defines the canonical data structures (`OptReceipt`, `RollbackToken`,
//! `InvarianceDigest`) that every adaptive optimization path must produce
//! before activation is permitted.
//!
//! Plan references: Section 10.12 item 1, 9H.1 (proof-carrying adaptive
//! optimizer), 9F.1 (verified adaptive compiler).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::security_epoch::SecurityEpoch;
use crate::tee_attestation_policy::DecisionImpact;

pub use crate::control_plane::SchemaVersion;

pub trait SchemaVersionExt {
    fn is_compatible_with(&self, other: &Self) -> bool;
    fn supports_attestation_bindings(&self) -> bool;
    fn major_val(&self) -> u32;
    fn minor_val(&self) -> u32;
}

pub fn proof_schema_version_v1_0() -> SchemaVersion {
    SchemaVersion::new(1, 0, 0)
}

pub fn proof_schema_version_v1_1() -> SchemaVersion {
    SchemaVersion::new(1, 1, 0)
}

pub fn proof_schema_version_current() -> SchemaVersion {
    proof_schema_version_v1_1()
}

pub fn proof_schema_attestation_binding_intro() -> SchemaVersion {
    proof_schema_version_v1_1()
}

impl SchemaVersionExt for SchemaVersion {
    fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }

    fn supports_attestation_bindings(&self) -> bool {
        let intro = proof_schema_attestation_binding_intro();
        self.major > intro.major || (self.major == intro.major && self.minor >= intro.minor)
    }

    fn major_val(&self) -> u32 {
        self.major
    }
    fn minor_val(&self) -> u32 {
        self.minor
    }
}

// ---------------------------------------------------------------------------
// OptimizationClass — types of optimizations
// ---------------------------------------------------------------------------

/// Classification of optimizer transformation types.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum OptimizationClass {
    /// Fused super-instruction combining multiple operations.
    Superinstruction,
    /// Trace specialization based on observed hot paths.
    TraceSpecialization,
    /// Memory layout optimization for data access patterns.
    LayoutSpecialization,
    /// Devirtualized host-call fast path.
    DevirtualizedHostcallFastPath,
}

impl fmt::Display for OptimizationClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Superinstruction => write!(f, "superinstruction"),
            Self::TraceSpecialization => write!(f, "trace_specialization"),
            Self::LayoutSpecialization => write!(f, "layout_specialization"),
            Self::DevirtualizedHostcallFastPath => write!(f, "devirtualized_hostcall_fast_path"),
        }
    }
}

// ---------------------------------------------------------------------------
// ActivationStage — lifecycle stages of an optimization
// ---------------------------------------------------------------------------

/// Promotion stage for an optimizer activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ActivationStage {
    /// Running in shadow mode (no effect on production traffic).
    Shadow,
    /// Canary deployment to a small fraction of traffic.
    Canary,
    /// Ramping to a larger fraction of traffic.
    Ramp,
    /// Default activation for all traffic.
    Default,
}

impl fmt::Display for ActivationStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shadow => write!(f, "shadow"),
            Self::Canary => write!(f, "canary"),
            Self::Ramp => write!(f, "ramp"),
            Self::Default => write!(f, "default"),
        }
    }
}

// ---------------------------------------------------------------------------
// EquivalenceVerdict
// ---------------------------------------------------------------------------

/// Result of trace-level semantic equivalence checking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EquivalenceVerdict {
    /// Baseline and candidate produce identical observable behavior.
    Equivalent,
    /// Observable behavioral difference detected.
    NonEquivalent { reason: String },
    /// Equivalence could not be determined (e.g. timeout, corpus too small).
    Inconclusive { reason: String },
}

// ---------------------------------------------------------------------------
// TraceComparisonMethodology
// ---------------------------------------------------------------------------

/// Methodology used for comparing baseline and candidate traces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TraceComparisonMethodology {
    /// Deterministic replay with bit-exact output comparison.
    DeterministicReplay,
    /// Symbolic execution with equivalence proof.
    SymbolicEquivalence,
    /// Statistical comparison over a corpus of inputs.
    StatisticalCorpus { corpus_size: u64 },
}

// ---------------------------------------------------------------------------
// InvarianceDigest — equivalence commitment
// ---------------------------------------------------------------------------

/// Cryptographic commitment over the semantic equivalence claim between
/// baseline IR traces and optimized candidate traces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvarianceDigest {
    /// Schema version for forward compatibility.
    pub schema_version: SchemaVersion,
    /// Hash of the golden test corpus used for comparison.
    pub golden_corpus_hash: ContentHash,
    /// Methodology used for trace comparison.
    pub trace_comparison_methodology: TraceComparisonMethodology,
    /// Outcome of the equivalence check.
    pub equivalence_verdict: EquivalenceVerdict,
    /// Root hash of the witness chain (Merkle root over individual
    /// trace-comparison witness entries).
    pub witness_chain_root: ContentHash,
}

impl InvarianceDigest {
    /// Compute the content hash of this digest for inclusion in receipts.
    pub fn content_hash(&self) -> ContentHash {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&self.schema_version.major.to_be_bytes());
        preimage.extend_from_slice(&self.schema_version.minor.to_be_bytes());
        preimage.extend_from_slice(self.golden_corpus_hash.as_bytes());

        let method_tag = match &self.trace_comparison_methodology {
            TraceComparisonMethodology::DeterministicReplay => b"deterministic_replay" as &[u8],
            TraceComparisonMethodology::SymbolicEquivalence => b"symbolic_equivalence",
            TraceComparisonMethodology::StatisticalCorpus { corpus_size } => {
                preimage.extend_from_slice(&corpus_size.to_be_bytes());
                b"statistical_corpus"
            }
        };
        preimage.extend_from_slice(&(method_tag.len() as u32).to_be_bytes());
        preimage.extend_from_slice(method_tag);

        let verdict_tag = match &self.equivalence_verdict {
            EquivalenceVerdict::Equivalent => b"equivalent" as &[u8],
            EquivalenceVerdict::NonEquivalent { reason } => {
                preimage.extend_from_slice(&(reason.len() as u32).to_be_bytes());
                preimage.extend_from_slice(reason.as_bytes());
                b"non_equivalent"
            }
            EquivalenceVerdict::Inconclusive { reason } => {
                preimage.extend_from_slice(&(reason.len() as u32).to_be_bytes());
                preimage.extend_from_slice(reason.as_bytes());
                b"inconclusive"
            }
        };
        preimage.extend_from_slice(&(verdict_tag.len() as u32).to_be_bytes());
        preimage.extend_from_slice(verdict_tag);

        preimage.extend_from_slice(self.witness_chain_root.as_bytes());

        ContentHash::compute(&preimage)
    }
}

// ---------------------------------------------------------------------------
// SignerKeyId — key identity for signatures
// ---------------------------------------------------------------------------

/// Identity of a signing key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignerKeyId {
    /// The key identifier (derived from the public key material).
    pub key_id: EngineObjectId,
    /// Role this key is authorized for.
    pub role: SignerRole,
    /// Security epoch this key is bound to.
    pub bound_epoch: SecurityEpoch,
}

/// Roles that signing keys can hold (split principal model per 10.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SignerRole {
    /// Optimizer subsystem signs receipts.
    OptimizerSubsystem,
    /// Policy plane signs epoch bindings.
    PolicyPlane,
    /// Attestation cell signs TEE-bound variants.
    AttestationCell,
}

impl fmt::Display for SignerRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OptimizerSubsystem => write!(f, "optimizer_subsystem"),
            Self::PolicyPlane => write!(f, "policy_plane"),
            Self::AttestationCell => write!(f, "attestation_cell"),
        }
    }
}

// ---------------------------------------------------------------------------
// Receipt attestation bindings
// ---------------------------------------------------------------------------

/// Explicit freshness window for attestation bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationValidityWindow {
    /// Inclusive start timestamp for attestation freshness.
    pub start_timestamp_ticks: u64,
    /// Inclusive end timestamp for attestation freshness.
    pub end_timestamp_ticks: u64,
}

impl AttestationValidityWindow {
    fn validate(&self) -> Result<(), ProofSchemaError> {
        if self.end_timestamp_ticks < self.start_timestamp_ticks {
            return Err(ProofSchemaError::InvalidAttestationBindings {
                reason: "validity_window.end_timestamp_ticks must be >= start_timestamp_ticks"
                    .to_string(),
            });
        }
        Ok(())
    }

    fn contains(&self, timestamp_ticks: u64) -> bool {
        self.start_timestamp_ticks <= timestamp_ticks && timestamp_ticks <= self.end_timestamp_ticks
    }
}

/// Cryptographic attestation bindings for TEE-produced receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptAttestationBindings {
    /// Hash of the full TEE quote accompanying this receipt.
    pub quote_digest: ContentHash,
    /// ID of the approved measurement active at signing time.
    pub measurement_id: EngineObjectId,
    /// ID of the attested signer key bound to the measured cell identity.
    pub attested_signer_key_id: EngineObjectId,
    /// Challenge nonce preventing quote replay.
    pub nonce: [u8; 32],
    /// Freshness window for this attestation binding.
    pub validity_window: AttestationValidityWindow,
}

impl ReceiptAttestationBindings {
    fn validate(&self) -> Result<(), ProofSchemaError> {
        self.validity_window.validate()?;
        if self.nonce.iter().all(|byte| *byte == 0) {
            return Err(ProofSchemaError::InvalidAttestationBindings {
                reason: "nonce must not be all zeros".to_string(),
            });
        }
        Ok(())
    }

    fn append_to_preimage(&self, preimage: &mut Vec<u8>) {
        preimage.extend_from_slice(self.quote_digest.as_bytes());
        preimage.extend_from_slice(self.measurement_id.as_bytes());
        preimage.extend_from_slice(self.attested_signer_key_id.as_bytes());
        preimage.extend_from_slice(&self.nonce);
        preimage.extend_from_slice(&self.validity_window.start_timestamp_ticks.to_be_bytes());
        preimage.extend_from_slice(&self.validity_window.end_timestamp_ticks.to_be_bytes());
    }
}

/// Policy-controlled threshold for attestation-binding requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationRequirementPolicy {
    /// Receipts at or above this impact tier must include attestation bindings.
    pub require_at_or_above: DecisionImpact,
    /// Allow pre-attestation schema receipts (v1.0) to validate without bindings.
    pub allow_legacy_receipts_without_attestation: bool,
}

impl Default for AttestationRequirementPolicy {
    fn default() -> Self {
        Self {
            require_at_or_above: DecisionImpact::HighImpact,
            allow_legacy_receipts_without_attestation: true,
        }
    }
}

impl AttestationRequirementPolicy {
    fn requires_attestation(&self, receipt: &OptReceipt) -> bool {
        if self.allow_legacy_receipts_without_attestation
            && !receipt.schema_version.supports_attestation_bindings()
        {
            return false;
        }
        receipt.decision_impact >= self.require_at_or_above
    }
}

/// Registry enforcing nonce uniqueness for attested receipt verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReceiptNonceRegistry {
    seen: BTreeSet<(EngineObjectId, [u8; 32])>,
}

impl ReceiptNonceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_record(
        &mut self,
        attested_signer_key_id: &EngineObjectId,
        nonce: [u8; 32],
    ) -> Result<(), ProofSchemaError> {
        let key = (attested_signer_key_id.clone(), nonce);
        if !self.seen.insert(key) {
            return Err(ProofSchemaError::NonceReplay {
                attested_signer_key_id: attested_signer_key_id.clone(),
                nonce_hex: format_nonce_hex(&nonce),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// OptReceipt — optimizer activation receipt
// ---------------------------------------------------------------------------

/// Structured receipt for an optimizer activation decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptReceipt {
    /// Schema version.
    pub schema_version: SchemaVersion,
    /// Unique optimization identifier.
    pub optimization_id: String,
    /// Class of the optimization.
    pub optimization_class: OptimizationClass,
    /// Content hash of the baseline IR.
    pub baseline_ir_hash: ContentHash,
    /// Content hash of the optimized candidate IR.
    pub candidate_ir_hash: ContentHash,
    /// Hash of the translation witness (proof of correct transformation).
    pub translation_witness_hash: ContentHash,
    /// Invariance digest proving semantic equivalence.
    pub invariance_digest: ContentHash,
    /// Rollback token ID for restoring baseline execution.
    pub rollback_token_id: String,
    /// Replay compatibility metadata (engine version, target arch, etc.).
    pub replay_compatibility: BTreeMap<String, String>,
    /// Security epoch at receipt issuance.
    pub policy_epoch: SecurityEpoch,
    /// Virtual timestamp (deterministic tick count).
    pub timestamp_ticks: u64,
    /// Key used to sign this receipt.
    pub signer_key_id: EngineObjectId,
    /// Correlation ID for audit chain linkage.
    pub correlation_id: String,
    /// Sentinel risk tier for this decision class.
    #[serde(default = "default_decision_impact")]
    pub decision_impact: DecisionImpact,
    /// Optional TEE attestation bindings (mandatory for policy-selected tiers).
    #[serde(default)]
    pub attestation_bindings: Option<ReceiptAttestationBindings>,
    /// Signature over the unsigned view of this receipt.
    pub signature: AuthenticityHash,
}

impl OptReceipt {
    /// Compute the unsigned preimage for signing.
    ///
    /// Uses deterministic field ordering per the 10.10 signature preimage
    /// contract. The `signature` field is excluded from the preimage.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut preimage = Vec::new();

        // Schema version.
        preimage.extend_from_slice(&self.schema_version.major.to_be_bytes());
        preimage.extend_from_slice(&self.schema_version.minor.to_be_bytes());

        // Optimization identity.
        append_length_prefixed(&mut preimage, self.optimization_id.as_bytes());
        append_length_prefixed(
            &mut preimage,
            self.optimization_class.to_string().as_bytes(),
        );

        // IR hashes.
        preimage.extend_from_slice(self.baseline_ir_hash.as_bytes());
        preimage.extend_from_slice(self.candidate_ir_hash.as_bytes());
        preimage.extend_from_slice(self.translation_witness_hash.as_bytes());
        preimage.extend_from_slice(self.invariance_digest.as_bytes());

        // Rollback token.
        append_length_prefixed(&mut preimage, self.rollback_token_id.as_bytes());

        // Replay compatibility (BTreeMap ensures deterministic ordering).
        preimage.extend_from_slice(&(self.replay_compatibility.len() as u32).to_be_bytes());
        for (k, v) in &self.replay_compatibility {
            append_length_prefixed(&mut preimage, k.as_bytes());
            append_length_prefixed(&mut preimage, v.as_bytes());
        }

        // Epoch and timestamp.
        preimage.extend_from_slice(&self.policy_epoch.as_u64().to_be_bytes());
        preimage.extend_from_slice(&self.timestamp_ticks.to_be_bytes());

        // Signer key.
        preimage.extend_from_slice(self.signer_key_id.as_bytes());

        // Correlation.
        append_length_prefixed(&mut preimage, self.correlation_id.as_bytes());

        if self.schema_version.supports_attestation_bindings() {
            append_length_prefixed(&mut preimage, decision_impact_bytes(self.decision_impact));
            match &self.attestation_bindings {
                Some(bindings) => {
                    preimage.push(1);
                    bindings.append_to_preimage(&mut preimage);
                }
                None => preimage.push(0),
            }
        }

        preimage
    }

    /// Sign this receipt with the given key material.
    pub fn sign(mut self, key: &[u8]) -> Self {
        let preimage = self.signing_preimage();
        self.signature = AuthenticityHash::compute_keyed(key, &preimage);
        self
    }

    /// Verify the receipt signature against the given key material.
    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let preimage = self.signing_preimage();
        let expected = AuthenticityHash::compute_keyed(key, &preimage);
        self.signature == expected
    }

    /// Derive the `EngineObjectId` for this receipt.
    pub fn object_id(
        &self,
        zone: &str,
    ) -> Result<EngineObjectId, crate::engine_object_id::IdError> {
        let schema_id = SchemaId::from_definition(b"proof_schema::OptReceipt::v1");
        crate::engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            zone,
            &schema_id,
            &self.signing_preimage(),
        )
    }
}

// ---------------------------------------------------------------------------
// RollbackToken — immutable rollback artifact
// ---------------------------------------------------------------------------

/// Immutable artifact sufficient to deterministically restore baseline
/// execution without re-running validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackToken {
    /// Schema version.
    pub schema_version: SchemaVersion,
    /// Unique token identifier.
    pub token_id: String,
    /// Optimization this token can roll back.
    pub optimization_id: String,
    /// Content hash of the baseline execution snapshot.
    pub baseline_snapshot_hash: ContentHash,
    /// Current activation stage at token issuance.
    pub activation_stage: ActivationStage,
    /// Epoch after which this token expires and cannot be used.
    pub expiry_epoch: SecurityEpoch,
    /// Key used to sign this token.
    pub issuer_key_id: EngineObjectId,
    /// Signature over the unsigned view.
    pub issuer_signature: AuthenticityHash,
}

impl RollbackToken {
    /// Compute the unsigned preimage for signing.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut preimage = Vec::new();

        preimage.extend_from_slice(&self.schema_version.major.to_be_bytes());
        preimage.extend_from_slice(&self.schema_version.minor.to_be_bytes());

        append_length_prefixed(&mut preimage, self.token_id.as_bytes());
        append_length_prefixed(&mut preimage, self.optimization_id.as_bytes());

        preimage.extend_from_slice(self.baseline_snapshot_hash.as_bytes());
        append_length_prefixed(&mut preimage, self.activation_stage.to_string().as_bytes());

        preimage.extend_from_slice(&self.expiry_epoch.as_u64().to_be_bytes());
        preimage.extend_from_slice(self.issuer_key_id.as_bytes());

        preimage
    }

    /// Sign this token with the given key material.
    pub fn sign(mut self, key: &[u8]) -> Self {
        let preimage = self.signing_preimage();
        self.issuer_signature = AuthenticityHash::compute_keyed(key, &preimage);
        self
    }

    /// Verify the token signature.
    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let preimage = self.signing_preimage();
        let expected = AuthenticityHash::compute_keyed(key, &preimage);
        self.issuer_signature == expected
    }

    /// Check if this token has expired relative to the given epoch.
    pub fn is_expired(&self, current_epoch: SecurityEpoch) -> bool {
        current_epoch > self.expiry_epoch
    }

    /// Derive the `EngineObjectId` for this token.
    pub fn object_id(
        &self,
        zone: &str,
    ) -> Result<EngineObjectId, crate::engine_object_id::IdError> {
        let schema_id = SchemaId::from_definition(b"proof_schema::RollbackToken::v1");
        crate::engine_object_id::derive_id(
            ObjectDomain::RecoveryArtifact,
            zone,
            &schema_id,
            &self.signing_preimage(),
        )
    }
}

// ---------------------------------------------------------------------------
// ProofSchemaError
// ---------------------------------------------------------------------------

/// Errors during proof schema validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofSchemaError {
    /// Receipt signature verification failed.
    InvalidSignature { artifact: String },
    /// Schema version is incompatible.
    IncompatibleVersion {
        expected_major: u32,
        actual: SchemaVersion,
    },
    /// Rollback token has expired.
    TokenExpired {
        token_id: String,
        expiry_epoch: u64,
        current_epoch: u64,
    },
    /// Required field is missing or empty.
    MissingField { field: String },
    /// Invariance digest indicates non-equivalence.
    NonEquivalent { reason: String },
    /// Signer role not authorized for this artifact type.
    UnauthorizedSigner { role: SignerRole, artifact: String },
    /// Epoch mismatch between receipt and current epoch.
    EpochMismatch {
        receipt_epoch: u64,
        current_epoch: u64,
    },
    /// Receipt requires attestation bindings but none were provided.
    MissingAttestationBindings { impact: DecisionImpact },
    /// Attestation bindings present on unsupported schema version.
    UnexpectedAttestationBindingsForVersion { schema_version: SchemaVersion },
    /// Attestation bindings failed deterministic validation.
    InvalidAttestationBindings { reason: String },
    /// Attestation nonce has already been observed for this signer key.
    NonceReplay {
        attested_signer_key_id: EngineObjectId,
        nonce_hex: String,
    },
}

impl fmt::Display for ProofSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignature { artifact } => {
                write!(f, "invalid signature on {artifact}")
            }
            Self::IncompatibleVersion {
                expected_major,
                actual,
            } => write!(
                f,
                "incompatible version: expected major {expected_major}, got {actual}"
            ),
            Self::TokenExpired {
                token_id,
                expiry_epoch,
                current_epoch,
            } => write!(
                f,
                "token {token_id} expired at epoch {expiry_epoch} (current: {current_epoch})"
            ),
            Self::MissingField { field } => write!(f, "missing required field: {field}"),
            Self::NonEquivalent { reason } => write!(f, "non-equivalent: {reason}"),
            Self::UnauthorizedSigner { role, artifact } => {
                write!(f, "role {role} not authorized for {artifact}")
            }
            Self::EpochMismatch {
                receipt_epoch,
                current_epoch,
            } => write!(
                f,
                "epoch mismatch: receipt epoch {receipt_epoch}, current {current_epoch}"
            ),
            Self::MissingAttestationBindings { impact } => {
                write!(
                    f,
                    "missing required attestation bindings for impact {impact:?}"
                )
            }
            Self::UnexpectedAttestationBindingsForVersion { schema_version } => write!(
                f,
                "attestation bindings not allowed for schema version {schema_version}"
            ),
            Self::InvalidAttestationBindings { reason } => {
                write!(f, "invalid attestation bindings: {reason}")
            }
            Self::NonceReplay {
                attested_signer_key_id,
                nonce_hex,
            } => write!(
                f,
                "nonce replay detected for signer {} nonce {}",
                attested_signer_key_id.to_hex(),
                nonce_hex
            ),
        }
    }
}

impl std::error::Error for ProofSchemaError {}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate an `OptReceipt` against the given key and current epoch.
pub fn validate_receipt(
    receipt: &OptReceipt,
    signing_key: &[u8],
    current_epoch: SecurityEpoch,
) -> Result<(), ProofSchemaError> {
    validate_receipt_with_policy(
        receipt,
        signing_key,
        current_epoch,
        &AttestationRequirementPolicy::default(),
        None,
    )
}

/// Validate an `OptReceipt` with a caller-supplied attestation policy.
pub fn validate_receipt_with_policy(
    receipt: &OptReceipt,
    signing_key: &[u8],
    current_epoch: SecurityEpoch,
    policy: &AttestationRequirementPolicy,
    mut nonce_registry: Option<&mut ReceiptNonceRegistry>,
) -> Result<(), ProofSchemaError> {
    // Version compatibility.
    if !receipt
        .schema_version
        .is_compatible_with(&proof_schema_version_current())
    {
        return Err(ProofSchemaError::IncompatibleVersion {
            expected_major: proof_schema_version_current().major,
            actual: receipt.schema_version,
        });
    }

    // Required fields.
    if receipt.optimization_id.is_empty() {
        return Err(ProofSchemaError::MissingField {
            field: "optimization_id".to_string(),
        });
    }
    if receipt.rollback_token_id.is_empty() {
        return Err(ProofSchemaError::MissingField {
            field: "rollback_token_id".to_string(),
        });
    }
    if receipt.correlation_id.is_empty() {
        return Err(ProofSchemaError::MissingField {
            field: "correlation_id".to_string(),
        });
    }

    if !receipt.schema_version.supports_attestation_bindings()
        && receipt.attestation_bindings.is_some()
    {
        return Err(ProofSchemaError::UnexpectedAttestationBindingsForVersion {
            schema_version: receipt.schema_version,
        });
    }

    if let Some(bindings) = &receipt.attestation_bindings {
        bindings.validate()?;
        if !bindings.validity_window.contains(receipt.timestamp_ticks) {
            return Err(ProofSchemaError::InvalidAttestationBindings {
                reason: "receipt timestamp outside attestation validity_window".to_string(),
            });
        }
        if bindings.attested_signer_key_id != receipt.signer_key_id {
            return Err(ProofSchemaError::InvalidAttestationBindings {
                reason: "attested_signer_key_id must match signer_key_id".to_string(),
            });
        }
        if let Some(registry) = &mut nonce_registry {
            registry.check_and_record(&bindings.attested_signer_key_id, bindings.nonce)?;
        }
    } else if policy.requires_attestation(receipt) {
        return Err(ProofSchemaError::MissingAttestationBindings {
            impact: receipt.decision_impact,
        });
    }

    // Epoch check.
    if receipt.policy_epoch != current_epoch {
        return Err(ProofSchemaError::EpochMismatch {
            receipt_epoch: receipt.policy_epoch.as_u64(),
            current_epoch: current_epoch.as_u64(),
        });
    }

    // Signature verification.
    if !receipt.verify_signature(signing_key) {
        return Err(ProofSchemaError::InvalidSignature {
            artifact: "OptReceipt".to_string(),
        });
    }

    Ok(())
}

/// Validate a `RollbackToken` against the given key and current epoch.
pub fn validate_rollback_token(
    token: &RollbackToken,
    signing_key: &[u8],
    current_epoch: SecurityEpoch,
) -> Result<(), ProofSchemaError> {
    // Version compatibility.
    if !token
        .schema_version
        .is_compatible_with(&proof_schema_version_current())
    {
        return Err(ProofSchemaError::IncompatibleVersion {
            expected_major: proof_schema_version_current().major,
            actual: token.schema_version,
        });
    }

    // Required fields.
    if token.token_id.is_empty() {
        return Err(ProofSchemaError::MissingField {
            field: "token_id".to_string(),
        });
    }
    if token.optimization_id.is_empty() {
        return Err(ProofSchemaError::MissingField {
            field: "optimization_id".to_string(),
        });
    }

    // Expiry.
    if token.is_expired(current_epoch) {
        return Err(ProofSchemaError::TokenExpired {
            token_id: token.token_id.clone(),
            expiry_epoch: token.expiry_epoch.as_u64(),
            current_epoch: current_epoch.as_u64(),
        });
    }

    // Signature.
    if !token.verify_signature(signing_key) {
        return Err(ProofSchemaError::InvalidSignature {
            artifact: "RollbackToken".to_string(),
        });
    }

    Ok(())
}

/// Check that a signer role is authorized for the given artifact type.
pub fn check_signer_authorization(
    role: SignerRole,
    artifact: &str,
) -> Result<(), ProofSchemaError> {
    let authorized = match artifact {
        "OptReceipt" => role == SignerRole::OptimizerSubsystem,
        "RollbackToken" => {
            role == SignerRole::OptimizerSubsystem || role == SignerRole::PolicyPlane
        }
        "InvarianceDigest" => role == SignerRole::OptimizerSubsystem,
        _ => false,
    };

    if !authorized {
        return Err(ProofSchemaError::UnauthorizedSigner {
            role,
            artifact: artifact.to_string(),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_decision_impact() -> DecisionImpact {
    DecisionImpact::Standard
}

fn decision_impact_bytes(impact: DecisionImpact) -> &'static [u8] {
    match impact {
        DecisionImpact::Standard => b"standard",
        DecisionImpact::HighImpact => b"high_impact",
    }
}

fn format_nonce_hex(nonce: &[u8; 32]) -> String {
    nonce.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Append a length-prefixed byte slice to a preimage buffer.
fn append_length_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::derive_id;

    const TEST_KEY: &[u8] = b"test-signing-key-material-32bytes!";
    const WRONG_KEY: &[u8] = b"wrong-signing-key-material-xxxxx";

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn test_signer_key_id() -> EngineObjectId {
        let schema = SchemaId::from_definition(b"test-signer-key");
        derive_id(ObjectDomain::CapabilityToken, "test-zone", &schema, b"key1").expect("derive id")
    }

    fn test_invariance_digest() -> InvarianceDigest {
        InvarianceDigest {
            schema_version: proof_schema_version_current(),
            golden_corpus_hash: ContentHash::compute(b"golden-corpus"),
            trace_comparison_methodology: TraceComparisonMethodology::DeterministicReplay,
            equivalence_verdict: EquivalenceVerdict::Equivalent,
            witness_chain_root: ContentHash::compute(b"witness-chain"),
        }
    }

    fn test_attestation_bindings() -> ReceiptAttestationBindings {
        ReceiptAttestationBindings {
            quote_digest: ContentHash::compute(b"quote"),
            measurement_id: derive_id(
                ObjectDomain::Attestation,
                "test-zone",
                &SchemaId::from_definition(b"measurement"),
                b"measurement-v1",
            )
            .expect("measurement id"),
            attested_signer_key_id: test_signer_key_id(),
            nonce: [7u8; 32],
            validity_window: AttestationValidityWindow {
                start_timestamp_ticks: 900,
                end_timestamp_ticks: 1200,
            },
        }
    }

    fn test_receipt_unsigned() -> OptReceipt {
        let digest = test_invariance_digest();
        OptReceipt {
            schema_version: proof_schema_version_current(),
            optimization_id: "opt-001".to_string(),
            optimization_class: OptimizationClass::Superinstruction,
            baseline_ir_hash: ContentHash::compute(b"baseline-ir"),
            candidate_ir_hash: ContentHash::compute(b"candidate-ir"),
            translation_witness_hash: ContentHash::compute(b"witness"),
            invariance_digest: digest.content_hash(),
            rollback_token_id: "rtk-001".to_string(),
            replay_compatibility: BTreeMap::from([
                ("engine_version".to_string(), "0.1.0".to_string()),
                ("target_arch".to_string(), "x86_64".to_string()),
            ]),
            policy_epoch: test_epoch(),
            timestamp_ticks: 1000,
            signer_key_id: test_signer_key_id(),
            correlation_id: "corr-001".to_string(),
            decision_impact: DecisionImpact::Standard,
            attestation_bindings: None,
            signature: AuthenticityHash::compute(b"placeholder"),
        }
    }

    fn test_receipt() -> OptReceipt {
        test_receipt_unsigned().sign(TEST_KEY)
    }

    fn test_rollback_unsigned() -> RollbackToken {
        RollbackToken {
            schema_version: proof_schema_version_current(),
            token_id: "rtk-001".to_string(),
            optimization_id: "opt-001".to_string(),
            baseline_snapshot_hash: ContentHash::compute(b"baseline-snapshot"),
            activation_stage: ActivationStage::Shadow,
            expiry_epoch: SecurityEpoch::from_raw(10),
            issuer_key_id: test_signer_key_id(),
            issuer_signature: AuthenticityHash::compute(b"placeholder"),
        }
    }

    fn test_rollback() -> RollbackToken {
        test_rollback_unsigned().sign(TEST_KEY)
    }

    // -- Schema version --

    #[test]
    fn schema_version_compatibility() {
        let v1_0 = SchemaVersion::new(1, 0, 0);
        let v1_1 = SchemaVersion::new(1, 1, 0);
        let v2_0 = SchemaVersion::new(2, 0, 0);

        assert!(v1_0.is_compatible_with(&v1_1));
        assert!(!v1_0.is_compatible_with(&v2_0));
    }

    #[test]
    fn schema_version_display() {
        assert_eq!(proof_schema_version_current().to_string(), "1.1.0");
    }

    // -- InvarianceDigest --

    #[test]
    fn invariance_digest_hash_is_deterministic() {
        let d1 = test_invariance_digest();
        let d2 = test_invariance_digest();
        assert_eq!(d1.content_hash(), d2.content_hash());
    }

    #[test]
    fn invariance_digest_different_verdict_different_hash() {
        let d1 = test_invariance_digest();
        let mut d2 = test_invariance_digest();
        d2.equivalence_verdict = EquivalenceVerdict::NonEquivalent {
            reason: "divergence".to_string(),
        };
        assert_ne!(d1.content_hash(), d2.content_hash());
    }

    #[test]
    fn invariance_digest_different_methodology_different_hash() {
        let d1 = test_invariance_digest();
        let mut d2 = test_invariance_digest();
        d2.trace_comparison_methodology =
            TraceComparisonMethodology::StatisticalCorpus { corpus_size: 1000 };
        assert_ne!(d1.content_hash(), d2.content_hash());
    }

    // -- OptReceipt signing --

    #[test]
    fn receipt_signing_round_trip() {
        let receipt = test_receipt();
        assert!(receipt.verify_signature(TEST_KEY));
    }

    #[test]
    fn receipt_rejects_wrong_key() {
        let receipt = test_receipt();
        assert!(!receipt.verify_signature(WRONG_KEY));
    }

    #[test]
    fn receipt_signing_is_deterministic() {
        let r1 = test_receipt();
        let r2 = test_receipt();
        assert_eq!(r1.signature, r2.signature);
    }

    #[test]
    fn receipt_preimage_changes_with_fields() {
        let r1 = test_receipt();
        let mut r2 = test_receipt_unsigned();
        r2.optimization_id = "opt-002".to_string();
        let r2 = r2.sign(TEST_KEY);
        assert_ne!(r1.signature, r2.signature);
    }

    // -- RollbackToken signing --

    #[test]
    fn rollback_signing_round_trip() {
        let token = test_rollback();
        assert!(token.verify_signature(TEST_KEY));
    }

    #[test]
    fn rollback_rejects_wrong_key() {
        let token = test_rollback();
        assert!(!token.verify_signature(WRONG_KEY));
    }

    #[test]
    fn rollback_signing_is_deterministic() {
        let t1 = test_rollback();
        let t2 = test_rollback();
        assert_eq!(t1.issuer_signature, t2.issuer_signature);
    }

    // -- RollbackToken expiry --

    #[test]
    fn rollback_not_expired_before_expiry_epoch() {
        let token = test_rollback();
        assert!(!token.is_expired(SecurityEpoch::from_raw(5)));
        assert!(!token.is_expired(SecurityEpoch::from_raw(10)));
    }

    #[test]
    fn rollback_expired_after_expiry_epoch() {
        let token = test_rollback();
        assert!(token.is_expired(SecurityEpoch::from_raw(11)));
    }

    // -- Receipt validation --

    #[test]
    fn validate_receipt_success() {
        let receipt = test_receipt();
        assert!(validate_receipt(&receipt, TEST_KEY, test_epoch()).is_ok());
    }

    #[test]
    fn validate_receipt_wrong_key() {
        let receipt = test_receipt();
        assert!(matches!(
            validate_receipt(&receipt, WRONG_KEY, test_epoch()),
            Err(ProofSchemaError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn validate_receipt_wrong_epoch() {
        let receipt = test_receipt();
        assert!(matches!(
            validate_receipt(&receipt, TEST_KEY, SecurityEpoch::from_raw(99)),
            Err(ProofSchemaError::EpochMismatch { .. })
        ));
    }

    #[test]
    fn validate_receipt_incompatible_version() {
        let mut receipt = test_receipt_unsigned();
        receipt.schema_version = SchemaVersion::new(99, 0, 0);
        let receipt = receipt.sign(TEST_KEY);
        assert!(matches!(
            validate_receipt(&receipt, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::IncompatibleVersion { .. })
        ));
    }

    #[test]
    fn validate_receipt_missing_optimization_id() {
        let mut receipt = test_receipt_unsigned();
        receipt.optimization_id = String::new();
        let receipt = receipt.sign(TEST_KEY);
        assert!(matches!(
            validate_receipt(&receipt, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::MissingField { .. })
        ));
    }

    #[test]
    fn validate_receipt_missing_rollback_token_id() {
        let mut receipt = test_receipt_unsigned();
        receipt.rollback_token_id = String::new();
        let receipt = receipt.sign(TEST_KEY);
        assert!(matches!(
            validate_receipt(&receipt, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::MissingField { .. })
        ));
    }

    #[test]
    fn validate_receipt_missing_correlation_id() {
        let mut receipt = test_receipt_unsigned();
        receipt.correlation_id = String::new();
        let receipt = receipt.sign(TEST_KEY);
        assert!(matches!(
            validate_receipt(&receipt, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::MissingField { .. })
        ));
    }

    #[test]
    fn validate_high_impact_receipt_requires_attestation_bindings() {
        let mut receipt = test_receipt_unsigned();
        receipt.decision_impact = DecisionImpact::HighImpact;
        let receipt = receipt.sign(TEST_KEY);
        assert!(matches!(
            validate_receipt(&receipt, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::MissingAttestationBindings { .. })
        ));
    }

    #[test]
    fn validate_high_impact_receipt_with_attestation_bindings() {
        let mut receipt = test_receipt_unsigned();
        receipt.decision_impact = DecisionImpact::HighImpact;
        receipt.attestation_bindings = Some(test_attestation_bindings());
        let receipt = receipt.sign(TEST_KEY);
        assert!(validate_receipt(&receipt, TEST_KEY, test_epoch()).is_ok());
    }

    #[test]
    fn validate_policy_threshold_can_require_standard_receipts() {
        let receipt = test_receipt();
        let policy = AttestationRequirementPolicy {
            require_at_or_above: DecisionImpact::Standard,
            allow_legacy_receipts_without_attestation: true,
        };
        assert!(matches!(
            validate_receipt_with_policy(&receipt, TEST_KEY, test_epoch(), &policy, None),
            Err(ProofSchemaError::MissingAttestationBindings { .. })
        ));
    }

    #[test]
    fn validate_legacy_high_impact_without_attestation_is_policy_controlled() {
        let mut receipt = test_receipt_unsigned();
        receipt.schema_version = proof_schema_version_v1_0();
        receipt.decision_impact = DecisionImpact::HighImpact;
        let receipt = receipt.sign(TEST_KEY);

        assert!(validate_receipt(&receipt, TEST_KEY, test_epoch()).is_ok());

        let strict_policy = AttestationRequirementPolicy {
            require_at_or_above: DecisionImpact::HighImpact,
            allow_legacy_receipts_without_attestation: false,
        };
        assert!(matches!(
            validate_receipt_with_policy(&receipt, TEST_KEY, test_epoch(), &strict_policy, None),
            Err(ProofSchemaError::MissingAttestationBindings { .. })
        ));
    }

    #[test]
    fn validate_attestation_bindings_not_allowed_before_v1_1() {
        let mut receipt = test_receipt_unsigned();
        receipt.schema_version = proof_schema_version_v1_0();
        receipt.attestation_bindings = Some(test_attestation_bindings());
        let receipt = receipt.sign(TEST_KEY);
        assert!(matches!(
            validate_receipt(&receipt, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::UnexpectedAttestationBindingsForVersion { .. })
        ));
    }

    #[test]
    fn validate_attestation_nonce_replay_detected() {
        let mut nonce_registry = ReceiptNonceRegistry::new();

        let mut receipt = test_receipt_unsigned();
        receipt.decision_impact = DecisionImpact::HighImpact;
        receipt.attestation_bindings = Some(test_attestation_bindings());
        let receipt = receipt.sign(TEST_KEY);

        assert!(
            validate_receipt_with_policy(
                &receipt,
                TEST_KEY,
                test_epoch(),
                &AttestationRequirementPolicy::default(),
                Some(&mut nonce_registry),
            )
            .is_ok()
        );

        let second = receipt.clone();
        assert!(matches!(
            validate_receipt_with_policy(
                &second,
                TEST_KEY,
                test_epoch(),
                &AttestationRequirementPolicy::default(),
                Some(&mut nonce_registry),
            ),
            Err(ProofSchemaError::NonceReplay { .. })
        ));
    }

    // -- Token validation --

    #[test]
    fn validate_token_success() {
        let token = test_rollback();
        assert!(validate_rollback_token(&token, TEST_KEY, test_epoch()).is_ok());
    }

    #[test]
    fn validate_token_wrong_key() {
        let token = test_rollback();
        assert!(matches!(
            validate_rollback_token(&token, WRONG_KEY, test_epoch()),
            Err(ProofSchemaError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn validate_token_expired() {
        let token = test_rollback();
        assert!(matches!(
            validate_rollback_token(&token, TEST_KEY, SecurityEpoch::from_raw(11)),
            Err(ProofSchemaError::TokenExpired { .. })
        ));
    }

    #[test]
    fn validate_token_incompatible_version() {
        let mut token = test_rollback_unsigned();
        token.schema_version = SchemaVersion::new(99, 0, 0);
        let token = token.sign(TEST_KEY);
        assert!(matches!(
            validate_rollback_token(&token, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::IncompatibleVersion { .. })
        ));
    }

    #[test]
    fn validate_token_missing_token_id() {
        let mut token = test_rollback_unsigned();
        token.token_id = String::new();
        let token = token.sign(TEST_KEY);
        assert!(matches!(
            validate_rollback_token(&token, TEST_KEY, test_epoch()),
            Err(ProofSchemaError::MissingField { .. })
        ));
    }

    // -- Signer authorization --

    #[test]
    fn optimizer_authorized_for_receipt() {
        assert!(check_signer_authorization(SignerRole::OptimizerSubsystem, "OptReceipt").is_ok());
    }

    #[test]
    fn policy_plane_not_authorized_for_receipt() {
        assert!(matches!(
            check_signer_authorization(SignerRole::PolicyPlane, "OptReceipt"),
            Err(ProofSchemaError::UnauthorizedSigner { .. })
        ));
    }

    #[test]
    fn policy_plane_authorized_for_rollback_token() {
        assert!(check_signer_authorization(SignerRole::PolicyPlane, "RollbackToken").is_ok());
    }

    #[test]
    fn attestation_cell_not_authorized_for_receipt() {
        assert!(matches!(
            check_signer_authorization(SignerRole::AttestationCell, "OptReceipt"),
            Err(ProofSchemaError::UnauthorizedSigner { .. })
        ));
    }

    // -- Object IDs --

    #[test]
    fn receipt_object_id_is_deterministic() {
        let r1 = test_receipt();
        let r2 = test_receipt();
        assert_eq!(
            r1.object_id("zone-a").unwrap(),
            r2.object_id("zone-a").unwrap()
        );
    }

    #[test]
    fn receipt_object_id_differs_by_zone() {
        let receipt = test_receipt();
        assert_ne!(
            receipt.object_id("zone-a").unwrap(),
            receipt.object_id("zone-b").unwrap()
        );
    }

    #[test]
    fn rollback_object_id_is_deterministic() {
        let t1 = test_rollback();
        let t2 = test_rollback();
        assert_eq!(
            t1.object_id("zone-a").unwrap(),
            t2.object_id("zone-a").unwrap()
        );
    }

    // -- Serialization --

    #[test]
    fn receipt_serialization_round_trip() {
        let receipt = test_receipt();
        let json = serde_json::to_string(&receipt).expect("serialize");
        let restored: OptReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, restored);
    }

    #[test]
    fn receipt_with_attestation_serialization_round_trip() {
        let mut receipt = test_receipt_unsigned();
        receipt.decision_impact = DecisionImpact::HighImpact;
        receipt.attestation_bindings = Some(test_attestation_bindings());
        let receipt = receipt.sign(TEST_KEY);
        let encoded = serde_json::to_vec(&receipt).expect("serialize");
        let restored: OptReceipt = serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(receipt, restored);
        assert_eq!(serde_json::to_vec(&restored).unwrap(), encoded);
    }

    #[test]
    fn legacy_preimage_ignores_attestation_fields_by_version() {
        let mut legacy_a = test_receipt_unsigned();
        legacy_a.schema_version = proof_schema_version_v1_0();
        legacy_a.decision_impact = DecisionImpact::Standard;
        legacy_a.attestation_bindings = None;

        let mut legacy_b = legacy_a.clone();
        legacy_b.decision_impact = DecisionImpact::HighImpact;
        legacy_b.attestation_bindings = Some(test_attestation_bindings());

        assert_eq!(legacy_a.signing_preimage(), legacy_b.signing_preimage());
    }

    #[test]
    fn rollback_serialization_round_trip() {
        let token = test_rollback();
        let json = serde_json::to_string(&token).expect("serialize");
        let restored: RollbackToken = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(token, restored);
    }

    #[test]
    fn invariance_digest_serialization_round_trip() {
        let digest = test_invariance_digest();
        let json = serde_json::to_string(&digest).expect("serialize");
        let restored: InvarianceDigest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(digest, restored);
    }

    #[test]
    fn proof_schema_error_serialization_round_trip() {
        let errors = vec![
            ProofSchemaError::InvalidSignature {
                artifact: "OptReceipt".to_string(),
            },
            ProofSchemaError::TokenExpired {
                token_id: "rtk-1".to_string(),
                expiry_epoch: 10,
                current_epoch: 11,
            },
            ProofSchemaError::MissingField {
                field: "optimization_id".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ProofSchemaError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- Error display --

    #[test]
    fn error_display_messages() {
        assert!(
            ProofSchemaError::InvalidSignature {
                artifact: "test".to_string()
            }
            .to_string()
            .contains("test")
        );
        assert!(
            ProofSchemaError::TokenExpired {
                token_id: "rtk-1".to_string(),
                expiry_epoch: 5,
                current_epoch: 6,
            }
            .to_string()
            .contains("rtk-1")
        );
    }

    // -- Display traits --

    #[test]
    fn optimization_class_display() {
        assert_eq!(
            OptimizationClass::Superinstruction.to_string(),
            "superinstruction"
        );
        assert_eq!(
            OptimizationClass::DevirtualizedHostcallFastPath.to_string(),
            "devirtualized_hostcall_fast_path"
        );
    }

    #[test]
    fn activation_stage_display() {
        assert_eq!(ActivationStage::Shadow.to_string(), "shadow");
        assert_eq!(ActivationStage::Default.to_string(), "default");
    }

    #[test]
    fn signer_role_display() {
        assert_eq!(
            SignerRole::OptimizerSubsystem.to_string(),
            "optimizer_subsystem"
        );
    }

    // -- Enrichment: std::error --

    #[test]
    fn proof_schema_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ProofSchemaError::InvalidSignature {
                artifact: "proof".into(),
            }),
            Box::new(ProofSchemaError::MissingField {
                field: "name".into(),
            }),
            Box::new(ProofSchemaError::NonEquivalent {
                reason: "mismatch".into(),
            }),
            Box::new(ProofSchemaError::UnauthorizedSigner {
                role: SignerRole::OptimizerSubsystem,
                artifact: "receipt".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 tested variants produce distinct messages"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn optimization_class_display_uniqueness() {
        let displays: BTreeSet<String> = [
            OptimizationClass::Superinstruction,
            OptimizationClass::TraceSpecialization,
            OptimizationClass::LayoutSpecialization,
            OptimizationClass::DevirtualizedHostcallFastPath,
        ]
        .iter()
        .map(|c| c.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn activation_stage_display_uniqueness() {
        let displays: BTreeSet<String> = [
            ActivationStage::Shadow,
            ActivationStage::Canary,
            ActivationStage::Ramp,
            ActivationStage::Default,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn signer_role_display_uniqueness() {
        let displays: BTreeSet<String> = [
            SignerRole::OptimizerSubsystem,
            SignerRole::PolicyPlane,
            SignerRole::AttestationCell,
        ]
        .iter()
        .map(|r| r.to_string())
        .collect();
        assert_eq!(displays.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Enrichment: schema version helpers
    // -----------------------------------------------------------------------

    #[test]
    fn schema_version_v1_0_does_not_support_attestation() {
        let v1_0 = proof_schema_version_v1_0();
        assert!(!v1_0.supports_attestation_bindings());
    }

    #[test]
    fn schema_version_v1_1_supports_attestation() {
        let v1_1 = proof_schema_version_v1_1();
        assert!(v1_1.supports_attestation_bindings());
    }

    #[test]
    fn schema_version_current_equals_v1_1() {
        assert_eq!(proof_schema_version_current(), proof_schema_version_v1_1());
    }

    // -----------------------------------------------------------------------
    // Enrichment: attestation validity window serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn attestation_validity_window_serde_roundtrip() {
        let window = AttestationValidityWindow {
            start_timestamp_ticks: 100,
            end_timestamp_ticks: 200,
        };
        let json = serde_json::to_string(&window).expect("serialize");
        let restored: AttestationValidityWindow = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(window, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: nonce registry serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn nonce_registry_serde_roundtrip() {
        let mut registry = ReceiptNonceRegistry::new();
        let key_id = test_signer_key_id();
        // Record a nonce via the public API.
        registry
            .check_and_record(&key_id, [42u8; 32])
            .expect("first record");
        let json = serde_json::to_string(&registry).expect("serialize");
        let restored: ReceiptNonceRegistry = serde_json::from_str(&json).expect("deserialize");
        // The restored registry should detect replay of the same nonce.
        let mut restored = restored;
        assert!(restored.check_and_record(&key_id, [42u8; 32]).is_err());
    }

    // -----------------------------------------------------------------------
    // Enrichment: attestation requirement policy default
    // -----------------------------------------------------------------------

    #[test]
    fn attestation_requirement_policy_default_roundtrip() {
        let policy = AttestationRequirementPolicy::default();
        let json = serde_json::to_string(&policy).expect("serialize");
        let restored: AttestationRequirementPolicy =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, restored);
    }

    // ── enrichment tests ────────────────────────────────────

    #[test]
    fn activation_stage_copy_semantics() {
        let a = ActivationStage::Shadow;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn signer_role_copy_semantics() {
        let a = SignerRole::OptimizerSubsystem;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn optimization_class_all_variants_serde_distinct() {
        let variants = [
            OptimizationClass::Superinstruction,
            OptimizationClass::TraceSpecialization,
            OptimizationClass::LayoutSpecialization,
            OptimizationClass::DevirtualizedHostcallFastPath,
        ];
        let jsons: Vec<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        for (i, a) in jsons.iter().enumerate() {
            for (j, b) in jsons.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn activation_stage_all_variants_serde_distinct() {
        let variants = [
            ActivationStage::Shadow,
            ActivationStage::Canary,
            ActivationStage::Ramp,
            ActivationStage::Default,
        ];
        let jsons: Vec<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        for (i, a) in jsons.iter().enumerate() {
            for (j, b) in jsons.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn equivalence_verdict_all_variants_serde_distinct() {
        let variants = [
            EquivalenceVerdict::Equivalent,
            EquivalenceVerdict::NonEquivalent {
                reason: "mismatch".to_string(),
            },
            EquivalenceVerdict::Inconclusive {
                reason: "timeout".to_string(),
            },
        ];
        let jsons: Vec<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        for (i, a) in jsons.iter().enumerate() {
            for (j, b) in jsons.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn trace_comparison_methodology_all_variants_serde_distinct() {
        let variants = [
            TraceComparisonMethodology::DeterministicReplay,
            TraceComparisonMethodology::SymbolicEquivalence,
            TraceComparisonMethodology::StatisticalCorpus { corpus_size: 100 },
        ];
        let jsons: Vec<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        for (i, a) in jsons.iter().enumerate() {
            for (j, b) in jsons.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn signer_role_all_variants_serde_distinct() {
        let variants = [
            SignerRole::OptimizerSubsystem,
            SignerRole::PolicyPlane,
            SignerRole::AttestationCell,
        ];
        let jsons: Vec<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        for (i, a) in jsons.iter().enumerate() {
            for (j, b) in jsons.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn optimization_class_debug_distinct() {
        let variants = [
            OptimizationClass::Superinstruction,
            OptimizationClass::TraceSpecialization,
            OptimizationClass::LayoutSpecialization,
            OptimizationClass::DevirtualizedHostcallFastPath,
        ];
        let dbgs: Vec<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        for (i, a) in dbgs.iter().enumerate() {
            assert!(!a.is_empty());
            for (j, b) in dbgs.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn activation_stage_debug_distinct() {
        let variants = [
            ActivationStage::Shadow,
            ActivationStage::Canary,
            ActivationStage::Ramp,
            ActivationStage::Default,
        ];
        let dbgs: Vec<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        for (i, a) in dbgs.iter().enumerate() {
            assert!(!a.is_empty());
            for (j, b) in dbgs.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn signer_key_id_clone_independence() {
        let s = SignerKeyId {
            key_id: test_signer_key_id(),
            role: SignerRole::PolicyPlane,
            bound_epoch: test_epoch(),
        };
        let mut cloned = s.clone();
        cloned.role = SignerRole::AttestationCell;
        assert_eq!(cloned.role, SignerRole::AttestationCell);
        assert_eq!(s.role, SignerRole::PolicyPlane);
    }

    #[test]
    fn invariance_digest_clone_independence() {
        let d = test_invariance_digest();
        let mut cloned = d.clone();
        cloned.equivalence_verdict = EquivalenceVerdict::NonEquivalent {
            reason: "changed".to_string(),
        };
        assert!(matches!(
            cloned.equivalence_verdict,
            EquivalenceVerdict::NonEquivalent { ref reason } if reason == "changed"
        ));
        assert_eq!(d.equivalence_verdict, EquivalenceVerdict::Equivalent);
    }

    #[test]
    fn opt_receipt_clone_independence() {
        let r = test_receipt();
        let mut cloned = r.clone();
        cloned.optimization_id = "changed".to_string();
        assert_eq!(cloned.optimization_id, "changed");
        assert_eq!(r.optimization_id, "opt-001");
    }

    #[test]
    fn rollback_token_clone_independence() {
        let t = test_rollback();
        let mut cloned = t.clone();
        cloned.token_id = "changed".to_string();
        assert_eq!(cloned.token_id, "changed");
        assert_eq!(t.token_id, "rtk-001");
    }

    #[test]
    fn invariance_digest_json_field_names() {
        let d = test_invariance_digest();
        let j = serde_json::to_string(&d).unwrap();
        for field in &[
            "schema_version",
            "golden_corpus_hash",
            "trace_comparison_methodology",
            "equivalence_verdict",
            "witness_chain_root",
        ] {
            assert!(j.contains(field), "missing: {field}");
        }
    }

    #[test]
    fn opt_receipt_json_field_names() {
        let r = test_receipt();
        let j = serde_json::to_string(&r).unwrap();
        for field in &[
            "schema_version",
            "optimization_id",
            "optimization_class",
            "baseline_ir_hash",
            "candidate_ir_hash",
            "rollback_token_id",
            "policy_epoch",
            "timestamp_ticks",
            "correlation_id",
            "signature",
        ] {
            assert!(j.contains(field), "missing: {field}");
        }
    }

    #[test]
    fn rollback_token_json_field_names() {
        let t = test_rollback();
        let j = serde_json::to_string(&t).unwrap();
        for field in &[
            "schema_version",
            "token_id",
            "optimization_id",
            "baseline_snapshot_hash",
            "activation_stage",
            "expiry_epoch",
            "signature",
        ] {
            assert!(j.contains(field), "missing: {field}");
        }
    }

    #[test]
    fn signer_key_id_json_field_names() {
        let s = SignerKeyId {
            key_id: test_signer_key_id(),
            role: SignerRole::OptimizerSubsystem,
            bound_epoch: test_epoch(),
        };
        let j = serde_json::to_string(&s).unwrap();
        for field in &["key_id", "role", "bound_epoch"] {
            assert!(j.contains(field), "missing: {field}");
        }
    }

    #[test]
    fn attestation_validity_window_json_field_names() {
        let w = AttestationValidityWindow {
            start_timestamp_ticks: 100,
            end_timestamp_ticks: 200,
        };
        let j = serde_json::to_string(&w).unwrap();
        assert!(j.contains("start_timestamp_ticks"));
        assert!(j.contains("end_timestamp_ticks"));
    }

    #[test]
    fn schema_version_v1_0_is_compatible_with_v1_1() {
        let v10 = proof_schema_version_v1_0();
        let v11 = proof_schema_version_v1_1();
        assert!(v10.is_compatible_with(&v11));
        assert!(v11.is_compatible_with(&v10));
    }

    #[test]
    fn schema_version_v1_0_does_not_support_attestation_enrichment_block() {
        let v10 = proof_schema_version_v1_0();
        assert!(!v10.supports_attestation_bindings());
    }

    #[test]
    fn schema_version_v1_1_supports_attestation_enrichment_block() {
        let v11 = proof_schema_version_v1_1();
        assert!(v11.supports_attestation_bindings());
    }

    #[test]
    fn schema_version_current_is_v1_1() {
        let current = proof_schema_version_current();
        let v11 = proof_schema_version_v1_1();
        assert_eq!(current, v11);
    }

    #[test]
    fn attestation_binding_intro_is_v1_1() {
        let intro = proof_schema_attestation_binding_intro();
        let v11 = proof_schema_version_v1_1();
        assert_eq!(intro, v11);
    }

    #[test]
    fn schema_version_major_minor_accessors() {
        let v = proof_schema_version_v1_1();
        assert_eq!(v.major_val(), 1);
        assert_eq!(v.minor_val(), 1);
    }

    #[test]
    fn proof_schema_error_debug_nonempty_enriched() {
        let e = ProofSchemaError::InvalidSignature {
            artifact: "receipt".to_string(),
        };
        let dbg = format!("{e:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("InvalidSignature"));
    }

    #[test]
    fn proof_schema_error_clone_independence_enriched() {
        let e = ProofSchemaError::InvalidSignature {
            artifact: "receipt".to_string(),
        };
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    #[test]
    fn receipt_nonce_registry_starts_empty() {
        let r = ReceiptNonceRegistry::new();
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("seen"));
    }

    #[test]
    fn receipt_nonce_registry_detects_replay() {
        let mut reg = ReceiptNonceRegistry::new();
        let key_id = test_signer_key_id();
        let nonce = [42u8; 32];
        assert!(reg.check_and_record(&key_id, nonce).is_ok());
        assert!(reg.check_and_record(&key_id, nonce).is_err());
    }

    #[test]
    fn receipt_nonce_registry_allows_different_nonces() {
        let mut reg = ReceiptNonceRegistry::new();
        let key_id = test_signer_key_id();
        assert!(reg.check_and_record(&key_id, [1u8; 32]).is_ok());
        assert!(reg.check_and_record(&key_id, [2u8; 32]).is_ok());
    }

    #[test]
    fn activation_stage_ordering() {
        assert!(ActivationStage::Shadow < ActivationStage::Canary);
        assert!(ActivationStage::Canary < ActivationStage::Ramp);
        assert!(ActivationStage::Ramp < ActivationStage::Default);
    }

    #[test]
    fn optimization_class_ordering() {
        assert!(OptimizationClass::Superinstruction < OptimizationClass::TraceSpecialization);
        assert!(OptimizationClass::TraceSpecialization < OptimizationClass::LayoutSpecialization);
    }

    #[test]
    fn signer_role_ordering() {
        assert!(SignerRole::OptimizerSubsystem < SignerRole::PolicyPlane);
        assert!(SignerRole::PolicyPlane < SignerRole::AttestationCell);
    }

    #[test]
    fn attestation_validity_window_clone_independence() {
        let w = AttestationValidityWindow {
            start_timestamp_ticks: 100,
            end_timestamp_ticks: 200,
        };
        let mut cloned = w.clone();
        cloned.start_timestamp_ticks = 999;
        assert_eq!(cloned.start_timestamp_ticks, 999);
        assert_eq!(w.start_timestamp_ticks, 100);
    }

    #[test]
    fn receipt_attestation_bindings_json_field_names() {
        let b = test_attestation_bindings();
        let j = serde_json::to_string(&b).unwrap();
        for field in &[
            "quote_digest",
            "measurement_id",
            "attested_signer_key_id",
            "nonce",
            "validity_window",
        ] {
            assert!(j.contains(field), "missing: {field}");
        }
    }

    #[test]
    fn receipt_attestation_bindings_clone_independence() {
        let b = test_attestation_bindings();
        let cloned = b.clone();
        assert_eq!(b, cloned);
    }

    #[test]
    fn attestation_requirement_policy_copy_semantics() {
        let p = AttestationRequirementPolicy::default();
        let q = p;
        assert_eq!(p, q);
    }

    #[test]
    fn attestation_requirement_policy_json_field_names() {
        let p = AttestationRequirementPolicy::default();
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("require_at_or_above"));
        assert!(j.contains("allow_legacy_receipts_without_attestation"));
    }

    #[test]
    fn signer_key_id_serde_roundtrip() {
        let s = SignerKeyId {
            key_id: test_signer_key_id(),
            role: SignerRole::AttestationCell,
            bound_epoch: test_epoch(),
        };
        let j = serde_json::to_string(&s).unwrap();
        let restored: SignerKeyId = serde_json::from_str(&j).unwrap();
        assert_eq!(s, restored);
    }

    #[test]
    fn signer_key_id_ordering() {
        let a = SignerKeyId {
            key_id: test_signer_key_id(),
            role: SignerRole::OptimizerSubsystem,
            bound_epoch: test_epoch(),
        };
        let b = SignerKeyId {
            key_id: test_signer_key_id(),
            role: SignerRole::PolicyPlane,
            bound_epoch: test_epoch(),
        };
        assert!(a < b);
    }

    #[test]
    fn receipt_attestation_bindings_serde_roundtrip() {
        let b = test_attestation_bindings();
        let j = serde_json::to_string(&b).unwrap();
        let restored: ReceiptAttestationBindings = serde_json::from_str(&j).unwrap();
        assert_eq!(b, restored);
    }
}
