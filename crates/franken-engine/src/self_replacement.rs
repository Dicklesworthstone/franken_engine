//! Verified self-replacement schema for the Verified Self-Replacement
//! Architecture.
//!
//! Extends [`crate::slot_registry`] with signed artifacts that make
//! delegate-to-native replacement verifiable and auditable.  Every
//! promotion step is captured in a cryptographically signed receipt
//! with multi-party attestation.
//!
//! Schema components:
//! - [`DelegateCellManifest`]: per-delegate-cell descriptor with sandbox
//!   configuration and behavioral contract.
//! - [`ReplacementReceipt`]: signed artifact linking old/new cell digests
//!   with validation evidence.
//! - [`PromotionDecision`]: gate-results decision artifact with verdict
//!   and risk assessment.
//!
//! Plan references: Section 10.15 item 1 (9I.6), bd-7rwi.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, SchemaHash};
use crate::engine_object_id::{self, EngineObjectId, IdError, ObjectDomain};
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    self, SIGNATURE_SENTINEL, Signature, SignatureError, SignaturePreimage, SigningKey,
    VerificationKey,
};
use crate::slot_registry::{AuthorityEnvelope, SlotId};

// ---------------------------------------------------------------------------
// Schema versioning
// ---------------------------------------------------------------------------

/// Schema version for self-replacement artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SchemaVersion {
    /// Initial version.
    V1,
}

impl SchemaVersion {
    /// Encode as canonical bytes for schema hash input.
    #[allow(dead_code)]
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::V1 => b"self-replacement.v1",
        }
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => f.write_str("v1"),
        }
    }
}

// ---------------------------------------------------------------------------
// Schema hashes (lazy static equivalents via const fn)
// ---------------------------------------------------------------------------

fn manifest_schema_hash() -> SchemaHash {
    SchemaHash::from_definition(b"self-replacement.delegate-cell-manifest.v1")
}

fn receipt_schema_hash() -> SchemaHash {
    SchemaHash::from_definition(b"self-replacement.replacement-receipt.v1")
}

fn decision_schema_hash() -> SchemaHash {
    SchemaHash::from_definition(b"self-replacement.promotion-decision.v1")
}

// ---------------------------------------------------------------------------
// SignatureBundle — multi-party signature container
// ---------------------------------------------------------------------------

/// A signature with its verification key for multi-party signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerEntry {
    /// Role of the signer (e.g., "gate-runner", "governance-approver").
    pub role: String,
    /// Verification key of the signer.
    pub verification_key: VerificationKey,
    /// The signature.
    pub signature: Signature,
}

/// Multi-party signature bundle.
///
/// Some artifacts (replacement receipts, promotion decisions) require
/// signatures from multiple parties to be valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBundle {
    /// Required minimum number of valid signatures.
    pub threshold: u32,
    /// Ordered (deterministic) list of signer entries.
    pub signers: Vec<SignerEntry>,
}

impl SignatureBundle {
    /// Create a new bundle with the given threshold.
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold,
            signers: Vec::new(),
        }
    }

    /// Add a signer entry.
    pub fn add_signer(&mut self, entry: SignerEntry) {
        self.signers.push(entry);
    }

    /// Whether enough valid signatures are present to meet the threshold.
    pub fn meets_threshold(&self) -> bool {
        self.signers.len() as u32 >= self.threshold
    }

    /// Verify all signatures against a preimage.
    pub fn verify_all(&self, preimage: &[u8]) -> Result<(), SelfReplacementError> {
        if !self.meets_threshold() {
            return Err(SelfReplacementError::InsufficientSignatures {
                required: self.threshold,
                present: self.signers.len() as u32,
            });
        }
        for (i, entry) in self.signers.iter().enumerate() {
            signature_preimage::verify_signature(
                &entry.verification_key,
                preimage,
                &entry.signature,
            )
            .map_err(|_| SelfReplacementError::SignatureInvalid {
                signer_index: i as u32,
                role: entry.role.clone(),
            })?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DelegateType — type of delegate implementation
// ---------------------------------------------------------------------------

/// Type of delegate cell implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DelegateType {
    /// QuickJS-backed delegate cell.
    QuickJsBacked,
    /// Wasm-backed delegate cell.
    WasmBacked,
    /// External process delegate.
    ExternalProcess,
}

impl fmt::Display for DelegateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QuickJsBacked => f.write_str("quickjs-backed"),
            Self::WasmBacked => f.write_str("wasm-backed"),
            Self::ExternalProcess => f.write_str("external-process"),
        }
    }
}

// ---------------------------------------------------------------------------
// SandboxConfiguration — delegate cell sandbox parameters
// ---------------------------------------------------------------------------

/// Sandbox configuration for a delegate cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxConfiguration {
    /// Maximum heap size in bytes.
    pub max_heap_bytes: u64,
    /// Maximum execution time per invocation (nanoseconds).
    pub max_execution_ns: u64,
    /// Maximum number of hostcalls per invocation.
    pub max_hostcalls: u64,
    /// Whether network egress is permitted.
    pub network_egress_allowed: bool,
    /// Whether filesystem access is permitted.
    pub filesystem_access_allowed: bool,
}

impl Default for SandboxConfiguration {
    fn default() -> Self {
        Self {
            max_heap_bytes: 64 * 1024 * 1024, // 64 MiB
            max_execution_ns: 5_000_000_000,  // 5 seconds
            max_hostcalls: 10_000,
            network_egress_allowed: false,
            filesystem_access_allowed: false,
        }
    }
}

// ---------------------------------------------------------------------------
// MonitoringHook — delegate cell monitoring configuration
// ---------------------------------------------------------------------------

/// Monitoring hook specification for a delegate cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitoringHook {
    /// Hook identifier.
    pub hook_id: String,
    /// Event that triggers the hook.
    pub trigger_event: String,
    /// Whether the hook blocks execution until complete.
    pub blocking: bool,
}

// ---------------------------------------------------------------------------
// DelegateCellManifest — per-delegate-cell descriptor
// ---------------------------------------------------------------------------

/// Manifest describing a delegate cell that occupies a replaceable slot.
///
/// Contains everything needed to instantiate, sandbox, and monitor a
/// delegate cell.  The manifest is content-addressed via its
/// [`EngineObjectId`] for immutable reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegateCellManifest {
    /// Content-addressed manifest identifier.
    pub manifest_id: EngineObjectId,
    /// Schema version.
    pub schema_version: SchemaVersion,
    /// Slot this delegate occupies.
    pub slot_id: SlotId,
    /// Type of delegate implementation.
    pub delegate_type: DelegateType,
    /// Capability envelope (what the delegate needs and is allowed).
    pub capability_envelope: AuthorityEnvelope,
    /// Sandbox configuration.
    pub sandbox: SandboxConfiguration,
    /// Monitoring hooks.
    pub monitoring_hooks: Vec<MonitoringHook>,
    /// Hash of expected behavioral contract for replay verification.
    pub expected_behavior_hash: [u8; 32],
    /// Zone scoping.
    pub zone: String,
    /// Signature over the manifest contents.
    pub signature: Signature,
}

impl DelegateCellManifest {
    /// Derive the manifest ID from its contents.
    pub fn derive_manifest_id(
        slot_id: &SlotId,
        delegate_type: DelegateType,
        behavior_hash: &[u8; 32],
        zone: &str,
    ) -> Result<EngineObjectId, IdError> {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(slot_id.as_str().as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(delegate_type.to_string().as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(behavior_hash);
        let schema_id =
            engine_object_id::SchemaId::from_definition(manifest_schema_hash().0.as_slice());
        engine_object_id::derive_id(ObjectDomain::SignedManifest, zone, &schema_id, &canonical)
    }

    /// Create a signed manifest.
    pub fn create_signed(
        signing_key: &SigningKey,
        input: CreateManifestInput<'_>,
    ) -> Result<Self, SelfReplacementError> {
        let manifest_id = Self::derive_manifest_id(
            input.slot_id,
            input.delegate_type,
            input.expected_behavior_hash,
            input.zone,
        )
        .map_err(SelfReplacementError::IdDerivationFailed)?;

        let mut manifest = Self {
            manifest_id,
            schema_version: SchemaVersion::V1,
            slot_id: input.slot_id.clone(),
            delegate_type: input.delegate_type,
            capability_envelope: input.capability_envelope.clone(),
            sandbox: input.sandbox.clone(),
            monitoring_hooks: input.monitoring_hooks.to_vec(),
            expected_behavior_hash: *input.expected_behavior_hash,
            zone: input.zone.to_string(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };

        let sig = signature_preimage::sign_object(&manifest, signing_key)
            .map_err(SelfReplacementError::SignatureFailed)?;
        manifest.signature = sig;
        Ok(manifest)
    }

    /// Verify the manifest signature.
    pub fn verify_signature(&self, vk: &VerificationKey) -> Result<(), SelfReplacementError> {
        signature_preimage::verify_object(self, vk, &self.signature)
            .map_err(SelfReplacementError::SignatureFailed)
    }
}

/// Input for creating a delegate cell manifest.
pub struct CreateManifestInput<'a> {
    pub slot_id: &'a SlotId,
    pub delegate_type: DelegateType,
    pub capability_envelope: &'a AuthorityEnvelope,
    pub sandbox: &'a SandboxConfiguration,
    pub monitoring_hooks: &'a [MonitoringHook],
    pub expected_behavior_hash: &'a [u8; 32],
    pub zone: &'a str,
}

impl SignaturePreimage for DelegateCellManifest {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::SignedManifest
    }

    fn signature_schema(&self) -> &SchemaHash {
        // Return a reference that lives long enough.
        // We use a thread-local or leak a static. Since SchemaHash is small,
        // we compute it fresh each time (deterministic).
        // However, the trait requires &SchemaHash. We use Box::leak for a
        // 'static reference. This is safe because schema hashes are fixed.
        // Actually, let's use a different approach — store in a const-like pattern.
        lazy_static_schema_hash(&manifest_schema_hash())
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "capability_envelope_permitted".to_string(),
            CanonicalValue::Array(
                self.capability_envelope
                    .permitted
                    .iter()
                    .map(|c| CanonicalValue::String(serde_json::to_string(c).unwrap_or_default()))
                    .collect(),
            ),
        );
        map.insert(
            "capability_envelope_required".to_string(),
            CanonicalValue::Array(
                self.capability_envelope
                    .required
                    .iter()
                    .map(|c| CanonicalValue::String(serde_json::to_string(c).unwrap_or_default()))
                    .collect(),
            ),
        );
        map.insert(
            "delegate_type".to_string(),
            CanonicalValue::String(self.delegate_type.to_string()),
        );
        map.insert(
            "expected_behavior_hash".to_string(),
            CanonicalValue::Bytes(self.expected_behavior_hash.to_vec()),
        );
        map.insert(
            "manifest_id".to_string(),
            CanonicalValue::Bytes(self.manifest_id.as_bytes().to_vec()),
        );
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.to_string()),
        );
        map.insert(
            "signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        map.insert(
            "sandbox_filesystem_access_allowed".to_string(),
            CanonicalValue::Bool(self.sandbox.filesystem_access_allowed),
        );
        map.insert(
            "sandbox_max_execution_ns".to_string(),
            CanonicalValue::U64(self.sandbox.max_execution_ns),
        );
        map.insert(
            "sandbox_max_heap_bytes".to_string(),
            CanonicalValue::U64(self.sandbox.max_heap_bytes),
        );
        map.insert(
            "sandbox_max_hostcalls".to_string(),
            CanonicalValue::U64(self.sandbox.max_hostcalls),
        );
        map.insert(
            "sandbox_network_egress_allowed".to_string(),
            CanonicalValue::Bool(self.sandbox.network_egress_allowed),
        );
        map.insert(
            "slot_id".to_string(),
            CanonicalValue::String(self.slot_id.as_str().to_string()),
        );
        map.insert(
            "zone".to_string(),
            CanonicalValue::String(self.zone.clone()),
        );
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// ValidationArtifactRef — reference to a validation result
// ---------------------------------------------------------------------------

/// Type of validation artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ValidationArtifactKind {
    /// Behavioral equivalence test results.
    EquivalenceResult,
    /// Capability-preservation proof.
    CapabilityPreservation,
    /// Performance benchmark results.
    PerformanceBenchmark,
    /// Adversarial survival test results.
    AdversarialSurvival,
}

impl fmt::Display for ValidationArtifactKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EquivalenceResult => f.write_str("equivalence"),
            Self::CapabilityPreservation => f.write_str("capability-preservation"),
            Self::PerformanceBenchmark => f.write_str("performance-benchmark"),
            Self::AdversarialSurvival => f.write_str("adversarial-survival"),
        }
    }
}

/// Reference to a validation artifact with pass/fail result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationArtifactRef {
    /// Kind of validation.
    pub kind: ValidationArtifactKind,
    /// Content-addressed reference to the artifact.
    pub artifact_digest: String,
    /// Whether validation passed.
    pub passed: bool,
    /// Summary of the result.
    pub summary: String,
}

// ---------------------------------------------------------------------------
// ReplacementReceipt — signed artifact linking old/new cell digests
// ---------------------------------------------------------------------------

/// Signed receipt linking an old cell to a new cell with validation evidence.
///
/// Multi-party signed: requires at minimum the automated gate runner
/// and a governance approver for high-risk slots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementReceipt {
    /// Content-addressed receipt identifier.
    pub receipt_id: EngineObjectId,
    /// Schema version.
    pub schema_version: SchemaVersion,
    /// Slot being replaced.
    pub slot_id: SlotId,
    /// Digest of the old cell implementation.
    pub old_cell_digest: String,
    /// Digest of the new cell implementation.
    pub new_cell_digest: String,
    /// Validation artifact references with results.
    pub validation_artifacts: Vec<ValidationArtifactRef>,
    /// Rollback token (digest of last-known-good for reversal).
    pub rollback_token: String,
    /// Rationale for the replacement.
    pub promotion_rationale: String,
    /// Timestamp (nanoseconds, monotonic).
    pub timestamp_ns: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Zone scoping.
    pub zone: String,
    /// Multi-party signature bundle.
    pub signature_bundle: SignatureBundle,
}

impl ReplacementReceipt {
    /// Derive receipt ID from its contents.
    pub fn derive_receipt_id(
        slot_id: &SlotId,
        old_digest: &str,
        new_digest: &str,
        timestamp_ns: u64,
        zone: &str,
    ) -> Result<EngineObjectId, IdError> {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(slot_id.as_str().as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(old_digest.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(new_digest.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&timestamp_ns.to_be_bytes());
        let schema_id =
            engine_object_id::SchemaId::from_definition(receipt_schema_hash().0.as_slice());
        engine_object_id::derive_id(
            ObjectDomain::CheckpointArtifact,
            zone,
            &schema_id,
            &canonical,
        )
    }

    /// Create an unsigned receipt (signatures added via bundle).
    pub fn create_unsigned(input: CreateReceiptInput<'_>) -> Result<Self, SelfReplacementError> {
        if input.validation_artifacts.is_empty() {
            return Err(SelfReplacementError::EmptyValidationArtifacts);
        }

        let receipt_id = Self::derive_receipt_id(
            input.slot_id,
            input.old_cell_digest,
            input.new_cell_digest,
            input.timestamp_ns,
            input.zone,
        )
        .map_err(SelfReplacementError::IdDerivationFailed)?;

        Ok(Self {
            receipt_id,
            schema_version: SchemaVersion::V1,
            slot_id: input.slot_id.clone(),
            old_cell_digest: input.old_cell_digest.to_string(),
            new_cell_digest: input.new_cell_digest.to_string(),
            validation_artifacts: input.validation_artifacts.to_vec(),
            rollback_token: input.rollback_token.to_string(),
            promotion_rationale: input.promotion_rationale.to_string(),
            timestamp_ns: input.timestamp_ns,
            epoch: input.epoch,
            zone: input.zone.to_string(),
            signature_bundle: SignatureBundle::new(input.required_signatures),
        })
    }

    /// Add a signer to the receipt's signature bundle.
    pub fn add_signature(
        &mut self,
        signing_key: &SigningKey,
        role: &str,
    ) -> Result<(), SelfReplacementError> {
        let preimage = self.preimage_bytes();
        let sig = signature_preimage::sign_preimage(signing_key, &preimage)
            .map_err(SelfReplacementError::SignatureFailed)?;
        self.signature_bundle.add_signer(SignerEntry {
            role: role.to_string(),
            verification_key: signing_key.verification_key(),
            signature: sig,
        });
        Ok(())
    }

    /// Verify all signatures in the bundle.
    pub fn verify_signatures(&self) -> Result<(), SelfReplacementError> {
        let preimage = self.preimage_bytes();
        self.signature_bundle.verify_all(&preimage)
    }

    /// Whether all validation artifacts passed.
    pub fn all_validations_passed(&self) -> bool {
        self.validation_artifacts.iter().all(|v| v.passed)
    }
}

/// Input for creating a replacement receipt.
pub struct CreateReceiptInput<'a> {
    pub slot_id: &'a SlotId,
    pub old_cell_digest: &'a str,
    pub new_cell_digest: &'a str,
    pub validation_artifacts: &'a [ValidationArtifactRef],
    pub rollback_token: &'a str,
    pub promotion_rationale: &'a str,
    pub timestamp_ns: u64,
    pub epoch: SecurityEpoch,
    pub zone: &'a str,
    pub required_signatures: u32,
}

impl SignaturePreimage for ReplacementReceipt {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::CheckpointArtifact
    }

    fn signature_schema(&self) -> &SchemaHash {
        lazy_static_schema_hash(&receipt_schema_hash())
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "epoch".to_string(),
            CanonicalValue::U64(self.epoch.as_u64()),
        );
        map.insert(
            "new_cell_digest".to_string(),
            CanonicalValue::String(self.new_cell_digest.clone()),
        );
        map.insert(
            "old_cell_digest".to_string(),
            CanonicalValue::String(self.old_cell_digest.clone()),
        );
        map.insert(
            "promotion_rationale".to_string(),
            CanonicalValue::String(self.promotion_rationale.clone()),
        );
        map.insert(
            "receipt_id".to_string(),
            CanonicalValue::Bytes(self.receipt_id.as_bytes().to_vec()),
        );
        map.insert(
            "rollback_token".to_string(),
            CanonicalValue::String(self.rollback_token.clone()),
        );
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.to_string()),
        );
        map.insert(
            "signature_bundle".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        map.insert(
            "slot_id".to_string(),
            CanonicalValue::String(self.slot_id.as_str().to_string()),
        );
        map.insert(
            "timestamp_ns".to_string(),
            CanonicalValue::U64(self.timestamp_ns),
        );
        map.insert(
            "validation_artifact_count".to_string(),
            CanonicalValue::U64(self.validation_artifacts.len() as u64),
        );
        map.insert(
            "zone".to_string(),
            CanonicalValue::String(self.zone.clone()),
        );
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// GateVerdict — overall gate result
// ---------------------------------------------------------------------------

/// Overall verdict from promotion gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GateVerdict {
    /// All gates passed; promotion approved.
    Approved,
    /// At least one gate failed; promotion denied.
    Denied,
    /// Gates inconclusive; additional evidence required.
    Inconclusive,
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approved => f.write_str("approved"),
            Self::Denied => f.write_str("denied"),
            Self::Inconclusive => f.write_str("inconclusive"),
        }
    }
}

// ---------------------------------------------------------------------------
// RiskLevel — promotion risk assessment
// ---------------------------------------------------------------------------

/// Risk level assessment for a promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Low risk; automated approval sufficient.
    Low,
    /// Medium risk; single-party approval sufficient.
    Medium,
    /// High risk; multi-party approval required.
    High,
    /// Critical risk; human governance review required.
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => f.write_str("low"),
            Self::Medium => f.write_str("medium"),
            Self::High => f.write_str("high"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// GateResult — per-gate result
// ---------------------------------------------------------------------------

/// Result of a single promotion gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// Name of the gate.
    pub gate_name: String,
    /// Whether the gate passed.
    pub passed: bool,
    /// Evidence references supporting the result.
    pub evidence_refs: Vec<String>,
    /// Human-readable summary.
    pub summary: String,
}

// ---------------------------------------------------------------------------
// ApproverKind — who approved the promotion
// ---------------------------------------------------------------------------

/// Who approved the promotion decision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ApproverKind {
    /// Automated system decision.
    System { component: String },
    /// Human operator decision.
    Human { operator_id: String },
}

impl fmt::Display for ApproverKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System { component } => write!(f, "system:{component}"),
            Self::Human { operator_id } => write!(f, "human:{operator_id}"),
        }
    }
}

// ---------------------------------------------------------------------------
// PromotionDecision — decision artifact
// ---------------------------------------------------------------------------

/// Signed decision artifact for a slot promotion.
///
/// Captures the gate evaluation results, overall verdict, risk assessment,
/// and approver identity.  Multi-party signed for high-risk slots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionDecision {
    /// Content-addressed decision identifier.
    pub decision_id: EngineObjectId,
    /// Schema version.
    pub schema_version: SchemaVersion,
    /// Slot being promoted.
    pub slot_id: SlotId,
    /// Candidate cell being considered for promotion.
    pub candidate_cell_digest: String,
    /// Per-gate evaluation results.
    pub gate_results: Vec<GateResult>,
    /// Overall verdict.
    pub verdict: GateVerdict,
    /// Risk assessment.
    pub risk_level: RiskLevel,
    /// Who approved (or denied) the promotion.
    pub approver: ApproverKind,
    /// Timestamp (nanoseconds, monotonic).
    pub timestamp_ns: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Zone scoping.
    pub zone: String,
    /// Multi-party signature bundle.
    pub signature_bundle: SignatureBundle,
}

impl PromotionDecision {
    /// Derive decision ID from its contents.
    pub fn derive_decision_id(
        slot_id: &SlotId,
        candidate_digest: &str,
        timestamp_ns: u64,
        zone: &str,
    ) -> Result<EngineObjectId, IdError> {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(slot_id.as_str().as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(candidate_digest.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&timestamp_ns.to_be_bytes());
        let schema_id =
            engine_object_id::SchemaId::from_definition(decision_schema_hash().0.as_slice());
        engine_object_id::derive_id(ObjectDomain::EvidenceRecord, zone, &schema_id, &canonical)
    }

    /// Create an unsigned decision (signatures added via bundle).
    pub fn create_unsigned(input: CreateDecisionInput<'_>) -> Result<Self, SelfReplacementError> {
        let decision_id = Self::derive_decision_id(
            input.slot_id,
            input.candidate_cell_digest,
            input.timestamp_ns,
            input.zone,
        )
        .map_err(SelfReplacementError::IdDerivationFailed)?;

        let verdict = if input.gate_results.is_empty() {
            GateVerdict::Inconclusive
        } else if input.gate_results.iter().all(|g| g.passed) {
            GateVerdict::Approved
        } else {
            GateVerdict::Denied
        };

        Ok(Self {
            decision_id,
            schema_version: SchemaVersion::V1,
            slot_id: input.slot_id.clone(),
            candidate_cell_digest: input.candidate_cell_digest.to_string(),
            gate_results: input.gate_results.to_vec(),
            verdict,
            risk_level: input.risk_level,
            approver: input.approver.clone(),
            timestamp_ns: input.timestamp_ns,
            epoch: input.epoch,
            zone: input.zone.to_string(),
            signature_bundle: SignatureBundle::new(input.required_signatures),
        })
    }

    /// Add a signer to the decision's signature bundle.
    pub fn add_signature(
        &mut self,
        signing_key: &SigningKey,
        role: &str,
    ) -> Result<(), SelfReplacementError> {
        let preimage = self.preimage_bytes();
        let sig = signature_preimage::sign_preimage(signing_key, &preimage)
            .map_err(SelfReplacementError::SignatureFailed)?;
        self.signature_bundle.add_signer(SignerEntry {
            role: role.to_string(),
            verification_key: signing_key.verification_key(),
            signature: sig,
        });
        Ok(())
    }

    /// Verify all signatures in the bundle.
    pub fn verify_signatures(&self) -> Result<(), SelfReplacementError> {
        let preimage = self.preimage_bytes();
        self.signature_bundle.verify_all(&preimage)
    }

    /// Whether the decision approves promotion.
    pub fn is_approved(&self) -> bool {
        self.verdict == GateVerdict::Approved
    }
}

/// Input for creating a promotion decision.
pub struct CreateDecisionInput<'a> {
    pub slot_id: &'a SlotId,
    pub candidate_cell_digest: &'a str,
    pub gate_results: &'a [GateResult],
    pub risk_level: RiskLevel,
    pub approver: &'a ApproverKind,
    pub timestamp_ns: u64,
    pub epoch: SecurityEpoch,
    pub zone: &'a str,
    pub required_signatures: u32,
}

impl SignaturePreimage for PromotionDecision {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::EvidenceRecord
    }

    fn signature_schema(&self) -> &SchemaHash {
        lazy_static_schema_hash(&decision_schema_hash())
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "approver".to_string(),
            CanonicalValue::String(self.approver.to_string()),
        );
        map.insert(
            "candidate_cell_digest".to_string(),
            CanonicalValue::String(self.candidate_cell_digest.clone()),
        );
        map.insert(
            "decision_id".to_string(),
            CanonicalValue::Bytes(self.decision_id.as_bytes().to_vec()),
        );
        map.insert(
            "epoch".to_string(),
            CanonicalValue::U64(self.epoch.as_u64()),
        );
        map.insert(
            "gate_count".to_string(),
            CanonicalValue::U64(self.gate_results.len() as u64),
        );
        map.insert(
            "risk_level".to_string(),
            CanonicalValue::String(self.risk_level.to_string()),
        );
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.to_string()),
        );
        map.insert(
            "signature_bundle".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        map.insert(
            "slot_id".to_string(),
            CanonicalValue::String(self.slot_id.as_str().to_string()),
        );
        map.insert(
            "timestamp_ns".to_string(),
            CanonicalValue::U64(self.timestamp_ns),
        );
        map.insert(
            "verdict".to_string(),
            CanonicalValue::String(self.verdict.to_string()),
        );
        map.insert(
            "zone".to_string(),
            CanonicalValue::String(self.zone.clone()),
        );
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// ReplacementLifecycle — full lifecycle orchestrator
// ---------------------------------------------------------------------------

/// Stage in the replacement lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReplacementStage {
    /// Initial research/development.
    Research,
    /// Shadow execution (delegate and native run in parallel).
    Shadow,
    /// Canary deployment (native handles a fraction of traffic).
    Canary,
    /// Full production promotion.
    Production,
}

impl fmt::Display for ReplacementStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Research => f.write_str("research"),
            Self::Shadow => f.write_str("shadow"),
            Self::Canary => f.write_str("canary"),
            Self::Production => f.write_str("production"),
        }
    }
}

/// Tracks the replacement lifecycle for a slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementLifecycle {
    /// Slot being replaced.
    pub slot_id: SlotId,
    /// Current stage.
    pub current_stage: ReplacementStage,
    /// Delegate cell manifest (always present).
    pub delegate_manifest: DelegateCellManifest,
    /// Promotion decisions accumulated during the lifecycle.
    pub decisions: Vec<PromotionDecision>,
    /// Replacement receipts (one per stage transition).
    pub receipts: Vec<ReplacementReceipt>,
}

impl ReplacementLifecycle {
    /// Create a new lifecycle starting at the research stage.
    pub fn new(slot_id: SlotId, delegate_manifest: DelegateCellManifest) -> Self {
        Self {
            slot_id,
            current_stage: ReplacementStage::Research,
            delegate_manifest,
            decisions: Vec::new(),
            receipts: Vec::new(),
        }
    }

    /// Record a promotion decision.
    pub fn record_decision(
        &mut self,
        decision: PromotionDecision,
    ) -> Result<(), SelfReplacementError> {
        if decision.slot_id != self.slot_id {
            return Err(SelfReplacementError::SlotMismatch {
                expected: self.slot_id.as_str().to_string(),
                got: decision.slot_id.as_str().to_string(),
            });
        }
        self.decisions.push(decision);
        Ok(())
    }

    /// Record a replacement receipt and advance to the next stage.
    pub fn record_receipt(
        &mut self,
        receipt: ReplacementReceipt,
    ) -> Result<(), SelfReplacementError> {
        if receipt.slot_id != self.slot_id {
            return Err(SelfReplacementError::SlotMismatch {
                expected: self.slot_id.as_str().to_string(),
                got: receipt.slot_id.as_str().to_string(),
            });
        }
        if !receipt.all_validations_passed() {
            return Err(SelfReplacementError::ValidationFailed {
                slot_id: self.slot_id.as_str().to_string(),
            });
        }
        self.receipts.push(receipt);
        self.advance_stage();
        Ok(())
    }

    /// Advance to the next stage.
    fn advance_stage(&mut self) {
        self.current_stage = match self.current_stage {
            ReplacementStage::Research => ReplacementStage::Shadow,
            ReplacementStage::Shadow => ReplacementStage::Canary,
            ReplacementStage::Canary => ReplacementStage::Production,
            ReplacementStage::Production => ReplacementStage::Production,
        };
    }

    /// Whether the lifecycle has reached production.
    pub fn is_production(&self) -> bool {
        self.current_stage == ReplacementStage::Production
    }

    /// Number of stage transitions completed.
    pub fn completed_stages(&self) -> usize {
        self.receipts.len()
    }
}

// ---------------------------------------------------------------------------
// SelfReplacementError
// ---------------------------------------------------------------------------

/// Errors from self-replacement operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelfReplacementError {
    /// ID derivation failed.
    IdDerivationFailed(IdError),
    /// Signature creation or verification failed.
    SignatureFailed(SignatureError),
    /// Insufficient signatures in bundle.
    InsufficientSignatures { required: u32, present: u32 },
    /// A specific signer's signature is invalid.
    SignatureInvalid { signer_index: u32, role: String },
    /// Slot ID mismatch between artifact and lifecycle.
    SlotMismatch { expected: String, got: String },
    /// Validation artifacts are empty (receipt requires at least one).
    EmptyValidationArtifacts,
    /// Not all validations passed.
    ValidationFailed { slot_id: String },
    /// Schema version not supported.
    UnsupportedSchemaVersion { version: String },
}

impl fmt::Display for SelfReplacementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdDerivationFailed(e) => write!(f, "id derivation failed: {e}"),
            Self::SignatureFailed(e) => write!(f, "signature error: {e}"),
            Self::InsufficientSignatures { required, present } => {
                write!(f, "insufficient signatures: {present}/{required}")
            }
            Self::SignatureInvalid { signer_index, role } => {
                write!(
                    f,
                    "invalid signature at index {signer_index} (role: {role})"
                )
            }
            Self::SlotMismatch { expected, got } => {
                write!(f, "slot mismatch: expected {expected}, got {got}")
            }
            Self::EmptyValidationArtifacts => {
                f.write_str("replacement receipt requires at least one validation artifact")
            }
            Self::ValidationFailed { slot_id } => {
                write!(f, "validation failed for slot {slot_id}")
            }
            Self::UnsupportedSchemaVersion { version } => {
                write!(f, "unsupported schema version: {version}")
            }
        }
    }
}

impl std::error::Error for SelfReplacementError {}

// ---------------------------------------------------------------------------
// Schema hash helper — returns 'static reference
// ---------------------------------------------------------------------------

/// Helper to return a &'static SchemaHash from a computed hash.
///
/// Uses a Vec-backed leak pattern since schema hashes are immutable
/// singletons computed from fixed definitions.
fn lazy_static_schema_hash(hash: &SchemaHash) -> &'static SchemaHash {
    // This is a controlled leak of a 32-byte value per unique call site.
    // Schema hashes are computed from fixed definitions and never change.
    Box::leak(Box::new(hash.clone()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot_registry::SlotCapability;

    // -- Test helpers --

    fn test_slot_id() -> SlotId {
        SlotId::new("parser-slot").unwrap()
    }

    fn test_authority_envelope() -> AuthorityEnvelope {
        AuthorityEnvelope {
            required: vec![SlotCapability::ReadSource],
            permitted: vec![
                SlotCapability::ReadSource,
                SlotCapability::EmitIr,
                SlotCapability::EmitEvidence,
            ],
        }
    }

    fn test_sandbox() -> SandboxConfiguration {
        SandboxConfiguration::default()
    }

    fn test_monitoring_hooks() -> Vec<MonitoringHook> {
        vec![MonitoringHook {
            hook_id: "telemetry-hook".to_string(),
            trigger_event: "hostcall-complete".to_string(),
            blocking: false,
        }]
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes([42u8; 32])
    }

    fn test_signing_key_2() -> SigningKey {
        SigningKey::from_bytes([99u8; 32])
    }

    fn test_behavior_hash() -> [u8; 32] {
        [0xABu8; 32]
    }

    fn test_validation_artifacts() -> Vec<ValidationArtifactRef> {
        vec![
            ValidationArtifactRef {
                kind: ValidationArtifactKind::EquivalenceResult,
                artifact_digest: "equiv-001".to_string(),
                passed: true,
                summary: "100% behavioral match".to_string(),
            },
            ValidationArtifactRef {
                kind: ValidationArtifactKind::PerformanceBenchmark,
                artifact_digest: "perf-001".to_string(),
                passed: true,
                summary: "2x throughput improvement".to_string(),
            },
        ]
    }

    fn test_gate_results() -> Vec<GateResult> {
        vec![
            GateResult {
                gate_name: "equivalence-gate".to_string(),
                passed: true,
                evidence_refs: vec!["equiv-001".to_string()],
                summary: "all test vectors match".to_string(),
            },
            GateResult {
                gate_name: "performance-gate".to_string(),
                passed: true,
                evidence_refs: vec!["perf-001".to_string()],
                summary: "meets latency targets".to_string(),
            },
        ]
    }

    fn create_test_manifest() -> DelegateCellManifest {
        let sk = test_signing_key();
        let hooks = test_monitoring_hooks();
        let envelope = test_authority_envelope();
        let sandbox = test_sandbox();
        let behavior = test_behavior_hash();
        DelegateCellManifest::create_signed(
            &sk,
            CreateManifestInput {
                slot_id: &test_slot_id(),
                delegate_type: DelegateType::QuickJsBacked,
                capability_envelope: &envelope,
                sandbox: &sandbox,
                monitoring_hooks: &hooks,
                expected_behavior_hash: &behavior,
                zone: "test-zone",
            },
        )
        .unwrap()
    }

    // -- SchemaVersion --

    #[test]
    fn schema_version_display() {
        assert_eq!(SchemaVersion::V1.to_string(), "v1");
    }

    #[test]
    fn schema_version_serde_roundtrip() {
        let json = serde_json::to_string(&SchemaVersion::V1).unwrap();
        let restored: SchemaVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(SchemaVersion::V1, restored);
    }

    // -- DelegateType --

    #[test]
    fn delegate_type_display() {
        assert_eq!(DelegateType::QuickJsBacked.to_string(), "quickjs-backed");
        assert_eq!(DelegateType::WasmBacked.to_string(), "wasm-backed");
        assert_eq!(
            DelegateType::ExternalProcess.to_string(),
            "external-process"
        );
    }

    #[test]
    fn delegate_type_serde_roundtrip() {
        for dt in [
            DelegateType::QuickJsBacked,
            DelegateType::WasmBacked,
            DelegateType::ExternalProcess,
        ] {
            let json = serde_json::to_string(&dt).unwrap();
            let restored: DelegateType = serde_json::from_str(&json).unwrap();
            assert_eq!(dt, restored);
        }
    }

    // -- SandboxConfiguration --

    #[test]
    fn sandbox_defaults() {
        let sb = SandboxConfiguration::default();
        assert_eq!(sb.max_heap_bytes, 64 * 1024 * 1024);
        assert_eq!(sb.max_execution_ns, 5_000_000_000);
        assert_eq!(sb.max_hostcalls, 10_000);
        assert!(!sb.network_egress_allowed);
        assert!(!sb.filesystem_access_allowed);
    }

    #[test]
    fn sandbox_serde_roundtrip() {
        let sb = SandboxConfiguration::default();
        let json = serde_json::to_string(&sb).unwrap();
        let restored: SandboxConfiguration = serde_json::from_str(&json).unwrap();
        assert_eq!(sb, restored);
    }

    // -- DelegateCellManifest --

    #[test]
    fn manifest_creation_and_id_derivation() {
        let manifest = create_test_manifest();
        assert_eq!(manifest.slot_id, test_slot_id());
        assert_eq!(manifest.delegate_type, DelegateType::QuickJsBacked);
        assert_eq!(manifest.zone, "test-zone");
        assert_eq!(manifest.schema_version, SchemaVersion::V1);
    }

    #[test]
    fn manifest_signature_verification() {
        let sk = test_signing_key();
        let vk = sk.verification_key();
        let manifest = create_test_manifest();
        assert!(manifest.verify_signature(&vk).is_ok());
    }

    #[test]
    fn manifest_signature_fails_with_wrong_key() {
        let wrong_sk = test_signing_key_2();
        let wrong_vk = wrong_sk.verification_key();
        let manifest = create_test_manifest();
        assert!(manifest.verify_signature(&wrong_vk).is_err());
    }

    #[test]
    fn manifest_id_deterministic() {
        let id1 = DelegateCellManifest::derive_manifest_id(
            &test_slot_id(),
            DelegateType::QuickJsBacked,
            &test_behavior_hash(),
            "zone-a",
        )
        .unwrap();
        let id2 = DelegateCellManifest::derive_manifest_id(
            &test_slot_id(),
            DelegateType::QuickJsBacked,
            &test_behavior_hash(),
            "zone-a",
        )
        .unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn manifest_id_differs_by_zone() {
        let id1 = DelegateCellManifest::derive_manifest_id(
            &test_slot_id(),
            DelegateType::QuickJsBacked,
            &test_behavior_hash(),
            "zone-a",
        )
        .unwrap();
        let id2 = DelegateCellManifest::derive_manifest_id(
            &test_slot_id(),
            DelegateType::QuickJsBacked,
            &test_behavior_hash(),
            "zone-b",
        )
        .unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let manifest = create_test_manifest();
        let json = serde_json::to_string(&manifest).unwrap();
        let restored: DelegateCellManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, restored);
    }

    #[test]
    fn manifest_preimage_deterministic() {
        let m = create_test_manifest();
        let p1 = m.preimage_bytes();
        let p2 = m.preimage_bytes();
        assert_eq!(p1, p2);
    }

    // -- SignatureBundle --

    #[test]
    fn bundle_meets_threshold() {
        let mut bundle = SignatureBundle::new(2);
        assert!(!bundle.meets_threshold());

        bundle.add_signer(SignerEntry {
            role: "gate-runner".to_string(),
            verification_key: test_signing_key().verification_key(),
            signature: Signature::from_bytes([0u8; 64]),
        });
        assert!(!bundle.meets_threshold());

        bundle.add_signer(SignerEntry {
            role: "approver".to_string(),
            verification_key: test_signing_key_2().verification_key(),
            signature: Signature::from_bytes([0u8; 64]),
        });
        assert!(bundle.meets_threshold());
    }

    #[test]
    fn bundle_serde_roundtrip() {
        let bundle = SignatureBundle::new(1);
        let json = serde_json::to_string(&bundle).unwrap();
        let restored: SignatureBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, restored);
    }

    // -- ReplacementReceipt --

    #[test]
    fn receipt_creation_requires_validation_artifacts() {
        let result = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: "old-001",
            new_cell_digest: "new-001",
            validation_artifacts: &[],
            rollback_token: "rollback-001",
            promotion_rationale: "performance improvement",
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 2,
        });
        assert!(matches!(
            result,
            Err(SelfReplacementError::EmptyValidationArtifacts)
        ));
    }

    #[test]
    fn receipt_creation_and_signing() {
        let artifacts = test_validation_artifacts();
        let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: "old-001",
            new_cell_digest: "new-001",
            validation_artifacts: &artifacts,
            rollback_token: "rollback-001",
            promotion_rationale: "performance improvement",
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 2,
        })
        .unwrap();

        assert_eq!(receipt.slot_id, test_slot_id());
        assert!(receipt.all_validations_passed());

        // Add two signatures.
        receipt
            .add_signature(&test_signing_key(), "gate-runner")
            .unwrap();
        receipt
            .add_signature(&test_signing_key_2(), "governance-approver")
            .unwrap();

        assert!(receipt.verify_signatures().is_ok());
    }

    #[test]
    fn receipt_insufficient_signatures() {
        let artifacts = test_validation_artifacts();
        let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: "old-001",
            new_cell_digest: "new-001",
            validation_artifacts: &artifacts,
            rollback_token: "rollback-001",
            promotion_rationale: "perf",
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 2,
        })
        .unwrap();

        // Only one signature.
        receipt
            .add_signature(&test_signing_key(), "gate-runner")
            .unwrap();

        assert!(matches!(
            receipt.verify_signatures(),
            Err(SelfReplacementError::InsufficientSignatures {
                required: 2,
                present: 1
            })
        ));
    }

    #[test]
    fn receipt_id_deterministic() {
        let id1 =
            ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old", "new", 1000, "zone-a")
                .unwrap();
        let id2 =
            ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old", "new", 1000, "zone-a")
                .unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn receipt_id_differs_by_timestamp() {
        let id1 =
            ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old", "new", 1000, "zone-a")
                .unwrap();
        let id2 =
            ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old", "new", 2000, "zone-a")
                .unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn receipt_serde_roundtrip() {
        let artifacts = test_validation_artifacts();
        let receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: "old-001",
            new_cell_digest: "new-001",
            validation_artifacts: &artifacts,
            rollback_token: "rollback-001",
            promotion_rationale: "perf",
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 1,
        })
        .unwrap();

        let json = serde_json::to_string(&receipt).unwrap();
        let restored: ReplacementReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
    }

    #[test]
    fn receipt_preimage_deterministic() {
        let artifacts = test_validation_artifacts();
        let receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: "old-001",
            new_cell_digest: "new-001",
            validation_artifacts: &artifacts,
            rollback_token: "rollback-001",
            promotion_rationale: "perf",
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 1,
        })
        .unwrap();
        let p1 = receipt.preimage_bytes();
        let p2 = receipt.preimage_bytes();
        assert_eq!(p1, p2);
    }

    // -- PromotionDecision --

    #[test]
    fn decision_auto_approved_when_all_gates_pass() {
        let gates = test_gate_results();
        let decision = PromotionDecision::create_unsigned(CreateDecisionInput {
            slot_id: &test_slot_id(),
            candidate_cell_digest: "candidate-001",
            gate_results: &gates,
            risk_level: RiskLevel::Medium,
            approver: &ApproverKind::System {
                component: "gate-runner".to_string(),
            },
            timestamp_ns: 2_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 1,
        })
        .unwrap();

        assert!(decision.is_approved());
        assert_eq!(decision.verdict, GateVerdict::Approved);
    }

    #[test]
    fn decision_denied_when_any_gate_fails() {
        let gates = vec![
            GateResult {
                gate_name: "equivalence-gate".to_string(),
                passed: true,
                evidence_refs: vec![],
                summary: "ok".to_string(),
            },
            GateResult {
                gate_name: "performance-gate".to_string(),
                passed: false,
                evidence_refs: vec![],
                summary: "latency regression".to_string(),
            },
        ];
        let decision = PromotionDecision::create_unsigned(CreateDecisionInput {
            slot_id: &test_slot_id(),
            candidate_cell_digest: "candidate-001",
            gate_results: &gates,
            risk_level: RiskLevel::High,
            approver: &ApproverKind::Human {
                operator_id: "op-42".to_string(),
            },
            timestamp_ns: 2_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 2,
        })
        .unwrap();

        assert!(!decision.is_approved());
        assert_eq!(decision.verdict, GateVerdict::Denied);
    }

    #[test]
    fn decision_creation_and_signing() {
        let gates = test_gate_results();
        let mut decision = PromotionDecision::create_unsigned(CreateDecisionInput {
            slot_id: &test_slot_id(),
            candidate_cell_digest: "candidate-001",
            gate_results: &gates,
            risk_level: RiskLevel::Low,
            approver: &ApproverKind::System {
                component: "gate-runner".to_string(),
            },
            timestamp_ns: 2_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 1,
        })
        .unwrap();

        decision
            .add_signature(&test_signing_key(), "gate-runner")
            .unwrap();
        assert!(decision.verify_signatures().is_ok());
    }

    #[test]
    fn decision_id_deterministic() {
        let id1 =
            PromotionDecision::derive_decision_id(&test_slot_id(), "candidate", 1000, "zone-a")
                .unwrap();
        let id2 =
            PromotionDecision::derive_decision_id(&test_slot_id(), "candidate", 1000, "zone-a")
                .unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn decision_serde_roundtrip() {
        let gates = test_gate_results();
        let decision = PromotionDecision::create_unsigned(CreateDecisionInput {
            slot_id: &test_slot_id(),
            candidate_cell_digest: "candidate-001",
            gate_results: &gates,
            risk_level: RiskLevel::Medium,
            approver: &ApproverKind::System {
                component: "gate-runner".to_string(),
            },
            timestamp_ns: 2_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 1,
        })
        .unwrap();

        let json = serde_json::to_string(&decision).unwrap();
        let restored: PromotionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, restored);
    }

    #[test]
    fn decision_preimage_deterministic() {
        let gates = test_gate_results();
        let d = PromotionDecision::create_unsigned(CreateDecisionInput {
            slot_id: &test_slot_id(),
            candidate_cell_digest: "candidate-001",
            gate_results: &gates,
            risk_level: RiskLevel::Low,
            approver: &ApproverKind::System {
                component: "x".to_string(),
            },
            timestamp_ns: 1000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test",
            required_signatures: 1,
        })
        .unwrap();
        let p1 = d.preimage_bytes();
        let p2 = d.preimage_bytes();
        assert_eq!(p1, p2);
    }

    // -- GateVerdict --

    #[test]
    fn gate_verdict_display() {
        assert_eq!(GateVerdict::Approved.to_string(), "approved");
        assert_eq!(GateVerdict::Denied.to_string(), "denied");
        assert_eq!(GateVerdict::Inconclusive.to_string(), "inconclusive");
    }

    #[test]
    fn gate_verdict_serde_roundtrip() {
        for v in [
            GateVerdict::Approved,
            GateVerdict::Denied,
            GateVerdict::Inconclusive,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let restored: GateVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, restored);
        }
    }

    // -- RiskLevel --

    #[test]
    fn risk_level_display() {
        assert_eq!(RiskLevel::Low.to_string(), "low");
        assert_eq!(RiskLevel::Critical.to_string(), "critical");
    }

    #[test]
    fn risk_level_serde_roundtrip() {
        for rl in [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            let json = serde_json::to_string(&rl).unwrap();
            let restored: RiskLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(rl, restored);
        }
    }

    // -- ReplacementStage --

    #[test]
    fn stage_display() {
        assert_eq!(ReplacementStage::Research.to_string(), "research");
        assert_eq!(ReplacementStage::Shadow.to_string(), "shadow");
        assert_eq!(ReplacementStage::Canary.to_string(), "canary");
        assert_eq!(ReplacementStage::Production.to_string(), "production");
    }

    #[test]
    fn stage_serde_roundtrip() {
        for s in [
            ReplacementStage::Research,
            ReplacementStage::Shadow,
            ReplacementStage::Canary,
            ReplacementStage::Production,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let restored: ReplacementStage = serde_json::from_str(&json).unwrap();
            assert_eq!(s, restored);
        }
    }

    // -- ReplacementLifecycle --

    #[test]
    fn lifecycle_starts_at_research() {
        let manifest = create_test_manifest();
        let lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);
        assert_eq!(lifecycle.current_stage, ReplacementStage::Research);
        assert!(!lifecycle.is_production());
        assert_eq!(lifecycle.completed_stages(), 0);
    }

    #[test]
    fn lifecycle_advances_through_stages() {
        let manifest = create_test_manifest();
        let mut lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);

        let artifacts = test_validation_artifacts();
        // Stage 1: Research -> Shadow.
        let mut r1 = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: "old",
            new_cell_digest: "new-shadow",
            validation_artifacts: &artifacts,
            rollback_token: "rb-1",
            promotion_rationale: "shadow test pass",
            timestamp_ns: 1000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 1,
        })
        .unwrap();
        r1.add_signature(&test_signing_key(), "gate-runner")
            .unwrap();
        lifecycle.record_receipt(r1).unwrap();
        assert_eq!(lifecycle.current_stage, ReplacementStage::Shadow);
        assert_eq!(lifecycle.completed_stages(), 1);

        // Stage 2: Shadow -> Canary.
        let mut r2 = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: "new-shadow",
            new_cell_digest: "new-canary",
            validation_artifacts: &artifacts,
            rollback_token: "rb-2",
            promotion_rationale: "canary test pass",
            timestamp_ns: 2000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 1,
        })
        .unwrap();
        r2.add_signature(&test_signing_key(), "gate-runner")
            .unwrap();
        lifecycle.record_receipt(r2).unwrap();
        assert_eq!(lifecycle.current_stage, ReplacementStage::Canary);

        // Stage 3: Canary -> Production.
        let mut r3 = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: "new-canary",
            new_cell_digest: "new-production",
            validation_artifacts: &artifacts,
            rollback_token: "rb-3",
            promotion_rationale: "production test pass",
            timestamp_ns: 3000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 1,
        })
        .unwrap();
        r3.add_signature(&test_signing_key(), "gate-runner")
            .unwrap();
        lifecycle.record_receipt(r3).unwrap();
        assert!(lifecycle.is_production());
        assert_eq!(lifecycle.completed_stages(), 3);
    }

    #[test]
    fn lifecycle_rejects_failed_validation() {
        let manifest = create_test_manifest();
        let mut lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);

        let failed_artifacts = vec![ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: "equiv-fail".to_string(),
            passed: false,
            summary: "behavioral mismatch".to_string(),
        }];
        let receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: "old",
            new_cell_digest: "new",
            validation_artifacts: &failed_artifacts,
            rollback_token: "rb-1",
            promotion_rationale: "attempt",
            timestamp_ns: 1000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 1,
        })
        .unwrap();

        assert!(matches!(
            lifecycle.record_receipt(receipt),
            Err(SelfReplacementError::ValidationFailed { .. })
        ));
        // Stage should NOT have advanced.
        assert_eq!(lifecycle.current_stage, ReplacementStage::Research);
    }

    #[test]
    fn lifecycle_rejects_slot_mismatch() {
        let manifest = create_test_manifest();
        let mut lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);

        let wrong_slot = SlotId::new("wrong-slot").unwrap();
        let artifacts = test_validation_artifacts();
        let receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &wrong_slot,
            old_cell_digest: "old",
            new_cell_digest: "new",
            validation_artifacts: &artifacts,
            rollback_token: "rb-1",
            promotion_rationale: "attempt",
            timestamp_ns: 1000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 1,
        })
        .unwrap();

        assert!(matches!(
            lifecycle.record_receipt(receipt),
            Err(SelfReplacementError::SlotMismatch { .. })
        ));
    }

    #[test]
    fn lifecycle_records_decisions() {
        let manifest = create_test_manifest();
        let mut lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);

        let gates = test_gate_results();
        let decision = PromotionDecision::create_unsigned(CreateDecisionInput {
            slot_id: &test_slot_id(),
            candidate_cell_digest: "candidate-001",
            gate_results: &gates,
            risk_level: RiskLevel::Low,
            approver: &ApproverKind::System {
                component: "gate".to_string(),
            },
            timestamp_ns: 1000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 1,
        })
        .unwrap();

        lifecycle.record_decision(decision).unwrap();
        assert_eq!(lifecycle.decisions.len(), 1);
    }

    // -- ApproverKind --

    #[test]
    fn approver_kind_display() {
        assert_eq!(
            ApproverKind::System {
                component: "gate-runner".to_string()
            }
            .to_string(),
            "system:gate-runner"
        );
        assert_eq!(
            ApproverKind::Human {
                operator_id: "op-1".to_string()
            }
            .to_string(),
            "human:op-1"
        );
    }

    #[test]
    fn approver_kind_serde_roundtrip() {
        let kinds = vec![
            ApproverKind::System {
                component: "x".to_string(),
            },
            ApproverKind::Human {
                operator_id: "y".to_string(),
            },
        ];
        for k in &kinds {
            let json = serde_json::to_string(k).unwrap();
            let restored: ApproverKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, restored);
        }
    }

    // -- ValidationArtifactKind --

    #[test]
    fn validation_artifact_kind_display() {
        assert_eq!(
            ValidationArtifactKind::EquivalenceResult.to_string(),
            "equivalence"
        );
        assert_eq!(
            ValidationArtifactKind::CapabilityPreservation.to_string(),
            "capability-preservation"
        );
        assert_eq!(
            ValidationArtifactKind::PerformanceBenchmark.to_string(),
            "performance-benchmark"
        );
        assert_eq!(
            ValidationArtifactKind::AdversarialSurvival.to_string(),
            "adversarial-survival"
        );
    }

    #[test]
    fn validation_artifact_ref_serde_roundtrip() {
        let v = ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: "abc".to_string(),
            passed: true,
            summary: "ok".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let restored: ValidationArtifactRef = serde_json::from_str(&json).unwrap();
        assert_eq!(v, restored);
    }

    // -- SelfReplacementError --

    #[test]
    fn error_display() {
        let err = SelfReplacementError::EmptyValidationArtifacts;
        assert!(err.to_string().contains("at least one"));

        let err = SelfReplacementError::InsufficientSignatures {
            required: 2,
            present: 1,
        };
        assert!(err.to_string().contains("1/2"));

        let err = SelfReplacementError::SlotMismatch {
            expected: "a".into(),
            got: "b".into(),
        };
        assert!(err.to_string().contains("a"));
        assert!(err.to_string().contains("b"));
    }

    #[test]
    fn error_serde_roundtrip() {
        let errors = vec![
            SelfReplacementError::EmptyValidationArtifacts,
            SelfReplacementError::InsufficientSignatures {
                required: 2,
                present: 1,
            },
            SelfReplacementError::SlotMismatch {
                expected: "a".into(),
                got: "b".into(),
            },
            SelfReplacementError::ValidationFailed {
                slot_id: "s".into(),
            },
            SelfReplacementError::UnsupportedSchemaVersion {
                version: "v99".into(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: SelfReplacementError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    // -- Content-addressable identity --

    #[test]
    fn all_artifact_ids_are_content_addressed() {
        // Verify that IDs change when content changes.
        let id_a = DelegateCellManifest::derive_manifest_id(
            &test_slot_id(),
            DelegateType::QuickJsBacked,
            &[1u8; 32],
            "zone",
        )
        .unwrap();
        let id_b = DelegateCellManifest::derive_manifest_id(
            &test_slot_id(),
            DelegateType::QuickJsBacked,
            &[2u8; 32],
            "zone",
        )
        .unwrap();
        assert_ne!(id_a, id_b, "different content must yield different IDs");

        let id_c =
            ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old-a", "new-a", 1000, "zone")
                .unwrap();
        let id_d =
            ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old-b", "new-a", 1000, "zone")
                .unwrap();
        assert_ne!(id_c, id_d);

        let id_e =
            PromotionDecision::derive_decision_id(&test_slot_id(), "cand-a", 1000, "zone").unwrap();
        let id_f =
            PromotionDecision::derive_decision_id(&test_slot_id(), "cand-b", 1000, "zone").unwrap();
        assert_ne!(id_e, id_f);
    }

    // -- Multi-party signing integration --

    #[test]
    fn multi_party_receipt_verification() {
        let artifacts = test_validation_artifacts();
        let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: "old",
            new_cell_digest: "new",
            validation_artifacts: &artifacts,
            rollback_token: "rb",
            promotion_rationale: "test",
            timestamp_ns: 1000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "zone",
            required_signatures: 2,
        })
        .unwrap();

        let sk1 = test_signing_key();
        let sk2 = test_signing_key_2();

        receipt.add_signature(&sk1, "gate-runner").unwrap();
        receipt.add_signature(&sk2, "governance-approver").unwrap();

        // Both signatures should verify.
        assert!(receipt.verify_signatures().is_ok());

        // Check signer roles.
        assert_eq!(receipt.signature_bundle.signers[0].role, "gate-runner");
        assert_eq!(
            receipt.signature_bundle.signers[1].role,
            "governance-approver"
        );
    }

    // -- Lifecycle serde --

    #[test]
    fn lifecycle_serde_roundtrip() {
        let manifest = create_test_manifest();
        let lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);
        let json = serde_json::to_string(&lifecycle).unwrap();
        let restored: ReplacementLifecycle = serde_json::from_str(&json).unwrap();
        assert_eq!(lifecycle, restored);
    }

    // -- MonitoringHook --

    #[test]
    fn monitoring_hook_serde_roundtrip() {
        let hook = MonitoringHook {
            hook_id: "h-1".to_string(),
            trigger_event: "hostcall".to_string(),
            blocking: true,
        };
        let json = serde_json::to_string(&hook).unwrap();
        let restored: MonitoringHook = serde_json::from_str(&json).unwrap();
        assert_eq!(hook, restored);
    }

    // -- Enrichment: ordering --

    #[test]
    fn schema_version_ordering() {
        // Only one variant, but confirm Ord is implemented.
        assert_eq!(
            SchemaVersion::V1.cmp(&SchemaVersion::V1),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn delegate_type_ordering() {
        assert!(DelegateType::QuickJsBacked < DelegateType::WasmBacked);
        assert!(DelegateType::WasmBacked < DelegateType::ExternalProcess);
    }

    #[test]
    fn validation_artifact_kind_ordering() {
        assert!(
            ValidationArtifactKind::EquivalenceResult
                < ValidationArtifactKind::CapabilityPreservation
        );
        assert!(
            ValidationArtifactKind::CapabilityPreservation
                < ValidationArtifactKind::PerformanceBenchmark
        );
        assert!(
            ValidationArtifactKind::PerformanceBenchmark
                < ValidationArtifactKind::AdversarialSurvival
        );
    }

    #[test]
    fn gate_verdict_ordering() {
        assert!(GateVerdict::Approved < GateVerdict::Denied);
        assert!(GateVerdict::Denied < GateVerdict::Inconclusive);
    }

    #[test]
    fn risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn replacement_stage_ordering() {
        assert!(ReplacementStage::Research < ReplacementStage::Shadow);
        assert!(ReplacementStage::Shadow < ReplacementStage::Canary);
        assert!(ReplacementStage::Canary < ReplacementStage::Production);
    }

    // -- Enrichment: error trait --

    #[test]
    fn self_replacement_error_is_std_error() {
        let e: Box<dyn std::error::Error> =
            Box::new(SelfReplacementError::EmptyValidationArtifacts);
        assert!(!e.to_string().is_empty());
    }

    // -- Enrichment: serde --

    #[test]
    fn gate_result_serde_roundtrip() {
        let gr = GateResult {
            gate_name: "equivalence".to_string(),
            passed: true,
            evidence_refs: vec!["ev-1".to_string()],
            summary: "all equivalent".to_string(),
        };
        let json = serde_json::to_string(&gr).unwrap();
        let restored: GateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(gr, restored);
    }

    #[test]
    fn signer_entry_serde_roundtrip() {
        let sk = SigningKey::from_bytes([42u8; 32]);
        let entry = SignerEntry {
            role: "admin".to_string(),
            verification_key: sk.verification_key(),
            signature: Signature::from_bytes([0u8; 64]),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let restored: SignerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, restored);
    }

    // -- Enrichment: display content --

    #[test]
    fn validation_artifact_kind_display_content() {
        assert_eq!(
            ValidationArtifactKind::EquivalenceResult.to_string(),
            "equivalence"
        );
        assert_eq!(
            ValidationArtifactKind::AdversarialSurvival.to_string(),
            "adversarial-survival"
        );
    }

    #[test]
    fn replacement_stage_display_content() {
        assert_eq!(ReplacementStage::Research.to_string(), "research");
        assert_eq!(ReplacementStage::Shadow.to_string(), "shadow");
        assert_eq!(ReplacementStage::Canary.to_string(), "canary");
        assert_eq!(ReplacementStage::Production.to_string(), "production");
    }

    #[test]
    fn delegate_type_ord() {
        assert!(DelegateType::QuickJsBacked < DelegateType::WasmBacked);
        assert!(DelegateType::WasmBacked < DelegateType::ExternalProcess);
    }

    #[test]
    fn validation_artifact_kind_ord() {
        assert!(
            ValidationArtifactKind::EquivalenceResult
                < ValidationArtifactKind::CapabilityPreservation
        );
        assert!(
            ValidationArtifactKind::CapabilityPreservation
                < ValidationArtifactKind::PerformanceBenchmark
        );
        assert!(
            ValidationArtifactKind::PerformanceBenchmark
                < ValidationArtifactKind::AdversarialSurvival
        );
    }

    #[test]
    fn gate_verdict_ord() {
        assert!(GateVerdict::Approved < GateVerdict::Denied);
        assert!(GateVerdict::Denied < GateVerdict::Inconclusive);
    }

    #[test]
    fn risk_level_ord() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn replacement_stage_ord() {
        assert!(ReplacementStage::Research < ReplacementStage::Shadow);
        assert!(ReplacementStage::Shadow < ReplacementStage::Canary);
        assert!(ReplacementStage::Canary < ReplacementStage::Production);
    }

    #[test]
    fn self_replacement_error_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(SelfReplacementError::InsufficientSignatures {
                required: 3,
                present: 1,
            }),
            Box::new(SelfReplacementError::SignatureInvalid {
                signer_index: 0,
                role: "admin".into(),
            }),
            Box::new(SelfReplacementError::SlotMismatch {
                expected: "a".into(),
                got: "b".into(),
            }),
            Box::new(SelfReplacementError::EmptyValidationArtifacts),
            Box::new(SelfReplacementError::ValidationFailed {
                slot_id: "s1".into(),
            }),
            Box::new(SelfReplacementError::UnsupportedSchemaVersion {
                version: "v99".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(format!("{v}"));
        }
        assert_eq!(displays.len(), 6);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn schema_version_as_bytes_not_empty() {
        assert!(!SchemaVersion::V1.as_bytes().is_empty());
    }

    #[test]
    fn schema_hash_functions_produce_distinct_values() {
        let m = manifest_schema_hash();
        let r = receipt_schema_hash();
        let d = decision_schema_hash();
        assert_ne!(m, r);
        assert_ne!(r, d);
        assert_ne!(m, d);
    }

    #[test]
    fn manifest_id_differs_by_delegate_type() {
        let hash = [0x11; 32];
        let id_quickjs = DelegateCellManifest::derive_manifest_id(
            &test_slot_id(),
            DelegateType::QuickJsBacked,
            &hash,
            "zone",
        )
        .unwrap();
        let id_wasm = DelegateCellManifest::derive_manifest_id(
            &test_slot_id(),
            DelegateType::WasmBacked,
            &hash,
            "zone",
        )
        .unwrap();
        assert_ne!(id_quickjs, id_wasm);
    }

    #[test]
    fn receipt_all_validations_passed_when_mixed() {
        let artifacts = vec![
            ValidationArtifactRef {
                kind: ValidationArtifactKind::EquivalenceResult,
                artifact_digest: "d-1".to_string(),
                passed: true,
                summary: "ok".to_string(),
            },
            ValidationArtifactRef {
                kind: ValidationArtifactKind::PerformanceBenchmark,
                artifact_digest: "d-2".to_string(),
                passed: false,
                summary: "too slow".to_string(),
            },
        ];
        let receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: "old",
            new_cell_digest: "new",
            validation_artifacts: &artifacts,
            rollback_token: "rb",
            promotion_rationale: "test",
            timestamp_ns: 1000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "zone",
            required_signatures: 1,
        })
        .unwrap();
        assert!(!receipt.all_validations_passed());
    }

    #[test]
    fn decision_empty_gates_yields_inconclusive() {
        let decision = PromotionDecision::create_unsigned(CreateDecisionInput {
            slot_id: &test_slot_id(),
            candidate_cell_digest: "cand",
            gate_results: &[],
            risk_level: RiskLevel::Low,
            approver: &ApproverKind::System {
                component: "auto".to_string(),
            },
            timestamp_ns: 1000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "zone",
            required_signatures: 1,
        })
        .unwrap();
        assert_eq!(decision.verdict, GateVerdict::Inconclusive);
        assert!(!decision.is_approved());
    }

    #[test]
    fn decision_is_approved_false_when_denied() {
        let gates = vec![GateResult {
            gate_name: "eq".to_string(),
            passed: false,
            evidence_refs: vec![],
            summary: "failed".to_string(),
        }];
        let decision = PromotionDecision::create_unsigned(CreateDecisionInput {
            slot_id: &test_slot_id(),
            candidate_cell_digest: "cand",
            gate_results: &gates,
            risk_level: RiskLevel::High,
            approver: &ApproverKind::Human {
                operator_id: "op".to_string(),
            },
            timestamp_ns: 2000,
            epoch: SecurityEpoch::from_raw(2),
            zone: "zone",
            required_signatures: 1,
        })
        .unwrap();
        assert_eq!(decision.verdict, GateVerdict::Denied);
        assert!(!decision.is_approved());
    }

    #[test]
    fn receipt_id_differs_by_zone() {
        let id_a =
            ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old", "new", 1000, "zone-a")
                .unwrap();
        let id_b =
            ReplacementReceipt::derive_receipt_id(&test_slot_id(), "old", "new", 1000, "zone-b")
                .unwrap();
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn decision_id_differs_by_zone() {
        let id_a =
            PromotionDecision::derive_decision_id(&test_slot_id(), "cand", 1000, "zone-a").unwrap();
        let id_b =
            PromotionDecision::derive_decision_id(&test_slot_id(), "cand", 1000, "zone-b").unwrap();
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn lifecycle_production_stays_at_production() {
        let manifest = create_test_manifest();
        let mut lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);
        // Advance to production: Research -> Shadow -> Canary -> Production
        let artifacts = test_validation_artifacts();
        for _ in 0..3 {
            let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
                slot_id: &test_slot_id(),
                old_cell_digest: "old",
                new_cell_digest: "new",
                validation_artifacts: &artifacts,
                rollback_token: "rb",
                promotion_rationale: "advance",
                timestamp_ns: 1000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "zone",
                required_signatures: 1,
            })
            .unwrap();
            receipt
                .add_signature(&test_signing_key(), "gate-runner")
                .unwrap();
            lifecycle.record_receipt(receipt).unwrap();
        }
        assert!(lifecycle.is_production());
        assert_eq!(lifecycle.completed_stages(), 3);

        // Recording another receipt at Production stays at Production
        let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot_id(),
            old_cell_digest: "old",
            new_cell_digest: "new",
            validation_artifacts: &artifacts,
            rollback_token: "rb",
            promotion_rationale: "post-production",
            timestamp_ns: 2000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "zone",
            required_signatures: 1,
        })
        .unwrap();
        receipt
            .add_signature(&test_signing_key(), "gate-runner")
            .unwrap();
        lifecycle.record_receipt(receipt).unwrap();
        assert!(lifecycle.is_production());
        assert_eq!(lifecycle.completed_stages(), 4);
    }

    #[test]
    fn sandbox_defaults_are_restrictive() {
        let sandbox = SandboxConfiguration::default();
        assert!(!sandbox.network_egress_allowed);
        assert!(!sandbox.filesystem_access_allowed);
        assert!(sandbox.max_heap_bytes > 0);
        assert!(sandbox.max_execution_ns > 0);
        assert!(sandbox.max_hostcalls > 0);
    }

    #[test]
    fn error_display_all_variants_distinct() {
        let variants = vec![
            SelfReplacementError::EmptyValidationArtifacts,
            SelfReplacementError::InsufficientSignatures {
                required: 2,
                present: 0,
            },
            SelfReplacementError::SignatureInvalid {
                signer_index: 0,
                role: "test".into(),
            },
            SelfReplacementError::SlotMismatch {
                expected: "x".into(),
                got: "y".into(),
            },
            SelfReplacementError::ValidationFailed {
                slot_id: "s".into(),
            },
            SelfReplacementError::UnsupportedSchemaVersion {
                version: "v99".into(),
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(v.to_string());
        }
        assert_eq!(displays.len(), variants.len());
    }

    #[test]
    fn signature_bundle_zero_threshold_meets_with_empty() {
        let bundle = SignatureBundle::new(0);
        assert!(bundle.meets_threshold());
    }

    #[test]
    fn lifecycle_completed_stages_matches_receipts() {
        let manifest = create_test_manifest();
        let lifecycle = ReplacementLifecycle::new(test_slot_id(), manifest);
        assert_eq!(lifecycle.completed_stages(), 0);
        assert_eq!(lifecycle.completed_stages(), lifecycle.receipts.len());
    }

    #[test]
    fn monitoring_hook_non_blocking_serde_roundtrip() {
        let hook = MonitoringHook {
            hook_id: "h-nb".to_string(),
            trigger_event: "invocation_start".to_string(),
            blocking: false,
        };
        let json = serde_json::to_string(&hook).unwrap();
        let restored: MonitoringHook = serde_json::from_str(&json).unwrap();
        assert_eq!(hook, restored);
        assert!(!restored.blocking);
    }
}
