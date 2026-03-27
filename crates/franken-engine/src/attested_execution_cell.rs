//! Attested execution-cell architecture and trust-root interface contract.
//!
//! Execution cells are isolated runtime compartments whose identity and code
//! measurement are cryptographically verifiable via hardware or software trust
//! roots.  This module defines:
//!
//! - **Cell registry**: maps `cell_id` to semantic contract, authority envelope,
//!   measurement, trust-root binding, and lifecycle status.
//! - **Trust-root interface**: `TrustRootBackend` trait abstracting measurement,
//!   attestation, and verification across backends (hardware TEE, software).
//! - **Lifecycle state machine**: provisioning → measured → attested → active →
//!   suspended → decommissioned, with signed receipts at each transition.
//! - **Fallback semantics**: attestation failure degrades high-impact actions to
//!   deterministic safe mode (challenge/sandbox-first).
//!
//! Fixed-point millionths (1_000_000 = 1.0) for all fractional values.
//!
//! All collections use `BTreeMap`/`BTreeSet` for deterministic iteration.
//!
//! Plan references: Section 10.12 item 9, 9H.4, 9I.1.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

const CELL_SCHEMA_DEF: &[u8] = b"AttestedExecutionCell.v1";
const MEASUREMENT_SCHEMA_DEF: &[u8] = b"MeasurementDigest.v1";

fn cell_schema_id() -> SchemaId {
    SchemaId::from_definition(CELL_SCHEMA_DEF)
}

fn measurement_schema_id() -> SchemaId {
    SchemaId::from_definition(MEASUREMENT_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// CellLifecycle — execution cell lifecycle states
// ---------------------------------------------------------------------------

/// Lifecycle state of an execution cell.
///
/// State progression: Provisioning → Measured → Attested → Active →
/// Suspended → Decommissioned.  Not all transitions are forward-only;
/// Suspended cells can be re-attested back to Active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CellLifecycle {
    /// Cell is being set up but not yet measured.
    Provisioning = 0,
    /// Cell code/config has been measured.
    Measured = 1,
    /// Cell has a valid attestation quote.
    Attested = 2,
    /// Cell is operational.
    Active = 3,
    /// Cell is paused (e.g., trust root revoked, awaiting re-attestation).
    Suspended = 4,
    /// Cell has been permanently retired.
    Decommissioned = 5,
}

impl CellLifecycle {
    /// Whether this state allows normal operation.
    pub fn is_operational(&self) -> bool {
        *self == Self::Active
    }

    /// Whether this state permits re-attestation.
    pub fn allows_reattestation(&self) -> bool {
        matches!(self, Self::Suspended | Self::Measured)
    }
}

impl fmt::Display for CellLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provisioning => f.write_str("provisioning"),
            Self::Measured => f.write_str("measured"),
            Self::Attested => f.write_str("attested"),
            Self::Active => f.write_str("active"),
            Self::Suspended => f.write_str("suspended"),
            Self::Decommissioned => f.write_str("decommissioned"),
        }
    }
}

// ---------------------------------------------------------------------------
// TrustLevel — confidence in the attestation backend
// ---------------------------------------------------------------------------

/// Trust level of an attestation backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Software-only attestation (development/testing).
    SoftwareOnly = 0,
    /// Software measurement with hardware key binding.
    Hybrid = 1,
    /// Full hardware TEE attestation.
    Hardware = 2,
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SoftwareOnly => f.write_str("software-only"),
            Self::Hybrid => f.write_str("hybrid"),
            Self::Hardware => f.write_str("hardware"),
        }
    }
}

// ---------------------------------------------------------------------------
// PlatformKind — supported attestation platforms
// ---------------------------------------------------------------------------

/// Supported attestation platform types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PlatformKind {
    /// Intel SGX / TDX.
    IntelSgx,
    /// ARM Confidential Compute Architecture.
    ArmCca,
    /// AMD SEV-SNP.
    AmdSevSnp,
    /// Software-only (no hardware TEE).
    Software,
}

impl fmt::Display for PlatformKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntelSgx => f.write_str("intel-sgx"),
            Self::ArmCca => f.write_str("arm-cca"),
            Self::AmdSevSnp => f.write_str("amd-sev-snp"),
            Self::Software => f.write_str("software"),
        }
    }
}

// ---------------------------------------------------------------------------
// MeasurementDigest — cryptographic identity of a cell's code + config
// ---------------------------------------------------------------------------

/// Cryptographic measurement of an execution cell's code and configuration.
///
/// Deterministic given identical inputs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MeasurementDigest {
    /// Hash of the cell's executable code.
    pub code_hash: ContentHash,
    /// Hash of the cell's configuration.
    pub config_hash: ContentHash,
    /// Hash of the applicable policy.
    pub policy_hash: ContentHash,
    /// Hash of the evidence schema governing the cell's outputs.
    pub evidence_schema_hash: ContentHash,
    /// Runtime version string.
    pub runtime_version: String,
    /// Platform identifier.
    pub platform: PlatformKind,
}

impl MeasurementDigest {
    /// Derive a deterministic object ID for this measurement.
    pub fn derive_id(&self, zone: &str) -> Result<EngineObjectId, CellError> {
        let canonical = self.canonical_bytes();
        engine_object_id::derive_id(
            ObjectDomain::Attestation,
            zone,
            &measurement_schema_id(),
            &canonical,
        )
        .map_err(|e| CellError::IdDerivation(e.to_string()))
    }

    /// Canonical byte representation for hashing/signing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.code_hash.as_bytes());
        buf.extend_from_slice(self.config_hash.as_bytes());
        buf.extend_from_slice(self.policy_hash.as_bytes());
        buf.extend_from_slice(self.evidence_schema_hash.as_bytes());
        buf.extend_from_slice(self.runtime_version.as_bytes());
        buf.extend_from_slice(&[self.platform as u8]);
        buf
    }

    /// Composite hash of the entire measurement.
    pub fn composite_hash(&self) -> ContentHash {
        ContentHash::compute(&self.canonical_bytes())
    }
}

// ---------------------------------------------------------------------------
// AttestationQuote — attestation evidence from a trust root
// ---------------------------------------------------------------------------

/// An attestation quote binding a measurement to a trust root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationQuote {
    /// The measurement this quote attests to.
    pub measurement: MeasurementDigest,
    /// Nonce challenge that was included in the quote.
    pub nonce: [u8; 32],
    /// Timestamp when the quote was issued (nanoseconds).
    pub issued_at_ns: u64,
    /// Validity window in nanoseconds from issuance.
    pub validity_window_ns: u64,
    /// Trust level of the backend that produced this quote.
    pub trust_level: TrustLevel,
    /// Platform that produced this quote.
    pub platform: PlatformKind,
    /// Signature bytes (opaque; format depends on backend).
    pub signature_bytes: Vec<u8>,
    /// Signer key identifier.
    pub signer_key_id: String,
}

impl AttestationQuote {
    /// Canonical bytes that must be integrity-bound by the trust-root signature.
    fn signature_payload(&self) -> Vec<u8> {
        let mut buf = self.measurement.canonical_bytes();
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.issued_at_ns.to_be_bytes());
        buf.extend_from_slice(&self.validity_window_ns.to_be_bytes());
        buf.push(self.trust_level as u8);
        buf.push(self.platform as u8);
        buf.extend_from_slice(self.signer_key_id.as_bytes());
        buf
    }

    /// Whether this quote is still fresh at the given timestamp.
    pub fn is_fresh_at(&self, current_ns: u64) -> bool {
        current_ns <= self.issued_at_ns.saturating_add(self.validity_window_ns)
    }

    /// Whether this quote has expired at the given timestamp.
    pub fn is_expired_at(&self, current_ns: u64) -> bool {
        !self.is_fresh_at(current_ns)
    }
}

// ---------------------------------------------------------------------------
// VerificationResult — outcome of verifying an attestation quote
// ---------------------------------------------------------------------------

/// Outcome of verifying an attestation quote against expected measurements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationResult {
    /// Quote is valid: measurement matches, signature verifies, quote is fresh.
    Valid,
    /// Measurement does not match expected value.
    MeasurementMismatch {
        expected: ContentHash,
        actual: ContentHash,
    },
    /// Quote signature verification failed.
    SignatureInvalid,
    /// Quote has expired.
    Expired {
        issued_at_ns: u64,
        validity_window_ns: u64,
        checked_at_ns: u64,
    },
    /// Nonce does not match the expected challenge.
    NonceMismatch,
    /// Signer key is revoked.
    SignerRevoked { key_id: String },
}

impl VerificationResult {
    /// Whether verification succeeded.
    pub fn is_valid(&self) -> bool {
        *self == Self::Valid
    }
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => f.write_str("valid"),
            Self::MeasurementMismatch { .. } => f.write_str("measurement-mismatch"),
            Self::SignatureInvalid => f.write_str("signature-invalid"),
            Self::Expired { .. } => f.write_str("expired"),
            Self::NonceMismatch => f.write_str("nonce-mismatch"),
            Self::SignerRevoked { key_id } => write!(f, "signer-revoked({key_id})"),
        }
    }
}

// ---------------------------------------------------------------------------
// TrustRootBackend — trait for attestation backends
// ---------------------------------------------------------------------------

/// Trait abstracting the trust root for attestation operations.
///
/// Implementations:
/// - **SoftwareTrustRoot**: For development/CI. Software-only measurement
///   and signing. Explicitly marked as non-production trust level.
/// - Future: hardware TEE backends (Intel SGX, ARM CCA, AMD SEV-SNP).
pub trait TrustRootBackend: fmt::Debug {
    /// The trust level this backend provides.
    fn trust_level(&self) -> TrustLevel;

    /// The platform kind this backend targets.
    fn platform(&self) -> PlatformKind;

    /// Compute the measurement of a cell's code and configuration.
    fn measure(
        &self,
        code: &[u8],
        config: &[u8],
        policy: &[u8],
        evidence_schema: &[u8],
        runtime_version: &str,
    ) -> MeasurementDigest;

    /// Produce an attestation quote binding the measurement to this trust root.
    fn attest(
        &self,
        measurement: &MeasurementDigest,
        nonce: [u8; 32],
        validity_window_ns: u64,
        issued_at_ns: u64,
    ) -> AttestationQuote;

    /// Verify an attestation quote against expected measurement and nonce.
    fn verify(
        &self,
        quote: &AttestationQuote,
        expected_measurement: &MeasurementDigest,
        expected_nonce: &[u8; 32],
        current_ns: u64,
    ) -> VerificationResult;
}

// ---------------------------------------------------------------------------
// SoftwareTrustRoot — development/CI attestation backend
// ---------------------------------------------------------------------------

/// Software-only trust root for development and testing.
///
/// Produces deterministic measurements and self-signed quotes.
/// **Not for production use** — explicitly labeled `TrustLevel::SoftwareOnly`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareTrustRoot {
    /// Key identifier for this software root.
    pub key_id: String,
    /// Secret key bytes for signing (deterministic, not secure).
    pub secret_key_bytes: [u8; 32],
    /// Set of revoked key IDs.
    pub revoked_keys: BTreeSet<String>,
}

impl SoftwareTrustRoot {
    /// Create a new software trust root with the given key ID and seed.
    pub fn new(key_id: &str, seed: u64) -> Self {
        let mut key = [0u8; 32];
        let seed_bytes = seed.to_le_bytes();
        key[..8].copy_from_slice(&seed_bytes);
        // Fill remaining bytes deterministically.
        for i in 8..32 {
            key[i] = key[i - 8].wrapping_add(i as u8);
        }
        Self {
            key_id: key_id.to_string(),
            secret_key_bytes: key,
            revoked_keys: BTreeSet::new(),
        }
    }

    /// Revoke a signer key.
    pub fn revoke_key(&mut self, key_id: &str) {
        self.revoked_keys.insert(key_id.to_string());
    }

    fn sign(&self, data: &[u8]) -> Vec<u8> {
        // Deterministic HMAC-like construction for testing.
        let mut sig_input = Vec::with_capacity(32 + data.len());
        sig_input.extend_from_slice(&self.secret_key_bytes);
        sig_input.extend_from_slice(data);
        ContentHash::compute(&sig_input).as_bytes().to_vec()
    }

    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> bool {
        let expected = self.sign(data);
        expected == signature
    }
}

impl TrustRootBackend for SoftwareTrustRoot {
    fn trust_level(&self) -> TrustLevel {
        TrustLevel::SoftwareOnly
    }

    fn platform(&self) -> PlatformKind {
        PlatformKind::Software
    }

    fn measure(
        &self,
        code: &[u8],
        config: &[u8],
        policy: &[u8],
        evidence_schema: &[u8],
        runtime_version: &str,
    ) -> MeasurementDigest {
        MeasurementDigest {
            code_hash: ContentHash::compute(code),
            config_hash: ContentHash::compute(config),
            policy_hash: ContentHash::compute(policy),
            evidence_schema_hash: ContentHash::compute(evidence_schema),
            runtime_version: runtime_version.to_string(),
            platform: PlatformKind::Software,
        }
    }

    fn attest(
        &self,
        measurement: &MeasurementDigest,
        nonce: [u8; 32],
        validity_window_ns: u64,
        issued_at_ns: u64,
    ) -> AttestationQuote {
        let mut quote = AttestationQuote {
            measurement: measurement.clone(),
            nonce,
            issued_at_ns,
            validity_window_ns,
            trust_level: TrustLevel::SoftwareOnly,
            platform: PlatformKind::Software,
            signature_bytes: Vec::new(),
            signer_key_id: self.key_id.clone(),
        };
        quote.signature_bytes = self.sign(&quote.signature_payload());
        quote
    }

    fn verify(
        &self,
        quote: &AttestationQuote,
        expected_measurement: &MeasurementDigest,
        expected_nonce: &[u8; 32],
        current_ns: u64,
    ) -> VerificationResult {
        if quote.signer_key_id != self.key_id {
            return VerificationResult::SignatureInvalid;
        }

        // Check revocation.
        if self.revoked_keys.contains(&quote.signer_key_id) {
            return VerificationResult::SignerRevoked {
                key_id: quote.signer_key_id.clone(),
            };
        }

        // Check signature before trusting mutable quote metadata.
        if !self.verify_signature(&quote.signature_payload(), &quote.signature_bytes) {
            return VerificationResult::SignatureInvalid;
        }

        // Check freshness.
        if quote.is_expired_at(current_ns) {
            return VerificationResult::Expired {
                issued_at_ns: quote.issued_at_ns,
                validity_window_ns: quote.validity_window_ns,
                checked_at_ns: current_ns,
            };
        }

        // Check nonce.
        if quote.nonce != *expected_nonce {
            return VerificationResult::NonceMismatch;
        }

        // Check measurement.
        let expected_composite = expected_measurement.composite_hash();
        let actual_composite = quote.measurement.composite_hash();
        if expected_composite != actual_composite {
            return VerificationResult::MeasurementMismatch {
                expected: expected_composite,
                actual: actual_composite,
            };
        }

        VerificationResult::Valid
    }
}

// ---------------------------------------------------------------------------
// CellFunction — what the cell does
// ---------------------------------------------------------------------------

/// The runtime function a cell performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CellFunction {
    /// Decision receipt signing.
    DecisionReceiptSigner,
    /// Evidence accumulation and emission.
    EvidenceAccumulator,
    /// Policy evaluation.
    PolicyEvaluator,
    /// Optimizer proof validation.
    ProofValidator,
    /// General-purpose extension execution.
    ExtensionRuntime,
}

impl fmt::Display for CellFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecisionReceiptSigner => f.write_str("decision-receipt-signer"),
            Self::EvidenceAccumulator => f.write_str("evidence-accumulator"),
            Self::PolicyEvaluator => f.write_str("policy-evaluator"),
            Self::ProofValidator => f.write_str("proof-validator"),
            Self::ExtensionRuntime => f.write_str("extension-runtime"),
        }
    }
}

// ---------------------------------------------------------------------------
// ExecutionCell — a single attested execution compartment
// ---------------------------------------------------------------------------

/// An attested execution cell with its full lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionCell {
    /// Deterministic cell identifier.
    pub cell_id: EngineObjectId,
    /// Human-readable label.
    pub label: String,
    /// What this cell does.
    pub function: CellFunction,
    /// Current lifecycle state.
    pub lifecycle: CellLifecycle,
    /// Security epoch of last state transition.
    pub epoch: SecurityEpoch,
    /// Zone this cell belongs to.
    pub zone: String,
    /// Measurement of the cell's current code/config.
    pub measurement: Option<MeasurementDigest>,
    /// Most recent attestation quote.
    pub attestation: Option<AttestationQuote>,
    /// Trust level of the attestation backend.
    pub trust_level: TrustLevel,
    /// Lifecycle transition receipts.
    pub transition_receipts: Vec<LifecycleReceipt>,
    /// Set of capabilities this cell is authorized to exercise.
    pub authority_envelope: BTreeSet<String>,
}

/// A signed receipt recording a lifecycle state transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleReceipt {
    /// Previous lifecycle state.
    pub from_state: CellLifecycle,
    /// New lifecycle state.
    pub to_state: CellLifecycle,
    /// Timestamp of the transition (nanoseconds).
    pub timestamp_ns: u64,
    /// Security epoch at transition.
    pub epoch: SecurityEpoch,
    /// Reason for the transition.
    pub reason: String,
    /// Signature over the transition (from the trust root).
    pub signature_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// CellError — errors from cell operations
// ---------------------------------------------------------------------------

/// Errors from execution cell operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellError {
    /// ID derivation failed.
    IdDerivation(String),
    /// Cell not found in registry.
    NotFound { cell_id: String },
    /// Duplicate cell in registry.
    Duplicate { cell_id: String },
    /// Invalid lifecycle transition.
    InvalidTransition {
        from: CellLifecycle,
        to: CellLifecycle,
    },
    /// Cell is not operational.
    NotOperational { lifecycle: CellLifecycle },
    /// Attestation verification failed.
    AttestationFailed { reason: String },
    /// Measurement not yet taken.
    NotMeasured,
    /// Trust root revoked.
    TrustRootRevoked { key_id: String },
    /// Label is empty.
    EmptyLabel,
    /// Zone is empty.
    EmptyZone,
    /// Authority envelope is empty.
    EmptyAuthority,
}

impl fmt::Display for CellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdDerivation(msg) => write!(f, "id derivation failed: {msg}"),
            Self::NotFound { cell_id } => write!(f, "cell not found: {cell_id}"),
            Self::Duplicate { cell_id } => write!(f, "duplicate cell: {cell_id}"),
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid transition: {from} -> {to}")
            }
            Self::NotOperational { lifecycle } => {
                write!(f, "cell not operational (state: {lifecycle})")
            }
            Self::AttestationFailed { reason } => {
                write!(f, "attestation failed: {reason}")
            }
            Self::NotMeasured => f.write_str("cell has not been measured"),
            Self::TrustRootRevoked { key_id } => {
                write!(f, "trust root revoked: {key_id}")
            }
            Self::EmptyLabel => f.write_str("cell label must not be empty"),
            Self::EmptyZone => f.write_str("cell zone must not be empty"),
            Self::EmptyAuthority => f.write_str("authority envelope must not be empty"),
        }
    }
}

impl std::error::Error for CellError {}

// ---------------------------------------------------------------------------
// CreateCellInput — input struct for cell creation
// ---------------------------------------------------------------------------

/// Input for creating a new execution cell.
#[derive(Debug, Clone)]
pub struct CreateCellInput {
    pub label: String,
    pub function: CellFunction,
    pub zone: String,
    pub epoch: SecurityEpoch,
    pub trust_level: TrustLevel,
    pub authority_envelope: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// CellRegistry — manages execution cells
// ---------------------------------------------------------------------------

/// Registry of attested execution cells.
///
/// Provides CRUD operations, lifecycle management, and lookup by
/// function type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellRegistry {
    /// All registered cells, keyed by cell_id display string.
    cells: BTreeMap<String, ExecutionCell>,
    /// Index: function → cell_ids.
    function_index: BTreeMap<CellFunction, BTreeSet<String>>,
    /// Index: zone → cell_ids.
    zone_index: BTreeMap<String, BTreeSet<String>>,
    /// Audit events.
    events: Vec<CellEvent>,
    /// Next event sequence number.
    next_seq: u64,
}

/// Audit event types for cell operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellEventType {
    /// Cell was created.
    Created,
    /// Cell was measured.
    Measured,
    /// Cell was attested.
    Attested,
    /// Cell became active.
    Activated,
    /// Cell was suspended.
    Suspended { reason: String },
    /// Cell was decommissioned.
    Decommissioned { reason: String },
    /// Attestation fallback activated.
    FallbackActivated { reason: String },
    /// Re-attestation succeeded.
    ReattestationSucceeded,
}

/// A timestamped cell audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellEvent {
    /// Monotonic sequence number.
    pub seq: u64,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Cell identifier.
    pub cell_id: String,
    /// Event payload.
    pub event_type: CellEventType,
}

impl CellRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            cells: BTreeMap::new(),
            function_index: BTreeMap::new(),
            zone_index: BTreeMap::new(),
            events: Vec::new(),
            next_seq: 0,
        }
    }

    /// Create and register a new cell in Provisioning state.
    pub fn create_cell(
        &mut self,
        input: CreateCellInput,
        timestamp_ns: u64,
    ) -> Result<EngineObjectId, CellError> {
        if input.label.trim().is_empty() {
            return Err(CellError::EmptyLabel);
        }
        if input.zone.trim().is_empty() {
            return Err(CellError::EmptyZone);
        }
        if input.authority_envelope.is_empty() {
            return Err(CellError::EmptyAuthority);
        }

        // Derive deterministic cell ID.
        let mut canonical = Vec::new();
        canonical.extend_from_slice(input.label.as_bytes());
        canonical.extend_from_slice(input.zone.as_bytes());
        canonical.extend_from_slice(&input.epoch.as_u64().to_be_bytes());
        canonical.push(input.function as u8);
        let cell_id = engine_object_id::derive_id(
            ObjectDomain::Attestation,
            &input.zone,
            &cell_schema_id(),
            &canonical,
        )
        .map_err(|e| CellError::IdDerivation(e.to_string()))?;

        let cell_id_str = format!("{cell_id}");
        if self.cells.contains_key(&cell_id_str) {
            return Err(CellError::Duplicate {
                cell_id: cell_id_str,
            });
        }

        let cell = ExecutionCell {
            cell_id: cell_id.clone(),
            label: input.label,
            function: input.function,
            lifecycle: CellLifecycle::Provisioning,
            epoch: input.epoch,
            zone: input.zone.clone(),
            measurement: None,
            attestation: None,
            trust_level: input.trust_level,
            transition_receipts: Vec::new(),
            authority_envelope: input.authority_envelope,
        };

        self.function_index
            .entry(input.function)
            .or_default()
            .insert(cell_id_str.clone());
        self.zone_index
            .entry(input.zone)
            .or_default()
            .insert(cell_id_str.clone());
        self.cells.insert(cell_id_str.clone(), cell);

        self.emit_event(CellEvent {
            seq: 0,
            timestamp_ns,
            epoch: input.epoch,
            cell_id: cell_id_str,
            event_type: CellEventType::Created,
        });

        Ok(cell_id)
    }

    /// Record the measurement of a cell (transitions Provisioning → Measured).
    pub fn measure_cell(
        &mut self,
        cell_id: &str,
        measurement: MeasurementDigest,
        timestamp_ns: u64,
        epoch: SecurityEpoch,
    ) -> Result<(), CellError> {
        let cell = self
            .cells
            .get_mut(cell_id)
            .ok_or_else(|| CellError::NotFound {
                cell_id: cell_id.to_string(),
            })?;

        if cell.lifecycle != CellLifecycle::Provisioning {
            return Err(CellError::InvalidTransition {
                from: cell.lifecycle,
                to: CellLifecycle::Measured,
            });
        }

        cell.measurement = Some(measurement);
        let receipt = LifecycleReceipt {
            from_state: cell.lifecycle,
            to_state: CellLifecycle::Measured,
            timestamp_ns,
            epoch,
            reason: "measurement recorded".to_string(),
            signature_bytes: Vec::new(),
        };
        cell.lifecycle = CellLifecycle::Measured;
        cell.epoch = epoch;
        cell.transition_receipts.push(receipt);

        self.emit_event(CellEvent {
            seq: 0,
            timestamp_ns,
            epoch,
            cell_id: cell_id.to_string(),
            event_type: CellEventType::Measured,
        });

        Ok(())
    }

    /// Record attestation of a cell (transitions Measured → Attested).
    pub fn attest_cell(
        &mut self,
        cell_id: &str,
        quote: AttestationQuote,
        timestamp_ns: u64,
        epoch: SecurityEpoch,
    ) -> Result<(), CellError> {
        let cell = self
            .cells
            .get_mut(cell_id)
            .ok_or_else(|| CellError::NotFound {
                cell_id: cell_id.to_string(),
            })?;

        if cell.lifecycle != CellLifecycle::Measured && cell.lifecycle != CellLifecycle::Suspended {
            return Err(CellError::InvalidTransition {
                from: cell.lifecycle,
                to: CellLifecycle::Attested,
            });
        }

        let from_state = cell.lifecycle;
        cell.attestation = Some(quote);
        let receipt = LifecycleReceipt {
            from_state,
            to_state: CellLifecycle::Attested,
            timestamp_ns,
            epoch,
            reason: "attestation quote recorded".to_string(),
            signature_bytes: Vec::new(),
        };
        cell.lifecycle = CellLifecycle::Attested;
        cell.epoch = epoch;
        cell.transition_receipts.push(receipt);

        let event_type = if from_state == CellLifecycle::Suspended {
            CellEventType::ReattestationSucceeded
        } else {
            CellEventType::Attested
        };

        self.emit_event(CellEvent {
            seq: 0,
            timestamp_ns,
            epoch,
            cell_id: cell_id.to_string(),
            event_type,
        });

        Ok(())
    }

    /// Activate a cell (transitions Attested → Active).
    pub fn activate_cell(
        &mut self,
        cell_id: &str,
        timestamp_ns: u64,
        epoch: SecurityEpoch,
    ) -> Result<(), CellError> {
        let cell = self
            .cells
            .get_mut(cell_id)
            .ok_or_else(|| CellError::NotFound {
                cell_id: cell_id.to_string(),
            })?;

        if cell.lifecycle != CellLifecycle::Attested {
            return Err(CellError::InvalidTransition {
                from: cell.lifecycle,
                to: CellLifecycle::Active,
            });
        }

        let receipt = LifecycleReceipt {
            from_state: cell.lifecycle,
            to_state: CellLifecycle::Active,
            timestamp_ns,
            epoch,
            reason: "cell activated".to_string(),
            signature_bytes: Vec::new(),
        };
        cell.lifecycle = CellLifecycle::Active;
        cell.epoch = epoch;
        cell.transition_receipts.push(receipt);

        self.emit_event(CellEvent {
            seq: 0,
            timestamp_ns,
            epoch,
            cell_id: cell_id.to_string(),
            event_type: CellEventType::Activated,
        });

        Ok(())
    }

    /// Suspend a cell (transitions Active → Suspended).
    pub fn suspend_cell(
        &mut self,
        cell_id: &str,
        reason: &str,
        timestamp_ns: u64,
        epoch: SecurityEpoch,
    ) -> Result<(), CellError> {
        let cell = self
            .cells
            .get_mut(cell_id)
            .ok_or_else(|| CellError::NotFound {
                cell_id: cell_id.to_string(),
            })?;

        if cell.lifecycle != CellLifecycle::Active {
            return Err(CellError::InvalidTransition {
                from: cell.lifecycle,
                to: CellLifecycle::Suspended,
            });
        }

        let receipt = LifecycleReceipt {
            from_state: cell.lifecycle,
            to_state: CellLifecycle::Suspended,
            timestamp_ns,
            epoch,
            reason: reason.to_string(),
            signature_bytes: Vec::new(),
        };
        cell.lifecycle = CellLifecycle::Suspended;
        cell.epoch = epoch;
        cell.transition_receipts.push(receipt);

        self.emit_event(CellEvent {
            seq: 0,
            timestamp_ns,
            epoch,
            cell_id: cell_id.to_string(),
            event_type: CellEventType::Suspended {
                reason: reason.to_string(),
            },
        });

        Ok(())
    }

    /// Decommission a cell (final state, from Active or Suspended).
    pub fn decommission_cell(
        &mut self,
        cell_id: &str,
        reason: &str,
        timestamp_ns: u64,
        epoch: SecurityEpoch,
    ) -> Result<(), CellError> {
        let cell = self
            .cells
            .get_mut(cell_id)
            .ok_or_else(|| CellError::NotFound {
                cell_id: cell_id.to_string(),
            })?;

        if cell.lifecycle != CellLifecycle::Active && cell.lifecycle != CellLifecycle::Suspended {
            return Err(CellError::InvalidTransition {
                from: cell.lifecycle,
                to: CellLifecycle::Decommissioned,
            });
        }

        let receipt = LifecycleReceipt {
            from_state: cell.lifecycle,
            to_state: CellLifecycle::Decommissioned,
            timestamp_ns,
            epoch,
            reason: reason.to_string(),
            signature_bytes: Vec::new(),
        };
        cell.lifecycle = CellLifecycle::Decommissioned;
        cell.epoch = epoch;
        cell.transition_receipts.push(receipt);

        self.emit_event(CellEvent {
            seq: 0,
            timestamp_ns,
            epoch,
            cell_id: cell_id.to_string(),
            event_type: CellEventType::Decommissioned {
                reason: reason.to_string(),
            },
        });

        Ok(())
    }

    /// Suspend all cells bound to a revoked trust root key.
    pub fn revoke_trust_root(
        &mut self,
        revoked_key_id: &str,
        timestamp_ns: u64,
        epoch: SecurityEpoch,
    ) -> Vec<String> {
        let mut suspended = Vec::new();
        let cell_ids: Vec<String> = self.cells.keys().cloned().collect();

        for cell_id in cell_ids {
            let should_suspend = {
                let cell = &self.cells[&cell_id];
                cell.lifecycle == CellLifecycle::Active
                    && cell
                        .attestation
                        .as_ref()
                        .is_some_and(|q| q.signer_key_id == revoked_key_id)
            };

            if should_suspend
                && self
                    .suspend_cell(
                        &cell_id,
                        &format!("trust root revoked: {revoked_key_id}"),
                        timestamp_ns,
                        epoch,
                    )
                    .is_ok()
            {
                suspended.push(cell_id);
            }
        }

        suspended
    }

    /// Get a cell by ID.
    pub fn get(&self, cell_id: &str) -> Option<&ExecutionCell> {
        self.cells.get(cell_id)
    }

    /// Get all cells with a specific function.
    pub fn cells_by_function(&self, function: CellFunction) -> Vec<&ExecutionCell> {
        self.function_index
            .get(&function)
            .map(|ids| ids.iter().filter_map(|id| self.cells.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get all active cells.
    pub fn active_cells(&self) -> Vec<&ExecutionCell> {
        self.cells
            .values()
            .filter(|c| c.lifecycle.is_operational())
            .collect()
    }

    /// Get all cells in a zone.
    pub fn cells_in_zone(&self, zone: &str) -> Vec<&ExecutionCell> {
        self.zone_index
            .get(zone)
            .map(|ids| ids.iter().filter_map(|id| self.cells.get(id)).collect())
            .unwrap_or_default()
    }

    /// Total cell count.
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// All audit events.
    pub fn events(&self) -> &[CellEvent] {
        &self.events
    }

    fn emit_event(&mut self, mut event: CellEvent) {
        event.seq = self.next_seq;
        self.next_seq += 1;
        self.events.push(event);
    }
}

impl Default for CellRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FallbackPolicy — degradation behavior on attestation failure
// ---------------------------------------------------------------------------

/// Policy governing degradation when attestation fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackPolicy {
    /// Whether automatic fallback is enabled.
    pub auto_fallback: bool,
    /// High-impact actions that require attestation (degrade to safe mode
    /// when attestation is unavailable).
    pub high_impact_actions: BTreeSet<String>,
    /// Safe mode: challenge before allowing high-impact actions.
    pub challenge_on_fallback: bool,
    /// Safe mode: sandbox extensions on fallback.
    pub sandbox_on_fallback: bool,
}

impl Default for FallbackPolicy {
    fn default() -> Self {
        Self {
            auto_fallback: true,
            high_impact_actions: BTreeSet::new(),
            challenge_on_fallback: true,
            sandbox_on_fallback: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn test_trust_root() -> SoftwareTrustRoot {
        SoftwareTrustRoot::new("test-key-1", 12345)
    }

    fn default_cell_input() -> CreateCellInput {
        let mut auth = BTreeSet::new();
        auth.insert("sign_receipts".to_string());
        auth.insert("emit_evidence".to_string());
        CreateCellInput {
            label: "receipt-signer-1".to_string(),
            function: CellFunction::DecisionReceiptSigner,
            zone: "production".to_string(),
            epoch: test_epoch(),
            trust_level: TrustLevel::SoftwareOnly,
            authority_envelope: auth,
        }
    }

    fn test_measurement(root: &SoftwareTrustRoot) -> MeasurementDigest {
        root.measure(
            b"cell-code-v1",
            b"cell-config-v1",
            b"cell-policy-v1",
            b"evidence-schema-v1",
            "1.0.0",
        )
    }

    fn test_quote(
        root: &SoftwareTrustRoot,
        measurement: &MeasurementDigest,
        nonce: [u8; 32],
        issued_at_ns: u64,
        validity_window_ns: u64,
    ) -> AttestationQuote {
        root.attest(measurement, nonce, validity_window_ns, issued_at_ns)
    }

    // --- CellLifecycle ---

    #[test]
    fn lifecycle_display() {
        assert_eq!(CellLifecycle::Provisioning.to_string(), "provisioning");
        assert_eq!(CellLifecycle::Measured.to_string(), "measured");
        assert_eq!(CellLifecycle::Attested.to_string(), "attested");
        assert_eq!(CellLifecycle::Active.to_string(), "active");
        assert_eq!(CellLifecycle::Suspended.to_string(), "suspended");
        assert_eq!(CellLifecycle::Decommissioned.to_string(), "decommissioned");
    }

    #[test]
    fn lifecycle_operational() {
        assert!(!CellLifecycle::Provisioning.is_operational());
        assert!(!CellLifecycle::Measured.is_operational());
        assert!(!CellLifecycle::Attested.is_operational());
        assert!(CellLifecycle::Active.is_operational());
        assert!(!CellLifecycle::Suspended.is_operational());
        assert!(!CellLifecycle::Decommissioned.is_operational());
    }

    #[test]
    fn lifecycle_allows_reattestation() {
        assert!(!CellLifecycle::Provisioning.allows_reattestation());
        assert!(CellLifecycle::Measured.allows_reattestation());
        assert!(!CellLifecycle::Attested.allows_reattestation());
        assert!(!CellLifecycle::Active.allows_reattestation());
        assert!(CellLifecycle::Suspended.allows_reattestation());
        assert!(!CellLifecycle::Decommissioned.allows_reattestation());
    }

    // --- TrustLevel ---

    #[test]
    fn trust_level_ordering() {
        assert!(TrustLevel::SoftwareOnly < TrustLevel::Hybrid);
        assert!(TrustLevel::Hybrid < TrustLevel::Hardware);
    }

    #[test]
    fn trust_level_display() {
        assert_eq!(TrustLevel::SoftwareOnly.to_string(), "software-only");
        assert_eq!(TrustLevel::Hybrid.to_string(), "hybrid");
        assert_eq!(TrustLevel::Hardware.to_string(), "hardware");
    }

    // --- PlatformKind ---

    #[test]
    fn platform_display() {
        assert_eq!(PlatformKind::IntelSgx.to_string(), "intel-sgx");
        assert_eq!(PlatformKind::ArmCca.to_string(), "arm-cca");
        assert_eq!(PlatformKind::AmdSevSnp.to_string(), "amd-sev-snp");
        assert_eq!(PlatformKind::Software.to_string(), "software");
    }

    // --- MeasurementDigest ---

    #[test]
    fn measurement_deterministic() {
        let root = test_trust_root();
        let m1 = test_measurement(&root);
        let m2 = test_measurement(&root);
        assert_eq!(m1, m2);
        assert_eq!(m1.composite_hash(), m2.composite_hash());
    }

    #[test]
    fn measurement_different_inputs_differ() {
        let root = test_trust_root();
        let m1 = root.measure(b"code-a", b"config", b"policy", b"schema", "1.0");
        let m2 = root.measure(b"code-b", b"config", b"policy", b"schema", "1.0");
        assert_ne!(m1.composite_hash(), m2.composite_hash());
    }

    #[test]
    fn measurement_derive_id() {
        let root = test_trust_root();
        let m = test_measurement(&root);
        let id = m.derive_id("production").unwrap();
        let id2 = m.derive_id("production").unwrap();
        assert_eq!(id, id2); // Deterministic.
    }

    #[test]
    fn measurement_derive_id_different_zones() {
        let root = test_trust_root();
        let m = test_measurement(&root);
        let id1 = m.derive_id("zone-a").unwrap();
        let id2 = m.derive_id("zone-b").unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn measurement_serde_roundtrip() {
        let root = test_trust_root();
        let m = test_measurement(&root);
        let json = serde_json::to_string(&m).unwrap();
        let restored: MeasurementDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, restored);
    }

    // --- AttestationQuote ---

    #[test]
    fn quote_freshness() {
        let root = test_trust_root();
        let m = test_measurement(&root);
        let quote = test_quote(&root, &m, [1u8; 32], 100, 1_000_000_000);

        assert!(quote.is_fresh_at(100));
        assert!(quote.is_fresh_at(1_000_000_100));
        assert!(!quote.is_fresh_at(1_000_000_101));
    }

    #[test]
    fn quote_serde_roundtrip() {
        let root = test_trust_root();
        let m = test_measurement(&root);
        let quote = test_quote(&root, &m, [2u8; 32], 200, 5_000_000);
        let json = serde_json::to_string(&quote).unwrap();
        let restored: AttestationQuote = serde_json::from_str(&json).unwrap();
        assert_eq!(quote, restored);
    }

    // --- VerificationResult ---

    #[test]
    fn verification_result_display() {
        assert_eq!(VerificationResult::Valid.to_string(), "valid");
        assert_eq!(
            VerificationResult::SignatureInvalid.to_string(),
            "signature-invalid"
        );
        assert_eq!(
            VerificationResult::NonceMismatch.to_string(),
            "nonce-mismatch"
        );
    }

    #[test]
    fn verification_is_valid() {
        assert!(VerificationResult::Valid.is_valid());
        assert!(!VerificationResult::NonceMismatch.is_valid());
    }

    // --- SoftwareTrustRoot ---

    #[test]
    fn software_root_trust_level() {
        let root = test_trust_root();
        assert_eq!(root.trust_level(), TrustLevel::SoftwareOnly);
        assert_eq!(root.platform(), PlatformKind::Software);
    }

    #[test]
    fn software_root_measure_and_verify_happy_path() {
        let root = test_trust_root();
        let m = test_measurement(&root);
        let nonce = [42u8; 32];
        let quote = test_quote(&root, &m, nonce, 1000, 10_000_000);

        let result = root.verify(&quote, &m, &nonce, 5000);
        assert_eq!(result, VerificationResult::Valid);
    }

    #[test]
    fn software_root_verify_expired() {
        let root = test_trust_root();
        let m = test_measurement(&root);
        let nonce = [1u8; 32];
        let quote = test_quote(&root, &m, nonce, 1000, 100);

        let result = root.verify(&quote, &m, &nonce, 2000);
        assert!(matches!(result, VerificationResult::Expired { .. }));
    }

    #[test]
    fn software_root_verify_nonce_mismatch() {
        let root = test_trust_root();
        let m = test_measurement(&root);
        let nonce = [1u8; 32];
        let wrong_nonce = [2u8; 32];
        let quote = test_quote(&root, &m, nonce, 1000, 10_000);

        let result = root.verify(&quote, &m, &wrong_nonce, 1500);
        assert_eq!(result, VerificationResult::NonceMismatch);
    }

    #[test]
    fn software_root_verify_measurement_mismatch() {
        let root = test_trust_root();
        let m = test_measurement(&root);
        let nonce = [1u8; 32];
        let quote = test_quote(&root, &m, nonce, 1000, 10_000);

        let different_m = root.measure(b"other-code", b"config", b"policy", b"schema", "2.0");
        let result = root.verify(&quote, &different_m, &nonce, 1500);
        assert!(matches!(
            result,
            VerificationResult::MeasurementMismatch { .. }
        ));
    }

    #[test]
    fn software_root_verify_revoked_key() {
        let mut root = test_trust_root();
        let m = test_measurement(&root);
        let nonce = [1u8; 32];
        let quote = test_quote(&root, &m, nonce, 1000, 10_000);

        root.revoke_key("test-key-1");
        let result = root.verify(&quote, &m, &nonce, 1500);
        assert!(matches!(result, VerificationResult::SignerRevoked { .. }));
    }

    #[test]
    fn software_root_verify_tampered_signature() {
        let root = test_trust_root();
        let m = test_measurement(&root);
        let nonce = [1u8; 32];
        let mut quote = test_quote(&root, &m, nonce, 1000, 10_000);
        // Tamper with signature.
        if let Some(byte) = quote.signature_bytes.first_mut() {
            *byte ^= 0xFF;
        }

        let result = root.verify(&quote, &m, &nonce, 1500);
        assert_eq!(result, VerificationResult::SignatureInvalid);
    }

    #[test]
    fn software_root_verify_tampered_issued_at_rejected() {
        let root = test_trust_root();
        let m = test_measurement(&root);
        let nonce = [3u8; 32];
        let mut quote = test_quote(&root, &m, nonce, 1000, 10_000);
        quote.issued_at_ns = 2500;

        let result = root.verify(&quote, &m, &nonce, 2600);
        assert_eq!(result, VerificationResult::SignatureInvalid);
    }

    #[test]
    fn software_root_verify_tampered_quote_metadata_rejected() {
        let root = test_trust_root();
        let m = test_measurement(&root);
        let nonce = [4u8; 32];
        let quote = test_quote(&root, &m, nonce, 1000, 10_000);

        let mut tampered_trust = quote.clone();
        tampered_trust.trust_level = TrustLevel::Hardware;
        assert_eq!(
            root.verify(&tampered_trust, &m, &nonce, 1500),
            VerificationResult::SignatureInvalid
        );

        let mut tampered_platform = quote.clone();
        tampered_platform.platform = PlatformKind::IntelSgx;
        assert_eq!(
            root.verify(&tampered_platform, &m, &nonce, 1500),
            VerificationResult::SignatureInvalid
        );

        let mut tampered_signer = quote;
        tampered_signer.signer_key_id = "other-key".to_string();
        assert_eq!(
            root.verify(&tampered_signer, &m, &nonce, 1500),
            VerificationResult::SignatureInvalid
        );
    }

    #[test]
    fn software_root_verify_wrong_root_key_rejected_even_with_same_secret() {
        let root = SoftwareTrustRoot::new("key-a", 77);
        let mismatched_root = SoftwareTrustRoot::new("key-b", 77);
        let m = test_measurement(&root);
        let nonce = [5u8; 32];
        let quote = root.attest(&m, nonce, 10_000, 1000);

        let result = mismatched_root.verify(&quote, &m, &nonce, 1500);
        assert_eq!(result, VerificationResult::SignatureInvalid);
    }

    // --- CellFunction ---

    #[test]
    fn cell_function_display() {
        assert_eq!(
            CellFunction::DecisionReceiptSigner.to_string(),
            "decision-receipt-signer"
        );
        assert_eq!(
            CellFunction::EvidenceAccumulator.to_string(),
            "evidence-accumulator"
        );
        assert_eq!(
            CellFunction::PolicyEvaluator.to_string(),
            "policy-evaluator"
        );
        assert_eq!(CellFunction::ProofValidator.to_string(), "proof-validator");
        assert_eq!(
            CellFunction::ExtensionRuntime.to_string(),
            "extension-runtime"
        );
    }

    // --- CellError ---

    #[test]
    fn cell_error_display_coverage() {
        let errors = [
            CellError::IdDerivation("test".to_string()),
            CellError::NotFound {
                cell_id: "abc".to_string(),
            },
            CellError::Duplicate {
                cell_id: "def".to_string(),
            },
            CellError::InvalidTransition {
                from: CellLifecycle::Active,
                to: CellLifecycle::Provisioning,
            },
            CellError::NotOperational {
                lifecycle: CellLifecycle::Suspended,
            },
            CellError::AttestationFailed {
                reason: "expired".to_string(),
            },
            CellError::NotMeasured,
            CellError::TrustRootRevoked {
                key_id: "key-1".to_string(),
            },
            CellError::EmptyLabel,
            CellError::EmptyZone,
            CellError::EmptyAuthority,
        ];
        for e in &errors {
            let s = e.to_string();
            assert!(!s.is_empty(), "error display should not be empty: {e:?}");
        }
    }

    // --- CellRegistry ---

    #[test]
    fn create_cell_happy_path() {
        let mut reg = CellRegistry::new();
        let cell_id = reg.create_cell(default_cell_input(), 1_000).unwrap();
        assert_eq!(reg.cell_count(), 1);

        let cell = reg.get(&format!("{cell_id}")).unwrap();
        assert_eq!(cell.lifecycle, CellLifecycle::Provisioning);
        assert_eq!(cell.function, CellFunction::DecisionReceiptSigner);
        assert_eq!(cell.zone, "production");
    }

    #[test]
    fn create_cell_rejects_empty_label() {
        let mut reg = CellRegistry::new();
        let mut input = default_cell_input();
        input.label = "  ".to_string();
        assert!(matches!(
            reg.create_cell(input, 1_000),
            Err(CellError::EmptyLabel)
        ));
    }

    #[test]
    fn create_cell_rejects_empty_zone() {
        let mut reg = CellRegistry::new();
        let mut input = default_cell_input();
        input.zone = String::new();
        assert!(matches!(
            reg.create_cell(input, 1_000),
            Err(CellError::EmptyZone)
        ));
    }

    #[test]
    fn create_cell_rejects_empty_authority() {
        let mut reg = CellRegistry::new();
        let mut input = default_cell_input();
        input.authority_envelope = BTreeSet::new();
        assert!(matches!(
            reg.create_cell(input, 1_000),
            Err(CellError::EmptyAuthority)
        ));
    }

    #[test]
    fn create_cell_rejects_duplicate() {
        let mut reg = CellRegistry::new();
        reg.create_cell(default_cell_input(), 1_000).unwrap();
        assert!(matches!(
            reg.create_cell(default_cell_input(), 2_000),
            Err(CellError::Duplicate { .. })
        ));
    }

    #[test]
    fn create_cell_deterministic_id() {
        let mut reg1 = CellRegistry::new();
        let mut reg2 = CellRegistry::new();
        let id1 = reg1.create_cell(default_cell_input(), 1_000).unwrap();
        let id2 = reg2.create_cell(default_cell_input(), 2_000).unwrap();
        assert_eq!(id1, id2);
    }

    // --- Lifecycle transitions ---

    #[test]
    fn full_lifecycle_happy_path() {
        let mut reg = CellRegistry::new();
        let root = test_trust_root();
        let epoch = test_epoch();
        let cell_id = reg.create_cell(default_cell_input(), 1_000).unwrap();
        let cid = format!("{cell_id}");

        // Measure.
        let measurement = test_measurement(&root);
        reg.measure_cell(&cid, measurement.clone(), 2_000, epoch)
            .unwrap();
        assert_eq!(reg.get(&cid).unwrap().lifecycle, CellLifecycle::Measured);

        // Attest.
        let nonce = [7u8; 32];
        let quote = root.attest(&measurement, nonce, 10_000_000, 2_000);
        reg.attest_cell(&cid, quote, 3_000, epoch).unwrap();
        assert_eq!(reg.get(&cid).unwrap().lifecycle, CellLifecycle::Attested);

        // Activate.
        reg.activate_cell(&cid, 4_000, epoch).unwrap();
        assert_eq!(reg.get(&cid).unwrap().lifecycle, CellLifecycle::Active);
        assert!(reg.get(&cid).unwrap().lifecycle.is_operational());

        // Decommission.
        reg.decommission_cell(&cid, "end of life", 5_000, epoch)
            .unwrap();
        assert_eq!(
            reg.get(&cid).unwrap().lifecycle,
            CellLifecycle::Decommissioned
        );
        assert_eq!(reg.get(&cid).unwrap().transition_receipts.len(), 4);
    }

    #[test]
    fn suspend_and_reattest_flow() {
        let mut reg = CellRegistry::new();
        let root = test_trust_root();
        let epoch = test_epoch();
        let cell_id = reg.create_cell(default_cell_input(), 1_000).unwrap();
        let cid = format!("{cell_id}");

        // Go to Active.
        let m = test_measurement(&root);
        reg.measure_cell(&cid, m.clone(), 2_000, epoch).unwrap();
        let q = root.attest(&m, [1u8; 32], 10_000_000, 2_000);
        reg.attest_cell(&cid, q, 3_000, epoch).unwrap();
        reg.activate_cell(&cid, 4_000, epoch).unwrap();

        // Suspend.
        reg.suspend_cell(&cid, "trust root update", 5_000, epoch)
            .unwrap();
        assert_eq!(reg.get(&cid).unwrap().lifecycle, CellLifecycle::Suspended);

        // Re-attest from Suspended.
        let q2 = root.attest(&m, [2u8; 32], 10_000_000, 5_000);
        reg.attest_cell(&cid, q2, 6_000, epoch).unwrap();
        assert_eq!(reg.get(&cid).unwrap().lifecycle, CellLifecycle::Attested);

        // Re-activate.
        reg.activate_cell(&cid, 7_000, epoch).unwrap();
        assert_eq!(reg.get(&cid).unwrap().lifecycle, CellLifecycle::Active);
    }

    #[test]
    fn invalid_transition_provisioning_to_active() {
        let mut reg = CellRegistry::new();
        let cell_id = reg.create_cell(default_cell_input(), 1_000).unwrap();
        let cid = format!("{cell_id}");
        assert!(matches!(
            reg.activate_cell(&cid, 2_000, test_epoch()),
            Err(CellError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn invalid_transition_measured_to_active() {
        let mut reg = CellRegistry::new();
        let root = test_trust_root();
        let cell_id = reg.create_cell(default_cell_input(), 1_000).unwrap();
        let cid = format!("{cell_id}");
        reg.measure_cell(&cid, test_measurement(&root), 2_000, test_epoch())
            .unwrap();
        assert!(matches!(
            reg.activate_cell(&cid, 3_000, test_epoch()),
            Err(CellError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn invalid_transition_suspend_from_provisioning() {
        let mut reg = CellRegistry::new();
        let cell_id = reg.create_cell(default_cell_input(), 1_000).unwrap();
        let cid = format!("{cell_id}");
        assert!(matches!(
            reg.suspend_cell(&cid, "test", 2_000, test_epoch()),
            Err(CellError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn decommission_from_suspended() {
        let mut reg = CellRegistry::new();
        let root = test_trust_root();
        let epoch = test_epoch();
        let cell_id = reg.create_cell(default_cell_input(), 1_000).unwrap();
        let cid = format!("{cell_id}");

        let m = test_measurement(&root);
        reg.measure_cell(&cid, m.clone(), 2_000, epoch).unwrap();
        let q = root.attest(&m, [1u8; 32], 10_000_000, 2_000);
        reg.attest_cell(&cid, q, 3_000, epoch).unwrap();
        reg.activate_cell(&cid, 4_000, epoch).unwrap();
        reg.suspend_cell(&cid, "test", 5_000, epoch).unwrap();
        reg.decommission_cell(&cid, "permanent removal", 6_000, epoch)
            .unwrap();
        assert_eq!(
            reg.get(&cid).unwrap().lifecycle,
            CellLifecycle::Decommissioned
        );
    }

    #[test]
    fn cell_not_found() {
        let mut reg = CellRegistry::new();
        assert!(matches!(
            reg.measure_cell(
                "nonexistent",
                test_measurement(&test_trust_root()),
                1_000,
                test_epoch()
            ),
            Err(CellError::NotFound { .. })
        ));
    }

    // --- Trust root revocation ---

    #[test]
    fn revoke_trust_root_suspends_active_cells() {
        let mut reg = CellRegistry::new();
        let root = test_trust_root();
        let epoch = test_epoch();

        // Create and activate cell.
        let cell_id = reg.create_cell(default_cell_input(), 1_000).unwrap();
        let cid = format!("{cell_id}");
        let m = test_measurement(&root);
        reg.measure_cell(&cid, m.clone(), 2_000, epoch).unwrap();
        let q = root.attest(&m, [1u8; 32], 10_000_000, 2_000);
        reg.attest_cell(&cid, q, 3_000, epoch).unwrap();
        reg.activate_cell(&cid, 4_000, epoch).unwrap();

        // Revoke trust root.
        let suspended = reg.revoke_trust_root("test-key-1", 5_000, epoch);
        assert_eq!(suspended.len(), 1);
        assert_eq!(reg.get(&cid).unwrap().lifecycle, CellLifecycle::Suspended);
    }

    #[test]
    fn revoke_trust_root_ignores_non_matching_cells() {
        let mut reg = CellRegistry::new();
        let root = test_trust_root();
        let epoch = test_epoch();

        let cell_id = reg.create_cell(default_cell_input(), 1_000).unwrap();
        let cid = format!("{cell_id}");
        let m = test_measurement(&root);
        reg.measure_cell(&cid, m.clone(), 2_000, epoch).unwrap();
        let q = root.attest(&m, [1u8; 32], 10_000_000, 2_000);
        reg.attest_cell(&cid, q, 3_000, epoch).unwrap();
        reg.activate_cell(&cid, 4_000, epoch).unwrap();

        let suspended = reg.revoke_trust_root("other-key", 5_000, epoch);
        assert!(suspended.is_empty());
        assert_eq!(reg.get(&cid).unwrap().lifecycle, CellLifecycle::Active);
    }

    // --- Registry lookups ---

    #[test]
    fn cells_by_function_lookup() {
        let mut reg = CellRegistry::new();
        reg.create_cell(default_cell_input(), 1_000).unwrap();

        let mut input2 = default_cell_input();
        input2.label = "evidence-accumulator-1".to_string();
        input2.function = CellFunction::EvidenceAccumulator;
        reg.create_cell(input2, 2_000).unwrap();

        assert_eq!(
            reg.cells_by_function(CellFunction::DecisionReceiptSigner)
                .len(),
            1
        );
        assert_eq!(
            reg.cells_by_function(CellFunction::EvidenceAccumulator)
                .len(),
            1
        );
        assert_eq!(
            reg.cells_by_function(CellFunction::PolicyEvaluator).len(),
            0
        );
    }

    #[test]
    fn cells_in_zone_lookup() {
        let mut reg = CellRegistry::new();
        reg.create_cell(default_cell_input(), 1_000).unwrap();

        let mut input2 = default_cell_input();
        input2.label = "staging-cell".to_string();
        input2.zone = "staging".to_string();
        reg.create_cell(input2, 2_000).unwrap();

        assert_eq!(reg.cells_in_zone("production").len(), 1);
        assert_eq!(reg.cells_in_zone("staging").len(), 1);
        assert_eq!(reg.cells_in_zone("dev").len(), 0);
    }

    #[test]
    fn active_cells_filters_correctly() {
        let mut reg = CellRegistry::new();
        let root = test_trust_root();
        let epoch = test_epoch();

        let cell_id = reg.create_cell(default_cell_input(), 1_000).unwrap();
        let cid = format!("{cell_id}");
        let m = test_measurement(&root);
        reg.measure_cell(&cid, m.clone(), 2_000, epoch).unwrap();
        let q = root.attest(&m, [1u8; 32], 10_000_000, 2_000);
        reg.attest_cell(&cid, q, 3_000, epoch).unwrap();
        reg.activate_cell(&cid, 4_000, epoch).unwrap();

        // Create a second cell that stays in Provisioning.
        let mut input2 = default_cell_input();
        input2.label = "other".to_string();
        reg.create_cell(input2, 5_000).unwrap();

        assert_eq!(reg.active_cells().len(), 1);
    }

    // --- Events ---

    #[test]
    fn registry_emits_events_for_lifecycle() {
        let mut reg = CellRegistry::new();
        let root = test_trust_root();
        let epoch = test_epoch();

        let cell_id = reg.create_cell(default_cell_input(), 1_000).unwrap();
        let cid = format!("{cell_id}");
        let m = test_measurement(&root);
        reg.measure_cell(&cid, m.clone(), 2_000, epoch).unwrap();
        let q = root.attest(&m, [1u8; 32], 10_000_000, 2_000);
        reg.attest_cell(&cid, q, 3_000, epoch).unwrap();
        reg.activate_cell(&cid, 4_000, epoch).unwrap();

        assert_eq!(reg.events().len(), 4);
        assert!(matches!(reg.events()[0].event_type, CellEventType::Created));
        assert!(matches!(
            reg.events()[1].event_type,
            CellEventType::Measured
        ));
        assert!(matches!(
            reg.events()[2].event_type,
            CellEventType::Attested
        ));
        assert!(matches!(
            reg.events()[3].event_type,
            CellEventType::Activated
        ));
    }

    #[test]
    fn reattestation_emits_correct_event() {
        let mut reg = CellRegistry::new();
        let root = test_trust_root();
        let epoch = test_epoch();

        let cell_id = reg.create_cell(default_cell_input(), 1_000).unwrap();
        let cid = format!("{cell_id}");
        let m = test_measurement(&root);
        reg.measure_cell(&cid, m.clone(), 2_000, epoch).unwrap();
        let q = root.attest(&m, [1u8; 32], 10_000_000, 2_000);
        reg.attest_cell(&cid, q, 3_000, epoch).unwrap();
        reg.activate_cell(&cid, 4_000, epoch).unwrap();
        reg.suspend_cell(&cid, "test", 5_000, epoch).unwrap();

        // Re-attest from suspended.
        let q2 = root.attest(&m, [2u8; 32], 10_000_000, 5_000);
        reg.attest_cell(&cid, q2, 6_000, epoch).unwrap();

        let events = reg.events();
        let last = &events[events.len() - 1];
        assert!(matches!(
            last.event_type,
            CellEventType::ReattestationSucceeded
        ));
    }

    // --- Serde round-trips ---

    #[test]
    fn cell_serde_roundtrip() {
        let mut reg = CellRegistry::new();
        let root = test_trust_root();
        let epoch = test_epoch();

        let cell_id = reg.create_cell(default_cell_input(), 1_000).unwrap();
        let cid = format!("{cell_id}");
        let m = test_measurement(&root);
        reg.measure_cell(&cid, m.clone(), 2_000, epoch).unwrap();

        let cell = reg.get(&cid).unwrap();
        let json = serde_json::to_string(cell).unwrap();
        let restored: ExecutionCell = serde_json::from_str(&json).unwrap();
        assert_eq!(*cell, restored);
    }

    #[test]
    fn registry_serde_roundtrip() {
        let mut reg = CellRegistry::new();
        reg.create_cell(default_cell_input(), 1_000).unwrap();
        let json = serde_json::to_string(&reg).unwrap();
        let restored: CellRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.cell_count(), 1);
    }

    #[test]
    fn software_trust_root_serde_roundtrip() {
        let root = test_trust_root();
        let json = serde_json::to_string(&root).unwrap();
        let restored: SoftwareTrustRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(root.key_id, restored.key_id);
        assert_eq!(root.secret_key_bytes, restored.secret_key_bytes);
    }

    #[test]
    fn verification_result_serde_roundtrip() {
        let results = vec![
            VerificationResult::Valid,
            VerificationResult::SignatureInvalid,
            VerificationResult::NonceMismatch,
            VerificationResult::Expired {
                issued_at_ns: 100,
                validity_window_ns: 50,
                checked_at_ns: 200,
            },
            VerificationResult::SignerRevoked {
                key_id: "k1".to_string(),
            },
        ];
        for r in &results {
            let json = serde_json::to_string(r).unwrap();
            let restored: VerificationResult = serde_json::from_str(&json).unwrap();
            assert_eq!(*r, restored);
        }
    }

    #[test]
    fn fallback_policy_defaults() {
        let fp = FallbackPolicy::default();
        assert!(fp.auto_fallback);
        assert!(fp.challenge_on_fallback);
        assert!(fp.sandbox_on_fallback);
        assert!(fp.high_impact_actions.is_empty());
    }

    #[test]
    fn fallback_policy_serde_roundtrip() {
        let mut fp = FallbackPolicy::default();
        fp.high_impact_actions.insert("deploy".to_string());
        let json = serde_json::to_string(&fp).unwrap();
        let restored: FallbackPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, restored);
    }

    #[test]
    fn cell_event_serde_roundtrip() {
        let event = CellEvent {
            seq: 0,
            timestamp_ns: 1_000,
            epoch: test_epoch(),
            cell_id: "test-cell".to_string(),
            event_type: CellEventType::Suspended {
                reason: "revoked".to_string(),
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: CellEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn cell_lifecycle_serde_roundtrip() {
        for lc in [
            CellLifecycle::Provisioning,
            CellLifecycle::Measured,
            CellLifecycle::Attested,
            CellLifecycle::Active,
            CellLifecycle::Suspended,
            CellLifecycle::Decommissioned,
        ] {
            let json = serde_json::to_string(&lc).unwrap();
            let restored: CellLifecycle = serde_json::from_str(&json).unwrap();
            assert_eq!(lc, restored);
        }
    }

    #[test]
    fn cell_function_serde_roundtrip() {
        for cf in [
            CellFunction::DecisionReceiptSigner,
            CellFunction::EvidenceAccumulator,
            CellFunction::PolicyEvaluator,
            CellFunction::ProofValidator,
            CellFunction::ExtensionRuntime,
        ] {
            let json = serde_json::to_string(&cf).unwrap();
            let restored: CellFunction = serde_json::from_str(&json).unwrap();
            assert_eq!(cf, restored);
        }
    }

    #[test]
    fn platform_kind_serde_roundtrip() {
        for pk in [
            PlatformKind::IntelSgx,
            PlatformKind::ArmCca,
            PlatformKind::AmdSevSnp,
            PlatformKind::Software,
        ] {
            let json = serde_json::to_string(&pk).unwrap();
            let restored: PlatformKind = serde_json::from_str(&json).unwrap();
            assert_eq!(pk, restored);
        }
    }

    #[test]
    fn trust_level_serde_roundtrip() {
        for tl in [
            TrustLevel::SoftwareOnly,
            TrustLevel::Hybrid,
            TrustLevel::Hardware,
        ] {
            let json = serde_json::to_string(&tl).unwrap();
            let restored: TrustLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(tl, restored);
        }
    }

    #[test]
    fn lifecycle_receipt_serde_roundtrip() {
        let receipt = LifecycleReceipt {
            from_state: CellLifecycle::Provisioning,
            to_state: CellLifecycle::Measured,
            timestamp_ns: 1_000,
            epoch: test_epoch(),
            reason: "initial measurement".to_string(),
            signature_bytes: vec![0u8; 64],
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let restored: LifecycleReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
    }

    // -- Enrichment: ordering --

    #[test]
    fn cell_lifecycle_ordering() {
        assert!(CellLifecycle::Provisioning < CellLifecycle::Measured);
        assert!(CellLifecycle::Measured < CellLifecycle::Attested);
        assert!(CellLifecycle::Attested < CellLifecycle::Active);
        assert!(CellLifecycle::Active < CellLifecycle::Suspended);
        assert!(CellLifecycle::Suspended < CellLifecycle::Decommissioned);
    }

    #[test]
    fn cell_function_ordering() {
        assert!(CellFunction::DecisionReceiptSigner < CellFunction::EvidenceAccumulator);
        assert!(CellFunction::EvidenceAccumulator < CellFunction::PolicyEvaluator);
        assert!(CellFunction::PolicyEvaluator < CellFunction::ProofValidator);
        assert!(CellFunction::ProofValidator < CellFunction::ExtensionRuntime);
    }

    #[test]
    fn platform_kind_ordering() {
        assert!(PlatformKind::IntelSgx < PlatformKind::ArmCca);
        assert!(PlatformKind::ArmCca < PlatformKind::AmdSevSnp);
        assert!(PlatformKind::AmdSevSnp < PlatformKind::Software);
    }

    // -- Enrichment: error trait --

    #[test]
    fn cell_error_is_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(CellError::NotMeasured),
            Box::new(CellError::EmptyLabel),
            Box::new(CellError::EmptyZone),
            Box::new(CellError::EmptyAuthority),
            Box::new(CellError::NotFound {
                cell_id: "c".to_string(),
            }),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    // -- Enrichment: cell event type serde --

    #[test]
    fn cell_event_type_serde_roundtrip() {
        let event_types = vec![
            CellEventType::Created,
            CellEventType::Measured,
            CellEventType::Attested,
            CellEventType::Activated,
            CellEventType::Suspended {
                reason: "revoked".to_string(),
            },
            CellEventType::Decommissioned {
                reason: "end of life".to_string(),
            },
            CellEventType::FallbackActivated {
                reason: "trust root expired".to_string(),
            },
            CellEventType::ReattestationSucceeded,
        ];
        for et in &event_types {
            let json = serde_json::to_string(et).unwrap();
            let restored: CellEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(*et, restored);
        }
    }

    #[test]
    fn cell_lifecycle_ord() {
        assert!(CellLifecycle::Provisioning < CellLifecycle::Measured);
        assert!(CellLifecycle::Measured < CellLifecycle::Attested);
        assert!(CellLifecycle::Attested < CellLifecycle::Active);
        assert!(CellLifecycle::Active < CellLifecycle::Suspended);
        assert!(CellLifecycle::Suspended < CellLifecycle::Decommissioned);
    }

    #[test]
    fn trust_level_ord() {
        assert!(TrustLevel::SoftwareOnly < TrustLevel::Hybrid);
        assert!(TrustLevel::Hybrid < TrustLevel::Hardware);
    }

    #[test]
    fn platform_kind_ord() {
        assert!(PlatformKind::IntelSgx < PlatformKind::ArmCca);
        assert!(PlatformKind::ArmCca < PlatformKind::AmdSevSnp);
        assert!(PlatformKind::AmdSevSnp < PlatformKind::Software);
    }

    #[test]
    fn cell_function_ord() {
        assert!(CellFunction::DecisionReceiptSigner < CellFunction::EvidenceAccumulator);
        assert!(CellFunction::EvidenceAccumulator < CellFunction::PolicyEvaluator);
        assert!(CellFunction::PolicyEvaluator < CellFunction::ProofValidator);
        assert!(CellFunction::ProofValidator < CellFunction::ExtensionRuntime);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn enrichment_cell_lifecycle_copy_semantics() {
        let a = CellLifecycle::Active;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_trust_level_copy_semantics() {
        let a = TrustLevel::Hardware;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_platform_kind_copy_semantics() {
        let a = PlatformKind::AmdSevSnp;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_cell_function_copy_semantics() {
        let a = CellFunction::ProofValidator;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_cell_lifecycle_hash_in_btreeset() {
        let mut set = std::collections::BTreeSet::new();
        for v in [
            CellLifecycle::Provisioning,
            CellLifecycle::Measured,
            CellLifecycle::Attested,
            CellLifecycle::Active,
            CellLifecycle::Suspended,
            CellLifecycle::Decommissioned,
        ] {
            set.insert(v);
        }
        set.insert(CellLifecycle::Active); // duplicate
        assert_eq!(set.len(), 6);
    }

    #[test]
    fn enrichment_cell_function_hash_in_btreeset() {
        let mut set = std::collections::BTreeSet::new();
        for v in [
            CellFunction::DecisionReceiptSigner,
            CellFunction::EvidenceAccumulator,
            CellFunction::PolicyEvaluator,
            CellFunction::ProofValidator,
            CellFunction::ExtensionRuntime,
        ] {
            set.insert(v);
        }
        set.insert(CellFunction::PolicyEvaluator); // duplicate
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn enrichment_lifecycle_receipt_clone_eq() {
        let r = LifecycleReceipt {
            from_state: CellLifecycle::Provisioning,
            to_state: CellLifecycle::Measured,
            timestamp_ns: 1_000,
            epoch: SecurityEpoch::GENESIS,
            reason: "initial measure".to_string(),
            signature_bytes: vec![1, 2, 3],
        };
        let c = r.clone();
        assert_eq!(r, c);
    }

    #[test]
    fn enrichment_cell_event_clone_eq() {
        let e = CellEvent {
            seq: 1,
            timestamp_ns: 5_000,
            epoch: SecurityEpoch::from_raw(2),
            cell_id: "cell-1".to_string(),
            event_type: CellEventType::Activated,
        };
        let c = e.clone();
        assert_eq!(e, c);
    }

    #[test]
    fn enrichment_json_field_presence_measurement_digest() {
        let root = SoftwareTrustRoot::new("k1", 42);
        let m = root.measure(b"code", b"cfg", b"pol", b"evi", "v1.0");
        let j = serde_json::to_string(&m).unwrap();
        assert!(j.contains("\"code_hash\""));
        assert!(j.contains("\"config_hash\""));
        assert!(j.contains("\"policy_hash\""));
        assert!(j.contains("\"evidence_schema_hash\""));
        assert!(j.contains("\"runtime_version\""));
        assert!(j.contains("\"platform\""));
    }

    #[test]
    fn enrichment_json_field_presence_cell_event() {
        let e = CellEvent {
            seq: 0,
            timestamp_ns: 100,
            epoch: SecurityEpoch::GENESIS,
            cell_id: "c-json".to_string(),
            event_type: CellEventType::Created,
        };
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains("\"seq\""));
        assert!(j.contains("\"timestamp_ns\""));
        assert!(j.contains("\"epoch\""));
        assert!(j.contains("\"cell_id\""));
        assert!(j.contains("\"event_type\""));
    }

    #[test]
    fn enrichment_cell_error_serde_all_variants() {
        let variants = vec![
            CellError::IdDerivation("bad".to_string()),
            CellError::NotFound {
                cell_id: "c1".to_string(),
            },
            CellError::Duplicate {
                cell_id: "c2".to_string(),
            },
            CellError::InvalidTransition {
                from: CellLifecycle::Provisioning,
                to: CellLifecycle::Active,
            },
            CellError::NotOperational {
                lifecycle: CellLifecycle::Suspended,
            },
            CellError::AttestationFailed {
                reason: "expired".to_string(),
            },
            CellError::NotMeasured,
            CellError::TrustRootRevoked {
                key_id: "k-rev".to_string(),
            },
            CellError::EmptyLabel,
            CellError::EmptyZone,
            CellError::EmptyAuthority,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: CellError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn enrichment_cell_error_source_is_none() {
        use std::error::Error as _;
        let err = CellError::NotMeasured;
        assert!(err.source().is_none());
    }

    #[test]
    fn enrichment_measurement_composite_hash_deterministic() {
        let root = SoftwareTrustRoot::new("det", 99);
        let m1 = root.measure(b"code-x", b"cfg-x", b"pol-x", b"evi-x", "v2.0");
        let m2 = root.measure(b"code-x", b"cfg-x", b"pol-x", b"evi-x", "v2.0");
        assert_eq!(m1.composite_hash(), m2.composite_hash());
    }

    #[test]
    fn enrichment_registry_clone_preserves_state() {
        let mut reg = CellRegistry::new();
        let mut auth = BTreeSet::new();
        auth.insert("exec".to_string());
        reg.create_cell(
            CreateCellInput {
                label: "cell-clone".to_string(),
                function: CellFunction::PolicyEvaluator,
                zone: "zone-clone".to_string(),
                epoch: SecurityEpoch::GENESIS,
                trust_level: TrustLevel::SoftwareOnly,
                authority_envelope: auth,
            },
            1000,
        )
        .unwrap();
        let cloned = reg.clone();
        assert_eq!(reg.cell_count(), cloned.cell_count());
        assert_eq!(reg.events().len(), cloned.events().len());
    }
}
