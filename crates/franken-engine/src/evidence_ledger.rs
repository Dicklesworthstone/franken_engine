//! Mandatory evidence-ledger schema for controller and security decisions.
//!
//! Every high-impact decision (allow, challenge, sandbox, suspend, terminate,
//! quarantine, policy update, revocation, epoch transition) produces a
//! structured [`EvidenceEntry`] containing the candidates considered,
//! constraints applied, chosen action, and witnesses.
//!
//! Plan references: Section 10.11 item 11, 9G.5 (policy controller with
//! expected-loss actions), Top-10 #2 (guardplane), #3 (deterministic
//! evidence graph and replay).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hash_tiers::ContentHash;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::hindsight_boundary_capture::{
    BoundaryCaptureRecord, BoundaryCaptureSession, BoundaryContext,
};
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    PreparedSigningKey, PreparedVerificationKey, SIGNATURE_SENTINEL, Signature, SigningKey,
    VerificationKey,
};

pub use crate::control_plane::SchemaVersion;

pub trait SchemaVersionExt {
    fn is_compatible_with(&self, reader_version: &SchemaVersion) -> bool;
    fn major_val(&self) -> u32;
    fn minor_val(&self) -> u32;
}

// Extension trait for SchemaVersion compatibility checking.
// Assumes SchemaVersion has public major and minor fields.
impl SchemaVersionExt for SchemaVersion {
    fn is_compatible_with(&self, reader_version: &SchemaVersion) -> bool {
        // Major versions must match; minor versions can be backward compatible.
        self.major == reader_version.major && self.minor <= reader_version.minor
    }
    fn major_val(&self) -> u32 {
        self.major
    }
    fn minor_val(&self) -> u32 {
        self.minor
    }
}

pub fn current_schema_version() -> SchemaVersion {
    SchemaVersion::new(2, 0, 0)
}

const DETACHED_EVIDENCE_SIGNATURE_DOMAIN: &str = "franken-engine.detached-evidence-signature.v1";

const TEST_EVIDENCE_PRODUCER_ID: &str = "franken-engine.evidence-ledger.builder";
const TEST_EVIDENCE_FIXTURE_ID: &str = "default-evidence-entry-fixture-v2";

// ---------------------------------------------------------------------------
// DecisionType — categorizes the decision
// ---------------------------------------------------------------------------

/// Category of the decision that produced this evidence entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DecisionType {
    /// Security action (sandbox, suspend, terminate, quarantine).
    SecurityAction,
    /// Policy update or rotation.
    PolicyUpdate,
    /// Security epoch transition.
    EpochTransition,
    /// Revocation of a credential, key, or capability.
    Revocation,
    /// Extension lifecycle decision (load, start, stop).
    ExtensionLifecycle,
    /// Capability grant or denial.
    CapabilityDecision,
    /// Evidence-contract evaluation.
    ContractEvaluation,
    /// Remote operation authorization.
    RemoteAuthorization,
}

impl fmt::Display for DecisionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::SecurityAction => "security_action",
            Self::PolicyUpdate => "policy_update",
            Self::EpochTransition => "epoch_transition",
            Self::Revocation => "revocation",
            Self::ExtensionLifecycle => "extension_lifecycle",
            Self::CapabilityDecision => "capability_decision",
            Self::ContractEvaluation => "contract_evaluation",
            Self::RemoteAuthorization => "remote_authorization",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// CandidateAction — an action considered during decision-making
// ---------------------------------------------------------------------------

/// A candidate action considered during decision-making, with its
/// expected-loss score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateAction {
    /// Human-readable action name.
    pub action_name: String,
    /// Expected loss score (lower is better).
    /// Stored as fixed-point (millionths) for deterministic serialization.
    pub expected_loss_millionths: i64,
    /// Whether this candidate was filtered out by a constraint.
    pub filtered: bool,
    /// Reason for filtering (if filtered).
    pub filter_reason: Option<String>,
}

impl CandidateAction {
    /// Create an unfiltered candidate.
    pub fn new(action_name: impl Into<String>, expected_loss_millionths: i64) -> Self {
        Self {
            action_name: action_name.into(),
            expected_loss_millionths,
            filtered: false,
            filter_reason: None,
        }
    }

    /// Create a filtered-out candidate.
    pub fn filtered(
        action_name: impl Into<String>,
        expected_loss_millionths: i64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            action_name: action_name.into(),
            expected_loss_millionths,
            filtered: true,
            filter_reason: Some(reason.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Constraint — an active guardrail or policy constraint
// ---------------------------------------------------------------------------

/// An active constraint or guardrail that influenced the decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    /// Constraint identifier (e.g., policy rule name).
    pub constraint_id: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this constraint actively blocked or filtered a candidate.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Witness — an evidence atom informing the decision
// ---------------------------------------------------------------------------

/// An evidence atom (observation, sensor reading, posterior value) that
/// informed the decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Witness {
    /// Unique witness identifier.
    pub witness_id: String,
    /// Type of witness data.
    pub witness_type: String,
    /// Value as a deterministic string representation.
    pub value: String,
}

// ---------------------------------------------------------------------------
// EvidenceSignatureEnvelope — producer authentication
// ---------------------------------------------------------------------------

const EVIDENCE_KEY_ID_DOMAIN: &[u8] = b"franken-engine.evidence-signing-key.v1";
const LAB_EVIDENCE_KEY_DOMAIN: &[u8] = b"franken-engine.lab-evidence-key.v1";

fn evidence_key_id(verification_key: &VerificationKey) -> String {
    let mut preimage =
        Vec::with_capacity(EVIDENCE_KEY_ID_DOMAIN.len() + verification_key.as_bytes().len());
    preimage.extend_from_slice(EVIDENCE_KEY_ID_DOMAIN);
    preimage.extend_from_slice(verification_key.as_bytes());
    format!("ed25519:{}", ContentHash::compute(&preimage).to_hex())
}

/// Public, signature-bound lifecycle coordinates for an evidence signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAuthorityClass {
    /// Runtime-owned authority supplied by a product composition root.
    Runtime,
    /// Source-reproducible authority for explicitly marked test/lab artifacts.
    LabFixture,
}

/// Public, signature-bound lifecycle coordinates for an evidence signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceKeyProvenance {
    /// Whether the key represents runtime authority or a reproducible lab
    /// fixture. This value is covered by every evidence signature.
    pub authority_class: EvidenceAuthorityClass,
    /// Domain-separated identity derived from the verification key.
    pub key_id: String,
    /// First security epoch in which this key may sign evidence.
    pub activation_epoch: SecurityEpoch,
    /// Monotonic position in this producer's key-rotation lineage.
    pub rotation_sequence: u64,
    /// Immediate predecessor key for every rotation after sequence one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_key_id: Option<String>,
}

impl EvidenceKeyProvenance {
    fn validate(&self, verification_key: &VerificationKey) -> Result<(), LedgerError> {
        let expected_key_id = evidence_key_id(verification_key);
        if self.key_id != expected_key_id {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "evidence key id mismatch: expected {expected_key_id}, actual {}",
                    self.key_id
                ),
            });
        }
        if self.rotation_sequence == 0 {
            return Err(LedgerError::SchemaValidationFailed {
                reason: "evidence key rotation sequence must be non-zero".to_string(),
            });
        }
        match (self.rotation_sequence, self.previous_key_id.as_deref()) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(LedgerError::SchemaValidationFailed {
                    reason: "initial evidence key must not name a predecessor".to_string(),
                });
            }
            (_, Some(previous)) if !previous.trim().is_empty() && previous != self.key_id => {}
            (_, Some(_)) => {
                return Err(LedgerError::SchemaValidationFailed {
                    reason: "rotated evidence key predecessor must be non-empty and distinct"
                        .to_string(),
                });
            }
            (_, None) => {
                return Err(LedgerError::SchemaValidationFailed {
                    reason: "rotated evidence key must name its immediate predecessor".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Private signing identity plus its public rotation provenance.
///
/// Debug output remains safe because [`SigningKey`] redacts its bytes.
#[derive(Debug, Clone)]
struct EvidenceSigningIdentity {
    producer_id: String,
    key_provenance: EvidenceKeyProvenance,
    signing_key: SigningKey,
    prepared_signing_key: Arc<PreparedSigningKey>,
}

impl PartialEq for EvidenceSigningIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.verification_identity() == other.verification_identity()
    }
}

impl Eq for EvidenceSigningIdentity {}

impl EvidenceSigningIdentity {
    fn from_signing_key(
        producer_id: impl Into<String>,
        signing_key: SigningKey,
        activation_epoch: SecurityEpoch,
        rotation_sequence: u64,
        previous_key_id: Option<String>,
    ) -> Result<Self, LedgerError> {
        Self::from_signing_key_with_authority_class(
            producer_id,
            signing_key,
            activation_epoch,
            rotation_sequence,
            previous_key_id,
            EvidenceAuthorityClass::Runtime,
        )
    }

    fn from_signing_key_with_authority_class(
        producer_id: impl Into<String>,
        signing_key: SigningKey,
        activation_epoch: SecurityEpoch,
        rotation_sequence: u64,
        previous_key_id: Option<String>,
        authority_class: EvidenceAuthorityClass,
    ) -> Result<Self, LedgerError> {
        let producer_id = producer_id.into();
        let verification_key = signing_key.verification_key();
        let prepared_signing_key = PreparedSigningKey::prepare(&signing_key).map_err(|error| {
            LedgerError::SchemaValidationFailed {
                reason: format!(
                    "evidence signing key preparation failed for {producer_id}: {error}"
                ),
            }
        })?;
        let identity = Self {
            producer_id,
            key_provenance: EvidenceKeyProvenance {
                authority_class,
                key_id: evidence_key_id(&verification_key),
                activation_epoch,
                rotation_sequence,
                previous_key_id,
            },
            signing_key,
            prepared_signing_key: Arc::new(prepared_signing_key),
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Construct a deterministic, source-reproducible identity for a named
    /// test or lab fixture.
    ///
    /// The resulting public provenance is permanently marked
    /// [`EvidenceAuthorityClass::LabFixture`]. Runtime ledgers and production
    /// composition roots reject that authority class.
    fn deterministic_lab_fixture(
        producer_id: impl Into<String>,
        fixture_id: &str,
        activation_epoch: SecurityEpoch,
    ) -> Result<Self, LedgerError> {
        let producer_id = producer_id.into();
        if fixture_id.trim().is_empty() {
            return Err(LedgerError::SchemaValidationFailed {
                reason: "lab evidence fixture id must not be empty".to_string(),
            });
        }
        let mut seed_preimage = Vec::with_capacity(
            LAB_EVIDENCE_KEY_DOMAIN.len() + producer_id.len() + fixture_id.len() + 16,
        );
        seed_preimage.extend_from_slice(LAB_EVIDENCE_KEY_DOMAIN);
        seed_preimage.extend_from_slice(&(producer_id.len() as u64).to_be_bytes());
        seed_preimage.extend_from_slice(producer_id.as_bytes());
        seed_preimage.extend_from_slice(&(fixture_id.len() as u64).to_be_bytes());
        seed_preimage.extend_from_slice(fixture_id.as_bytes());
        let signing_key = SigningKey::from_bytes(*ContentHash::compute(&seed_preimage).as_bytes())
            .map_err(|error| LedgerError::SchemaValidationFailed {
                reason: format!("derived lab evidence signing key is invalid: {error}"),
            })?;
        Self::from_signing_key_with_authority_class(
            producer_id,
            signing_key,
            activation_epoch,
            1,
            None,
            EvidenceAuthorityClass::LabFixture,
        )
    }

    /// Generate a fresh, non-exported identity from the operating-system CSPRNG.
    fn generate_runtime_owned(
        producer_id: impl Into<String>,
        activation_epoch: SecurityEpoch,
        rotation_sequence: u64,
        previous_key_id: Option<String>,
    ) -> Result<Self, LedgerError> {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|error| LedgerError::SchemaValidationFailed {
                reason: format!(
                    "operating-system CSPRNG unavailable for evidence signing: {error}"
                ),
            })?;
        let signing_key =
            SigningKey::from_bytes(bytes).map_err(|error| LedgerError::SchemaValidationFailed {
                reason: format!("CSPRNG generated an invalid evidence signing key: {error}"),
            })?;
        Self::from_signing_key(
            producer_id,
            signing_key,
            activation_epoch,
            rotation_sequence,
            previous_key_id,
        )
    }

    fn validate(&self) -> Result<(), LedgerError> {
        if self.producer_id.trim().is_empty() {
            return Err(LedgerError::SchemaValidationFailed {
                reason: "evidence producer id must not be empty".to_string(),
            });
        }
        self.key_provenance
            .validate(&self.signing_key.verification_key())
    }

    fn validate_for_entry_epoch(&self, entry_epoch: SecurityEpoch) -> Result<(), LedgerError> {
        self.validate()?;
        if self.key_provenance.activation_epoch.as_u64() > entry_epoch.as_u64() {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "evidence key {} activates at epoch {}, after entry epoch {}",
                    self.key_provenance.key_id,
                    self.key_provenance.activation_epoch.as_u64(),
                    entry_epoch.as_u64()
                ),
            });
        }
        Ok(())
    }

    fn validate_runtime_authority(&self) -> Result<(), LedgerError> {
        self.validate()?;
        if self.key_provenance.authority_class != EvidenceAuthorityClass::Runtime {
            return Err(LedgerError::SchemaValidationFailed {
                reason: "lab evidence identity cannot authorize a production runtime".to_string(),
            });
        }
        Ok(())
    }

    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }

    pub fn key_provenance(&self) -> &EvidenceKeyProvenance {
        &self.key_provenance
    }

    pub fn verification_key(&self) -> VerificationKey {
        self.prepared_signing_key.verification_key()
    }

    /// Public identity that verifiers must obtain from a trusted runtime
    /// registry or recorded run input, never from the claimant's envelope.
    pub fn verification_identity(&self) -> EvidenceVerificationIdentity {
        EvidenceVerificationIdentity {
            producer_id: self.producer_id.clone(),
            key_provenance: self.key_provenance.clone(),
            verification_key: self.verification_key(),
        }
    }

    fn sign_preimage(&self, preimage: &[u8]) -> Signature {
        self.prepared_signing_key.sign(preimage)
    }

    /// Sign a payload outside the ledger while binding this producer's public
    /// identity, key lineage, and security epoch into the detached signature.
    pub fn sign_detached(
        &self,
        payload: &[u8],
        signed_epoch: SecurityEpoch,
    ) -> Result<EvidenceSignatureEnvelope, LedgerError> {
        self.validate_for_entry_epoch(signed_epoch)?;
        let mut envelope = EvidenceSignatureEnvelope {
            producer_id: self.producer_id.clone(),
            key_provenance: self.key_provenance.clone(),
            signed_epoch,
            verification_key: self.verification_key(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        let preimage = envelope.detached_signature_preimage(payload)?;
        envelope.signature = self.sign_preimage(&preimage);
        Ok(envelope)
    }
}

/// Runtime signing capability supplied by a product composition root.
///
/// The private key never appears in serialized artifacts. Runtime APIs accept
/// this type rather than a generic signer so a lab fixture cannot be passed
/// accidentally or enabled through Cargo feature unification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvidenceAuthority(EvidenceSigningIdentity);

impl RuntimeEvidenceAuthority {
    /// Construct a runtime authority from key material owned by the caller's
    /// key backend.
    pub fn from_signing_key(
        producer_id: impl Into<String>,
        signing_key: SigningKey,
        activation_epoch: SecurityEpoch,
        rotation_sequence: u64,
        previous_key_id: Option<String>,
    ) -> Result<Self, LedgerError> {
        let identity = EvidenceSigningIdentity::from_signing_key(
            producer_id,
            signing_key,
            activation_epoch,
            rotation_sequence,
            previous_key_id,
        )?;
        identity.validate_runtime_authority()?;
        Ok(Self(identity))
    }

    /// Generate a fresh runtime authority from the operating-system CSPRNG.
    pub fn generate_runtime_owned(
        producer_id: impl Into<String>,
        activation_epoch: SecurityEpoch,
        rotation_sequence: u64,
        previous_key_id: Option<String>,
    ) -> Result<Self, LedgerError> {
        let identity = EvidenceSigningIdentity::generate_runtime_owned(
            producer_id,
            activation_epoch,
            rotation_sequence,
            previous_key_id,
        )?;
        identity.validate_runtime_authority()?;
        Ok(Self(identity))
    }

    pub fn producer_id(&self) -> &str {
        self.0.producer_id()
    }

    pub fn key_provenance(&self) -> &EvidenceKeyProvenance {
        self.0.key_provenance()
    }

    pub fn verification_key(&self) -> VerificationKey {
        self.0.verification_key()
    }

    pub fn verification_identity(&self) -> EvidenceVerificationIdentity {
        self.0.verification_identity()
    }

    pub fn sign_detached(
        &self,
        payload: &[u8],
        signed_epoch: SecurityEpoch,
    ) -> Result<EvidenceSignatureEnvelope, LedgerError> {
        self.0.sign_detached(payload, signed_epoch)
    }

    fn signing_identity(&self) -> &EvidenceSigningIdentity {
        &self.0
    }
}

/// Deterministic signing capability for explicitly labelled lab artifacts.
///
/// Lab signatures are useful for reproducible fixtures and benchmarks, but
/// their signed provenance is permanently marked `lab_fixture`; runtime
/// ledgers reject them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabEvidenceAuthority(EvidenceSigningIdentity);

impl LabEvidenceAuthority {
    /// Derive a deterministic lab authority from a domain-separated fixture
    /// identifier. This is intentionally available without a Cargo feature:
    /// callers must opt in through an explicitly lab-named API.
    pub fn deterministic_fixture(
        producer_id: impl Into<String>,
        fixture_id: &str,
        activation_epoch: SecurityEpoch,
    ) -> Result<Self, LedgerError> {
        Ok(Self(EvidenceSigningIdentity::deterministic_lab_fixture(
            producer_id,
            fixture_id,
            activation_epoch,
        )?))
    }

    pub fn producer_id(&self) -> &str {
        self.0.producer_id()
    }

    pub fn key_provenance(&self) -> &EvidenceKeyProvenance {
        self.0.key_provenance()
    }

    pub fn verification_key(&self) -> VerificationKey {
        self.0.verification_key()
    }

    pub fn verification_identity(&self) -> EvidenceVerificationIdentity {
        self.0.verification_identity()
    }

    pub fn sign_detached(
        &self,
        payload: &[u8],
        signed_epoch: SecurityEpoch,
    ) -> Result<EvidenceSignatureEnvelope, LedgerError> {
        self.0.sign_detached(payload, signed_epoch)
    }

    fn signing_identity(&self) -> &EvidenceSigningIdentity {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EvidenceSigningAuthority {
    Runtime(RuntimeEvidenceAuthority),
    Lab(LabEvidenceAuthority),
}

impl EvidenceSigningAuthority {
    fn signing_identity(&self) -> &EvidenceSigningIdentity {
        match self {
            Self::Runtime(authority) => authority.signing_identity(),
            Self::Lab(authority) => authority.signing_identity(),
        }
    }

    pub(crate) fn verification_identity(&self) -> EvidenceVerificationIdentity {
        self.signing_identity().verification_identity()
    }

    pub(crate) fn producer_id(&self) -> &str {
        self.signing_identity().producer_id()
    }

    pub(crate) fn sign_detached(
        &self,
        payload: &[u8],
        signed_epoch: SecurityEpoch,
    ) -> Result<EvidenceSignatureEnvelope, LedgerError> {
        self.signing_identity().sign_detached(payload, signed_epoch)
    }

    pub(crate) fn is_lab(&self) -> bool {
        matches!(self, Self::Lab(_))
    }
}

/// Trusted public coordinates for one runtime evidence-signing identity.
///
/// A verifier must obtain this value from a trusted registry or an
/// authenticated recorded run input. Constructing it from the untrusted
/// [`EvidenceSignatureEnvelope`] being checked would provide integrity only,
/// not runtime-origin authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceVerificationIdentity {
    pub producer_id: String,
    pub key_provenance: EvidenceKeyProvenance,
    pub verification_key: VerificationKey,
}

impl EvidenceVerificationIdentity {
    fn validate(&self) -> Result<(), LedgerError> {
        if self.producer_id.trim().is_empty() {
            return Err(LedgerError::SchemaValidationFailed {
                reason: "trusted evidence producer id must not be empty".to_string(),
            });
        }
        self.key_provenance.validate(&self.verification_key)
    }

    fn validate_runtime_authority(&self) -> Result<(), LedgerError> {
        self.validate()?;
        if self.key_provenance.authority_class != EvidenceAuthorityClass::Runtime {
            return Err(LedgerError::SchemaValidationFailed {
                reason: "lab evidence identity cannot authorize a production runtime".to_string(),
            });
        }
        Ok(())
    }

    fn validate_lab_authority(&self) -> Result<(), LedgerError> {
        self.validate()?;
        if self.key_provenance.authority_class != EvidenceAuthorityClass::LabFixture {
            return Err(LedgerError::SchemaValidationFailed {
                reason: "lab evidence surface requires a lab-fixture identity".to_string(),
            });
        }
        Ok(())
    }
}

/// Signature proving which registered producer emitted an evidence entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSignatureEnvelope {
    /// Registered producer identity.
    pub producer_id: String,
    /// Exact verification-key lineage registered for the producer.
    pub key_provenance: EvidenceKeyProvenance,
    /// Entry epoch explicitly bound into the signature envelope.
    pub signed_epoch: SecurityEpoch,
    /// Public verification key for the producer.
    pub verification_key: VerificationKey,
    /// Signature over the unsigned canonical entry.
    pub signature: Signature,
}

impl EvidenceSignatureEnvelope {
    fn unsigned_for(
        identity: &EvidenceSigningIdentity,
        signed_epoch: SecurityEpoch,
    ) -> EvidenceSignatureEnvelope {
        EvidenceSignatureEnvelope {
            producer_id: identity.producer_id.clone(),
            key_provenance: identity.key_provenance.clone(),
            signed_epoch,
            verification_key: identity.verification_key(),
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        }
    }

    fn validate_public_provenance(&self) -> Result<(), LedgerError> {
        if self.producer_id.trim().is_empty() {
            return Err(LedgerError::SchemaValidationFailed {
                reason: "evidence signature producer id must not be empty".to_string(),
            });
        }
        self.key_provenance.validate(&self.verification_key)?;
        if self.key_provenance.activation_epoch.as_u64() > self.signed_epoch.as_u64() {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "evidence key {} activates at epoch {}, after signed epoch {}",
                    self.key_provenance.key_id,
                    self.key_provenance.activation_epoch.as_u64(),
                    self.signed_epoch.as_u64()
                ),
            });
        }
        Ok(())
    }

    fn detached_signature_preimage(&self, payload: &[u8]) -> Result<Vec<u8>, LedgerError> {
        let mut unsigned_envelope = self.clone();
        unsigned_envelope.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        serde_json::to_vec(&(
            DETACHED_EVIDENCE_SIGNATURE_DOMAIN,
            payload,
            unsigned_envelope,
        ))
        .map_err(|error| LedgerError::SchemaValidationFailed {
            reason: format!("detached evidence signature serialization failed: {error}"),
        })
    }

    /// Verify a detached payload against a trusted runtime identity.
    ///
    /// The trusted identity must come from an authenticated registry or
    /// recorded run input. The verification key embedded in this claimant's
    /// envelope is never accepted as its own trust anchor.
    pub fn verify_detached(
        &self,
        payload: &[u8],
        trusted_identity: &EvidenceVerificationIdentity,
    ) -> Result<(), LedgerError> {
        trusted_identity.validate()?;
        self.validate_public_provenance()?;
        let claimed_identity = EvidenceVerificationIdentity {
            producer_id: self.producer_id.clone(),
            key_provenance: self.key_provenance.clone(),
            verification_key: self.verification_key.clone(),
        };
        if &claimed_identity != trusted_identity {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "detached evidence signer is not the trusted runtime identity: claimed {}/{}, \
                     trusted {}/{}",
                    claimed_identity.producer_id,
                    claimed_identity.key_provenance.key_id,
                    trusted_identity.producer_id,
                    trusted_identity.key_provenance.key_id
                ),
            });
        }
        PreparedVerificationKey::prepare(self.verification_key.clone())
            .verify(&self.detached_signature_preimage(payload)?, &self.signature)
            .map_err(|_| LedgerError::SchemaValidationFailed {
                reason: format!(
                    "invalid detached evidence signature from producer: {}",
                    self.producer_id
                ),
            })
    }
}

// ---------------------------------------------------------------------------
// ChosenAction — the selected action
// ---------------------------------------------------------------------------

/// The action selected by the decision process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChosenAction {
    /// Name of the chosen action.
    pub action_name: String,
    /// Expected-loss score of the chosen action (millionths).
    pub expected_loss_millionths: i64,
    /// Rationale for selection.
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// EvidenceEntry — the core ledger entry
// ---------------------------------------------------------------------------

/// A structured evidence entry for a high-impact decision.
///
/// Every mandatory field is present; the schema is versioned for
/// forward compatibility.  Uses `BTreeMap` for deterministic ordering
/// of metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceEntry {
    /// Schema version of this entry.
    pub schema_version: SchemaVersion,
    /// Deterministic, content-addressed entry identifier.
    pub entry_id: String,
    /// Correlation trace identifier.
    pub trace_id: String,
    /// Unique decision instance identifier.
    pub decision_id: String,
    /// Active policy identifier at decision time.
    pub policy_id: String,
    /// Security epoch in which the decision was made.
    pub epoch_id: SecurityEpoch,
    /// Virtual or wall-clock timestamp (nanoseconds since epoch).
    pub timestamp_ns: u64,
    /// Category of decision.
    pub decision_type: DecisionType,
    /// Ordered list of candidate actions considered.
    pub candidates: Vec<CandidateAction>,
    /// Active constraints and guardrails.
    pub constraints: Vec<Constraint>,
    /// The selected action.
    pub chosen_action: ChosenAction,
    /// Evidence atoms informing the decision.
    pub witnesses: Vec<Witness>,
    /// Content hash of this entry for integrity chain linking.
    pub evidence_hash: String,
    /// Producer signature envelope verified by the ledger before storage.
    ///
    /// Authentication is mandatory in schema v2 and private so callers cannot
    /// deserialize/build an unsigned entry or replace its signer after content
    /// identifiers have been computed.
    signed_envelope: EvidenceSignatureEnvelope,
    /// Additional structured metadata (deterministic via BTreeMap).
    pub metadata: BTreeMap<String, String>,
}

impl EvidenceEntry {
    fn unsigned_signature_view(&self) -> Self {
        let mut unsigned = self.clone();
        unsigned.signed_envelope.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        unsigned
    }

    fn unsigned_signature_preimage(&self) -> Result<Vec<u8>, LedgerError> {
        serde_json::to_vec(&self.unsigned_signature_view()).map_err(|e| {
            LedgerError::SchemaValidationFailed {
                reason: format!("evidence entry signature preimage serialization failed: {e}"),
            }
        })
    }

    fn recomputed_content_ids(&self) -> Result<(String, String), LedgerError> {
        let mut unsigned = self.unsigned_signature_view();
        unsigned.entry_id.clear();
        unsigned.evidence_hash.clear();
        let hash_input =
            serde_json::to_string(&unsigned).map_err(|e| LedgerError::SchemaValidationFailed {
                reason: format!("evidence entry serialization failed: {e}"),
            })?;
        let evidence_hash = deterministic_hash(&hash_input);
        let entry_id = format!("ev-{}", evidence_hash.get(..32).unwrap_or(&evidence_hash));
        Ok((entry_id, evidence_hash))
    }

    /// Read the mandatory producer authentication envelope.
    pub fn signed_envelope(&self) -> &EvidenceSignatureEnvelope {
        &self.signed_envelope
    }

    /// Sign this entry while binding public key/epoch/rotation provenance into
    /// both content identifiers and the signature. This is private so a
    /// completed entry cannot have its authority replaced.
    fn sign_with_identity(
        &mut self,
        identity: &EvidenceSigningIdentity,
    ) -> Result<(), LedgerError> {
        identity.validate_for_entry_epoch(self.epoch_id)?;
        self.signed_envelope = EvidenceSignatureEnvelope::unsigned_for(identity, self.epoch_id);

        let (entry_id, evidence_hash) = self.recomputed_content_ids()?;
        self.entry_id = entry_id;
        self.evidence_hash = evidence_hash;
        let preimage = self.unsigned_signature_preimage()?;
        self.signed_envelope.signature = identity.sign_preimage(&preimage);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EvidenceEntryBuilder — ergonomic construction
// ---------------------------------------------------------------------------

/// Builder for constructing [`EvidenceEntry`] instances.
#[derive(Debug)]
pub struct EvidenceEntryBuilder {
    trace_id: String,
    decision_id: String,
    policy_id: String,
    epoch_id: SecurityEpoch,
    timestamp_ns: u64,
    decision_type: DecisionType,
    candidates: Vec<CandidateAction>,
    constraints: Vec<Constraint>,
    chosen_action: Option<ChosenAction>,
    witnesses: Vec<Witness>,
    metadata: BTreeMap<String, String>,
    signing_identity: EvidenceSigningIdentity,
}

impl EvidenceEntryBuilder {
    /// Start building an entry with an explicit runtime authority.
    pub fn new_with_runtime_authority(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        epoch_id: SecurityEpoch,
        decision_type: DecisionType,
        authority: &RuntimeEvidenceAuthority,
    ) -> Self {
        Self::new_with_signing_identity(
            trace_id,
            decision_id,
            policy_id,
            epoch_id,
            decision_type,
            authority.signing_identity(),
        )
    }

    /// Start building an explicitly lab-scoped entry.
    pub fn new_with_lab_authority(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        epoch_id: SecurityEpoch,
        decision_type: DecisionType,
        authority: &LabEvidenceAuthority,
    ) -> Self {
        Self::new_with_signing_identity(
            trace_id,
            decision_id,
            policy_id,
            epoch_id,
            decision_type,
            authority.signing_identity(),
        )
    }

    pub(crate) fn new_with_authority(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        epoch_id: SecurityEpoch,
        decision_type: DecisionType,
        authority: &EvidenceSigningAuthority,
    ) -> Self {
        Self::new_with_signing_identity(
            trace_id,
            decision_id,
            policy_id,
            epoch_id,
            decision_type,
            authority.signing_identity(),
        )
    }

    fn new_with_signing_identity(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        epoch_id: SecurityEpoch,
        decision_type: DecisionType,
        signing_identity: &EvidenceSigningIdentity,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
            epoch_id,
            timestamp_ns: 0,
            decision_type,
            // H6.1 audit: typical evidence entries have 2-3 candidates, 3-8 constraints, 2-3 witnesses
            candidates: Vec::with_capacity(4),
            constraints: Vec::with_capacity(8),
            chosen_action: None,
            witnesses: Vec::with_capacity(4),
            metadata: BTreeMap::new(),
            signing_identity: signing_identity.clone(),
        }
    }

    /// Start building a deterministic, explicitly labelled lab fixture.
    ///
    /// The resulting signature provenance is `lab_fixture` and cannot be
    /// admitted by a runtime ledger. Product code must call
    /// [`Self::new_with_runtime_authority`].
    pub fn new_lab_fixture(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        epoch_id: SecurityEpoch,
        decision_type: DecisionType,
    ) -> Self {
        let authority = LabEvidenceAuthority::deterministic_fixture(
            TEST_EVIDENCE_PRODUCER_ID,
            TEST_EVIDENCE_FIXTURE_ID,
            SecurityEpoch::GENESIS,
        )
        .expect("built-in lab evidence identity must be valid");
        Self::new_with_lab_authority(
            trace_id,
            decision_id,
            policy_id,
            epoch_id,
            decision_type,
            &authority,
        )
    }

    #[cfg(test)]
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        epoch_id: SecurityEpoch,
        decision_type: DecisionType,
    ) -> Self {
        Self::new_lab_fixture(trace_id, decision_id, policy_id, epoch_id, decision_type)
    }

    /// Set the timestamp.
    pub fn timestamp_ns(mut self, ts: u64) -> Self {
        self.timestamp_ns = ts;
        self
    }

    /// Add a candidate action.
    pub fn candidate(mut self, candidate: CandidateAction) -> Self {
        self.candidates.push(candidate);
        self
    }

    /// Add a constraint.
    pub fn constraint(mut self, constraint: Constraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    /// Set the chosen action.
    pub fn chosen(mut self, action: ChosenAction) -> Self {
        self.chosen_action = Some(action);
        self
    }

    /// Add a witness.
    pub fn witness(mut self, witness: Witness) -> Self {
        self.witnesses.push(witness);
        self
    }

    /// Add metadata.
    pub fn meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    #[cfg(test)]
    fn signed_by(mut self, producer_id: impl Into<String>, signing_key: SigningKey) -> Self {
        self.signing_identity = EvidenceSigningIdentity::from_signing_key(
            producer_id,
            signing_key,
            SecurityEpoch::GENESIS,
            1,
            None,
        )
        .expect("test signing identity must be valid");
        self
    }

    #[cfg(test)]
    fn signed_by_identity(mut self, signing_identity: EvidenceSigningIdentity) -> Self {
        self.signing_identity = signing_identity;
        self
    }

    /// Build the entry, computing entry_id and evidence_hash.
    ///
    /// Returns `Err` if `chosen_action` was not set.
    pub fn build(self) -> Result<EvidenceEntry, LedgerError> {
        let signing_identity = self.signing_identity;
        let chosen_action = self.chosen_action.ok_or(LedgerError::MissingChosenAction)?;

        let mut temp_entry = EvidenceEntry {
            schema_version: current_schema_version(),
            entry_id: String::new(),
            trace_id: self.trace_id,
            decision_id: self.decision_id,
            policy_id: self.policy_id,
            epoch_id: self.epoch_id,
            timestamp_ns: self.timestamp_ns,
            decision_type: self.decision_type,
            candidates: {
                let mut c = self.candidates;
                c.sort_by(|a, b| a.action_name.cmp(&b.action_name));
                c
            },
            constraints: {
                let mut c = self.constraints;
                c.sort_by(|a, b| a.constraint_id.cmp(&b.constraint_id));
                c
            },
            chosen_action,
            witnesses: {
                let mut w = self.witnesses;
                w.sort_by(|a, b| a.witness_id.cmp(&b.witness_id));
                w
            },
            evidence_hash: String::new(),
            signed_envelope: EvidenceSignatureEnvelope::unsigned_for(
                &signing_identity,
                self.epoch_id,
            ),
            metadata: self.metadata,
        };
        temp_entry.sign_with_identity(&signing_identity)?;

        Ok(temp_entry)
    }
}

/// Deliberate opt-in for legacy-shaped integration fixtures.
///
/// Importing this lab-named trait is required before
/// `EvidenceEntryBuilder::new(...)` resolves outside this module's unit tests.
/// The resulting entry is permanently marked with lab authority and cannot be
/// admitted by a runtime ledger.
pub trait LabFixtureEvidenceEntryBuilderExt: Sized {
    fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        epoch_id: SecurityEpoch,
        decision_type: DecisionType,
    ) -> Self;
}

impl LabFixtureEvidenceEntryBuilderExt for EvidenceEntryBuilder {
    fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        epoch_id: SecurityEpoch,
        decision_type: DecisionType,
    ) -> Self {
        EvidenceEntryBuilder::new_lab_fixture(
            trace_id,
            decision_id,
            policy_id,
            epoch_id,
            decision_type,
        )
    }
}

/// Deterministic cryptographic hash for content addressing.
///
/// Uses SHA-256 for collision resistance and tamper detection.
fn deterministic_hash(input: &str) -> String {
    ContentHash::compute(input.as_bytes()).to_hex()
}

// ---------------------------------------------------------------------------
// LedgerError
// ---------------------------------------------------------------------------

/// Errors from evidence ledger operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerError {
    /// Builder was missing the chosen action.
    MissingChosenAction,
    /// Entry failed schema validation.
    SchemaValidationFailed { reason: String },
    /// Schema version incompatible with reader.
    IncompatibleSchema {
        entry_version: SchemaVersion,
        reader_version: SchemaVersion,
    },
    /// Duplicate entry ID in the ledger.
    DuplicateEntryId { entry_id: String },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingChosenAction => write!(f, "chosen action is required"),
            Self::SchemaValidationFailed { reason } => {
                write!(f, "schema validation failed: {reason}")
            }
            Self::IncompatibleSchema {
                entry_version,
                reader_version,
            } => write!(
                f,
                "incompatible schema: entry {entry_version}, reader {reader_version}"
            ),
            Self::DuplicateEntryId { entry_id } => {
                write!(f, "duplicate entry id: {entry_id}")
            }
        }
    }
}

impl std::error::Error for LedgerError {}

// ---------------------------------------------------------------------------
// EvidenceEmitter — trait for emitting evidence entries
// ---------------------------------------------------------------------------

/// Trait for components that emit evidence entries.
///
/// All components that produce evidence must use this shared interface,
/// preventing ad-hoc evidence formats.
pub trait EvidenceEmitter: fmt::Debug {
    /// Emit an evidence entry to the ledger.
    fn emit(&mut self, entry: EvidenceEntry) -> Result<(), LedgerError>;

    /// Atomically emit an ordered batch of evidence entries.
    ///
    /// Implementors that do not provide a transactional batch path fail
    /// closed before emitting any entry when the batch contains more than one
    /// item. This preserves source compatibility for single-entry emitters
    /// without pretending that repeated [`Self::emit`] calls are atomic.
    fn emit_batch(&mut self, entries: Vec<EvidenceEntry>) -> Result<(), LedgerError> {
        if entries.len() > 1 {
            return Err(LedgerError::SchemaValidationFailed {
                reason: "atomic evidence batch emission is unsupported by this emitter".to_string(),
            });
        }
        for entry in entries {
            self.emit(entry)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// InMemoryLedger — simple in-memory implementation
// ---------------------------------------------------------------------------

/// In-memory evidence ledger for testing and lab mode.
///
/// Stores entries in insertion order, rejects duplicates by entry_id.
#[derive(Debug)]
struct AuthorizedEvidenceProducer {
    key_provenance: EvidenceKeyProvenance,
    verification_key: PreparedVerificationKey,
}

#[derive(Debug)]
pub struct InMemoryLedger {
    entries: Vec<EvidenceEntry>,
    entry_ids: std::collections::BTreeSet<String>,
    current_epoch: Option<SecurityEpoch>,
    allow_lab_authority: bool,
    // Prepared form: the Ed25519 point is decompressed/validated once at
    // registration instead of on every emit-time signature verification.
    authorized_producers: BTreeMap<(String, String), AuthorizedEvidenceProducer>,
    authorized_policy_ids: BTreeSet<String>,
}

#[cfg(test)]
impl Default for InMemoryLedger {
    fn default() -> Self {
        Self::new_lab()
    }
}

impl InMemoryLedger {
    fn empty_for_epoch(current_epoch: Option<SecurityEpoch>, allow_lab_authority: bool) -> Self {
        Self {
            entries: Vec::new(),
            entry_ids: BTreeSet::new(),
            current_epoch,
            allow_lab_authority,
            authorized_producers: BTreeMap::new(),
            authorized_policy_ids: BTreeSet::new(),
        }
    }

    /// Explicitly lab-scoped ledger trusting the built-in deterministic
    /// fixture identity.
    pub fn new_lab() -> Self {
        let authority = LabEvidenceAuthority::deterministic_fixture(
            TEST_EVIDENCE_PRODUCER_ID,
            TEST_EVIDENCE_FIXTURE_ID,
            SecurityEpoch::GENESIS,
        )
        .expect("built-in lab evidence identity must be valid");
        let mut ledger = Self::empty_for_epoch(None, true);
        ledger
            .authorize_verification_identity(&authority.verification_identity())
            .expect("built-in lab evidence identity must remain valid");
        ledger
    }

    /// Epoch-bound lab ledger trusting the built-in deterministic fixture.
    pub fn for_lab_epoch(epoch: SecurityEpoch) -> Self {
        Self {
            current_epoch: Some(epoch),
            ..Self::new_lab()
        }
    }

    #[cfg(test)]
    pub fn new() -> Self {
        Self::new_lab()
    }

    #[cfg(test)]
    pub fn for_epoch(epoch: SecurityEpoch) -> Self {
        Self::for_lab_epoch(epoch)
    }

    /// Construct a ledger from an externally trusted public identity.
    pub fn for_verification_identity(
        epoch: SecurityEpoch,
        identity: &EvidenceVerificationIdentity,
    ) -> Result<Self, LedgerError> {
        identity.validate_runtime_authority()?;
        if identity.key_provenance.activation_epoch.as_u64() > epoch.as_u64() {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "evidence trust root activates at epoch {}, after ledger epoch {}",
                    identity.key_provenance.activation_epoch.as_u64(),
                    epoch.as_u64()
                ),
            });
        }
        let mut ledger = Self::empty_for_epoch(Some(epoch), false);
        ledger.authorize_verification_identity(identity)?;
        Ok(ledger)
    }

    /// Construct an explicitly lab-scoped ledger.
    ///
    /// Runtime verification code must use [`Self::for_verification_identity`].
    pub fn for_lab_verification_identity(
        epoch: SecurityEpoch,
        identity: &EvidenceVerificationIdentity,
    ) -> Result<Self, LedgerError> {
        identity.validate_lab_authority()?;
        if identity.key_provenance.activation_epoch.as_u64() > epoch.as_u64() {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "lab evidence trust root activates at epoch {}, after ledger epoch {}",
                    identity.key_provenance.activation_epoch.as_u64(),
                    epoch.as_u64()
                ),
            });
        }
        let mut ledger = Self::empty_for_epoch(Some(epoch), true);
        ledger.authorize_verification_identity(identity)?;
        Ok(ledger)
    }

    /// Construct a runtime ledger from a runtime authority's public identity.
    pub fn for_runtime_authority(
        epoch: SecurityEpoch,
        authority: &RuntimeEvidenceAuthority,
    ) -> Result<Self, LedgerError> {
        Self::for_verification_identity(epoch, &authority.verification_identity())
    }

    /// Construct a lab ledger from a lab authority's public identity.
    pub fn for_lab_authority(
        epoch: SecurityEpoch,
        authority: &LabEvidenceAuthority,
    ) -> Result<Self, LedgerError> {
        Self::for_lab_verification_identity(epoch, &authority.verification_identity())
    }

    #[cfg(test)]
    fn for_signing_identity(
        epoch: SecurityEpoch,
        identity: &EvidenceSigningIdentity,
    ) -> Result<Self, LedgerError> {
        match identity.key_provenance.authority_class {
            EvidenceAuthorityClass::Runtime => {
                Self::for_verification_identity(epoch, &identity.verification_identity())
            }
            EvidenceAuthorityClass::LabFixture => {
                Self::for_lab_verification_identity(epoch, &identity.verification_identity())
            }
        }
    }

    #[cfg(test)]
    fn authorize_producer(
        &mut self,
        producer_id: impl Into<String>,
        verification_key: VerificationKey,
    ) {
        let producer_id = producer_id.into();
        let identity = EvidenceVerificationIdentity {
            key_provenance: EvidenceKeyProvenance {
                authority_class: if self.allow_lab_authority {
                    EvidenceAuthorityClass::LabFixture
                } else {
                    EvidenceAuthorityClass::Runtime
                },
                key_id: evidence_key_id(&verification_key),
                activation_epoch: SecurityEpoch::GENESIS,
                rotation_sequence: 1,
                previous_key_id: None,
            },
            producer_id,
            verification_key,
        };
        let _ = self.authorize_verification_identity(&identity);
    }

    #[cfg(test)]
    fn authorize_signing_identity(
        &mut self,
        identity: &EvidenceSigningIdentity,
    ) -> Result<(), LedgerError> {
        self.authorize_verification_identity(&identity.verification_identity())
    }

    pub fn authorize_verification_identity(
        &mut self,
        identity: &EvidenceVerificationIdentity,
    ) -> Result<(), LedgerError> {
        if self.allow_lab_authority {
            identity.validate_lab_authority()?;
        } else {
            identity.validate_runtime_authority()?;
        }
        let verification_key = identity.verification_key.clone();
        let producer_id = identity.producer_id.clone();
        let provenance = &identity.key_provenance;
        let map_key = (producer_id.clone(), provenance.key_id.clone());

        if let Some(existing) = self.authorized_producers.get(&map_key) {
            if existing.verification_key.raw() != &verification_key {
                return Err(LedgerError::SchemaValidationFailed {
                    reason: format!(
                        "evidence key id collision for producer/key: {}/{}",
                        producer_id, provenance.key_id
                    ),
                });
            }
            if &existing.key_provenance == provenance {
                return Ok(());
            }
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "evidence key provenance redefinition for producer/key: {}/{}",
                    producer_id, provenance.key_id
                ),
            });
        }

        let producer_chain: Vec<&EvidenceKeyProvenance> = self
            .authorized_producers
            .iter()
            .filter_map(|((registered_producer, _), registered)| {
                (registered_producer == &producer_id).then_some(&registered.key_provenance)
            })
            .collect();

        if provenance.rotation_sequence == 1 {
            if producer_chain
                .iter()
                .any(|registered| registered.key_id != provenance.key_id)
            {
                return Err(LedgerError::SchemaValidationFailed {
                    reason: format!(
                        "evidence producer {producer_id} already has a distinct rotation root"
                    ),
                });
            }
        } else {
            let previous_key_id = provenance
                .previous_key_id
                .as_ref()
                .expect("validated rotated provenance names a predecessor");
            let previous = self
                .authorized_producers
                .get(&(producer_id.clone(), previous_key_id.clone()))
                .map(|registered| &registered.key_provenance)
                .ok_or_else(|| LedgerError::SchemaValidationFailed {
                    reason: format!(
                        "evidence rotation predecessor is not registered for producer: \
                         {producer_id}/{previous_key_id}"
                    ),
                })?;
            let expected_sequence = previous.rotation_sequence.checked_add(1).ok_or_else(|| {
                LedgerError::SchemaValidationFailed {
                    reason: "evidence rotation sequence overflow".to_string(),
                }
            })?;
            if provenance.rotation_sequence != expected_sequence {
                return Err(LedgerError::SchemaValidationFailed {
                    reason: format!(
                        "evidence rotation sequence must advance exactly once: predecessor {}, \
                         candidate {}",
                        previous.rotation_sequence, provenance.rotation_sequence
                    ),
                });
            }
            if provenance.activation_epoch.as_u64() < previous.activation_epoch.as_u64() {
                return Err(LedgerError::SchemaValidationFailed {
                    reason: format!(
                        "evidence rotation activation epoch regressed: predecessor {}, candidate {}",
                        previous.activation_epoch.as_u64(),
                        provenance.activation_epoch.as_u64()
                    ),
                });
            }
            if let Some(latest_predecessor_epoch) = self
                .entries
                .iter()
                .map(EvidenceEntry::signed_envelope)
                .filter(|envelope| {
                    envelope.producer_id == producer_id
                        && envelope.key_provenance.key_id == *previous_key_id
                })
                .map(|envelope| envelope.signed_epoch)
                .max()
                && provenance.activation_epoch <= latest_predecessor_epoch
            {
                return Err(LedgerError::SchemaValidationFailed {
                    reason: format!(
                        "evidence rotation activation epoch {} must follow latest accepted \
                         predecessor evidence epoch {}",
                        provenance.activation_epoch.as_u64(),
                        latest_predecessor_epoch.as_u64()
                    ),
                });
            }
            if let Some(highest_sequence) = producer_chain
                .iter()
                .map(|registered| registered.rotation_sequence)
                .max()
                && previous.rotation_sequence != highest_sequence
            {
                return Err(LedgerError::SchemaValidationFailed {
                    reason: format!(
                        "evidence rotation must extend the current producer tip: predecessor {}, \
                         current tip {}",
                        previous.rotation_sequence, highest_sequence
                    ),
                });
            }
            if producer_chain.iter().any(|registered| {
                registered.rotation_sequence == provenance.rotation_sequence
                    && registered.key_id != provenance.key_id
            }) {
                return Err(LedgerError::SchemaValidationFailed {
                    reason: format!(
                        "evidence producer {producer_id} already has a key at rotation sequence {}",
                        provenance.rotation_sequence
                    ),
                });
            }
        }

        self.authorized_producers.insert(
            map_key,
            AuthorizedEvidenceProducer {
                key_provenance: provenance.clone(),
                verification_key: PreparedVerificationKey::prepare(verification_key),
            },
        );
        Ok(())
    }

    pub fn authorize_policy(&mut self, policy_id: impl Into<String>) {
        self.authorized_policy_ids.insert(policy_id.into());
    }

    /// Number of entries in the ledger.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// All entries in insertion order.
    pub fn entries(&self) -> &[EvidenceEntry] {
        &self.entries
    }

    /// Find entries by decision type.
    pub fn by_decision_type(&self, dt: DecisionType) -> Vec<&EvidenceEntry> {
        self.entries
            .iter()
            .filter(|e| e.decision_type == dt)
            .collect()
    }

    /// Find entries by epoch.
    pub fn by_epoch(&self, epoch: SecurityEpoch) -> Vec<&EvidenceEntry> {
        self.entries
            .iter()
            .filter(|e| e.epoch_id == epoch)
            .collect()
    }

    fn validate_entry(&self, entry: &EvidenceEntry) -> Result<(), LedgerError> {
        let reader_version = current_schema_version();
        if !entry.schema_version.is_compatible_with(&reader_version) {
            return Err(LedgerError::IncompatibleSchema {
                entry_version: entry.schema_version,
                reader_version,
            });
        }
        let (expected_entry_id, expected_hash) = entry.recomputed_content_ids()?;
        if entry.evidence_hash != expected_hash {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!("evidence hash mismatch for entry {}", entry.entry_id),
            });
        }
        if entry.entry_id != expected_entry_id {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "entry id mismatch: expected {expected_entry_id}, actual {}",
                    entry.entry_id
                ),
            });
        }

        if let Some(expected_epoch) = self.current_epoch
            && entry.epoch_id != expected_epoch
        {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "evidence epoch mismatch: expected {}, actual {}",
                    expected_epoch.as_u64(),
                    entry.epoch_id.as_u64()
                ),
            });
        }

        if !self.authorized_policy_ids.is_empty()
            && !self.authorized_policy_ids.contains(&entry.policy_id)
        {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!("unauthorized policy id: {}", entry.policy_id),
            });
        }

        let envelope = entry.signed_envelope();
        envelope.validate_public_provenance()?;
        if envelope.signed_epoch != entry.epoch_id {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "evidence signature epoch mismatch: envelope {}, entry {}",
                    envelope.signed_epoch.as_u64(),
                    entry.epoch_id.as_u64()
                ),
            });
        }
        let registered = self
            .authorized_producers
            .get(&(
                envelope.producer_id.clone(),
                envelope.key_provenance.key_id.clone(),
            ))
            .ok_or_else(|| LedgerError::SchemaValidationFailed {
                reason: format!(
                    "unauthorized evidence producer/key: {}/{}",
                    envelope.producer_id, envelope.key_provenance.key_id
                ),
            })?;
        if registered.key_provenance != envelope.key_provenance {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "producer key provenance mismatch: {}/{}",
                    envelope.producer_id, envelope.key_provenance.key_id
                ),
            });
        }
        if let Some(successor) =
            self.authorized_producers
                .iter()
                .find_map(|((registered_producer, _), candidate)| {
                    (registered_producer == &envelope.producer_id
                        && candidate.key_provenance.previous_key_id.as_deref()
                            == Some(envelope.key_provenance.key_id.as_str()))
                    .then_some(&candidate.key_provenance)
                })
            && envelope.signed_epoch >= successor.activation_epoch
        {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "evidence key {} retired at successor activation epoch {}",
                    envelope.key_provenance.key_id,
                    successor.activation_epoch.as_u64()
                ),
            });
        }
        if registered.verification_key.raw() != &envelope.verification_key {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "producer verification key mismatch: {}",
                    envelope.producer_id
                ),
            });
        }
        registered
            .verification_key
            .verify(&entry.unsigned_signature_preimage()?, &envelope.signature)
            .map_err(|_| LedgerError::SchemaValidationFailed {
                reason: format!(
                    "invalid evidence signature from producer: {}",
                    envelope.producer_id
                ),
            })?;
        Ok(())
    }
}

impl EvidenceEmitter for InMemoryLedger {
    fn emit(&mut self, entry: EvidenceEntry) -> Result<(), LedgerError> {
        self.emit_batch(vec![entry])
    }

    fn emit_batch(&mut self, entries: Vec<EvidenceEntry>) -> Result<(), LedgerError> {
        let mut pending_ids = std::collections::BTreeSet::new();
        for entry in &entries {
            if self.entry_ids.contains(&entry.entry_id)
                || !pending_ids.insert(entry.entry_id.clone())
            {
                return Err(LedgerError::DuplicateEntryId {
                    entry_id: entry.entry_id.clone(),
                });
            }
            self.validate_entry(entry)?;
        }

        self.entry_ids.extend(pending_ids);
        self.entries.extend(entries);
        Ok(())
    }
}

/// Deliberate opt-in for lab ledgers in integration fixtures.
///
/// Runtime code should construct a ledger from an externally trusted
/// [`EvidenceVerificationIdentity`] or [`RuntimeEvidenceAuthority`].
pub trait LabFixtureInMemoryLedgerExt: Sized {
    fn new() -> Self;
    fn for_epoch(epoch: SecurityEpoch) -> InMemoryLedger;
}

impl LabFixtureInMemoryLedgerExt for InMemoryLedger {
    fn new() -> Self {
        InMemoryLedger::new_lab()
    }

    fn for_epoch(epoch: SecurityEpoch) -> InMemoryLedger {
        InMemoryLedger::for_lab_epoch(epoch)
    }
}

pub const EVIDENCE_LEDGER_STITCHING_BEAD_ID: &str = "bd-1lsy.9.11.2";
pub const EVIDENCE_LEDGER_STITCHING_COMPONENT: &str = "evidence_ledger_stitching";
pub const EVIDENCE_LEDGER_GRAPH_SCHEMA_VERSION: &str =
    "franken-engine.rgc-evidence-ledger-graph.v1";
pub const DECISION_SEMANTICS_LOG_SCHEMA_VERSION: &str =
    "franken-engine.rgc-decision-semantics-log.v1";
pub const ARTIFACT_LINEAGE_INDEX_SCHEMA_VERSION: &str =
    "franken-engine.rgc-artifact-lineage-index.v1";
pub const EVIDENCE_QUERY_SURFACE_SCHEMA_VERSION: &str =
    "franken-engine.rgc-evidence-query-surface.v1";
pub const EVIDENCE_LEDGER_STITCHING_BUNDLE_SCHEMA_VERSION: &str =
    "franken-engine.rgc-evidence-ledger-stitching-bundle.v1";
pub const EVIDENCE_LEDGER_STITCHING_TRACE_IDS_SCHEMA_VERSION: &str =
    "franken-engine.rgc-evidence-ledger-stitching-trace-ids.v1";
pub const EVIDENCE_LEDGER_STITCHING_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.rgc-evidence-ledger-stitching-run-manifest.v1";

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DecisionSemanticsAnnotations {
    pub confidence_tier: Option<String>,
    pub fallback_reason: Option<String>,
    pub regret_summary: Option<String>,
    pub scope_limits: Vec<String>,
    pub assumptions: BTreeMap<String, String>,
    pub linked_boundary_correlation_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub artifact_id: String,
    pub artifact_kind: String,
    pub artifact_locator: String,
    pub artifact_hash: String,
    pub supporting_boundary_correlation_keys: Vec<String>,
}

impl ArtifactRecord {
    pub fn new(
        artifact_id: impl Into<String>,
        artifact_kind: impl Into<String>,
        artifact_locator: impl Into<String>,
        artifact_hash: impl Into<String>,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            artifact_kind: artifact_kind.into(),
            artifact_locator: artifact_locator.into(),
            artifact_hash: artifact_hash.into(),
            supporting_boundary_correlation_keys: Vec::new(),
        }
    }

    pub fn supporting_boundary(mut self, correlation_key: impl Into<String>) -> Self {
        self.supporting_boundary_correlation_keys
            .push(correlation_key.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGraphNodeKind {
    BoundaryCapture,
    DecisionEntry,
    Artifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGraphEdgeKind {
    BoundaryInformsDecision,
    DecisionProducesArtifact,
    BoundarySupportsArtifact,
}

impl EvidenceGraphEdgeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::BoundaryInformsDecision => "boundary_informs_decision",
            Self::DecisionProducesArtifact => "decision_produces_artifact",
            Self::BoundarySupportsArtifact => "boundary_supports_artifact",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceGraphNode {
    pub node_id: String,
    pub node_kind: EvidenceGraphNodeKind,
    pub label: String,
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceGraphEdge {
    pub edge_id: String,
    pub edge_kind: EvidenceGraphEdgeKind,
    pub from_node_id: String,
    pub to_node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLedgerGraph {
    pub schema_version: String,
    pub bead_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub nodes: Vec<EvidenceGraphNode>,
    pub edges: Vec<EvidenceGraphEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionSemanticsRecord {
    pub schema_version: String,
    pub bead_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub evidence_entry_id: String,
    pub evidence_hash: String,
    pub decision_type: DecisionType,
    pub chosen_action: String,
    pub expected_loss_millionths: i64,
    pub filtered_candidates: Vec<String>,
    pub active_constraints: Vec<String>,
    pub witness_ids: Vec<String>,
    pub boundary_correlation_keys: Vec<String>,
    pub confidence_tier: Option<String>,
    pub fallback_reason: Option<String>,
    pub regret_summary: Option<String>,
    pub scope_limits: Vec<String>,
    pub assumptions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactLineageRecord {
    pub schema_version: String,
    pub bead_id: String,
    pub artifact_id: String,
    pub artifact_kind: String,
    pub artifact_locator: String,
    pub artifact_hash: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub evidence_entry_id: String,
    pub boundary_correlation_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceQueryRecord {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub evidence_entry_id: String,
    pub chosen_action: String,
    pub boundary_correlation_keys: Vec<String>,
    pub artifact_ids: Vec<String>,
    pub witness_ids: Vec<String>,
    pub confidence_tier: Option<String>,
    pub fallback_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceQuerySurfaceSnapshot {
    pub schema_version: String,
    pub bead_id: String,
    pub decisions: Vec<EvidenceQueryRecord>,
}

impl EvidenceQuerySurfaceSnapshot {
    pub fn by_decision(&self, decision_id: &str) -> Option<&EvidenceQueryRecord> {
        self.decisions
            .iter()
            .find(|record| record.decision_id == decision_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLedgerStitchingBundle {
    pub schema_version: String,
    pub bead_id: String,
    pub evidence_ledger_graph: EvidenceLedgerGraph,
    pub decision_semantics_log: Vec<DecisionSemanticsRecord>,
    pub artifact_lineage_index: Vec<ArtifactLineageRecord>,
    pub evidence_query_surface_snapshot: EvidenceQuerySurfaceSnapshot,
}

impl EvidenceLedgerStitchingBundle {
    pub fn stitch(
        entry: &EvidenceEntry,
        boundary_records: &[BoundaryCaptureRecord],
        artifacts: &[ArtifactRecord],
        annotations: DecisionSemanticsAnnotations,
    ) -> Result<Self, LedgerError> {
        let sorted_boundaries = normalize_boundary_records(entry, boundary_records)?;
        let linked_boundary_correlation_keys = resolve_boundary_links(
            &sorted_boundaries,
            &annotations.linked_boundary_correlation_keys,
            "decision semantics",
        )?;
        let sorted_artifacts = normalize_artifacts(artifacts)?;
        let decision_node_id = build_decision_node_id(entry);

        let mut nodes = Vec::with_capacity(1 + sorted_boundaries.len() + sorted_artifacts.len());
        nodes.push(EvidenceGraphNode {
            node_id: decision_node_id.clone(),
            node_kind: EvidenceGraphNodeKind::DecisionEntry,
            label: entry.chosen_action.action_name.clone(),
            trace_id: entry.trace_id.clone(),
            decision_id: Some(entry.decision_id.clone()),
            policy_id: Some(entry.policy_id.clone()),
            metadata: decision_metadata(entry),
        });

        let mut edges = Vec::new();
        let mut boundary_node_ids = BTreeMap::new();
        for boundary in &sorted_boundaries {
            let node_id = build_boundary_node_id(boundary);
            boundary_node_ids.insert(boundary.correlation_key.clone(), node_id.clone());
            nodes.push(EvidenceGraphNode {
                node_id: node_id.clone(),
                node_kind: EvidenceGraphNodeKind::BoundaryCapture,
                label: boundary.nondeterminism_tag.clone(),
                trace_id: boundary.trace_id.clone(),
                decision_id: Some(boundary.decision_id.clone()),
                policy_id: Some(boundary.policy_id.clone()),
                metadata: boundary_metadata(boundary),
            });
            if linked_boundary_correlation_keys.contains(&boundary.correlation_key) {
                edges.push(build_edge(
                    EvidenceGraphEdgeKind::BoundaryInformsDecision,
                    node_id,
                    decision_node_id.clone(),
                ));
            }
        }

        let mut artifact_lineage_index = Vec::with_capacity(sorted_artifacts.len());
        let mut artifact_ids = Vec::with_capacity(sorted_artifacts.len());
        for artifact in &sorted_artifacts {
            let artifact_links = resolve_boundary_links(
                &sorted_boundaries,
                &artifact.supporting_boundary_correlation_keys,
                artifact.artifact_id.as_str(),
            )?;
            let artifact_node_id = build_artifact_node_id(entry, artifact);
            nodes.push(EvidenceGraphNode {
                node_id: artifact_node_id.clone(),
                node_kind: EvidenceGraphNodeKind::Artifact,
                label: artifact.artifact_kind.clone(),
                trace_id: entry.trace_id.clone(),
                decision_id: Some(entry.decision_id.clone()),
                policy_id: Some(entry.policy_id.clone()),
                metadata: artifact_metadata(artifact),
            });
            edges.push(build_edge(
                EvidenceGraphEdgeKind::DecisionProducesArtifact,
                decision_node_id.clone(),
                artifact_node_id.clone(),
            ));
            for correlation_key in &artifact_links {
                let boundary_node_id = boundary_node_ids.get(correlation_key).ok_or_else(|| {
                    LedgerError::SchemaValidationFailed {
                        reason: format!(
                            "artifact {} references missing boundary correlation key: {}",
                            artifact.artifact_id, correlation_key
                        ),
                    }
                })?;
                edges.push(build_edge(
                    EvidenceGraphEdgeKind::BoundarySupportsArtifact,
                    boundary_node_id.clone(),
                    artifact_node_id.clone(),
                ));
            }
            artifact_ids.push(artifact.artifact_id.clone());
            artifact_lineage_index.push(ArtifactLineageRecord {
                schema_version: ARTIFACT_LINEAGE_INDEX_SCHEMA_VERSION.to_string(),
                bead_id: EVIDENCE_LEDGER_STITCHING_BEAD_ID.to_string(),
                artifact_id: artifact.artifact_id.clone(),
                artifact_kind: artifact.artifact_kind.clone(),
                artifact_locator: artifact.artifact_locator.clone(),
                artifact_hash: artifact.artifact_hash.clone(),
                trace_id: entry.trace_id.clone(),
                decision_id: entry.decision_id.clone(),
                policy_id: entry.policy_id.clone(),
                evidence_entry_id: entry.entry_id.clone(),
                boundary_correlation_keys: artifact_links,
            });
        }

        let decision_semantics = DecisionSemanticsRecord {
            schema_version: DECISION_SEMANTICS_LOG_SCHEMA_VERSION.to_string(),
            bead_id: EVIDENCE_LEDGER_STITCHING_BEAD_ID.to_string(),
            trace_id: entry.trace_id.clone(),
            decision_id: entry.decision_id.clone(),
            policy_id: entry.policy_id.clone(),
            evidence_entry_id: entry.entry_id.clone(),
            evidence_hash: entry.evidence_hash.clone(),
            decision_type: entry.decision_type,
            chosen_action: entry.chosen_action.action_name.clone(),
            expected_loss_millionths: entry.chosen_action.expected_loss_millionths,
            filtered_candidates: entry
                .candidates
                .iter()
                .filter(|candidate| candidate.filtered)
                .map(|candidate| candidate.action_name.clone())
                .collect(),
            active_constraints: entry
                .constraints
                .iter()
                .filter(|constraint| constraint.active)
                .map(|constraint| constraint.constraint_id.clone())
                .collect(),
            witness_ids: entry
                .witnesses
                .iter()
                .map(|witness| witness.witness_id.clone())
                .collect(),
            boundary_correlation_keys: linked_boundary_correlation_keys.clone(),
            confidence_tier: annotations.confidence_tier.clone(),
            fallback_reason: annotations.fallback_reason.clone(),
            regret_summary: annotations.regret_summary.clone(),
            scope_limits: annotations.scope_limits.clone(),
            assumptions: annotations.assumptions.clone(),
        };

        let query_surface = EvidenceQuerySurfaceSnapshot {
            schema_version: EVIDENCE_QUERY_SURFACE_SCHEMA_VERSION.to_string(),
            bead_id: EVIDENCE_LEDGER_STITCHING_BEAD_ID.to_string(),
            decisions: vec![EvidenceQueryRecord {
                trace_id: entry.trace_id.clone(),
                decision_id: entry.decision_id.clone(),
                policy_id: entry.policy_id.clone(),
                evidence_entry_id: entry.entry_id.clone(),
                chosen_action: entry.chosen_action.action_name.clone(),
                boundary_correlation_keys: linked_boundary_correlation_keys,
                artifact_ids,
                witness_ids: entry
                    .witnesses
                    .iter()
                    .map(|witness| witness.witness_id.clone())
                    .collect(),
                confidence_tier: annotations.confidence_tier,
                fallback_reason: annotations.fallback_reason,
            }],
        };

        Ok(Self {
            schema_version: EVIDENCE_LEDGER_STITCHING_BUNDLE_SCHEMA_VERSION.to_string(),
            bead_id: EVIDENCE_LEDGER_STITCHING_BEAD_ID.to_string(),
            evidence_ledger_graph: EvidenceLedgerGraph {
                schema_version: EVIDENCE_LEDGER_GRAPH_SCHEMA_VERSION.to_string(),
                bead_id: EVIDENCE_LEDGER_STITCHING_BEAD_ID.to_string(),
                trace_id: entry.trace_id.clone(),
                decision_id: entry.decision_id.clone(),
                policy_id: entry.policy_id.clone(),
                nodes,
                edges,
            },
            decision_semantics_log: vec![decision_semantics],
            artifact_lineage_index,
            evidence_query_surface_snapshot: query_surface,
        })
    }
}

fn normalize_boundary_records(
    entry: &EvidenceEntry,
    boundary_records: &[BoundaryCaptureRecord],
) -> Result<Vec<BoundaryCaptureRecord>, LedgerError> {
    let mut sorted = boundary_records.to_vec();
    sorted.sort_by(|left, right| {
        left.sequence
            .cmp(&right.sequence)
            .then_with(|| left.correlation_key.cmp(&right.correlation_key))
    });
    for boundary in &sorted {
        if boundary.trace_id != entry.trace_id
            || boundary.decision_id != entry.decision_id
            || boundary.policy_id != entry.policy_id
        {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "boundary {} does not match decision identity ({}/{}/{})",
                    boundary.correlation_key, entry.trace_id, entry.decision_id, entry.policy_id
                ),
            });
        }
    }
    Ok(sorted)
}

fn normalize_artifacts(artifacts: &[ArtifactRecord]) -> Result<Vec<ArtifactRecord>, LedgerError> {
    let mut seen = BTreeSet::new();
    let mut sorted = artifacts.to_vec();
    sorted.sort_by(|left, right| {
        left.artifact_id
            .cmp(&right.artifact_id)
            .then_with(|| left.artifact_kind.cmp(&right.artifact_kind))
            .then_with(|| left.artifact_locator.cmp(&right.artifact_locator))
    });
    for artifact in &sorted {
        if artifact.artifact_id.is_empty() {
            return Err(LedgerError::SchemaValidationFailed {
                reason: "artifact id must not be empty".to_string(),
            });
        }
        if artifact.artifact_kind.is_empty() {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!("artifact {} has empty artifact_kind", artifact.artifact_id),
            });
        }
        if !seen.insert(artifact.artifact_id.clone()) {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!("duplicate artifact id: {}", artifact.artifact_id),
            });
        }
    }
    Ok(sorted)
}

fn resolve_boundary_links(
    boundary_records: &[BoundaryCaptureRecord],
    requested: &[String],
    label: &str,
) -> Result<Vec<String>, LedgerError> {
    if requested.is_empty() {
        return Ok(boundary_records
            .iter()
            .map(|boundary| boundary.correlation_key.clone())
            .collect());
    }

    let available = boundary_records
        .iter()
        .map(|boundary| boundary.correlation_key.as_str())
        .collect::<BTreeSet<_>>();
    let mut resolved = BTreeSet::new();
    for correlation_key in requested {
        if !available.contains(correlation_key.as_str()) {
            return Err(LedgerError::SchemaValidationFailed {
                reason: format!(
                    "{label} references missing boundary correlation key: {correlation_key}"
                ),
            });
        }
        resolved.insert(correlation_key.clone());
    }
    Ok(resolved.into_iter().collect())
}

fn decision_metadata(entry: &EvidenceEntry) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert("decision_type".to_string(), entry.decision_type.to_string());
    metadata.insert(
        "chosen_action".to_string(),
        entry.chosen_action.action_name.clone(),
    );
    metadata.insert("evidence_entry_id".to_string(), entry.entry_id.clone());
    metadata.insert("evidence_hash".to_string(), entry.evidence_hash.clone());
    metadata
}

fn boundary_metadata(boundary: &BoundaryCaptureRecord) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "boundary_class".to_string(),
        boundary.boundary_class.to_string(),
    );
    metadata.insert(
        "correlation_key".to_string(),
        boundary.correlation_key.clone(),
    );
    metadata.insert("component".to_string(), boundary.component.clone());
    metadata.insert("sequence".to_string(), boundary.sequence.to_string());
    metadata
}

fn artifact_metadata(artifact: &ArtifactRecord) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert("artifact_id".to_string(), artifact.artifact_id.clone());
    metadata.insert("artifact_kind".to_string(), artifact.artifact_kind.clone());
    metadata.insert(
        "artifact_locator".to_string(),
        artifact.artifact_locator.clone(),
    );
    metadata.insert("artifact_hash".to_string(), artifact.artifact_hash.clone());
    metadata
}

fn build_decision_node_id(entry: &EvidenceEntry) -> String {
    format!("dnode-{}", deterministic_hash(entry.entry_id.as_str()))
}

fn build_boundary_node_id(boundary: &BoundaryCaptureRecord) -> String {
    format!(
        "bnode-{}",
        deterministic_hash(boundary.correlation_key.as_str())
    )
}

fn build_artifact_node_id(entry: &EvidenceEntry, artifact: &ArtifactRecord) -> String {
    // Length-prefix each field to prevent delimiter collisions when fields
    // contain the ':' separator character.
    let canonical = format!(
        "{}|{}:{}|{}:{}|{}:{}|{}",
        entry.entry_id.len(),
        entry.entry_id,
        artifact.artifact_id.len(),
        artifact.artifact_id,
        artifact.artifact_kind.len(),
        artifact.artifact_kind,
        artifact.artifact_hash.len(),
        artifact.artifact_hash
    );
    format!("anode-{}", deterministic_hash(&canonical))
}

fn build_edge(
    edge_kind: EvidenceGraphEdgeKind,
    from_node_id: String,
    to_node_id: String,
) -> EvidenceGraphEdge {
    let seed = format!("{}:{from_node_id}:{to_node_id}", edge_kind.as_str());
    EvidenceGraphEdge {
        edge_id: format!("edge-{}", deterministic_hash(seed.as_str())),
        edge_kind,
        from_node_id,
        to_node_id,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StitchingTraceIdsArtifact {
    pub schema_version: String,
    pub trace_ids: Vec<String>,
    pub decision_id: String,
    pub policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StitchingStructuredLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub artifact_id: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StitchingArtifactContext {
    pub artifact_dir: PathBuf,
    pub run_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub generated_at_utc: String,
    pub source_commit: String,
    pub toolchain: String,
    pub command_invocation: String,
}

impl StitchingArtifactContext {
    /// Creates a new stitching context with deterministic defaults.
    /// For CLI usage with observational timestamps, use `with_timestamps()` instead.
    pub fn new(artifact_dir: impl Into<PathBuf>) -> Self {
        Self::with_timestamps(
            artifact_dir,
            None, // Use deterministic run_id
            None, // Use deterministic generated_at_utc
        )
    }

    /// Creates a new stitching context with explicit timestamps.
    /// Use this from CLI wrappers when wall-clock stamping is needed for observational purposes.
    /// For deterministic replay/evidence, use `new()` instead.
    pub fn with_timestamps(
        artifact_dir: impl Into<PathBuf>,
        run_id: Option<String>,
        generated_at_utc: Option<String>,
    ) -> Self {
        let artifact_path = artifact_dir.into();

        // Generate deterministic run_id if not provided
        let final_run_id = run_id.unwrap_or_else(|| {
            // Use artifact directory path for deterministic ID generation
            let path_hash = ContentHash::compute(artifact_path.as_os_str().as_encoded_bytes());
            let path_hash_hex = path_hash.to_hex();
            format!(
                "run-{}-deterministic-{}",
                EVIDENCE_LEDGER_STITCHING_COMPONENT,
                &path_hash_hex[..16] // First 16 hex chars (8 bytes) for shorter ID
            )
        });

        // Generate deterministic timestamp if not provided
        let final_generated_at_utc = generated_at_utc.unwrap_or_else(|| {
            // Use deterministic timestamp for SecurityEpoch::GENESIS
            "2024-01-01T00:00:00Z".to_string()
        });

        Self {
            artifact_dir: artifact_path,
            run_id: final_run_id,
            trace_id: "trace.rgc.811b".to_string(),
            decision_id: "decision.rgc.811b".to_string(),
            policy_id: "policy.rgc.811b".to_string(),
            generated_at_utc: final_generated_at_utc,
            source_commit: "unknown".to_string(),
            toolchain: std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "nightly".to_string()),
            command_invocation: "cargo run -p frankenengine-engine --bin franken_evidence_ledger_stitching -- --artifact-dir <path>".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StitchingBundleWriteReport {
    pub artifact_dir: PathBuf,
    pub bundle: EvidenceLedgerStitchingBundle,
    pub trace_ids_path: PathBuf,
    pub written_files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ManifestArtifactReference {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone)]
struct EvaluatedStitchingArtifacts {
    bundle: EvidenceLedgerStitchingBundle,
    trace_ids: StitchingTraceIdsArtifact,
    logs: Vec<StitchingStructuredLogEvent>,
}

#[derive(Debug, Clone)]
struct BundleFileArtifact {
    path: String,
    contents: Vec<u8>,
}

#[derive(Debug)]
struct BundleWriteLock {
    path: PathBuf,
}

impl Drop for BundleWriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
const DOCS_CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc-evidence-ledger-stitching-docs.v1";

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DocsContractFixture {
    schema_version: String,
    bead_id: String,
    required_artifacts: Vec<String>,
    required_query_fields: Vec<String>,
    artifact_kinds: Vec<String>,
    edge_kinds: Vec<String>,
}

pub fn render_stitching_summary(bundle: &EvidenceLedgerStitchingBundle) -> String {
    let Some(query) = bundle.evidence_query_surface_snapshot.decisions.first() else {
        return "# Evidence Ledger Stitching Summary\n\nNo decisions found.".to_string();
    };
    let Some(semantics) = bundle.decision_semantics_log.first() else {
        return "# Evidence Ledger Stitching Summary\n\nNo semantics log entries.".to_string();
    };
    let mut lines = vec![
        "# Evidence Ledger Stitching Summary".to_string(),
        String::new(),
        format!("- bead_id: `{}`", EVIDENCE_LEDGER_STITCHING_BEAD_ID),
        format!("- component: `{}`", EVIDENCE_LEDGER_STITCHING_COMPONENT),
        format!("- trace_id: `{}`", query.trace_id),
        format!("- decision_id: `{}`", query.decision_id),
        format!("- policy_id: `{}`", query.policy_id),
        format!(
            "- graph_nodes: `{}`",
            bundle.evidence_ledger_graph.nodes.len()
        ),
        format!(
            "- graph_edges: `{}`",
            bundle.evidence_ledger_graph.edges.len()
        ),
        format!(
            "- stitched_artifacts: `{}`",
            bundle.artifact_lineage_index.len()
        ),
        format!(
            "- linked_boundaries: `{}`",
            query.boundary_correlation_keys.len()
        ),
        String::new(),
        "## Query Surface".to_string(),
        format!("- chosen_action: `{}`", query.chosen_action),
        format!(
            "- confidence_tier: `{}`",
            semantics
                .confidence_tier
                .as_deref()
                .unwrap_or("unspecified")
        ),
        format!(
            "- fallback_reason: `{}`",
            semantics.fallback_reason.as_deref().unwrap_or("none")
        ),
        String::new(),
        "## Artifact Lineage".to_string(),
    ];

    for artifact in &bundle.artifact_lineage_index {
        lines.push(format!(
            "- `{}` kind=`{}` boundaries={} locator=`{}`",
            artifact.artifact_id,
            artifact.artifact_kind,
            artifact.boundary_correlation_keys.len(),
            artifact.artifact_locator,
        ));
    }

    lines
        .into_iter()
        .chain(std::iter::once(String::new()))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn emit_default_stitching_bundle(
    context: &StitchingArtifactContext,
) -> io::Result<StitchingBundleWriteReport> {
    let evaluated = evaluate_default_stitching_artifacts(context)?;
    write_stitching_bundle(context, &evaluated)
}

#[cfg(test)]
fn build_docs_contract_fixture() -> DocsContractFixture {
    let mut artifact_kinds = default_artifact_records(
        &default_boundary_records(&StitchingArtifactContext {
            artifact_dir: PathBuf::from("."),
            run_id: "docs".to_string(),
            trace_id: "trace-doc".to_string(),
            decision_id: "decision-doc".to_string(),
            policy_id: "policy-doc".to_string(),
            generated_at_utc: "2026-03-07T00:00:00Z".to_string(),
            source_commit: "deadbeef".to_string(),
            toolchain: "nightly".to_string(),
            command_invocation: "docs-fixture".to_string(),
        })
        .expect("docs boundaries"),
    )
    .into_iter()
    .map(|artifact| artifact.artifact_kind)
    .collect::<Vec<_>>();
    artifact_kinds.sort();

    DocsContractFixture {
        schema_version: DOCS_CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: EVIDENCE_LEDGER_STITCHING_BEAD_ID.to_string(),
        required_artifacts: required_artifact_names(),
        required_query_fields: vec![
            "trace_id".to_string(),
            "decision_id".to_string(),
            "policy_id".to_string(),
            "evidence_entry_id".to_string(),
            "chosen_action".to_string(),
            "boundary_correlation_keys".to_string(),
            "artifact_ids".to_string(),
            "witness_ids".to_string(),
            "confidence_tier".to_string(),
            "fallback_reason".to_string(),
        ],
        artifact_kinds,
        edge_kinds: vec![
            EvidenceGraphEdgeKind::BoundaryInformsDecision
                .as_str()
                .to_string(),
            EvidenceGraphEdgeKind::BoundarySupportsArtifact
                .as_str()
                .to_string(),
            EvidenceGraphEdgeKind::DecisionProducesArtifact
                .as_str()
                .to_string(),
        ],
    }
}

fn evaluate_default_stitching_artifacts(
    context: &StitchingArtifactContext,
) -> io::Result<EvaluatedStitchingArtifacts> {
    let entry = default_stitching_entry(context);
    let boundaries = default_boundary_records(context)?;
    let artifacts = default_artifact_records(&boundaries);
    let annotations = default_decision_annotations(&boundaries);
    let bundle =
        EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &artifacts, annotations)
            .map_err(|error| io::Error::other(error.to_string()))?;

    let mut logs = boundaries
        .iter()
        .map(|boundary| StitchingStructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: EVIDENCE_LEDGER_STITCHING_COMPONENT.to_string(),
            event: "boundary_linked".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            artifact_id: None,
            detail: format!(
                "boundary_class={} correlation_key={}",
                boundary.boundary_class, boundary.correlation_key
            ),
        })
        .collect::<Vec<_>>();

    logs.extend(
        bundle
            .artifact_lineage_index
            .iter()
            .map(|artifact| StitchingStructuredLogEvent {
                trace_id: context.trace_id.clone(),
                decision_id: context.decision_id.clone(),
                policy_id: context.policy_id.clone(),
                component: EVIDENCE_LEDGER_STITCHING_COMPONENT.to_string(),
                event: "artifact_lineage_recorded".to_string(),
                outcome: "pass".to_string(),
                error_code: None,
                artifact_id: Some(artifact.artifact_id.clone()),
                detail: format!(
                    "artifact_kind={} linked_boundaries={}",
                    artifact.artifact_kind,
                    artifact.boundary_correlation_keys.len()
                ),
            }),
    );

    logs.push(StitchingStructuredLogEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: EVIDENCE_LEDGER_STITCHING_COMPONENT.to_string(),
        event: "stitching_bundle_built".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        artifact_id: None,
        detail: format!(
            "nodes={} edges={} artifacts={}",
            bundle.evidence_ledger_graph.nodes.len(),
            bundle.evidence_ledger_graph.edges.len(),
            bundle.artifact_lineage_index.len()
        ),
    });

    logs.sort_by(|left, right| {
        left.event
            .cmp(&right.event)
            .then(left.artifact_id.cmp(&right.artifact_id))
            .then(left.detail.cmp(&right.detail))
    });

    Ok(EvaluatedStitchingArtifacts {
        bundle,
        trace_ids: StitchingTraceIdsArtifact {
            schema_version: EVIDENCE_LEDGER_STITCHING_TRACE_IDS_SCHEMA_VERSION.to_string(),
            trace_ids: vec![context.trace_id.clone()],
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
        },
        logs,
    })
}

fn write_stitching_bundle(
    context: &StitchingArtifactContext,
    evaluated: &EvaluatedStitchingArtifacts,
) -> io::Result<StitchingBundleWriteReport> {
    fs::create_dir_all(&context.artifact_dir)?;

    let summary_md = render_stitching_summary(&evaluated.bundle);
    let artifact_dir_display = context.artifact_dir.display().to_string();
    let commands = vec![
        context.command_invocation.clone(),
        format!(
            "jq '.decisions[0]' {}/evidence_query_surface_snapshot.json",
            artifact_dir_display
        ),
        format!(
            "jq '.edges | length' {}/evidence_ledger_graph.json",
            artifact_dir_display
        ),
        format!("cat {}/run_manifest.json", artifact_dir_display),
    ];

    let env_json = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": "franken-engine.env.v1",
        "captured_at_utc": &context.generated_at_utc,
        "project": {
            "name": "franken_engine",
            "repo_url": "https://github.com/Dicklesworthstone/franken_engine",
            "commit": &context.source_commit,
            "bead_id": EVIDENCE_LEDGER_STITCHING_BEAD_ID,
        },
        "host": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "toolchain": {
            "rustup_toolchain": &context.toolchain,
        },
        "runtime": {
            "component": EVIDENCE_LEDGER_STITCHING_COMPONENT,
            "trace_id": &context.trace_id,
        },
        "policy": {
            "policy_id": &context.policy_id,
        }
    }))
    .expect("serde serialization should succeed");

    let mut primary_files = vec![
        BundleFileArtifact::json("evidence_ledger_stitching_bundle.json", &evaluated.bundle),
        BundleFileArtifact::json(
            "evidence_ledger_graph.json",
            &evaluated.bundle.evidence_ledger_graph,
        ),
        BundleFileArtifact::jsonl(
            "decision_semantics_log.jsonl",
            &evaluated.bundle.decision_semantics_log,
        ),
        BundleFileArtifact::json(
            "artifact_lineage_index.json",
            &evaluated.bundle.artifact_lineage_index,
        ),
        BundleFileArtifact::json(
            "evidence_query_surface_snapshot.json",
            &evaluated.bundle.evidence_query_surface_snapshot,
        ),
        BundleFileArtifact::json("trace_ids.json", &evaluated.trace_ids),
        BundleFileArtifact::json(
            "run_manifest.json",
            &serde_json::json!({
                "schema_version": EVIDENCE_LEDGER_STITCHING_RUN_MANIFEST_SCHEMA_VERSION,
                "bead_id": EVIDENCE_LEDGER_STITCHING_BEAD_ID,
                "component": EVIDENCE_LEDGER_STITCHING_COMPONENT,
                "run_id": &context.run_id,
                "generated_at_utc": &context.generated_at_utc,
                "trace_id": &context.trace_id,
                "decision_id": &context.decision_id,
                "policy_id": &context.policy_id,
                "node_count": evaluated.bundle.evidence_ledger_graph.nodes.len(),
                "edge_count": evaluated.bundle.evidence_ledger_graph.edges.len(),
                "artifact_count": evaluated.bundle.artifact_lineage_index.len(),
                "boundary_count": evaluated.bundle.evidence_query_surface_snapshot.decisions.first().map_or(0, |d| d.boundary_correlation_keys.len()),
                "bundle_hash": digest_json(&serde_json::to_value(&evaluated.bundle).expect("serde serialization should succeed")),
                "graph_hash": digest_json(&serde_json::to_value(&evaluated.bundle.evidence_ledger_graph).expect("serde serialization should succeed")),
                "query_snapshot_hash": digest_json(&serde_json::to_value(&evaluated.bundle.evidence_query_surface_snapshot).expect("serde serialization should succeed")),
                "artifacts": required_artifact_names(),
                "operator_verification": commands.clone(),
            }),
        ),
        BundleFileArtifact::jsonl("events.jsonl", &evaluated.logs),
        BundleFileArtifact::text("commands.txt", &commands.join("\n")),
        BundleFileArtifact::text("summary.md", &summary_md),
        BundleFileArtifact::text("env.json", &env_json),
    ];
    primary_files.sort_by(|left, right| left.path.cmp(&right.path));

    let primary_hashes = primary_files
        .iter()
        .map(|artifact| {
            (
                artifact.path.clone(),
                format!("sha256:{}", sha256_hex(&artifact.contents)),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let repro_lock = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": "franken-engine.repro-lock.v1",
        "generated_at_utc": &context.generated_at_utc,
        "lock_id": format!("{}-{}", EVIDENCE_LEDGER_STITCHING_COMPONENT, context.run_id),
        "source_commit": &context.source_commit,
        "determinism": {
            "allow_network": false,
            "allow_wall_clock": false,
            "allow_randomness": false,
        },
        "commands": commands.clone(),
        "expected_outputs": primary_hashes.iter().map(|(path, sha256)| {
            serde_json::json!({
                "path": path,
                "sha256": sha256,
            })
        }).collect::<Vec<_>>(),
        "replay": {
            "trace_id": &context.trace_id,
            "decision_id": &context.decision_id,
            "policy_id": &context.policy_id,
        }
    }))
    .expect("serde serialization should succeed");
    primary_files.push(BundleFileArtifact::text("repro.lock", &repro_lock));
    primary_files.sort_by(|left, right| left.path.cmp(&right.path));

    let manifest_artifacts = primary_files
        .iter()
        .map(|artifact| ManifestArtifactReference {
            path: artifact.path.clone(),
            sha256: format!("sha256:{}", sha256_hex(&artifact.contents)),
        })
        .collect::<Vec<_>>();

    let manifest_json = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": "franken-engine.manifest.v1",
        "manifest_id": format!("{}-{}", EVIDENCE_LEDGER_STITCHING_COMPONENT, context.run_id),
        "generated_at_utc": &context.generated_at_utc,
        "claim": {
            "claim_id": EVIDENCE_LEDGER_STITCHING_BEAD_ID,
            "class": "implementation",
            "statement": "Extend decision logs into deterministic evidence-ledger, artifact-lineage, and query-surface bundles.",
            "status": "observed",
            "bundle_root": &artifact_dir_display,
        },
        "source_revision": {
            "repo": "franken_engine",
            "branch": "main",
            "commit": &context.source_commit,
        },
        "provenance": {
            "trace_id": &context.trace_id,
            "decision_id": &context.decision_id,
            "policy_id": &context.policy_id,
            "replay_pointer": format!("file://{artifact_dir_display}/commands.txt"),
            "evidence_pointer": format!("file://{artifact_dir_display}/evidence_ledger_stitching_bundle.json"),
        },
        "artifacts": &manifest_artifacts,
    }))
    .expect("serde serialization should succeed");
    let manifest_artifact = BundleFileArtifact::text("manifest.json", &manifest_json);

    let _bundle_lock = acquire_bundle_write_lock(&context.artifact_dir)?;
    remove_commit_marker(&context.artifact_dir.join(&manifest_artifact.path))?;
    let mut written_files = BTreeMap::new();
    for artifact in primary_files {
        let full_path = context.artifact_dir.join(&artifact.path);
        write_atomic(&full_path, &artifact.contents)?;
        written_files.insert(
            artifact.path,
            format!("sha256:{}", sha256_hex(&artifact.contents)),
        );
    }
    let manifest_path = context.artifact_dir.join(&manifest_artifact.path);
    write_atomic(&manifest_path, &manifest_artifact.contents)?;
    written_files.insert(
        manifest_artifact.path,
        format!("sha256:{}", sha256_hex(&manifest_artifact.contents)),
    );

    Ok(StitchingBundleWriteReport {
        artifact_dir: context.artifact_dir.clone(),
        bundle: evaluated.bundle.clone(),
        trace_ids_path: context.artifact_dir.join("trace_ids.json"),
        written_files,
    })
}

fn default_stitching_entry(context: &StitchingArtifactContext) -> EvidenceEntry {
    let authority = LabEvidenceAuthority::deterministic_fixture(
        "franken-engine.lab.evidence-ledger-stitching",
        EVIDENCE_LEDGER_STITCHING_BEAD_ID,
        SecurityEpoch::GENESIS,
    )
    .expect("stitching lab identity must be derivable");
    EvidenceEntryBuilder::new_with_lab_authority(
        context.trace_id.clone(),
        context.decision_id.clone(),
        context.policy_id.clone(),
        SecurityEpoch::from_raw(5),
        DecisionType::SecurityAction,
        &authority,
    )
    .timestamp_ns(1_000_000)
    .candidate(CandidateAction::new("sandbox", 100_000))
    .candidate(CandidateAction::new("terminate", 500_000))
    .candidate(CandidateAction::filtered(
        "ignore",
        900_000,
        "exceeds loss budget",
    ))
    .constraint(Constraint {
        constraint_id: "max-loss".to_string(),
        description: "maximum expected loss threshold".to_string(),
        active: true,
    })
    .chosen(ChosenAction {
        action_name: "sandbox".to_string(),
        expected_loss_millionths: 100_000,
        rationale: "lowest expected loss within constraints".to_string(),
    })
    .witness(Witness {
        witness_id: "obs-001".to_string(),
        witness_type: "posterior".to_string(),
        value: "0.85".to_string(),
    })
    .meta("extension_id", "ext-abc")
    .build()
    .expect("build default stitching entry")
}

fn default_boundary_records(
    context: &StitchingArtifactContext,
) -> io::Result<Vec<BoundaryCaptureRecord>> {
    let mut session = BoundaryCaptureSession::default_v1();
    let boundary_context = BoundaryContext::new(
        context.trace_id.as_str(),
        context.decision_id.as_str(),
        context.policy_id.as_str(),
        EVIDENCE_LEDGER_STITCHING_COMPONENT,
        128,
    );
    let scheduling = session
        .capture_scheduling_decision(
            &boundary_context,
            "hot-lane",
            "task-17",
            "digest-order",
            None,
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
    let override_record = session
        .capture_controller_override(
            &boundary_context,
            "safety-router",
            "force-sandbox",
            "digest-override",
            None,
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
    let policy = session
        .capture_external_policy_read(
            &boundary_context,
            "release_policy",
            "digest-policy",
            11,
            None,
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
    Ok(vec![scheduling, override_record, policy])
}

fn default_artifact_records(boundaries: &[BoundaryCaptureRecord]) -> Vec<ArtifactRecord> {
    vec![
        ArtifactRecord::new(
            "benchmark-snapshot",
            "benchmark_manifest",
            "artifacts/benchmark-snapshot.json",
            "hash-benchmark",
        )
        .supporting_boundary(boundaries[0].correlation_key.clone()),
        ArtifactRecord::new(
            "release-gate",
            "release_gate_report",
            "artifacts/release-gate.json",
            "hash-release",
        )
        .supporting_boundary(boundaries[2].correlation_key.clone()),
        ArtifactRecord::new(
            "support-export",
            "support_bundle",
            "artifacts/support-export.json",
            "hash-support",
        ),
    ]
}

fn default_decision_annotations(
    boundaries: &[BoundaryCaptureRecord],
) -> DecisionSemanticsAnnotations {
    DecisionSemanticsAnnotations {
        confidence_tier: Some("high".to_string()),
        fallback_reason: Some("safe_mode_guard".to_string()),
        regret_summary: Some("bounded_regret<=1000".to_string()),
        scope_limits: vec![
            "controller=safety-router".to_string(),
            "release=report-only".to_string(),
        ],
        assumptions: BTreeMap::from([
            ("policy_snapshot".to_string(), "signed".to_string()),
            ("support_visibility".to_string(), "operator".to_string()),
        ]),
        linked_boundary_correlation_keys: boundaries
            .iter()
            .map(|boundary| boundary.correlation_key.clone())
            .collect(),
    }
}

fn required_artifact_names() -> Vec<String> {
    vec![
        "artifact_lineage_index.json".to_string(),
        "commands.txt".to_string(),
        "decision_semantics_log.jsonl".to_string(),
        "env.json".to_string(),
        "evidence_ledger_graph.json".to_string(),
        "evidence_ledger_stitching_bundle.json".to_string(),
        "evidence_query_surface_snapshot.json".to_string(),
        "events.jsonl".to_string(),
        "manifest.json".to_string(),
        "repro.lock".to_string(),
        "run_manifest.json".to_string(),
        "summary.md".to_string(),
        "trace_ids.json".to_string(),
    ]
}

fn acquire_bundle_write_lock(artifact_dir: &Path) -> io::Result<BundleWriteLock> {
    let lock_path = artifact_dir.join(".evidence_ledger_stitching.lock");

    // Check for existing lock and validate if owner is still alive
    if lock_path.exists() {
        if let Ok(lock_content) = fs::read_to_string(&lock_path)
            && let Ok(lock_pid) = lock_content.trim().parse::<u32>()
        {
            // Check if the process is still running
            #[cfg(unix)]
            {
                use std::process::Command;
                let is_alive = Command::new("kill")
                    .arg("-0")
                    .arg(lock_pid.to_string())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if is_alive {
                    return Err(io::Error::new(
                        ErrorKind::AlreadyExists,
                        format!(
                            "bundle already being written by PID {}: {}",
                            lock_pid,
                            lock_path.display()
                        ),
                    ));
                }
            }
            #[cfg(not(unix))]
            {
                // On non-Unix platforms, assume stale if older than 5 minutes
                if let Ok(metadata) = lock_path.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        if modified.elapsed().unwrap_or(std::time::Duration::MAX)
                            < std::time::Duration::from_secs(300)
                        {
                            return Err(io::Error::new(
                                ErrorKind::AlreadyExists,
                                format!(
                                    "bundle recently locked by PID {}: {}",
                                    lock_pid,
                                    lock_path.display()
                                ),
                            ));
                        }
                    }
                }
            }
        }
        // Lock exists but is stale, remove it
        let _ = fs::remove_file(&lock_path);
    }

    // Write our PID to the lock file
    let current_pid = std::process::id();
    match fs::write(&lock_path, current_pid.to_string()) {
        Ok(()) => Ok(BundleWriteLock { path: lock_path }),
        Err(source) => Err(io::Error::new(
            source.kind(),
            format!(
                "failed to acquire bundle write lock {}: {source}",
                lock_path.display()
            ),
        )),
    }
}

fn remove_commit_marker(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(source),
    }
}

fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp_path = unique_temp_path(path);
    fs::write(&temp_path, contents)?;
    if let Err(source) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(source);
    }
    Ok(())
}

fn unique_temp_path(path: &Path) -> PathBuf {
    let sequence = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let mut temp_name = OsString::from(".");
    match path.file_name() {
        Some(file_name) => temp_name.push(file_name),
        None => temp_name.push("artifact"),
    }
    temp_name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(temp_name)
}

fn digest_json(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).expect("serde serialization should succeed");
    sha256_hex(&bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    ContentHash::compute(bytes).to_hex()
}

impl BundleFileArtifact {
    fn json<T: Serialize>(path: &str, value: &T) -> Self {
        Self {
            path: path.to_string(),
            contents: serde_json::to_vec_pretty(value).expect("serde serialization should succeed"),
        }
    }

    fn jsonl<T: Serialize>(path: &str, records: &[T]) -> Self {
        let mut contents = Vec::new();
        for record in records {
            let mut line = serde_json::to_vec(record).expect("serde serialization should succeed");
            line.push(b'\n');
            contents.extend_from_slice(&line);
        }
        Self {
            path: path.to_string(),
            contents,
        }
    }

    fn text(path: &str, contents: &str) -> Self {
        Self {
            path: path.to_string(),
            contents: contents.as_bytes().to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hindsight_boundary_capture::{BoundaryCaptureSession, BoundaryContext};
    use crate::signature_preimage::sign_preimage;

    fn sample_entry() -> EvidenceEntry {
        EvidenceEntryBuilder::new(
            "trace-001",
            "decision-001",
            "policy-v1",
            SecurityEpoch::from_raw(5),
            DecisionType::SecurityAction,
        )
        .timestamp_ns(1_000_000)
        .candidate(CandidateAction::new("sandbox", 100_000))
        .candidate(CandidateAction::new("terminate", 500_000))
        .candidate(CandidateAction::filtered(
            "ignore",
            900_000,
            "exceeds loss budget",
        ))
        .constraint(Constraint {
            constraint_id: "max-loss".to_string(),
            description: "maximum expected loss threshold".to_string(),
            active: true,
        })
        .chosen(ChosenAction {
            action_name: "sandbox".to_string(),
            expected_loss_millionths: 100_000,
            rationale: "lowest expected loss within constraints".to_string(),
        })
        .witness(Witness {
            witness_id: "obs-001".to_string(),
            witness_type: "posterior".to_string(),
            value: "0.85".to_string(),
        })
        .meta("extension_id", "ext-abc")
        .build()
        .expect("build sample entry")
    }

    fn batch_entry(decision_id: &str) -> EvidenceEntry {
        EvidenceEntryBuilder::new(
            format!("trace-{decision_id}"),
            decision_id,
            "policy-v1",
            SecurityEpoch::from_raw(5),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: "sandbox".to_string(),
            expected_loss_millionths: 100_000,
            rationale: "atomic batch fixture".to_string(),
        })
        .build()
        .expect("build batch entry")
    }

    fn sample_boundary_records() -> Vec<BoundaryCaptureRecord> {
        let mut session = BoundaryCaptureSession::default_v1();
        let context =
            BoundaryContext::new("trace-001", "decision-001", "policy-v1", "orchestrator", 64);
        let controller_override = session
            .capture_controller_override(
                &context,
                "risk-controller",
                "forced-sandbox",
                "digest-override",
                None,
            )
            .expect("capture controller override");
        let external_policy = session
            .capture_external_policy_read(&context, "extension_policy", "digest-policy", 7, None)
            .expect("capture external policy read");
        vec![controller_override, external_policy]
    }

    // -- Schema version --

    #[test]
    fn schema_version_current() {
        assert_eq!(current_schema_version().major, 2);
        assert_eq!(current_schema_version().minor, 0);
    }

    #[test]
    fn schema_version_compatibility() {
        let v1_0 = SchemaVersion::new(1, 0, 0);
        let v1_1 = SchemaVersion::new(1, 1, 0);
        let v2_0 = SchemaVersion::new(2, 0, 0);

        // v1.0 entry compatible with v1.0 reader.
        assert!(v1_0.is_compatible_with(&v1_0));
        // v1.0 entry compatible with v1.1 reader (additive).
        assert!(v1_0.is_compatible_with(&v1_1));
        // v1.1 entry NOT compatible with v1.0 reader.
        assert!(!v1_1.is_compatible_with(&v1_0));
        // v1.0 entry NOT compatible with v2.0 reader.
        assert!(!v1_0.is_compatible_with(&v2_0));
    }

    #[test]
    fn schema_version_display() {
        assert_eq!(current_schema_version().to_string(), "2.0.0");
    }

    // -- Builder --

    #[test]
    fn builder_produces_valid_entry() {
        let entry = sample_entry();
        assert_eq!(entry.schema_version, current_schema_version());
        assert!(entry.entry_id.starts_with("ev-"));
        assert_eq!(entry.trace_id, "trace-001");
        assert_eq!(entry.decision_id, "decision-001");
        assert_eq!(entry.policy_id, "policy-v1");
        assert_eq!(entry.epoch_id, SecurityEpoch::from_raw(5));
        assert_eq!(entry.decision_type, DecisionType::SecurityAction);
        assert_eq!(entry.candidates.len(), 3);
        assert_eq!(entry.constraints.len(), 1);
        assert_eq!(entry.chosen_action.action_name, "sandbox");
        assert_eq!(entry.witnesses.len(), 1);
        assert!(!entry.evidence_hash.is_empty());
        assert_eq!(entry.metadata["extension_id"], "ext-abc");
    }

    #[test]
    fn builder_requires_chosen_action() {
        let err = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::GENESIS,
            DecisionType::PolicyUpdate,
        )
        .build()
        .unwrap_err();
        assert_eq!(err, LedgerError::MissingChosenAction);
    }

    // -- Deterministic hashing --

    #[test]
    fn deterministic_hash_is_stable() {
        let h1 = deterministic_hash("test input");
        let h2 = deterministic_hash("test input");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_inputs_produce_different_hashes() {
        let h1 = deterministic_hash("input A");
        let h2 = deterministic_hash("input B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn entry_id_and_hash_are_deterministic() {
        let e1 = sample_entry();
        let e2 = sample_entry();
        assert_eq!(e1.entry_id, e2.entry_id);
        assert_eq!(e1.evidence_hash, e2.evidence_hash);
    }

    // -- CandidateAction --

    #[test]
    fn candidate_unfiltered() {
        let c = CandidateAction::new("allow", 50_000);
        assert!(!c.filtered);
        assert!(c.filter_reason.is_none());
    }

    #[test]
    fn candidate_filtered() {
        let c = CandidateAction::filtered("terminate", 999_000, "policy forbids");
        assert!(c.filtered);
        assert_eq!(c.filter_reason.as_deref(), Some("policy forbids"));
    }

    // -- Decision type display --

    #[test]
    fn decision_type_display() {
        assert_eq!(DecisionType::SecurityAction.to_string(), "security_action");
        assert_eq!(DecisionType::PolicyUpdate.to_string(), "policy_update");
        assert_eq!(
            DecisionType::EpochTransition.to_string(),
            "epoch_transition"
        );
        assert_eq!(DecisionType::Revocation.to_string(), "revocation");
    }

    // -- InMemoryLedger --

    #[test]
    fn ledger_stores_entries() {
        let mut ledger = InMemoryLedger::new();
        assert!(ledger.is_empty());

        ledger.emit(sample_entry()).expect("emit");
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn ledger_rejects_duplicate_entry_id() {
        let mut ledger = InMemoryLedger::new();
        let entry = sample_entry();
        ledger.emit(entry.clone()).expect("first emit");

        let err = ledger.emit(entry).unwrap_err();
        assert!(matches!(err, LedgerError::DuplicateEntryId { .. }));
    }

    #[test]
    fn bd_gjrlf_batch_preserves_order_and_rejects_late_duplicate_atomically() {
        let first = batch_entry("batch-first");
        let second = batch_entry("batch-second");
        let mut ledger = InMemoryLedger::new();

        ledger
            .emit_batch(vec![first.clone(), second.clone()])
            .expect("valid evidence batch must commit");
        assert_eq!(
            ledger
                .entries()
                .iter()
                .map(|entry| entry.entry_id.as_str())
                .collect::<Vec<_>>(),
            vec![first.entry_id.as_str(), second.entry_id.as_str()]
        );

        let before_ids = ledger
            .entries()
            .iter()
            .map(|entry| entry.entry_id.clone())
            .collect::<Vec<_>>();
        let late_new_entry = batch_entry("batch-late-new");
        let error = ledger
            .emit_batch(vec![late_new_entry, second])
            .expect_err("a duplicate later in the batch must reject the whole batch");

        assert!(matches!(error, LedgerError::DuplicateEntryId { .. }));
        assert_eq!(
            ledger
                .entries()
                .iter()
                .map(|entry| entry.entry_id.clone())
                .collect::<Vec<_>>(),
            before_ids,
            "no valid prefix may be committed before a later batch failure"
        );
    }

    #[test]
    fn schema_v2_rejects_deserialization_without_authentication() {
        let mut value = serde_json::to_value(sample_entry()).expect("serialize entry");
        value
            .as_object_mut()
            .expect("entry serializes as an object")
            .remove("signed_envelope");
        assert!(
            serde_json::from_value::<EvidenceEntry>(value).is_err(),
            "schema-v2 evidence cannot deserialize without authentication"
        );
    }

    #[test]
    fn ledger_rejects_unauthorized_producer() {
        let signing_key = SigningKey::from_bytes([0x33; 32]).expect("non-zero test signing key");
        let entry = EvidenceEntryBuilder::new(
            "trace-attacker",
            "decision-attacker",
            "policy-v1",
            SecurityEpoch::from_raw(5),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "forged".to_string(),
        })
        .signed_by("unregistered-producer", signing_key)
        .build()
        .expect("build signed forged entry");

        let mut ledger = InMemoryLedger::new();
        let err = ledger.emit(entry).unwrap_err();
        assert!(
            matches!(err, LedgerError::SchemaValidationFailed { reason } if reason.contains("unauthorized evidence producer"))
        );
    }

    #[test]
    fn bd_90u6o_source_known_seed_cannot_forge_runtime_identity() {
        let epoch = SecurityEpoch::from_raw(5);
        let runtime_identity = EvidenceSigningIdentity::generate_runtime_owned(
            "runtime-a",
            SecurityEpoch::from_raw(1),
            1,
            None,
        )
        .expect("OS-backed runtime identity");
        let mut ledger = InMemoryLedger::for_signing_identity(epoch, &runtime_identity)
            .expect("runtime identity registration");

        let public_old_seed =
            SigningKey::from_bytes([0x7B; 32]).expect("historical source-known seed is non-zero");
        let forged = EvidenceEntryBuilder::new(
            "trace-forged",
            "decision-forged",
            "policy-v1",
            epoch,
            DecisionType::SecurityAction,
        )
        .signed_by(runtime_identity.producer_id(), public_old_seed)
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "source-known forgery".to_string(),
        })
        .build()
        .expect("attacker can build a byte-valid envelope under its own key");

        let err = ledger.emit(forged).unwrap_err();
        assert!(
            matches!(err, LedgerError::SchemaValidationFailed { reason } if reason.contains("unauthorized evidence producer/key"))
        );
    }

    #[test]
    fn bd_90u6o_rotation_provenance_is_signature_bound() {
        let epoch = SecurityEpoch::from_raw(9);
        let root = EvidenceSigningIdentity::from_signing_key(
            "runtime-rotated",
            SigningKey::from_bytes([0x61; 32]).expect("non-zero root key"),
            SecurityEpoch::from_raw(7),
            1,
            None,
        )
        .expect("rotation root");
        let identity = EvidenceSigningIdentity::generate_runtime_owned(
            "runtime-rotated",
            SecurityEpoch::from_raw(8),
            2,
            Some(root.key_provenance().key_id.clone()),
        )
        .expect("rotated runtime identity");
        let mut entry = EvidenceEntryBuilder::new(
            "trace-rotated",
            "decision-rotated",
            "policy-v1",
            epoch,
            DecisionType::PolicyUpdate,
        )
        .signed_by_identity(identity.clone())
        .chosen(ChosenAction {
            action_name: "rotate".to_string(),
            expected_loss_millionths: 0,
            rationale: "authorized rotation".to_string(),
        })
        .build()
        .expect("rotated entry");
        entry.signed_envelope.key_provenance.previous_key_id = Some("ed25519:tampered".to_string());

        let mut ledger =
            InMemoryLedger::for_signing_identity(epoch, &root).expect("root registration");
        ledger
            .authorize_signing_identity(&identity)
            .expect("validated rotation registration");
        let err = ledger.emit(entry).unwrap_err();
        assert!(
            matches!(err, LedgerError::SchemaValidationFailed { reason } if reason.contains("evidence hash mismatch"))
        );
    }

    #[test]
    fn bd_90u6o_rotation_registry_rejects_gaps_forks_and_epoch_regression() {
        let epoch = SecurityEpoch::from_raw(12);
        let root = EvidenceSigningIdentity::from_signing_key(
            "runtime-lineage",
            SigningKey::from_bytes([0x62; 32]).expect("non-zero root key"),
            SecurityEpoch::from_raw(8),
            1,
            None,
        )
        .expect("rotation root");
        let root_key_id = root.key_provenance().key_id.clone();

        let skipped = EvidenceSigningIdentity::from_signing_key(
            "runtime-lineage",
            SigningKey::from_bytes([0x63; 32]).expect("non-zero skipped key"),
            SecurityEpoch::from_raw(9),
            3,
            Some(root_key_id.clone()),
        )
        .expect("syntactically valid skipped identity");
        let mut ledger =
            InMemoryLedger::for_signing_identity(epoch, &root).expect("root registration");
        assert!(
            matches!(
                ledger.authorize_signing_identity(&skipped),
                Err(LedgerError::SchemaValidationFailed { reason })
                    if reason.contains("advance exactly once")
            ),
            "a rotation sequence gap must be rejected"
        );

        let regressed = EvidenceSigningIdentity::from_signing_key(
            "runtime-lineage",
            SigningKey::from_bytes([0x64; 32]).expect("non-zero regressed key"),
            SecurityEpoch::from_raw(7),
            2,
            Some(root_key_id.clone()),
        )
        .expect("syntactically valid regressed identity");
        assert!(
            matches!(
                ledger.authorize_signing_identity(&regressed),
                Err(LedgerError::SchemaValidationFailed { reason })
                    if reason.contains("activation epoch regressed")
            ),
            "rotation activation epochs must be monotonic"
        );

        let second = EvidenceSigningIdentity::from_signing_key(
            "runtime-lineage",
            SigningKey::from_bytes([0x65; 32]).expect("non-zero second key"),
            SecurityEpoch::from_raw(9),
            2,
            Some(root_key_id.clone()),
        )
        .expect("second identity");
        ledger
            .authorize_signing_identity(&second)
            .expect("first child extends the root");
        let fork = EvidenceSigningIdentity::from_signing_key(
            "runtime-lineage",
            SigningKey::from_bytes([0x66; 32]).expect("non-zero fork key"),
            SecurityEpoch::from_raw(10),
            2,
            Some(root_key_id),
        )
        .expect("fork identity");
        assert!(
            matches!(
                ledger.authorize_signing_identity(&fork),
                Err(LedgerError::SchemaValidationFailed { reason })
                    if reason.contains("current producer tip")
                        || reason.contains("already has a key at rotation sequence")
            ),
            "a second child of an old predecessor must be rejected"
        );
    }

    #[test]
    fn bd_90u6o_legacy_registration_cannot_downgrade_a_pinned_lineage() {
        let epoch = SecurityEpoch::from_raw(8);
        let root = EvidenceSigningIdentity::from_signing_key(
            "runtime-pinned",
            SigningKey::from_bytes([0x67; 32]).expect("non-zero root key"),
            SecurityEpoch::from_raw(4),
            1,
            None,
        )
        .expect("pinned root");
        let mut ledger =
            InMemoryLedger::for_signing_identity(epoch, &root).expect("root registration");

        ledger.authorize_producer(root.producer_id(), root.verification_key());
        let relabeled_root = EvidenceSigningIdentity::from_signing_key(
            "runtime-pinned",
            SigningKey::from_bytes([0x67; 32]).expect("same non-zero root key"),
            SecurityEpoch::from_raw(3),
            1,
            None,
        )
        .expect("structurally valid relabeled root");
        let relabeled_entry = EvidenceEntryBuilder::new(
            "trace-relabeled",
            "decision-relabeled",
            "policy-v1",
            epoch,
            DecisionType::SecurityAction,
        )
        .signed_by_identity(relabeled_root)
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "attempt legacy provenance downgrade".to_string(),
        })
        .build()
        .expect("byte-valid relabeled entry");
        assert!(
            matches!(
                ledger.emit(relabeled_entry),
                Err(LedgerError::SchemaValidationFailed { reason })
                    if reason.contains("producer key provenance mismatch")
            ),
            "legacy registration must not erase pinned provenance"
        );

        let unrelated_key =
            SigningKey::from_bytes([0x68; 32]).expect("non-zero unrelated legacy key");
        ledger.authorize_producer("runtime-pinned", unrelated_key.verification_key());
        let unrelated_entry = EvidenceEntryBuilder::new(
            "trace-unrelated",
            "decision-unrelated",
            "policy-v1",
            epoch,
            DecisionType::SecurityAction,
        )
        .signed_by("runtime-pinned", unrelated_key)
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "attempt unrelated legacy root".to_string(),
        })
        .build()
        .expect("byte-valid unrelated entry");
        assert!(
            matches!(
                ledger.emit(unrelated_entry),
                Err(LedgerError::SchemaValidationFailed { reason })
                    if reason.contains("unauthorized evidence producer/key")
            ),
            "legacy registration must not add another root to a pinned producer"
        );
    }

    #[test]
    fn bd_90u6o_predecessor_is_valid_only_before_successor_activation() {
        let root = EvidenceSigningIdentity::from_signing_key(
            "runtime-retirement",
            SigningKey::from_bytes([0x69; 32]).expect("non-zero root key"),
            SecurityEpoch::from_raw(2),
            1,
            None,
        )
        .expect("rotation root");
        let successor = EvidenceSigningIdentity::from_signing_key(
            "runtime-retirement",
            SigningKey::from_bytes([0x6A; 32]).expect("non-zero successor key"),
            SecurityEpoch::from_raw(10),
            2,
            Some(root.key_provenance().key_id.clone()),
        )
        .expect("rotation successor");

        let mut backdated_ledger = InMemoryLedger::new();
        backdated_ledger
            .authorize_signing_identity(&root)
            .expect("backdated-test root registration");
        let already_accepted = EvidenceEntryBuilder::new(
            "trace-before-late-registration",
            "decision-before-late-registration",
            "policy-v1",
            SecurityEpoch::from_raw(11),
            DecisionType::SecurityAction,
        )
        .signed_by_identity(root.clone())
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "accepted before a backdated rotation attempt".to_string(),
        })
        .build()
        .expect("predecessor entry before rotation registration");
        backdated_ledger
            .emit(already_accepted)
            .expect("predecessor entry is initially valid");
        assert!(
            matches!(
                backdated_ledger.authorize_signing_identity(&successor),
                Err(LedgerError::SchemaValidationFailed { reason })
                    if reason.contains(
                        "activation epoch 10 must follow latest accepted predecessor evidence epoch 11"
                    )
            ),
            "a rotation must not retroactively invalidate accepted predecessor evidence"
        );

        let mut ledger = InMemoryLedger::new();
        ledger
            .authorize_signing_identity(&root)
            .expect("root registration");
        ledger
            .authorize_signing_identity(&successor)
            .expect("successor registration");

        let before_activation = EvidenceEntryBuilder::new(
            "trace-before-rotation",
            "decision-before-rotation",
            "policy-v1",
            SecurityEpoch::from_raw(9),
            DecisionType::SecurityAction,
        )
        .signed_by_identity(root.clone())
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "historical predecessor evidence".to_string(),
        })
        .build()
        .expect("historical predecessor entry");
        ledger
            .emit(before_activation)
            .expect("predecessor remains valid before successor activation");

        for (epoch, suffix) in [(10, "at"), (11, "after")] {
            let retired_entry = EvidenceEntryBuilder::new(
                format!("trace-{suffix}-rotation"),
                format!("decision-{suffix}-rotation"),
                "policy-v1",
                SecurityEpoch::from_raw(epoch),
                DecisionType::SecurityAction,
            )
            .signed_by_identity(root.clone())
            .chosen(ChosenAction {
                action_name: "allow".to_string(),
                expected_loss_millionths: 0,
                rationale: "retired predecessor attempt".to_string(),
            })
            .build()
            .expect("byte-valid predecessor entry");
            assert!(
                matches!(
                    ledger.emit(retired_entry),
                    Err(LedgerError::SchemaValidationFailed { reason })
                        if reason.contains("retired at successor activation epoch 10")
                ),
                "predecessor must be rejected {suffix} successor activation"
            );
        }

        let successor_entry = EvidenceEntryBuilder::new(
            "trace-current-rotation",
            "decision-current-rotation",
            "policy-v1",
            SecurityEpoch::from_raw(10),
            DecisionType::SecurityAction,
        )
        .signed_by_identity(successor)
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "active successor evidence".to_string(),
        })
        .build()
        .expect("active successor entry");
        ledger
            .emit(successor_entry)
            .expect("successor is valid at its activation epoch");
    }

    #[test]
    fn bd_90u6o_independent_runtime_identities_do_not_reuse_keys() {
        let first = EvidenceSigningIdentity::generate_runtime_owned(
            "runtime-a",
            SecurityEpoch::from_raw(1),
            1,
            None,
        )
        .expect("first runtime identity");
        let second = EvidenceSigningIdentity::generate_runtime_owned(
            "runtime-b",
            SecurityEpoch::from_raw(1),
            1,
            None,
        )
        .expect("second runtime identity");
        assert_ne!(
            first.key_provenance().key_id,
            second.key_provenance().key_id
        );
    }

    #[test]
    fn ledger_rejects_mismatched_epoch() {
        let mut ledger = InMemoryLedger::for_epoch(SecurityEpoch::from_raw(6));
        let err = ledger.emit(sample_entry()).unwrap_err();
        assert!(
            matches!(err, LedgerError::SchemaValidationFailed { reason } if reason.contains("evidence epoch mismatch"))
        );
    }

    #[test]
    fn ledger_query_by_decision_type() {
        let mut ledger = InMemoryLedger::new();
        ledger.emit(sample_entry()).expect("emit");

        let entry2 = EvidenceEntryBuilder::new(
            "trace-002",
            "decision-002",
            "policy-v1",
            SecurityEpoch::from_raw(5),
            DecisionType::PolicyUpdate,
        )
        .chosen(ChosenAction {
            action_name: "rotate".to_string(),
            expected_loss_millionths: 0,
            rationale: "scheduled rotation".to_string(),
        })
        .build()
        .expect("build");
        ledger.emit(entry2).expect("emit");

        let security_entries = ledger.by_decision_type(DecisionType::SecurityAction);
        assert_eq!(security_entries.len(), 1);

        let policy_entries = ledger.by_decision_type(DecisionType::PolicyUpdate);
        assert_eq!(policy_entries.len(), 1);
    }

    #[test]
    fn ledger_query_by_epoch() {
        let mut ledger = InMemoryLedger::new();
        ledger.emit(sample_entry()).expect("emit");

        let entries_e5 = ledger.by_epoch(SecurityEpoch::from_raw(5));
        assert_eq!(entries_e5.len(), 1);

        let entries_e1 = ledger.by_epoch(SecurityEpoch::from_raw(1));
        assert!(entries_e1.is_empty());
    }

    // -- Error display --

    #[test]
    fn ledger_error_display() {
        assert_eq!(
            LedgerError::MissingChosenAction.to_string(),
            "chosen action is required"
        );
        assert_eq!(
            LedgerError::DuplicateEntryId {
                entry_id: "ev-123".to_string()
            }
            .to_string(),
            "duplicate entry id: ev-123"
        );
        let err = LedgerError::IncompatibleSchema {
            entry_version: SchemaVersion::new(3, 0, 0),
            reader_version: current_schema_version(),
        };
        assert_eq!(
            err.to_string(),
            "incompatible schema: entry 3.0.0, reader 2.0.0"
        );
    }

    // -- Serialization --

    #[test]
    fn evidence_entry_serialization_round_trip() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).expect("serde serialization should succeed");
        let restored: EvidenceEntry =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(entry, restored);
    }

    #[test]
    fn evidence_entry_deterministic_serialization() {
        let entry = sample_entry();
        let json1 = serde_json::to_string(&entry).expect("serde serialization should succeed");
        let json2 = serde_json::to_string(&entry).expect("serde serialization should succeed");
        assert_eq!(json1, json2);
    }

    #[test]
    fn all_error_variants_serialize() {
        let errors = vec![
            LedgerError::MissingChosenAction,
            LedgerError::SchemaValidationFailed {
                reason: "test".to_string(),
            },
            LedgerError::IncompatibleSchema {
                entry_version: SchemaVersion::new(2, 0, 0),
                reader_version: current_schema_version(),
            },
            LedgerError::DuplicateEntryId {
                entry_id: "ev-test".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serde serialization should succeed");
            let restored: LedgerError =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn candidate_action_serialization_round_trip() {
        let c = CandidateAction::filtered("sandbox", 100_000, "max-loss");
        let json = serde_json::to_string(&c).expect("serde serialization should succeed");
        let restored: CandidateAction =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(c, restored);
    }

    #[test]
    fn schema_version_serialization_round_trip() {
        let v = current_schema_version();
        let json = serde_json::to_string(&v).expect("serde serialization should succeed");
        let restored: SchemaVersion =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(v, restored);
    }

    // -- Enrichment: ordering --

    #[test]
    fn decision_type_ordering() {
        assert!(DecisionType::SecurityAction < DecisionType::PolicyUpdate);
        assert!(DecisionType::PolicyUpdate < DecisionType::EpochTransition);
        assert!(DecisionType::EpochTransition < DecisionType::Revocation);
        assert!(DecisionType::Revocation < DecisionType::ExtensionLifecycle);
        assert!(DecisionType::ExtensionLifecycle < DecisionType::CapabilityDecision);
        assert!(DecisionType::CapabilityDecision < DecisionType::ContractEvaluation);
        assert!(DecisionType::ContractEvaluation < DecisionType::RemoteAuthorization);
    }

    // -- Enrichment: error trait --

    #[test]
    fn ledger_error_is_std_error() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(LedgerError::MissingChosenAction),
            Box::new(LedgerError::SchemaValidationFailed {
                reason: "bad".to_string(),
            }),
            Box::new(LedgerError::DuplicateEntryId {
                entry_id: "e".to_string(),
            }),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn decision_type_serde_roundtrip() {
        for dt in [
            DecisionType::SecurityAction,
            DecisionType::PolicyUpdate,
            DecisionType::EpochTransition,
            DecisionType::Revocation,
            DecisionType::ExtensionLifecycle,
            DecisionType::CapabilityDecision,
            DecisionType::ContractEvaluation,
            DecisionType::RemoteAuthorization,
        ] {
            let json = serde_json::to_string(&dt).expect("serde serialization should succeed");
            let restored: DecisionType =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(dt, restored);
        }
    }

    #[test]
    fn constraint_serde_roundtrip() {
        let c = Constraint {
            constraint_id: "c-1".to_string(),
            description: "rate limit".to_string(),
            active: true,
        };
        let json = serde_json::to_string(&c).expect("serde serialization should succeed");
        let restored: Constraint =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(c, restored);
    }

    #[test]
    fn witness_serde_roundtrip() {
        let w = Witness {
            witness_id: "w-1".to_string(),
            witness_type: "monotonicity".to_string(),
            value: "proof-hash".to_string(),
        };
        let json = serde_json::to_string(&w).expect("serde serialization should succeed");
        let restored: Witness = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(w, restored);
    }

    #[test]
    fn chosen_action_serde_roundtrip() {
        let ca = ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 100_000,
            rationale: "lowest loss".to_string(),
        };
        let json = serde_json::to_string(&ca).expect("serde serialization should succeed");
        let restored: ChosenAction =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(ca, restored);
    }

    // -- Enrichment: default --

    #[test]
    fn in_memory_ledger_default_is_empty() {
        let ledger = InMemoryLedger::default();
        assert_eq!(ledger.len(), 0);
        assert!(ledger.is_empty());
    }

    // --- enrichment: builder edge cases ---

    #[test]
    fn builder_no_candidates_builds_ok() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "default".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");
        assert!(entry.candidates.is_empty());
        assert!(entry.constraints.is_empty());
        assert!(entry.witnesses.is_empty());
        assert!(entry.metadata.is_empty());
    }

    #[test]
    fn builder_timestamp_is_set() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::Revocation,
        )
        .timestamp_ns(42_000_000)
        .chosen(ChosenAction {
            action_name: "revoke".to_string(),
            expected_loss_millionths: 10_000,
            rationale: "expired".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");
        assert_eq!(entry.timestamp_ns, 42_000_000);
    }

    #[test]
    fn entry_id_format() {
        let entry = sample_entry();
        assert!(entry.entry_id.starts_with("ev-"));
        assert_eq!(entry.entry_id.len(), 3 + 32);
    }

    #[test]
    fn evidence_hash_is_sha256_hex() {
        let entry = sample_entry();
        // SHA-256 produces 64 hex characters.
        assert_eq!(entry.evidence_hash.len(), 64);
        assert!(entry.evidence_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn schema_version_ext_accessors() {
        let v = SchemaVersion::new(3, 7, 0);
        assert_eq!(v.major_val(), 3);
        assert_eq!(v.minor_val(), 7);
    }

    #[test]
    fn ledger_entries_accessor() {
        let mut ledger = InMemoryLedger::new();
        ledger
            .emit(sample_entry())
            .expect("serde serialization should succeed");
        assert_eq!(ledger.entries().len(), 1);
        assert_eq!(ledger.entries()[0].trace_id, "trace-001");
    }

    #[test]
    fn decision_type_display_all_eight() {
        let types = [
            DecisionType::SecurityAction,
            DecisionType::PolicyUpdate,
            DecisionType::EpochTransition,
            DecisionType::Revocation,
            DecisionType::ExtensionLifecycle,
            DecisionType::CapabilityDecision,
            DecisionType::ContractEvaluation,
            DecisionType::RemoteAuthorization,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for dt in &types {
            let s = dt.to_string();
            assert!(!s.is_empty());
            seen.insert(s);
        }
        assert_eq!(seen.len(), 8, "all 8 types have unique display strings");
    }

    #[test]
    fn different_decision_types_produce_different_hashes() {
        let e1 = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");

        let e2 = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::PolicyUpdate,
        )
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");

        assert_ne!(e1.evidence_hash, e2.evidence_hash);
        assert_ne!(e1.entry_id, e2.entry_id);
    }

    // -- Enrichment batch 2: additional coverage --

    #[test]
    fn candidate_negative_expected_loss_round_trips() {
        let c = CandidateAction::new("action", -999_999);
        assert_eq!(c.expected_loss_millionths, -999_999);
        let json = serde_json::to_string(&c).expect("serde serialization should succeed");
        let restored: CandidateAction =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(c, restored);
    }

    #[test]
    fn ledger_error_schema_validation_display() {
        let err = LedgerError::SchemaValidationFailed {
            reason: "missing field xyz".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("schema validation failed"));
        assert!(display.contains("missing field xyz"));
    }

    #[test]
    fn ledger_error_display_uniqueness() {
        let errors = [
            LedgerError::MissingChosenAction,
            LedgerError::SchemaValidationFailed {
                reason: "bad".to_string(),
            },
            LedgerError::IncompatibleSchema {
                entry_version: SchemaVersion::new(2, 0, 0),
                reader_version: current_schema_version(),
            },
            LedgerError::DuplicateEntryId {
                entry_id: "ev-x".to_string(),
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for e in &errors {
            displays.insert(e.to_string());
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 error variants have distinct display"
        );
    }

    #[test]
    fn deterministic_hash_empty_input() {
        let h1 = deterministic_hash("");
        let h2 = deterministic_hash("");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256
    }

    #[test]
    fn builder_multiple_metadata_keys_sorted() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .meta("z_key", "zval")
        .meta("a_key", "aval")
        .meta("m_key", "mval")
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");
        // BTreeMap keys should be in sorted order
        let keys: Vec<&String> = entry.metadata.keys().collect();
        assert_eq!(keys, vec!["a_key", "m_key", "z_key"]);
    }

    #[test]
    fn builder_multiple_witnesses_preserved_in_order() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .witness(Witness {
            witness_id: "w-2".to_string(),
            witness_type: "b".to_string(),
            value: "v2".to_string(),
        })
        .witness(Witness {
            witness_id: "w-1".to_string(),
            witness_type: "a".to_string(),
            value: "v1".to_string(),
        })
        .chosen(ChosenAction {
            action_name: "allow".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");
        assert_eq!(entry.witnesses.len(), 2);
        // Builder sorts witnesses by witness_id for determinism.
        assert_eq!(entry.witnesses[0].witness_id, "w-1");
        assert_eq!(entry.witnesses[1].witness_id, "w-2");
    }

    #[test]
    fn ledger_multiple_epochs_filter() {
        let mut ledger = InMemoryLedger::new();
        for epoch_raw in [1u64, 2, 3] {
            let entry = EvidenceEntryBuilder::new(
                format!("t-{epoch_raw}"),
                format!("d-{epoch_raw}"),
                "p",
                SecurityEpoch::from_raw(epoch_raw),
                DecisionType::SecurityAction,
            )
            .chosen(ChosenAction {
                action_name: "allow".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .expect("serde serialization should succeed");
            ledger
                .emit(entry)
                .expect("serde serialization should succeed");
        }
        assert_eq!(ledger.len(), 3);
        assert_eq!(ledger.by_epoch(SecurityEpoch::from_raw(2)).len(), 1);
        assert_eq!(ledger.by_epoch(SecurityEpoch::from_raw(99)).len(), 0);
    }

    #[test]
    fn ledger_multiple_decision_types_filter() {
        let mut ledger = InMemoryLedger::new();
        for (i, dt) in [
            DecisionType::SecurityAction,
            DecisionType::PolicyUpdate,
            DecisionType::PolicyUpdate,
            DecisionType::EpochTransition,
        ]
        .iter()
        .enumerate()
        {
            let entry = EvidenceEntryBuilder::new(
                format!("t-{i}"),
                format!("d-{i}"),
                "p",
                SecurityEpoch::from_raw(1),
                *dt,
            )
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .expect("serde serialization should succeed");
            ledger
                .emit(entry)
                .expect("serde serialization should succeed");
        }
        assert_eq!(ledger.by_decision_type(DecisionType::PolicyUpdate).len(), 2);
        assert_eq!(
            ledger.by_decision_type(DecisionType::EpochTransition).len(),
            1
        );
        assert_eq!(ledger.by_decision_type(DecisionType::Revocation).len(), 0);
    }

    #[test]
    fn schema_version_compatibility_same_major_higher_minor() {
        let v1_5 = SchemaVersion::new(1, 5, 0);
        let v1_3 = SchemaVersion::new(1, 3, 0);
        // v1.3 is compatible with reader v1.5
        assert!(v1_3.is_compatible_with(&v1_5));
        // v1.5 is NOT compatible with reader v1.3
        assert!(!v1_5.is_compatible_with(&v1_3));
    }

    // -- Enrichment batch 3: hash sensitivity and edge cases --

    #[test]
    fn hash_sensitive_to_trace_id_change() {
        let base = |trace: &str| {
            EvidenceEntryBuilder::new(
                trace,
                "d",
                "p",
                SecurityEpoch::from_raw(1),
                DecisionType::SecurityAction,
            )
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .expect("serde serialization should succeed")
        };
        let e1 = base("trace-A");
        let e2 = base("trace-B");
        assert_ne!(e1.evidence_hash, e2.evidence_hash);
    }

    #[test]
    fn hash_sensitive_to_policy_id_change() {
        let base = |policy: &str| {
            EvidenceEntryBuilder::new(
                "t",
                "d",
                policy,
                SecurityEpoch::from_raw(1),
                DecisionType::SecurityAction,
            )
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .expect("serde serialization should succeed")
        };
        assert_ne!(
            base("policy-v1").evidence_hash,
            base("policy-v2").evidence_hash
        );
    }

    #[test]
    fn hash_sensitive_to_epoch_change() {
        let base = |epoch: u64| {
            EvidenceEntryBuilder::new(
                "t",
                "d",
                "p",
                SecurityEpoch::from_raw(epoch),
                DecisionType::SecurityAction,
            )
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .expect("serde serialization should succeed")
        };
        assert_ne!(base(1).evidence_hash, base(2).evidence_hash);
    }

    #[test]
    fn hash_sensitive_to_timestamp_change() {
        let base = |ts: u64| {
            EvidenceEntryBuilder::new(
                "t",
                "d",
                "p",
                SecurityEpoch::from_raw(1),
                DecisionType::SecurityAction,
            )
            .timestamp_ns(ts)
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .expect("serde serialization should succeed")
        };
        assert_ne!(base(1000).evidence_hash, base(2000).evidence_hash);
    }

    #[test]
    fn hash_sensitive_to_metadata_change() {
        let base = |val: &str| {
            EvidenceEntryBuilder::new(
                "t",
                "d",
                "p",
                SecurityEpoch::from_raw(1),
                DecisionType::SecurityAction,
            )
            .meta("key", val)
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .expect("serde serialization should succeed")
        };
        assert_ne!(base("alpha").evidence_hash, base("beta").evidence_hash);
    }

    #[test]
    fn hash_sensitive_to_candidate_addition() {
        let without = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");

        let with = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .candidate(CandidateAction::new("extra", 50_000))
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");

        assert_ne!(without.evidence_hash, with.evidence_hash);
    }

    #[test]
    fn hash_sensitive_to_witness_addition() {
        let without = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");

        let with = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .witness(Witness {
            witness_id: "w".to_string(),
            witness_type: "t".to_string(),
            value: "v".to_string(),
        })
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");

        assert_ne!(without.evidence_hash, with.evidence_hash);
    }

    #[test]
    fn hash_sensitive_to_constraint_addition() {
        let without = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");

        let with = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .constraint(Constraint {
            constraint_id: "c".to_string(),
            description: "d".to_string(),
            active: true,
        })
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");

        assert_ne!(without.evidence_hash, with.evidence_hash);
    }

    #[test]
    fn genesis_epoch_entry_builds_ok() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::GENESIS,
            DecisionType::EpochTransition,
        )
        .chosen(ChosenAction {
            action_name: "transition".to_string(),
            expected_loss_millionths: 0,
            rationale: "genesis".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");
        assert_eq!(entry.epoch_id, SecurityEpoch::GENESIS);
    }

    #[test]
    fn entry_clone_preserves_all_fields() {
        let entry = sample_entry();
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
        assert_eq!(entry.entry_id, cloned.entry_id);
        assert_eq!(entry.evidence_hash, cloned.evidence_hash);
        assert_eq!(entry.metadata, cloned.metadata);
    }

    #[test]
    fn candidate_zero_expected_loss() {
        let c = CandidateAction::new("noop", 0);
        assert_eq!(c.expected_loss_millionths, 0);
        assert_eq!(c.action_name, "noop");
    }

    #[test]
    fn candidate_max_expected_loss() {
        let c = CandidateAction::new("extreme", i64::MAX);
        assert_eq!(c.expected_loss_millionths, i64::MAX);
    }

    #[test]
    fn witness_empty_value_round_trips() {
        let w = Witness {
            witness_id: "w-empty".to_string(),
            witness_type: "void".to_string(),
            value: String::new(),
        };
        let json = serde_json::to_string(&w).expect("serde serialization should succeed");
        let restored: Witness = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(w, restored);
        assert!(restored.value.is_empty());
    }

    #[test]
    fn constraint_inactive_round_trips() {
        let c = Constraint {
            constraint_id: "c-inactive".to_string(),
            description: "disabled rule".to_string(),
            active: false,
        };
        let json = serde_json::to_string(&c).expect("serde serialization should succeed");
        let restored: Constraint =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(c, restored);
        assert!(!restored.active);
    }

    #[test]
    fn multiple_filtered_candidates_different_reasons() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .candidate(CandidateAction::filtered("a", 100, "reason-1"))
        .candidate(CandidateAction::filtered("b", 200, "reason-2"))
        .candidate(CandidateAction::filtered("c", 300, "reason-3"))
        .chosen(ChosenAction {
            action_name: "d".to_string(),
            expected_loss_millionths: 0,
            rationale: "only option".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");
        assert_eq!(entry.candidates.len(), 3);
        assert!(entry.candidates.iter().all(|c| c.filtered));
        let reasons: Vec<_> = entry
            .candidates
            .iter()
            .map(|c| {
                c.filter_reason
                    .as_deref()
                    .expect("serde serialization should succeed")
            })
            .collect();
        assert_eq!(reasons, vec!["reason-1", "reason-2", "reason-3"]);
    }

    #[test]
    fn ledger_insertion_order_preserved() {
        let mut ledger = InMemoryLedger::new();
        let traces = ["trace-z", "trace-a", "trace-m"];
        for (i, trace) in traces.iter().enumerate() {
            let entry = EvidenceEntryBuilder::new(
                *trace,
                format!("d-{i}"),
                "p",
                SecurityEpoch::from_raw(1),
                DecisionType::SecurityAction,
            )
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .expect("serde serialization should succeed");
            ledger
                .emit(entry)
                .expect("serde serialization should succeed");
        }
        let stored_traces: Vec<&str> = ledger
            .entries()
            .iter()
            .map(|e| e.trace_id.as_str())
            .collect();
        assert_eq!(stored_traces, vec!["trace-z", "trace-a", "trace-m"]);
    }

    #[test]
    fn ledger_by_epoch_returns_correct_references() {
        let mut ledger = InMemoryLedger::new();
        let entry = EvidenceEntryBuilder::new(
            "t-ref",
            "d-ref",
            "p",
            SecurityEpoch::from_raw(42),
            DecisionType::Revocation,
        )
        .chosen(ChosenAction {
            action_name: "revoke".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");
        let expected_id = entry.entry_id.clone();
        ledger
            .emit(entry)
            .expect("serde serialization should succeed");

        let results = ledger.by_epoch(SecurityEpoch::from_raw(42));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].entry_id, expected_id);
        assert_eq!(results[0].trace_id, "t-ref");
    }

    #[test]
    fn empty_string_fields_produce_valid_entry() {
        let entry = EvidenceEntryBuilder::new(
            "",
            "",
            "",
            SecurityEpoch::from_raw(0),
            DecisionType::SecurityAction,
        )
        .chosen(ChosenAction {
            action_name: String::new(),
            expected_loss_millionths: 0,
            rationale: String::new(),
        })
        .build()
        .expect("serde serialization should succeed");
        assert!(entry.entry_id.starts_with("ev-"));
        assert!(!entry.evidence_hash.is_empty());
    }

    #[test]
    fn large_metadata_map_deterministic() {
        let build = || {
            let mut builder = EvidenceEntryBuilder::new(
                "t",
                "d",
                "p",
                SecurityEpoch::from_raw(1),
                DecisionType::SecurityAction,
            );
            for i in 0..50 {
                builder = builder.meta(format!("key-{i:03}"), format!("val-{i}"));
            }
            builder
                .chosen(ChosenAction {
                    action_name: "a".to_string(),
                    expected_loss_millionths: 0,
                    rationale: "r".to_string(),
                })
                .build()
                .expect("serde serialization should succeed")
        };
        let e1 = build();
        let e2 = build();
        assert_eq!(e1.evidence_hash, e2.evidence_hash);
        assert_eq!(e1.metadata.len(), 50);
    }

    #[test]
    fn decision_type_copy_semantics() {
        let dt = DecisionType::SecurityAction;
        let dt2 = dt;
        assert_eq!(dt, dt2);
    }

    #[test]
    fn decision_type_hash_consistency() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(DecisionType::SecurityAction);
        set.insert(DecisionType::SecurityAction);
        assert_eq!(set.len(), 1);
        set.insert(DecisionType::PolicyUpdate);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn ledger_many_entries_no_collisions() {
        let mut ledger = InMemoryLedger::new();
        for i in 0..100 {
            let entry = EvidenceEntryBuilder::new(
                format!("t-{i}"),
                format!("d-{i}"),
                "p",
                SecurityEpoch::from_raw(i),
                DecisionType::SecurityAction,
            )
            .timestamp_ns(i)
            .chosen(ChosenAction {
                action_name: format!("action-{i}"),
                expected_loss_millionths: i as i64,
                rationale: "r".to_string(),
            })
            .build()
            .expect("serde serialization should succeed");
            ledger
                .emit(entry)
                .expect("serde serialization should succeed");
        }
        assert_eq!(ledger.len(), 100);
    }

    #[test]
    fn entry_json_contains_all_top_level_fields() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).expect("serde serialization should succeed");
        for field in [
            "schema_version",
            "entry_id",
            "trace_id",
            "decision_id",
            "policy_id",
            "epoch_id",
            "timestamp_ns",
            "decision_type",
            "candidates",
            "constraints",
            "chosen_action",
            "witnesses",
            "evidence_hash",
            "metadata",
        ] {
            assert!(json.contains(field), "JSON missing field: {field}");
        }
    }

    #[test]
    fn chosen_action_negative_loss() {
        let ca = ChosenAction {
            action_name: "reward".to_string(),
            expected_loss_millionths: -500_000,
            rationale: "net gain".to_string(),
        };
        let json = serde_json::to_string(&ca).expect("serde serialization should succeed");
        let restored: ChosenAction =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(ca, restored);
        assert_eq!(restored.expected_loss_millionths, -500_000);
    }

    #[test]
    fn schema_version_patch_ignored_in_compatibility() {
        let v1_0_0 = SchemaVersion::new(1, 0, 0);
        let v1_0_5 = SchemaVersion::new(1, 0, 5);
        // Compatibility only checks major and minor, patch is irrelevant
        assert!(v1_0_0.is_compatible_with(&v1_0_5));
        assert!(v1_0_5.is_compatible_with(&v1_0_0));
    }

    #[test]
    fn builder_overwrites_metadata_key() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .meta("key", "first")
        .meta("key", "second")
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");
        assert_eq!(entry.metadata.len(), 1);
        assert_eq!(entry.metadata["key"], "second");
    }

    #[test]
    fn all_decision_types_produce_valid_entries() {
        let types = [
            DecisionType::SecurityAction,
            DecisionType::PolicyUpdate,
            DecisionType::EpochTransition,
            DecisionType::Revocation,
            DecisionType::ExtensionLifecycle,
            DecisionType::CapabilityDecision,
            DecisionType::ContractEvaluation,
            DecisionType::RemoteAuthorization,
        ];
        for (i, dt) in types.iter().enumerate() {
            let entry = EvidenceEntryBuilder::new(
                format!("t-{i}"),
                format!("d-{i}"),
                "p",
                SecurityEpoch::from_raw(1),
                *dt,
            )
            .chosen(ChosenAction {
                action_name: "a".to_string(),
                expected_loss_millionths: 0,
                rationale: "r".to_string(),
            })
            .build()
            .expect("serde serialization should succeed");
            assert!(entry.entry_id.starts_with("ev-"));
            assert_eq!(entry.decision_type, *dt);
        }
    }

    #[test]
    fn ledger_duplicate_error_contains_entry_id() {
        let mut ledger = InMemoryLedger::new();
        let entry = sample_entry();
        let entry_id = entry.entry_id.clone();
        ledger
            .emit(entry.clone())
            .expect("serde serialization should succeed");

        let err = ledger.emit(entry).unwrap_err();
        match err {
            LedgerError::DuplicateEntryId { entry_id: eid } => {
                assert_eq!(eid, entry_id);
            }
            other => panic!("expected DuplicateEntryId, got: {other:?}"),
        }
    }

    #[test]
    fn deterministic_hash_long_input() {
        let long_input: String = "x".repeat(10_000);
        let h1 = deterministic_hash(&long_input);
        let h2 = deterministic_hash(&long_input);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256
    }

    #[test]
    fn deterministic_hash_single_byte_difference() {
        let h1 = deterministic_hash("abc");
        let h2 = deterministic_hash("abd");
        assert_ne!(h1, h2);
    }

    #[test]
    fn mixed_active_inactive_constraints() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .constraint(Constraint {
            constraint_id: "c-active".to_string(),
            description: "blocks action".to_string(),
            active: true,
        })
        .constraint(Constraint {
            constraint_id: "c-passive".to_string(),
            description: "monitored only".to_string(),
            active: false,
        })
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 0,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");
        assert_eq!(entry.constraints.len(), 2);
        assert!(entry.constraints[0].active);
        assert!(!entry.constraints[1].active);
    }

    #[test]
    fn candidate_order_preserved_in_entry() {
        let entry = EvidenceEntryBuilder::new(
            "t",
            "d",
            "p",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        )
        .candidate(CandidateAction::new("c", 300))
        .candidate(CandidateAction::new("a", 100))
        .candidate(CandidateAction::new("b", 200))
        .chosen(ChosenAction {
            action_name: "a".to_string(),
            expected_loss_millionths: 100,
            rationale: "r".to_string(),
        })
        .build()
        .expect("serde serialization should succeed");
        let names: Vec<&str> = entry
            .candidates
            .iter()
            .map(|c| c.action_name.as_str())
            .collect();
        // Builder sorts candidates by action_name for determinism.
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn ledger_by_decision_type_empty_result() {
        let ledger = InMemoryLedger::new();
        assert!(
            ledger
                .by_decision_type(DecisionType::SecurityAction)
                .is_empty()
        );
    }

    #[test]
    fn ledger_by_epoch_empty_result() {
        let ledger = InMemoryLedger::new();
        assert!(ledger.by_epoch(SecurityEpoch::from_raw(1)).is_empty());
    }

    #[test]
    fn stitching_bundle_links_boundaries_decision_and_artifacts() {
        let entry = sample_entry();
        let boundaries = sample_boundary_records();
        let artifacts = vec![
            ArtifactRecord::new(
                "release-gate",
                "release_gate_report",
                "artifacts/release-gate.json",
                "hash-release-gate",
            ),
            ArtifactRecord::new(
                "support-export",
                "support_bundle",
                "artifacts/support-export.json",
                "hash-support-export",
            )
            .supporting_boundary(boundaries[0].correlation_key.clone()),
        ];
        let annotations = DecisionSemanticsAnnotations {
            confidence_tier: Some("high".to_string()),
            fallback_reason: Some("safe_mode_guard".to_string()),
            regret_summary: Some("bounded_regret<=1000".to_string()),
            scope_limits: vec!["extension_id=ext-abc".to_string()],
            assumptions: BTreeMap::from([("policy_snapshot".to_string(), "signed".to_string())]),
            linked_boundary_correlation_keys: boundaries
                .iter()
                .map(|boundary| boundary.correlation_key.clone())
                .collect(),
        };

        let bundle =
            EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &artifacts, annotations)
                .expect("stitching bundle");

        assert_eq!(bundle.evidence_ledger_graph.nodes.len(), 5);
        assert_eq!(
            bundle
                .evidence_ledger_graph
                .edges
                .iter()
                .filter(|edge| edge.edge_kind == EvidenceGraphEdgeKind::BoundaryInformsDecision)
                .count(),
            2
        );
        assert_eq!(
            bundle
                .evidence_ledger_graph
                .edges
                .iter()
                .filter(|edge| edge.edge_kind == EvidenceGraphEdgeKind::DecisionProducesArtifact)
                .count(),
            2
        );
        assert_eq!(
            bundle
                .evidence_ledger_graph
                .edges
                .iter()
                .filter(|edge| edge.edge_kind == EvidenceGraphEdgeKind::BoundarySupportsArtifact)
                .count(),
            3
        );
        assert_eq!(bundle.decision_semantics_log.len(), 1);
        assert_eq!(
            bundle.decision_semantics_log[0].confidence_tier.as_deref(),
            Some("high")
        );
        assert_eq!(
            bundle.decision_semantics_log[0]
                .boundary_correlation_keys
                .len(),
            2
        );
        let query = bundle
            .evidence_query_surface_snapshot
            .by_decision("decision-001")
            .expect("decision query record");
        assert_eq!(query.artifact_ids, vec!["release-gate", "support-export"]);
        assert_eq!(query.boundary_correlation_keys.len(), 2);
        assert_eq!(query.fallback_reason.as_deref(), Some("safe_mode_guard"));
    }

    #[test]
    fn stitching_bundle_is_deterministic_for_same_inputs() {
        let entry = sample_entry();
        let boundaries = sample_boundary_records();
        let artifacts = vec![ArtifactRecord::new(
            "benchmark-proof",
            "benchmark_manifest",
            "artifacts/benchmark-proof.json",
            "hash-benchmark-proof",
        )];
        let annotations = DecisionSemanticsAnnotations {
            confidence_tier: Some("medium".to_string()),
            ..DecisionSemanticsAnnotations::default()
        };

        let left = EvidenceLedgerStitchingBundle::stitch(
            &entry,
            &boundaries,
            &artifacts,
            annotations.clone(),
        )
        .expect("left bundle");
        let right =
            EvidenceLedgerStitchingBundle::stitch(&entry, &boundaries, &artifacts, annotations)
                .expect("right bundle");

        assert_eq!(left, right);
    }

    #[test]
    fn stitching_bundle_rejects_missing_boundary_link() {
        let entry = sample_entry();
        let boundaries = sample_boundary_records();
        let err = EvidenceLedgerStitchingBundle::stitch(
            &entry,
            &boundaries,
            &[],
            DecisionSemanticsAnnotations {
                linked_boundary_correlation_keys: vec!["bcorr_missing".to_string()],
                ..DecisionSemanticsAnnotations::default()
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            LedgerError::SchemaValidationFailed {
                reason:
                    "decision semantics references missing boundary correlation key: bcorr_missing"
                        .to_string(),
            }
        );
    }

    #[test]
    fn stitching_bundle_rejects_boundary_from_other_decision() {
        let entry = sample_entry();
        let mut session = BoundaryCaptureSession::default_v1();
        let mismatched_context = BoundaryContext::new(
            "trace-other",
            "decision-other",
            "policy-v1",
            "orchestrator",
            10,
        );
        let mismatched = session
            .capture_clock_read(&mismatched_context, "mono", "monotonic", 99, None)
            .expect("capture clock read");

        let err = EvidenceLedgerStitchingBundle::stitch(
            &entry,
            &[mismatched],
            &[],
            DecisionSemanticsAnnotations::default(),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            LedgerError::SchemaValidationFailed { reason }
            if reason.contains("does not match decision identity")
        ));
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "franken-engine-evidence-ledger-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn emit_default_stitching_bundle_writes_required_artifacts() {
        let artifact_dir = temp_dir("bundle");
        let mut context = StitchingArtifactContext::new(&artifact_dir);
        context.run_id = "run-rgc-811b-test".to_string();
        context.trace_id = "trace-rgc-811b-test".to_string();
        context.decision_id = "decision-rgc-811b-test".to_string();
        context.policy_id = "policy-rgc-811b-test".to_string();
        context.generated_at_utc = "2026-03-07T00:00:00Z".to_string();
        context.source_commit = "deadbeef".to_string();
        context.toolchain = "nightly".to_string();
        context.command_invocation = format!(
            "cargo run -p frankenengine-engine --bin franken_evidence_ledger_stitching -- --artifact-dir {}",
            artifact_dir.display()
        );

        let bundle = emit_default_stitching_bundle(&context).expect("bundle should write");

        for artifact in required_artifact_names() {
            assert!(
                artifact_dir.join(&artifact).exists(),
                "expected artifact `{artifact}` to exist",
            );
        }

        let run_manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
        )
        .expect("parse run manifest");
        assert_eq!(
            run_manifest["schema_version"].as_str(),
            Some(EVIDENCE_LEDGER_STITCHING_RUN_MANIFEST_SCHEMA_VERSION)
        );
        assert_eq!(bundle.bundle.artifact_lineage_index.len(), 3);
        assert_eq!(
            bundle.bundle.evidence_query_surface_snapshot.decisions[0]
                .artifact_ids
                .len(),
            3
        );

        let _ = std::fs::remove_dir_all(&artifact_dir);
    }

    #[test]
    fn docs_contract_fixture_matches_checked_in_json() {
        let expected = build_docs_contract_fixture();
        let docs_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/rgc_evidence_ledger_stitching_v1.json");
        let actual: DocsContractFixture =
            serde_json::from_slice(&std::fs::read(&docs_path).expect("read docs fixture"))
                .expect("fixture should parse");

        assert_eq!(actual.schema_version, DOCS_CONTRACT_SCHEMA_VERSION);
        assert_eq!(actual, expected);
    }

    // PERF-H1.3 tests for an explicitly owned, prepared runtime authority.

    fn perf_runtime_authority() -> RuntimeEvidenceAuthority {
        RuntimeEvidenceAuthority::from_signing_key(
            "perf-h1-runtime",
            SigningKey::from_bytes([0x61; 32]).expect("non-zero perf key"),
            SecurityEpoch::from_raw(1),
            1,
            None,
        )
        .expect("perf runtime authority")
    }

    #[test]
    fn runtime_authority_clone_preserves_signing_key() {
        let authority = perf_runtime_authority();
        let cloned = authority.clone();
        let a = &authority.0.signing_key;
        let b = &cloned.0.signing_key;
        assert_eq!(
            a.as_bytes(),
            b.as_bytes(),
            "cloning one explicit runtime authority must retain its signing identity"
        );
    }

    #[test]
    fn cached_runtime_key_matches_explicit_expansion() {
        let authority = perf_runtime_authority();
        let cached = &authority.0.signing_key;
        let eager =
            SigningKey::from_bytes(*cached.as_bytes()).expect("runtime key bytes are non-zero");
        assert_eq!(
            cached.as_bytes(),
            eager.as_bytes(),
            "cached runtime key must survive explicit expansion"
        );
        assert_eq!(
            cached.verification_key().as_bytes(),
            eager.verification_key().as_bytes(),
            "derived VerifyingKey must also match"
        );
    }

    #[test]
    fn signature_byte_equal_with_cached_runtime_key() {
        let payload = b"frankenengine-h1-perf-pass-fixed-payload";
        let authority = perf_runtime_authority();
        let identity = authority.signing_identity();
        let cached_sig = identity.sign_preimage(payload);
        let eager_sig = sign_preimage(&identity.signing_key, payload).expect("sign must succeed");
        assert_eq!(
            cached_sig.to_bytes(),
            eager_sig.to_bytes(),
            "signatures must be byte-equal; Ed25519 is deterministic given same key and payload"
        );
    }

    #[test]
    fn prepared_runtime_authority_safe_under_concurrent_clones() {
        use std::sync::{Arc, Barrier};
        use std::thread;
        const N: usize = 32;
        let barrier = Arc::new(Barrier::new(N));
        let authority = perf_runtime_authority();
        let mut handles = Vec::with_capacity(N);
        for _ in 0..N {
            let b = barrier.clone();
            let thread_authority = authority.clone();
            handles.push(thread::spawn(move || {
                b.wait();
                *thread_authority.0.signing_key.as_bytes()
            }));
        }
        let mut bytes_set = std::collections::BTreeSet::new();
        for h in handles {
            bytes_set.insert(h.join().expect("thread must not panic"));
        }
        assert_eq!(
            bytes_set.len(),
            1,
            "all threads must observe the same SigningKey bytes"
        );
    }

    #[test]
    fn evidence_entry_uses_registered_runtime_provenance() {
        let authority = perf_runtime_authority();
        let entry = EvidenceEntryBuilder::new_with_runtime_authority(
            "trace-h1",
            "decision-h1",
            "policy-h1",
            SecurityEpoch::from_raw(1),
            DecisionType::ContractEvaluation,
            &authority,
        )
        .timestamp_ns(1_700_000_000_000_000_001)
        .candidate(CandidateAction::new("do-nothing", 0))
        .chosen(ChosenAction {
            action_name: "do-nothing".into(),
            expected_loss_millionths: 0,
            rationale: "h1 fixed entry".into(),
        })
        .build()
        .expect("entry must build");

        let envelope = entry.signed_envelope();
        assert_eq!(envelope.producer_id, authority.producer_id());
        assert_eq!(&envelope.key_provenance, authority.key_provenance());
        assert_eq!(envelope.signed_epoch, entry.epoch_id);

        let mut ledger =
            InMemoryLedger::for_runtime_authority(entry.epoch_id, &authority).expect("ledger");
        ledger.emit(entry).expect("runtime entry must verify");
    }

    #[test]
    fn bd_90u6o_detached_signature_binds_public_provenance() {
        let identity = EvidenceSigningIdentity::from_signing_key(
            "runtime-detached",
            SigningKey::from_bytes([0x31; 32]).expect("non-zero key"),
            SecurityEpoch::from_raw(4),
            2,
            Some("ed25519:predecessor".to_string()),
        )
        .expect("identity");
        let payload = b"detached evidence payload";
        let envelope = identity
            .sign_detached(payload, SecurityEpoch::from_raw(5))
            .expect("signature");
        let trusted_identity = identity.verification_identity();
        envelope
            .verify_detached(payload, &trusted_identity)
            .expect("valid signature");

        let mut producer_tamper = envelope.clone();
        producer_tamper.producer_id = "forged-runtime".to_string();
        assert!(
            producer_tamper
                .verify_detached(payload, &trusted_identity)
                .is_err(),
            "producer identity must be signature-bound"
        );

        let mut epoch_tamper = envelope.clone();
        epoch_tamper.signed_epoch = SecurityEpoch::from_raw(6);
        assert!(
            epoch_tamper
                .verify_detached(payload, &trusted_identity)
                .is_err(),
            "signed epoch must be signature-bound"
        );

        let source_known_identity = EvidenceSigningIdentity::from_signing_key(
            identity.producer_id(),
            SigningKey::from_bytes([0x7B; 32]).expect("historical source-known seed"),
            SecurityEpoch::from_raw(4),
            1,
            None,
        )
        .expect("attacker-controlled identity");
        let source_known_forgery = source_known_identity
            .sign_detached(payload, SecurityEpoch::from_raw(5))
            .expect("attacker can self-sign an internally valid envelope");
        assert!(
            source_known_forgery
                .verify_detached(payload, &trusted_identity)
                .is_err(),
            "a claimant-supplied source-known key must not authenticate as the trusted runtime"
        );
    }
}
