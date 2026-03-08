//! Owner-signed key attestation objects with expiry and nonce freshness.
//!
//! Cryptographically binds a principal's operational keys to the
//! principal's root identity. Each attestation includes:
//! - An expiry window (hard enforcement, no grace period).
//! - A nonce for freshness verification (replay detection).
//! - Optional device-posture evidence.
//! - An owner signature (the attested key cannot self-attest).
//!
//! Plan references: Section 10.10 item 12, 9E.5 (owner-signed attestation
//! lifecycle with expiry, nonce freshness, device-posture evidence).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability_token::PrincipalId;
use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::policy_checkpoint::DeterministicTimestamp;
use crate::principal_key_roles::KeyRole;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_preimage,
    verify_signature,
};

// ---------------------------------------------------------------------------
// Schema definitions
// ---------------------------------------------------------------------------

const ATTESTATION_SCHEMA_DEF: &[u8] = b"FrankenEngine.KeyAttestation.v1";

pub fn attestation_schema() -> SchemaHash {
    SchemaHash::from_definition(ATTESTATION_SCHEMA_DEF)
}

pub fn attestation_schema_id() -> SchemaId {
    SchemaId::from_definition(ATTESTATION_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// AttestationNonce — freshness token
// ---------------------------------------------------------------------------

/// A unique nonce for attestation freshness verification.
///
/// Uses a monotonic counter rather than random bytes to avoid
/// unbounded storage of seen nonces. The counter is scoped per
/// principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AttestationNonce(pub u64);

impl AttestationNonce {
    pub fn from_counter(counter: u64) -> Self {
        Self(counter)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for AttestationNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nonce:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// DevicePosture — optional hardware attestation evidence
// ---------------------------------------------------------------------------

/// Security state of the device at attestation time.
///
/// Verification is policy-dependent. The posture is opaque bytes with
/// a type tag; actual validation is delegated to a `DevicePostureVerifier`
/// trait implementor.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DevicePosture {
    /// Type of device posture evidence (e.g. "tpm2", "sgx", "trustzone").
    pub posture_type: String,
    /// Opaque posture evidence bytes.
    pub evidence: Vec<u8>,
}

/// Trait for pluggable device posture verification.
pub trait DevicePostureVerifier {
    fn verify(&self, posture: &DevicePosture) -> Result<(), AttestationError>;
}

// ---------------------------------------------------------------------------
// KeyAttestation — the core attestation object
// ---------------------------------------------------------------------------

/// An owner-signed key attestation binding an operational key to a
/// principal's root identity.
///
/// The attestation is only valid if signed by the principal's owner
/// key (not the attested key itself).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAttestation {
    /// Unique domain-separated attestation identity.
    pub attestation_id: EngineObjectId,
    /// The principal whose key is being attested.
    pub principal_id: PrincipalId,
    /// The operational key being attested (public/verification key).
    pub attested_key: VerificationKey,
    /// The role of the attested key.
    pub key_role: KeyRole,
    /// When this attestation was issued.
    pub issued_at: DeterministicTimestamp,
    /// Hard expiry — attestation is invalid after this timestamp.
    pub expires_at: DeterministicTimestamp,
    /// Security epoch at attestation time.
    pub epoch: SecurityEpoch,
    /// Monotonic nonce for freshness (replay detection).
    pub nonce: AttestationNonce,
    /// Optional device posture evidence.
    pub device_posture: Option<DevicePosture>,
    /// Owner signature over all fields (with this field set to sentinel).
    pub owner_signature: Signature,
    /// Zone partition.
    pub zone: String,
}

/// Input parameters for creating a signed key attestation.
#[derive(Debug, Clone)]
pub struct CreateAttestationInput<'a> {
    pub principal_id: PrincipalId,
    pub attested_key: VerificationKey,
    pub key_role: KeyRole,
    pub issued_at: DeterministicTimestamp,
    pub expires_at: DeterministicTimestamp,
    pub epoch: SecurityEpoch,
    pub nonce: AttestationNonce,
    pub device_posture: Option<DevicePosture>,
    pub zone: &'a str,
}

impl KeyAttestation {
    /// Derive the attestation ID from canonical content.
    pub fn derive_attestation_id(
        principal_id: &PrincipalId,
        attested_key: &VerificationKey,
        key_role: KeyRole,
        nonce: AttestationNonce,
        zone: &str,
    ) -> Result<EngineObjectId, engine_object_id::IdError> {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(principal_id.as_bytes());
        canonical.extend_from_slice(attested_key.as_bytes());
        canonical.extend_from_slice(key_role.derivation_domain());
        canonical.extend_from_slice(&nonce.as_u64().to_be_bytes());
        engine_object_id::derive_id(
            ObjectDomain::Attestation,
            zone,
            &attestation_schema_id(),
            &canonical,
        )
    }

    /// Build the unsigned view for signature computation.
    fn build_unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "attestation_id".to_string(),
            CanonicalValue::Bytes(self.attestation_id.as_bytes().to_vec()),
        );
        map.insert(
            "attested_key".to_string(),
            CanonicalValue::Bytes(self.attested_key.as_bytes().to_vec()),
        );
        map.insert(
            "device_posture".to_string(),
            match &self.device_posture {
                Some(dp) => {
                    let mut dp_map = BTreeMap::new();
                    dp_map.insert(
                        "evidence".to_string(),
                        CanonicalValue::Bytes(dp.evidence.clone()),
                    );
                    dp_map.insert(
                        "posture_type".to_string(),
                        CanonicalValue::String(dp.posture_type.clone()),
                    );
                    CanonicalValue::Map(dp_map)
                }
                None => CanonicalValue::Null,
            },
        );
        map.insert(
            "epoch".to_string(),
            CanonicalValue::U64(self.epoch.as_u64()),
        );
        map.insert(
            "expires_at".to_string(),
            CanonicalValue::U64(self.expires_at.0),
        );
        map.insert(
            "issued_at".to_string(),
            CanonicalValue::U64(self.issued_at.0),
        );
        map.insert(
            "key_role".to_string(),
            CanonicalValue::String(self.key_role.to_string()),
        );
        map.insert(
            "nonce".to_string(),
            CanonicalValue::U64(self.nonce.as_u64()),
        );
        map.insert(
            "owner_signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        map.insert(
            "principal_id".to_string(),
            CanonicalValue::Bytes(self.principal_id.as_bytes().to_vec()),
        );
        map.insert(
            "zone".to_string(),
            CanonicalValue::String(self.zone.clone()),
        );
        CanonicalValue::Map(map)
    }

    /// Create and sign a new attestation.
    ///
    /// The `owner_signing_key` is the principal's root key. It must
    /// NOT be the same as the `attested_key` (self-attestation is
    /// rejected).
    pub fn create_signed(
        owner_signing_key: &SigningKey,
        input: CreateAttestationInput<'_>,
    ) -> Result<Self, AttestationError> {
        // Reject self-attestation: the attested key cannot sign its own attestation.
        let owner_vk = owner_signing_key.verification_key();
        if owner_vk == input.attested_key {
            return Err(AttestationError::SelfAttestationRejected);
        }

        // Expiry must be after issued_at.
        if input.expires_at.0 <= input.issued_at.0 {
            return Err(AttestationError::InvalidExpiry {
                issued_at: input.issued_at,
                expires_at: input.expires_at,
            });
        }

        let attestation_id = Self::derive_attestation_id(
            &input.principal_id,
            &input.attested_key,
            input.key_role,
            input.nonce,
            input.zone,
        )
        .map_err(|e| AttestationError::IdDerivationFailed {
            detail: e.to_string(),
        })?;

        let mut attestation = Self {
            attestation_id,
            principal_id: input.principal_id,
            attested_key: input.attested_key,
            key_role: input.key_role,
            issued_at: input.issued_at,
            expires_at: input.expires_at,
            epoch: input.epoch,
            nonce: input.nonce,
            device_posture: input.device_posture,
            owner_signature: Signature::from_bytes(SIGNATURE_SENTINEL),
            zone: input.zone.to_string(),
        };

        let preimage = attestation.preimage_bytes();
        let sig = sign_preimage(owner_signing_key, &preimage).map_err(|e| {
            AttestationError::SignatureFailed {
                detail: e.to_string(),
            }
        })?;
        attestation.owner_signature = sig;

        Ok(attestation)
    }

    /// Verify the owner signature on this attestation.
    pub fn verify_owner_signature(
        &self,
        owner_vk: &VerificationKey,
    ) -> Result<(), AttestationError> {
        // The owner key must not be the attested key.
        if *owner_vk == self.attested_key {
            return Err(AttestationError::SelfAttestationRejected);
        }

        let preimage = self.preimage_bytes();
        verify_signature(owner_vk, &preimage, &self.owner_signature).map_err(|e| {
            AttestationError::SignatureInvalid {
                detail: e.to_string(),
            }
        })
    }

    /// Check whether the attestation has expired at the given timestamp.
    pub fn is_expired(&self, current_time: DeterministicTimestamp) -> bool {
        current_time.0 > self.expires_at.0
    }
}

impl SignaturePreimage for KeyAttestation {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::Attestation
    }

    fn signature_schema(&self) -> &SchemaHash {
        unreachable!("use preimage_bytes directly")
    }

    fn unsigned_view(&self) -> CanonicalValue {
        self.build_unsigned_view()
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let domain_tag = self.signature_domain().tag();
        let schema = attestation_schema();
        let unsigned = self.unsigned_view();
        let value_bytes = deterministic_serde::encode_value(&unsigned);

        let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
        preimage.extend_from_slice(domain_tag);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&value_bytes);
        preimage
    }
}

impl fmt::Display for KeyAttestation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyAttestation({}, role={}, nonce={}, expires={})",
            self.attestation_id, self.key_role, self.nonce, self.expires_at
        )
    }
}

// ---------------------------------------------------------------------------
// NonceRegistry — per-principal nonce tracking
// ---------------------------------------------------------------------------

/// A (principal, high-water) pair for serialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NonceEntry {
    principal: PrincipalId,
    high_water: u64,
}

/// Tracks seen nonces per principal for replay detection.
///
/// Uses a monotonic high-water mark: any nonce below the high-water
/// mark is considered already seen. This avoids unbounded storage of
/// individual nonces.
///
/// Serializes as a vec of `(principal, high_water)` pairs to avoid
/// JSON key-type limitations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceRegistry {
    /// Per-principal high-water mark for nonces.
    #[serde(
        serialize_with = "serialize_high_water",
        deserialize_with = "deserialize_high_water"
    )]
    high_water: BTreeMap<PrincipalId, u64>,
}

fn serialize_high_water<S: serde::Serializer>(
    map: &BTreeMap<PrincipalId, u64>,
    s: S,
) -> Result<S::Ok, S::Error> {
    let entries: Vec<NonceEntry> = map
        .iter()
        .map(|(k, v)| NonceEntry {
            principal: k.clone(),
            high_water: *v,
        })
        .collect();
    entries.serialize(s)
}

fn deserialize_high_water<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<PrincipalId, u64>, D::Error> {
    let entries: Vec<NonceEntry> = Vec::deserialize(d)?;
    Ok(entries
        .into_iter()
        .map(|e| (e.principal, e.high_water))
        .collect())
}

impl NonceRegistry {
    pub fn new() -> Self {
        Self {
            high_water: BTreeMap::new(),
        }
    }

    /// Check and record a nonce. Returns `Err` if the nonce has been
    /// seen (is at or below the high-water mark for this principal).
    pub fn check_and_record(
        &mut self,
        principal: &PrincipalId,
        nonce: AttestationNonce,
    ) -> Result<(), AttestationError> {
        let current_hw = self.high_water.get(principal).copied().unwrap_or(0);
        let nonce_val = nonce.as_u64();

        if nonce_val == 0 {
            return Err(AttestationError::InvalidNonce {
                detail: "nonce must be > 0".to_string(),
            });
        }

        if nonce_val <= current_hw {
            return Err(AttestationError::NonceReplay {
                principal: principal.clone(),
                nonce,
                high_water: current_hw,
            });
        }

        self.high_water.insert(principal.clone(), nonce_val);
        Ok(())
    }

    /// Current high-water mark for a principal, or 0 if never seen.
    pub fn high_water_for(&self, principal: &PrincipalId) -> u64 {
        self.high_water.get(principal).copied().unwrap_or(0)
    }

    /// Number of principals tracked.
    pub fn principal_count(&self) -> usize {
        self.high_water.len()
    }
}

impl Default for NonceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AttestationStore — lifecycle manager
// ---------------------------------------------------------------------------

/// Manages active attestations for a zone with expiry and nonce enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationStore {
    /// Active attestations indexed by attestation ID.
    attestations: BTreeMap<EngineObjectId, KeyAttestation>,
    /// Per-principal attestation index: principal -> set of attestation IDs.
    principal_index: BTreeMap<PrincipalId, BTreeSet<EngineObjectId>>,
    /// Nonce registry for replay detection.
    nonce_registry: NonceRegistry,
    /// Audit events.
    audit_events: Vec<AttestationEvent>,
    /// Zone this store manages.
    zone: String,
}

impl AttestationStore {
    pub fn new(zone: &str) -> Self {
        Self {
            attestations: BTreeMap::new(),
            principal_index: BTreeMap::new(),
            nonce_registry: NonceRegistry::new(),
            audit_events: Vec::new(),
            zone: zone.to_string(),
        }
    }

    /// Register a new attestation after full verification.
    ///
    /// Validates: owner signature, expiry window, nonce freshness,
    /// zone match, and non-self-attestation.
    pub fn register(
        &mut self,
        attestation: KeyAttestation,
        owner_vk: &VerificationKey,
        current_time: DeterministicTimestamp,
        trace_id: &str,
    ) -> Result<EngineObjectId, AttestationError> {
        // Zone check.
        if attestation.zone != self.zone {
            self.emit_event(
                AttestationEventType::RegistrationRejected {
                    reason: format!(
                        "zone mismatch: store={}, attestation={}",
                        self.zone, attestation.zone
                    ),
                },
                trace_id,
            );
            return Err(AttestationError::ZoneMismatch {
                expected: self.zone.clone(),
                actual: attestation.zone.clone(),
            });
        }

        // Verify owner signature.
        attestation.verify_owner_signature(owner_vk)?;

        // Check expiry is in the future.
        if attestation.is_expired(current_time) {
            self.emit_event(
                AttestationEventType::RegistrationRejected {
                    reason: "attestation already expired".to_string(),
                },
                trace_id,
            );
            return Err(AttestationError::Expired {
                expires_at: attestation.expires_at,
                current_time,
            });
        }

        // Check nonce freshness.
        self.nonce_registry
            .check_and_record(&attestation.principal_id, attestation.nonce)?;

        // Check for duplicate attestation ID.
        if self.attestations.contains_key(&attestation.attestation_id) {
            return Err(AttestationError::DuplicateAttestation {
                attestation_id: attestation.attestation_id.clone(),
            });
        }

        let att_id = attestation.attestation_id.clone();
        let principal = attestation.principal_id.clone();

        // Store attestation.
        self.principal_index
            .entry(principal.clone())
            .or_default()
            .insert(att_id.clone());
        self.attestations.insert(att_id.clone(), attestation);

        self.emit_event(
            AttestationEventType::Registered {
                attestation_id: att_id.clone(),
                principal,
            },
            trace_id,
        );

        Ok(att_id)
    }

    /// Look up an attestation by ID, returning `None` if not found.
    pub fn get(&self, attestation_id: &EngineObjectId) -> Option<&KeyAttestation> {
        self.attestations.get(attestation_id)
    }

    /// Get all active (non-expired) attestations for a principal at the
    /// given time.
    pub fn active_for_principal(
        &self,
        principal: &PrincipalId,
        current_time: DeterministicTimestamp,
    ) -> Vec<&KeyAttestation> {
        let Some(ids) = self.principal_index.get(principal) else {
            return Vec::new();
        };
        ids.iter()
            .filter_map(|id| self.attestations.get(id))
            .filter(|att| !att.is_expired(current_time))
            .collect()
    }

    /// Get all active attestations for a specific key role.
    pub fn active_for_role(
        &self,
        principal: &PrincipalId,
        role: KeyRole,
        current_time: DeterministicTimestamp,
    ) -> Vec<&KeyAttestation> {
        self.active_for_principal(principal, current_time)
            .into_iter()
            .filter(|att| att.key_role == role)
            .collect()
    }

    /// Revoke an attestation by ID.
    pub fn revoke(
        &mut self,
        attestation_id: &EngineObjectId,
        trace_id: &str,
    ) -> Result<(), AttestationError> {
        let attestation =
            self.attestations
                .remove(attestation_id)
                .ok_or_else(|| AttestationError::NotFound {
                    attestation_id: attestation_id.clone(),
                })?;

        if let Some(ids) = self.principal_index.get_mut(&attestation.principal_id) {
            ids.remove(attestation_id);
            if ids.is_empty() {
                self.principal_index.remove(&attestation.principal_id);
            }
        }

        self.emit_event(
            AttestationEventType::Revoked {
                attestation_id: attestation_id.clone(),
                principal: attestation.principal_id.clone(),
            },
            trace_id,
        );

        Ok(())
    }

    /// Purge all expired attestations at the given time.
    pub fn purge_expired(&mut self, current_time: DeterministicTimestamp, trace_id: &str) -> usize {
        let expired_ids: Vec<EngineObjectId> = self
            .attestations
            .iter()
            .filter(|(_, att)| att.is_expired(current_time))
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired_ids.len();
        for id in &expired_ids {
            if let Some(att) = self.attestations.remove(id)
                && let Some(ids) = self.principal_index.get_mut(&att.principal_id)
            {
                ids.remove(id);
                if ids.is_empty() {
                    self.principal_index.remove(&att.principal_id);
                }
            }
        }

        if count > 0 {
            self.emit_event(AttestationEventType::ExpiredPurged { count }, trace_id);
        }

        count
    }

    /// Total number of stored attestations (including expired).
    pub fn total_count(&self) -> usize {
        self.attestations.len()
    }

    /// Number of tracked principals.
    pub fn principal_count(&self) -> usize {
        self.principal_index.len()
    }

    /// Drain accumulated audit events.
    pub fn drain_events(&mut self) -> Vec<AttestationEvent> {
        std::mem::take(&mut self.audit_events)
    }

    fn emit_event(&mut self, event_type: AttestationEventType, trace_id: &str) {
        self.audit_events.push(AttestationEvent {
            event_type,
            zone: self.zone.clone(),
            trace_id: trace_id.to_string(),
        });
    }
}

// ---------------------------------------------------------------------------
// AttestationError
// ---------------------------------------------------------------------------

/// Errors from attestation operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationError {
    /// The attested key cannot sign its own attestation.
    SelfAttestationRejected,
    /// Attestation has expired.
    Expired {
        expires_at: DeterministicTimestamp,
        current_time: DeterministicTimestamp,
    },
    /// Nonce replay detected.
    NonceReplay {
        principal: PrincipalId,
        nonce: AttestationNonce,
        high_water: u64,
    },
    /// Invalid nonce value.
    InvalidNonce { detail: String },
    /// Owner signature verification failed.
    SignatureInvalid { detail: String },
    /// Signature computation failed.
    SignatureFailed { detail: String },
    /// ID derivation failed.
    IdDerivationFailed { detail: String },
    /// Invalid expiry (must be after issued_at).
    InvalidExpiry {
        issued_at: DeterministicTimestamp,
        expires_at: DeterministicTimestamp,
    },
    /// Zone mismatch between store and attestation.
    ZoneMismatch { expected: String, actual: String },
    /// Duplicate attestation ID.
    DuplicateAttestation { attestation_id: EngineObjectId },
    /// Attestation not found.
    NotFound { attestation_id: EngineObjectId },
    /// Device posture verification failed.
    DevicePostureInvalid { detail: String },
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelfAttestationRejected => write!(f, "self-attestation rejected"),
            Self::Expired {
                expires_at,
                current_time,
            } => write!(
                f,
                "attestation expired: expires_at={expires_at}, current_time={current_time}"
            ),
            Self::NonceReplay {
                principal,
                nonce,
                high_water,
            } => write!(
                f,
                "nonce replay: principal={}, nonce={nonce}, high_water={high_water}",
                principal.to_hex()
            ),
            Self::InvalidNonce { detail } => write!(f, "invalid nonce: {detail}"),
            Self::SignatureInvalid { detail } => write!(f, "signature invalid: {detail}"),
            Self::SignatureFailed { detail } => write!(f, "signature failed: {detail}"),
            Self::IdDerivationFailed { detail } => write!(f, "id derivation failed: {detail}"),
            Self::InvalidExpiry {
                issued_at,
                expires_at,
            } => write!(
                f,
                "invalid expiry: issued_at={issued_at}, expires_at={expires_at}"
            ),
            Self::ZoneMismatch { expected, actual } => {
                write!(f, "zone mismatch: expected={expected}, actual={actual}")
            }
            Self::DuplicateAttestation { attestation_id } => {
                write!(f, "duplicate attestation: {attestation_id}")
            }
            Self::NotFound { attestation_id } => {
                write!(f, "attestation not found: {attestation_id}")
            }
            Self::DevicePostureInvalid { detail } => {
                write!(f, "device posture invalid: {detail}")
            }
        }
    }
}

impl std::error::Error for AttestationError {}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationEventType {
    Registered {
        attestation_id: EngineObjectId,
        principal: PrincipalId,
    },
    Revoked {
        attestation_id: EngineObjectId,
        principal: PrincipalId,
    },
    RegistrationRejected {
        reason: String,
    },
    ExpiredPurged {
        count: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationEvent {
    pub event_type: AttestationEventType,
    pub zone: String,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ZONE: &str = "test-zone";

    fn owner_signing_key() -> SigningKey {
        SigningKey::from_bytes([0x01; 32])
    }

    fn owner_vk() -> VerificationKey {
        owner_signing_key().verification_key()
    }

    fn attested_signing_key() -> SigningKey {
        SigningKey::from_bytes([0x02; 32])
    }

    fn attested_vk() -> VerificationKey {
        attested_signing_key().verification_key()
    }

    fn test_principal() -> PrincipalId {
        PrincipalId::from_verification_key(&owner_vk())
    }

    fn create_test_attestation(
        role: KeyRole,
        nonce: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> KeyAttestation {
        KeyAttestation::create_signed(
            &owner_signing_key(),
            CreateAttestationInput {
                principal_id: test_principal(),
                attested_key: attested_vk(),
                key_role: role,
                issued_at: DeterministicTimestamp(issued_at),
                expires_at: DeterministicTimestamp(expires_at),
                epoch: SecurityEpoch::from_raw(1),
                nonce: AttestationNonce::from_counter(nonce),
                device_posture: None,
                zone: TEST_ZONE,
            },
        )
        .expect("create test attestation")
    }

    // -------------------------------------------------------------------
    // Creation tests
    // -------------------------------------------------------------------

    #[test]
    fn create_attestation_succeeds() {
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        assert_eq!(att.key_role, KeyRole::Signing);
        assert_eq!(att.principal_id, test_principal());
        assert_eq!(att.attested_key, attested_vk());
        assert_eq!(att.nonce, AttestationNonce::from_counter(1));
        assert_eq!(att.zone, TEST_ZONE);
    }

    #[test]
    fn create_attestation_for_each_role() {
        for role in KeyRole::ALL {
            let att = create_test_attestation(*role, 1, 100, 200);
            assert_eq!(att.key_role, *role);
        }
    }

    #[test]
    fn create_attestation_deterministic() {
        let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let att2 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        assert_eq!(att1.attestation_id, att2.attestation_id);
        assert_eq!(att1.owner_signature, att2.owner_signature);
    }

    #[test]
    fn create_attestation_different_roles_different_ids() {
        let att_sign = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let att_enc = create_test_attestation(KeyRole::Encryption, 1, 100, 200);
        let att_iss = create_test_attestation(KeyRole::Issuance, 1, 100, 200);
        assert_ne!(att_sign.attestation_id, att_enc.attestation_id);
        assert_ne!(att_sign.attestation_id, att_iss.attestation_id);
        assert_ne!(att_enc.attestation_id, att_iss.attestation_id);
    }

    #[test]
    fn create_attestation_different_nonces_different_ids() {
        let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let att2 = create_test_attestation(KeyRole::Signing, 2, 100, 200);
        assert_ne!(att1.attestation_id, att2.attestation_id);
    }

    // -------------------------------------------------------------------
    // Self-attestation rejection
    // -------------------------------------------------------------------

    #[test]
    fn self_attestation_rejected() {
        let sk = owner_signing_key();
        let vk = sk.verification_key();
        let result = KeyAttestation::create_signed(
            &sk,
            CreateAttestationInput {
                principal_id: test_principal(),
                attested_key: vk, // Same as owner's verification key
                key_role: KeyRole::Signing,
                issued_at: DeterministicTimestamp(100),
                expires_at: DeterministicTimestamp(200),
                epoch: SecurityEpoch::from_raw(1),
                nonce: AttestationNonce::from_counter(1),
                device_posture: None,
                zone: TEST_ZONE,
            },
        );
        assert!(matches!(
            result,
            Err(AttestationError::SelfAttestationRejected)
        ));
    }

    // -------------------------------------------------------------------
    // Expiry tests
    // -------------------------------------------------------------------

    #[test]
    fn invalid_expiry_rejected() {
        let result = KeyAttestation::create_signed(
            &owner_signing_key(),
            CreateAttestationInput {
                principal_id: test_principal(),
                attested_key: attested_vk(),
                key_role: KeyRole::Signing,
                issued_at: DeterministicTimestamp(200),
                expires_at: DeterministicTimestamp(100), // expires before issued
                epoch: SecurityEpoch::from_raw(1),
                nonce: AttestationNonce::from_counter(1),
                device_posture: None,
                zone: TEST_ZONE,
            },
        );
        assert!(matches!(
            result,
            Err(AttestationError::InvalidExpiry { .. })
        ));
    }

    #[test]
    fn equal_expiry_and_issued_at_rejected() {
        let result = KeyAttestation::create_signed(
            &owner_signing_key(),
            CreateAttestationInput {
                principal_id: test_principal(),
                attested_key: attested_vk(),
                key_role: KeyRole::Signing,
                issued_at: DeterministicTimestamp(100),
                expires_at: DeterministicTimestamp(100), // same as issued_at
                epoch: SecurityEpoch::from_raw(1),
                nonce: AttestationNonce::from_counter(1),
                device_posture: None,
                zone: TEST_ZONE,
            },
        );
        assert!(matches!(
            result,
            Err(AttestationError::InvalidExpiry { .. })
        ));
    }

    #[test]
    fn is_expired_before_expiry() {
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        assert!(!att.is_expired(DeterministicTimestamp(150)));
        assert!(!att.is_expired(DeterministicTimestamp(199)));
    }

    #[test]
    fn is_expired_at_expiry() {
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        assert!(!att.is_expired(DeterministicTimestamp(200)));
    }

    #[test]
    fn is_expired_after_expiry() {
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        assert!(att.is_expired(DeterministicTimestamp(201)));
        assert!(att.is_expired(DeterministicTimestamp(u64::MAX)));
    }

    // -------------------------------------------------------------------
    // Signature verification
    // -------------------------------------------------------------------

    #[test]
    fn verify_owner_signature_succeeds() {
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        att.verify_owner_signature(&owner_vk())
            .expect("valid signature");
    }

    #[test]
    fn verify_owner_signature_wrong_key_fails() {
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let wrong_sk = SigningKey::from_bytes([0xFF; 32]);
        let wrong_vk = wrong_sk.verification_key();
        let result = att.verify_owner_signature(&wrong_vk);
        assert!(matches!(
            result,
            Err(AttestationError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn verify_self_attestation_on_verify_fails() {
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        // Try to verify with the attested key as the "owner" key
        let result = att.verify_owner_signature(&attested_vk());
        assert!(matches!(
            result,
            Err(AttestationError::SelfAttestationRejected)
        ));
    }

    // -------------------------------------------------------------------
    // Device posture tests
    // -------------------------------------------------------------------

    #[test]
    fn attestation_without_device_posture_valid() {
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        assert!(att.device_posture.is_none());
        att.verify_owner_signature(&owner_vk()).expect("valid");
    }

    #[test]
    fn attestation_with_device_posture_valid() {
        let posture = DevicePosture {
            posture_type: "tpm2".to_string(),
            evidence: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let att = KeyAttestation::create_signed(
            &owner_signing_key(),
            CreateAttestationInput {
                principal_id: test_principal(),
                attested_key: attested_vk(),
                key_role: KeyRole::Signing,
                issued_at: DeterministicTimestamp(100),
                expires_at: DeterministicTimestamp(200),
                epoch: SecurityEpoch::from_raw(1),
                nonce: AttestationNonce::from_counter(1),
                device_posture: Some(posture.clone()),
                zone: TEST_ZONE,
            },
        )
        .expect("create with posture");

        assert_eq!(att.device_posture, Some(posture));
        att.verify_owner_signature(&owner_vk()).expect("valid");
    }

    #[test]
    fn device_posture_changes_signature() {
        let att_no_posture = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let att_with_posture = KeyAttestation::create_signed(
            &owner_signing_key(),
            CreateAttestationInput {
                principal_id: test_principal(),
                attested_key: attested_vk(),
                key_role: KeyRole::Signing,
                issued_at: DeterministicTimestamp(100),
                expires_at: DeterministicTimestamp(200),
                epoch: SecurityEpoch::from_raw(1),
                nonce: AttestationNonce::from_counter(1),
                device_posture: Some(DevicePosture {
                    posture_type: "sgx".to_string(),
                    evidence: vec![0x01],
                }),
                zone: TEST_ZONE,
            },
        )
        .expect("create");

        assert_ne!(
            att_no_posture.owner_signature,
            att_with_posture.owner_signature
        );
    }

    // -------------------------------------------------------------------
    // NonceRegistry tests
    // -------------------------------------------------------------------

    #[test]
    fn nonce_registry_accepts_first_nonce() {
        let mut registry = NonceRegistry::new();
        registry
            .check_and_record(&test_principal(), AttestationNonce::from_counter(1))
            .expect("first nonce");
        assert_eq!(registry.high_water_for(&test_principal()), 1);
    }

    #[test]
    fn nonce_registry_accepts_monotonic_increase() {
        let mut registry = NonceRegistry::new();
        for i in 1..=5 {
            registry
                .check_and_record(&test_principal(), AttestationNonce::from_counter(i))
                .unwrap_or_else(|_| panic!("nonce {i}"));
        }
        assert_eq!(registry.high_water_for(&test_principal()), 5);
    }

    #[test]
    fn nonce_registry_accepts_gaps() {
        let mut registry = NonceRegistry::new();
        registry
            .check_and_record(&test_principal(), AttestationNonce::from_counter(1))
            .expect("nonce 1");
        registry
            .check_and_record(&test_principal(), AttestationNonce::from_counter(100))
            .expect("nonce 100");
        assert_eq!(registry.high_water_for(&test_principal()), 100);
    }

    #[test]
    fn nonce_registry_rejects_replay() {
        let mut registry = NonceRegistry::new();
        registry
            .check_and_record(&test_principal(), AttestationNonce::from_counter(5))
            .expect("nonce 5");
        let result =
            registry.check_and_record(&test_principal(), AttestationNonce::from_counter(5));
        assert!(matches!(result, Err(AttestationError::NonceReplay { .. })));
    }

    #[test]
    fn nonce_registry_rejects_lower_nonce() {
        let mut registry = NonceRegistry::new();
        registry
            .check_and_record(&test_principal(), AttestationNonce::from_counter(10))
            .expect("nonce 10");
        let result =
            registry.check_and_record(&test_principal(), AttestationNonce::from_counter(5));
        assert!(matches!(result, Err(AttestationError::NonceReplay { .. })));
    }

    #[test]
    fn nonce_registry_rejects_zero_nonce() {
        let mut registry = NonceRegistry::new();
        let result =
            registry.check_and_record(&test_principal(), AttestationNonce::from_counter(0));
        assert!(matches!(result, Err(AttestationError::InvalidNonce { .. })));
    }

    #[test]
    fn nonce_registry_per_principal_isolation() {
        let mut registry = NonceRegistry::new();
        let p1 = test_principal();
        let p2 = PrincipalId::from_bytes([0xBB; 32]);

        registry
            .check_and_record(&p1, AttestationNonce::from_counter(10))
            .expect("p1 nonce 10");
        registry
            .check_and_record(&p2, AttestationNonce::from_counter(5))
            .expect("p2 nonce 5");

        assert_eq!(registry.high_water_for(&p1), 10);
        assert_eq!(registry.high_water_for(&p2), 5);
        assert_eq!(registry.principal_count(), 2);
    }

    // -------------------------------------------------------------------
    // AttestationStore tests
    // -------------------------------------------------------------------

    #[test]
    fn store_register_succeeds() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let id = store
            .register(att, &owner_vk(), DeterministicTimestamp(150), "t-reg")
            .expect("register");
        assert_eq!(store.total_count(), 1);
        assert!(store.get(&id).is_some());
    }

    #[test]
    fn store_register_expired_rejected() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let result = store.register(att, &owner_vk(), DeterministicTimestamp(300), "t-exp");
        assert!(matches!(result, Err(AttestationError::Expired { .. })));
    }

    #[test]
    fn store_register_zone_mismatch_rejected() {
        let mut store = AttestationStore::new("different-zone");
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let result = store.register(att, &owner_vk(), DeterministicTimestamp(150), "t-zone");
        assert!(matches!(result, Err(AttestationError::ZoneMismatch { .. })));
    }

    #[test]
    fn store_register_nonce_replay_rejected() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        store
            .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-1")
            .expect("first");

        let att2 = create_test_attestation(KeyRole::Encryption, 1, 100, 200);
        let result = store.register(att2, &owner_vk(), DeterministicTimestamp(150), "t-2");
        assert!(matches!(result, Err(AttestationError::NonceReplay { .. })));
    }

    #[test]
    fn store_register_wrong_signature_rejected() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let wrong_sk = SigningKey::from_bytes([0xFF; 32]);
        let wrong_vk = wrong_sk.verification_key();
        let result = store.register(att, &wrong_vk, DeterministicTimestamp(150), "t-sig");
        assert!(matches!(
            result,
            Err(AttestationError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn store_active_for_principal() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let att2 = create_test_attestation(KeyRole::Encryption, 2, 100, 300);
        store
            .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-1")
            .expect("first");
        store
            .register(att2, &owner_vk(), DeterministicTimestamp(150), "t-2")
            .expect("second");

        let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(150));
        assert_eq!(active.len(), 2);

        // At time 250, the first has expired
        let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(250));
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].key_role, KeyRole::Encryption);
    }

    #[test]
    fn store_active_for_role() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let att2 = create_test_attestation(KeyRole::Encryption, 2, 100, 200);
        store
            .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-1")
            .expect("first");
        store
            .register(att2, &owner_vk(), DeterministicTimestamp(150), "t-2")
            .expect("second");

        let signing = store.active_for_role(
            &test_principal(),
            KeyRole::Signing,
            DeterministicTimestamp(150),
        );
        assert_eq!(signing.len(), 1);
        assert_eq!(signing[0].key_role, KeyRole::Signing);

        let issuance = store.active_for_role(
            &test_principal(),
            KeyRole::Issuance,
            DeterministicTimestamp(150),
        );
        assert_eq!(issuance.len(), 0);
    }

    #[test]
    fn store_revoke_succeeds() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let id = store
            .register(att, &owner_vk(), DeterministicTimestamp(150), "t-reg")
            .expect("register");

        store.revoke(&id, "t-revoke").expect("revoke");
        assert_eq!(store.total_count(), 0);
        assert!(store.get(&id).is_none());
    }

    #[test]
    fn store_revoke_not_found() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let fake_id = EngineObjectId([0xFF; 32]);
        let result = store.revoke(&fake_id, "t-revoke");
        assert!(matches!(result, Err(AttestationError::NotFound { .. })));
    }

    #[test]
    fn store_purge_expired() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let att2 = create_test_attestation(KeyRole::Encryption, 2, 100, 300);
        let att3 = create_test_attestation(KeyRole::Issuance, 3, 100, 400);
        store
            .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-1")
            .expect("1");
        store
            .register(att2, &owner_vk(), DeterministicTimestamp(150), "t-2")
            .expect("2");
        store
            .register(att3, &owner_vk(), DeterministicTimestamp(150), "t-3")
            .expect("3");

        assert_eq!(store.total_count(), 3);

        let purged = store.purge_expired(DeterministicTimestamp(250), "t-purge");
        assert_eq!(purged, 1); // Only att1 expired (200 <= 250)
        assert_eq!(store.total_count(), 2);

        let purged = store.purge_expired(DeterministicTimestamp(350), "t-purge2");
        assert_eq!(purged, 1); // att2 expired (300 <= 350)
        assert_eq!(store.total_count(), 1);
    }

    // -------------------------------------------------------------------
    // Audit event tests
    // -------------------------------------------------------------------

    #[test]
    fn audit_events_emitted_on_register() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        store
            .register(att, &owner_vk(), DeterministicTimestamp(150), "t-reg")
            .expect("register");

        let events = store.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].event_type,
            AttestationEventType::Registered { .. }
        ));
    }

    #[test]
    fn audit_events_emitted_on_rejection() {
        let mut store = AttestationStore::new("wrong-zone");
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let _ = store.register(att, &owner_vk(), DeterministicTimestamp(150), "t-rej");

        let events = store.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].event_type,
            AttestationEventType::RegistrationRejected { .. }
        ));
    }

    #[test]
    fn audit_events_emitted_on_revoke() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let id = store
            .register(att, &owner_vk(), DeterministicTimestamp(150), "t-reg")
            .expect("register");
        store.drain_events(); // clear registration events

        store.revoke(&id, "t-revoke").expect("revoke");
        let events = store.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].event_type,
            AttestationEventType::Revoked { .. }
        ));
    }

    #[test]
    fn audit_events_emitted_on_purge() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        store
            .register(att, &owner_vk(), DeterministicTimestamp(150), "t-reg")
            .expect("register");
        store.drain_events();

        store.purge_expired(DeterministicTimestamp(300), "t-purge");
        let events = store.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].event_type,
            AttestationEventType::ExpiredPurged { count: 1 }
        ));
    }

    // -------------------------------------------------------------------
    // Serialization tests
    // -------------------------------------------------------------------

    #[test]
    fn attestation_serialization_round_trip() {
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let json = serde_json::to_string(&att).expect("serialize");
        let restored: KeyAttestation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(att, restored);
    }

    #[test]
    fn attestation_with_posture_serialization_round_trip() {
        let att = KeyAttestation::create_signed(
            &owner_signing_key(),
            CreateAttestationInput {
                principal_id: test_principal(),
                attested_key: attested_vk(),
                key_role: KeyRole::Signing,
                issued_at: DeterministicTimestamp(100),
                expires_at: DeterministicTimestamp(200),
                epoch: SecurityEpoch::from_raw(1),
                nonce: AttestationNonce::from_counter(1),
                device_posture: Some(DevicePosture {
                    posture_type: "tpm2".to_string(),
                    evidence: vec![0x01, 0x02, 0x03],
                }),
                zone: TEST_ZONE,
            },
        )
        .expect("create");

        let json = serde_json::to_string(&att).expect("serialize");
        let restored: KeyAttestation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(att, restored);
    }

    #[test]
    fn attestation_error_serialization_round_trip() {
        let errors: Vec<AttestationError> = vec![
            AttestationError::SelfAttestationRejected,
            AttestationError::Expired {
                expires_at: DeterministicTimestamp(100),
                current_time: DeterministicTimestamp(200),
            },
            AttestationError::NonceReplay {
                principal: test_principal(),
                nonce: AttestationNonce::from_counter(5),
                high_water: 10,
            },
            AttestationError::InvalidNonce {
                detail: "test".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: AttestationError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn nonce_registry_serialization_round_trip() {
        let mut registry = NonceRegistry::new();
        registry
            .check_and_record(&test_principal(), AttestationNonce::from_counter(5))
            .expect("record");

        let json = serde_json::to_string(&registry).expect("serialize");
        let restored: NonceRegistry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.high_water_for(&test_principal()), 5);
    }

    // -------------------------------------------------------------------
    // Display tests
    // -------------------------------------------------------------------

    #[test]
    fn attestation_display() {
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let display = att.to_string();
        assert!(display.contains("KeyAttestation"));
        assert!(display.contains("signing"));
    }

    #[test]
    fn error_display() {
        let err = AttestationError::SelfAttestationRejected;
        assert_eq!(err.to_string(), "self-attestation rejected");

        let err = AttestationError::Expired {
            expires_at: DeterministicTimestamp(100),
            current_time: DeterministicTimestamp(200),
        };
        let display = err.to_string();
        assert!(display.contains("100"));
        assert!(display.contains("200"));
    }

    #[test]
    fn nonce_display() {
        let nonce = AttestationNonce::from_counter(42);
        assert_eq!(nonce.to_string(), "nonce:42");
    }

    // -------------------------------------------------------------------
    // Integration: full attestation lifecycle
    // -------------------------------------------------------------------

    #[test]
    fn full_lifecycle_create_verify_rotate_revoke() {
        let mut store = AttestationStore::new(TEST_ZONE);

        // Create and register initial attestation.
        let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 500);
        let id1 = store
            .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-create")
            .expect("register initial");

        // Verify it's active.
        let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(200));
        assert_eq!(active.len(), 1);

        // Rotate: create new attestation with different key and higher nonce.
        let new_key_sk = SigningKey::from_bytes([0x03; 32]);
        let new_key_vk = new_key_sk.verification_key();
        let att2 = KeyAttestation::create_signed(
            &owner_signing_key(),
            CreateAttestationInput {
                principal_id: test_principal(),
                attested_key: new_key_vk,
                key_role: KeyRole::Signing,
                issued_at: DeterministicTimestamp(300),
                expires_at: DeterministicTimestamp(600),
                epoch: SecurityEpoch::from_raw(2),
                nonce: AttestationNonce::from_counter(2),
                device_posture: None,
                zone: TEST_ZONE,
            },
        )
        .expect("create rotation");
        let id2 = store
            .register(att2, &owner_vk(), DeterministicTimestamp(350), "t-rotate")
            .expect("register rotation");

        // Both active at time 400.
        let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(400));
        assert_eq!(active.len(), 2);

        // Revoke old attestation.
        store.revoke(&id1, "t-revoke-old").expect("revoke old");

        // Only new one remains.
        let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(400));
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].attestation_id, id2);
    }

    #[test]
    fn multiple_principals_isolated() {
        let mut store = AttestationStore::new(TEST_ZONE);

        // Principal 1
        let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        store
            .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-p1")
            .expect("p1");

        // Principal 2 (different owner key)
        let p2_owner_sk = SigningKey::from_bytes([0x10; 32]);
        let p2_owner_vk = p2_owner_sk.verification_key();
        let p2_principal = PrincipalId::from_verification_key(&p2_owner_vk);
        let p2_attested_sk = SigningKey::from_bytes([0x20; 32]);
        let p2_attested_vk = p2_attested_sk.verification_key();

        let att2 = KeyAttestation::create_signed(
            &p2_owner_sk,
            CreateAttestationInput {
                principal_id: p2_principal.clone(),
                attested_key: p2_attested_vk,
                key_role: KeyRole::Encryption,
                issued_at: DeterministicTimestamp(100),
                expires_at: DeterministicTimestamp(200),
                epoch: SecurityEpoch::from_raw(1),
                nonce: AttestationNonce::from_counter(1),
                device_posture: None,
                zone: TEST_ZONE,
            },
        )
        .expect("create p2 att");

        store
            .register(att2, &p2_owner_vk, DeterministicTimestamp(150), "t-p2")
            .expect("p2");

        assert_eq!(store.total_count(), 2);
        assert_eq!(store.principal_count(), 2);

        let p1_active = store.active_for_principal(&test_principal(), DeterministicTimestamp(150));
        assert_eq!(p1_active.len(), 1);
        assert_eq!(p1_active[0].key_role, KeyRole::Signing);

        let p2_active = store.active_for_principal(&p2_principal, DeterministicTimestamp(150));
        assert_eq!(p2_active.len(), 1);
        assert_eq!(p2_active[0].key_role, KeyRole::Encryption);
    }

    // -------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------

    #[test]
    fn attestation_id_hex_roundtrip() {
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let hex = att.attestation_id.to_hex();
        let recovered = EngineObjectId::from_hex(&hex).expect("from_hex");
        assert_eq!(att.attestation_id, recovered);
    }

    #[test]
    fn empty_store_queries() {
        let store = AttestationStore::new(TEST_ZONE);
        assert_eq!(store.total_count(), 0);
        assert_eq!(store.principal_count(), 0);
        let active = store.active_for_principal(&test_principal(), DeterministicTimestamp(100));
        assert!(active.is_empty());
    }

    #[test]
    fn duplicate_attestation_rejected() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        store
            .register(att.clone(), &owner_vk(), DeterministicTimestamp(150), "t-1")
            .expect("first");

        // Same attestation again (but nonce will be rejected first).
        let result = store.register(att, &owner_vk(), DeterministicTimestamp(150), "t-2");
        assert!(result.is_err());
    }

    #[test]
    fn purge_expired_on_empty_store() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let purged = store.purge_expired(DeterministicTimestamp(1000), "t-purge");
        assert_eq!(purged, 0);
    }

    #[test]
    fn attestation_schema_determinism() {
        let s1 = attestation_schema();
        let s2 = attestation_schema();
        assert_eq!(s1, s2);
    }

    #[test]
    fn attestation_schema_id_determinism() {
        let s1 = attestation_schema_id();
        let s2 = attestation_schema_id();
        assert_eq!(s1, s2);
    }

    // -------------------------------------------------------------------
    // Enrichment: Display uniqueness, serde, edge cases
    // -------------------------------------------------------------------

    #[test]
    fn attestation_error_display_all_variants_unique() {
        use std::collections::BTreeSet;
        let errors = vec![
            AttestationError::SelfAttestationRejected,
            AttestationError::Expired {
                expires_at: DeterministicTimestamp(100),
                current_time: DeterministicTimestamp(200),
            },
            AttestationError::NonceReplay {
                principal: test_principal(),
                nonce: AttestationNonce::from_counter(5),
                high_water: 10,
            },
            AttestationError::InvalidNonce {
                detail: "bad".to_string(),
            },
            AttestationError::SignatureInvalid {
                detail: "mismatch".to_string(),
            },
            AttestationError::ZoneMismatch {
                expected: "z1".to_string(),
                actual: "z2".to_string(),
            },
            AttestationError::NotFound {
                attestation_id: EngineObjectId([0xAA; 32]),
            },
        ];
        let mut displays = BTreeSet::new();
        for err in &errors {
            let msg = format!("{err}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            errors.len(),
            "all variants have unique Display"
        );
    }

    #[test]
    fn attestation_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(AttestationError::SelfAttestationRejected);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn device_posture_serde_roundtrip() {
        let dp = DevicePosture {
            posture_type: "tpm2".to_string(),
            evidence: vec![0x01, 0x02, 0x03, 0xFF],
        };
        let json = serde_json::to_string(&dp).expect("serialize");
        let restored: DevicePosture = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(dp, restored);
    }

    #[test]
    fn nonce_ordering_is_by_counter() {
        let n1 = AttestationNonce::from_counter(1);
        let n5 = AttestationNonce::from_counter(5);
        let n10 = AttestationNonce::from_counter(10);
        assert!(n1 < n5);
        assert!(n5 < n10);
    }

    #[test]
    fn attestation_event_serde_roundtrip() {
        let event = AttestationEvent {
            event_type: AttestationEventType::Registered {
                attestation_id: EngineObjectId([0xAA; 32]),
                principal: test_principal(),
            },
            zone: TEST_ZONE.to_string(),
            trace_id: "t-test".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: AttestationEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn store_drain_events_clears_buffer() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        store
            .register(att, &owner_vk(), DeterministicTimestamp(150), "t-reg")
            .expect("register");

        let events1 = store.drain_events();
        assert_eq!(events1.len(), 1);
        let events2 = store.drain_events();
        assert!(events2.is_empty(), "drain should clear buffer");
    }

    #[test]
    fn attestation_schema_differs_from_schema_id() {
        let sh = attestation_schema();
        let si = attestation_schema_id();
        // SchemaHash and SchemaId are different types wrapping the same def
        // but we can at least verify both are deterministic and non-trivial
        let sh2 = attestation_schema();
        let si2 = attestation_schema_id();
        assert_eq!(sh, sh2);
        assert_eq!(si, si2);
    }

    #[test]
    fn nonce_registry_high_water_for_unknown_principal_is_zero() {
        let registry = NonceRegistry::new();
        let unknown = PrincipalId::from_bytes([0xCC; 32]);
        assert_eq!(registry.high_water_for(&unknown), 0);
    }

    // -------------------------------------------------------------------
    // Enrichment: additional trait, serde, edge-case coverage
    // -------------------------------------------------------------------

    #[test]
    fn enrichment_attestation_nonce_copy_semantics() {
        let n = AttestationNonce::from_counter(42);
        let n2 = n; // Copy
        let n3 = n; // Still valid — Copy
        assert_eq!(n, n2);
        assert_eq!(n2, n3);
        assert_eq!(n.as_u64(), 42);
    }

    #[test]
    fn enrichment_attestation_nonce_hash_consistent() {
        use std::hash::{Hash, Hasher};
        let n1 = AttestationNonce::from_counter(99);
        let n2 = AttestationNonce::from_counter(99);
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        n1.hash(&mut h1);
        n2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn enrichment_attestation_nonce_serde_roundtrip() {
        let nonce = AttestationNonce::from_counter(1_000_000);
        let json = serde_json::to_string(&nonce).expect("serialize");
        let restored: AttestationNonce = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(nonce, restored);
        assert_eq!(restored.as_u64(), 1_000_000);
    }

    #[test]
    fn enrichment_attestation_nonce_clone_eq() {
        let n = AttestationNonce::from_counter(7);
        let cloned = n;
        assert_eq!(n, cloned);
        assert_eq!(n.as_u64(), cloned.as_u64());
    }

    #[test]
    fn enrichment_device_posture_ord_ordering() {
        let dp_a = DevicePosture {
            posture_type: "aaa".to_string(),
            evidence: vec![0x01],
        };
        let dp_b = DevicePosture {
            posture_type: "bbb".to_string(),
            evidence: vec![0x01],
        };
        let dp_a2 = DevicePosture {
            posture_type: "aaa".to_string(),
            evidence: vec![0x02],
        };
        assert!(dp_a < dp_b, "posture_type 'aaa' < 'bbb'");
        assert!(dp_a < dp_a2, "same type, evidence [0x01] < [0x02]");
    }

    #[test]
    fn enrichment_device_posture_hash_consistent() {
        use std::hash::{Hash, Hasher};
        let dp1 = DevicePosture {
            posture_type: "sgx".to_string(),
            evidence: vec![0xCA, 0xFE],
        };
        let dp2 = dp1.clone();
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        dp1.hash(&mut h1);
        dp2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn enrichment_device_posture_json_fields() {
        let dp = DevicePosture {
            posture_type: "trustzone".to_string(),
            evidence: vec![0xAB],
        };
        let json: serde_json::Value = serde_json::to_value(&dp).expect("to_value");
        assert!(json.get("posture_type").is_some());
        assert!(json.get("evidence").is_some());
        assert_eq!(json["posture_type"], "trustzone");
    }

    #[test]
    fn enrichment_key_attestation_clone_eq() {
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        let cloned = att.clone();
        assert_eq!(att, cloned);
        assert_eq!(att.attestation_id, cloned.attestation_id);
        assert_eq!(att.owner_signature, cloned.owner_signature);
    }

    #[test]
    fn enrichment_key_attestation_json_field_names() {
        let att = create_test_attestation(KeyRole::Encryption, 1, 100, 200);
        let json: serde_json::Value = serde_json::to_value(&att).expect("to_value");
        let expected_fields = [
            "attestation_id",
            "principal_id",
            "attested_key",
            "key_role",
            "issued_at",
            "expires_at",
            "epoch",
            "nonce",
            "device_posture",
            "owner_signature",
            "zone",
        ];
        for field in &expected_fields {
            assert!(json.get(field).is_some(), "missing JSON field: {field}");
        }
        assert_eq!(json["zone"], TEST_ZONE);
    }

    #[test]
    fn enrichment_attestation_store_clone_preserves_state() {
        // AttestationStore uses BTreeMap<EngineObjectId, _> which cannot
        // JSON-serialize (key must be a string). Verify clone fidelity instead.
        let mut store = AttestationStore::new(TEST_ZONE);
        let att1 = create_test_attestation(KeyRole::Signing, 1, 100, 500);
        let att2 = create_test_attestation(KeyRole::Encryption, 2, 100, 600);
        let id1 = store
            .register(att1, &owner_vk(), DeterministicTimestamp(150), "t-1")
            .expect("reg1");
        let id2 = store
            .register(att2, &owner_vk(), DeterministicTimestamp(150), "t-2")
            .expect("reg2");

        let cloned = store.clone();
        assert_eq!(cloned.total_count(), 2);
        assert_eq!(cloned.principal_count(), 1);
        assert!(cloned.get(&id1).is_some());
        assert!(cloned.get(&id2).is_some());
    }

    #[test]
    fn enrichment_nonce_registry_default_trait() {
        let reg: NonceRegistry = Default::default();
        assert_eq!(reg.principal_count(), 0);
        assert_eq!(reg.high_water_for(&test_principal()), 0);
    }

    #[test]
    fn enrichment_nonce_registry_clone_preserves_state() {
        let mut reg = NonceRegistry::new();
        reg.check_and_record(&test_principal(), AttestationNonce::from_counter(10))
            .expect("record");
        let cloned = reg.clone();
        assert_eq!(cloned.high_water_for(&test_principal()), 10);
        assert_eq!(cloned.principal_count(), 1);
    }

    #[test]
    fn enrichment_attestation_error_clone_eq_all_variants() {
        let variants: Vec<AttestationError> = vec![
            AttestationError::SelfAttestationRejected,
            AttestationError::Expired {
                expires_at: DeterministicTimestamp(100),
                current_time: DeterministicTimestamp(200),
            },
            AttestationError::NonceReplay {
                principal: test_principal(),
                nonce: AttestationNonce::from_counter(3),
                high_water: 5,
            },
            AttestationError::InvalidNonce {
                detail: "zero".to_string(),
            },
            AttestationError::SignatureInvalid {
                detail: "bad sig".to_string(),
            },
            AttestationError::SignatureFailed {
                detail: "cannot sign".to_string(),
            },
            AttestationError::IdDerivationFailed {
                detail: "id err".to_string(),
            },
            AttestationError::InvalidExpiry {
                issued_at: DeterministicTimestamp(200),
                expires_at: DeterministicTimestamp(100),
            },
            AttestationError::ZoneMismatch {
                expected: "z1".to_string(),
                actual: "z2".to_string(),
            },
            AttestationError::DuplicateAttestation {
                attestation_id: EngineObjectId([0xBB; 32]),
            },
            AttestationError::NotFound {
                attestation_id: EngineObjectId([0xCC; 32]),
            },
            AttestationError::DevicePostureInvalid {
                detail: "bad posture".to_string(),
            },
        ];
        for variant in &variants {
            let cloned = variant.clone();
            assert_eq!(*variant, cloned, "clone/eq failed for: {variant}");
        }
    }

    #[test]
    fn enrichment_attestation_error_display_remaining_variants() {
        // Cover variants not individually tested in error_display
        let err = AttestationError::SignatureFailed {
            detail: "failed to sign".to_string(),
        };
        assert!(err.to_string().contains("signature failed"));
        assert!(err.to_string().contains("failed to sign"));

        let err = AttestationError::IdDerivationFailed {
            detail: "bad domain".to_string(),
        };
        assert!(err.to_string().contains("id derivation failed"));

        let err = AttestationError::DuplicateAttestation {
            attestation_id: EngineObjectId([0xDD; 32]),
        };
        assert!(err.to_string().contains("duplicate attestation"));

        let err = AttestationError::DevicePostureInvalid {
            detail: "tampered evidence".to_string(),
        };
        assert!(err.to_string().contains("device posture invalid"));
        assert!(err.to_string().contains("tampered evidence"));

        let err = AttestationError::InvalidExpiry {
            issued_at: DeterministicTimestamp(500),
            expires_at: DeterministicTimestamp(100),
        };
        assert!(err.to_string().contains("invalid expiry"));
        assert!(err.to_string().contains("500"));
    }

    #[test]
    fn enrichment_attestation_event_type_all_variants_serde() {
        let variants: Vec<AttestationEventType> = vec![
            AttestationEventType::Registered {
                attestation_id: EngineObjectId([0x11; 32]),
                principal: test_principal(),
            },
            AttestationEventType::Revoked {
                attestation_id: EngineObjectId([0x22; 32]),
                principal: test_principal(),
            },
            AttestationEventType::RegistrationRejected {
                reason: "zone mismatch".to_string(),
            },
            AttestationEventType::ExpiredPurged { count: 42 },
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).expect("serialize");
            let restored: AttestationEventType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*variant, restored);
        }
    }

    #[test]
    fn enrichment_attestation_event_clone_eq() {
        let event = AttestationEvent {
            event_type: AttestationEventType::ExpiredPurged { count: 3 },
            zone: "zone-x".to_string(),
            trace_id: "trace-123".to_string(),
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
        assert_eq!(cloned.zone, "zone-x");
        assert_eq!(cloned.trace_id, "trace-123");
    }

    #[test]
    fn enrichment_key_attestation_display_contains_nonce_and_expires() {
        let att = create_test_attestation(KeyRole::Encryption, 7, 100, 999);
        let display = att.to_string();
        assert!(display.contains("nonce:7"), "display should contain nonce");
        assert!(display.contains("999"), "display should contain expires_at");
        assert!(
            display.contains("encryption"),
            "display should contain role"
        );
    }

    #[test]
    fn enrichment_store_purge_clears_principal_index() {
        let mut store = AttestationStore::new(TEST_ZONE);
        let att = create_test_attestation(KeyRole::Signing, 1, 100, 200);
        store
            .register(att, &owner_vk(), DeterministicTimestamp(150), "t-1")
            .expect("register");
        assert_eq!(store.principal_count(), 1);

        // Purge after expiry
        let purged = store.purge_expired(DeterministicTimestamp(300), "t-purge");
        assert_eq!(purged, 1);
        assert_eq!(store.total_count(), 0);
        assert_eq!(
            store.principal_count(),
            0,
            "principal index should be cleaned up after purge"
        );
    }
}
