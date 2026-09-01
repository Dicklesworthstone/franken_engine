use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::capability_token::PrincipalId;
use crate::engine_object_id::EngineObjectId;
use crate::policy_checkpoint::DeterministicTimestamp;
use crate::principal_key_roles::KeyRole;
use crate::signature_preimage::VerificationKey;

use super::compat::{
    AttestationError, AttestationEvent, AttestationEventType, AttestationNonce, KeyAttestation,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NonceEntry {
    principal: PrincipalId,
    high_water: u64,
}

/// Replay-safe per-principal nonce high-water registry.
///
/// The serialized representation is wire-compatible with the historical
/// registry, but duplicate principals fail deserialization instead of silently
/// overwriting an earlier high-water value.
#[derive(Debug, Clone, Serialize)]
pub struct NonceRegistry {
    #[serde(serialize_with = "serialize_high_water")]
    high_water: BTreeMap<PrincipalId, u64>,
}

fn serialize_high_water<S: serde::Serializer>(
    map: &BTreeMap<PrincipalId, u64>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    map.iter()
        .map(|(principal, high_water)| NonceEntry {
            principal: principal.clone(),
            high_water: *high_water,
        })
        .collect::<Vec<_>>()
        .serialize(serializer)
}

impl<'de> Deserialize<'de> for NonceRegistry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            high_water: Vec<NonceEntry>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let mut high_water = BTreeMap::new();
        for entry in wire.high_water {
            if high_water
                .insert(entry.principal.clone(), entry.high_water)
                .is_some()
            {
                return Err(serde::de::Error::custom(format!(
                    "duplicate nonce high-water principal {}",
                    entry.principal.to_hex()
                )));
            }
        }
        Ok(Self { high_water })
    }
}

impl NonceRegistry {
    pub fn new() -> Self {
        Self {
            high_water: BTreeMap::new(),
        }
    }

    pub fn check_and_record(
        &mut self,
        principal: &PrincipalId,
        nonce: AttestationNonce,
    ) -> Result<(), AttestationError> {
        let current = self.high_water.get(principal).copied().unwrap_or(0);
        let value = nonce.as_u64();
        if value == 0 {
            return Err(AttestationError::InvalidNonce {
                detail: "nonce must be > 0".to_string(),
            });
        }
        if value <= current {
            return Err(AttestationError::NonceReplay {
                principal: principal.clone(),
                nonce,
                high_water: current,
            });
        }
        self.high_water.insert(principal.clone(), value);
        Ok(())
    }

    pub fn high_water_for(&self, principal: &PrincipalId) -> u64 {
        self.high_water.get(principal).copied().unwrap_or(0)
    }

    pub fn principal_count(&self) -> usize {
        self.high_water.len()
    }
}

impl Default for NonceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Hardened compatibility store for historical [`KeyAttestation`] objects.
///
/// It preserves the historical public methods and serialized field names while
/// enforcing the security invariants missing from the original store boundary:
/// owner/principal binding, recomputed content-derived IDs, nonce monotonicity,
/// and exact persisted-index consistency.
#[derive(Debug, Clone, Serialize)]
pub struct AttestationStore {
    attestations: BTreeMap<EngineObjectId, KeyAttestation>,
    principal_index: BTreeMap<PrincipalId, BTreeSet<EngineObjectId>>,
    nonce_registry: NonceRegistry,
    audit_events: Vec<AttestationEvent>,
    zone: String,
}

impl<'de> Deserialize<'de> for AttestationStore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            attestations: BTreeMap<EngineObjectId, KeyAttestation>,
            principal_index: BTreeMap<PrincipalId, BTreeSet<EngineObjectId>>,
            nonce_registry: NonceRegistry,
            audit_events: Vec<AttestationEvent>,
            zone: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        let store = Self {
            attestations: wire.attestations,
            principal_index: wire.principal_index,
            nonce_registry: wire.nonce_registry,
            audit_events: wire.audit_events,
            zone: wire.zone,
        };
        store
            .validate_persisted_structure()
            .map_err(serde::de::Error::custom)?;
        Ok(store)
    }
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

    pub fn register(
        &mut self,
        attestation: KeyAttestation,
        owner_vk: &VerificationKey,
        current_time: DeterministicTimestamp,
        trace_id: &str,
    ) -> Result<EngineObjectId, AttestationError> {
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

        self.verify_content_identity(&attestation)?;
        self.verify_owner_binding_and_signature(&attestation, owner_vk)?;

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

        self.nonce_registry
            .check_and_record(&attestation.principal_id, attestation.nonce)?;
        if self.attestations.contains_key(&attestation.attestation_id) {
            return Err(AttestationError::DuplicateAttestation {
                attestation_id: attestation.attestation_id.clone(),
            });
        }

        let attestation_id = attestation.attestation_id.clone();
        let principal = attestation.principal_id.clone();
        self.principal_index
            .entry(principal.clone())
            .or_default()
            .insert(attestation_id.clone());
        self.attestations
            .insert(attestation_id.clone(), attestation);
        self.emit_event(
            AttestationEventType::Registered {
                attestation_id: attestation_id.clone(),
                principal,
            },
            trace_id,
        );
        Ok(attestation_id)
    }

    /// Verify every retained signature after loading by supplying the owner
    /// verification keys that are deliberately not persisted inside attestations.
    pub fn validate_loaded(
        &self,
        owner_keys: &BTreeMap<PrincipalId, VerificationKey>,
    ) -> Result<(), AttestationError> {
        self.validate_persisted_structure()?;
        for attestation in self.attestations.values() {
            let owner_key = owner_keys.get(&attestation.principal_id).ok_or_else(|| {
                AttestationError::SignatureInvalid {
                    detail: format!(
                        "missing owner verification key for principal {}",
                        attestation.principal_id.to_hex()
                    ),
                }
            })?;
            self.verify_owner_binding_and_signature(attestation, owner_key)?;
        }
        Ok(())
    }

    pub fn get(&self, attestation_id: &EngineObjectId) -> Option<&KeyAttestation> {
        self.attestations.get(attestation_id)
    }

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
            .filter(|attestation| !attestation.is_expired(current_time))
            .collect()
    }

    pub fn active_for_role(
        &self,
        principal: &PrincipalId,
        role: KeyRole,
        current_time: DeterministicTimestamp,
    ) -> Vec<&KeyAttestation> {
        self.active_for_principal(principal, current_time)
            .into_iter()
            .filter(|attestation| attestation.key_role == role)
            .collect()
    }

    pub fn revoke(
        &mut self,
        attestation_id: &EngineObjectId,
        trace_id: &str,
    ) -> Result<(), AttestationError> {
        let attestation = self
            .attestations
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
                principal: attestation.principal_id,
            },
            trace_id,
        );
        Ok(())
    }

    pub fn purge_expired(
        &mut self,
        current_time: DeterministicTimestamp,
        trace_id: &str,
    ) -> usize {
        let expired_ids = self
            .attestations
            .iter()
            .filter(|(_, attestation)| attestation.is_expired(current_time))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        let count = expired_ids.len();
        for id in &expired_ids {
            if let Some(attestation) = self.attestations.remove(id)
                && let Some(ids) = self.principal_index.get_mut(&attestation.principal_id)
            {
                ids.remove(id);
                if ids.is_empty() {
                    self.principal_index.remove(&attestation.principal_id);
                }
            }
        }
        if count > 0 {
            self.emit_event(AttestationEventType::ExpiredPurged { count }, trace_id);
        }
        count
    }

    pub fn total_count(&self) -> usize {
        self.attestations.len()
    }

    pub fn principal_count(&self) -> usize {
        self.principal_index.len()
    }

    pub fn drain_events(&mut self) -> Vec<AttestationEvent> {
        std::mem::take(&mut self.audit_events)
    }

    fn verify_content_identity(&self, attestation: &KeyAttestation) -> Result<(), AttestationError> {
        if attestation.expires_at.0 <= attestation.issued_at.0 {
            return Err(AttestationError::InvalidExpiry {
                issued_at: attestation.issued_at,
                expires_at: attestation.expires_at,
            });
        }
        if attestation.nonce.as_u64() == 0 {
            return Err(AttestationError::InvalidNonce {
                detail: "nonce must be > 0".to_string(),
            });
        }
        let expected = KeyAttestation::derive_attestation_id(
            &attestation.principal_id,
            &attestation.attested_key,
            attestation.key_role,
            attestation.nonce,
            &attestation.zone,
        )
        .map_err(|error| AttestationError::IdDerivationFailed {
            detail: error.to_string(),
        })?;
        if expected != attestation.attestation_id {
            return Err(AttestationError::IdDerivationFailed {
                detail: "attestation_id does not match the historical content-derived identity"
                    .to_string(),
            });
        }
        Ok(())
    }

    fn verify_owner_binding_and_signature(
        &self,
        attestation: &KeyAttestation,
        owner_vk: &VerificationKey,
    ) -> Result<(), AttestationError> {
        let expected_principal = PrincipalId::from_verification_key(owner_vk);
        if expected_principal != attestation.principal_id {
            return Err(AttestationError::SignatureInvalid {
                detail: format!(
                    "owner key principal {} does not match attestation principal {}",
                    expected_principal.to_hex(),
                    attestation.principal_id.to_hex()
                ),
            });
        }
        attestation.verify_owner_signature(owner_vk)
    }

    fn validate_persisted_structure(&self) -> Result<(), AttestationError> {
        if self.zone.trim().is_empty() {
            return Err(AttestationError::ZoneMismatch {
                expected: "non-empty zone".to_string(),
                actual: self.zone.clone(),
            });
        }
        let mut expected_index: BTreeMap<PrincipalId, BTreeSet<EngineObjectId>> = BTreeMap::new();
        let mut required_high_water: BTreeMap<PrincipalId, u64> = BTreeMap::new();
        for (key, attestation) in &self.attestations {
            if key != &attestation.attestation_id {
                return Err(AttestationError::IdDerivationFailed {
                    detail: "attestation map key does not match payload attestation_id".to_string(),
                });
            }
            if attestation.zone != self.zone {
                return Err(AttestationError::ZoneMismatch {
                    expected: self.zone.clone(),
                    actual: attestation.zone.clone(),
                });
            }
            self.verify_content_identity(attestation)?;
            expected_index
                .entry(attestation.principal_id.clone())
                .or_default()
                .insert(attestation.attestation_id.clone());
            required_high_water
                .entry(attestation.principal_id.clone())
                .and_modify(|current| *current = (*current).max(attestation.nonce.as_u64()))
                .or_insert(attestation.nonce.as_u64());
        }
        if expected_index != self.principal_index {
            return Err(AttestationError::IdDerivationFailed {
                detail: "persisted principal_index does not match authoritative attestations"
                    .to_string(),
            });
        }
        for (principal, required) in required_high_water {
            let actual = self.nonce_registry.high_water_for(&principal);
            if actual < required {
                return Err(AttestationError::InvalidNonce {
                    detail: format!(
                        "persisted nonce high-water {actual} is below retained attestation nonce {required} for principal {}",
                        principal.to_hex()
                    ),
                });
            }
        }
        Ok(())
    }

    fn emit_event(&mut self, event_type: AttestationEventType, trace_id: &str) {
        self.audit_events.push(AttestationEvent {
            event_type,
            zone: self.zone.clone(),
            trace_id: trace_id.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_attestation::{CreateAttestationInput, KeyAttestation};
    use crate::security_epoch::SecurityEpoch;
    use crate::signature_preimage::{sign_preimage, SignaturePreimage, SigningKey};

    const ZONE: &str = "test-zone";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32]).expect("valid key")
    }

    fn attestation(owner: &SigningKey, nonce: u64) -> KeyAttestation {
        KeyAttestation::create_signed(
            owner,
            CreateAttestationInput {
                principal_id: PrincipalId::from_verification_key(&owner.verification_key()),
                attested_key: key(9).verification_key(),
                key_role: KeyRole::Signing,
                issued_at: DeterministicTimestamp(10),
                expires_at: DeterministicTimestamp(100),
                epoch: SecurityEpoch::GENESIS,
                nonce: AttestationNonce::from_counter(nonce),
                device_posture: None,
                zone: ZONE,
            },
        )
        .expect("attestation")
    }

    #[test]
    fn duplicate_nonce_principal_is_rejected_on_deserialize() {
        let principal = PrincipalId::from_verification_key(&key(1).verification_key());
        let value = serde_json::json!({
            "high_water": [
                {"principal": principal, "high_water": 100},
                {"principal": principal, "high_water": 1}
            ]
        });
        assert!(serde_json::from_value::<NonceRegistry>(value).is_err());
    }

    #[test]
    fn register_rejects_owner_key_for_different_principal() {
        let owner = key(1);
        let wrong_owner = key(2);
        let attestation = attestation(&owner, 1);
        let mut store = AttestationStore::new(ZONE);
        assert!(matches!(
            store.register(
                attestation,
                &wrong_owner.verification_key(),
                DeterministicTimestamp(20),
                "wrong-owner"
            ),
            Err(AttestationError::SignatureInvalid { .. })
        ));
        assert_eq!(store.total_count(), 0);
    }

    #[test]
    fn register_recomputes_attestation_id_even_if_owner_resigns_tampered_id() {
        let owner = key(1);
        let mut attestation = attestation(&owner, 1);
        attestation.attestation_id.0[0] ^= 1;
        attestation.owner_signature =
            sign_preimage(&owner, &attestation.preimage_bytes()).expect("resign crafted id");
        let mut store = AttestationStore::new(ZONE);
        assert!(matches!(
            store.register(
                attestation,
                &owner.verification_key(),
                DeterministicTimestamp(20),
                "bad-id"
            ),
            Err(AttestationError::IdDerivationFailed { .. })
        ));
    }

    #[test]
    fn ordinary_registration_still_works() {
        let owner = key(1);
        let attestation = attestation(&owner, 1);
        let mut store = AttestationStore::new(ZONE);
        let id = store
            .register(
                attestation.clone(),
                &owner.verification_key(),
                DeterministicTimestamp(20),
                "register",
            )
            .expect("register");
        assert_eq!(store.get(&id), Some(&attestation));
    }

    #[test]
    fn structural_validation_rejects_lowered_nonce_high_water() {
        let owner = key(1);
        let attestation = attestation(&owner, 10);
        let principal = attestation.principal_id.clone();
        let mut store = AttestationStore::new(ZONE);
        store
            .register(
                attestation,
                &owner.verification_key(),
                DeterministicTimestamp(20),
                "register",
            )
            .expect("register");
        store.nonce_registry.high_water.insert(principal, 1);
        assert!(matches!(
            store.validate_persisted_structure(),
            Err(AttestationError::InvalidNonce { .. })
        ));
    }

    #[test]
    fn structural_validation_rejects_inconsistent_principal_index() {
        let owner = key(1);
        let attestation = attestation(&owner, 1);
        let mut store = AttestationStore::new(ZONE);
        store
            .register(
                attestation,
                &owner.verification_key(),
                DeterministicTimestamp(20),
                "register",
            )
            .expect("register");
        store.principal_index.clear();
        assert!(store.validate_persisted_structure().is_err());
    }

    #[test]
    fn validate_loaded_checks_owner_signature_set() {
        let owner = key(1);
        let attestation = attestation(&owner, 1);
        let principal = attestation.principal_id.clone();
        let mut store = AttestationStore::new(ZONE);
        store
            .register(
                attestation,
                &owner.verification_key(),
                DeterministicTimestamp(20),
                "register",
            )
            .expect("register");
        let owners = BTreeMap::from([(principal, owner.verification_key())]);
        store.validate_loaded(&owners).expect("validate loaded");
    }
}
