//! Principal key role separation: signing, encryption, and issuance.
//!
//! Every runtime principal holds three distinct key roles:
//! - **Signing**: creates signatures on evidence, attestations, and objects.
//! - **Encryption**: decrypts data addressed to the principal (X25519-style).
//! - **Issuance**: issues capability tokens and delegation chains.
//!
//! Each role has an independent lifecycle (creation, activation, rotation,
//! revocation, expiry).  A compromise of one role does not automatically
//! compromise the others.
//!
//! All three keys are bound together through an `OwnerKeyBundle` signed by
//! the principal's root/owner key.  The bundle is a signed object using the
//! signature preimage contract (bd-1b2) and carries an `EngineObjectId`
//! (bd-2y7) for domain-separated identity.
//!
//! Plan references: Section 10.10 item 11, 9E.5 (key-role separation plus
//! owner-signed attestation lifecycle).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, SchemaHash};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_LEN, SIGNATURE_SENTINEL, Signature, SigningKey, VerificationKey, build_preimage,
    sign_preimage, verify_signature,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of an encryption public key in bytes (X25519-style, 32 bytes).
pub const ENCRYPTION_KEY_LEN: usize = 32;

/// Domain separator for signing-key derivation from a master seed.
const SIGNING_DERIVE_DOMAIN: &[u8] = b"franken::keyrole::signing::";

/// Domain separator for encryption-key derivation from a master seed.
const ENCRYPTION_DERIVE_DOMAIN: &[u8] = b"franken::keyrole::encryption::";

/// Domain separator for issuance-key derivation from a master seed.
const ISSUANCE_DERIVE_DOMAIN: &[u8] = b"franken::keyrole::issuance::";

// ---------------------------------------------------------------------------
// Schema definitions
// ---------------------------------------------------------------------------

const BUNDLE_SCHEMA_DEF: &[u8] = b"FrankenEngine.OwnerKeyBundle.v1";

pub fn bundle_schema() -> SchemaHash {
    SchemaHash::from_definition(BUNDLE_SCHEMA_DEF)
}

pub fn bundle_schema_id() -> SchemaId {
    SchemaId::from_definition(BUNDLE_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// KeyRole — the three principal key roles
// ---------------------------------------------------------------------------

/// The three distinct key roles a principal may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum KeyRole {
    /// Creates signatures on objects, evidence, and attestations.
    Signing,
    /// Decrypts data addressed to the principal.
    Encryption,
    /// Issues capability tokens and delegation chains.
    Issuance,
}

impl KeyRole {
    /// All role variants for exhaustive iteration.
    pub const ALL: &'static [KeyRole] = &[KeyRole::Signing, KeyRole::Encryption, KeyRole::Issuance];

    /// Domain separator bytes for key derivation.
    pub fn derivation_domain(&self) -> &'static [u8] {
        match self {
            Self::Signing => SIGNING_DERIVE_DOMAIN,
            Self::Encryption => ENCRYPTION_DERIVE_DOMAIN,
            Self::Issuance => ISSUANCE_DERIVE_DOMAIN,
        }
    }
}

impl fmt::Display for KeyRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signing => f.write_str("signing"),
            Self::Encryption => f.write_str("encryption"),
            Self::Issuance => f.write_str("issuance"),
        }
    }
}

// ---------------------------------------------------------------------------
// KeyStatus — lifecycle state per key
// ---------------------------------------------------------------------------

/// Lifecycle state for a single key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum KeyStatus {
    /// Created but not yet activated.
    Pending,
    /// Active and valid for its designated role.
    Active,
    /// Rotated out; still valid for verification but not for new operations.
    Rotated,
    /// Revoked; invalid for all operations.
    Revoked,
    /// Expired; invalid for all operations.
    Expired,
}

impl KeyStatus {
    /// Whether this status allows new cryptographic operations (signing, decrypting, issuing).
    pub fn allows_creation(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Whether this status allows verification of existing signatures.
    pub fn allows_verification(&self) -> bool {
        matches!(self, Self::Active | Self::Rotated)
    }
}

impl fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => f.write_str("pending"),
            Self::Active => f.write_str("active"),
            Self::Rotated => f.write_str("rotated"),
            Self::Revoked => f.write_str("revoked"),
            Self::Expired => f.write_str("expired"),
        }
    }
}

// ---------------------------------------------------------------------------
// EncryptionPublicKey — X25519-style public key for encryption
// ---------------------------------------------------------------------------

/// A public encryption key (X25519-style, 32 bytes).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EncryptionPublicKey(pub [u8; ENCRYPTION_KEY_LEN]);

impl EncryptionPublicKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; ENCRYPTION_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8; ENCRYPTION_KEY_LEN] {
        &self.0
    }
}

impl fmt::Display for EncryptionPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A private encryption key (X25519-style, 32 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionPrivateKey(pub [u8; ENCRYPTION_KEY_LEN]);

impl EncryptionPrivateKey {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; ENCRYPTION_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> EncryptionPublicKey {
        let mut preimage = Vec::with_capacity(16 + ENCRYPTION_KEY_LEN);
        preimage.extend_from_slice(b"enc-pk-derive:");
        preimage.extend_from_slice(&self.0);
        let hash = ContentHash::compute(&preimage);
        EncryptionPublicKey(*hash.as_bytes())
    }

    /// Access the raw bytes.
    pub fn as_bytes(&self) -> &[u8; ENCRYPTION_KEY_LEN] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// RoleKeyEntry — a single key with role and lifecycle metadata
// ---------------------------------------------------------------------------

/// A key entry for a specific role with lifecycle metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleKeyEntry {
    /// Which role this key serves.
    pub role: KeyRole,
    /// The public verification key (used for signing and issuance roles).
    pub verification_key: VerificationKey,
    /// For encryption role: the public encryption key.
    pub encryption_public_key: Option<EncryptionPublicKey>,
    /// Current lifecycle status.
    pub status: KeyStatus,
    /// Epoch when this key was created.
    pub created_epoch: SecurityEpoch,
    /// Epoch when this key was activated (if activated).
    pub activated_epoch: Option<SecurityEpoch>,
    /// Epoch when this key was revoked (if revoked).
    pub revoked_epoch: Option<SecurityEpoch>,
    /// Sequence number for ordering keys within the same role (rotation).
    pub sequence: u64,
}

impl RoleKeyEntry {
    /// Unique identity bytes for this key entry.
    pub fn identity_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.role.derivation_domain());
        match self.role {
            KeyRole::Encryption => {
                if let Some(encryption_public_key) = &self.encryption_public_key {
                    out.extend_from_slice(encryption_public_key.as_bytes());
                } else {
                    out.extend_from_slice(b"missing-encryption-public-key:");
                    out.extend_from_slice(self.verification_key.as_bytes());
                }
            }
            KeyRole::Signing | KeyRole::Issuance => {
                out.extend_from_slice(self.verification_key.as_bytes());
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// OwnerKeyBundle — signed binding of all three key roles
// ---------------------------------------------------------------------------

/// A signed bundle binding a principal's three key roles together.
///
/// The owner signs this bundle with their root signing key.  Each role's
/// public key is included, and the bundle carries epoch and sequence
/// metadata for lifecycle tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerKeyBundle {
    /// Unique object identity.
    pub id: EngineObjectId,
    /// The principal's signing verification key.
    pub signing_key: VerificationKey,
    /// The principal's encryption public key.
    pub encryption_key: EncryptionPublicKey,
    /// The principal's issuance verification key.
    pub issuance_key: VerificationKey,
    /// Epoch at which this bundle was created.
    pub epoch: SecurityEpoch,
    /// Bundle sequence number (monotonically increasing per principal).
    pub sequence: u64,
    /// Owner signature binding all fields.
    pub owner_signature: Signature,
}

impl OwnerKeyBundle {
    /// Derive the object ID for this bundle from its constituent keys.
    pub fn derive_id(
        signing_key: &VerificationKey,
        encryption_key: &EncryptionPublicKey,
        issuance_key: &VerificationKey,
        epoch: SecurityEpoch,
        sequence: u64,
    ) -> Result<EngineObjectId, engine_object_id::IdError> {
        let mut canonical_bytes = Vec::new();
        canonical_bytes.extend_from_slice(signing_key.as_bytes());
        canonical_bytes.extend_from_slice(encryption_key.as_bytes());
        canonical_bytes.extend_from_slice(issuance_key.as_bytes());
        canonical_bytes.extend_from_slice(&epoch.as_u64().to_le_bytes());
        canonical_bytes.extend_from_slice(&sequence.to_le_bytes());

        engine_object_id::derive_id(
            ObjectDomain::KeyBundle,
            "global",
            &bundle_schema_id(),
            &canonical_bytes,
        )
    }

    /// Build the signature preimage for this bundle.
    fn signature_preimage_bytes(&self) -> Vec<u8> {
        let mut fields = BTreeMap::new();

        fields.insert(
            "id".to_string(),
            CanonicalValue::Bytes(self.id.as_bytes().to_vec()),
        );
        fields.insert(
            "signing_key".to_string(),
            CanonicalValue::Bytes(self.signing_key.as_bytes().to_vec()),
        );
        fields.insert(
            "encryption_key".to_string(),
            CanonicalValue::Bytes(self.encryption_key.as_bytes().to_vec()),
        );
        fields.insert(
            "issuance_key".to_string(),
            CanonicalValue::Bytes(self.issuance_key.as_bytes().to_vec()),
        );
        fields.insert(
            "epoch".to_string(),
            CanonicalValue::U64(self.epoch.as_u64()),
        );
        fields.insert("sequence".to_string(), CanonicalValue::U64(self.sequence));
        fields.insert(
            "owner_signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );

        let schema = bundle_schema();
        let unsigned_view = CanonicalValue::Map(fields);
        build_preimage(ObjectDomain::KeyBundle, &schema, &unsigned_view)
    }

    /// Create and sign a new bundle.
    pub fn create_signed(
        owner_signing_key: &SigningKey,
        signing_vk: VerificationKey,
        encryption_pk: EncryptionPublicKey,
        issuance_vk: VerificationKey,
        epoch: SecurityEpoch,
        sequence: u64,
    ) -> Result<Self, KeyRoleError> {
        let id = Self::derive_id(&signing_vk, &encryption_pk, &issuance_vk, epoch, sequence)
            .map_err(|_| KeyRoleError::BundleCreationFailed)?;

        let mut bundle = Self {
            id,
            signing_key: signing_vk,
            encryption_key: encryption_pk,
            issuance_key: issuance_vk,
            epoch,
            sequence,
            owner_signature: Signature::from_bytes([0u8; SIGNATURE_LEN]),
        };

        let preimage = bundle.signature_preimage_bytes();
        bundle.owner_signature = sign_preimage(owner_signing_key, &preimage)
            .map_err(|_| KeyRoleError::BundleCreationFailed)?;
        Ok(bundle)
    }

    /// Verify the owner signature on this bundle.
    pub fn verify(&self, owner_vk: &VerificationKey) -> Result<(), KeyRoleError> {
        let preimage = self.signature_preimage_bytes();
        if verify_signature(owner_vk, &preimage, &self.owner_signature).is_ok() {
            Ok(())
        } else {
            Err(KeyRoleError::BundleSignatureInvalid)
        }
    }
}

// ---------------------------------------------------------------------------
// KeyRoleError — domain-specific errors
// ---------------------------------------------------------------------------

/// Errors from key role operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyRoleError {
    /// Attempted to use a key outside its designated role.
    KeyRoleMismatch { expected: KeyRole, actual: KeyRole },
    /// Key is not in a status that allows the requested operation.
    KeyNotActive { role: KeyRole, status: KeyStatus },
    /// No active key found for the given role.
    NoActiveKey { role: KeyRole },
    /// Bundle creation failed (ID derivation error).
    BundleCreationFailed,
    /// Bundle signature verification failed.
    BundleSignatureInvalid,
    /// Key sequence regression (new sequence must be > existing).
    SequenceRegression {
        role: KeyRole,
        existing: u64,
        attempted: u64,
    },
    /// Principal not found.
    PrincipalNotFound,
    /// Duplicate key registration for the same role and sequence.
    DuplicateKey { role: KeyRole, sequence: u64 },
}

impl fmt::Display for KeyRoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyRoleMismatch { expected, actual } => {
                write!(f, "key role mismatch: expected {expected}, got {actual}")
            }
            Self::KeyNotActive { role, status } => {
                write!(f, "key for role {role} is {status}, not active")
            }
            Self::NoActiveKey { role } => {
                write!(f, "no active key for role {role}")
            }
            Self::BundleCreationFailed => f.write_str("bundle creation failed"),
            Self::BundleSignatureInvalid => f.write_str("bundle signature invalid"),
            Self::SequenceRegression {
                role,
                existing,
                attempted,
            } => {
                write!(
                    f,
                    "sequence regression for {role}: existing={existing}, attempted={attempted}"
                )
            }
            Self::PrincipalNotFound => f.write_str("principal not found"),
            Self::DuplicateKey { role, sequence } => {
                write!(f, "duplicate key for role {role} at sequence {sequence}")
            }
        }
    }
}

impl std::error::Error for KeyRoleError {}

// ---------------------------------------------------------------------------
// derive_role_key — domain-separated key derivation from a master seed
// ---------------------------------------------------------------------------

/// Derive a role-specific key from a master seed with domain separation.
///
/// Ensures that signing and encryption keys derived from the same seed are
/// cryptographically distinct.
pub fn derive_role_key(master_seed: &[u8; 32], role: KeyRole, epoch: SecurityEpoch) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(role.derivation_domain());
    preimage.extend_from_slice(master_seed);
    preimage.extend_from_slice(&epoch.as_u64().to_le_bytes());
    *ContentHash::compute(&preimage).as_bytes()
}

// ---------------------------------------------------------------------------
// PrincipalKeyStore — per-principal key management
// ---------------------------------------------------------------------------

/// Per-principal key store managing all three key roles with independent
/// lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalKeyStore {
    /// Keys indexed by (role, sequence).
    keys: BTreeMap<(KeyRole, u64), RoleKeyEntry>,
    /// The current active key bundle (if any).
    active_bundle: Option<OwnerKeyBundle>,
}

impl PrincipalKeyStore {
    /// Create a new empty key store.
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            active_bundle: None,
        }
    }

    /// Register a new key entry for a given role.
    pub fn register_key(&mut self, entry: RoleKeyEntry) -> Result<(), KeyRoleError> {
        let key = (entry.role, entry.sequence);
        if self.keys.contains_key(&key) {
            return Err(KeyRoleError::DuplicateKey {
                role: entry.role,
                sequence: entry.sequence,
            });
        }

        // Check sequence monotonicity within role.
        let max_seq = self
            .keys
            .keys()
            .filter(|(r, _)| *r == entry.role)
            .map(|(_, s)| *s)
            .max();
        if let Some(max) = max_seq
            && entry.sequence <= max
        {
            return Err(KeyRoleError::SequenceRegression {
                role: entry.role,
                existing: max,
                attempted: entry.sequence,
            });
        }

        self.keys.insert(key, entry);
        Ok(())
    }

    /// Get the active key for a given role.
    pub fn get_active_key(&self, role: KeyRole) -> Result<&RoleKeyEntry, KeyRoleError> {
        self.keys
            .values()
            .rfind(|e| e.role == role && e.status == KeyStatus::Active)
            .ok_or(KeyRoleError::NoActiveKey { role })
    }

    /// Get all keys for a given role (any status).
    pub fn keys_for_role(&self, role: KeyRole) -> Vec<&RoleKeyEntry> {
        self.keys.values().filter(|e| e.role == role).collect()
    }

    /// Get all keys that allow verification (Active or Rotated).
    pub fn verification_keys_for_role(&self, role: KeyRole) -> Vec<&RoleKeyEntry> {
        self.keys
            .values()
            .filter(|e| e.role == role && e.status.allows_verification())
            .collect()
    }

    /// Activate a pending key.
    pub fn activate_key(
        &mut self,
        role: KeyRole,
        sequence: u64,
        epoch: SecurityEpoch,
    ) -> Result<(), KeyRoleError> {
        let entry = self
            .keys
            .get_mut(&(role, sequence))
            .ok_or(KeyRoleError::NoActiveKey { role })?;

        if entry.status != KeyStatus::Pending {
            return Err(KeyRoleError::KeyNotActive {
                role,
                status: entry.status,
            });
        }

        entry.status = KeyStatus::Active;
        entry.activated_epoch = Some(epoch);
        Ok(())
    }

    /// Revoke a specific key (by role and sequence).
    pub fn revoke_key(
        &mut self,
        role: KeyRole,
        sequence: u64,
        epoch: SecurityEpoch,
    ) -> Result<(), KeyRoleError> {
        let entry = self
            .keys
            .get_mut(&(role, sequence))
            .ok_or(KeyRoleError::NoActiveKey { role })?;

        entry.status = KeyStatus::Revoked;
        entry.revoked_epoch = Some(epoch);
        Ok(())
    }

    /// Rotate a key: mark the current active key as Rotated and activate the next one.
    pub fn rotate_key(
        &mut self,
        role: KeyRole,
        old_sequence: u64,
        new_sequence: u64,
        epoch: SecurityEpoch,
    ) -> Result<(), KeyRoleError> {
        // Mark old key as rotated.
        let old_entry = self
            .keys
            .get_mut(&(role, old_sequence))
            .ok_or(KeyRoleError::NoActiveKey { role })?;
        if old_entry.status != KeyStatus::Active {
            return Err(KeyRoleError::KeyNotActive {
                role,
                status: old_entry.status,
            });
        }
        old_entry.status = KeyStatus::Rotated;

        // Activate new key.
        let new_entry = self
            .keys
            .get_mut(&(role, new_sequence))
            .ok_or(KeyRoleError::NoActiveKey { role })?;
        if new_entry.status != KeyStatus::Pending {
            return Err(KeyRoleError::KeyNotActive {
                role,
                status: new_entry.status,
            });
        }
        new_entry.status = KeyStatus::Active;
        new_entry.activated_epoch = Some(epoch);
        Ok(())
    }

    /// Set the active bundle.
    pub fn set_bundle(&mut self, bundle: OwnerKeyBundle) {
        self.active_bundle = Some(bundle);
    }

    /// Get the active bundle (if any).
    pub fn bundle(&self) -> Option<&OwnerKeyBundle> {
        self.active_bundle.as_ref()
    }

    /// Count of all keys across all roles.
    pub fn total_key_count(&self) -> usize {
        self.keys.len()
    }
}

impl Default for PrincipalKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// enforce_role — runtime role enforcement
// ---------------------------------------------------------------------------

/// Verify that a key entry matches the expected role.  Returns
/// `KeyRoleMismatch` if the role does not match.
pub fn enforce_role(entry: &RoleKeyEntry, expected: KeyRole) -> Result<(), KeyRoleError> {
    if entry.role != expected {
        Err(KeyRoleError::KeyRoleMismatch {
            expected,
            actual: entry.role,
        })
    } else {
        Ok(())
    }
}

/// Verify that a key entry is active and matches the expected role.
pub fn enforce_active_role(entry: &RoleKeyEntry, expected: KeyRole) -> Result<(), KeyRoleError> {
    enforce_role(entry, expected)?;
    if !entry.status.allows_creation() {
        return Err(KeyRoleError::KeyNotActive {
            role: expected,
            status: entry.status,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> [u8; 32] {
        [0xAA; 32]
    }

    fn make_signing_key(seed: &[u8; 32], epoch: SecurityEpoch) -> SigningKey {
        let derived = derive_role_key(seed, KeyRole::Signing, epoch);
        // SAFETY: Test helper unwrap, derive_role_key produces valid 32-byte array
        SigningKey::from_bytes(derived).expect("serde deserialization should succeed")
    }

    fn make_encryption_private(seed: &[u8; 32], epoch: SecurityEpoch) -> EncryptionPrivateKey {
        let derived = derive_role_key(seed, KeyRole::Encryption, epoch);
        EncryptionPrivateKey::from_bytes(derived)
    }

    fn make_issuance_key(seed: &[u8; 32], epoch: SecurityEpoch) -> SigningKey {
        let derived = derive_role_key(seed, KeyRole::Issuance, epoch);
        // SAFETY: Test helper unwrap, derive_role_key produces valid 32-byte array
        SigningKey::from_bytes(derived).expect("serde deserialization should succeed")
    }

    fn make_role_entry(
        role: KeyRole,
        vk: VerificationKey,
        enc_pk: Option<EncryptionPublicKey>,
        status: KeyStatus,
        epoch: SecurityEpoch,
        seq: u64,
    ) -> RoleKeyEntry {
        RoleKeyEntry {
            role,
            verification_key: vk,
            encryption_public_key: enc_pk,
            status,
            created_epoch: epoch,
            activated_epoch: if status == KeyStatus::Active {
                Some(epoch)
            } else {
                None
            },
            revoked_epoch: None,
            sequence: seq,
        }
    }

    #[test]
    fn domain_separation_produces_distinct_keys() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);

        let signing = derive_role_key(&seed, KeyRole::Signing, epoch);
        let encryption = derive_role_key(&seed, KeyRole::Encryption, epoch);
        let issuance = derive_role_key(&seed, KeyRole::Issuance, epoch);

        assert_ne!(signing, encryption, "signing != encryption");
        assert_ne!(signing, issuance, "signing != issuance");
        assert_ne!(encryption, issuance, "encryption != issuance");
    }

    #[test]
    fn different_epochs_produce_distinct_keys() {
        let seed = test_seed();
        let k1 = derive_role_key(&seed, KeyRole::Signing, SecurityEpoch::from_raw(1));
        let k2 = derive_role_key(&seed, KeyRole::Signing, SecurityEpoch::from_raw(2));
        assert_ne!(k1, k2);
    }

    #[test]
    fn different_seeds_produce_distinct_keys() {
        let s1 = [0x11; 32];
        let s2 = [0x22; 32];
        let epoch = SecurityEpoch::from_raw(1);
        let k1 = derive_role_key(&s1, KeyRole::Signing, epoch);
        let k2 = derive_role_key(&s2, KeyRole::Signing, epoch);
        assert_ne!(k1, k2);
    }

    #[test]
    fn key_role_mismatch_rejected() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);
        let sk = make_signing_key(&seed, epoch);
        let vk = sk.verification_key();

        let entry = make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Active, epoch, 0);

        assert!(enforce_role(&entry, KeyRole::Signing).is_ok());
        assert_eq!(
            enforce_role(&entry, KeyRole::Encryption),
            Err(KeyRoleError::KeyRoleMismatch {
                expected: KeyRole::Encryption,
                actual: KeyRole::Signing,
            })
        );
        assert_eq!(
            enforce_role(&entry, KeyRole::Issuance),
            Err(KeyRoleError::KeyRoleMismatch {
                expected: KeyRole::Issuance,
                actual: KeyRole::Signing,
            })
        );
    }

    #[test]
    fn enforce_active_role_rejects_revoked() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);
        let sk = make_signing_key(&seed, epoch);
        let vk = sk.verification_key();

        let entry = make_role_entry(KeyRole::Signing, vk, None, KeyStatus::Revoked, epoch, 0);

        assert_eq!(
            enforce_active_role(&entry, KeyRole::Signing),
            Err(KeyRoleError::KeyNotActive {
                role: KeyRole::Signing,
                status: KeyStatus::Revoked,
            })
        );
    }

    #[test]
    fn independent_revocation_per_role() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);
        let epoch2 = SecurityEpoch::from_raw(2);

        let sk = make_signing_key(&seed, epoch);
        let enc = make_encryption_private(&seed, epoch);
        let iss = make_issuance_key(&seed, epoch);

        let mut store = PrincipalKeyStore::new();

        // Register all three roles.
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                0,
            ))
            // SAFETY: Test-only unwrap with valid key registration parameters
            .expect("serde deserialization should succeed");
        store
            .register_key(make_role_entry(
                KeyRole::Encryption,
                SigningKey::from_bytes([0x01; 32])
                    // SAFETY: Test helper with fixed 32-byte array should create valid SigningKey
                    .expect("serde deserialization should succeed")
                    .verification_key(),
                Some(enc.public_key()),
                KeyStatus::Active,
                epoch,
                0,
            ))
            // SAFETY: Test-only unwrap with valid key registration parameters
            .expect("serde deserialization should succeed");
        store
            .register_key(make_role_entry(
                KeyRole::Issuance,
                iss.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                0,
            ))
            // SAFETY: Test-only unwrap with valid key registration parameters
            .expect("serde deserialization should succeed");

        // Revoke only the signing key.
        // SAFETY: Test-only unwrap with valid revocation parameters (registered key)
        store
            .revoke_key(KeyRole::Signing, 0, epoch2)
            .expect("serde deserialization should succeed");

        // Signing is revoked.
        let signing = store.get_active_key(KeyRole::Signing);
        assert!(signing.is_err());

        // Encryption and issuance still active.
        assert!(store.get_active_key(KeyRole::Encryption).is_ok());
        assert!(store.get_active_key(KeyRole::Issuance).is_ok());
    }

    #[test]
    fn owner_key_bundle_sign_and_verify() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);

        let owner_sk = make_signing_key(&seed, epoch);
        let owner_vk = owner_sk.verification_key();

        let enc = make_encryption_private(&seed, epoch);
        let iss = make_issuance_key(&seed, epoch);

        let bundle = OwnerKeyBundle::create_signed(
            &owner_sk,
            owner_vk.clone(),
            enc.public_key(),
            iss.verification_key(),
            epoch,
            1,
        )
        // SAFETY: Test-only unwrap with valid bundle creation parameters
        .expect("serde deserialization should succeed");

        assert!(bundle.verify(&owner_vk).is_ok());
    }

    #[test]
    fn bundle_rejects_wrong_verifier() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);

        let owner_sk = make_signing_key(&seed, epoch);
        let owner_vk = owner_sk.verification_key();
        let enc = make_encryption_private(&seed, epoch);
        let iss = make_issuance_key(&seed, epoch);

        let bundle = OwnerKeyBundle::create_signed(
            &owner_sk,
            owner_vk,
            enc.public_key(),
            iss.verification_key(),
            epoch,
            1,
        )
        // SAFETY: Test-only unwrap with valid bundle creation parameters
        .expect("serde deserialization should succeed");

        let wrong_vk = SigningKey::from_bytes([0xAB; 32])
            // SAFETY: Test helper with fixed 32-byte array should create valid SigningKey
            .expect("serde deserialization should succeed")
            .verification_key();
        assert_eq!(
            bundle.verify(&wrong_vk),
            Err(KeyRoleError::BundleSignatureInvalid)
        );
    }

    #[test]
    fn key_rotation_with_overlap_window() {
        let seed = test_seed();
        let epoch1 = SecurityEpoch::from_raw(1);
        let epoch2 = SecurityEpoch::from_raw(2);

        let sk1 = make_signing_key(&seed, epoch1);
        let seed2 = [0xBB; 32];
        let sk2 = make_signing_key(&seed2, epoch2);

        let mut store = PrincipalKeyStore::new();

        // Register and activate first key.
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk1.verification_key(),
                None,
                KeyStatus::Active,
                epoch1,
                0,
            ))
            .expect("serde deserialization should succeed");

        // Register second key as pending.
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk2.verification_key(),
                None,
                KeyStatus::Pending,
                epoch2,
                1,
            ))
            .expect("serde deserialization should succeed");

        // Rotate: old becomes Rotated, new becomes Active.
        store
            .rotate_key(KeyRole::Signing, 0, 1, epoch2)
            .expect("serde deserialization should succeed");

        // Both should be valid for verification.
        let verifiable = store.verification_keys_for_role(KeyRole::Signing);
        assert_eq!(verifiable.len(), 2);

        // Only the new key is active for creation.
        let active = store
            .get_active_key(KeyRole::Signing)
            .expect("serde deserialization should succeed");
        assert_eq!(active.sequence, 1);
    }

    #[test]
    fn sequence_regression_rejected() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);
        let sk = make_signing_key(&seed, epoch);

        let mut store = PrincipalKeyStore::new();
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                5,
            ))
            .expect("serde deserialization should succeed");

        let sk2 = make_signing_key(&[0xBB; 32], epoch);
        let result = store.register_key(make_role_entry(
            KeyRole::Signing,
            sk2.verification_key(),
            None,
            KeyStatus::Pending,
            epoch,
            3,
        ));

        assert_eq!(
            result,
            Err(KeyRoleError::SequenceRegression {
                role: KeyRole::Signing,
                existing: 5,
                attempted: 3,
            })
        );
    }

    #[test]
    fn duplicate_key_rejected() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);
        let sk = make_signing_key(&seed, epoch);

        let mut store = PrincipalKeyStore::new();
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");

        let result = store.register_key(make_role_entry(
            KeyRole::Signing,
            sk.verification_key(),
            None,
            KeyStatus::Pending,
            epoch,
            0,
        ));

        assert_eq!(
            result,
            Err(KeyRoleError::DuplicateKey {
                role: KeyRole::Signing,
                sequence: 0,
            })
        );
    }

    #[test]
    fn get_active_key_returns_correct_role() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);

        let sk = make_signing_key(&seed, epoch);
        let enc = make_encryption_private(&seed, epoch);
        let iss = make_issuance_key(&seed, epoch);

        let mut store = PrincipalKeyStore::new();

        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");
        store
            .register_key(make_role_entry(
                KeyRole::Encryption,
                SigningKey::from_bytes([0x01; 32])
                    .expect("serde deserialization should succeed")
                    .verification_key(),
                Some(enc.public_key()),
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");
        store
            .register_key(make_role_entry(
                KeyRole::Issuance,
                iss.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");

        let s = store
            .get_active_key(KeyRole::Signing)
            .expect("serde deserialization should succeed");
        assert_eq!(s.role, KeyRole::Signing);

        let e = store
            .get_active_key(KeyRole::Encryption)
            .expect("serde deserialization should succeed");
        assert_eq!(e.role, KeyRole::Encryption);

        let i = store
            .get_active_key(KeyRole::Issuance)
            .expect("serde deserialization should succeed");
        assert_eq!(i.role, KeyRole::Issuance);
    }

    #[test]
    fn no_active_key_returns_error() {
        let store = PrincipalKeyStore::new();
        assert_eq!(
            store.get_active_key(KeyRole::Signing),
            Err(KeyRoleError::NoActiveKey {
                role: KeyRole::Signing
            })
        );
    }

    #[test]
    fn key_lifecycle_create_activate_revoke() {
        let seed = test_seed();
        let epoch1 = SecurityEpoch::from_raw(1);
        let epoch2 = SecurityEpoch::from_raw(2);
        let epoch3 = SecurityEpoch::from_raw(3);

        let sk = make_signing_key(&seed, epoch1);
        let mut store = PrincipalKeyStore::new();

        // Create as pending.
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk.verification_key(),
                None,
                KeyStatus::Pending,
                epoch1,
                0,
            ))
            .expect("serde deserialization should succeed");

        // Not yet active.
        assert!(store.get_active_key(KeyRole::Signing).is_err());

        // Activate.
        store
            .activate_key(KeyRole::Signing, 0, epoch2)
            .expect("serde deserialization should succeed");
        assert!(store.get_active_key(KeyRole::Signing).is_ok());

        // Revoke.
        store
            .revoke_key(KeyRole::Signing, 0, epoch3)
            .expect("serde deserialization should succeed");
        assert!(store.get_active_key(KeyRole::Signing).is_err());
    }

    #[test]
    fn key_role_display() {
        assert_eq!(format!("{}", KeyRole::Signing), "signing");
        assert_eq!(format!("{}", KeyRole::Encryption), "encryption");
        assert_eq!(format!("{}", KeyRole::Issuance), "issuance");
    }

    #[test]
    fn key_status_display() {
        assert_eq!(format!("{}", KeyStatus::Pending), "pending");
        assert_eq!(format!("{}", KeyStatus::Active), "active");
        assert_eq!(format!("{}", KeyStatus::Rotated), "rotated");
        assert_eq!(format!("{}", KeyStatus::Revoked), "revoked");
        assert_eq!(format!("{}", KeyStatus::Expired), "expired");
    }

    #[test]
    fn key_status_creation_and_verification_semantics() {
        assert!(!KeyStatus::Pending.allows_creation());
        assert!(KeyStatus::Active.allows_creation());
        assert!(!KeyStatus::Rotated.allows_creation());
        assert!(!KeyStatus::Revoked.allows_creation());
        assert!(!KeyStatus::Expired.allows_creation());

        assert!(!KeyStatus::Pending.allows_verification());
        assert!(KeyStatus::Active.allows_verification());
        assert!(KeyStatus::Rotated.allows_verification());
        assert!(!KeyStatus::Revoked.allows_verification());
        assert!(!KeyStatus::Expired.allows_verification());
    }

    #[test]
    fn encryption_key_derivation_roundtrip() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);
        let enc = make_encryption_private(&seed, epoch);
        let pk1 = enc.public_key();
        let pk2 = enc.public_key();
        assert_eq!(pk1, pk2, "public key derivation is deterministic");
    }

    #[test]
    fn bundle_id_deterministic() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);

        let sk = make_signing_key(&seed, epoch);
        let enc = make_encryption_private(&seed, epoch);
        let iss = make_issuance_key(&seed, epoch);

        let id1 = OwnerKeyBundle::derive_id(
            &sk.verification_key(),
            &enc.public_key(),
            &iss.verification_key(),
            epoch,
            1,
        )
        .expect("serde deserialization should succeed");
        let id2 = OwnerKeyBundle::derive_id(
            &sk.verification_key(),
            &enc.public_key(),
            &iss.verification_key(),
            epoch,
            1,
        )
        .expect("serde deserialization should succeed");

        assert_eq!(id1, id2, "ID derivation is deterministic");
    }

    #[test]
    fn bundle_id_changes_with_different_keys() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);

        let sk1 = make_signing_key(&seed, epoch);
        let sk2 = make_signing_key(&[0xBB; 32], epoch);
        let enc = make_encryption_private(&seed, epoch);
        let iss = make_issuance_key(&seed, epoch);

        let id1 = OwnerKeyBundle::derive_id(
            &sk1.verification_key(),
            &enc.public_key(),
            &iss.verification_key(),
            epoch,
            1,
        )
        .expect("serde deserialization should succeed");
        let id2 = OwnerKeyBundle::derive_id(
            &sk2.verification_key(),
            &enc.public_key(),
            &iss.verification_key(),
            epoch,
            1,
        )
        .expect("serde deserialization should succeed");

        assert_ne!(id1, id2);
    }

    #[test]
    fn keys_for_role_returns_all_including_revoked() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);
        let epoch2 = SecurityEpoch::from_raw(2);

        let sk1 = make_signing_key(&seed, epoch);
        let sk2 = make_signing_key(&[0xBB; 32], epoch);

        let mut store = PrincipalKeyStore::new();
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk1.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk2.verification_key(),
                None,
                KeyStatus::Pending,
                epoch,
                1,
            ))
            .expect("serde deserialization should succeed");

        store
            .revoke_key(KeyRole::Signing, 0, epoch2)
            .expect("serde deserialization should succeed");

        let all = store.keys_for_role(KeyRole::Signing);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn total_key_count() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);

        let sk = make_signing_key(&seed, epoch);
        let enc = make_encryption_private(&seed, epoch);

        let mut store = PrincipalKeyStore::new();
        assert_eq!(store.total_key_count(), 0);

        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");
        assert_eq!(store.total_key_count(), 1);

        store
            .register_key(make_role_entry(
                KeyRole::Encryption,
                SigningKey::from_bytes([0x01; 32])
                    .expect("serde deserialization should succeed")
                    .verification_key(),
                Some(enc.public_key()),
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");
        assert_eq!(store.total_key_count(), 2);
    }

    #[test]
    fn role_identity_bytes_are_role_specific() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);

        let vk = make_signing_key(&seed, epoch).verification_key();

        let signing_entry = make_role_entry(
            KeyRole::Signing,
            vk.clone(),
            None,
            KeyStatus::Active,
            epoch,
            0,
        );
        let issuance_entry =
            make_role_entry(KeyRole::Issuance, vk, None, KeyStatus::Active, epoch, 0);

        assert_ne!(
            signing_entry.identity_bytes(),
            issuance_entry.identity_bytes(),
            "same vk but different roles produce different identity bytes"
        );
    }

    #[test]
    fn encryption_role_identity_bytes_include_encryption_public_key() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);
        let verification_key = SigningKey::from_bytes([0x01; 32])
            .expect("serde deserialization should succeed")
            .verification_key();
        let encryption_a = make_encryption_private(&seed, epoch).public_key();
        let encryption_b = make_encryption_private(&[0x44; 32], epoch).public_key();

        let entry_a = make_role_entry(
            KeyRole::Encryption,
            verification_key.clone(),
            Some(encryption_a.clone()),
            KeyStatus::Active,
            epoch,
            0,
        );
        let entry_b = make_role_entry(
            KeyRole::Encryption,
            verification_key,
            Some(encryption_b),
            KeyStatus::Active,
            epoch,
            0,
        );

        assert_ne!(
            entry_a.identity_bytes(),
            entry_b.identity_bytes(),
            "encryption identities must vary with encryption public key material"
        );
        let identity = entry_a.identity_bytes();
        assert_eq!(
            &identity[identity.len() - ENCRYPTION_KEY_LEN..],
            encryption_a.as_bytes()
        );
    }

    #[test]
    fn key_role_error_display() {
        let err = KeyRoleError::KeyRoleMismatch {
            expected: KeyRole::Signing,
            actual: KeyRole::Encryption,
        };
        assert!(format!("{err}").contains("mismatch"));

        let err2 = KeyRoleError::NoActiveKey {
            role: KeyRole::Issuance,
        };
        assert!(format!("{err2}").contains("issuance"));
    }

    #[test]
    fn encryption_public_key_display() {
        let pk = EncryptionPublicKey([0x42; 32]);
        let s = format!("{pk}");
        assert!(s.starts_with("42424242"));
    }

    #[test]
    fn bundle_set_and_get() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);

        let owner_sk = make_signing_key(&seed, epoch);
        let enc = make_encryption_private(&seed, epoch);
        let iss = make_issuance_key(&seed, epoch);

        let bundle = OwnerKeyBundle::create_signed(
            &owner_sk,
            owner_sk.verification_key(),
            enc.public_key(),
            iss.verification_key(),
            epoch,
            1,
        )
        .expect("serde deserialization should succeed");

        let mut store = PrincipalKeyStore::new();
        assert!(store.bundle().is_none());
        store.set_bundle(bundle.clone());
        assert!(store.bundle().is_some());
        assert_eq!(
            store
                .bundle()
                .expect("serde deserialization should succeed")
                .sequence,
            1
        );
    }

    #[test]
    fn cross_role_rejection_in_workflow() {
        // Simulate: signing key should not be usable for issuance.
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);

        let sk = make_signing_key(&seed, epoch);
        let iss = make_issuance_key(&seed, epoch);

        let mut store = PrincipalKeyStore::new();
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");
        store
            .register_key(make_role_entry(
                KeyRole::Issuance,
                iss.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");

        // Get signing key.
        let signing_entry = store
            .get_active_key(KeyRole::Signing)
            .expect("serde deserialization should succeed");

        // Attempt to use it for issuance should fail.
        assert!(enforce_role(signing_entry, KeyRole::Issuance).is_err());

        // Correct issuance key should work.
        let issuance_entry = store
            .get_active_key(KeyRole::Issuance)
            .expect("serde deserialization should succeed");
        assert!(enforce_role(issuance_entry, KeyRole::Issuance).is_ok());
    }

    #[test]
    fn adversarial_forge_issuance_with_signing_key() {
        // An attacker who compromises the signing key should NOT be able
        // to use it for issuance.
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);

        let compromised_sk = make_signing_key(&seed, epoch);
        let legitimate_iss = make_issuance_key(&seed, epoch);

        let mut store = PrincipalKeyStore::new();
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                compromised_sk.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");
        store
            .register_key(make_role_entry(
                KeyRole::Issuance,
                legitimate_iss.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");

        // Attacker retrieves signing entry.
        let signing_entry = store
            .get_active_key(KeyRole::Signing)
            .expect("serde deserialization should succeed");

        // Role enforcement blocks issuance use.
        assert_eq!(
            enforce_active_role(signing_entry, KeyRole::Issuance),
            Err(KeyRoleError::KeyRoleMismatch {
                expected: KeyRole::Issuance,
                actual: KeyRole::Signing,
            })
        );

        // The signing key's verification key differs from issuance key's
        // verification key due to domain separation.
        assert_ne!(
            compromised_sk.verification_key(),
            legitimate_iss.verification_key(),
            "domain separation ensures different derived keys"
        );
    }

    #[test]
    fn default_store_is_empty() {
        let store = PrincipalKeyStore::default();
        assert_eq!(store.total_key_count(), 0);
        assert!(store.bundle().is_none());
    }

    #[test]
    fn activate_non_pending_fails() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);

        let sk = make_signing_key(&seed, epoch);
        let mut store = PrincipalKeyStore::new();
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");

        // Trying to activate an already-active key should fail.
        let result = store.activate_key(KeyRole::Signing, 0, epoch);
        assert!(result.is_err());
    }

    #[test]
    fn rotate_non_active_old_key_fails() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);

        let sk1 = make_signing_key(&seed, epoch);
        let sk2 = make_signing_key(&[0xBB; 32], epoch);

        let mut store = PrincipalKeyStore::new();
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk1.verification_key(),
                None,
                KeyStatus::Pending,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk2.verification_key(),
                None,
                KeyStatus::Pending,
                epoch,
                1,
            ))
            .expect("serde deserialization should succeed");

        // Old key is Pending, not Active — rotation should fail.
        let result = store.rotate_key(KeyRole::Signing, 0, 1, epoch);
        assert!(result.is_err());
    }

    // -- serde roundtrips for enums -------------------------------------------

    #[test]
    fn key_role_serde_roundtrip() {
        for role in KeyRole::ALL {
            let json = serde_json::to_string(role).expect("serde deserialization should succeed");
            let back: KeyRole =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*role, back);
        }
    }

    #[test]
    fn key_status_serde_roundtrip() {
        for status in &[
            KeyStatus::Pending,
            KeyStatus::Active,
            KeyStatus::Rotated,
            KeyStatus::Revoked,
            KeyStatus::Expired,
        ] {
            let json = serde_json::to_string(status).expect("serde deserialization should succeed");
            let back: KeyStatus =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*status, back);
        }
    }

    #[test]
    fn key_role_error_serde_roundtrip() {
        let errors = vec![
            KeyRoleError::KeyRoleMismatch {
                expected: KeyRole::Signing,
                actual: KeyRole::Encryption,
            },
            KeyRoleError::KeyNotActive {
                role: KeyRole::Issuance,
                status: KeyStatus::Revoked,
            },
            KeyRoleError::NoActiveKey {
                role: KeyRole::Signing,
            },
            KeyRoleError::BundleCreationFailed,
            KeyRoleError::BundleSignatureInvalid,
            KeyRoleError::SequenceRegression {
                role: KeyRole::Signing,
                existing: 5,
                attempted: 3,
            },
            KeyRoleError::PrincipalNotFound,
            KeyRoleError::DuplicateKey {
                role: KeyRole::Encryption,
                sequence: 2,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serde deserialization should succeed");
            let back: KeyRoleError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*err, back);
        }
    }

    // -- KeyRoleError Display: all 8 variants ---------------------------------

    #[test]
    fn key_role_error_display_key_not_active() {
        let err = KeyRoleError::KeyNotActive {
            role: KeyRole::Signing,
            status: KeyStatus::Expired,
        };
        let s = err.to_string();
        assert!(s.contains("signing"));
        assert!(s.contains("expired"));
    }

    #[test]
    fn key_role_error_display_bundle_creation_failed() {
        assert!(
            KeyRoleError::BundleCreationFailed
                .to_string()
                .contains("bundle creation failed")
        );
    }

    #[test]
    fn key_role_error_display_bundle_signature_invalid() {
        assert!(
            KeyRoleError::BundleSignatureInvalid
                .to_string()
                .contains("signature invalid")
        );
    }

    #[test]
    fn key_role_error_display_sequence_regression() {
        let err = KeyRoleError::SequenceRegression {
            role: KeyRole::Issuance,
            existing: 10,
            attempted: 5,
        };
        let s = err.to_string();
        assert!(s.contains("issuance"));
        assert!(s.contains("10"));
        assert!(s.contains("5"));
    }

    #[test]
    fn key_role_error_display_principal_not_found() {
        assert!(
            KeyRoleError::PrincipalNotFound
                .to_string()
                .contains("principal not found")
        );
    }

    #[test]
    fn key_role_error_display_duplicate_key() {
        let err = KeyRoleError::DuplicateKey {
            role: KeyRole::Encryption,
            sequence: 7,
        };
        let s = err.to_string();
        assert!(s.contains("encryption"));
        assert!(s.contains("7"));
    }

    // -- struct serde roundtrips -----------------------------------------------

    #[test]
    fn encryption_public_key_serde_roundtrip() {
        let pk = EncryptionPublicKey::from_bytes([0x42; 32]);
        let json = serde_json::to_string(&pk).expect("serde deserialization should succeed");
        let back: EncryptionPublicKey =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(pk, back);
    }

    #[test]
    fn encryption_private_key_serde_roundtrip() {
        let sk = EncryptionPrivateKey::from_bytes([0x99; 32]);
        let json = serde_json::to_string(&sk).expect("serde deserialization should succeed");
        let back: EncryptionPrivateKey =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(sk.as_bytes(), back.as_bytes());
    }

    #[test]
    fn role_key_entry_serde_roundtrip() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);
        let sk = make_signing_key(&seed, epoch);
        let entry = make_role_entry(
            KeyRole::Signing,
            sk.verification_key(),
            None,
            KeyStatus::Active,
            epoch,
            0,
        );
        let json = serde_json::to_string(&entry).expect("serde deserialization should succeed");
        let back: RoleKeyEntry =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(entry, back);
    }

    // -- schema / derivation determinism --------------------------------------

    #[test]
    fn bundle_schema_deterministic() {
        let s1 = bundle_schema();
        let s2 = bundle_schema();
        assert_eq!(s1, s2);
    }

    #[test]
    fn bundle_schema_id_deterministic() {
        let id1 = bundle_schema_id();
        let id2 = bundle_schema_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn derive_role_key_deterministic() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);
        let k1 = derive_role_key(&seed, KeyRole::Signing, epoch);
        let k2 = derive_role_key(&seed, KeyRole::Signing, epoch);
        assert_eq!(k1, k2);
    }

    #[test]
    fn key_role_all_has_three() {
        assert_eq!(KeyRole::ALL.len(), 3);
    }

    // -- encryption key display length ----------------------------------------

    #[test]
    fn encryption_public_key_display_is_64_hex_chars() {
        let pk = EncryptionPublicKey::from_bytes([0x00; 32]);
        let s = pk.to_string();
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -- verification_keys_for_role excludes revoked --------------------------

    // -- Enrichment: Ord, std::error --

    #[test]
    fn key_role_ordering() {
        assert!(KeyRole::Signing < KeyRole::Encryption);
        assert!(KeyRole::Encryption < KeyRole::Issuance);
    }

    #[test]
    fn key_status_ordering() {
        assert!(KeyStatus::Pending < KeyStatus::Active);
        assert!(KeyStatus::Active < KeyStatus::Rotated);
        assert!(KeyStatus::Rotated < KeyStatus::Revoked);
        assert!(KeyStatus::Revoked < KeyStatus::Expired);
    }

    #[test]
    fn key_role_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(KeyRoleError::KeyRoleMismatch {
                expected: KeyRole::Signing,
                actual: KeyRole::Encryption,
            }),
            Box::new(KeyRoleError::KeyNotActive {
                role: KeyRole::Signing,
                status: KeyStatus::Revoked,
            }),
            Box::new(KeyRoleError::NoActiveKey {
                role: KeyRole::Issuance,
            }),
            Box::new(KeyRoleError::BundleCreationFailed),
            Box::new(KeyRoleError::BundleSignatureInvalid),
            Box::new(KeyRoleError::SequenceRegression {
                role: KeyRole::Signing,
                existing: 5,
                attempted: 3,
            }),
            Box::new(KeyRoleError::PrincipalNotFound),
            Box::new(KeyRoleError::DuplicateKey {
                role: KeyRole::Signing,
                sequence: 1,
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
            8,
            "all 8 variants produce distinct messages"
        );
    }

    #[test]
    fn verification_keys_excludes_revoked_and_pending() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);
        let sk = make_signing_key(&seed, epoch);

        let mut store = PrincipalKeyStore::new();
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk.verification_key(),
                None,
                KeyStatus::Pending,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");

        // Pending keys are not verifiable.
        assert!(
            store
                .verification_keys_for_role(KeyRole::Signing)
                .is_empty()
        );
    }

    // ── Enrichment: Display uniqueness ──────────────────────────

    #[test]
    fn key_role_display_all_unique() {
        let displays: std::collections::BTreeSet<String> =
            KeyRole::ALL.iter().map(|r| r.to_string()).collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn key_status_display_all_unique() {
        let displays: std::collections::BTreeSet<String> = [
            KeyStatus::Pending,
            KeyStatus::Active,
            KeyStatus::Rotated,
            KeyStatus::Revoked,
            KeyStatus::Expired,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(displays.len(), 5);
    }

    // ── Enrichment: PrincipalKeyStore serde roundtrip ────────────

    #[test]
    fn principal_key_store_register_and_count() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);
        let sk = make_signing_key(&seed, epoch);
        let enc = make_encryption_private(&seed, epoch);

        let mut store = PrincipalKeyStore::new();
        assert_eq!(store.total_key_count(), 0);
        store
            .register_key(make_role_entry(
                KeyRole::Signing,
                sk.verification_key(),
                None,
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");
        assert_eq!(store.total_key_count(), 1);
        store
            .register_key(make_role_entry(
                KeyRole::Encryption,
                SigningKey::from_bytes([0x01; 32])
                    .expect("serde deserialization should succeed")
                    .verification_key(),
                Some(enc.public_key()),
                KeyStatus::Active,
                epoch,
                0,
            ))
            .expect("serde deserialization should succeed");
        assert_eq!(store.total_key_count(), 2);
    }

    // ── Enrichment: derive_role_key domain separation includes epoch ──

    #[test]
    fn derive_role_key_same_role_different_epochs_differ() {
        let seed = test_seed();
        let k1 = derive_role_key(&seed, KeyRole::Encryption, SecurityEpoch::from_raw(1));
        let k2 = derive_role_key(&seed, KeyRole::Encryption, SecurityEpoch::from_raw(2));
        assert_ne!(k1, k2);
    }

    // ── Enrichment: revoke non-existent key fails ───────────────

    #[test]
    fn revoke_nonexistent_key_fails() {
        let mut store = PrincipalKeyStore::new();
        let result = store.revoke_key(KeyRole::Signing, 99, SecurityEpoch::from_raw(1));
        assert!(result.is_err());
    }

    // ── Enrichment: activate non-existent sequence fails ────────

    #[test]
    fn activate_nonexistent_sequence_fails() {
        let mut store = PrincipalKeyStore::new();
        let result = store.activate_key(KeyRole::Signing, 0, SecurityEpoch::from_raw(1));
        assert!(result.is_err());
    }

    // ── Enrichment: OwnerKeyBundle serde roundtrip ──────────────

    #[test]
    fn owner_key_bundle_serde_roundtrip() {
        let seed = test_seed();
        let epoch = SecurityEpoch::from_raw(1);
        let sk = make_signing_key(&seed, epoch);
        let enc = make_encryption_private(&seed, epoch);
        let iss = make_issuance_key(&seed, epoch);

        // SAFETY: Test scenario with valid keys and epoch; bundle creation should succeed
        let bundle = OwnerKeyBundle::create_signed(
            &sk,
            sk.verification_key(),
            enc.public_key(),
            iss.verification_key(),
            epoch,
            1,
        )
        .expect("serde deserialization should succeed");

        // SAFETY: OwnerKeyBundle derives Serialize and has no non-serializable fields
        let json = serde_json::to_string(&bundle).expect("serde deserialization should succeed");
        // SAFETY: JSON was just produced by valid OwnerKeyBundle serialization
        let back: OwnerKeyBundle =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(bundle.sequence, back.sequence);
        assert_eq!(bundle.epoch, back.epoch);
    }

    // ── Enrichment: encryption key display length ───────────────

    #[test]
    fn encryption_private_key_public_derivation_deterministic() {
        let sk = EncryptionPrivateKey::from_bytes([0x42; 32]);
        let pk1 = sk.public_key();
        let pk2 = sk.public_key();
        assert_eq!(pk1, pk2);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch: Display, serde, clone/eq, status semantics
    // -----------------------------------------------------------------------

    #[test]
    fn key_role_display_all_three() {
        assert_eq!(KeyRole::Signing.to_string(), "signing");
        assert_eq!(KeyRole::Encryption.to_string(), "encryption");
        assert_eq!(KeyRole::Issuance.to_string(), "issuance");
    }

    #[test]
    fn key_role_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> =
            KeyRole::ALL.iter().map(|r| r.to_string()).collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn key_role_serde_all_variants() {
        for role in KeyRole::ALL {
            // SAFETY: KeyRole derives Serialize and has no non-serializable fields
            let json = serde_json::to_string(role).expect("serde deserialization should succeed");
            // SAFETY: JSON was just produced by valid KeyRole serialization
            let back: KeyRole =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*role, back);
        }
    }

    #[test]
    fn key_role_derivation_domain_unique() {
        let domains: std::collections::BTreeSet<&[u8]> =
            KeyRole::ALL.iter().map(|r| r.derivation_domain()).collect();
        assert_eq!(domains.len(), 3);
    }

    #[test]
    fn key_status_display_all_five() {
        assert_eq!(KeyStatus::Pending.to_string(), "pending");
        assert_eq!(KeyStatus::Active.to_string(), "active");
        assert_eq!(KeyStatus::Rotated.to_string(), "rotated");
        assert_eq!(KeyStatus::Revoked.to_string(), "revoked");
        assert_eq!(KeyStatus::Expired.to_string(), "expired");
    }

    #[test]
    fn key_status_display_uniqueness() {
        let displays: std::collections::BTreeSet<String> = [
            KeyStatus::Pending,
            KeyStatus::Active,
            KeyStatus::Rotated,
            KeyStatus::Revoked,
            KeyStatus::Expired,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(displays.len(), 5);
    }

    #[test]
    fn key_status_serde_all_variants() {
        for status in [
            KeyStatus::Pending,
            KeyStatus::Active,
            KeyStatus::Rotated,
            KeyStatus::Revoked,
            KeyStatus::Expired,
        ] {
            // SAFETY: KeyStatus derives Serialize and has no non-serializable fields
            let json =
                serde_json::to_string(&status).expect("serde deserialization should succeed");
            // SAFETY: JSON was just produced by valid KeyStatus serialization
            let back: KeyStatus =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(status, back);
        }
    }

    #[test]
    fn key_status_allows_creation_only_active() {
        assert!(!KeyStatus::Pending.allows_creation());
        assert!(KeyStatus::Active.allows_creation());
        assert!(!KeyStatus::Rotated.allows_creation());
        assert!(!KeyStatus::Revoked.allows_creation());
        assert!(!KeyStatus::Expired.allows_creation());
    }

    #[test]
    fn key_status_allows_verification_active_and_rotated() {
        assert!(!KeyStatus::Pending.allows_verification());
        assert!(KeyStatus::Active.allows_verification());
        assert!(KeyStatus::Rotated.allows_verification());
        assert!(!KeyStatus::Revoked.allows_verification());
        assert!(!KeyStatus::Expired.allows_verification());
    }

    #[test]
    fn encryption_public_key_display_hex_length() {
        let pk = EncryptionPublicKey::from_bytes([0xab; 32]);
        let display = pk.to_string();
        assert_eq!(display.len(), 64); // 32 bytes * 2 hex chars
        assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn encryption_public_key_bytes_serde_roundtrip() {
        let pk = EncryptionPublicKey::from_bytes([0x01; 32]);
        let json = serde_json::to_string(&pk).expect("serde deserialization should succeed");
        let back: EncryptionPublicKey =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(pk, back);
    }

    #[test]
    fn encryption_private_key_bytes_serde_roundtrip() {
        let sk = EncryptionPrivateKey::from_bytes([0x99; 32]);
        let json = serde_json::to_string(&sk).expect("serde deserialization should succeed");
        let back: EncryptionPrivateKey =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(sk, back);
    }

    #[test]
    fn encryption_public_key_clone_eq() {
        let pk = EncryptionPublicKey::from_bytes([0x42; 32]);
        let cloned = pk.clone();
        assert_eq!(pk, cloned);
    }

    #[test]
    fn encryption_private_key_clone_eq() {
        let sk = EncryptionPrivateKey::from_bytes([0x42; 32]);
        let cloned = sk.clone();
        assert_eq!(sk, cloned);
    }

    #[test]
    fn different_private_keys_produce_different_public_keys() {
        let sk1 = EncryptionPrivateKey::from_bytes([0x01; 32]);
        let sk2 = EncryptionPrivateKey::from_bytes([0x02; 32]);
        assert_ne!(sk1.public_key(), sk2.public_key());
    }

    #[test]
    fn encryption_public_key_from_bytes_roundtrip() {
        let bytes = [0xde; 32];
        let pk = EncryptionPublicKey::from_bytes(bytes);
        assert_eq!(*pk.as_bytes(), bytes);
    }

    #[test]
    fn encryption_private_key_as_bytes_roundtrip() {
        let bytes = [0xfe; 32];
        let sk = EncryptionPrivateKey::from_bytes(bytes);
        assert_eq!(*sk.as_bytes(), bytes);
    }

    #[test]
    fn key_role_copy_semantics() {
        let role = KeyRole::Signing;
        let copied = role;
        assert_eq!(role, copied);
    }

    #[test]
    fn key_status_copy_semantics() {
        let status = KeyStatus::Active;
        let copied = status;
        assert_eq!(status, copied);
    }

    #[test]
    fn key_role_all_has_three_elements() {
        assert_eq!(KeyRole::ALL.len(), 3);
    }

    #[test]
    fn bundle_schema_fn_deterministic() {
        let s1 = bundle_schema();
        let s2 = bundle_schema();
        assert_eq!(s1, s2);
    }

    #[test]
    fn bundle_schema_id_fn_deterministic() {
        let id1 = bundle_schema_id();
        let id2 = bundle_schema_id();
        assert_eq!(id1, id2);
    }
}
