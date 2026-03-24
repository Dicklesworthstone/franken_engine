//! Optional threshold-signing workflow for emergency operations.
//!
//! Provides a k-of-n threshold signing scheme for high-impact operations
//! such as key revocation, key rotation, and authority-set changes.
//! Instead of requiring a single owner key, threshold signing requires
//! cooperation of `k` out of `n` authorized share holders to produce
//! a valid combined signature.
//!
//! **Security model**: each share holder independently signs the preimage
//! with their own key.  The combined signature is the sorted set of `k`
//! individual signatures from authorized holders.  No single compromised
//! key can unilaterally authorize emergency operations.
//!
//! **Scope**: threshold signing is optional.  When not configured, the
//! system uses single-key signing.  Threshold is only required for
//! operations in `ThresholdScope`.
//!
//! Plan reference: Section 10.10 item 13, 9E.5 (threshold owner signing
//! for high-impact operations).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability_token::PrincipalId;
use crate::deterministic_serde::SchemaHash;
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::policy_checkpoint::DeterministicTimestamp;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    Signature, SigningKey, VerificationKey, sign_preimage, verify_signature,
};

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

const THRESHOLD_POLICY_SCHEMA_DEF: &[u8] = b"FrankenEngine.ThresholdSigningPolicy.v1";
const THRESHOLD_CEREMONY_SCHEMA_DEF: &[u8] = b"FrankenEngine.ThresholdCeremony.v1";

pub fn threshold_policy_schema() -> SchemaHash {
    SchemaHash::from_definition(THRESHOLD_POLICY_SCHEMA_DEF)
}

pub fn threshold_policy_schema_id() -> SchemaId {
    SchemaId::from_definition(THRESHOLD_POLICY_SCHEMA_DEF)
}

pub fn threshold_ceremony_schema_id() -> SchemaId {
    SchemaId::from_definition(THRESHOLD_CEREMONY_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// ThresholdScope — which operations require threshold signing
// ---------------------------------------------------------------------------

/// Operations that may require threshold signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ThresholdScope {
    /// Emergency key revocation.
    EmergencyRevocation,
    /// Key rotation (changing active keys for a principal).
    KeyRotation,
    /// Authority set changes (epoch transitions).
    AuthoritySetChange,
    /// High-severity policy checkpoint creation.
    PolicyCheckpoint,
}

impl ThresholdScope {
    /// All scope variants.
    pub const ALL: &'static [ThresholdScope] = &[
        ThresholdScope::EmergencyRevocation,
        ThresholdScope::KeyRotation,
        ThresholdScope::AuthoritySetChange,
        ThresholdScope::PolicyCheckpoint,
    ];
}

impl fmt::Display for ThresholdScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmergencyRevocation => write!(f, "emergency_revocation"),
            Self::KeyRotation => write!(f, "key_rotation"),
            Self::AuthoritySetChange => write!(f, "authority_set_change"),
            Self::PolicyCheckpoint => write!(f, "policy_checkpoint"),
        }
    }
}

// ---------------------------------------------------------------------------
// ShareHolderId — identifier for a threshold share holder
// ---------------------------------------------------------------------------

/// Unique identifier for a threshold share holder.
///
/// Derived from the share holder's verification key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ShareHolderId(pub [u8; 32]);

impl ShareHolderId {
    pub fn from_verification_key(vk: &VerificationKey) -> Self {
        Self(*vk.as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Display for ShareHolderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "share:{}", &self.to_hex()[..16])
    }
}

// ---------------------------------------------------------------------------
// ThresholdSigningPolicy — defines k-of-n requirements
// ---------------------------------------------------------------------------

/// Policy defining threshold signing requirements for a principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdSigningPolicy {
    /// Unique policy identity.
    pub policy_id: EngineObjectId,
    /// The principal this policy applies to.
    pub principal_id: PrincipalId,
    /// Minimum number of shares required (k).
    pub threshold_k: u32,
    /// Total number of authorized shares (n).
    pub total_n: u32,
    /// Authorized share holders (verification keys).
    pub authorized_shares: BTreeSet<ShareHolderId>,
    /// Which operations require threshold signing.
    pub scoped_operations: BTreeSet<ThresholdScope>,
    /// Epoch at which this policy was created.
    pub epoch: SecurityEpoch,
    /// Zone partition.
    pub zone: String,
}

/// Input for creating a threshold policy.
#[derive(Debug, Clone)]
pub struct CreateThresholdPolicyInput<'a> {
    pub principal_id: PrincipalId,
    pub threshold_k: u32,
    pub authorized_shares: BTreeSet<ShareHolderId>,
    pub scoped_operations: BTreeSet<ThresholdScope>,
    pub epoch: SecurityEpoch,
    pub zone: &'a str,
}

impl ThresholdSigningPolicy {
    /// Create a new threshold signing policy.
    pub fn create(input: CreateThresholdPolicyInput<'_>) -> Result<Self, ThresholdError> {
        let total_n = input.authorized_shares.len() as u32;

        if input.threshold_k == 0 {
            return Err(ThresholdError::InvalidThreshold {
                k: input.threshold_k,
                n: total_n,
                detail: "threshold k must be > 0".to_string(),
            });
        }

        if input.threshold_k > total_n {
            return Err(ThresholdError::InvalidThreshold {
                k: input.threshold_k,
                n: total_n,
                detail: "threshold k must be <= n".to_string(),
            });
        }

        if total_n < 2 {
            return Err(ThresholdError::InvalidThreshold {
                k: input.threshold_k,
                n: total_n,
                detail: "need at least 2 share holders".to_string(),
            });
        }

        if input.scoped_operations.is_empty() {
            return Err(ThresholdError::NoScopedOperations);
        }

        let mut canonical = Vec::new();
        canonical.extend_from_slice(input.principal_id.as_bytes());
        canonical.extend_from_slice(&input.threshold_k.to_be_bytes());
        canonical.extend_from_slice(&total_n.to_be_bytes());
        for share in &input.authorized_shares {
            canonical.extend_from_slice(share.as_bytes());
        }
        // Include scoped_operations (BTreeSet, deterministic iteration).
        for op in &input.scoped_operations {
            canonical.extend_from_slice(op.to_string().as_bytes());
        }
        canonical.extend_from_slice(input.zone.as_bytes());
        canonical.extend_from_slice(&input.epoch.as_u64().to_be_bytes());

        let policy_id = engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            input.zone,
            &threshold_policy_schema_id(),
            &canonical,
        )
        .map_err(|e| ThresholdError::IdDerivationFailed {
            detail: e.to_string(),
        })?;

        Ok(Self {
            policy_id,
            principal_id: input.principal_id,
            threshold_k: input.threshold_k,
            total_n,
            authorized_shares: input.authorized_shares,
            scoped_operations: input.scoped_operations,
            epoch: input.epoch,
            zone: input.zone.to_string(),
        })
    }

    /// Check if a given operation requires threshold signing.
    pub fn requires_threshold(&self, scope: ThresholdScope) -> bool {
        self.scoped_operations.contains(&scope)
    }

    /// Check if a share holder is authorized.
    pub fn is_authorized(&self, holder: &ShareHolderId) -> bool {
        self.authorized_shares.contains(holder)
    }
}

impl fmt::Display for ThresholdSigningPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ThresholdPolicy({}, {}-of-{}, scopes={})",
            self.policy_id,
            self.threshold_k,
            self.total_n,
            self.scoped_operations.len()
        )
    }
}

// ---------------------------------------------------------------------------
// PartialSignature — one share holder's contribution
// ---------------------------------------------------------------------------

/// A partial signature from a single share holder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialSignature {
    /// Who signed.
    pub signer: ShareHolderId,
    /// The signer's verification key.
    pub verification_key: VerificationKey,
    /// The individual signature.
    pub signature: Signature,
    /// When this partial signature was produced.
    pub signed_at: DeterministicTimestamp,
}

// ---------------------------------------------------------------------------
// ThresholdCeremony — collects partial signatures
// ---------------------------------------------------------------------------

/// A threshold signing ceremony that collects partial signatures until
/// the threshold is met.
///
/// The ceremony is scoped to a specific preimage (the data being signed).
/// Each authorized share holder independently signs the preimage and
/// submits their partial signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdCeremony {
    /// Unique ceremony identity.
    pub ceremony_id: EngineObjectId,
    /// Reference to the policy governing this ceremony.
    pub policy_id: EngineObjectId,
    /// The scope of the operation being authorized.
    pub scope: ThresholdScope,
    /// Required threshold (k).
    pub threshold_k: u32,
    /// The preimage being signed (hash of the actual data).
    pub preimage_hash: [u8; 32],
    /// Collected partial signatures.
    partial_signatures: BTreeMap<ShareHolderId, PartialSignature>,
    /// Authorized share holders for this ceremony.
    authorized_shares: BTreeSet<ShareHolderId>,
    /// When this ceremony was initiated.
    pub initiated_at: DeterministicTimestamp,
    /// Zone partition.
    pub zone: String,
    /// Whether the ceremony has been finalized.
    finalized: bool,
    /// Audit trail.
    events: Vec<ThresholdEvent>,
}

impl ThresholdCeremony {
    /// Create a new threshold ceremony.
    pub fn new(
        policy: &ThresholdSigningPolicy,
        scope: ThresholdScope,
        preimage: &[u8],
        initiated_at: DeterministicTimestamp,
    ) -> Result<Self, ThresholdError> {
        if !policy.requires_threshold(scope) {
            return Err(ThresholdError::ScopeNotThresholded { scope });
        }

        let preimage_hash = crate::hash_tiers::ContentHash::compute(preimage);

        let mut canonical = Vec::new();
        canonical.extend_from_slice(policy.policy_id.as_bytes());
        canonical.extend_from_slice(preimage_hash.as_bytes());
        canonical.extend_from_slice(&initiated_at.0.to_be_bytes());

        let ceremony_id = engine_object_id::derive_id(
            ObjectDomain::EvidenceRecord,
            &policy.zone,
            &threshold_ceremony_schema_id(),
            &canonical,
        )
        .map_err(|e| ThresholdError::IdDerivationFailed {
            detail: e.to_string(),
        })?;

        let mut ceremony = Self {
            ceremony_id,
            policy_id: policy.policy_id.clone(),
            scope,
            threshold_k: policy.threshold_k,
            preimage_hash: *preimage_hash.as_bytes(),
            partial_signatures: BTreeMap::new(),
            authorized_shares: policy.authorized_shares.clone(),
            initiated_at,
            zone: policy.zone.clone(),
            finalized: false,
            events: Vec::new(),
        };

        ceremony.emit_event(ThresholdEventType::CeremonyInitiated {
            scope,
            threshold_k: policy.threshold_k,
            total_authorized: policy.total_n,
        });

        Ok(ceremony)
    }

    /// Submit a partial signature from a share holder.
    pub fn submit_partial(
        &mut self,
        signer_key: &SigningKey,
        preimage: &[u8],
        signed_at: DeterministicTimestamp,
    ) -> Result<(), ThresholdError> {
        if self.finalized {
            return Err(ThresholdError::CeremonyAlreadyFinalized);
        }

        // Verify preimage matches.
        let hash = crate::hash_tiers::ContentHash::compute(preimage);
        if *hash.as_bytes() != self.preimage_hash {
            return Err(ThresholdError::PreimageMismatch);
        }

        let vk = signer_key.verification_key();
        let holder_id = ShareHolderId::from_verification_key(&vk);

        // Check authorization.
        if !self.authorized_shares.contains(&holder_id) {
            self.emit_event(ThresholdEventType::UnauthorizedSubmission {
                signer: holder_id.clone(),
            });
            return Err(ThresholdError::UnauthorizedShareHolder { holder: holder_id });
        }

        // Check for duplicate submission.
        if self.partial_signatures.contains_key(&holder_id) {
            return Err(ThresholdError::DuplicateSubmission { holder: holder_id });
        }

        // Sign the preimage.
        let signature =
            sign_preimage(signer_key, preimage).map_err(|e| ThresholdError::SigningFailed {
                detail: e.to_string(),
            })?;

        let partial = PartialSignature {
            signer: holder_id.clone(),
            verification_key: vk,
            signature,
            signed_at,
        };

        self.partial_signatures.insert(holder_id.clone(), partial);

        self.emit_event(ThresholdEventType::PartialSignatureSubmitted {
            signer: holder_id,
            signatures_collected: self.partial_signatures.len() as u32,
            threshold_k: self.threshold_k,
        });

        Ok(())
    }

    /// Check if the threshold has been met.
    pub fn is_threshold_met(&self) -> bool {
        self.partial_signatures.len() as u32 >= self.threshold_k
    }

    /// Number of partial signatures collected so far.
    pub fn signatures_collected(&self) -> u32 {
        self.partial_signatures.len() as u32
    }

    /// Finalize the ceremony if the threshold has been met.
    ///
    /// Returns the combined threshold result.
    pub fn finalize(&mut self, preimage: &[u8]) -> Result<ThresholdResult, ThresholdError> {
        if self.finalized {
            return Err(ThresholdError::CeremonyAlreadyFinalized);
        }

        if !self.is_threshold_met() {
            return Err(ThresholdError::InsufficientThresholdShares {
                collected: self.partial_signatures.len() as u32,
                required: self.threshold_k,
            });
        }

        // Verify all partial signatures against the preimage.
        for (holder_id, partial) in &self.partial_signatures {
            verify_signature(&partial.verification_key, preimage, &partial.signature).map_err(
                |_| ThresholdError::PartialSignatureInvalid {
                    holder: holder_id.clone(),
                },
            )?;
        }

        let participating_shares: Vec<ShareHolderId> =
            self.partial_signatures.keys().cloned().collect();

        let signatures: Vec<PartialSignature> = self.partial_signatures.values().cloned().collect();

        self.finalized = true;

        self.emit_event(ThresholdEventType::CeremonyFinalized {
            participants: participating_shares.clone(),
        });

        Ok(ThresholdResult {
            ceremony_id: self.ceremony_id.clone(),
            policy_id: self.policy_id.clone(),
            scope: self.scope,
            preimage_hash: self.preimage_hash,
            signatures,
            participating_shares,
            threshold_k: self.threshold_k,
        })
    }

    /// Get participating share holder IDs so far.
    pub fn participants(&self) -> Vec<&ShareHolderId> {
        self.partial_signatures.keys().collect()
    }

    /// Drain accumulated audit events.
    pub fn drain_events(&mut self) -> Vec<ThresholdEvent> {
        std::mem::take(&mut self.events)
    }

    fn emit_event(&mut self, event_type: ThresholdEventType) {
        self.events.push(ThresholdEvent {
            event_type,
            ceremony_id: self.ceremony_id.clone(),
            zone: self.zone.clone(),
        });
    }
}

// ---------------------------------------------------------------------------
// ThresholdResult — successful ceremony output
// ---------------------------------------------------------------------------

/// The result of a finalized threshold signing ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdResult {
    /// The ceremony that produced this result.
    pub ceremony_id: EngineObjectId,
    /// The policy that governed the ceremony.
    pub policy_id: EngineObjectId,
    /// The scope of the authorized operation.
    pub scope: ThresholdScope,
    /// Hash of the signed preimage.
    pub preimage_hash: [u8; 32],
    /// The collected partial signatures (sorted by share holder ID).
    pub signatures: Vec<PartialSignature>,
    /// Which share holders participated.
    pub participating_shares: Vec<ShareHolderId>,
    /// The threshold that was satisfied.
    pub threshold_k: u32,
}

impl ThresholdResult {
    /// Verify this result against the preimage.
    pub fn verify(&self, preimage: &[u8]) -> Result<(), ThresholdError> {
        // Check preimage hash matches.
        let hash = crate::hash_tiers::ContentHash::compute(preimage);
        if *hash.as_bytes() != self.preimage_hash {
            return Err(ThresholdError::PreimageMismatch);
        }

        // Check threshold is met.
        if (self.signatures.len() as u32) < self.threshold_k {
            return Err(ThresholdError::InsufficientThresholdShares {
                collected: self.signatures.len() as u32,
                required: self.threshold_k,
            });
        }

        // Verify each individual signature.
        for partial in &self.signatures {
            verify_signature(&partial.verification_key, preimage, &partial.signature).map_err(
                |_| ThresholdError::PartialSignatureInvalid {
                    holder: partial.signer.clone(),
                },
            )?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ShareRefreshResult — proactive share refresh
// ---------------------------------------------------------------------------

/// Result of a share refresh operation.
///
/// Share refresh generates new share holder keys while maintaining
/// the same threshold policy.  This limits exposure from share
/// compromise: old shares become useless after refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareRefreshResult {
    /// The policy ID that was refreshed.
    pub policy_id: EngineObjectId,
    /// Old share holder IDs that were replaced.
    pub old_shares: BTreeSet<ShareHolderId>,
    /// New share holder IDs.
    pub new_shares: BTreeSet<ShareHolderId>,
    /// Epoch at which the refresh occurred.
    pub refresh_epoch: SecurityEpoch,
}

/// Perform a proactive share refresh: replace all share holders with
/// new keys while maintaining the same threshold parameters.
pub fn refresh_shares(
    policy: &ThresholdSigningPolicy,
    new_share_keys: &[VerificationKey],
    refresh_epoch: SecurityEpoch,
) -> Result<(ThresholdSigningPolicy, ShareRefreshResult), ThresholdError> {
    if new_share_keys.len() != policy.total_n as usize {
        return Err(ThresholdError::InvalidThreshold {
            k: policy.threshold_k,
            n: new_share_keys.len() as u32,
            detail: format!(
                "new share count {} must match original n={}",
                new_share_keys.len(),
                policy.total_n
            ),
        });
    }

    let old_shares = policy.authorized_shares.clone();
    let new_shares: BTreeSet<ShareHolderId> = new_share_keys
        .iter()
        .map(ShareHolderId::from_verification_key)
        .collect();

    // Ensure no duplicate keys in new set.
    if new_shares.len() != new_share_keys.len() {
        return Err(ThresholdError::DuplicateShareHolder);
    }

    let new_policy = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
        principal_id: policy.principal_id.clone(),
        threshold_k: policy.threshold_k,
        authorized_shares: new_shares.clone(),
        scoped_operations: policy.scoped_operations.clone(),
        epoch: refresh_epoch,
        zone: &policy.zone,
    })?;

    let refresh_result = ShareRefreshResult {
        policy_id: policy.policy_id.clone(),
        old_shares,
        new_shares,
        refresh_epoch,
    };

    Ok((new_policy, refresh_result))
}

// ---------------------------------------------------------------------------
// ThresholdError
// ---------------------------------------------------------------------------

/// Errors from threshold signing operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdError {
    /// Invalid threshold parameters.
    InvalidThreshold { k: u32, n: u32, detail: String },
    /// Fewer than k shares submitted.
    InsufficientThresholdShares { collected: u32, required: u32 },
    /// Share holder is not authorized.
    UnauthorizedShareHolder { holder: ShareHolderId },
    /// Duplicate submission from the same share holder.
    DuplicateSubmission { holder: ShareHolderId },
    /// Duplicate share holder in the policy.
    DuplicateShareHolder,
    /// A partial signature failed verification.
    PartialSignatureInvalid { holder: ShareHolderId },
    /// Signing operation failed.
    SigningFailed { detail: String },
    /// ID derivation failed.
    IdDerivationFailed { detail: String },
    /// The ceremony has already been finalized.
    CeremonyAlreadyFinalized,
    /// The preimage hash does not match.
    PreimageMismatch,
    /// The operation scope is not covered by threshold policy.
    ScopeNotThresholded { scope: ThresholdScope },
    /// No scoped operations in the policy.
    NoScopedOperations,
}

impl fmt::Display for ThresholdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidThreshold { k, n, detail } => {
                write!(f, "invalid threshold {k}-of-{n}: {detail}")
            }
            Self::InsufficientThresholdShares {
                collected,
                required,
            } => {
                write!(f, "insufficient threshold shares: {collected}/{required}")
            }
            Self::UnauthorizedShareHolder { holder } => {
                write!(f, "unauthorized share holder: {holder}")
            }
            Self::DuplicateSubmission { holder } => {
                write!(f, "duplicate submission from: {holder}")
            }
            Self::DuplicateShareHolder => write!(f, "duplicate share holder"),
            Self::PartialSignatureInvalid { holder } => {
                write!(f, "partial signature invalid from: {holder}")
            }
            Self::SigningFailed { detail } => write!(f, "signing failed: {detail}"),
            Self::IdDerivationFailed { detail } => {
                write!(f, "id derivation failed: {detail}")
            }
            Self::CeremonyAlreadyFinalized => write!(f, "ceremony already finalized"),
            Self::PreimageMismatch => write!(f, "preimage hash mismatch"),
            Self::ScopeNotThresholded { scope } => {
                write!(f, "scope not thresholded: {scope}")
            }
            Self::NoScopedOperations => write!(f, "no scoped operations"),
        }
    }
}

impl std::error::Error for ThresholdError {}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

/// Audit event types for threshold signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdEventType {
    /// A ceremony was initiated.
    CeremonyInitiated {
        scope: ThresholdScope,
        threshold_k: u32,
        total_authorized: u32,
    },
    /// A partial signature was submitted.
    PartialSignatureSubmitted {
        signer: ShareHolderId,
        signatures_collected: u32,
        threshold_k: u32,
    },
    /// An unauthorized submission was attempted.
    UnauthorizedSubmission { signer: ShareHolderId },
    /// The ceremony was finalized successfully.
    CeremonyFinalized { participants: Vec<ShareHolderId> },
}

/// A threshold signing audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdEvent {
    pub event_type: ThresholdEventType,
    pub ceremony_id: EngineObjectId,
    pub zone: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ZONE: &str = "threshold-zone";
    const TEST_PREIMAGE: &[u8] = b"emergency-revocation-preimage-v1";

    fn make_share_keys(count: usize) -> Vec<SigningKey> {
        (0..count)
            .map(|i| SigningKey::from_bytes([(i + 10) as u8; 32]))
            .collect()
    }

    fn make_share_holder_ids(keys: &[SigningKey]) -> BTreeSet<ShareHolderId> {
        keys.iter()
            .map(|sk| ShareHolderId::from_verification_key(&sk.verification_key()))
            .collect()
    }

    fn make_scopes() -> BTreeSet<ThresholdScope> {
        let mut scopes = BTreeSet::new();
        scopes.insert(ThresholdScope::EmergencyRevocation);
        scopes.insert(ThresholdScope::KeyRotation);
        scopes
    }

    fn test_principal() -> PrincipalId {
        PrincipalId::from_bytes([0x42; 32])
    }

    fn create_test_policy(k: u32, keys: &[SigningKey]) -> ThresholdSigningPolicy {
        ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
            principal_id: test_principal(),
            threshold_k: k,
            authorized_shares: make_share_holder_ids(keys),
            scoped_operations: make_scopes(),
            epoch: SecurityEpoch::from_raw(1),
            zone: TEST_ZONE,
        })
        .expect("create policy")
    }

    // -------------------------------------------------------------------
    // Policy creation tests
    // -------------------------------------------------------------------

    #[test]
    fn create_policy_2_of_3() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        assert_eq!(policy.threshold_k, 2);
        assert_eq!(policy.total_n, 3);
        assert_eq!(policy.authorized_shares.len(), 3);
    }

    #[test]
    fn create_policy_3_of_5() {
        let keys = make_share_keys(5);
        let policy = create_test_policy(3, &keys);
        assert_eq!(policy.threshold_k, 3);
        assert_eq!(policy.total_n, 5);
    }

    #[test]
    fn create_policy_k_equals_n() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(3, &keys);
        assert_eq!(policy.threshold_k, 3);
        assert_eq!(policy.total_n, 3);
    }

    #[test]
    fn create_policy_zero_threshold_rejected() {
        let keys = make_share_keys(3);
        let result = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
            principal_id: test_principal(),
            threshold_k: 0,
            authorized_shares: make_share_holder_ids(&keys),
            scoped_operations: make_scopes(),
            epoch: SecurityEpoch::from_raw(1),
            zone: TEST_ZONE,
        });
        assert!(matches!(
            result,
            Err(ThresholdError::InvalidThreshold { .. })
        ));
    }

    #[test]
    fn create_policy_k_exceeds_n_rejected() {
        let keys = make_share_keys(3);
        let result = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
            principal_id: test_principal(),
            threshold_k: 4,
            authorized_shares: make_share_holder_ids(&keys),
            scoped_operations: make_scopes(),
            epoch: SecurityEpoch::from_raw(1),
            zone: TEST_ZONE,
        });
        assert!(matches!(
            result,
            Err(ThresholdError::InvalidThreshold { .. })
        ));
    }

    #[test]
    fn create_policy_single_share_rejected() {
        let keys = make_share_keys(1);
        let result = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
            principal_id: test_principal(),
            threshold_k: 1,
            authorized_shares: make_share_holder_ids(&keys),
            scoped_operations: make_scopes(),
            epoch: SecurityEpoch::from_raw(1),
            zone: TEST_ZONE,
        });
        assert!(matches!(
            result,
            Err(ThresholdError::InvalidThreshold { .. })
        ));
    }

    #[test]
    fn create_policy_no_scopes_rejected() {
        let keys = make_share_keys(3);
        let result = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
            principal_id: test_principal(),
            threshold_k: 2,
            authorized_shares: make_share_holder_ids(&keys),
            scoped_operations: BTreeSet::new(),
            epoch: SecurityEpoch::from_raw(1),
            zone: TEST_ZONE,
        });
        assert!(matches!(result, Err(ThresholdError::NoScopedOperations)));
    }

    #[test]
    fn policy_deterministic() {
        let keys = make_share_keys(3);
        let p1 = create_test_policy(2, &keys);
        let p2 = create_test_policy(2, &keys);
        assert_eq!(p1.policy_id, p2.policy_id);
    }

    #[test]
    fn policy_requires_threshold_check() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        assert!(policy.requires_threshold(ThresholdScope::EmergencyRevocation));
        assert!(policy.requires_threshold(ThresholdScope::KeyRotation));
        assert!(!policy.requires_threshold(ThresholdScope::AuthoritySetChange));
        assert!(!policy.requires_threshold(ThresholdScope::PolicyCheckpoint));
    }

    #[test]
    fn policy_authorized_check() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let holder = ShareHolderId::from_verification_key(&keys[0].verification_key());
        assert!(policy.is_authorized(&holder));
        let rogue = ShareHolderId(*VerificationKey::from_bytes([0xFF; 32]).as_bytes());
        assert!(!policy.is_authorized(&rogue));
    }

    // -------------------------------------------------------------------
    // Ceremony tests — basic flow
    // -------------------------------------------------------------------

    #[test]
    fn ceremony_2_of_3_succeeds() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .expect("new ceremony");

        assert!(!ceremony.is_threshold_met());
        assert_eq!(ceremony.signatures_collected(), 0);

        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .expect("partial 0");
        assert!(!ceremony.is_threshold_met());

        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
            .expect("partial 1");
        assert!(ceremony.is_threshold_met());

        let result = ceremony.finalize(TEST_PREIMAGE).expect("finalize");
        assert_eq!(result.threshold_k, 2);
        assert_eq!(result.signatures.len(), 2);
    }

    #[test]
    fn ceremony_3_of_5_succeeds() {
        let keys = make_share_keys(5);
        let policy = create_test_policy(3, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::KeyRotation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .expect("new ceremony");

        for (i, key) in keys.iter().take(3).enumerate() {
            ceremony
                .submit_partial(key, TEST_PREIMAGE, DeterministicTimestamp(1000 + i as u64))
                .expect("partial");
        }
        assert!(ceremony.is_threshold_met());

        let result = ceremony.finalize(TEST_PREIMAGE).expect("finalize");
        assert_eq!(result.signatures.len(), 3);
        assert_eq!(result.participating_shares.len(), 3);
    }

    #[test]
    fn ceremony_different_subsets_both_valid() {
        let keys = make_share_keys(4);
        let policy = create_test_policy(2, &keys);

        // Subset A: keys[0] and keys[1]
        let mut ceremony_a = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .expect("ceremony a");
        ceremony_a
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        ceremony_a
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
            .unwrap();
        let result_a = ceremony_a.finalize(TEST_PREIMAGE).expect("finalize a");

        // Subset B: keys[2] and keys[3]
        let mut ceremony_b = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(2000),
        )
        .expect("ceremony b");
        ceremony_b
            .submit_partial(&keys[2], TEST_PREIMAGE, DeterministicTimestamp(2001))
            .unwrap();
        ceremony_b
            .submit_partial(&keys[3], TEST_PREIMAGE, DeterministicTimestamp(2002))
            .unwrap();
        let result_b = ceremony_b.finalize(TEST_PREIMAGE).expect("finalize b");

        // Both should verify.
        result_a.verify(TEST_PREIMAGE).expect("verify a");
        result_b.verify(TEST_PREIMAGE).expect("verify b");
    }

    // -------------------------------------------------------------------
    // Ceremony tests — rejection cases
    // -------------------------------------------------------------------

    #[test]
    fn ceremony_insufficient_shares_rejected() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        // Only 1 of 2 required.
        let result = ceremony.finalize(TEST_PREIMAGE);
        assert!(matches!(
            result,
            Err(ThresholdError::InsufficientThresholdShares {
                collected: 1,
                required: 2
            })
        ));
    }

    #[test]
    fn ceremony_unauthorized_holder_rejected() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        let rogue_key = SigningKey::from_bytes([0xFF; 32]);
        let result =
            ceremony.submit_partial(&rogue_key, TEST_PREIMAGE, DeterministicTimestamp(1001));
        assert!(matches!(
            result,
            Err(ThresholdError::UnauthorizedShareHolder { .. })
        ));
    }

    #[test]
    fn ceremony_duplicate_submission_rejected() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        let result = ceremony.submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1002));
        assert!(matches!(
            result,
            Err(ThresholdError::DuplicateSubmission { .. })
        ));
    }

    #[test]
    fn ceremony_wrong_preimage_rejected() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        let result =
            ceremony.submit_partial(&keys[0], b"wrong-preimage", DeterministicTimestamp(1001));
        assert!(matches!(result, Err(ThresholdError::PreimageMismatch)));
    }

    #[test]
    fn ceremony_non_threshold_scope_rejected() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let result = ThresholdCeremony::new(
            &policy,
            ThresholdScope::AuthoritySetChange, // Not in scoped_operations
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        );
        assert!(matches!(
            result,
            Err(ThresholdError::ScopeNotThresholded { .. })
        ));
    }

    #[test]
    fn ceremony_finalize_twice_rejected() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
            .unwrap();

        ceremony.finalize(TEST_PREIMAGE).expect("first finalize");
        let result = ceremony.finalize(TEST_PREIMAGE);
        assert!(matches!(
            result,
            Err(ThresholdError::CeremonyAlreadyFinalized)
        ));
    }

    #[test]
    fn ceremony_submit_after_finalize_rejected() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
            .unwrap();
        ceremony.finalize(TEST_PREIMAGE).unwrap();

        let result = ceremony.submit_partial(&keys[2], TEST_PREIMAGE, DeterministicTimestamp(1003));
        assert!(matches!(
            result,
            Err(ThresholdError::CeremonyAlreadyFinalized)
        ));
    }

    // -------------------------------------------------------------------
    // Result verification tests
    // -------------------------------------------------------------------

    #[test]
    fn result_verify_succeeds() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
            .unwrap();

        let result = ceremony.finalize(TEST_PREIMAGE).unwrap();
        result.verify(TEST_PREIMAGE).expect("verify");
    }

    #[test]
    fn result_verify_wrong_preimage_fails() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
            .unwrap();

        let result = ceremony.finalize(TEST_PREIMAGE).unwrap();
        let verify_result = result.verify(b"wrong-preimage");
        assert!(matches!(
            verify_result,
            Err(ThresholdError::PreimageMismatch)
        ));
    }

    // -------------------------------------------------------------------
    // Share refresh tests
    // -------------------------------------------------------------------

    #[test]
    fn share_refresh_produces_new_policy() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let new_keys = make_share_keys(3)
            .into_iter()
            .enumerate()
            .map(|(i, _)| SigningKey::from_bytes([(i + 50) as u8; 32]))
            .collect::<Vec<_>>();
        let new_vks: Vec<VerificationKey> =
            new_keys.iter().map(|sk| sk.verification_key()).collect();

        let (new_policy, refresh_result) =
            refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2)).expect("refresh");

        assert_eq!(new_policy.threshold_k, 2);
        assert_eq!(new_policy.total_n, 3);
        assert_ne!(new_policy.policy_id, policy.policy_id);
        assert_eq!(new_policy.epoch, SecurityEpoch::from_raw(2));
        assert_eq!(refresh_result.old_shares.len(), 3);
        assert_eq!(refresh_result.new_shares.len(), 3);
    }

    #[test]
    fn share_refresh_wrong_count_rejected() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let new_vks: Vec<VerificationKey> = make_share_keys(2)
            .iter()
            .map(|sk| sk.verification_key())
            .collect();
        let result = refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2));
        assert!(matches!(
            result,
            Err(ThresholdError::InvalidThreshold { .. })
        ));
    }

    #[test]
    fn share_refresh_new_keys_work() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let new_keys: Vec<SigningKey> = (0..3)
            .map(|i| SigningKey::from_bytes([(i + 50) as u8; 32]))
            .collect();
        let new_vks: Vec<VerificationKey> =
            new_keys.iter().map(|sk| sk.verification_key()).collect();

        let (new_policy, _) =
            refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2)).unwrap();

        // New keys can sign a ceremony with the new policy.
        let mut ceremony = ThresholdCeremony::new(
            &new_policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(2000),
        )
        .unwrap();

        ceremony
            .submit_partial(&new_keys[0], TEST_PREIMAGE, DeterministicTimestamp(2001))
            .unwrap();
        ceremony
            .submit_partial(&new_keys[1], TEST_PREIMAGE, DeterministicTimestamp(2002))
            .unwrap();
        let result = ceremony.finalize(TEST_PREIMAGE).unwrap();
        result.verify(TEST_PREIMAGE).expect("verify with new keys");
    }

    #[test]
    fn share_refresh_old_keys_rejected_in_new_policy() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let new_keys: Vec<SigningKey> = (0..3)
            .map(|i| SigningKey::from_bytes([(i + 50) as u8; 32]))
            .collect();
        let new_vks: Vec<VerificationKey> =
            new_keys.iter().map(|sk| sk.verification_key()).collect();

        let (new_policy, _) =
            refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2)).unwrap();

        let mut ceremony = ThresholdCeremony::new(
            &new_policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(3000),
        )
        .unwrap();

        // Old key should be rejected.
        let result = ceremony.submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(3001));
        assert!(matches!(
            result,
            Err(ThresholdError::UnauthorizedShareHolder { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Audit event tests
    // -------------------------------------------------------------------

    #[test]
    fn audit_events_emitted_on_ceremony() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
            .unwrap();
        ceremony.finalize(TEST_PREIMAGE).unwrap();

        let events = ceremony.drain_events();
        assert_eq!(events.len(), 4); // init + 2 partials + finalize

        assert!(matches!(
            events[0].event_type,
            ThresholdEventType::CeremonyInitiated { .. }
        ));
        assert!(matches!(
            events[1].event_type,
            ThresholdEventType::PartialSignatureSubmitted { .. }
        ));
        assert!(matches!(
            events[2].event_type,
            ThresholdEventType::PartialSignatureSubmitted { .. }
        ));
        assert!(matches!(
            events[3].event_type,
            ThresholdEventType::CeremonyFinalized { .. }
        ));
    }

    #[test]
    fn audit_event_on_unauthorized_attempt() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        let rogue = SigningKey::from_bytes([0xFF; 32]);
        let _ = ceremony.submit_partial(&rogue, TEST_PREIMAGE, DeterministicTimestamp(1001));

        let events = ceremony.drain_events();
        // init + unauthorized
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[1].event_type,
            ThresholdEventType::UnauthorizedSubmission { .. }
        ));
    }

    #[test]
    fn finalized_event_includes_participant_ids() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        ceremony
            .submit_partial(&keys[2], TEST_PREIMAGE, DeterministicTimestamp(1002))
            .unwrap();
        ceremony.finalize(TEST_PREIMAGE).unwrap();

        let events = ceremony.drain_events();
        if let ThresholdEventType::CeremonyFinalized { participants } =
            &events.last().unwrap().event_type
        {
            assert_eq!(participants.len(), 2);
        } else {
            panic!("expected CeremonyFinalized event");
        }
    }

    // -------------------------------------------------------------------
    // Serialization tests
    // -------------------------------------------------------------------

    #[test]
    fn policy_serde_roundtrip() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let json = serde_json::to_string(&policy).expect("serialize");
        let restored: ThresholdSigningPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, restored);
    }

    #[test]
    fn result_serde_roundtrip() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();
        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
            .unwrap();
        let result = ceremony.finalize(TEST_PREIMAGE).unwrap();

        let json = serde_json::to_string(&result).expect("serialize");
        let restored: ThresholdResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, restored);
    }

    #[test]
    fn error_serde_roundtrip() {
        let errors: Vec<ThresholdError> = vec![
            ThresholdError::InsufficientThresholdShares {
                collected: 1,
                required: 2,
            },
            ThresholdError::CeremonyAlreadyFinalized,
            ThresholdError::PreimageMismatch,
            ThresholdError::NoScopedOperations,
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ThresholdError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -------------------------------------------------------------------
    // Display tests
    // -------------------------------------------------------------------

    #[test]
    fn scope_display() {
        assert_eq!(
            ThresholdScope::EmergencyRevocation.to_string(),
            "emergency_revocation"
        );
        assert_eq!(ThresholdScope::KeyRotation.to_string(), "key_rotation");
    }

    #[test]
    fn policy_display() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let display = policy.to_string();
        assert!(display.contains("2-of-3"));
    }

    #[test]
    fn error_display() {
        let err = ThresholdError::InsufficientThresholdShares {
            collected: 1,
            required: 3,
        };
        assert!(err.to_string().contains("1/3"));
    }

    #[test]
    fn share_holder_display() {
        let sk = SigningKey::from_bytes([0x42; 32]);
        let holder = ShareHolderId::from_verification_key(&sk.verification_key());
        let display = holder.to_string();
        assert!(display.starts_with("share:"));
    }

    // -------------------------------------------------------------------
    // Determinism tests
    // -------------------------------------------------------------------

    #[test]
    fn ceremony_deterministic() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);

        let run = || {
            let mut c = ThresholdCeremony::new(
                &policy,
                ThresholdScope::EmergencyRevocation,
                TEST_PREIMAGE,
                DeterministicTimestamp(1000),
            )
            .unwrap();
            c.submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
                .unwrap();
            c.submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
                .unwrap();
            c.finalize(TEST_PREIMAGE).unwrap()
        };

        let r1 = run();
        let r2 = run();
        assert_eq!(r1.ceremony_id, r2.ceremony_id);
        assert_eq!(r1.signatures.len(), r2.signatures.len());
        for (s1, s2) in r1.signatures.iter().zip(r2.signatures.iter()) {
            assert_eq!(s1.signature, s2.signature);
        }
    }

    // -------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------

    #[test]
    fn single_share_attempt_on_emergency_fails() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        // Try to finalize with only 1 share.
        let result = ceremony.finalize(TEST_PREIMAGE);
        assert!(matches!(
            result,
            Err(ThresholdError::InsufficientThresholdShares { .. })
        ));
    }

    #[test]
    fn all_shares_submitting_succeeds() {
        let keys = make_share_keys(5);
        let policy = create_test_policy(3, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        // All 5 submit.
        for (i, key) in keys.iter().enumerate() {
            ceremony
                .submit_partial(key, TEST_PREIMAGE, DeterministicTimestamp(1000 + i as u64))
                .unwrap();
        }
        assert_eq!(ceremony.signatures_collected(), 5);
        let result = ceremony.finalize(TEST_PREIMAGE).unwrap();
        assert_eq!(result.signatures.len(), 5);
        result.verify(TEST_PREIMAGE).expect("verify all");
    }

    #[test]
    fn participants_list_correct() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        ceremony
            .submit_partial(&keys[2], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        let participants = ceremony.participants();
        assert_eq!(participants.len(), 1);
        assert_eq!(
            *participants[0],
            ShareHolderId::from_verification_key(&keys[2].verification_key())
        );
    }

    // -- Enrichment: Ord, std::error --

    #[test]
    fn threshold_scope_ordering() {
        assert!(ThresholdScope::EmergencyRevocation < ThresholdScope::KeyRotation);
        assert!(ThresholdScope::KeyRotation < ThresholdScope::AuthoritySetChange);
        assert!(ThresholdScope::AuthoritySetChange < ThresholdScope::PolicyCheckpoint);
    }

    #[test]
    fn threshold_error_implements_std_error() {
        let holder = ShareHolderId([0xAA; 32]);
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ThresholdError::InvalidThreshold {
                k: 5,
                n: 3,
                detail: "k > n".into(),
            }),
            Box::new(ThresholdError::InsufficientThresholdShares {
                collected: 1,
                required: 3,
            }),
            Box::new(ThresholdError::UnauthorizedShareHolder {
                holder: holder.clone(),
            }),
            Box::new(ThresholdError::DuplicateSubmission {
                holder: holder.clone(),
            }),
            Box::new(ThresholdError::DuplicateShareHolder),
            Box::new(ThresholdError::PartialSignatureInvalid { holder }),
            Box::new(ThresholdError::SigningFailed {
                detail: "fail".into(),
            }),
            Box::new(ThresholdError::IdDerivationFailed {
                detail: "bad".into(),
            }),
            Box::new(ThresholdError::CeremonyAlreadyFinalized),
            Box::new(ThresholdError::PreimageMismatch),
            Box::new(ThresholdError::ScopeNotThresholded {
                scope: ThresholdScope::EmergencyRevocation,
            }),
            Box::new(ThresholdError::NoScopedOperations),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            12,
            "all 12 variants produce distinct messages"
        );
    }

    #[test]
    fn threshold_scope_all_variants() {
        assert_eq!(ThresholdScope::ALL.len(), 4);
    }

    // -- Enrichment: Display uniqueness, serde, edge cases --

    #[test]
    fn threshold_scope_display_uniqueness_btreeset() {
        let mut displays = BTreeSet::new();
        for scope in ThresholdScope::ALL {
            displays.insert(scope.to_string());
        }
        assert_eq!(displays.len(), ThresholdScope::ALL.len());
    }

    #[test]
    fn threshold_event_type_serde_roundtrip() {
        let holder =
            ShareHolderId::from_verification_key(&make_share_keys(1)[0].verification_key());
        let events = vec![
            ThresholdEventType::CeremonyInitiated {
                scope: ThresholdScope::EmergencyRevocation,
                threshold_k: 2,
                total_authorized: 3,
            },
            ThresholdEventType::PartialSignatureSubmitted {
                signer: holder.clone(),
                signatures_collected: 1,
                threshold_k: 2,
            },
            ThresholdEventType::CeremonyFinalized {
                participants: vec![holder.clone()],
            },
            ThresholdEventType::UnauthorizedSubmission { signer: holder },
        ];
        for evt in &events {
            let json = serde_json::to_string(evt).expect("serialize");
            let restored: ThresholdEventType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*evt, restored);
        }
    }

    #[test]
    fn threshold_result_verify_deterministic_across_runs() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let run = || {
            let mut c = ThresholdCeremony::new(
                &policy,
                ThresholdScope::EmergencyRevocation,
                TEST_PREIMAGE,
                DeterministicTimestamp(1000),
            )
            .unwrap();
            c.submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
                .unwrap();
            c.submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
                .unwrap();
            c.finalize(TEST_PREIMAGE).unwrap()
        };
        let r1 = run();
        let r2 = run();
        let json1 = serde_json::to_string(&r1).unwrap();
        let json2 = serde_json::to_string(&r2).unwrap();
        assert_eq!(json1, json2, "serialized results must be byte-identical");
    }

    #[test]
    fn share_holder_id_ord_deterministic() {
        let keys = make_share_keys(5);
        let holders: BTreeSet<ShareHolderId> = keys
            .iter()
            .map(|sk| ShareHolderId::from_verification_key(&sk.verification_key()))
            .collect();
        // BTreeSet guarantees deterministic ordering; re-collect and compare.
        let holders2: BTreeSet<ShareHolderId> = keys
            .iter()
            .map(|sk| ShareHolderId::from_verification_key(&sk.verification_key()))
            .collect();
        assert_eq!(
            holders.iter().collect::<Vec<_>>(),
            holders2.iter().collect::<Vec<_>>()
        );
    }

    #[test]
    fn policy_id_differs_for_different_principals() {
        let keys = make_share_keys(3);
        let p1 = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
            principal_id: PrincipalId::from_bytes([0x01; 32]),
            threshold_k: 2,
            authorized_shares: make_share_holder_ids(&keys),
            scoped_operations: make_scopes(),
            epoch: SecurityEpoch::from_raw(1),
            zone: TEST_ZONE,
        })
        .unwrap();
        let p2 = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
            principal_id: PrincipalId::from_bytes([0x02; 32]),
            threshold_k: 2,
            authorized_shares: make_share_holder_ids(&keys),
            scoped_operations: make_scopes(),
            epoch: SecurityEpoch::from_raw(1),
            zone: TEST_ZONE,
        })
        .unwrap();
        assert_ne!(p1.policy_id, p2.policy_id);
    }

    #[test]
    fn schema_ids_are_distinct() {
        let policy_schema = threshold_policy_schema_id();
        let ceremony_schema = threshold_ceremony_schema_id();
        assert_ne!(policy_schema, ceremony_schema);
    }

    #[test]
    fn ceremony_id_differs_for_different_timestamps() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let c1 = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();
        let c2 = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(2000),
        )
        .unwrap();
        assert_ne!(c1.ceremony_id, c2.ceremony_id);
    }

    // ── Enrichment: serde roundtrip tests ────────────────────────────

    #[test]
    fn threshold_scope_serde_roundtrip_all_variants() {
        for scope in ThresholdScope::ALL {
            let json = serde_json::to_string(scope).unwrap();
            let back: ThresholdScope = serde_json::from_str(&json).unwrap();
            assert_eq!(back, *scope);
        }
    }

    #[test]
    fn share_holder_id_serde_roundtrip() {
        let id = ShareHolderId([42u8; 32]);
        let json = serde_json::to_string(&id).unwrap();
        let back: ShareHolderId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn share_holder_id_display_hex_prefix() {
        let id = ShareHolderId([0xABu8; 32]);
        let s = id.to_string();
        assert!(s.starts_with("share:"));
        assert!(s.len() > 6); // "share:" + hex
    }

    #[test]
    fn share_holder_id_display_zeros() {
        let id = ShareHolderId([0u8; 32]);
        let s = id.to_string();
        assert!(s.starts_with("share:"));
        assert!(s.contains("0000"));
    }

    // ── Enrichment: clone equality ─────────────────────────────────────

    #[test]
    fn enrichment_policy_clone_equality() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let cloned = policy.clone();
        assert_eq!(policy.policy_id, cloned.policy_id);
        assert_eq!(policy.principal_id, cloned.principal_id);
        assert_eq!(policy.threshold_k, cloned.threshold_k);
        assert_eq!(policy.total_n, cloned.total_n);
        assert_eq!(policy.authorized_shares, cloned.authorized_shares);
        assert_eq!(policy.scoped_operations, cloned.scoped_operations);
        assert_eq!(policy.epoch, cloned.epoch);
        assert_eq!(policy.zone, cloned.zone);
    }

    #[test]
    fn enrichment_threshold_result_clone_equality() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();
        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
            .unwrap();
        let result = ceremony.finalize(TEST_PREIMAGE).unwrap();
        let cloned = result.clone();
        assert_eq!(result.ceremony_id, cloned.ceremony_id);
        assert_eq!(result.policy_id, cloned.policy_id);
        assert_eq!(result.scope, cloned.scope);
        assert_eq!(result.preimage_hash, cloned.preimage_hash);
        assert_eq!(result.signatures, cloned.signatures);
        assert_eq!(result.participating_shares, cloned.participating_shares);
        assert_eq!(result.threshold_k, cloned.threshold_k);
    }

    #[test]
    fn enrichment_share_refresh_result_clone_equality() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let new_keys: Vec<SigningKey> = (0..3)
            .map(|i| SigningKey::from_bytes([(i + 80) as u8; 32]))
            .collect();
        let new_vks: Vec<VerificationKey> =
            new_keys.iter().map(|sk| sk.verification_key()).collect();
        let (_, refresh) = refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(5)).unwrap();
        let cloned = refresh.clone();
        assert_eq!(refresh.policy_id, cloned.policy_id);
        assert_eq!(refresh.old_shares, cloned.old_shares);
        assert_eq!(refresh.new_shares, cloned.new_shares);
        assert_eq!(refresh.refresh_epoch, cloned.refresh_epoch);
    }

    #[test]
    fn enrichment_partial_signature_clone_equality() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();
        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
            .unwrap();
        let result = ceremony.finalize(TEST_PREIMAGE).unwrap();
        let partial = &result.signatures[0];
        let cloned = partial.clone();
        assert_eq!(partial.signer, cloned.signer);
        assert_eq!(partial.verification_key, cloned.verification_key);
        assert_eq!(partial.signature, cloned.signature);
        assert_eq!(partial.signed_at, cloned.signed_at);
    }

    #[test]
    fn enrichment_threshold_event_clone_equality() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();
        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        let events = ceremony.drain_events();
        assert!(!events.is_empty());
        let event = &events[0];
        let cloned = event.clone();
        assert_eq!(event.event_type, cloned.event_type);
        assert_eq!(event.ceremony_id, cloned.ceremony_id);
        assert_eq!(event.zone, cloned.zone);
    }

    // ── Enrichment: JSON field presence ────────────────────────────────

    #[test]
    fn enrichment_policy_json_field_presence() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"policy_id\""), "missing policy_id");
        assert!(json.contains("\"principal_id\""), "missing principal_id");
        assert!(json.contains("\"threshold_k\""), "missing threshold_k");
        assert!(json.contains("\"total_n\""), "missing total_n");
        assert!(
            json.contains("\"authorized_shares\""),
            "missing authorized_shares"
        );
        assert!(
            json.contains("\"scoped_operations\""),
            "missing scoped_operations"
        );
        assert!(json.contains("\"epoch\""), "missing epoch");
        assert!(json.contains("\"zone\""), "missing zone");
    }

    #[test]
    fn enrichment_threshold_result_json_field_presence() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();
        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(1001))
            .unwrap();
        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(1002))
            .unwrap();
        let result = ceremony.finalize(TEST_PREIMAGE).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"ceremony_id\""), "missing ceremony_id");
        assert!(json.contains("\"policy_id\""), "missing policy_id");
        assert!(json.contains("\"scope\""), "missing scope");
        assert!(json.contains("\"preimage_hash\""), "missing preimage_hash");
        assert!(json.contains("\"signatures\""), "missing signatures");
        assert!(
            json.contains("\"participating_shares\""),
            "missing participating_shares"
        );
        assert!(json.contains("\"threshold_k\""), "missing threshold_k");
    }

    #[test]
    fn enrichment_share_refresh_result_json_field_presence() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let new_keys: Vec<SigningKey> = (0..3)
            .map(|i| SigningKey::from_bytes([(i + 80) as u8; 32]))
            .collect();
        let new_vks: Vec<VerificationKey> =
            new_keys.iter().map(|sk| sk.verification_key()).collect();
        let (_, refresh) = refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(5)).unwrap();
        let json = serde_json::to_string(&refresh).unwrap();
        assert!(json.contains("\"policy_id\""), "missing policy_id");
        assert!(json.contains("\"old_shares\""), "missing old_shares");
        assert!(json.contains("\"new_shares\""), "missing new_shares");
        assert!(json.contains("\"refresh_epoch\""), "missing refresh_epoch");
    }

    // ── Enrichment: serde roundtrip ────────────────────────────────────

    #[test]
    fn enrichment_ceremony_serde_roundtrip() {
        // NOTE: ThresholdCeremony contains BTreeMap<ShareHolderId, PartialSignature>
        // where ShareHolderId([u8; 32]) is not a valid JSON map key.
        // Test roundtrip on a ceremony with no partial signatures collected
        // (empty BTreeMap serializes fine as `{}`).
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();
        let json = serde_json::to_string(&ceremony).unwrap();
        let restored: ThresholdCeremony = serde_json::from_str(&json).unwrap();
        assert_eq!(ceremony.ceremony_id, restored.ceremony_id);
        assert_eq!(ceremony.policy_id, restored.policy_id);
        assert_eq!(ceremony.scope, restored.scope);
        assert_eq!(ceremony.threshold_k, restored.threshold_k);
        assert_eq!(ceremony.preimage_hash, restored.preimage_hash);
        assert_eq!(ceremony.initiated_at, restored.initiated_at);
        assert_eq!(ceremony.zone, restored.zone);
        assert_eq!(
            ceremony.signatures_collected(),
            restored.signatures_collected()
        );
    }

    // ── Enrichment: Display uniqueness ─────────────────────────────────

    #[test]
    fn enrichment_error_display_all_variants_unique() {
        let holder_a = ShareHolderId([0xAAu8; 32]);
        let holder_b = ShareHolderId([0xBBu8; 32]);
        let all_errors = vec![
            ThresholdError::InvalidThreshold {
                k: 5,
                n: 3,
                detail: "test".into(),
            },
            ThresholdError::InsufficientThresholdShares {
                collected: 1,
                required: 3,
            },
            ThresholdError::UnauthorizedShareHolder {
                holder: holder_a.clone(),
            },
            ThresholdError::DuplicateSubmission {
                holder: holder_a.clone(),
            },
            ThresholdError::DuplicateShareHolder,
            ThresholdError::PartialSignatureInvalid { holder: holder_b },
            ThresholdError::SigningFailed {
                detail: "oops".into(),
            },
            ThresholdError::IdDerivationFailed {
                detail: "bad id".into(),
            },
            ThresholdError::CeremonyAlreadyFinalized,
            ThresholdError::PreimageMismatch,
            ThresholdError::ScopeNotThresholded {
                scope: ThresholdScope::KeyRotation,
            },
            ThresholdError::NoScopedOperations,
        ];
        let displays: BTreeSet<String> = all_errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            displays.len(),
            all_errors.len(),
            "all Display strings must be unique"
        );
    }

    // ── Enrichment: boundary conditions ────────────────────────────────

    #[test]
    fn enrichment_policy_id_differs_for_different_epochs() {
        let keys = make_share_keys(3);
        let p1 = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
            principal_id: test_principal(),
            threshold_k: 2,
            authorized_shares: make_share_holder_ids(&keys),
            scoped_operations: make_scopes(),
            epoch: SecurityEpoch::from_raw(1),
            zone: TEST_ZONE,
        })
        .unwrap();
        let p2 = ThresholdSigningPolicy::create(CreateThresholdPolicyInput {
            principal_id: test_principal(),
            threshold_k: 2,
            authorized_shares: make_share_holder_ids(&keys),
            scoped_operations: make_scopes(),
            epoch: SecurityEpoch::from_raw(2),
            zone: TEST_ZONE,
        })
        .unwrap();
        assert_ne!(
            p1.policy_id, p2.policy_id,
            "different epoch must produce different policy_id"
        );
    }

    // ── Enrichment: Ord / Error source ─────────────────────────────────

    #[test]
    fn enrichment_share_holder_id_ord_consistent_with_eq() {
        let a = ShareHolderId([0x01u8; 32]);
        let b = ShareHolderId([0x02u8; 32]);
        let c = ShareHolderId([0x01u8; 32]);
        // a == c, a < b
        assert_eq!(a, c);
        assert!(a < b);
        assert!(b > a);
        // Ordering should be transitive with BTreeSet
        let mut set = BTreeSet::new();
        set.insert(b.clone());
        set.insert(a.clone());
        set.insert(c.clone());
        assert_eq!(set.len(), 2, "a == c so only 2 distinct entries");
        let ordered: Vec<_> = set.into_iter().collect();
        assert!(ordered[0] < ordered[1], "BTreeSet preserves ordering");
    }

    // ── Empty preimage ceremony ───────────────────────────────────────

    #[test]
    fn ceremony_with_empty_preimage() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            b"",
            DeterministicTimestamp(1000),
        );
        assert!(ceremony.is_ok());
    }

    // ── k=n ceremony with one missing share ───────────────────────────

    #[test]
    fn k_equals_n_ceremony_missing_one_fails() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(3, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        // Submit only 2 of 3.
        for key in &keys[..2] {
            ceremony
                .submit_partial(key, TEST_PREIMAGE, DeterministicTimestamp(2000))
                .unwrap();
        }
        assert!(!ceremony.is_threshold_met());
        let err = ceremony.finalize(TEST_PREIMAGE).unwrap_err();
        assert!(matches!(
            err,
            ThresholdError::InsufficientThresholdShares { .. }
        ));
    }

    // ── requires_threshold returns false for unlisted scope ───────────

    #[test]
    fn requires_threshold_returns_false_for_unlisted_scope() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        // make_scopes() only includes EmergencyRevocation and KeyRotation.
        assert!(!policy.requires_threshold(ThresholdScope::PolicyCheckpoint));
        assert!(!policy.requires_threshold(ThresholdScope::AuthoritySetChange));
    }

    // ── is_authorized returns false for unknown holder ────────────────

    #[test]
    fn is_authorized_false_for_unknown_holder() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let unknown = ShareHolderId([0xffu8; 32]);
        assert!(!policy.is_authorized(&unknown));
    }

    // ── Share holder hex display ──────────────────────────────────────

    #[test]
    fn share_holder_to_hex_length() {
        let holder = ShareHolderId([0xab; 32]);
        let hex = holder.to_hex();
        assert_eq!(hex.len(), 64); // 32 bytes × 2 hex chars
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn share_holder_display_prefix() {
        let holder = ShareHolderId([0xcd; 32]);
        let display = holder.to_string();
        assert!(display.starts_with("share:"));
        // Display truncates to first 16 hex chars.
        assert_eq!(display.len(), "share:".len() + 16);
    }

    // ── Policy display format ─────────────────────────────────────────

    #[test]
    fn policy_display_format() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let display = policy.to_string();
        assert!(display.contains("2-of-3"));
        assert!(display.contains("scopes=2"));
        assert!(display.starts_with("ThresholdPolicy("));
    }

    // ── signatures_collected counts ───────────────────────────────────

    #[test]
    fn signatures_collected_increments() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::KeyRotation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        assert_eq!(ceremony.signatures_collected(), 0);
        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(2000))
            .unwrap();
        assert_eq!(ceremony.signatures_collected(), 1);
        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(3000))
            .unwrap();
        assert_eq!(ceremony.signatures_collected(), 2);
    }

    // ── participants list ─────────────────────────────────────────────

    #[test]
    fn participants_returns_submitters() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        assert!(ceremony.participants().is_empty());
        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(2000))
            .unwrap();
        assert_eq!(ceremony.participants().len(), 1);
    }

    // ── drain_events does not affect ceremony state ───────────────────

    #[test]
    fn drain_events_preserves_ceremony_state() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(2000))
            .unwrap();
        let events = ceremony.drain_events();
        assert!(!events.is_empty());
        // Ceremony state unchanged — can still submit and finalize.
        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(3000))
            .unwrap();
        assert!(ceremony.is_threshold_met());
        let result = ceremony.finalize(TEST_PREIMAGE);
        assert!(result.is_ok());
    }

    // ── ThresholdResult verify catches wrong hash ─────────────────────

    #[test]
    fn threshold_result_verify_wrong_preimage() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();
        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(2000))
            .unwrap();
        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(3000))
            .unwrap();
        let result = ceremony.finalize(TEST_PREIMAGE).unwrap();
        let err = result.verify(b"wrong-preimage").unwrap_err();
        assert!(matches!(err, ThresholdError::PreimageMismatch));
    }

    // ── ThresholdResult verify checks threshold count ─────────────────

    #[test]
    fn threshold_result_verify_success() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();
        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(2000))
            .unwrap();
        ceremony
            .submit_partial(&keys[1], TEST_PREIMAGE, DeterministicTimestamp(3000))
            .unwrap();
        let result = ceremony.finalize(TEST_PREIMAGE).unwrap();
        assert!(result.verify(TEST_PREIMAGE).is_ok());
        assert_eq!(result.threshold_k, 2);
        assert_eq!(result.signatures.len(), 2);
        assert_eq!(result.participating_shares.len(), 2);
    }

    // ── Error display coverage ────────────────────────────────────────

    #[test]
    fn error_display_insufficient_shares() {
        let err = ThresholdError::InsufficientThresholdShares {
            collected: 1,
            required: 3,
        };
        let msg = err.to_string();
        assert!(msg.contains('1'));
        assert!(msg.contains('3'));
    }

    #[test]
    fn error_display_preimage_mismatch() {
        let err = ThresholdError::PreimageMismatch;
        let msg = err.to_string();
        assert!(msg.contains("preimage"));
    }

    #[test]
    fn error_display_ceremony_already_finalized() {
        let err = ThresholdError::CeremonyAlreadyFinalized;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn error_display_no_scoped_operations() {
        let err = ThresholdError::NoScopedOperations;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn error_display_scope_not_thresholded() {
        let err = ThresholdError::ScopeNotThresholded {
            scope: ThresholdScope::PolicyCheckpoint,
        };
        let msg = err.to_string();
        assert!(msg.contains("policy_checkpoint"));
    }

    // ── Schema stability ──────────────────────────────────────────────

    #[test]
    fn schema_ids_are_stable() {
        let s1 = threshold_policy_schema_id();
        let s2 = threshold_policy_schema_id();
        assert_eq!(s1, s2);
        let c1 = threshold_ceremony_schema_id();
        let c2 = threshold_ceremony_schema_id();
        assert_eq!(c1, c2);
    }

    #[test]
    fn schema_hash_stable() {
        let h1 = threshold_policy_schema();
        let h2 = threshold_policy_schema();
        assert_eq!(h1, h2);
    }

    // ── ThresholdScope ALL constant ───────────────────────────────────

    #[test]
    fn threshold_scope_all_contains_four() {
        assert_eq!(ThresholdScope::ALL.len(), 4);
        assert!(ThresholdScope::ALL.contains(&ThresholdScope::EmergencyRevocation));
        assert!(ThresholdScope::ALL.contains(&ThresholdScope::KeyRotation));
        assert!(ThresholdScope::ALL.contains(&ThresholdScope::AuthoritySetChange));
        assert!(ThresholdScope::ALL.contains(&ThresholdScope::PolicyCheckpoint));
    }

    // ── Share refresh preserves k ─────────────────────────────────────

    #[test]
    fn share_refresh_preserves_threshold_k() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let new_keys = make_share_keys(3);
        let new_vks: Vec<_> = new_keys.iter().map(|k| k.verification_key()).collect();
        let (new_policy, _) =
            refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2)).unwrap();
        assert_eq!(new_policy.threshold_k, policy.threshold_k);
        assert_eq!(new_policy.total_n, policy.total_n);
    }

    // ── Share refresh wrong count ─────────────────────────────────────

    #[test]
    fn share_refresh_wrong_count_fails() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let new_keys = make_share_keys(4); // 4 != 3
        let new_vks: Vec<_> = new_keys.iter().map(|k| k.verification_key()).collect();
        let err = refresh_shares(&policy, &new_vks, SecurityEpoch::from_raw(2)).unwrap_err();
        assert!(matches!(err, ThresholdError::InvalidThreshold { .. }));
    }

    // ── Ceremony event types ──────────────────────────────────────────

    #[test]
    fn ceremony_events_include_initiated() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();

        let events = ceremony.drain_events();
        assert!(
            events
                .iter()
                .any(|e| matches!(e.event_type, ThresholdEventType::CeremonyInitiated { .. }))
        );
    }

    #[test]
    fn ceremony_events_include_submission() {
        let keys = make_share_keys(3);
        let policy = create_test_policy(2, &keys);
        let mut ceremony = ThresholdCeremony::new(
            &policy,
            ThresholdScope::EmergencyRevocation,
            TEST_PREIMAGE,
            DeterministicTimestamp(1000),
        )
        .unwrap();
        ceremony
            .submit_partial(&keys[0], TEST_PREIMAGE, DeterministicTimestamp(2000))
            .unwrap();

        let events = ceremony.drain_events();
        assert!(events.iter().any(|e| matches!(
            e.event_type,
            ThresholdEventType::PartialSignatureSubmitted { .. }
        )));
    }
}
