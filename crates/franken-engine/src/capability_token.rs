//! Extended capability tokens with audience, temporal validity, checkpoint
//! binding, and revocation freshness binding.
//!
//! Each token is a cryptographically-bound, temporally-scoped, context-aware
//! authority assertion.  All extended fields are included in the signature
//! preimage — modifying any field invalidates the signature.
//!
//! Verification order:
//! 1. Signature
//! 2. Canonicality
//! 3. Audience
//! 4. Temporal validity (nbf, expiry)
//! 5. Checkpoint binding
//! 6. Revocation freshness binding
//! 7. Revocation status (deferred to caller)
//!
//! Plan references: Section 10.10 item 9, 9E.4 (authority chain hardening
//! with non-ambient capability delegation).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::RuntimeCapability;
use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::policy_checkpoint::DeterministicTimestamp;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_preimage,
    verify_signature,
};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const TOKEN_SCHEMA_DEF: &[u8] = b"FrankenEngine.CapabilityToken.v2";

pub fn token_schema() -> SchemaHash {
    SchemaHash::from_definition(TOKEN_SCHEMA_DEF)
}

pub fn token_schema_id() -> SchemaId {
    SchemaId::from_definition(TOKEN_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// PrincipalId — identifies a token audience member
// ---------------------------------------------------------------------------

/// Identifies a principal (actor) in the system.
///
/// Derived from a verification key or other stable identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PrincipalId(pub [u8; 32]);

impl PrincipalId {
    pub fn from_verification_key(vk: &VerificationKey) -> Self {
        Self(ContentHash::compute(vk.as_bytes()).as_bytes().to_owned())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in &self.0 {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "principal:{}", &self.to_hex()[..8])
    }
}

// ---------------------------------------------------------------------------
// TokenId — unique token identifier (jti)
// ---------------------------------------------------------------------------

/// Unique token identifier for revocation lookup and replay detection.
///
/// Derived via EngineObjectId from the unsigned view.
pub type TokenId = EngineObjectId;

// ---------------------------------------------------------------------------
// CheckpointRef — checkpoint frontier binding
// ---------------------------------------------------------------------------

/// Reference to a minimum checkpoint frontier state.
///
/// The token is invalid if the verifier's frontier is below this checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointRef {
    /// Minimum checkpoint sequence the verifier must have accepted.
    pub min_checkpoint_seq: u64,
    /// The checkpoint ID that established this binding.
    pub checkpoint_id: EngineObjectId,
}

// ---------------------------------------------------------------------------
// RevocationFreshnessRef — revocation head binding
// ---------------------------------------------------------------------------

/// Reference to a minimum revocation head state.
///
/// The token is invalid if the verifier's revocation head is older than
/// this reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationFreshnessRef {
    /// Minimum revocation head sequence.
    pub min_revocation_seq: u64,
    /// Content hash of the revocation head at the reference point.
    pub revocation_head_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// TokenVersion — format version discriminator
// ---------------------------------------------------------------------------

/// Token format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TokenVersion {
    /// Extended token format with all bindings.
    V2,
}

impl fmt::Display for TokenVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V2 => write!(f, "v2"),
        }
    }
}

// ---------------------------------------------------------------------------
// TokenError — verification failure codes
// ---------------------------------------------------------------------------

/// Typed error for token verification failures.
///
/// Each variant corresponds to a specific verification stage, ordered
/// by verification priority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenError {
    /// Signature verification failed.
    SignatureInvalid { detail: String },
    /// Canonicality check failed.
    NonCanonical { detail: String },
    /// Presenter is not in the audience list.
    AudienceRejected {
        presenter: PrincipalId,
        audience_size: usize,
    },
    /// Token is not yet valid (current time < nbf).
    NotYetValid { current_tick: u64, not_before: u64 },
    /// Token has expired (current time > expiry).
    Expired { current_tick: u64, expiry: u64 },
    /// Verifier's checkpoint frontier is below the token's binding.
    CheckpointBindingFailed {
        required_seq: u64,
        verifier_seq: u64,
    },
    /// Verifier's revocation head is stale relative to the token's binding.
    RevocationFreshnessStale {
        required_seq: u64,
        verifier_seq: u64,
    },
    /// Token version not supported.
    UnsupportedVersion { version: String },
    /// ID derivation failed.
    IdDerivationFailed { detail: String },
    /// Temporal validity window is inverted (nbf > expiry).
    InvertedTemporalWindow { not_before: u64, expiry: u64 },
    /// Empty capabilities.
    EmptyCapabilities,
    /// Empty audience — tokens must bind to at least one audience principal.
    EmptyAudience,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignatureInvalid { detail } => {
                write!(f, "signature invalid: {detail}")
            }
            Self::NonCanonical { detail } => write!(f, "non-canonical: {detail}"),
            Self::AudienceRejected {
                presenter,
                audience_size,
            } => write!(
                f,
                "audience rejected: {presenter} not in {audience_size} audience members"
            ),
            Self::NotYetValid {
                current_tick,
                not_before,
            } => write!(
                f,
                "not yet valid: current tick={current_tick}, nbf={not_before}"
            ),
            Self::Expired {
                current_tick,
                expiry,
            } => write!(f, "expired: current tick={current_tick}, expiry={expiry}"),
            Self::CheckpointBindingFailed {
                required_seq,
                verifier_seq,
            } => write!(
                f,
                "checkpoint binding failed: required seq={required_seq}, \
                 verifier seq={verifier_seq}"
            ),
            Self::RevocationFreshnessStale {
                required_seq,
                verifier_seq,
            } => write!(
                f,
                "revocation freshness stale: required seq={required_seq}, \
                 verifier seq={verifier_seq}"
            ),
            Self::UnsupportedVersion { version } => {
                write!(f, "unsupported version: {version}")
            }
            Self::IdDerivationFailed { detail } => {
                write!(f, "ID derivation failed: {detail}")
            }
            Self::InvertedTemporalWindow { not_before, expiry } => {
                write!(
                    f,
                    "inverted temporal window: nbf={not_before} > expiry={expiry}"
                )
            }
            Self::EmptyCapabilities => write!(f, "empty capabilities"),
            Self::EmptyAudience => write!(f, "empty audience"),
        }
    }
}

impl std::error::Error for TokenError {}

// ---------------------------------------------------------------------------
// CapabilityToken — the extended token
// ---------------------------------------------------------------------------

/// An extended capability token with all context bindings.
///
/// Immutable after creation. The `jti` is derived from the unsigned view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Token format version.
    pub version: TokenVersion,
    /// Unique token identifier.
    pub jti: TokenId,
    /// The issuer's verification key.
    pub issuer: VerificationKey,
    /// Principals authorized to use this token.
    pub audience: BTreeSet<PrincipalId>,
    /// Granted capabilities.
    pub capabilities: BTreeSet<RuntimeCapability>,
    /// Not-before timestamp (token invalid before this tick).
    pub nbf: DeterministicTimestamp,
    /// Expiry timestamp (token invalid after this tick).
    pub expiry: DeterministicTimestamp,
    /// Security epoch at issuance.
    pub epoch: SecurityEpoch,
    /// Checkpoint frontier binding (if set).
    pub checkpoint_binding: Option<CheckpointRef>,
    /// Revocation freshness binding (if set).
    pub revocation_freshness: Option<RevocationFreshnessRef>,
    /// Token signature.
    pub signature: Signature,
    /// Zone this token is scoped to.
    pub zone: String,
}

impl SignaturePreimage for CapabilityToken {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::CapabilityToken
    }

    fn signature_schema(&self) -> &SchemaHash {
        unreachable!("use preimage_bytes() directly")
    }

    fn unsigned_view(&self) -> CanonicalValue {
        build_unsigned_view(self)
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let schema = token_schema();
        let domain_tag = ObjectDomain::CapabilityToken.tag();
        let unsigned = self.unsigned_view();
        let value_bytes = deterministic_serde::encode_value(&unsigned);

        let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
        preimage.extend_from_slice(domain_tag);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&value_bytes);
        preimage
    }
}

// ---------------------------------------------------------------------------
// Unsigned view
// ---------------------------------------------------------------------------

fn build_unsigned_view(token: &CapabilityToken) -> CanonicalValue {
    let mut map = BTreeMap::new();

    // audience (sorted set of hex-encoded principal IDs)
    let audience_arr: Vec<CanonicalValue> = token
        .audience
        .iter()
        .map(|p| CanonicalValue::Bytes(p.0.to_vec()))
        .collect();
    map.insert("audience".to_string(), CanonicalValue::Array(audience_arr));

    // capabilities (sorted by Display name)
    let caps_arr: Vec<CanonicalValue> = token
        .capabilities
        .iter()
        .map(|c| CanonicalValue::String(c.to_string()))
        .collect();
    map.insert("capabilities".to_string(), CanonicalValue::Array(caps_arr));

    // checkpoint_binding
    match &token.checkpoint_binding {
        Some(binding) => {
            let mut bm = BTreeMap::new();
            bm.insert(
                "checkpoint_id".to_string(),
                CanonicalValue::Bytes(binding.checkpoint_id.as_bytes().to_vec()),
            );
            bm.insert(
                "min_checkpoint_seq".to_string(),
                CanonicalValue::U64(binding.min_checkpoint_seq),
            );
            map.insert("checkpoint_binding".to_string(), CanonicalValue::Map(bm));
        }
        None => {
            map.insert("checkpoint_binding".to_string(), CanonicalValue::Null);
        }
    }

    // epoch
    map.insert(
        "epoch".to_string(),
        CanonicalValue::U64(token.epoch.as_u64()),
    );

    // expiry
    map.insert("expiry".to_string(), CanonicalValue::U64(token.expiry.0));

    // issuer
    map.insert(
        "issuer".to_string(),
        CanonicalValue::Bytes(token.issuer.as_bytes().to_vec()),
    );

    // jti (unique token identifier — MUST be in signing preimage)
    map.insert(
        "jti".to_string(),
        CanonicalValue::Bytes(token.jti.as_bytes().to_vec()),
    );

    // nbf
    map.insert("nbf".to_string(), CanonicalValue::U64(token.nbf.0));

    // revocation_freshness
    match &token.revocation_freshness {
        Some(rf) => {
            let mut rfm = BTreeMap::new();
            rfm.insert(
                "min_revocation_seq".to_string(),
                CanonicalValue::U64(rf.min_revocation_seq),
            );
            rfm.insert(
                "revocation_head_hash".to_string(),
                CanonicalValue::Bytes(rf.revocation_head_hash.as_bytes().to_vec()),
            );
            map.insert("revocation_freshness".to_string(), CanonicalValue::Map(rfm));
        }
        None => {
            map.insert("revocation_freshness".to_string(), CanonicalValue::Null);
        }
    }

    // signature sentinel
    map.insert(
        "signature".to_string(),
        CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
    );

    // version
    map.insert(
        "version".to_string(),
        CanonicalValue::String(token.version.to_string()),
    );

    // zone
    map.insert(
        "zone".to_string(),
        CanonicalValue::String(token.zone.clone()),
    );

    CanonicalValue::Map(map)
}

// ---------------------------------------------------------------------------
// TokenBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing and signing capability tokens.
pub struct TokenBuilder {
    issuer_sk: SigningKey,
    audience: BTreeSet<PrincipalId>,
    capabilities: BTreeSet<RuntimeCapability>,
    nbf: DeterministicTimestamp,
    expiry: DeterministicTimestamp,
    epoch: SecurityEpoch,
    checkpoint_binding: Option<CheckpointRef>,
    revocation_freshness: Option<RevocationFreshnessRef>,
    zone: String,
}

impl TokenBuilder {
    /// Start building a token.
    pub fn new(
        issuer_sk: SigningKey,
        nbf: DeterministicTimestamp,
        expiry: DeterministicTimestamp,
        epoch: SecurityEpoch,
        zone: &str,
    ) -> Self {
        Self {
            issuer_sk,
            audience: BTreeSet::new(),
            capabilities: BTreeSet::new(),
            nbf,
            expiry,
            epoch,
            checkpoint_binding: None,
            revocation_freshness: None,
            zone: zone.to_string(),
        }
    }

    /// Add a principal to the audience.
    pub fn add_audience(mut self, principal: PrincipalId) -> Self {
        self.audience.insert(principal);
        self
    }

    /// Add a capability.
    pub fn add_capability(mut self, cap: RuntimeCapability) -> Self {
        self.capabilities.insert(cap);
        self
    }

    /// Add multiple capabilities.
    pub fn add_capabilities(mut self, caps: impl IntoIterator<Item = RuntimeCapability>) -> Self {
        self.capabilities.extend(caps);
        self
    }

    /// Set checkpoint binding.
    pub fn bind_checkpoint(mut self, binding: CheckpointRef) -> Self {
        self.checkpoint_binding = Some(binding);
        self
    }

    /// Set revocation freshness binding.
    pub fn bind_revocation_freshness(mut self, binding: RevocationFreshnessRef) -> Self {
        self.revocation_freshness = Some(binding);
        self
    }

    /// Build and sign the token.
    pub fn build(self) -> Result<CapabilityToken, TokenError> {
        // Validate.
        if self.capabilities.is_empty() {
            return Err(TokenError::EmptyCapabilities);
        }
        if self.audience.is_empty() {
            return Err(TokenError::EmptyAudience);
        }
        if self.nbf.0 > self.expiry.0 {
            return Err(TokenError::InvertedTemporalWindow {
                not_before: self.nbf.0,
                expiry: self.expiry.0,
            });
        }

        let issuer_vk = self.issuer_sk.verification_key();

        // Build a placeholder token to compute unsigned view.
        let placeholder = CapabilityToken {
            version: TokenVersion::V2,
            jti: EngineObjectId([0; 32]),
            issuer: issuer_vk.clone(),
            audience: self.audience,
            capabilities: self.capabilities,
            nbf: self.nbf,
            expiry: self.expiry,
            epoch: self.epoch,
            checkpoint_binding: self.checkpoint_binding,
            revocation_freshness: self.revocation_freshness,
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
            zone: self.zone,
        };

        // Derive jti from unsigned view.
        let unsigned_view = build_unsigned_view(&placeholder);
        let canonical_bytes = deterministic_serde::encode_value(&unsigned_view);
        let schema_id = token_schema_id();

        let jti = engine_object_id::derive_id(
            ObjectDomain::CapabilityToken,
            &placeholder.zone,
            &schema_id,
            &canonical_bytes,
        )
        .map_err(|e| TokenError::IdDerivationFailed {
            detail: e.to_string(),
        })?;

        // Build the real token with jti.
        let mut token = placeholder;
        token.jti = jti;

        // Compute preimage and sign.
        let preimage = token.preimage_bytes();
        let sig = sign_preimage(&self.issuer_sk, &preimage).map_err(|e| {
            TokenError::SignatureInvalid {
                detail: format!("signing failed: {e}"),
            }
        })?;
        token.signature = sig;

        Ok(token)
    }
}

// ---------------------------------------------------------------------------
// Verification context
// ---------------------------------------------------------------------------

/// Context for verifying a capability token.
pub struct VerificationContext {
    /// Current deterministic tick.
    pub current_tick: u64,
    /// Verifier's checkpoint frontier sequence.
    pub verifier_checkpoint_seq: u64,
    /// Verifier's revocation head sequence.
    pub verifier_revocation_seq: u64,
}

/// Verify a capability token against all bindings.
///
/// Performs checks in the documented order:
/// 1. Signature
/// 2. Audience
/// 3. Temporal validity (nbf, expiry)
/// 4. Checkpoint binding
/// 5. Revocation freshness binding
///
/// Returns `Ok(())` if all checks pass. Callers should additionally
/// check revocation status (whether the jti has been revoked).
pub fn verify_token(
    token: &CapabilityToken,
    presenter: &PrincipalId,
    ctx: &VerificationContext,
) -> Result<(), TokenError> {
    // 1. Signature verification.
    let preimage = token.preimage_bytes();
    verify_signature(&token.issuer, &preimage, &token.signature).map_err(|e| {
        TokenError::SignatureInvalid {
            detail: e.to_string(),
        }
    })?;

    // 2. Audience check.
    if !token.audience.is_empty() && !token.audience.contains(presenter) {
        return Err(TokenError::AudienceRejected {
            presenter: presenter.clone(),
            audience_size: token.audience.len(),
        });
    }

    // 3. Temporal validity.
    if ctx.current_tick < token.nbf.0 {
        return Err(TokenError::NotYetValid {
            current_tick: ctx.current_tick,
            not_before: token.nbf.0,
        });
    }
    if ctx.current_tick > token.expiry.0 {
        return Err(TokenError::Expired {
            current_tick: ctx.current_tick,
            expiry: token.expiry.0,
        });
    }

    // 4. Checkpoint binding.
    if let Some(ref binding) = token.checkpoint_binding
        && ctx.verifier_checkpoint_seq < binding.min_checkpoint_seq
    {
        return Err(TokenError::CheckpointBindingFailed {
            required_seq: binding.min_checkpoint_seq,
            verifier_seq: ctx.verifier_checkpoint_seq,
        });
    }

    // 5. Revocation freshness binding.
    if let Some(ref freshness) = token.revocation_freshness
        && ctx.verifier_revocation_seq < freshness.min_revocation_seq
    {
        return Err(TokenError::RevocationFreshnessStale {
            required_seq: freshness.min_revocation_seq,
            verifier_seq: ctx.verifier_revocation_seq,
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

/// Types of token events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenEventType {
    /// Token issued.
    TokenIssued { jti: TokenId },
    /// Token verified successfully.
    TokenVerified { jti: TokenId },
    /// Token verification failed.
    TokenRejected { jti: TokenId, reason: String },
}

impl fmt::Display for TokenEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TokenIssued { jti } => write!(f, "token_issued({})", jti.to_hex()),
            Self::TokenVerified { jti } => write!(f, "token_verified({})", jti.to_hex()),
            Self::TokenRejected { jti, reason } => {
                write!(f, "token_rejected({}, {reason})", jti.to_hex())
            }
        }
    }
}

/// A structured token event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenEvent {
    pub event_type: TokenEventType,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes([seed; 32])
    }

    fn make_principal(seed: u8) -> PrincipalId {
        PrincipalId::from_bytes([seed; 32])
    }

    fn make_checkpoint_ref(seq: u64) -> CheckpointRef {
        CheckpointRef {
            min_checkpoint_seq: seq,
            checkpoint_id: EngineObjectId([seq as u8; 32]),
        }
    }

    fn make_revocation_ref(seq: u64) -> RevocationFreshnessRef {
        RevocationFreshnessRef {
            min_revocation_seq: seq,
            revocation_head_hash: ContentHash::compute(&seq.to_be_bytes()),
        }
    }

    fn build_basic_token(sk: &SigningKey) -> CapabilityToken {
        TokenBuilder::new(
            sk.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .build()
        .unwrap()
    }

    fn basic_ctx() -> VerificationContext {
        VerificationContext {
            current_tick: 500,
            verifier_checkpoint_seq: 10,
            verifier_revocation_seq: 5,
        }
    }

    // -- Token creation --

    #[test]
    fn token_created_with_all_fields() {
        let sk = make_sk(1);
        let token = build_basic_token(&sk);

        assert_eq!(token.version, TokenVersion::V2);
        assert_eq!(token.issuer, sk.verification_key());
        assert_eq!(token.capabilities.len(), 1);
        assert!(token.capabilities.contains(&RuntimeCapability::VmDispatch));
        assert_eq!(token.nbf, DeterministicTimestamp(100));
        assert_eq!(token.expiry, DeterministicTimestamp(1000));
    }

    #[test]
    fn token_jti_is_deterministic() {
        let sk = make_sk(1);
        let t1 = build_basic_token(&sk);
        let t2 = build_basic_token(&sk);
        assert_eq!(t1.jti, t2.jti);
    }

    #[test]
    fn token_with_checkpoint_binding() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_checkpoint(make_checkpoint_ref(5))
        .build()
        .unwrap();

        assert!(token.checkpoint_binding.is_some());
        assert_eq!(
            token
                .checkpoint_binding
                .as_ref()
                .unwrap()
                .min_checkpoint_seq,
            5
        );
    }

    #[test]
    fn token_with_revocation_freshness() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capability(RuntimeCapability::PolicyRead)
        .bind_revocation_freshness(make_revocation_ref(3))
        .build()
        .unwrap();

        assert!(token.revocation_freshness.is_some());
    }

    #[test]
    fn token_with_multiple_capabilities() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capabilities(vec![
            RuntimeCapability::VmDispatch,
            RuntimeCapability::GcInvoke,
            RuntimeCapability::IrLowering,
        ])
        .build()
        .unwrap();

        assert_eq!(token.capabilities.len(), 3);
    }

    // -- Builder validation --

    #[test]
    fn empty_capabilities_rejected() {
        let sk = make_sk(1);
        let err = TokenBuilder::new(
            sk,
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .build()
        .unwrap_err();

        assert!(matches!(err, TokenError::EmptyCapabilities));
    }

    #[test]
    fn inverted_temporal_window_rejected() {
        let sk = make_sk(1);
        let err = TokenBuilder::new(
            sk,
            DeterministicTimestamp(1000), // nbf > expiry
            DeterministicTimestamp(100),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .build()
        .unwrap_err();

        assert!(matches!(err, TokenError::InvertedTemporalWindow { .. }));
    }

    // -- Verification: happy path --

    #[test]
    fn verification_succeeds() {
        let sk = make_sk(1);
        let token = build_basic_token(&sk);
        let ctx = basic_ctx();
        verify_token(&token, &make_principal(10), &ctx).unwrap();
    }

    #[test]
    fn verification_with_empty_audience_allows_anyone() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_capability(RuntimeCapability::VmDispatch)
        .build()
        .unwrap();

        let ctx = basic_ctx();
        // Any principal should be accepted when audience is empty.
        verify_token(&token, &make_principal(99), &ctx).unwrap();
    }

    // -- Verification: signature --

    #[test]
    fn tampered_signature_rejected() {
        let sk = make_sk(1);
        let mut token = build_basic_token(&sk);
        token.signature.lower[0] ^= 0xFF; // tamper

        let ctx = basic_ctx();
        let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
        assert!(matches!(err, TokenError::SignatureInvalid { .. }));
    }

    #[test]
    fn wrong_issuer_rejected() {
        let sk = make_sk(1);
        let mut token = build_basic_token(&sk);
        // Change issuer to a different key.
        token.issuer = VerificationKey::from_bytes([0xFF; 32]);

        let ctx = basic_ctx();
        let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
        assert!(matches!(err, TokenError::SignatureInvalid { .. }));
    }

    // -- Verification: audience --

    #[test]
    fn non_audience_presenter_rejected() {
        let sk = make_sk(1);
        let token = build_basic_token(&sk);
        let ctx = basic_ctx();

        let err = verify_token(&token, &make_principal(99), &ctx).unwrap_err();
        assert!(matches!(err, TokenError::AudienceRejected { .. }));
    }

    // -- Verification: temporal --

    #[test]
    fn not_yet_valid_rejected() {
        let sk = make_sk(1);
        let token = build_basic_token(&sk);
        let ctx = VerificationContext {
            current_tick: 50, // before nbf=100
            verifier_checkpoint_seq: 10,
            verifier_revocation_seq: 5,
        };

        let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
        assert!(matches!(err, TokenError::NotYetValid { .. }));
    }

    #[test]
    fn expired_rejected() {
        let sk = make_sk(1);
        let token = build_basic_token(&sk);
        let ctx = VerificationContext {
            current_tick: 2000, // after expiry=1000
            verifier_checkpoint_seq: 10,
            verifier_revocation_seq: 5,
        };

        let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
        assert!(matches!(err, TokenError::Expired { .. }));
    }

    #[test]
    fn exact_nbf_accepted() {
        let sk = make_sk(1);
        let token = build_basic_token(&sk);
        let ctx = VerificationContext {
            current_tick: 100, // exactly nbf
            verifier_checkpoint_seq: 10,
            verifier_revocation_seq: 5,
        };
        verify_token(&token, &make_principal(10), &ctx).unwrap();
    }

    #[test]
    fn exact_expiry_accepted() {
        let sk = make_sk(1);
        let token = build_basic_token(&sk);
        let ctx = VerificationContext {
            current_tick: 1000, // exactly expiry
            verifier_checkpoint_seq: 10,
            verifier_revocation_seq: 5,
        };
        verify_token(&token, &make_principal(10), &ctx).unwrap();
    }

    // -- Verification: checkpoint binding --

    #[test]
    fn checkpoint_binding_fails_when_frontier_too_low() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_checkpoint(make_checkpoint_ref(20))
        .build()
        .unwrap();

        let ctx = VerificationContext {
            current_tick: 500,
            verifier_checkpoint_seq: 15, // below required 20
            verifier_revocation_seq: 5,
        };

        let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CheckpointBindingFailed {
                required_seq: 20,
                verifier_seq: 15,
            }
        ));
    }

    #[test]
    fn checkpoint_binding_passes_when_frontier_sufficient() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_checkpoint(make_checkpoint_ref(10))
        .build()
        .unwrap();

        let ctx = basic_ctx(); // verifier_checkpoint_seq = 10
        verify_token(&token, &make_principal(10), &ctx).unwrap();
    }

    // -- Verification: revocation freshness --

    #[test]
    fn revocation_freshness_fails_when_stale() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_revocation_freshness(make_revocation_ref(10))
        .build()
        .unwrap();

        let ctx = VerificationContext {
            current_tick: 500,
            verifier_checkpoint_seq: 10,
            verifier_revocation_seq: 3, // below required 10
        };

        let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
        assert!(matches!(
            err,
            TokenError::RevocationFreshnessStale {
                required_seq: 10,
                verifier_seq: 3,
            }
        ));
    }

    #[test]
    fn revocation_freshness_passes_when_sufficient() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_revocation_freshness(make_revocation_ref(5))
        .build()
        .unwrap();

        let ctx = basic_ctx(); // verifier_revocation_seq = 5
        verify_token(&token, &make_principal(10), &ctx).unwrap();
    }

    // -- Signature covers all fields --

    #[test]
    fn modifying_audience_invalidates_signature() {
        let sk = make_sk(1);
        let mut token = build_basic_token(&sk);
        token.audience.insert(make_principal(99));

        let ctx = basic_ctx();
        let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
        assert!(matches!(err, TokenError::SignatureInvalid { .. }));
    }

    #[test]
    fn modifying_capabilities_invalidates_signature() {
        let sk = make_sk(1);
        let mut token = build_basic_token(&sk);
        token.capabilities.insert(RuntimeCapability::FsWrite);

        let ctx = basic_ctx();
        let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
        assert!(matches!(err, TokenError::SignatureInvalid { .. }));
    }

    #[test]
    fn modifying_expiry_invalidates_signature() {
        let sk = make_sk(1);
        let mut token = build_basic_token(&sk);
        token.expiry = DeterministicTimestamp(9999);

        let ctx = basic_ctx();
        let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
        assert!(matches!(err, TokenError::SignatureInvalid { .. }));
    }

    #[test]
    fn modifying_zone_invalidates_signature() {
        let sk = make_sk(1);
        let mut token = build_basic_token(&sk);
        token.zone = "zone-evil".to_string();

        let ctx = basic_ctx();
        let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
        assert!(matches!(err, TokenError::SignatureInvalid { .. }));
    }

    // -- Preimage stability --

    #[test]
    fn preimage_is_deterministic() {
        let sk = make_sk(1);
        let t = build_basic_token(&sk);
        assert_eq!(t.preimage_bytes(), t.preimage_bytes());
    }

    #[test]
    fn same_inputs_same_preimage() {
        let sk = make_sk(1);
        let t1 = build_basic_token(&sk);
        let t2 = build_basic_token(&sk);
        assert_eq!(t1.preimage_bytes(), t2.preimage_bytes());
    }

    // -- Serialization --

    #[test]
    fn token_serialization_round_trip() {
        let sk = make_sk(1);
        let token = build_basic_token(&sk);
        let json = serde_json::to_string(&token).expect("serialize");
        let restored: CapabilityToken = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(token, restored);
    }

    #[test]
    fn token_with_all_bindings_serialization_round_trip() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk.clone(),
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::from_raw(5),
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_audience(make_principal(20))
        .add_capability(RuntimeCapability::VmDispatch)
        .add_capability(RuntimeCapability::PolicyRead)
        .bind_checkpoint(make_checkpoint_ref(10))
        .bind_revocation_freshness(make_revocation_ref(5))
        .build()
        .unwrap();

        let json = serde_json::to_string(&token).expect("serialize");
        let restored: CapabilityToken = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(token, restored);
    }

    #[test]
    fn token_error_serialization_round_trip() {
        let errors = vec![
            TokenError::SignatureInvalid {
                detail: "bad".to_string(),
            },
            TokenError::AudienceRejected {
                presenter: make_principal(1),
                audience_size: 3,
            },
            TokenError::NotYetValid {
                current_tick: 50,
                not_before: 100,
            },
            TokenError::Expired {
                current_tick: 2000,
                expiry: 1000,
            },
            TokenError::CheckpointBindingFailed {
                required_seq: 20,
                verifier_seq: 15,
            },
            TokenError::RevocationFreshnessStale {
                required_seq: 10,
                verifier_seq: 3,
            },
            TokenError::EmptyCapabilities,
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: TokenError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -- Display --

    #[test]
    fn token_error_display() {
        let err = TokenError::Expired {
            current_tick: 2000,
            expiry: 1000,
        };
        let s = err.to_string();
        assert!(s.contains("2000"));
        assert!(s.contains("1000"));
    }

    #[test]
    fn principal_id_display() {
        let p = make_principal(0xAB);
        assert!(p.to_string().starts_with("principal:"));
    }

    #[test]
    fn token_event_type_display() {
        let et = TokenEventType::TokenIssued {
            jti: EngineObjectId([1; 32]),
        };
        assert!(et.to_string().contains("token_issued"));
    }

    #[test]
    fn token_version_display() {
        assert_eq!(TokenVersion::V2.to_string(), "v2");
    }

    // -- Enrichment: std::error --

    #[test]
    fn token_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(TokenError::SignatureInvalid {
                detail: "bad".into(),
            }),
            Box::new(TokenError::NonCanonical {
                detail: "order".into(),
            }),
            Box::new(TokenError::AudienceRejected {
                presenter: PrincipalId([0xAA; 32]),
                audience_size: 0,
            }),
            Box::new(TokenError::NotYetValid {
                current_tick: 50,
                not_before: 100,
            }),
            Box::new(TokenError::Expired {
                current_tick: 200,
                expiry: 100,
            }),
            Box::new(TokenError::CheckpointBindingFailed {
                required_seq: 10,
                verifier_seq: 5,
            }),
            Box::new(TokenError::RevocationFreshnessStale {
                required_seq: 10,
                verifier_seq: 5,
            }),
            Box::new(TokenError::UnsupportedVersion {
                version: "v99".into(),
            }),
            Box::new(TokenError::IdDerivationFailed {
                detail: "bad".into(),
            }),
            Box::new(TokenError::InvertedTemporalWindow {
                not_before: 200,
                expiry: 100,
            }),
            Box::new(TokenError::EmptyCapabilities),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            11,
            "all 11 variants produce distinct messages"
        );
    }

    // -- Enrichment batch 2: Display uniqueness, serde all variants, boundary, error trait --

    #[test]
    fn token_error_display_all_variants_contain_key_details() {
        let display_sig = TokenError::SignatureInvalid {
            detail: "tampered".to_string(),
        }
        .to_string();
        assert!(display_sig.contains("tampered"));

        let display_nc = TokenError::NonCanonical {
            detail: "order".to_string(),
        }
        .to_string();
        assert!(display_nc.contains("non-canonical"));

        let display_aud = TokenError::AudienceRejected {
            presenter: make_principal(1),
            audience_size: 5,
        }
        .to_string();
        assert!(display_aud.contains("5"));

        let display_nyv = TokenError::NotYetValid {
            current_tick: 10,
            not_before: 100,
        }
        .to_string();
        assert!(display_nyv.contains("10"));
        assert!(display_nyv.contains("100"));

        let display_uv = TokenError::UnsupportedVersion {
            version: "v99".to_string(),
        }
        .to_string();
        assert!(display_uv.contains("v99"));

        let display_id = TokenError::IdDerivationFailed {
            detail: "entropy".to_string(),
        }
        .to_string();
        assert!(display_id.contains("entropy"));
    }

    #[test]
    fn token_error_serde_all_11_variants() {
        let errors = vec![
            TokenError::SignatureInvalid {
                detail: "bad".to_string(),
            },
            TokenError::NonCanonical {
                detail: "order".to_string(),
            },
            TokenError::AudienceRejected {
                presenter: make_principal(1),
                audience_size: 3,
            },
            TokenError::NotYetValid {
                current_tick: 50,
                not_before: 100,
            },
            TokenError::Expired {
                current_tick: 2000,
                expiry: 1000,
            },
            TokenError::CheckpointBindingFailed {
                required_seq: 20,
                verifier_seq: 15,
            },
            TokenError::RevocationFreshnessStale {
                required_seq: 10,
                verifier_seq: 3,
            },
            TokenError::UnsupportedVersion {
                version: "v99".to_string(),
            },
            TokenError::IdDerivationFailed {
                detail: "entropy".to_string(),
            },
            TokenError::InvertedTemporalWindow {
                not_before: 200,
                expiry: 100,
            },
            TokenError::EmptyCapabilities,
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: TokenError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn principal_id_hex_is_64_chars() {
        let p = make_principal(0xAB);
        let hex = p.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn principal_id_from_verification_key_deterministic() {
        let sk = make_sk(42);
        let vk = sk.verification_key();
        let p1 = PrincipalId::from_verification_key(&vk);
        let p2 = PrincipalId::from_verification_key(&vk);
        assert_eq!(p1, p2);
    }

    #[test]
    fn principal_id_serde_roundtrip() {
        let p = make_principal(0xCD);
        let json = serde_json::to_string(&p).expect("serialize");
        let restored: PrincipalId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, restored);
    }

    #[test]
    fn checkpoint_ref_serde_roundtrip() {
        let cr = make_checkpoint_ref(42);
        let json = serde_json::to_string(&cr).expect("serialize");
        let restored: CheckpointRef = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cr, restored);
    }

    #[test]
    fn revocation_freshness_ref_serde_roundtrip() {
        let rf = make_revocation_ref(99);
        let json = serde_json::to_string(&rf).expect("serialize");
        let restored: RevocationFreshnessRef = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rf, restored);
    }

    #[test]
    fn token_version_serde_roundtrip() {
        let v = TokenVersion::V2;
        let json = serde_json::to_string(&v).expect("serialize");
        let restored: TokenVersion = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(v, restored);
    }

    #[test]
    fn token_event_serde_roundtrip() {
        let event = TokenEvent {
            event_type: TokenEventType::TokenRejected {
                jti: EngineObjectId([7; 32]),
                reason: "expired".to_string(),
            },
            trace_id: "trace-abc".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: TokenEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn token_event_type_display_all_variants_unique() {
        let jti = EngineObjectId([1; 32]);
        let displays: std::collections::BTreeSet<String> = [
            TokenEventType::TokenIssued { jti: jti.clone() },
            TokenEventType::TokenVerified { jti: jti.clone() },
            TokenEventType::TokenRejected {
                jti,
                reason: "expired".to_string(),
            },
        ]
        .iter()
        .map(|e| e.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            3,
            "all TokenEventType Display strings must be unique"
        );
    }

    #[test]
    fn token_with_equal_nbf_expiry_accepted() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk.clone(),
            DeterministicTimestamp(500),
            DeterministicTimestamp(500), // nbf == expiry (zero-width window)
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .build()
        .unwrap();

        let ctx = VerificationContext {
            current_tick: 500,
            verifier_checkpoint_seq: 10,
            verifier_revocation_seq: 5,
        };
        verify_token(&token, &make_principal(10), &ctx).unwrap();
    }

    #[test]
    fn token_schema_deterministic() {
        let s1 = token_schema();
        let s2 = token_schema();
        assert_eq!(s1, s2);
    }

    #[test]
    fn token_schema_id_deterministic() {
        let id1 = token_schema_id();
        let id2 = token_schema_id();
        assert_eq!(id1, id2);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone, JSON fields, ordering, edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn principal_id_clone_equality() {
        let pid = make_principal(42);
        let cloned = pid.clone();
        assert_eq!(pid, cloned);
    }

    #[test]
    fn checkpoint_ref_clone_equality() {
        let cref = make_checkpoint_ref(10);
        let cloned = cref.clone();
        assert_eq!(cref, cloned);
    }

    #[test]
    fn revocation_freshness_ref_clone_equality() {
        let rref = make_revocation_ref(7);
        let cloned = rref.clone();
        assert_eq!(rref, cloned);
    }

    #[test]
    fn token_error_clone_equality() {
        let errors = vec![
            TokenError::SignatureInvalid {
                detail: "bad sig".into(),
            },
            TokenError::EmptyCapabilities,
            TokenError::Expired {
                current_tick: 200,
                expiry: 100,
            },
        ];
        for e in &errors {
            let cloned = e.clone();
            assert_eq!(*e, cloned);
        }
    }

    #[test]
    fn capability_token_clone_equality() {
        let sk = make_sk(1);
        let token = build_basic_token(&sk);
        let cloned = token.clone();
        assert_eq!(token, cloned);
    }

    #[test]
    fn token_event_clone_equality() {
        let event = TokenEvent {
            event_type: TokenEventType::TokenIssued {
                jti: EngineObjectId([5; 32]),
            },
            trace_id: "t-99".into(),
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    #[test]
    fn capability_token_json_field_presence() {
        let sk = make_sk(1);
        let token = build_basic_token(&sk);
        let json = serde_json::to_string(&token).unwrap();
        for field in [
            "version",
            "jti",
            "issuer",
            "audience",
            "capabilities",
            "nbf",
            "expiry",
            "epoch",
            "signature",
            "zone",
        ] {
            assert!(json.contains(field), "missing field: {field}");
        }
    }

    #[test]
    fn checkpoint_ref_json_field_presence() {
        let cref = make_checkpoint_ref(15);
        let json = serde_json::to_string(&cref).unwrap();
        assert!(json.contains("min_checkpoint_seq"));
        assert!(json.contains("checkpoint_id"));
    }

    #[test]
    fn revocation_freshness_ref_json_field_presence() {
        let rref = make_revocation_ref(8);
        let json = serde_json::to_string(&rref).unwrap();
        assert!(json.contains("min_revocation_seq"));
        assert!(json.contains("revocation_head_hash"));
    }

    #[test]
    fn principal_id_ordering_deterministic() {
        let p1 = PrincipalId::from_bytes([0; 32]);
        let p2 = PrincipalId::from_bytes([1; 32]);
        let p3 = PrincipalId::from_bytes([255; 32]);
        assert!(p1 < p2);
        assert!(p2 < p3);
    }

    #[test]
    fn principal_id_from_bytes_roundtrip() {
        let bytes = [42u8; 32];
        let pid = PrincipalId::from_bytes(bytes);
        assert_eq!(*pid.as_bytes(), bytes);
    }

    #[test]
    fn token_with_multiple_audience_serializes() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk,
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_audience(make_principal(20))
        .add_audience(make_principal(30))
        .add_capability(RuntimeCapability::VmDispatch)
        .build()
        .unwrap();

        assert_eq!(token.audience.len(), 3);
        let json = serde_json::to_string(&token).unwrap();
        let back: CapabilityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, back);
    }

    #[test]
    fn verification_context_boundary_tick_equals_nbf() {
        let sk = make_sk(1);
        let token = build_basic_token(&sk); // nbf=100, expiry=1000
        let ctx = VerificationContext {
            current_tick: 100, // exactly at nbf
            verifier_checkpoint_seq: 10,
            verifier_revocation_seq: 5,
        };
        verify_token(&token, &make_principal(10), &ctx).unwrap();
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: deep coverage, stress, isolation, replay, clone
    // independence, Display/Debug, ordering, error message content
    // -----------------------------------------------------------------------

    #[test]
    fn clone_independence_principal_id_enrichment() {
        let original = make_principal(0xAA);
        let mut cloned = original.clone();
        cloned.0[0] = 0xFF;
        assert_ne!(original, cloned);
        assert_eq!(original.0[0], 0xAA);
    }

    #[test]
    fn clone_independence_checkpoint_ref_enrichment() {
        let original = make_checkpoint_ref(10);
        let mut cloned = original.clone();
        cloned.min_checkpoint_seq = 999;
        assert_ne!(original.min_checkpoint_seq, cloned.min_checkpoint_seq);
        assert_eq!(original.min_checkpoint_seq, 10);
    }

    #[test]
    fn clone_independence_revocation_freshness_ref_enrichment() {
        let original = make_revocation_ref(5);
        let mut cloned = original.clone();
        cloned.min_revocation_seq = 999;
        assert_ne!(original.min_revocation_seq, cloned.min_revocation_seq);
        assert_eq!(original.min_revocation_seq, 5);
    }

    #[test]
    fn clone_independence_capability_token_enrichment() {
        let sk = make_sk(1);
        let original = build_basic_token(&sk);
        let mut cloned = original.clone();
        cloned.zone = "zone-tampered".to_string();
        assert_ne!(original.zone, cloned.zone);
        assert_eq!(original.zone, "zone-a");
    }

    #[test]
    fn clone_independence_token_event_enrichment() {
        let original = TokenEvent {
            event_type: TokenEventType::TokenIssued {
                jti: EngineObjectId([3; 32]),
            },
            trace_id: "trace-1".into(),
        };
        let mut cloned = original.clone();
        cloned.trace_id = "trace-modified".into();
        assert_ne!(original.trace_id, cloned.trace_id);
        assert_eq!(original.trace_id, "trace-1");
    }

    #[test]
    fn principal_id_debug_contains_bytes_enrichment() {
        let p = make_principal(0x42);
        let dbg = format!("{p:?}");
        assert!(dbg.contains("PrincipalId"));
    }

    #[test]
    fn token_version_debug_enrichment() {
        let v = TokenVersion::V2;
        let dbg = format!("{v:?}");
        assert!(dbg.contains("V2"));
    }

    #[test]
    fn token_error_debug_all_variants_enrichment() {
        let variants = vec![
            TokenError::SignatureInvalid {
                detail: "dbg".into(),
            },
            TokenError::NonCanonical {
                detail: "dbg".into(),
            },
            TokenError::AudienceRejected {
                presenter: make_principal(1),
                audience_size: 2,
            },
            TokenError::NotYetValid {
                current_tick: 1,
                not_before: 2,
            },
            TokenError::Expired {
                current_tick: 3,
                expiry: 2,
            },
            TokenError::CheckpointBindingFailed {
                required_seq: 5,
                verifier_seq: 3,
            },
            TokenError::RevocationFreshnessStale {
                required_seq: 7,
                verifier_seq: 4,
            },
            TokenError::UnsupportedVersion {
                version: "v0".into(),
            },
            TokenError::IdDerivationFailed {
                detail: "bad".into(),
            },
            TokenError::InvertedTemporalWindow {
                not_before: 200,
                expiry: 100,
            },
            TokenError::EmptyCapabilities,
        ];
        let mut debugs = BTreeSet::new();
        for v in &variants {
            let d = format!("{v:?}");
            assert!(!d.is_empty());
            debugs.insert(d);
        }
        assert_eq!(debugs.len(), 11, "all Debug outputs should be unique");
    }

    #[test]
    fn token_version_ordering_enrichment() {
        // Only one variant, but Ord is derived so we test reflexivity.
        let v = TokenVersion::V2;
        assert!(v == v);
        assert!(v >= v);
    }

    #[test]
    fn principal_id_ordering_btreeset_enrichment() {
        let mut set = BTreeSet::new();
        for seed in (0u8..10).rev() {
            set.insert(PrincipalId::from_bytes([seed; 32]));
        }
        assert_eq!(set.len(), 10);
        // Verify iteration order is ascending by first byte.
        let first_bytes: Vec<u8> = set.iter().map(|p| p.0[0]).collect();
        for w in first_bytes.windows(2) {
            assert!(w[0] < w[1]);
        }
    }

    #[test]
    fn principal_id_hash_consistency_enrichment() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let p = make_principal(0x77);
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        p.hash(&mut h1);
        p.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn error_display_signature_invalid_enrichment() {
        let err = TokenError::SignatureInvalid {
            detail: "hmac mismatch".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("signature invalid"));
        assert!(s.contains("hmac mismatch"));
    }

    #[test]
    fn error_display_non_canonical_enrichment() {
        let err = TokenError::NonCanonical {
            detail: "field ordering".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("non-canonical"));
        assert!(s.contains("field ordering"));
    }

    #[test]
    fn error_display_audience_rejected_enrichment() {
        let err = TokenError::AudienceRejected {
            presenter: make_principal(0xAB),
            audience_size: 3,
        };
        let s = err.to_string();
        assert!(s.contains("audience rejected"));
        assert!(s.contains("3 audience members"));
    }

    #[test]
    fn error_display_checkpoint_binding_failed_enrichment() {
        let err = TokenError::CheckpointBindingFailed {
            required_seq: 100,
            verifier_seq: 50,
        };
        let s = err.to_string();
        assert!(s.contains("checkpoint binding failed"));
        assert!(s.contains("100"));
        assert!(s.contains("50"));
    }

    #[test]
    fn error_display_revocation_freshness_stale_enrichment() {
        let err = TokenError::RevocationFreshnessStale {
            required_seq: 42,
            verifier_seq: 7,
        };
        let s = err.to_string();
        assert!(s.contains("revocation freshness stale"));
        assert!(s.contains("42"));
        assert!(s.contains("7"));
    }

    #[test]
    fn error_display_unsupported_version_enrichment() {
        let err = TokenError::UnsupportedVersion {
            version: "v999".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("unsupported version"));
        assert!(s.contains("v999"));
    }

    #[test]
    fn error_display_id_derivation_failed_enrichment() {
        let err = TokenError::IdDerivationFailed {
            detail: "no entropy".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("ID derivation failed"));
        assert!(s.contains("no entropy"));
    }

    #[test]
    fn error_display_inverted_temporal_window_enrichment() {
        let err = TokenError::InvertedTemporalWindow {
            not_before: 500,
            expiry: 100,
        };
        let s = err.to_string();
        assert!(s.contains("inverted temporal window"));
        assert!(s.contains("500"));
        assert!(s.contains("100"));
    }

    #[test]
    fn error_display_empty_capabilities_enrichment() {
        let err = TokenError::EmptyCapabilities;
        assert_eq!(err.to_string(), "empty capabilities");
    }

    #[test]
    fn error_display_not_yet_valid_enrichment() {
        let err = TokenError::NotYetValid {
            current_tick: 30,
            not_before: 200,
        };
        let s = err.to_string();
        assert!(s.contains("not yet valid"));
        assert!(s.contains("30"));
        assert!(s.contains("200"));
    }

    #[test]
    fn deterministic_replay_full_bindings_enrichment() {
        let sk = make_sk(7);
        let build = || {
            TokenBuilder::new(
                sk.clone(),
                DeterministicTimestamp(200),
                DeterministicTimestamp(2000),
                SecurityEpoch::from_raw(3),
                "zone-replay",
            )
            .add_audience(make_principal(10))
            .add_audience(make_principal(20))
            .add_capability(RuntimeCapability::VmDispatch)
            .add_capability(RuntimeCapability::PolicyRead)
            .add_capability(RuntimeCapability::FsRead)
            .bind_checkpoint(make_checkpoint_ref(15))
            .bind_revocation_freshness(make_revocation_ref(8))
            .build()
            .unwrap()
        };
        let t1 = build();
        let t2 = build();
        assert_eq!(t1.jti, t2.jti);
        assert_eq!(t1.signature, t2.signature);
        assert_eq!(t1.preimage_bytes(), t2.preimage_bytes());
    }

    #[test]
    fn stress_many_audience_members_enrichment() {
        let sk = make_sk(1);
        let mut builder = TokenBuilder::new(
            sk,
            DeterministicTimestamp(0),
            DeterministicTimestamp(u64::MAX),
            SecurityEpoch::GENESIS,
            "zone-stress",
        )
        .add_capability(RuntimeCapability::VmDispatch);

        for i in 0u8..50 {
            builder = builder.add_audience(make_principal(i));
        }

        let token = builder.build().unwrap();
        assert_eq!(token.audience.len(), 50);

        // Verify any audience member can verify.
        let ctx = VerificationContext {
            current_tick: 100,
            verifier_checkpoint_seq: 0,
            verifier_revocation_seq: 0,
        };
        verify_token(&token, &make_principal(0), &ctx).unwrap();
        verify_token(&token, &make_principal(25), &ctx).unwrap();
        verify_token(&token, &make_principal(49), &ctx).unwrap();
    }

    #[test]
    fn stress_all_capabilities_enrichment() {
        let sk = make_sk(2);
        let all_caps = vec![
            RuntimeCapability::VmDispatch,
            RuntimeCapability::GcInvoke,
            RuntimeCapability::IrLowering,
            RuntimeCapability::PolicyRead,
            RuntimeCapability::PolicyWrite,
            RuntimeCapability::EvidenceEmit,
            RuntimeCapability::DecisionInvoke,
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::LeaseManagement,
            RuntimeCapability::IdempotencyDerive,
            RuntimeCapability::ExtensionLifecycle,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::EnvRead,
            RuntimeCapability::ProcessSpawn,
            RuntimeCapability::FsRead,
            RuntimeCapability::FsWrite,
        ];
        let token = TokenBuilder::new(
            sk,
            DeterministicTimestamp(0),
            DeterministicTimestamp(u64::MAX),
            SecurityEpoch::GENESIS,
            "zone-all",
        )
        .add_audience(make_principal(1))
        .add_capabilities(all_caps)
        .build()
        .unwrap();

        assert_eq!(token.capabilities.len(), 16);
        let json = serde_json::to_string(&token).unwrap();
        let back: CapabilityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, back);
    }

    #[test]
    fn stress_duplicate_audience_deduplication_enrichment() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk,
            DeterministicTimestamp(0),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-dedup",
        )
        .add_audience(make_principal(10))
        .add_audience(make_principal(10)) // duplicate
        .add_audience(make_principal(10)) // duplicate
        .add_capability(RuntimeCapability::VmDispatch)
        .build()
        .unwrap();

        assert_eq!(token.audience.len(), 1);
    }

    #[test]
    fn stress_duplicate_capabilities_deduplication_enrichment() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk,
            DeterministicTimestamp(0),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-dedup-cap",
        )
        .add_audience(make_principal(1))
        .add_capability(RuntimeCapability::FsRead)
        .add_capability(RuntimeCapability::FsRead) // duplicate
        .add_capability(RuntimeCapability::FsRead) // duplicate
        .build()
        .unwrap();

        assert_eq!(token.capabilities.len(), 1);
    }

    #[test]
    fn different_zones_produce_different_jti_enrichment() {
        let sk = make_sk(1);
        let build_for_zone = |zone: &str| {
            TokenBuilder::new(
                sk.clone(),
                DeterministicTimestamp(100),
                DeterministicTimestamp(1000),
                SecurityEpoch::GENESIS,
                zone,
            )
            .add_audience(make_principal(10))
            .add_capability(RuntimeCapability::VmDispatch)
            .build()
            .unwrap()
        };

        let t1 = build_for_zone("zone-alpha");
        let t2 = build_for_zone("zone-beta");
        assert_ne!(t1.jti, t2.jti);
    }

    #[test]
    fn different_epochs_produce_different_jti_enrichment() {
        let sk = make_sk(1);
        let build_for_epoch = |epoch: SecurityEpoch| {
            TokenBuilder::new(
                sk.clone(),
                DeterministicTimestamp(100),
                DeterministicTimestamp(1000),
                epoch,
                "zone-a",
            )
            .add_audience(make_principal(10))
            .add_capability(RuntimeCapability::VmDispatch)
            .build()
            .unwrap()
        };

        let t1 = build_for_epoch(SecurityEpoch::GENESIS);
        let t2 = build_for_epoch(SecurityEpoch::from_raw(1));
        assert_ne!(t1.jti, t2.jti);
    }

    #[test]
    fn different_capabilities_produce_different_jti_enrichment() {
        let sk = make_sk(1);
        let build_with_cap = |cap: RuntimeCapability| {
            TokenBuilder::new(
                sk.clone(),
                DeterministicTimestamp(100),
                DeterministicTimestamp(1000),
                SecurityEpoch::GENESIS,
                "zone-a",
            )
            .add_audience(make_principal(10))
            .add_capability(cap)
            .build()
            .unwrap()
        };

        let t1 = build_with_cap(RuntimeCapability::VmDispatch);
        let t2 = build_with_cap(RuntimeCapability::FsWrite);
        assert_ne!(t1.jti, t2.jti);
    }

    #[test]
    fn different_audience_produces_different_jti_enrichment() {
        let sk = make_sk(1);
        let build_with_audience = |seed: u8| {
            TokenBuilder::new(
                sk.clone(),
                DeterministicTimestamp(100),
                DeterministicTimestamp(1000),
                SecurityEpoch::GENESIS,
                "zone-a",
            )
            .add_audience(make_principal(seed))
            .add_capability(RuntimeCapability::VmDispatch)
            .build()
            .unwrap()
        };

        let t1 = build_with_audience(10);
        let t2 = build_with_audience(20);
        assert_ne!(t1.jti, t2.jti);
    }

    #[test]
    fn verification_priority_signature_before_temporal_enrichment() {
        // A token with tampered signature AND expired time should fail on
        // signature, not temporal.
        let sk = make_sk(1);
        let mut token = build_basic_token(&sk);
        token.signature.lower[0] ^= 0xFF; // tamper signature

        let ctx = VerificationContext {
            current_tick: 9999, // way past expiry
            verifier_checkpoint_seq: 10,
            verifier_revocation_seq: 5,
        };
        let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
        assert!(
            matches!(err, TokenError::SignatureInvalid { .. }),
            "signature check must happen before temporal check"
        );
    }

    #[test]
    fn verification_priority_audience_before_temporal_enrichment() {
        // Wrong audience AND before nbf: should fail audience, not temporal.
        let sk = make_sk(1);
        let token = build_basic_token(&sk); // audience = principal(10)

        let ctx = VerificationContext {
            current_tick: 50, // before nbf=100
            verifier_checkpoint_seq: 10,
            verifier_revocation_seq: 5,
        };
        let err = verify_token(&token, &make_principal(99), &ctx).unwrap_err();
        assert!(
            matches!(err, TokenError::AudienceRejected { .. }),
            "audience check must happen before temporal check"
        );
    }

    #[test]
    fn modifying_nbf_invalidates_signature_enrichment() {
        let sk = make_sk(1);
        let mut token = build_basic_token(&sk);
        token.nbf = DeterministicTimestamp(0);
        let ctx = basic_ctx();
        let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
        assert!(matches!(err, TokenError::SignatureInvalid { .. }));
    }

    #[test]
    fn modifying_epoch_invalidates_signature_enrichment() {
        let sk = make_sk(1);
        let mut token = build_basic_token(&sk);
        token.epoch = SecurityEpoch::from_raw(999);
        let ctx = basic_ctx();
        let err = verify_token(&token, &make_principal(10), &ctx).unwrap_err();
        assert!(matches!(err, TokenError::SignatureInvalid { .. }));
    }

    #[test]
    fn token_event_type_serde_all_variants_enrichment() {
        let jti = EngineObjectId([0xBB; 32]);
        let variants = vec![
            TokenEventType::TokenIssued { jti: jti.clone() },
            TokenEventType::TokenVerified { jti: jti.clone() },
            TokenEventType::TokenRejected {
                jti,
                reason: "test".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: TokenEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn token_event_debug_enrichment() {
        let event = TokenEvent {
            event_type: TokenEventType::TokenVerified {
                jti: EngineObjectId([0xCC; 32]),
            },
            trace_id: "trace-dbg".into(),
        };
        let dbg = format!("{event:?}");
        assert!(dbg.contains("TokenEvent"));
        assert!(dbg.contains("trace-dbg"));
    }

    #[test]
    fn principal_id_display_truncated_to_8_hex_enrichment() {
        let p = PrincipalId::from_bytes([0xFF; 32]);
        let s = p.to_string();
        // Display is "principal:" + first 8 hex chars of 64-char hex.
        assert!(s.starts_with("principal:"));
        assert_eq!(s.len(), "principal:".len() + 8);
    }

    #[test]
    fn principal_id_zero_bytes_enrichment() {
        let p = PrincipalId::from_bytes([0u8; 32]);
        let hex = p.to_hex();
        assert_eq!(hex, "0".repeat(64));
        assert_eq!(p.to_string(), "principal:00000000");
    }

    #[test]
    fn principal_id_max_bytes_enrichment() {
        let p = PrincipalId::from_bytes([0xFF; 32]);
        let hex = p.to_hex();
        assert_eq!(hex, "f".repeat(64));
    }

    #[test]
    fn serde_roundtrip_token_with_no_optional_bindings_enrichment() {
        let sk = make_sk(3);
        let token = TokenBuilder::new(
            sk,
            DeterministicTimestamp(0),
            DeterministicTimestamp(u64::MAX),
            SecurityEpoch::GENESIS,
            "zone-minimal",
        )
        .add_capability(RuntimeCapability::GcInvoke)
        .build()
        .unwrap();

        assert!(token.checkpoint_binding.is_none());
        assert!(token.revocation_freshness.is_none());
        assert!(token.audience.is_empty());

        let json = serde_json::to_string(&token).unwrap();
        assert!(json.contains("null") || json.contains("\"checkpoint_binding\":null"));
        let back: CapabilityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, back);
    }

    #[test]
    fn serde_roundtrip_token_max_temporal_window_enrichment() {
        let sk = make_sk(4);
        let token = TokenBuilder::new(
            sk,
            DeterministicTimestamp(0),
            DeterministicTimestamp(u64::MAX),
            SecurityEpoch::from_raw(u64::MAX),
            "zone-max",
        )
        .add_audience(make_principal(1))
        .add_capability(RuntimeCapability::NetworkEgress)
        .build()
        .unwrap();

        let json = serde_json::to_string(&token).unwrap();
        let back: CapabilityToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, back);
    }

    #[test]
    fn token_unsigned_view_excludes_signature_enrichment() {
        let sk = make_sk(1);
        let token = build_basic_token(&sk);
        let unsigned = build_unsigned_view(&token);
        // The unsigned view should contain the sentinel, not the actual signature.
        if let CanonicalValue::Map(ref map) = unsigned {
            if let Some(CanonicalValue::Bytes(sig_bytes)) = map.get("signature") {
                assert_eq!(
                    sig_bytes.as_slice(),
                    SIGNATURE_SENTINEL,
                    "unsigned view must use signature sentinel"
                );
            } else {
                panic!("signature field missing or wrong type in unsigned view");
            }
        } else {
            panic!("unsigned view should be a Map");
        }
    }

    #[test]
    fn token_preimage_starts_with_domain_tag_enrichment() {
        let sk = make_sk(1);
        let token = build_basic_token(&sk);
        let preimage = token.preimage_bytes();
        let domain_tag = ObjectDomain::CapabilityToken.tag();
        assert!(
            preimage.starts_with(domain_tag),
            "preimage must start with domain tag"
        );
    }

    #[test]
    fn inverted_temporal_window_exact_values_enrichment() {
        let sk = make_sk(1);
        let err = TokenBuilder::new(
            sk,
            DeterministicTimestamp(500),
            DeterministicTimestamp(499),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .build()
        .unwrap_err();

        match err {
            TokenError::InvertedTemporalWindow { not_before, expiry } => {
                assert_eq!(not_before, 500);
                assert_eq!(expiry, 499);
            }
            other => panic!("expected InvertedTemporalWindow, got: {other:?}"),
        }
    }

    #[test]
    fn checkpoint_binding_exact_boundary_passes_enrichment() {
        // Verifier checkpoint_seq == required seq should pass.
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk,
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_checkpoint(make_checkpoint_ref(42))
        .build()
        .unwrap();

        let ctx = VerificationContext {
            current_tick: 500,
            verifier_checkpoint_seq: 42, // exactly equal
            verifier_revocation_seq: 5,
        };
        verify_token(&token, &make_principal(10), &ctx).unwrap();
    }

    #[test]
    fn revocation_freshness_exact_boundary_passes_enrichment() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk,
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_revocation_freshness(make_revocation_ref(42))
        .build()
        .unwrap();

        let ctx = VerificationContext {
            current_tick: 500,
            verifier_checkpoint_seq: 10,
            verifier_revocation_seq: 42, // exactly equal
        };
        verify_token(&token, &make_principal(10), &ctx).unwrap();
    }

    #[test]
    fn both_bindings_checked_enrichment() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk,
            DeterministicTimestamp(100),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "zone-a",
        )
        .add_audience(make_principal(10))
        .add_capability(RuntimeCapability::VmDispatch)
        .bind_checkpoint(make_checkpoint_ref(20))
        .bind_revocation_freshness(make_revocation_ref(15))
        .build()
        .unwrap();

        // Both bindings satisfied.
        let ctx_ok = VerificationContext {
            current_tick: 500,
            verifier_checkpoint_seq: 25,
            verifier_revocation_seq: 20,
        };
        verify_token(&token, &make_principal(10), &ctx_ok).unwrap();

        // Checkpoint fails, revocation ok.
        let ctx_cp_fail = VerificationContext {
            current_tick: 500,
            verifier_checkpoint_seq: 10, // below 20
            verifier_revocation_seq: 20,
        };
        let err = verify_token(&token, &make_principal(10), &ctx_cp_fail).unwrap_err();
        assert!(matches!(err, TokenError::CheckpointBindingFailed { .. }));

        // Checkpoint ok, revocation fails.
        let ctx_rv_fail = VerificationContext {
            current_tick: 500,
            verifier_checkpoint_seq: 25,
            verifier_revocation_seq: 10, // below 15
        };
        let err = verify_token(&token, &make_principal(10), &ctx_rv_fail).unwrap_err();
        assert!(matches!(err, TokenError::RevocationFreshnessStale { .. }));
    }

    #[test]
    fn token_event_type_display_rejected_contains_reason_enrichment() {
        let et = TokenEventType::TokenRejected {
            jti: EngineObjectId([2; 32]),
            reason: "expired beyond window".to_string(),
        };
        let s = et.to_string();
        assert!(s.contains("token_rejected"));
        assert!(s.contains("expired beyond window"));
    }

    #[test]
    fn token_event_type_display_verified_enrichment() {
        let et = TokenEventType::TokenVerified {
            jti: EngineObjectId([3; 32]),
        };
        let s = et.to_string();
        assert!(s.contains("token_verified"));
    }

    #[test]
    fn principal_id_from_different_vks_differ_enrichment() {
        let sk1 = make_sk(1);
        let sk2 = make_sk(2);
        let p1 = PrincipalId::from_verification_key(&sk1.verification_key());
        let p2 = PrincipalId::from_verification_key(&sk2.verification_key());
        assert_ne!(p1, p2);
    }

    #[test]
    fn token_schema_and_schema_id_consistent_enrichment() {
        // Both are derived from the same definition, so they should be
        // deterministic and non-trivial.
        let s1 = token_schema();
        let s2 = token_schema();
        assert_eq!(s1, s2);
        let id1 = token_schema_id();
        let id2 = token_schema_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn empty_zone_string_accepted_enrichment() {
        let sk = make_sk(1);
        let token = TokenBuilder::new(
            sk,
            DeterministicTimestamp(0),
            DeterministicTimestamp(1000),
            SecurityEpoch::GENESIS,
            "", // empty zone
        )
        .add_audience(make_principal(1))
        .add_capability(RuntimeCapability::VmDispatch)
        .build()
        .unwrap();

        assert_eq!(token.zone, "");
        let ctx = VerificationContext {
            current_tick: 500,
            verifier_checkpoint_seq: 0,
            verifier_revocation_seq: 0,
        };
        verify_token(&token, &make_principal(1), &ctx).unwrap();
    }
}
