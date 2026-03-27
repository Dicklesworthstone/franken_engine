//! TEE attestation policy contract for decision-receipt emitters.
//!
//! Defines a machine-readable policy schema containing:
//! - approved measurements per TEE platform
//! - attestation freshness windows for standard/high-impact decisions
//! - ordered revocation sources with fallback semantics
//! - platform trust roots with pinning + rotation metadata
//!
//! The policy is fail-closed at load time: parse/validation failures halt
//! receipt emission. Temporary trust-root additions require signed override
//! artifacts and all policy transitions append structured governance events.
//!
//! Plan references: Section 10.15 (9I.1), bead bd-2xu5.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SigningKey, VerificationKey, sign_preimage, verify_signature,
};

const TEE_ATTESTATION_POLICY_SCHEMA_DEF: &[u8] = b"FrankenEngine.TeeAttestationPolicy.v1";
const TRUST_ROOT_OVERRIDE_ARTIFACT_SCHEMA_DEF: &[u8] =
    b"FrankenEngine.TrustRootOverrideArtifact.v1";
const POLICY_ZONE: &str = "tee-attestation";
const COMPONENT_NAME: &str = "tee_attestation_policy";

fn tee_attestation_policy_schema_id() -> SchemaId {
    SchemaId::from_definition(TEE_ATTESTATION_POLICY_SCHEMA_DEF)
}

fn trust_root_override_artifact_schema_id() -> SchemaId {
    SchemaId::from_definition(TRUST_ROOT_OVERRIDE_ARTIFACT_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// TeePlatform
// ---------------------------------------------------------------------------

/// Supported TEE platforms for decision-receipt attestation binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeePlatform {
    IntelSgx,
    ArmTrustZone,
    ArmCca,
    AmdSev,
}

impl TeePlatform {
    pub const ALL: [Self; 4] = [
        Self::IntelSgx,
        Self::ArmTrustZone,
        Self::ArmCca,
        Self::AmdSev,
    ];

    /// Stable canonical tag for hashing/signing contexts, decoupled from Display.
    pub fn canonical_tag(&self) -> &'static str {
        match self {
            Self::IntelSgx => "intel_sgx",
            Self::ArmTrustZone => "arm_trustzone",
            Self::ArmCca => "arm_cca",
            Self::AmdSev => "amd_sev",
        }
    }
}

impl fmt::Display for TeePlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntelSgx => f.write_str("intel_sgx"),
            Self::ArmTrustZone => f.write_str("arm_trustzone"),
            Self::ArmCca => f.write_str("arm_cca"),
            Self::AmdSev => f.write_str("amd_sev"),
        }
    }
}

// ---------------------------------------------------------------------------
// MeasurementDigest
// ---------------------------------------------------------------------------

/// Hash algorithm used for a platform measurement digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl MeasurementAlgorithm {
    fn digest_len_bytes(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

impl fmt::Display for MeasurementAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha256 => f.write_str("sha256"),
            Self::Sha384 => f.write_str("sha384"),
            Self::Sha512 => f.write_str("sha512"),
        }
    }
}

/// Measurement digest approved for a specific platform.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MeasurementDigest {
    pub algorithm: MeasurementAlgorithm,
    /// Lowercase hex-encoded digest bytes.
    pub digest_hex: String,
}

impl MeasurementDigest {
    fn canonicalize(&mut self) {
        self.digest_hex = self.digest_hex.to_ascii_lowercase();
    }

    fn validate_for_platform(
        &self,
        platform: TeePlatform,
    ) -> Result<(), TeeAttestationPolicyError> {
        let expected_hex_len = self.algorithm.digest_len_bytes() * 2;
        if self.digest_hex.len() != expected_hex_len {
            return Err(TeeAttestationPolicyError::InvalidMeasurementDigest {
                platform,
                digest: self.digest_hex.clone(),
                expected_hex_len,
            });
        }
        if !is_hex_ascii(&self.digest_hex) {
            return Err(TeeAttestationPolicyError::InvalidMeasurementDigest {
                platform,
                digest: self.digest_hex.clone(),
                expected_hex_len,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Freshness windows
// ---------------------------------------------------------------------------

/// Maximum accepted quote age in seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationFreshnessWindow {
    /// Maximum quote age for standard decisions.
    pub standard_max_age_secs: u64,
    /// Maximum quote age for high-impact decisions.
    pub high_impact_max_age_secs: u64,
}

impl AttestationFreshnessWindow {
    fn validate(&self) -> Result<(), TeeAttestationPolicyError> {
        if self.standard_max_age_secs == 0
            || self.high_impact_max_age_secs == 0
            || self.high_impact_max_age_secs > self.standard_max_age_secs
        {
            return Err(TeeAttestationPolicyError::InvalidFreshnessWindow {
                standard_max_age_secs: self.standard_max_age_secs,
                high_impact_max_age_secs: self.high_impact_max_age_secs,
            });
        }
        Ok(())
    }

    fn max_age_for(&self, impact: DecisionImpact) -> u64 {
        match impact {
            DecisionImpact::Standard => self.standard_max_age_secs,
            DecisionImpact::HighImpact => self.high_impact_max_age_secs,
        }
    }
}

// ---------------------------------------------------------------------------
// Revocation source policy
// ---------------------------------------------------------------------------

/// Revocation endpoint family.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationSourceType {
    IntelPcs,
    ManufacturerCrl,
    InternalLedger,
    Other(String),
}

/// Fallback behavior when a revocation source is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationFallback {
    /// Attempt the next source in configured order.
    TryNextSource,
    /// Fail closed immediately.
    FailClosed,
}

/// One revocation-check endpoint in ordered fallback sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationSource {
    pub source_id: String,
    pub source_type: RevocationSourceType,
    pub endpoint: String,
    pub on_unavailable: RevocationFallback,
}

impl RevocationSource {
    fn validate(&self) -> Result<(), TeeAttestationPolicyError> {
        if self.source_id.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidRevocationSource {
                reason: "source_id is empty".to_string(),
            });
        }
        if self.endpoint.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidRevocationSource {
                reason: format!("endpoint is empty for source '{}'", self.source_id),
            });
        }
        if let RevocationSourceType::Other(name) = &self.source_type
            && name.trim().is_empty()
        {
            return Err(TeeAttestationPolicyError::InvalidRevocationSource {
                reason: format!("source '{}' has empty custom source_type", self.source_id),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Trust roots
// ---------------------------------------------------------------------------

/// Pinning/rotation semantics for a platform trust root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRootPinning {
    /// Hard pin: trust only this root ID unless policy explicitly changes.
    Pinned,
    /// Root can rotate inside a named rotation group.
    Rotating { rotation_group: String },
}

/// Source of a configured trust root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRootSource {
    /// Present in baseline policy document.
    Policy,
    /// Temporary operator override with signed justification.
    TemporaryOverride {
        override_id: String,
        justification_artifact_id: String,
    },
}

/// One trust root accepted for a platform's attestation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformTrustRoot {
    pub root_id: String,
    pub platform: TeePlatform,
    /// PEM payload or equivalent encoded trust anchor.
    pub trust_anchor_pem: String,
    pub valid_from_epoch: SecurityEpoch,
    pub valid_until_epoch: Option<SecurityEpoch>,
    pub pinning: TrustRootPinning,
    pub source: TrustRootSource,
}

impl PlatformTrustRoot {
    fn validate(&self) -> Result<(), TeeAttestationPolicyError> {
        if self.root_id.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                root_id: self.root_id.clone(),
                reason: "root_id is empty".to_string(),
            });
        }
        if self.trust_anchor_pem.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                root_id: self.root_id.clone(),
                reason: "trust_anchor_pem is empty".to_string(),
            });
        }
        if let Some(until) = self.valid_until_epoch
            && until.as_u64() < self.valid_from_epoch.as_u64()
        {
            return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                root_id: self.root_id.clone(),
                reason: "valid_until_epoch is before valid_from_epoch".to_string(),
            });
        }
        if let TrustRootPinning::Rotating { rotation_group } = &self.pinning {
            if rotation_group.trim().is_empty() {
                return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                    root_id: self.root_id.clone(),
                    reason: "rotating root has empty rotation_group".to_string(),
                });
            }
            if self.valid_until_epoch.is_none() {
                return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                    root_id: self.root_id.clone(),
                    reason: "rotating root must set valid_until_epoch".to_string(),
                });
            }
        }
        if let TrustRootSource::TemporaryOverride {
            override_id,
            justification_artifact_id,
        } = &self.source
        {
            if override_id.trim().is_empty() || justification_artifact_id.trim().is_empty() {
                return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                    root_id: self.root_id.clone(),
                    reason: "temporary override metadata is incomplete".to_string(),
                });
            }
            if self.valid_until_epoch.is_none() {
                return Err(TeeAttestationPolicyError::InvalidTrustRoot {
                    root_id: self.root_id.clone(),
                    reason: "temporary override root must set valid_until_epoch".to_string(),
                });
            }
        }
        Ok(())
    }

    fn active_at_epoch(&self, epoch: SecurityEpoch) -> bool {
        if epoch.as_u64() < self.valid_from_epoch.as_u64() {
            return false;
        }
        match self.valid_until_epoch {
            Some(until) => epoch.as_u64() <= until.as_u64(),
            None => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Policy schema
// ---------------------------------------------------------------------------

/// Machine-readable TEE attestation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeAttestationPolicy {
    /// Additive schema version for policy contract compatibility.
    pub schema_version: u32,
    /// Security epoch at which this policy becomes authoritative.
    pub policy_epoch: SecurityEpoch,
    /// Approved measurement digests per supported platform.
    pub approved_measurements: BTreeMap<TeePlatform, Vec<MeasurementDigest>>,
    /// Quote freshness policy.
    pub freshness_window: AttestationFreshnessWindow,
    /// Ordered revocation sources (fallback order is significant).
    pub revocation_sources: Vec<RevocationSource>,
    /// Trust roots accepted for quote-chain verification.
    pub platform_trust_roots: Vec<PlatformTrustRoot>,
}

impl TeeAttestationPolicy {
    /// Parse, canonicalize, and validate from JSON.
    pub fn from_json(policy_json: &str) -> Result<Self, TeeAttestationPolicyError> {
        let mut parsed: Self = serde_json::from_str(policy_json).map_err(|e| {
            TeeAttestationPolicyError::ParseFailed {
                detail: e.to_string(),
            }
        })?;
        parsed.canonicalize_in_place();
        parsed.validate()?;
        Ok(parsed)
    }

    /// Encode policy to canonical JSON (sorted deterministic collections).
    pub fn to_canonical_json(&self) -> Result<String, TeeAttestationPolicyError> {
        let mut clone = self.clone();
        clone.canonicalize_in_place();
        serde_json::to_string(&clone).map_err(|e| TeeAttestationPolicyError::SerializationFailed {
            detail: e.to_string(),
        })
    }

    /// Deterministically derive a policy object ID.
    pub fn derive_policy_id(&self) -> Result<EngineObjectId, TeeAttestationPolicyError> {
        let canonical_json = self.to_canonical_json()?;
        engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            POLICY_ZONE,
            &tee_attestation_policy_schema_id(),
            canonical_json.as_bytes(),
        )
        .map_err(|e| TeeAttestationPolicyError::IdDerivationFailed {
            detail: e.to_string(),
        })
    }

    /// Validate policy invariants.
    pub fn validate(&self) -> Result<(), TeeAttestationPolicyError> {
        if self.schema_version != 1 {
            return Err(TeeAttestationPolicyError::ParseFailed {
                detail: format!(
                    "unsupported schema version {}: only version 1 is recognized",
                    self.schema_version
                ),
            });
        }
        self.freshness_window.validate()?;

        for platform in TeePlatform::ALL {
            let Some(measurements) = self.approved_measurements.get(&platform) else {
                return Err(TeeAttestationPolicyError::MissingMeasurementsForPlatform { platform });
            };
            if measurements.is_empty() {
                return Err(TeeAttestationPolicyError::MissingMeasurementsForPlatform { platform });
            }
            let mut seen = BTreeSet::new();
            for digest in measurements {
                digest.validate_for_platform(platform)?;
                let key = (digest.algorithm, digest.digest_hex.clone());
                if !seen.insert(key) {
                    return Err(TeeAttestationPolicyError::DuplicateMeasurementDigest {
                        platform,
                        digest: digest.digest_hex.clone(),
                    });
                }
            }
        }

        if self.revocation_sources.is_empty() {
            return Err(TeeAttestationPolicyError::EmptyRevocationSources);
        }
        let mut seen_source_ids = BTreeSet::new();
        let mut has_fail_closed_source = false;
        for source in &self.revocation_sources {
            source.validate()?;
            if !seen_source_ids.insert(source.source_id.clone()) {
                return Err(TeeAttestationPolicyError::DuplicateRevocationSource {
                    source_id: source.source_id.clone(),
                });
            }
            if source.on_unavailable == RevocationFallback::FailClosed {
                has_fail_closed_source = true;
            }
        }
        if !has_fail_closed_source {
            return Err(TeeAttestationPolicyError::RevocationFallbackBypass);
        }

        if self.platform_trust_roots.is_empty() {
            return Err(TeeAttestationPolicyError::MissingTrustRoots);
        }
        let mut seen_root_keys = BTreeSet::new();
        let mut has_pinned_for_platform: BTreeMap<TeePlatform, bool> =
            TeePlatform::ALL.into_iter().map(|p| (p, false)).collect();
        for root in &self.platform_trust_roots {
            root.validate()?;
            let dedup_key = (root.platform, root.root_id.clone());
            if !seen_root_keys.insert(dedup_key) {
                return Err(TeeAttestationPolicyError::DuplicateTrustRoot {
                    platform: root.platform,
                    root_id: root.root_id.clone(),
                });
            }
            if matches!(root.pinning, TrustRootPinning::Pinned)
                && root.active_at_epoch(self.policy_epoch)
            {
                has_pinned_for_platform.insert(root.platform, true);
            }
        }
        for platform in TeePlatform::ALL {
            if !has_pinned_for_platform
                .get(&platform)
                .copied()
                .unwrap_or(false)
            {
                return Err(TeeAttestationPolicyError::MissingPinnedTrustRoot { platform });
            }
        }

        Ok(())
    }

    /// Validate one quote against this policy at runtime epoch.
    pub fn evaluate_quote(
        &self,
        quote: &AttestationQuote,
        impact: DecisionImpact,
        runtime_epoch: SecurityEpoch,
    ) -> Result<(), TeeAttestationPolicyError> {
        quote.measurement.validate_for_platform(quote.platform)?;

        let approved = self.approved_measurements.get(&quote.platform).ok_or(
            TeeAttestationPolicyError::MissingMeasurementsForPlatform {
                platform: quote.platform,
            },
        )?;
        let measurement_approved = approved.iter().any(|candidate| {
            candidate.algorithm == quote.measurement.algorithm
                && candidate.digest_hex == quote.measurement.digest_hex
        });
        if !measurement_approved {
            return Err(TeeAttestationPolicyError::UnknownMeasurementDigest {
                platform: quote.platform,
                digest: quote.measurement.digest_hex.clone(),
            });
        }

        let max_age_secs = self.freshness_window.max_age_for(impact);
        if quote.quote_age_secs > max_age_secs {
            return Err(TeeAttestationPolicyError::AttestationStale {
                quote_age_secs: quote.quote_age_secs,
                max_age_secs,
            });
        }

        let root_match = self
            .platform_trust_roots
            .iter()
            .find(|root| root.platform == quote.platform && root.root_id == quote.trust_root_id);
        let Some(root) = root_match else {
            return Err(TeeAttestationPolicyError::UnknownTrustRoot {
                platform: quote.platform,
                root_id: quote.trust_root_id.clone(),
            });
        };
        if !root.active_at_epoch(runtime_epoch) {
            return Err(TeeAttestationPolicyError::ExpiredTrustRoot {
                root_id: root.root_id.clone(),
                runtime_epoch,
                valid_until_epoch: root.valid_until_epoch,
            });
        }

        let mut any_good = false;
        for source in &self.revocation_sources {
            let observation = quote
                .revocation_observations
                .get(&source.source_id)
                .copied()
                .unwrap_or(RevocationProbeStatus::Unavailable);
            match observation {
                RevocationProbeStatus::Good => any_good = true,
                RevocationProbeStatus::Revoked => {
                    return Err(TeeAttestationPolicyError::RevokedBySource {
                        source_id: source.source_id.clone(),
                    });
                }
                RevocationProbeStatus::Unavailable => {
                    if source.on_unavailable == RevocationFallback::FailClosed {
                        return Err(TeeAttestationPolicyError::RevocationSourceUnavailable {
                            source_id: source.source_id.clone(),
                        });
                    }
                }
            }
        }

        if any_good || self.revocation_sources.is_empty() {
            Ok(())
        } else {
            Err(TeeAttestationPolicyError::RevocationEvidenceUnavailable)
        }
    }

    fn canonicalize_in_place(&mut self) {
        for measurements in self.approved_measurements.values_mut() {
            for digest in measurements.iter_mut() {
                digest.canonicalize();
            }
            measurements.sort();
            measurements.dedup();
        }
        for root in &mut self.platform_trust_roots {
            root.root_id = root.root_id.trim().to_string();
        }
        self.platform_trust_roots.sort_by(|a, b| {
            (a.platform, a.root_id.as_str()).cmp(&(b.platform, b.root_id.as_str()))
        });
    }
}

// ---------------------------------------------------------------------------
// Quote model
// ---------------------------------------------------------------------------

/// Impact class for decision-receipt emission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionImpact {
    Standard,
    HighImpact,
}

/// Revocation source result at quote verification time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationProbeStatus {
    Good,
    Revoked,
    Unavailable,
}

/// Input quote attributes evaluated by policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationQuote {
    pub platform: TeePlatform,
    pub measurement: MeasurementDigest,
    pub quote_age_secs: u64,
    pub trust_root_id: String,
    pub revocation_observations: BTreeMap<String, RevocationProbeStatus>,
}

// ---------------------------------------------------------------------------
// Signed override artifacts
// ---------------------------------------------------------------------------

/// Unsigned payload for temporary trust-root override authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRootOverrideArtifactInput {
    pub actor: String,
    pub justification: String,
    pub evidence_refs: Vec<String>,
    pub target_platform: TeePlatform,
    pub target_root_id: String,
    pub issued_epoch: SecurityEpoch,
    pub expires_epoch: SecurityEpoch,
}

/// Signed justification artifact for temporary trust-root additions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTrustRootOverrideArtifact {
    pub artifact_id: String,
    pub actor: String,
    pub justification: String,
    pub evidence_refs: Vec<String>,
    pub target_platform: TeePlatform,
    pub target_root_id: String,
    pub issued_epoch: SecurityEpoch,
    pub expires_epoch: SecurityEpoch,
    pub signature: Signature,
}

impl SignedTrustRootOverrideArtifact {
    /// Create and sign a new override artifact.
    pub fn create_signed(
        signer: &SigningKey,
        mut input: TrustRootOverrideArtifactInput,
    ) -> Result<Self, TeeAttestationPolicyError> {
        if input.actor.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidOverrideArtifact {
                reason: "actor is empty".to_string(),
            });
        }
        if input.justification.trim().is_empty() {
            return Err(TeeAttestationPolicyError::OverrideJustificationMissing);
        }
        if input.target_root_id.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidOverrideArtifact {
                reason: "target_root_id is empty".to_string(),
            });
        }
        if input.expires_epoch.as_u64() <= input.issued_epoch.as_u64() {
            return Err(TeeAttestationPolicyError::InvalidOverrideArtifact {
                reason: "expires_epoch must be after issued_epoch".to_string(),
            });
        }
        input.evidence_refs.sort();
        input.evidence_refs.dedup();

        let mut artifact = Self {
            artifact_id: String::new(),
            actor: input.actor,
            justification: input.justification,
            evidence_refs: input.evidence_refs,
            target_platform: input.target_platform,
            target_root_id: input.target_root_id,
            issued_epoch: input.issued_epoch,
            expires_epoch: input.expires_epoch,
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        let id_preimage = artifact.preimage_bytes();
        artifact.artifact_id = ContentHash::compute(&id_preimage).to_hex();
        let signature_preimage = artifact.preimage_bytes();
        artifact.signature = sign_preimage(signer, &signature_preimage).map_err(|e| {
            TeeAttestationPolicyError::OverrideSignatureInvalid {
                detail: e.to_string(),
            }
        })?;
        Ok(artifact)
    }

    /// Verify artifact signature and freshness.
    pub fn verify(
        &self,
        verifier: &VerificationKey,
        current_epoch: SecurityEpoch,
    ) -> Result<(), TeeAttestationPolicyError> {
        if self.justification.trim().is_empty() {
            return Err(TeeAttestationPolicyError::OverrideJustificationMissing);
        }
        if current_epoch.as_u64() >= self.expires_epoch.as_u64() {
            return Err(TeeAttestationPolicyError::OverrideExpired {
                current_epoch,
                expires_epoch: self.expires_epoch,
            });
        }
        let preimage = self.preimage_bytes();
        verify_signature(verifier, &preimage, &self.signature).map_err(|e| {
            TeeAttestationPolicyError::OverrideSignatureInvalid {
                detail: e.to_string(),
            }
        })?;
        Ok(())
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let unsigned_map = self.unsigned_value();
        let value_bytes = crate::deterministic_serde::encode_value(&unsigned_map);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(ObjectDomain::PolicyObject.tag());
        preimage.extend_from_slice(trust_root_override_artifact_schema_id().as_bytes());
        preimage.extend_from_slice(&value_bytes);
        preimage
    }

    fn unsigned_value(&self) -> crate::deterministic_serde::CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "actor".to_string(),
            crate::deterministic_serde::CanonicalValue::String(self.actor.clone()),
        );
        map.insert(
            "artifact_id".to_string(),
            crate::deterministic_serde::CanonicalValue::String(self.artifact_id.clone()),
        );
        map.insert(
            "evidence_refs".to_string(),
            crate::deterministic_serde::CanonicalValue::Array(
                self.evidence_refs
                    .iter()
                    .map(|s| crate::deterministic_serde::CanonicalValue::String(s.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "expires_epoch".to_string(),
            crate::deterministic_serde::CanonicalValue::U64(self.expires_epoch.as_u64()),
        );
        map.insert(
            "issued_epoch".to_string(),
            crate::deterministic_serde::CanonicalValue::U64(self.issued_epoch.as_u64()),
        );
        map.insert(
            "justification".to_string(),
            crate::deterministic_serde::CanonicalValue::String(self.justification.clone()),
        );
        map.insert(
            "signature".to_string(),
            crate::deterministic_serde::CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        map.insert(
            "target_platform".to_string(),
            crate::deterministic_serde::CanonicalValue::String(
                self.target_platform.canonical_tag().to_string(),
            ),
        );
        map.insert(
            "target_root_id".to_string(),
            crate::deterministic_serde::CanonicalValue::String(self.target_root_id.clone()),
        );
        crate::deterministic_serde::CanonicalValue::Map(map)
    }
}

/// Request to add one temporary trust root via signed override artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporaryTrustRootOverride {
    pub override_id: String,
    pub trust_root: PlatformTrustRoot,
    pub artifact: SignedTrustRootOverrideArtifact,
}

impl TemporaryTrustRootOverride {
    fn validate(
        &self,
        verifier: &VerificationKey,
        current_epoch: SecurityEpoch,
    ) -> Result<(), TeeAttestationPolicyError> {
        if self.override_id.trim().is_empty() {
            return Err(TeeAttestationPolicyError::InvalidOverrideArtifact {
                reason: "override_id is empty".to_string(),
            });
        }
        self.artifact.verify(verifier, current_epoch)?;
        if self.trust_root.platform != self.artifact.target_platform
            || self.trust_root.root_id != self.artifact.target_root_id
        {
            return Err(TeeAttestationPolicyError::OverrideTargetMismatch {
                expected_platform: self.artifact.target_platform,
                expected_root_id: self.artifact.target_root_id.clone(),
                actual_platform: self.trust_root.platform,
                actual_root_id: self.trust_root.root_id.clone(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Governance event ledger
// ---------------------------------------------------------------------------

/// Structured policy-governance event entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyGovernanceEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: String,
    pub metadata: BTreeMap<String, String>,
}

/// Runtime policy store with fail-closed load semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeAttestationPolicyStore {
    active_policy: Option<TeeAttestationPolicy>,
    governance_ledger: Vec<PolicyGovernanceEvent>,
    receipt_emission_halted: bool,
    last_error_code: Option<String>,
}

impl Default for TeeAttestationPolicyStore {
    fn default() -> Self {
        Self {
            active_policy: None,
            governance_ledger: Vec::new(),
            receipt_emission_halted: true,
            last_error_code: Some("policy_not_loaded".to_string()),
        }
    }
}

impl TeeAttestationPolicyStore {
    pub fn active_policy(&self) -> Option<&TeeAttestationPolicy> {
        self.active_policy.as_ref()
    }

    pub fn governance_ledger(&self) -> &[PolicyGovernanceEvent] {
        &self.governance_ledger
    }

    pub fn receipt_emission_halted(&self) -> bool {
        self.receipt_emission_halted
    }

    pub fn last_error_code(&self) -> Option<&str> {
        self.last_error_code.as_deref()
    }

    /// Parse + load policy from JSON. On error, enter fail-closed halt.
    pub fn load_policy_json(
        &mut self,
        policy_json: &str,
        trace_id: &str,
        decision_id: &str,
    ) -> Result<EngineObjectId, TeeAttestationPolicyError> {
        match TeeAttestationPolicy::from_json(policy_json) {
            Ok(policy) => self.load_policy(policy, trace_id, decision_id),
            Err(err) => {
                self.receipt_emission_halted = true;
                self.last_error_code = Some(err.error_code().to_string());
                let mut metadata = BTreeMap::new();
                metadata.insert("reason".to_string(), err.to_string());
                self.append_event(PolicyGovernanceEvent {
                    trace_id: trace_id.to_string(),
                    decision_id: decision_id.to_string(),
                    policy_id: "policy-unavailable".to_string(),
                    component: COMPONENT_NAME.to_string(),
                    event: "policy_load_failed".to_string(),
                    outcome: "deny".to_string(),
                    error_code: err.error_code().to_string(),
                    metadata,
                });
                Err(err)
            }
        }
    }

    /// Load a validated policy object.
    pub fn load_policy(
        &mut self,
        policy: TeeAttestationPolicy,
        trace_id: &str,
        decision_id: &str,
    ) -> Result<EngineObjectId, TeeAttestationPolicyError> {
        policy.validate()?;
        if let Some(current) = self.active_policy.as_ref()
            && policy.policy_epoch.as_u64() <= current.policy_epoch.as_u64()
        {
            let err = TeeAttestationPolicyError::PolicyEpochRegression {
                current: current.policy_epoch,
                attempted: policy.policy_epoch,
            };
            self.receipt_emission_halted = true;
            self.last_error_code = Some(err.error_code().to_string());
            let mut metadata = BTreeMap::new();
            metadata.insert("reason".to_string(), err.to_string());
            self.append_event(PolicyGovernanceEvent {
                trace_id: trace_id.to_string(),
                decision_id: decision_id.to_string(),
                policy_id: "policy-unavailable".to_string(),
                component: COMPONENT_NAME.to_string(),
                event: "policy_load_failed".to_string(),
                outcome: "deny".to_string(),
                error_code: err.error_code().to_string(),
                metadata,
            });
            return Err(err);
        }

        let policy_id = policy.derive_policy_id()?;
        self.active_policy = Some(policy.clone());
        self.receipt_emission_halted = false;
        self.last_error_code = None;
        let mut metadata = BTreeMap::new();
        metadata.insert(
            "policy_epoch".to_string(),
            policy.policy_epoch.as_u64().to_string(),
        );
        metadata.insert(
            "schema_version".to_string(),
            policy.schema_version.to_string(),
        );
        self.append_event(PolicyGovernanceEvent {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_hex(),
            component: COMPONENT_NAME.to_string(),
            event: "policy_loaded".to_string(),
            outcome: "allow".to_string(),
            error_code: "ok".to_string(),
            metadata,
        });
        Ok(policy_id)
    }

    /// Apply temporary trust-root override with signed justification artifact.
    pub fn apply_temporary_trust_root_override(
        &mut self,
        request: TemporaryTrustRootOverride,
        verifier: &VerificationKey,
        current_epoch: SecurityEpoch,
        trace_id: &str,
        decision_id: &str,
    ) -> Result<EngineObjectId, TeeAttestationPolicyError> {
        let current_policy = self
            .active_policy
            .as_ref()
            .cloned()
            .ok_or(TeeAttestationPolicyError::NoActivePolicy)?;
        request.validate(verifier, current_epoch)?;

        let mut candidate = current_policy;
        let mut root = request.trust_root.clone();
        root.source = TrustRootSource::TemporaryOverride {
            override_id: request.override_id.clone(),
            justification_artifact_id: request.artifact.artifact_id.clone(),
        };
        let capped_expiry = match root.valid_until_epoch {
            Some(until) => {
                SecurityEpoch::from_raw(until.as_u64().min(request.artifact.expires_epoch.as_u64()))
            }
            None => request.artifact.expires_epoch,
        };
        root.valid_until_epoch = Some(capped_expiry);

        if let Some(existing_idx) = candidate.platform_trust_roots.iter().position(|existing| {
            existing.platform == root.platform && existing.root_id == root.root_id
        }) {
            candidate.platform_trust_roots[existing_idx] = root;
        } else {
            candidate.platform_trust_roots.push(root);
        }
        candidate.canonicalize_in_place();
        candidate.validate()?;
        let policy_id = candidate.derive_policy_id()?;

        self.active_policy = Some(candidate);
        self.receipt_emission_halted = false;
        self.last_error_code = None;
        let mut metadata = BTreeMap::new();
        metadata.insert("override_id".to_string(), request.override_id);
        metadata.insert(
            "justification_artifact_id".to_string(),
            request.artifact.artifact_id,
        );
        metadata.insert(
            "expires_epoch".to_string(),
            request.artifact.expires_epoch.as_u64().to_string(),
        );
        self.append_event(PolicyGovernanceEvent {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_hex(),
            component: COMPONENT_NAME.to_string(),
            event: "temporary_trust_root_override_applied".to_string(),
            outcome: "allow".to_string(),
            error_code: "ok".to_string(),
            metadata,
        });
        Ok(policy_id)
    }

    /// Validate a quote against active policy and append governance event.
    pub fn evaluate_quote(
        &mut self,
        quote: &AttestationQuote,
        impact: DecisionImpact,
        runtime_epoch: SecurityEpoch,
        trace_id: &str,
        decision_id: &str,
    ) -> Result<(), TeeAttestationPolicyError> {
        if self.receipt_emission_halted {
            let err = TeeAttestationPolicyError::ReceiptEmissionHalted;
            self.append_event(PolicyGovernanceEvent {
                trace_id: trace_id.to_string(),
                decision_id: decision_id.to_string(),
                policy_id: "policy-unavailable".to_string(),
                component: COMPONENT_NAME.to_string(),
                event: "quote_evaluation_failed".to_string(),
                outcome: "deny".to_string(),
                error_code: err.error_code().to_string(),
                metadata: BTreeMap::new(),
            });
            return Err(err);
        }
        let Some(policy) = self.active_policy.clone() else {
            let err = TeeAttestationPolicyError::NoActivePolicy;
            self.append_event(PolicyGovernanceEvent {
                trace_id: trace_id.to_string(),
                decision_id: decision_id.to_string(),
                policy_id: "policy-unavailable".to_string(),
                component: COMPONENT_NAME.to_string(),
                event: "quote_evaluation_failed".to_string(),
                outcome: "deny".to_string(),
                error_code: err.error_code().to_string(),
                metadata: BTreeMap::new(),
            });
            return Err(err);
        };
        let policy_id = policy.derive_policy_id()?;
        match policy.evaluate_quote(quote, impact, runtime_epoch) {
            Ok(()) => {
                let mut metadata = BTreeMap::new();
                metadata.insert("platform".to_string(), quote.platform.to_string());
                metadata.insert("trust_root_id".to_string(), quote.trust_root_id.clone());
                self.append_event(PolicyGovernanceEvent {
                    trace_id: trace_id.to_string(),
                    decision_id: decision_id.to_string(),
                    policy_id: policy_id.to_hex(),
                    component: COMPONENT_NAME.to_string(),
                    event: "quote_accepted".to_string(),
                    outcome: "allow".to_string(),
                    error_code: "ok".to_string(),
                    metadata,
                });
                Ok(())
            }
            Err(err) => {
                let mut metadata = BTreeMap::new();
                metadata.insert("platform".to_string(), quote.platform.to_string());
                metadata.insert("trust_root_id".to_string(), quote.trust_root_id.clone());
                metadata.insert("reason".to_string(), err.to_string());
                self.append_event(PolicyGovernanceEvent {
                    trace_id: trace_id.to_string(),
                    decision_id: decision_id.to_string(),
                    policy_id: policy_id.to_hex(),
                    component: COMPONENT_NAME.to_string(),
                    event: "quote_rejected".to_string(),
                    outcome: "deny".to_string(),
                    error_code: err.error_code().to_string(),
                    metadata,
                });
                Err(err)
            }
        }
    }

    fn append_event(&mut self, entry: PolicyGovernanceEvent) {
        self.governance_ledger.push(entry);
    }
}

// ---------------------------------------------------------------------------
// Decision-receipt emitter sync policy
// ---------------------------------------------------------------------------

/// Lightweight receipt-emitter state tracking policy-epoch sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceiptEmitter {
    pub emitter_id: String,
    pub last_synced_policy_epoch: Option<SecurityEpoch>,
}

impl DecisionReceiptEmitter {
    pub fn new(emitter_id: impl Into<String>) -> Self {
        Self {
            emitter_id: emitter_id.into(),
            last_synced_policy_epoch: None,
        }
    }

    /// Pull current policy epoch from store.
    pub fn sync_policy(
        &mut self,
        store: &TeeAttestationPolicyStore,
    ) -> Result<SecurityEpoch, TeeAttestationPolicyError> {
        if store.receipt_emission_halted {
            return Err(TeeAttestationPolicyError::ReceiptEmissionHalted);
        }
        let epoch = store
            .active_policy()
            .map(|policy| policy.policy_epoch)
            .ok_or(TeeAttestationPolicyError::NoActivePolicy)?;
        self.last_synced_policy_epoch = Some(epoch);
        Ok(epoch)
    }

    /// Ensure emitter is synced not more than one epoch behind.
    pub fn can_emit(
        &self,
        runtime_epoch: SecurityEpoch,
        store: &TeeAttestationPolicyStore,
    ) -> Result<(), TeeAttestationPolicyError> {
        if store.receipt_emission_halted {
            return Err(TeeAttestationPolicyError::ReceiptEmissionHalted);
        }
        let active_epoch = store
            .active_policy()
            .map(|policy| policy.policy_epoch)
            .ok_or(TeeAttestationPolicyError::NoActivePolicy)?;
        let synced_epoch =
            self.last_synced_policy_epoch
                .ok_or(TeeAttestationPolicyError::EmitterNotSynced {
                    emitter_id: self.emitter_id.clone(),
                })?;
        if active_epoch.as_u64() > synced_epoch.as_u64().saturating_add(1) {
            return Err(TeeAttestationPolicyError::EmitterPolicyStale {
                emitter_id: self.emitter_id.clone(),
                synced_epoch,
                required_epoch: active_epoch,
            });
        }
        if runtime_epoch.as_u64() > synced_epoch.as_u64().saturating_add(1) {
            return Err(TeeAttestationPolicyError::EmitterPolicyStale {
                emitter_id: self.emitter_id.clone(),
                synced_epoch,
                required_epoch: runtime_epoch,
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from TEE attestation policy loading/validation/evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeeAttestationPolicyError {
    ParseFailed {
        detail: String,
    },
    SerializationFailed {
        detail: String,
    },
    MissingMeasurementsForPlatform {
        platform: TeePlatform,
    },
    InvalidMeasurementDigest {
        platform: TeePlatform,
        digest: String,
        expected_hex_len: usize,
    },
    DuplicateMeasurementDigest {
        platform: TeePlatform,
        digest: String,
    },
    InvalidFreshnessWindow {
        standard_max_age_secs: u64,
        high_impact_max_age_secs: u64,
    },
    EmptyRevocationSources,
    InvalidRevocationSource {
        reason: String,
    },
    DuplicateRevocationSource {
        source_id: String,
    },
    RevocationFallbackBypass,
    MissingTrustRoots,
    InvalidTrustRoot {
        root_id: String,
        reason: String,
    },
    DuplicateTrustRoot {
        platform: TeePlatform,
        root_id: String,
    },
    MissingPinnedTrustRoot {
        platform: TeePlatform,
    },
    PolicyEpochRegression {
        current: SecurityEpoch,
        attempted: SecurityEpoch,
    },
    IdDerivationFailed {
        detail: String,
    },
    ReceiptEmissionHalted,
    NoActivePolicy,
    UnknownMeasurementDigest {
        platform: TeePlatform,
        digest: String,
    },
    AttestationStale {
        quote_age_secs: u64,
        max_age_secs: u64,
    },
    UnknownTrustRoot {
        platform: TeePlatform,
        root_id: String,
    },
    ExpiredTrustRoot {
        root_id: String,
        runtime_epoch: SecurityEpoch,
        valid_until_epoch: Option<SecurityEpoch>,
    },
    RevokedBySource {
        source_id: String,
    },
    RevocationSourceUnavailable {
        source_id: String,
    },
    RevocationEvidenceUnavailable,
    InvalidOverrideArtifact {
        reason: String,
    },
    OverrideJustificationMissing,
    OverrideExpired {
        current_epoch: SecurityEpoch,
        expires_epoch: SecurityEpoch,
    },
    OverrideSignatureInvalid {
        detail: String,
    },
    OverrideTargetMismatch {
        expected_platform: TeePlatform,
        expected_root_id: String,
        actual_platform: TeePlatform,
        actual_root_id: String,
    },
    EmitterNotSynced {
        emitter_id: String,
    },
    EmitterPolicyStale {
        emitter_id: String,
        synced_epoch: SecurityEpoch,
        required_epoch: SecurityEpoch,
    },
}

impl TeeAttestationPolicyError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::ParseFailed { .. } => "tee_policy_parse_failed",
            Self::SerializationFailed { .. } => "tee_policy_serialize_failed",
            Self::MissingMeasurementsForPlatform { .. } => "tee_policy_missing_measurements",
            Self::InvalidMeasurementDigest { .. } => "tee_policy_invalid_measurement_digest",
            Self::DuplicateMeasurementDigest { .. } => "tee_policy_duplicate_measurement_digest",
            Self::InvalidFreshnessWindow { .. } => "tee_policy_invalid_freshness_window",
            Self::EmptyRevocationSources => "tee_policy_empty_revocation_sources",
            Self::InvalidRevocationSource { .. } => "tee_policy_invalid_revocation_source",
            Self::DuplicateRevocationSource { .. } => "tee_policy_duplicate_revocation_source",
            Self::RevocationFallbackBypass => "tee_policy_revocation_bypass_config",
            Self::MissingTrustRoots => "tee_policy_missing_trust_roots",
            Self::InvalidTrustRoot { .. } => "tee_policy_invalid_trust_root",
            Self::DuplicateTrustRoot { .. } => "tee_policy_duplicate_trust_root",
            Self::MissingPinnedTrustRoot { .. } => "tee_policy_missing_pinned_trust_root",
            Self::PolicyEpochRegression { .. } => "tee_policy_epoch_regression",
            Self::IdDerivationFailed { .. } => "tee_policy_id_derivation_failed",
            Self::ReceiptEmissionHalted => "tee_policy_emission_halted",
            Self::NoActivePolicy => "tee_policy_not_loaded",
            Self::UnknownMeasurementDigest { .. } => "tee_policy_measurement_not_approved",
            Self::AttestationStale { .. } => "tee_policy_attestation_stale",
            Self::UnknownTrustRoot { .. } => "tee_policy_unknown_trust_root",
            Self::ExpiredTrustRoot { .. } => "tee_policy_expired_trust_root",
            Self::RevokedBySource { .. } => "tee_policy_revoked",
            Self::RevocationSourceUnavailable { .. } => "tee_policy_revocation_source_unavailable",
            Self::RevocationEvidenceUnavailable => "tee_policy_revocation_evidence_unavailable",
            Self::InvalidOverrideArtifact { .. } => "tee_policy_override_artifact_invalid",
            Self::OverrideJustificationMissing => "tee_policy_override_justification_missing",
            Self::OverrideExpired { .. } => "tee_policy_override_expired",
            Self::OverrideSignatureInvalid { .. } => "tee_policy_override_signature_invalid",
            Self::OverrideTargetMismatch { .. } => "tee_policy_override_target_mismatch",
            Self::EmitterNotSynced { .. } => "tee_policy_emitter_not_synced",
            Self::EmitterPolicyStale { .. } => "tee_policy_emitter_stale",
        }
    }
}

impl fmt::Display for TeeAttestationPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseFailed { detail } => write!(f, "policy parse failed: {detail}"),
            Self::SerializationFailed { detail } => {
                write!(f, "policy serialization failed: {detail}")
            }
            Self::MissingMeasurementsForPlatform { platform } => {
                write!(f, "missing approved measurements for platform {platform}")
            }
            Self::InvalidMeasurementDigest {
                platform,
                digest,
                expected_hex_len,
            } => write!(
                f,
                "invalid measurement digest for {platform}: digest='{digest}', expected_hex_len={expected_hex_len}"
            ),
            Self::DuplicateMeasurementDigest { platform, digest } => {
                write!(f, "duplicate measurement digest for {platform}: {digest}")
            }
            Self::InvalidFreshnessWindow {
                standard_max_age_secs,
                high_impact_max_age_secs,
            } => write!(
                f,
                "invalid freshness window: standard_max_age_secs={standard_max_age_secs}, high_impact_max_age_secs={high_impact_max_age_secs}"
            ),
            Self::EmptyRevocationSources => f.write_str("revocation source list is empty"),
            Self::InvalidRevocationSource { reason } => {
                write!(f, "invalid revocation source: {reason}")
            }
            Self::DuplicateRevocationSource { source_id } => {
                write!(f, "duplicate revocation source: {source_id}")
            }
            Self::RevocationFallbackBypass => {
                f.write_str("revocation configuration has no fail-closed source")
            }
            Self::MissingTrustRoots => f.write_str("platform trust root set is empty"),
            Self::InvalidTrustRoot { root_id, reason } => {
                write!(f, "invalid trust root '{root_id}': {reason}")
            }
            Self::DuplicateTrustRoot { platform, root_id } => {
                write!(f, "duplicate trust root for {platform}: {root_id}")
            }
            Self::MissingPinnedTrustRoot { platform } => {
                write!(f, "no active pinned trust root for {platform}")
            }
            Self::PolicyEpochRegression { current, attempted } => {
                write!(
                    f,
                    "policy epoch regression: current={current}, attempted={attempted}"
                )
            }
            Self::IdDerivationFailed { detail } => {
                write!(f, "policy ID derivation failed: {detail}")
            }
            Self::ReceiptEmissionHalted => f.write_str("receipt emission halted (fail-closed)"),
            Self::NoActivePolicy => f.write_str("no active TEE attestation policy loaded"),
            Self::UnknownMeasurementDigest { platform, digest } => {
                write!(
                    f,
                    "measurement digest not approved for {platform}: {digest}"
                )
            }
            Self::AttestationStale {
                quote_age_secs,
                max_age_secs,
            } => write!(
                f,
                "attestation quote is stale: age_secs={quote_age_secs}, max_age_secs={max_age_secs}"
            ),
            Self::UnknownTrustRoot { platform, root_id } => {
                write!(f, "unknown trust root for {platform}: {root_id}")
            }
            Self::ExpiredTrustRoot {
                root_id,
                runtime_epoch,
                valid_until_epoch,
            } => write!(
                f,
                "trust root '{root_id}' not active at runtime {runtime_epoch} (valid_until={valid_until_epoch:?})"
            ),
            Self::RevokedBySource { source_id } => {
                write!(f, "quote revoked by source {source_id}")
            }
            Self::RevocationSourceUnavailable { source_id } => {
                write!(
                    f,
                    "revocation source unavailable (fail-closed): {source_id}"
                )
            }
            Self::RevocationEvidenceUnavailable => {
                f.write_str("revocation evidence unavailable across configured fallback chain")
            }
            Self::InvalidOverrideArtifact { reason } => {
                write!(f, "invalid trust-root override artifact: {reason}")
            }
            Self::OverrideJustificationMissing => {
                f.write_str("override artifact missing signed justification")
            }
            Self::OverrideExpired {
                current_epoch,
                expires_epoch,
            } => write!(
                f,
                "override artifact expired: current_epoch={current_epoch}, expires_epoch={expires_epoch}"
            ),
            Self::OverrideSignatureInvalid { detail } => {
                write!(f, "override signature verification failed: {detail}")
            }
            Self::OverrideTargetMismatch {
                expected_platform,
                expected_root_id,
                actual_platform,
                actual_root_id,
            } => write!(
                f,
                "override target mismatch: expected {expected_platform}:{expected_root_id}, got {actual_platform}:{actual_root_id}"
            ),
            Self::EmitterNotSynced { emitter_id } => {
                write!(f, "emitter '{emitter_id}' has not synced policy epoch")
            }
            Self::EmitterPolicyStale {
                emitter_id,
                synced_epoch,
                required_epoch,
            } => write!(
                f,
                "emitter '{emitter_id}' stale policy epoch: synced={synced_epoch}, required={required_epoch}"
            ),
        }
    }
}

impl std::error::Error for TeeAttestationPolicyError {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_hex_ascii(s: &str) -> bool {
    s.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_hex(byte: u8, bytes: usize) -> String {
        let mut out = String::with_capacity(bytes * 2);
        for _ in 0..bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn sample_policy(epoch: u64) -> TeeAttestationPolicy {
        let mut approved = BTreeMap::new();
        approved.insert(
            TeePlatform::IntelSgx,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha384,
                digest_hex: digest_hex(0x11, 48),
            }],
        );
        approved.insert(
            TeePlatform::ArmTrustZone,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha256,
                digest_hex: digest_hex(0x22, 32),
            }],
        );
        approved.insert(
            TeePlatform::ArmCca,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha256,
                digest_hex: digest_hex(0x44, 32),
            }],
        );
        approved.insert(
            TeePlatform::AmdSev,
            vec![MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha384,
                digest_hex: digest_hex(0x33, 48),
            }],
        );

        TeeAttestationPolicy {
            schema_version: 1,
            policy_epoch: SecurityEpoch::from_raw(epoch),
            approved_measurements: approved,
            freshness_window: AttestationFreshnessWindow {
                standard_max_age_secs: 300,
                high_impact_max_age_secs: 60,
            },
            revocation_sources: vec![
                RevocationSource {
                    source_id: "intel_pcs".to_string(),
                    source_type: RevocationSourceType::IntelPcs,
                    endpoint: "https://intel.example/pcs".to_string(),
                    on_unavailable: RevocationFallback::TryNextSource,
                },
                RevocationSource {
                    source_id: "manufacturer_crl".to_string(),
                    source_type: RevocationSourceType::ManufacturerCrl,
                    endpoint: "https://manufacturer.example/crl".to_string(),
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
                    root_id: "sgx-root-a".to_string(),
                    platform: TeePlatform::IntelSgx,
                    trust_anchor_pem: "-----BEGIN CERT-----SGX-A".to_string(),
                    valid_from_epoch: SecurityEpoch::from_raw(0),
                    valid_until_epoch: None,
                    pinning: TrustRootPinning::Pinned,
                    source: TrustRootSource::Policy,
                },
                PlatformTrustRoot {
                    root_id: "tz-root-a".to_string(),
                    platform: TeePlatform::ArmTrustZone,
                    trust_anchor_pem: "-----BEGIN CERT-----TZ-A".to_string(),
                    valid_from_epoch: SecurityEpoch::from_raw(0),
                    valid_until_epoch: None,
                    pinning: TrustRootPinning::Pinned,
                    source: TrustRootSource::Policy,
                },
                PlatformTrustRoot {
                    root_id: "cca-root-a".to_string(),
                    platform: TeePlatform::ArmCca,
                    trust_anchor_pem: "-----BEGIN CERT-----CCA-A".to_string(),
                    valid_from_epoch: SecurityEpoch::from_raw(0),
                    valid_until_epoch: None,
                    pinning: TrustRootPinning::Pinned,
                    source: TrustRootSource::Policy,
                },
                PlatformTrustRoot {
                    root_id: "sev-root-a".to_string(),
                    platform: TeePlatform::AmdSev,
                    trust_anchor_pem: "-----BEGIN CERT-----SEV-A".to_string(),
                    valid_from_epoch: SecurityEpoch::from_raw(0),
                    valid_until_epoch: None,
                    pinning: TrustRootPinning::Pinned,
                    source: TrustRootSource::Policy,
                },
            ],
        }
    }

    fn quote_for_sgx() -> AttestationQuote {
        let mut rev = BTreeMap::new();
        rev.insert("intel_pcs".to_string(), RevocationProbeStatus::Unavailable);
        rev.insert(
            "manufacturer_crl".to_string(),
            RevocationProbeStatus::Unavailable,
        );
        rev.insert("internal_ledger".to_string(), RevocationProbeStatus::Good);

        AttestationQuote {
            platform: TeePlatform::IntelSgx,
            measurement: MeasurementDigest {
                algorithm: MeasurementAlgorithm::Sha384,
                digest_hex: digest_hex(0x11, 48),
            },
            quote_age_secs: 12,
            trust_root_id: "sgx-root-a".to_string(),
            revocation_observations: rev,
        }
    }

    #[test]
    fn policy_round_trip_canonical_json() {
        let policy = sample_policy(7);
        let json = policy.to_canonical_json().expect("serialize");
        let parsed = TeeAttestationPolicy::from_json(&json).expect("parse");
        assert_eq!(policy, parsed);
    }

    #[test]
    fn policy_id_is_deterministic() {
        let p1 = sample_policy(3);
        let p2 = sample_policy(3);
        assert_eq!(
            p1.derive_policy_id().expect("id 1"),
            p2.derive_policy_id().expect("id 2")
        );
    }

    #[test]
    fn policy_requires_measurements_for_all_platforms() {
        let mut policy = sample_policy(1);
        policy.approved_measurements.remove(&TeePlatform::AmdSev);
        let err = policy.validate().expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::MissingMeasurementsForPlatform {
                platform: TeePlatform::AmdSev
            }
        ));
    }

    #[test]
    fn freshness_window_rejects_inverted_thresholds() {
        let mut policy = sample_policy(1);
        policy.freshness_window = AttestationFreshnessWindow {
            standard_max_age_secs: 10,
            high_impact_max_age_secs: 20,
        };
        let err = policy.validate().expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidFreshnessWindow { .. }
        ));
    }

    #[test]
    fn unknown_measurement_digest_is_rejected() {
        let policy = sample_policy(1);
        let mut quote = quote_for_sgx();
        quote.measurement.digest_hex = digest_hex(0x44, 48);
        let err = policy
            .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
            .expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::UnknownMeasurementDigest { .. }
        ));
    }

    #[test]
    fn high_impact_freshness_boundary_enforced() {
        let policy = sample_policy(1);
        let mut quote = quote_for_sgx();
        quote.quote_age_secs = 61;
        let err = policy
            .evaluate_quote(
                &quote,
                DecisionImpact::HighImpact,
                SecurityEpoch::from_raw(1),
            )
            .expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::AttestationStale { .. }
        ));
    }

    #[test]
    fn revocation_fallback_uses_ordered_try_next_chain() {
        let policy = sample_policy(1);
        let quote = quote_for_sgx();
        policy
            .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
            .expect("fallback should reach internal ledger success");
    }

    #[test]
    fn revocation_fail_closed_source_blocks_on_unavailable() {
        let policy = sample_policy(1);
        let mut quote = quote_for_sgx();
        quote.revocation_observations.insert(
            "internal_ledger".to_string(),
            RevocationProbeStatus::Unavailable,
        );
        let err = policy
            .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
            .expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::RevocationSourceUnavailable { .. }
        ));
    }

    #[test]
    fn trust_root_must_be_active_at_runtime_epoch() {
        let mut policy = sample_policy(1);
        policy.platform_trust_roots[0].valid_until_epoch = Some(SecurityEpoch::from_raw(2));
        let quote = quote_for_sgx();
        let err = policy
            .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(3))
            .expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::ExpiredTrustRoot { .. }
        ));
    }

    #[test]
    fn load_failure_halts_emission_fail_closed() {
        let mut store = TeeAttestationPolicyStore::default();
        let err = store
            .load_policy_json(
                r#"{"schema_version":"bad"}"#,
                "trace-fail-1",
                "decision-fail-1",
            )
            .expect_err("must fail");
        assert_eq!(err.error_code(), "tee_policy_parse_failed");
        assert!(store.receipt_emission_halted());
    }

    #[test]
    fn signed_override_applies_temporary_root() {
        let mut store = TeeAttestationPolicyStore::default();
        let policy = sample_policy(10);
        store
            .load_policy(policy.clone(), "trace-load-1", "decision-load-1")
            .expect("policy load");

        let signing_key = SigningKey::from_bytes([7u8; 32]);
        let verifier = signing_key.verification_key();
        let artifact = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator-1".to_string(),
                justification: "temporary manufacturer root during incident".to_string(),
                evidence_refs: vec!["evidence-1".to_string(), "evidence-2".to_string()],
                target_platform: TeePlatform::IntelSgx,
                target_root_id: "sgx-root-temp".to_string(),
                issued_epoch: SecurityEpoch::from_raw(10),
                expires_epoch: SecurityEpoch::from_raw(12),
            },
        )
        .expect("artifact");

        let request = TemporaryTrustRootOverride {
            override_id: "ovr-1".to_string(),
            trust_root: PlatformTrustRoot {
                root_id: "sgx-root-temp".to_string(),
                platform: TeePlatform::IntelSgx,
                trust_anchor_pem: "-----BEGIN CERT-----SGX-TEMP".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(10),
                valid_until_epoch: None,
                pinning: TrustRootPinning::Rotating {
                    rotation_group: "sgx-rollover".to_string(),
                },
                source: TrustRootSource::Policy,
            },
            artifact,
        };

        store
            .apply_temporary_trust_root_override(
                request,
                &verifier,
                SecurityEpoch::from_raw(10),
                "trace-ovr-1",
                "decision-ovr-1",
            )
            .expect("override apply");

        let active = store.active_policy().expect("active policy");
        let has_temp = active.platform_trust_roots.iter().any(|root| {
            root.platform == TeePlatform::IntelSgx
                && root.root_id == "sgx-root-temp"
                && matches!(root.source, TrustRootSource::TemporaryOverride { .. })
        });
        assert!(has_temp);
    }

    #[test]
    fn override_signature_must_verify() {
        let mut store = TeeAttestationPolicyStore::default();
        store
            .load_policy(sample_policy(10), "trace-load-2", "decision-load-2")
            .expect("policy load");

        let signing_key = SigningKey::from_bytes([8u8; 32]);
        let verifier = signing_key.verification_key();
        let mut artifact = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator-2".to_string(),
                justification: "temporary roll".to_string(),
                evidence_refs: vec!["evidence-z".to_string()],
                target_platform: TeePlatform::IntelSgx,
                target_root_id: "sgx-root-temp-2".to_string(),
                issued_epoch: SecurityEpoch::from_raw(10),
                expires_epoch: SecurityEpoch::from_raw(11),
            },
        )
        .expect("artifact");
        artifact.justification = "tampered".to_string();

        let request = TemporaryTrustRootOverride {
            override_id: "ovr-2".to_string(),
            trust_root: PlatformTrustRoot {
                root_id: "sgx-root-temp-2".to_string(),
                platform: TeePlatform::IntelSgx,
                trust_anchor_pem: "-----BEGIN CERT-----SGX-TEMP-2".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(10),
                valid_until_epoch: Some(SecurityEpoch::from_raw(11)),
                pinning: TrustRootPinning::Rotating {
                    rotation_group: "sgx-rollover".to_string(),
                },
                source: TrustRootSource::Policy,
            },
            artifact,
        };

        let err = store
            .apply_temporary_trust_root_override(
                request,
                &verifier,
                SecurityEpoch::from_raw(10),
                "trace-ovr-2",
                "decision-ovr-2",
            )
            .expect_err("must fail");
        assert!(matches!(
            err,
            TeeAttestationPolicyError::OverrideSignatureInvalid { .. }
        ));
    }

    #[test]
    fn governance_events_emit_stable_fields() {
        let mut store = TeeAttestationPolicyStore::default();
        let policy = sample_policy(5);
        store
            .load_policy(policy, "trace-audit-1", "decision-audit-1")
            .expect("load");
        let quote = quote_for_sgx();
        store
            .evaluate_quote(
                &quote,
                DecisionImpact::Standard,
                SecurityEpoch::from_raw(5),
                "trace-audit-2",
                "decision-audit-2",
            )
            .expect("quote ok");
        let entries = store.governance_ledger();
        assert!(entries.len() >= 2);
        let last = entries.last().expect("last event");
        assert!(!last.trace_id.is_empty());
        assert!(!last.decision_id.is_empty());
        assert!(!last.policy_id.is_empty());
        assert_eq!(last.component, COMPONENT_NAME);
        assert!(!last.event.is_empty());
        assert!(!last.outcome.is_empty());
        assert!(!last.error_code.is_empty());
    }

    #[test]
    fn tee_platform_all_covers_four_variants() {
        assert_eq!(TeePlatform::ALL.len(), 4);
        assert_eq!(TeePlatform::IntelSgx.to_string(), "intel_sgx");
        assert_eq!(TeePlatform::ArmTrustZone.to_string(), "arm_trustzone");
        assert_eq!(TeePlatform::ArmCca.to_string(), "arm_cca");
        assert_eq!(TeePlatform::AmdSev.to_string(), "amd_sev");
    }

    // -----------------------------------------------------------------------
    // TeePlatform serde round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn tee_platform_serde_round_trip() {
        for platform in TeePlatform::ALL {
            let json = serde_json::to_string(&platform).unwrap();
            let parsed: TeePlatform = serde_json::from_str(&json).unwrap();
            assert_eq!(platform, parsed);
        }
    }

    // -----------------------------------------------------------------------
    // MeasurementAlgorithm
    // -----------------------------------------------------------------------

    #[test]
    fn measurement_algorithm_display() {
        assert_eq!(MeasurementAlgorithm::Sha256.to_string(), "sha256");
        assert_eq!(MeasurementAlgorithm::Sha384.to_string(), "sha384");
        assert_eq!(MeasurementAlgorithm::Sha512.to_string(), "sha512");
    }

    #[test]
    fn measurement_algorithm_digest_len_bytes() {
        assert_eq!(MeasurementAlgorithm::Sha256.digest_len_bytes(), 32);
        assert_eq!(MeasurementAlgorithm::Sha384.digest_len_bytes(), 48);
        assert_eq!(MeasurementAlgorithm::Sha512.digest_len_bytes(), 64);
    }

    #[test]
    fn measurement_algorithm_serde_round_trip() {
        for alg in [
            MeasurementAlgorithm::Sha256,
            MeasurementAlgorithm::Sha384,
            MeasurementAlgorithm::Sha512,
        ] {
            let json = serde_json::to_string(&alg).unwrap();
            let parsed: MeasurementAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(alg, parsed);
        }
    }

    // -----------------------------------------------------------------------
    // MeasurementDigest validation
    // -----------------------------------------------------------------------

    #[test]
    fn measurement_digest_canonicalize_lowercases() {
        let mut digest = MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: "AABBCCDD".to_string(),
        };
        digest.canonicalize();
        assert_eq!(digest.digest_hex, "aabbccdd");
    }

    #[test]
    fn measurement_digest_validate_wrong_length() {
        let digest = MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: "aabb".to_string(), // too short for sha256 (needs 64 hex chars)
        };
        let err = digest
            .validate_for_platform(TeePlatform::IntelSgx)
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidMeasurementDigest { .. }
        ));
    }

    #[test]
    fn measurement_digest_validate_non_hex_chars() {
        let digest = MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: "zz".repeat(32), // 64 chars but not hex
        };
        let err = digest
            .validate_for_platform(TeePlatform::AmdSev)
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidMeasurementDigest { .. }
        ));
    }

    #[test]
    fn measurement_digest_validate_correct_sha512() {
        let digest = MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha512,
            digest_hex: digest_hex(0xaa, 64),
        };
        digest.validate_for_platform(TeePlatform::ArmCca).unwrap();
    }

    // -----------------------------------------------------------------------
    // AttestationFreshnessWindow
    // -----------------------------------------------------------------------

    #[test]
    fn freshness_window_zero_standard_rejected() {
        let window = AttestationFreshnessWindow {
            standard_max_age_secs: 0,
            high_impact_max_age_secs: 0,
        };
        let err = window.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidFreshnessWindow { .. }
        ));
    }

    #[test]
    fn freshness_window_max_age_for_standard() {
        let window = AttestationFreshnessWindow {
            standard_max_age_secs: 300,
            high_impact_max_age_secs: 60,
        };
        assert_eq!(window.max_age_for(DecisionImpact::Standard), 300);
        assert_eq!(window.max_age_for(DecisionImpact::HighImpact), 60);
    }

    #[test]
    fn freshness_window_equal_values_valid() {
        let window = AttestationFreshnessWindow {
            standard_max_age_secs: 100,
            high_impact_max_age_secs: 100,
        };
        window.validate().unwrap();
    }

    // -----------------------------------------------------------------------
    // RevocationSource validation
    // -----------------------------------------------------------------------

    #[test]
    fn revocation_source_empty_source_id_rejected() {
        let source = RevocationSource {
            source_id: "  ".to_string(),
            source_type: RevocationSourceType::IntelPcs,
            endpoint: "https://example.com".to_string(),
            on_unavailable: RevocationFallback::FailClosed,
        };
        let err = source.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidRevocationSource { .. }
        ));
    }

    #[test]
    fn revocation_source_empty_endpoint_rejected() {
        let source = RevocationSource {
            source_id: "src-1".to_string(),
            source_type: RevocationSourceType::IntelPcs,
            endpoint: "".to_string(),
            on_unavailable: RevocationFallback::FailClosed,
        };
        let err = source.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidRevocationSource { .. }
        ));
    }

    #[test]
    fn revocation_source_other_empty_name_rejected() {
        let source = RevocationSource {
            source_id: "src-1".to_string(),
            source_type: RevocationSourceType::Other("".to_string()),
            endpoint: "https://example.com".to_string(),
            on_unavailable: RevocationFallback::FailClosed,
        };
        let err = source.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidRevocationSource { .. }
        ));
    }

    #[test]
    fn revocation_source_type_serde_round_trip() {
        for st in [
            RevocationSourceType::IntelPcs,
            RevocationSourceType::ManufacturerCrl,
            RevocationSourceType::InternalLedger,
            RevocationSourceType::Other("custom".to_string()),
        ] {
            let json = serde_json::to_string(&st).unwrap();
            let parsed: RevocationSourceType = serde_json::from_str(&json).unwrap();
            assert_eq!(st, parsed);
        }
    }

    // -----------------------------------------------------------------------
    // PlatformTrustRoot validation
    // -----------------------------------------------------------------------

    #[test]
    fn trust_root_empty_root_id_rejected() {
        let root = PlatformTrustRoot {
            root_id: "".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(0),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Pinned,
            source: TrustRootSource::Policy,
        };
        let err = root.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidTrustRoot { .. }
        ));
    }

    #[test]
    fn trust_root_empty_pem_rejected() {
        let root = PlatformTrustRoot {
            root_id: "root-1".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(0),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Pinned,
            source: TrustRootSource::Policy,
        };
        let err = root.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidTrustRoot { .. }
        ));
    }

    #[test]
    fn trust_root_inverted_epochs_rejected() {
        let root = PlatformTrustRoot {
            root_id: "root-1".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "PEM".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(10),
            valid_until_epoch: Some(SecurityEpoch::from_raw(5)),
            pinning: TrustRootPinning::Pinned,
            source: TrustRootSource::Policy,
        };
        let err = root.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidTrustRoot { .. }
        ));
    }

    #[test]
    fn trust_root_rotating_empty_group_rejected() {
        let root = PlatformTrustRoot {
            root_id: "root-1".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "PEM".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(0),
            valid_until_epoch: Some(SecurityEpoch::from_raw(10)),
            pinning: TrustRootPinning::Rotating {
                rotation_group: "".to_string(),
            },
            source: TrustRootSource::Policy,
        };
        let err = root.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidTrustRoot { .. }
        ));
    }

    #[test]
    fn trust_root_rotating_without_until_rejected() {
        let root = PlatformTrustRoot {
            root_id: "root-1".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "PEM".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(0),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Rotating {
                rotation_group: "grp".to_string(),
            },
            source: TrustRootSource::Policy,
        };
        let err = root.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidTrustRoot { .. }
        ));
    }

    #[test]
    fn trust_root_temp_override_empty_ids_rejected() {
        let root = PlatformTrustRoot {
            root_id: "root-1".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "PEM".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(0),
            valid_until_epoch: Some(SecurityEpoch::from_raw(10)),
            pinning: TrustRootPinning::Pinned,
            source: TrustRootSource::TemporaryOverride {
                override_id: "".to_string(),
                justification_artifact_id: "art-1".to_string(),
            },
        };
        let err = root.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidTrustRoot { .. }
        ));
    }

    #[test]
    fn trust_root_temp_override_without_until_rejected() {
        let root = PlatformTrustRoot {
            root_id: "root-1".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "PEM".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(0),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Pinned,
            source: TrustRootSource::TemporaryOverride {
                override_id: "ovr-1".to_string(),
                justification_artifact_id: "art-1".to_string(),
            },
        };
        let err = root.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidTrustRoot { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // PlatformTrustRoot active_at_epoch
    // -----------------------------------------------------------------------

    #[test]
    fn trust_root_active_at_epoch_before_valid_from() {
        let root = PlatformTrustRoot {
            root_id: "r".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "PEM".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(5),
            valid_until_epoch: Some(SecurityEpoch::from_raw(10)),
            pinning: TrustRootPinning::Pinned,
            source: TrustRootSource::Policy,
        };
        assert!(!root.active_at_epoch(SecurityEpoch::from_raw(4)));
        assert!(root.active_at_epoch(SecurityEpoch::from_raw(5)));
        assert!(root.active_at_epoch(SecurityEpoch::from_raw(10)));
        assert!(!root.active_at_epoch(SecurityEpoch::from_raw(11)));
    }

    #[test]
    fn trust_root_active_at_epoch_no_until_always_active() {
        let root = PlatformTrustRoot {
            root_id: "r".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "PEM".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(3),
            valid_until_epoch: None,
            pinning: TrustRootPinning::Pinned,
            source: TrustRootSource::Policy,
        };
        assert!(root.active_at_epoch(SecurityEpoch::from_raw(3)));
        assert!(root.active_at_epoch(SecurityEpoch::from_raw(u64::MAX)));
    }

    // -----------------------------------------------------------------------
    // Policy validation edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn policy_empty_measurements_list_rejected() {
        let mut policy = sample_policy(1);
        policy
            .approved_measurements
            .insert(TeePlatform::IntelSgx, vec![]);
        let err = policy.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::MissingMeasurementsForPlatform {
                platform: TeePlatform::IntelSgx
            }
        ));
    }

    #[test]
    fn policy_duplicate_measurements_rejected() {
        let mut policy = sample_policy(1);
        let dup_digest = MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x11, 48),
        };
        policy
            .approved_measurements
            .insert(TeePlatform::IntelSgx, vec![dup_digest.clone(), dup_digest]);
        let err = policy.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::DuplicateMeasurementDigest { .. }
        ));
    }

    #[test]
    fn policy_empty_revocation_sources_rejected() {
        let mut policy = sample_policy(1);
        policy.revocation_sources.clear();
        let err = policy.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::EmptyRevocationSources
        ));
    }

    #[test]
    fn policy_duplicate_revocation_source_rejected() {
        let mut policy = sample_policy(1);
        let dup = policy.revocation_sources[0].clone();
        policy.revocation_sources.push(dup);
        let err = policy.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::DuplicateRevocationSource { .. }
        ));
    }

    #[test]
    fn policy_no_fail_closed_revocation_rejected() {
        let mut policy = sample_policy(1);
        for source in &mut policy.revocation_sources {
            source.on_unavailable = RevocationFallback::TryNextSource;
        }
        let err = policy.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::RevocationFallbackBypass
        ));
    }

    #[test]
    fn policy_empty_trust_roots_rejected() {
        let mut policy = sample_policy(1);
        policy.platform_trust_roots.clear();
        let err = policy.validate().unwrap_err();
        assert!(matches!(err, TeeAttestationPolicyError::MissingTrustRoots));
    }

    #[test]
    fn policy_duplicate_trust_root_rejected() {
        let mut policy = sample_policy(1);
        let dup = policy.platform_trust_roots[0].clone();
        policy.platform_trust_roots.push(dup);
        let err = policy.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::DuplicateTrustRoot { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // evaluate_quote edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_quote_revoked_by_source() {
        let policy = sample_policy(1);
        let mut quote = quote_for_sgx();
        quote
            .revocation_observations
            .insert("intel_pcs".to_string(), RevocationProbeStatus::Revoked);
        let err = policy
            .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::RevokedBySource { .. }
        ));
    }

    #[test]
    fn evaluate_quote_standard_at_max_age_passes() {
        let policy = sample_policy(1);
        let mut quote = quote_for_sgx();
        quote.quote_age_secs = 300; // exactly at standard max
        policy
            .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
            .unwrap();
    }

    #[test]
    fn evaluate_quote_standard_over_max_age_fails() {
        let policy = sample_policy(1);
        let mut quote = quote_for_sgx();
        quote.quote_age_secs = 301;
        let err = policy
            .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::AttestationStale { .. }
        ));
    }

    #[test]
    fn evaluate_quote_unknown_trust_root() {
        let policy = sample_policy(1);
        let mut quote = quote_for_sgx();
        quote.trust_root_id = "nonexistent-root".to_string();
        let err = policy
            .evaluate_quote(&quote, DecisionImpact::Standard, SecurityEpoch::from_raw(1))
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::UnknownTrustRoot { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // TeeAttestationPolicyStore
    // -----------------------------------------------------------------------

    #[test]
    fn store_default_halts_emission() {
        let store = TeeAttestationPolicyStore::default();
        assert!(store.receipt_emission_halted());
        assert_eq!(store.last_error_code(), Some("policy_not_loaded"));
        assert!(store.active_policy().is_none());
        assert!(store.governance_ledger().is_empty());
    }

    #[test]
    fn store_load_policy_epoch_regression_rejected() {
        let mut store = TeeAttestationPolicyStore::default();
        store.load_policy(sample_policy(10), "t-1", "d-1").unwrap();
        let err = store
            .load_policy(sample_policy(5), "t-2", "d-2")
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::PolicyEpochRegression { .. }
        ));
        assert!(store.receipt_emission_halted());
    }

    #[test]
    fn store_evaluate_quote_when_halted() {
        let mut store = TeeAttestationPolicyStore::default();
        let quote = quote_for_sgx();
        let err = store
            .evaluate_quote(
                &quote,
                DecisionImpact::Standard,
                SecurityEpoch::from_raw(1),
                "t-1",
                "d-1",
            )
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::ReceiptEmissionHalted
        ));
    }

    #[test]
    fn store_evaluate_quote_success_emits_event() {
        let mut store = TeeAttestationPolicyStore::default();
        store
            .load_policy(sample_policy(5), "t-load", "d-load")
            .unwrap();
        let quote = quote_for_sgx();
        store
            .evaluate_quote(
                &quote,
                DecisionImpact::Standard,
                SecurityEpoch::from_raw(5),
                "t-eval",
                "d-eval",
            )
            .unwrap();
        let last = store.governance_ledger().last().unwrap();
        assert_eq!(last.event, "quote_accepted");
        assert_eq!(last.outcome, "allow");
    }

    #[test]
    fn store_evaluate_quote_rejection_emits_event() {
        let mut store = TeeAttestationPolicyStore::default();
        store
            .load_policy(sample_policy(5), "t-load", "d-load")
            .unwrap();
        let mut quote = quote_for_sgx();
        quote.quote_age_secs = 999; // too old for standard
        let err = store
            .evaluate_quote(
                &quote,
                DecisionImpact::Standard,
                SecurityEpoch::from_raw(5),
                "t-eval",
                "d-eval",
            )
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::AttestationStale { .. }
        ));
        let last = store.governance_ledger().last().unwrap();
        assert_eq!(last.event, "quote_rejected");
        assert_eq!(last.outcome, "deny");
    }

    // -----------------------------------------------------------------------
    // DecisionReceiptEmitter
    // -----------------------------------------------------------------------

    #[test]
    fn emitter_new_has_no_synced_epoch() {
        let emitter = DecisionReceiptEmitter::new("emitter-1");
        assert_eq!(emitter.emitter_id, "emitter-1");
        assert!(emitter.last_synced_policy_epoch.is_none());
    }

    #[test]
    fn emitter_sync_when_halted_fails() {
        let mut emitter = DecisionReceiptEmitter::new("e-1");
        let store = TeeAttestationPolicyStore::default();
        let err = emitter.sync_policy(&store).unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::ReceiptEmissionHalted
        ));
    }

    #[test]
    fn emitter_sync_sets_epoch() {
        let mut emitter = DecisionReceiptEmitter::new("e-1");
        let mut store = TeeAttestationPolicyStore::default();
        store.load_policy(sample_policy(7), "t-1", "d-1").unwrap();
        let epoch = emitter.sync_policy(&store).unwrap();
        assert_eq!(epoch, SecurityEpoch::from_raw(7));
        assert_eq!(
            emitter.last_synced_policy_epoch,
            Some(SecurityEpoch::from_raw(7))
        );
    }

    #[test]
    fn emitter_can_emit_not_synced_fails() {
        let emitter = DecisionReceiptEmitter::new("e-1");
        let mut store = TeeAttestationPolicyStore::default();
        store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();
        let err = emitter
            .can_emit(SecurityEpoch::from_raw(5), &store)
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::EmitterNotSynced { .. }
        ));
    }

    #[test]
    fn emitter_can_emit_stale_fails() {
        let mut emitter = DecisionReceiptEmitter::new("e-1");
        let mut store = TeeAttestationPolicyStore::default();
        store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();
        emitter.sync_policy(&store).unwrap();
        // Load a much newer policy
        store.load_policy(sample_policy(10), "t-2", "d-2").unwrap();
        let err = emitter
            .can_emit(SecurityEpoch::from_raw(10), &store)
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::EmitterPolicyStale { .. }
        ));
    }

    #[test]
    fn emitter_can_emit_one_behind_ok() {
        let mut emitter = DecisionReceiptEmitter::new("e-1");
        let mut store = TeeAttestationPolicyStore::default();
        store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();
        emitter.sync_policy(&store).unwrap();
        store.load_policy(sample_policy(6), "t-2", "d-2").unwrap();
        // Synced at 5, active is 6 — one epoch behind is OK
        emitter
            .can_emit(SecurityEpoch::from_raw(6), &store)
            .unwrap();
    }

    // -----------------------------------------------------------------------
    // TeeAttestationPolicyError error_code coverage
    // -----------------------------------------------------------------------

    #[test]
    fn error_code_coverage_all_variants() {
        let variants: Vec<TeeAttestationPolicyError> = vec![
            TeeAttestationPolicyError::ParseFailed {
                detail: "bad".to_string(),
            },
            TeeAttestationPolicyError::SerializationFailed {
                detail: "err".to_string(),
            },
            TeeAttestationPolicyError::MissingMeasurementsForPlatform {
                platform: TeePlatform::IntelSgx,
            },
            TeeAttestationPolicyError::InvalidMeasurementDigest {
                platform: TeePlatform::ArmCca,
                digest: "abc".to_string(),
                expected_hex_len: 64,
            },
            TeeAttestationPolicyError::DuplicateMeasurementDigest {
                platform: TeePlatform::AmdSev,
                digest: "dd".to_string(),
            },
            TeeAttestationPolicyError::InvalidFreshnessWindow {
                standard_max_age_secs: 0,
                high_impact_max_age_secs: 0,
            },
            TeeAttestationPolicyError::EmptyRevocationSources,
            TeeAttestationPolicyError::InvalidRevocationSource {
                reason: "test".to_string(),
            },
            TeeAttestationPolicyError::DuplicateRevocationSource {
                source_id: "s".to_string(),
            },
            TeeAttestationPolicyError::RevocationFallbackBypass,
            TeeAttestationPolicyError::MissingTrustRoots,
            TeeAttestationPolicyError::InvalidTrustRoot {
                root_id: "r".to_string(),
                reason: "bad".to_string(),
            },
            TeeAttestationPolicyError::DuplicateTrustRoot {
                platform: TeePlatform::IntelSgx,
                root_id: "r".to_string(),
            },
            TeeAttestationPolicyError::MissingPinnedTrustRoot {
                platform: TeePlatform::IntelSgx,
            },
            TeeAttestationPolicyError::PolicyEpochRegression {
                current: SecurityEpoch::from_raw(5),
                attempted: SecurityEpoch::from_raw(3),
            },
            TeeAttestationPolicyError::IdDerivationFailed {
                detail: "fail".to_string(),
            },
            TeeAttestationPolicyError::ReceiptEmissionHalted,
            TeeAttestationPolicyError::NoActivePolicy,
            TeeAttestationPolicyError::UnknownMeasurementDigest {
                platform: TeePlatform::IntelSgx,
                digest: "dd".to_string(),
            },
            TeeAttestationPolicyError::AttestationStale {
                quote_age_secs: 500,
                max_age_secs: 300,
            },
            TeeAttestationPolicyError::UnknownTrustRoot {
                platform: TeePlatform::IntelSgx,
                root_id: "r".to_string(),
            },
            TeeAttestationPolicyError::ExpiredTrustRoot {
                root_id: "r".to_string(),
                runtime_epoch: SecurityEpoch::from_raw(10),
                valid_until_epoch: Some(SecurityEpoch::from_raw(5)),
            },
            TeeAttestationPolicyError::RevokedBySource {
                source_id: "s".to_string(),
            },
            TeeAttestationPolicyError::RevocationSourceUnavailable {
                source_id: "s".to_string(),
            },
            TeeAttestationPolicyError::RevocationEvidenceUnavailable,
            TeeAttestationPolicyError::InvalidOverrideArtifact {
                reason: "bad".to_string(),
            },
            TeeAttestationPolicyError::OverrideJustificationMissing,
            TeeAttestationPolicyError::OverrideExpired {
                current_epoch: SecurityEpoch::from_raw(10),
                expires_epoch: SecurityEpoch::from_raw(5),
            },
            TeeAttestationPolicyError::OverrideSignatureInvalid {
                detail: "bad".to_string(),
            },
            TeeAttestationPolicyError::OverrideTargetMismatch {
                expected_platform: TeePlatform::IntelSgx,
                expected_root_id: "r1".to_string(),
                actual_platform: TeePlatform::AmdSev,
                actual_root_id: "r2".to_string(),
            },
            TeeAttestationPolicyError::EmitterNotSynced {
                emitter_id: "e".to_string(),
            },
            TeeAttestationPolicyError::EmitterPolicyStale {
                emitter_id: "e".to_string(),
                synced_epoch: SecurityEpoch::from_raw(3),
                required_epoch: SecurityEpoch::from_raw(5),
            },
        ];
        for variant in &variants {
            let code = variant.error_code();
            assert!(!code.is_empty(), "error_code empty for {variant}");
            let display = variant.to_string();
            assert!(!display.is_empty(), "Display empty for error_code {code}");
        }
    }

    // -----------------------------------------------------------------------
    // is_hex_ascii edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn is_hex_ascii_valid() {
        assert!(is_hex_ascii("0123456789abcdefABCDEF"));
    }

    #[test]
    fn is_hex_ascii_empty() {
        assert!(is_hex_ascii(""));
    }

    #[test]
    fn is_hex_ascii_invalid_chars() {
        assert!(!is_hex_ascii("zz"));
        assert!(!is_hex_ascii("0g"));
    }

    // -----------------------------------------------------------------------
    // SignedTrustRootOverrideArtifact validation edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn override_artifact_empty_actor_rejected() {
        let signing_key = SigningKey::from_bytes([7u8; 32]);
        let err = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "".to_string(),
                justification: "test".to_string(),
                evidence_refs: vec![],
                target_platform: TeePlatform::IntelSgx,
                target_root_id: "root-1".to_string(),
                issued_epoch: SecurityEpoch::from_raw(1),
                expires_epoch: SecurityEpoch::from_raw(5),
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
        ));
    }

    #[test]
    fn override_artifact_empty_justification_rejected() {
        let signing_key = SigningKey::from_bytes([7u8; 32]);
        let err = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator".to_string(),
                justification: "".to_string(),
                evidence_refs: vec![],
                target_platform: TeePlatform::IntelSgx,
                target_root_id: "root-1".to_string(),
                issued_epoch: SecurityEpoch::from_raw(1),
                expires_epoch: SecurityEpoch::from_raw(5),
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::OverrideJustificationMissing
        ));
    }

    #[test]
    fn override_artifact_expires_before_issued_rejected() {
        let signing_key = SigningKey::from_bytes([7u8; 32]);
        let err = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator".to_string(),
                justification: "fix".to_string(),
                evidence_refs: vec![],
                target_platform: TeePlatform::IntelSgx,
                target_root_id: "root-1".to_string(),
                issued_epoch: SecurityEpoch::from_raw(10),
                expires_epoch: SecurityEpoch::from_raw(5),
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
        ));
    }

    #[test]
    fn override_artifact_verify_expired_rejected() {
        let signing_key = SigningKey::from_bytes([7u8; 32]);
        let verifier = signing_key.verification_key();
        let artifact = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator".to_string(),
                justification: "fix".to_string(),
                evidence_refs: vec![],
                target_platform: TeePlatform::IntelSgx,
                target_root_id: "root-1".to_string(),
                issued_epoch: SecurityEpoch::from_raw(1),
                expires_epoch: SecurityEpoch::from_raw(5),
            },
        )
        .unwrap();
        let err = artifact
            .verify(&verifier, SecurityEpoch::from_raw(6))
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::OverrideExpired { .. }
        ));
    }

    // -----------------------------------------------------------------------
    // TrustRootPinning serde round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn trust_root_pinning_serde_round_trip() {
        for pinning in [
            TrustRootPinning::Pinned,
            TrustRootPinning::Rotating {
                rotation_group: "grp-1".to_string(),
            },
        ] {
            let json = serde_json::to_string(&pinning).unwrap();
            let parsed: TrustRootPinning = serde_json::from_str(&json).unwrap();
            assert_eq!(pinning, parsed);
        }
    }

    // -----------------------------------------------------------------------
    // DecisionImpact and RevocationProbeStatus serde
    // -----------------------------------------------------------------------

    #[test]
    fn decision_impact_serde_round_trip() {
        for impact in [DecisionImpact::Standard, DecisionImpact::HighImpact] {
            let json = serde_json::to_string(&impact).unwrap();
            let parsed: DecisionImpact = serde_json::from_str(&json).unwrap();
            assert_eq!(impact, parsed);
        }
    }

    #[test]
    fn revocation_probe_status_serde_round_trip() {
        for status in [
            RevocationProbeStatus::Good,
            RevocationProbeStatus::Revoked,
            RevocationProbeStatus::Unavailable,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: RevocationProbeStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, parsed);
        }
    }

    // -----------------------------------------------------------------------
    // RevocationFallback serde
    // -----------------------------------------------------------------------

    #[test]
    fn revocation_fallback_serde_round_trip() {
        for fb in [
            RevocationFallback::TryNextSource,
            RevocationFallback::FailClosed,
        ] {
            let json = serde_json::to_string(&fb).unwrap();
            let parsed: RevocationFallback = serde_json::from_str(&json).unwrap();
            assert_eq!(fb, parsed);
        }
    }

    // -----------------------------------------------------------------------
    // Policy ID changes with epoch
    // -----------------------------------------------------------------------

    #[test]
    fn policy_id_differs_for_different_epochs() {
        let p1 = sample_policy(1);
        let p2 = sample_policy(2);
        assert_ne!(
            p1.derive_policy_id().unwrap(),
            p2.derive_policy_id().unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // PolicyGovernanceEvent serde
    // -----------------------------------------------------------------------

    #[test]
    fn policy_governance_event_serde_round_trip() {
        let event = PolicyGovernanceEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: COMPONENT_NAME.to_string(),
            event: "policy_loaded".to_string(),
            outcome: "allow".to_string(),
            error_code: "ok".to_string(),
            metadata: BTreeMap::new(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: PolicyGovernanceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    // -----------------------------------------------------------------------
    // Enrichment: PearlTower 2026-02-26
    // -----------------------------------------------------------------------

    #[test]
    fn error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(TeeAttestationPolicyError::NoActivePolicy);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn trust_root_source_serde_all_variants() {
        let variants = [
            TrustRootSource::Policy,
            TrustRootSource::TemporaryOverride {
                override_id: "ovr-1".to_string(),
                justification_artifact_id: "art-1".to_string(),
            },
        ];
        for src in variants {
            let json = serde_json::to_string(&src).unwrap();
            let parsed: TrustRootSource = serde_json::from_str(&json).unwrap();
            assert_eq!(src, parsed);
        }
    }

    #[test]
    fn attestation_quote_serde_roundtrip() {
        let quote = quote_for_sgx();
        let json = serde_json::to_string(&quote).unwrap();
        let parsed: AttestationQuote = serde_json::from_str(&json).unwrap();
        assert_eq!(quote, parsed);
    }

    #[test]
    fn measurement_digest_serde_roundtrip() {
        let digest = MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha512,
            digest_hex: digest_hex(0xbb, 64),
        };
        let json = serde_json::to_string(&digest).unwrap();
        let parsed: MeasurementDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(digest, parsed);
    }

    #[test]
    fn revocation_source_serde_roundtrip() {
        let source = RevocationSource {
            source_id: "src-1".to_string(),
            source_type: RevocationSourceType::Other("custom-provider".to_string()),
            endpoint: "https://revocation.example".to_string(),
            on_unavailable: RevocationFallback::TryNextSource,
        };
        let json = serde_json::to_string(&source).unwrap();
        let parsed: RevocationSource = serde_json::from_str(&json).unwrap();
        assert_eq!(source, parsed);
    }

    #[test]
    fn platform_trust_root_serde_roundtrip() {
        let root = PlatformTrustRoot {
            root_id: "sev-root-1".to_string(),
            platform: TeePlatform::AmdSev,
            trust_anchor_pem: "-----BEGIN CERT-----SEV".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(1),
            valid_until_epoch: Some(SecurityEpoch::from_raw(100)),
            pinning: TrustRootPinning::Rotating {
                rotation_group: "sev-group".to_string(),
            },
            source: TrustRootSource::TemporaryOverride {
                override_id: "ovr-x".to_string(),
                justification_artifact_id: "art-x".to_string(),
            },
        };
        let json = serde_json::to_string(&root).unwrap();
        let parsed: PlatformTrustRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(root, parsed);
    }

    #[test]
    fn store_serde_roundtrip() {
        let mut store = TeeAttestationPolicyStore::default();
        store.load_policy(sample_policy(3), "t-1", "d-1").unwrap();
        let json = serde_json::to_string(&store).unwrap();
        let parsed: TeeAttestationPolicyStore = serde_json::from_str(&json).unwrap();
        assert_eq!(
            store.receipt_emission_halted(),
            parsed.receipt_emission_halted()
        );
        assert_eq!(store.last_error_code(), parsed.last_error_code());
        assert_eq!(
            store.governance_ledger().len(),
            parsed.governance_ledger().len()
        );
        assert_eq!(
            store.active_policy().unwrap().policy_epoch,
            parsed.active_policy().unwrap().policy_epoch
        );
    }

    #[test]
    fn emitter_serde_roundtrip() {
        let mut emitter = DecisionReceiptEmitter::new("e-serde");
        emitter.last_synced_policy_epoch = Some(SecurityEpoch::from_raw(42));
        let json = serde_json::to_string(&emitter).unwrap();
        let parsed: DecisionReceiptEmitter = serde_json::from_str(&json).unwrap();
        assert_eq!(emitter, parsed);
    }

    #[test]
    fn emitter_can_emit_when_store_halted_fails() {
        let mut emitter = DecisionReceiptEmitter::new("e-halt");
        emitter.last_synced_policy_epoch = Some(SecurityEpoch::from_raw(5));
        let store = TeeAttestationPolicyStore::default(); // halted by default
        let err = emitter
            .can_emit(SecurityEpoch::from_raw(5), &store)
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::ReceiptEmissionHalted
        ));
    }

    #[test]
    fn store_load_policy_json_success() {
        let mut store = TeeAttestationPolicyStore::default();
        let policy = sample_policy(20);
        let json = policy.to_canonical_json().unwrap();
        let policy_id = store.load_policy_json(&json, "t-json", "d-json").unwrap();
        assert!(!store.receipt_emission_halted());
        assert!(store.last_error_code().is_none());
        // Policy ID should be deterministic
        assert_eq!(policy_id, policy.derive_policy_id().unwrap());
    }

    #[test]
    fn override_empty_target_root_id_rejected() {
        let signing_key = SigningKey::from_bytes([7u8; 32]);
        let err = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator".to_string(),
                justification: "fix".to_string(),
                evidence_refs: vec![],
                target_platform: TeePlatform::IntelSgx,
                target_root_id: "".to_string(),
                issued_epoch: SecurityEpoch::from_raw(1),
                expires_epoch: SecurityEpoch::from_raw(5),
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
        ));
    }

    #[test]
    fn override_target_mismatch_rejected() {
        let mut store = TeeAttestationPolicyStore::default();
        store.load_policy(sample_policy(10), "t-1", "d-1").unwrap();
        let signing_key = SigningKey::from_bytes([9u8; 32]);
        let verifier = signing_key.verification_key();
        let artifact = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator".to_string(),
                justification: "mismatch test".to_string(),
                evidence_refs: vec![],
                target_platform: TeePlatform::AmdSev,
                target_root_id: "sev-root-temp".to_string(),
                issued_epoch: SecurityEpoch::from_raw(10),
                expires_epoch: SecurityEpoch::from_raw(15),
            },
        )
        .unwrap();
        let request = TemporaryTrustRootOverride {
            override_id: "ovr-mismatch".to_string(),
            trust_root: PlatformTrustRoot {
                root_id: "sgx-root-temp".to_string(), // different from artifact target
                platform: TeePlatform::IntelSgx,      // different from artifact target
                trust_anchor_pem: "-----BEGIN CERT-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(10),
                valid_until_epoch: Some(SecurityEpoch::from_raw(15)),
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            artifact,
        };
        let err = store
            .apply_temporary_trust_root_override(
                request,
                &verifier,
                SecurityEpoch::from_raw(10),
                "t-mm",
                "d-mm",
            )
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::OverrideTargetMismatch { .. }
        ));
    }

    #[test]
    fn override_no_active_policy_rejected() {
        let mut store = TeeAttestationPolicyStore {
            receipt_emission_halted: false,
            last_error_code: None,
            ..TeeAttestationPolicyStore::default()
        };

        let signing_key = SigningKey::from_bytes([7u8; 32]);
        let verifier = signing_key.verification_key();
        let artifact = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator".to_string(),
                justification: "test".to_string(),
                evidence_refs: vec![],
                target_platform: TeePlatform::IntelSgx,
                target_root_id: "sgx-root-1".to_string(),
                issued_epoch: SecurityEpoch::from_raw(1),
                expires_epoch: SecurityEpoch::from_raw(5),
            },
        )
        .unwrap();
        let request = TemporaryTrustRootOverride {
            override_id: "ovr-no-policy".to_string(),
            trust_root: PlatformTrustRoot {
                root_id: "sgx-root-1".to_string(),
                platform: TeePlatform::IntelSgx,
                trust_anchor_pem: "-----BEGIN CERT-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: Some(SecurityEpoch::from_raw(5)),
                pinning: TrustRootPinning::Pinned,
                source: TrustRootSource::Policy,
            },
            artifact,
        };
        let err = store
            .apply_temporary_trust_root_override(
                request,
                &verifier,
                SecurityEpoch::from_raw(1),
                "t-nop",
                "d-nop",
            )
            .unwrap_err();
        assert!(matches!(err, TeeAttestationPolicyError::NoActivePolicy));
    }

    #[test]
    fn policy_missing_pinned_trust_root_rejected() {
        let mut policy = sample_policy(1);
        // Remove the pinned SGX root and replace with a rotating one
        policy
            .platform_trust_roots
            .retain(|r| r.platform != TeePlatform::IntelSgx);
        policy.platform_trust_roots.push(PlatformTrustRoot {
            root_id: "sgx-rotating".to_string(),
            platform: TeePlatform::IntelSgx,
            trust_anchor_pem: "-----BEGIN CERT-----SGX-ROT".to_string(),
            valid_from_epoch: SecurityEpoch::from_raw(0),
            valid_until_epoch: Some(SecurityEpoch::from_raw(100)),
            pinning: TrustRootPinning::Rotating {
                rotation_group: "sgx-grp".to_string(),
            },
            source: TrustRootSource::Policy,
        });
        let err = policy.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::MissingPinnedTrustRoot {
                platform: TeePlatform::IntelSgx
            }
        ));
    }

    #[test]
    fn emitter_can_emit_runtime_epoch_too_far_ahead() {
        let mut emitter = DecisionReceiptEmitter::new("e-rt");
        let mut store = TeeAttestationPolicyStore::default();
        store.load_policy(sample_policy(5), "t-1", "d-1").unwrap();
        emitter.sync_policy(&store).unwrap();
        // Runtime epoch is 2 ahead of synced epoch (5) — should fail
        let err = emitter
            .can_emit(SecurityEpoch::from_raw(7), &store)
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::EmitterPolicyStale { .. }
        ));
    }

    #[test]
    fn canonicalize_lowercases_and_deduplicates_measurements() {
        let mut policy = sample_policy(1);
        let upper_digest = MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha384,
            digest_hex: digest_hex(0x11, 48).to_uppercase(),
        };
        policy
            .approved_measurements
            .get_mut(&TeePlatform::IntelSgx)
            .unwrap()
            .push(upper_digest);
        // Before canonicalize: SGX has 2 entries (one lower, one upper)
        assert_eq!(
            policy.approved_measurements[&TeePlatform::IntelSgx].len(),
            2
        );
        policy.canonicalize_in_place();
        // After canonicalize: both lowercased and deduped to 1
        assert_eq!(
            policy.approved_measurements[&TeePlatform::IntelSgx].len(),
            1
        );
    }

    #[test]
    fn override_artifact_evidence_refs_sorted_and_deduped() {
        let signing_key = SigningKey::from_bytes([7u8; 32]);
        let artifact = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator".to_string(),
                justification: "test dedup".to_string(),
                evidence_refs: vec![
                    "z-ref".to_string(),
                    "a-ref".to_string(),
                    "z-ref".to_string(),
                ],
                target_platform: TeePlatform::IntelSgx,
                target_root_id: "root-1".to_string(),
                issued_epoch: SecurityEpoch::from_raw(1),
                expires_epoch: SecurityEpoch::from_raw(5),
            },
        )
        .unwrap();
        assert_eq!(artifact.evidence_refs, vec!["a-ref", "z-ref"]);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn freshness_window_serde_round_trip() {
        let window = AttestationFreshnessWindow {
            standard_max_age_secs: 300,
            high_impact_max_age_secs: 60,
        };
        let json = serde_json::to_string(&window).unwrap();
        let back: AttestationFreshnessWindow = serde_json::from_str(&json).unwrap();
        assert_eq!(window, back);
    }

    #[test]
    fn temporary_trust_root_override_serde_round_trip() {
        let signing_key = SigningKey::from_bytes([7u8; 32]);
        let artifact = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator-serde".to_string(),
                justification: "serde test".to_string(),
                evidence_refs: vec!["ev-1".to_string()],
                target_platform: TeePlatform::ArmCca,
                target_root_id: "cca-temp".to_string(),
                issued_epoch: SecurityEpoch::from_raw(1),
                expires_epoch: SecurityEpoch::from_raw(10),
            },
        )
        .unwrap();
        let override_req = TemporaryTrustRootOverride {
            override_id: "ovr-serde".to_string(),
            trust_root: PlatformTrustRoot {
                root_id: "cca-temp".to_string(),
                platform: TeePlatform::ArmCca,
                trust_anchor_pem: "-----BEGIN CERT-----CCA-TEMP".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(1),
                valid_until_epoch: Some(SecurityEpoch::from_raw(10)),
                pinning: TrustRootPinning::Rotating {
                    rotation_group: "cca-rollover".to_string(),
                },
                source: TrustRootSource::Policy,
            },
            artifact,
        };
        let json = serde_json::to_string(&override_req).unwrap();
        let back: TemporaryTrustRootOverride = serde_json::from_str(&json).unwrap();
        assert_eq!(override_req, back);
    }

    #[test]
    fn override_empty_override_id_rejected() {
        let mut store = TeeAttestationPolicyStore::default();
        store.load_policy(sample_policy(10), "t-1", "d-1").unwrap();
        let signing_key = SigningKey::from_bytes([7u8; 32]);
        let verifier = signing_key.verification_key();
        let artifact = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator".to_string(),
                justification: "test".to_string(),
                evidence_refs: vec![],
                target_platform: TeePlatform::IntelSgx,
                target_root_id: "sgx-root-temp-eid".to_string(),
                issued_epoch: SecurityEpoch::from_raw(10),
                expires_epoch: SecurityEpoch::from_raw(12),
            },
        )
        .unwrap();
        let request = TemporaryTrustRootOverride {
            override_id: "".to_string(),
            trust_root: PlatformTrustRoot {
                root_id: "sgx-root-temp-eid".to_string(),
                platform: TeePlatform::IntelSgx,
                trust_anchor_pem: "-----BEGIN CERT-----".to_string(),
                valid_from_epoch: SecurityEpoch::from_raw(10),
                valid_until_epoch: Some(SecurityEpoch::from_raw(12)),
                pinning: TrustRootPinning::Rotating {
                    rotation_group: "sgx-rollover".to_string(),
                },
                source: TrustRootSource::Policy,
            },
            artifact,
        };
        let err = store
            .apply_temporary_trust_root_override(
                request,
                &verifier,
                SecurityEpoch::from_raw(10),
                "t-eid",
                "d-eid",
            )
            .unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidOverrideArtifact { .. }
        ));
    }

    #[test]
    fn verify_artifact_valid_signature_passes() {
        let signing_key = SigningKey::from_bytes([7u8; 32]);
        let verifier = signing_key.verification_key();
        let artifact = SignedTrustRootOverrideArtifact::create_signed(
            &signing_key,
            TrustRootOverrideArtifactInput {
                actor: "operator".to_string(),
                justification: "test verify pass".to_string(),
                evidence_refs: vec!["ev-1".to_string()],
                target_platform: TeePlatform::IntelSgx,
                target_root_id: "root-verify".to_string(),
                issued_epoch: SecurityEpoch::from_raw(1),
                expires_epoch: SecurityEpoch::from_raw(10),
            },
        )
        .unwrap();
        artifact
            .verify(&verifier, SecurityEpoch::from_raw(5))
            .unwrap();
    }

    #[test]
    fn error_code_all_variants_unique() {
        let variants: Vec<TeeAttestationPolicyError> = vec![
            TeeAttestationPolicyError::ParseFailed {
                detail: "a".to_string(),
            },
            TeeAttestationPolicyError::SerializationFailed {
                detail: "b".to_string(),
            },
            TeeAttestationPolicyError::MissingMeasurementsForPlatform {
                platform: TeePlatform::IntelSgx,
            },
            TeeAttestationPolicyError::InvalidMeasurementDigest {
                platform: TeePlatform::IntelSgx,
                digest: "c".to_string(),
                expected_hex_len: 64,
            },
            TeeAttestationPolicyError::DuplicateMeasurementDigest {
                platform: TeePlatform::IntelSgx,
                digest: "d".to_string(),
            },
            TeeAttestationPolicyError::InvalidFreshnessWindow {
                standard_max_age_secs: 0,
                high_impact_max_age_secs: 0,
            },
            TeeAttestationPolicyError::EmptyRevocationSources,
            TeeAttestationPolicyError::InvalidRevocationSource {
                reason: "e".to_string(),
            },
            TeeAttestationPolicyError::DuplicateRevocationSource {
                source_id: "f".to_string(),
            },
            TeeAttestationPolicyError::RevocationFallbackBypass,
            TeeAttestationPolicyError::MissingTrustRoots,
            TeeAttestationPolicyError::InvalidTrustRoot {
                root_id: "g".to_string(),
                reason: "h".to_string(),
            },
            TeeAttestationPolicyError::DuplicateTrustRoot {
                platform: TeePlatform::IntelSgx,
                root_id: "i".to_string(),
            },
            TeeAttestationPolicyError::MissingPinnedTrustRoot {
                platform: TeePlatform::IntelSgx,
            },
            TeeAttestationPolicyError::PolicyEpochRegression {
                current: SecurityEpoch::from_raw(5),
                attempted: SecurityEpoch::from_raw(3),
            },
            TeeAttestationPolicyError::IdDerivationFailed {
                detail: "j".to_string(),
            },
            TeeAttestationPolicyError::ReceiptEmissionHalted,
            TeeAttestationPolicyError::NoActivePolicy,
            TeeAttestationPolicyError::UnknownMeasurementDigest {
                platform: TeePlatform::IntelSgx,
                digest: "k".to_string(),
            },
            TeeAttestationPolicyError::AttestationStale {
                quote_age_secs: 500,
                max_age_secs: 300,
            },
            TeeAttestationPolicyError::UnknownTrustRoot {
                platform: TeePlatform::IntelSgx,
                root_id: "l".to_string(),
            },
            TeeAttestationPolicyError::ExpiredTrustRoot {
                root_id: "m".to_string(),
                runtime_epoch: SecurityEpoch::from_raw(10),
                valid_until_epoch: Some(SecurityEpoch::from_raw(5)),
            },
            TeeAttestationPolicyError::RevokedBySource {
                source_id: "n".to_string(),
            },
            TeeAttestationPolicyError::RevocationSourceUnavailable {
                source_id: "o".to_string(),
            },
            TeeAttestationPolicyError::RevocationEvidenceUnavailable,
            TeeAttestationPolicyError::InvalidOverrideArtifact {
                reason: "p".to_string(),
            },
            TeeAttestationPolicyError::OverrideJustificationMissing,
            TeeAttestationPolicyError::OverrideExpired {
                current_epoch: SecurityEpoch::from_raw(10),
                expires_epoch: SecurityEpoch::from_raw(5),
            },
            TeeAttestationPolicyError::OverrideSignatureInvalid {
                detail: "q".to_string(),
            },
            TeeAttestationPolicyError::OverrideTargetMismatch {
                expected_platform: TeePlatform::IntelSgx,
                expected_root_id: "r1".to_string(),
                actual_platform: TeePlatform::AmdSev,
                actual_root_id: "r2".to_string(),
            },
            TeeAttestationPolicyError::EmitterNotSynced {
                emitter_id: "s".to_string(),
            },
            TeeAttestationPolicyError::EmitterPolicyStale {
                emitter_id: "t".to_string(),
                synced_epoch: SecurityEpoch::from_raw(3),
                required_epoch: SecurityEpoch::from_raw(5),
            },
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            let code = v.error_code();
            assert!(seen.insert(code), "duplicate error_code: {code}");
        }
    }

    #[test]
    fn canonicalize_trims_trust_root_ids() {
        let mut policy = sample_policy(1);
        policy.platform_trust_roots[0].root_id = "  sgx-root-a  ".to_string();
        policy.canonicalize_in_place();
        assert_eq!(policy.platform_trust_roots[0].root_id, "sgx-root-a");
    }

    #[test]
    fn store_evaluate_quote_no_policy_not_halted() {
        let mut store = TeeAttestationPolicyStore {
            receipt_emission_halted: false,
            last_error_code: None,
            ..TeeAttestationPolicyStore::default()
        };
        let quote = quote_for_sgx();
        let err = store
            .evaluate_quote(
                &quote,
                DecisionImpact::Standard,
                SecurityEpoch::from_raw(1),
                "t-no-pol",
                "d-no-pol",
            )
            .unwrap_err();
        assert!(matches!(err, TeeAttestationPolicyError::NoActivePolicy));
        let last = store.governance_ledger().last().unwrap();
        assert_eq!(last.event, "quote_evaluation_failed");
        assert_eq!(last.outcome, "deny");
    }

    #[test]
    fn policy_governance_event_metadata_preserved() {
        let mut store = TeeAttestationPolicyStore::default();
        store
            .load_policy(sample_policy(5), "t-meta", "d-meta")
            .unwrap();
        let load_event = &store.governance_ledger()[0];
        assert_eq!(load_event.event, "policy_loaded");
        assert!(load_event.metadata.contains_key("policy_epoch"));
        assert!(load_event.metadata.contains_key("schema_version"));
    }

    #[test]
    fn emitter_serde_no_synced_epoch() {
        let emitter = DecisionReceiptEmitter::new("e-no-sync");
        let json = serde_json::to_string(&emitter).unwrap();
        let back: DecisionReceiptEmitter = serde_json::from_str(&json).unwrap();
        assert_eq!(emitter, back);
        assert!(back.last_synced_policy_epoch.is_none());
    }

    #[test]
    fn freshness_window_zero_high_impact_only_rejected() {
        let window = AttestationFreshnessWindow {
            standard_max_age_secs: 300,
            high_impact_max_age_secs: 0,
        };
        let err = window.validate().unwrap_err();
        assert!(matches!(
            err,
            TeeAttestationPolicyError::InvalidFreshnessWindow { .. }
        ));
    }

    #[test]
    fn signed_artifact_deterministic_id() {
        let signing_key = SigningKey::from_bytes([7u8; 32]);
        let input = TrustRootOverrideArtifactInput {
            actor: "op".to_string(),
            justification: "determ test".to_string(),
            evidence_refs: vec!["ev".to_string()],
            target_platform: TeePlatform::AmdSev,
            target_root_id: "sev-det".to_string(),
            issued_epoch: SecurityEpoch::from_raw(1),
            expires_epoch: SecurityEpoch::from_raw(5),
        };
        let a1 =
            SignedTrustRootOverrideArtifact::create_signed(&signing_key, input.clone()).unwrap();
        let a2 = SignedTrustRootOverrideArtifact::create_signed(&signing_key, input).unwrap();
        assert_eq!(a1.artifact_id, a2.artifact_id);
    }

    #[test]
    fn error_display_all_variants_non_empty() {
        let variants: Vec<TeeAttestationPolicyError> = vec![
            TeeAttestationPolicyError::ParseFailed {
                detail: "a".to_string(),
            },
            TeeAttestationPolicyError::EmptyRevocationSources,
            TeeAttestationPolicyError::RevocationFallbackBypass,
            TeeAttestationPolicyError::MissingTrustRoots,
            TeeAttestationPolicyError::ReceiptEmissionHalted,
            TeeAttestationPolicyError::NoActivePolicy,
            TeeAttestationPolicyError::RevocationEvidenceUnavailable,
            TeeAttestationPolicyError::OverrideJustificationMissing,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let s = v.to_string();
            assert!(!s.is_empty());
            displays.insert(s);
        }
        assert_eq!(displays.len(), variants.len(), "duplicate Display outputs");
    }

    // ── Enrichment: Display tests ────────────────────────────────────

    #[test]
    fn tee_platform_display_all_variants() {
        let all = [
            (TeePlatform::IntelSgx, "intel_sgx"),
            (TeePlatform::ArmTrustZone, "arm_trustzone"),
            (TeePlatform::ArmCca, "arm_cca"),
            (TeePlatform::AmdSev, "amd_sev"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (p, expected) in &all {
            assert_eq!(&p.to_string(), expected);
            assert!(seen.insert(p.to_string()));
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn measurement_algorithm_display_all_variants() {
        let all = [
            (MeasurementAlgorithm::Sha256, "sha256"),
            (MeasurementAlgorithm::Sha384, "sha384"),
            (MeasurementAlgorithm::Sha512, "sha512"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (a, expected) in &all {
            assert_eq!(&a.to_string(), expected);
            assert!(seen.insert(a.to_string()));
        }
        assert_eq!(seen.len(), 3);
    }

    // ── Enrichment: Serde roundtrip tests ────────────────────────────

    #[test]
    fn tee_platform_serde_roundtrip_all() {
        for p in TeePlatform::ALL {
            let json = serde_json::to_string(&p).unwrap();
            let back: TeePlatform = serde_json::from_str(&json).unwrap();
            assert_eq!(back, p);
        }
    }

    #[test]
    fn measurement_algorithm_serde_roundtrip_all() {
        for a in [
            MeasurementAlgorithm::Sha256,
            MeasurementAlgorithm::Sha384,
            MeasurementAlgorithm::Sha512,
        ] {
            let json = serde_json::to_string(&a).unwrap();
            let back: MeasurementAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(back, a);
        }
    }

    #[test]
    fn revocation_source_type_serde_roundtrip_all() {
        let variants = [
            RevocationSourceType::IntelPcs,
            RevocationSourceType::ManufacturerCrl,
            RevocationSourceType::InternalLedger,
            RevocationSourceType::Other("custom-source".to_string()),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: RevocationSourceType = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn revocation_fallback_serde_roundtrip() {
        for f in [
            RevocationFallback::TryNextSource,
            RevocationFallback::FailClosed,
        ] {
            let json = serde_json::to_string(&f).unwrap();
            let back: RevocationFallback = serde_json::from_str(&json).unwrap();
            assert_eq!(back, f);
        }
    }

    #[test]
    fn trust_root_pinning_serde_roundtrip_all() {
        let variants = [
            TrustRootPinning::Pinned,
            TrustRootPinning::Rotating {
                rotation_group: "group-alpha".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: TrustRootPinning = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn trust_root_source_serde_roundtrip_all() {
        let variants = [
            TrustRootSource::Policy,
            TrustRootSource::TemporaryOverride {
                override_id: "ov-001".to_string(),
                justification_artifact_id: "just-001".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: TrustRootSource = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn decision_impact_serde_roundtrip() {
        for d in [DecisionImpact::Standard, DecisionImpact::HighImpact] {
            let json = serde_json::to_string(&d).unwrap();
            let back: DecisionImpact = serde_json::from_str(&json).unwrap();
            assert_eq!(back, d);
        }
    }

    #[test]
    fn revocation_probe_status_serde_roundtrip_all() {
        for s in [
            RevocationProbeStatus::Good,
            RevocationProbeStatus::Revoked,
            RevocationProbeStatus::Unavailable,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: RevocationProbeStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, s);
        }
    }

    #[test]
    fn measurement_digest_serde_roundtrip_alt() {
        let digest = MeasurementDigest {
            algorithm: MeasurementAlgorithm::Sha256,
            digest_hex: "a".repeat(64),
        };
        let json = serde_json::to_string(&digest).unwrap();
        let back: MeasurementDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, digest);
    }
}
