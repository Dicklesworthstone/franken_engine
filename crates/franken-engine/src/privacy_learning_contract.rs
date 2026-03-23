//! Privacy-preserving fleet learning contract for calibration data governance.
//!
//! Defines the canonical contract schema that governs how fleet-wide
//! calibration data is collected, aggregated, and consumed without
//! centralising raw tenant-sensitive traces.  Every privacy guarantee
//! is machine-readable, versioned, and auditable.
//!
//! Key contract components:
//! - **Feature schema** — typed fields for local model updates with
//!   versioning and backward-compatibility rules.
//! - **Update policy** — frequency, sample minimums, submission windows.
//! - **Clipping strategy** — per-feature sensitivity bounding before
//!   noise addition.
//! - **DP budget semantics** — epsilon/delta, composition accounting,
//!   hard fail-closed on exhaustion.
//! - **Secure aggregation requirements** — minimum participant threshold,
//!   dropout tolerance, coordinator trust model.
//!
//! Design invariants:
//! - Learning state is *stochastic*; decision state is *deterministic*.
//!   Live decision paths consume only signed snapshot artifacts, never
//!   raw learning state.
//! - Contract changes require signed governance approval and propagation
//!   to all fleet participants.
//! - Budget exhaustion is *fail-closed*: no silent degradation.
//!
//! Plan references: Section 10.15 (Delta Moonshots), subsection 9I.2
//! (Privacy-Preserving Fleet Learning Layer), item 1 of 4.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue, SchemaHash};
use crate::engine_object_id::{self, EngineObjectId, ObjectDomain, SchemaId};
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_preimage,
    verify_signature,
};

// ---------------------------------------------------------------------------
// Schema definitions
// ---------------------------------------------------------------------------

const CONTRACT_SCHEMA_DEF: &[u8] = b"FrankenEngine.PrivacyLearningContract.v1";

pub fn contract_schema() -> SchemaHash {
    SchemaHash::from_definition(CONTRACT_SCHEMA_DEF)
}

pub fn contract_schema_id() -> SchemaId {
    SchemaId::from_definition(CONTRACT_SCHEMA_DEF)
}

// ---------------------------------------------------------------------------
// Feature field types
// ---------------------------------------------------------------------------

/// Supported data types for feature schema fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FeatureFieldType {
    /// Fixed-point millionths (i64 where 1_000_000 = 1.0).
    FixedPoint,
    /// Unsigned 64-bit integer counter.
    Counter,
    /// Boolean flag.
    Boolean,
    /// Categorical index (bounded enum ordinal).
    Categorical,
}

impl fmt::Display for FeatureFieldType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FixedPoint => write!(f, "fixed_point"),
            Self::Counter => write!(f, "counter"),
            Self::Boolean => write!(f, "boolean"),
            Self::Categorical => write!(f, "categorical"),
        }
    }
}

/// A single field in the feature schema.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FeatureField {
    /// Machine-readable field name (snake_case, unique within schema).
    pub name: String,
    /// Data type of this field.
    pub field_type: FeatureFieldType,
    /// Human-readable description of what this field captures.
    pub description: String,
    /// Whether this field was present in the previous schema version.
    /// New fields must be marked `false` for backward compatibility.
    pub existed_in_prior_version: bool,
}

/// Typed definition of local model update / summary statistic fields.
///
/// Each version is immutable once published.  Adding fields is the only
/// permitted change; removing or retyping fields requires a new major
/// version with explicit migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureSchema {
    /// Schema version (monotonically increasing).
    pub version: u32,
    /// Fields in deterministic order (sorted by name).
    pub fields: BTreeMap<String, FeatureField>,
    /// Optional reference to the prior schema version for migration.
    pub prior_version: Option<u32>,
}

impl FeatureSchema {
    /// Validate the schema for internal consistency.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.fields.is_empty() {
            return Err(ContractError::EmptyFeatureSchema);
        }
        if self.version == 0 {
            return Err(ContractError::InvalidVersion {
                detail: "schema version must be > 0".to_string(),
            });
        }
        // Ensure field names match their map keys.
        for (key, field) in &self.fields {
            if key != &field.name {
                return Err(ContractError::FieldNameMismatch {
                    key: key.clone(),
                    field_name: field.name.clone(),
                });
            }
        }
        // If prior_version exists, new fields must be marked accordingly.
        if self.prior_version.is_some() {
            let has_new_fields = self.fields.values().any(|f| !f.existed_in_prior_version);
            let has_old_fields = self.fields.values().any(|f| f.existed_in_prior_version);
            if !has_old_fields {
                return Err(ContractError::BackwardCompatibilityViolation {
                    detail: "schema with prior_version must retain at least one prior field"
                        .to_string(),
                });
            }
            // Version must be strictly greater than prior.
            if let Some(prior) = self.prior_version
                && self.version <= prior
            {
                return Err(ContractError::InvalidVersion {
                    detail: format!("version {} must be > prior_version {}", self.version, prior),
                });
            }
            let _ = has_new_fields; // lint: used for documentation, not logic gate
        }
        Ok(())
    }

    /// Check backward compatibility: all fields from `prior` must exist
    /// in `self` with the same type.
    pub fn is_backward_compatible_with(&self, prior: &FeatureSchema) -> bool {
        for (name, prior_field) in &prior.fields {
            match self.fields.get(name) {
                Some(current_field) => {
                    if current_field.field_type != prior_field.field_type {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Update policy
// ---------------------------------------------------------------------------

/// Rules governing when and how local updates are computed and submitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePolicy {
    /// Minimum number of local samples before an update may be submitted.
    pub min_local_samples: u64,
    /// Maximum submission frequency: minimum interval between submissions
    /// (in deterministic timestamp units).
    pub min_submission_interval: u64,
    /// Maximum age of local data included in a submission (staleness bound).
    pub max_data_age: u64,
    /// Whether participants may skip a submission round without penalty.
    pub allow_skip: bool,
    /// Maximum number of consecutive skips before the participant is
    /// considered dropped from the current aggregation epoch.
    pub max_consecutive_skips: u32,
}

impl UpdatePolicy {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.min_local_samples == 0 {
            return Err(ContractError::InvalidUpdatePolicy {
                detail: "min_local_samples must be > 0".to_string(),
            });
        }
        if self.min_submission_interval == 0 {
            return Err(ContractError::InvalidUpdatePolicy {
                detail: "min_submission_interval must be > 0".to_string(),
            });
        }
        if self.max_data_age == 0 {
            return Err(ContractError::InvalidUpdatePolicy {
                detail: "max_data_age must be > 0".to_string(),
            });
        }
        if self.allow_skip && self.max_consecutive_skips == 0 {
            return Err(ContractError::InvalidUpdatePolicy {
                detail: "max_consecutive_skips must be > 0 when skips are allowed".to_string(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Clipping strategy
// ---------------------------------------------------------------------------

/// Method for bounding the sensitivity of a feature field before noise
/// addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ClippingMethod {
    /// L2 norm clipping: scale the entire update vector if its L2 norm
    /// exceeds the bound.
    L2Norm,
    /// Per-coordinate clipping: independently clip each field to its bound.
    PerCoordinate,
    /// Adaptive clipping: adjust the bound based on observed quantiles
    /// (requires additional DP budget for the quantile estimation).
    Adaptive,
}

impl fmt::Display for ClippingMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::L2Norm => write!(f, "l2_norm"),
            Self::PerCoordinate => write!(f, "per_coordinate"),
            Self::Adaptive => write!(f, "adaptive"),
        }
    }
}

/// Per-feature clipping bounds to control sensitivity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClippingStrategy {
    /// Global clipping method applied to the update vector.
    pub method: ClippingMethod,
    /// Global clipping bound (fixed-point millionths).
    /// For L2Norm: the maximum L2 norm of the update vector.
    /// For PerCoordinate: the default per-field bound.
    pub global_bound_millionths: i64,
    /// Optional per-field overrides (field name -> bound in millionths).
    /// Only valid when method is PerCoordinate.
    pub per_field_bounds: BTreeMap<String, i64>,
}

impl ClippingStrategy {
    pub fn validate(&self, feature_schema: &FeatureSchema) -> Result<(), ContractError> {
        if self.global_bound_millionths <= 0 {
            return Err(ContractError::InvalidClippingStrategy {
                detail: "global_bound_millionths must be > 0".to_string(),
            });
        }
        // Per-field bounds only valid with PerCoordinate.
        if self.method != ClippingMethod::PerCoordinate && !self.per_field_bounds.is_empty() {
            return Err(ContractError::InvalidClippingStrategy {
                detail: "per_field_bounds only valid with PerCoordinate clipping".to_string(),
            });
        }
        // All per-field bound keys must exist in the feature schema.
        for field_name in self.per_field_bounds.keys() {
            if !feature_schema.fields.contains_key(field_name) {
                return Err(ContractError::InvalidClippingStrategy {
                    detail: format!("per_field_bound references unknown field: {field_name}"),
                });
            }
        }
        // All per-field bounds must be positive.
        for (name, bound) in &self.per_field_bounds {
            if *bound <= 0 {
                return Err(ContractError::InvalidClippingStrategy {
                    detail: format!("per_field_bound for '{name}' must be > 0"),
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DP budget semantics
// ---------------------------------------------------------------------------

/// Composition accounting method for differential privacy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CompositionMethod {
    /// Basic (linear) composition: epsilon sums linearly.
    Basic,
    /// Advanced composition theorem (Dwork et al. 2010).
    Advanced,
    /// Renyi Differential Privacy (Mironov 2017).
    Renyi,
    /// Zero-Concentrated DP (Bun & Steinke 2016).
    ZeroCdp,
}

impl fmt::Display for CompositionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic => write!(f, "basic"),
            Self::Advanced => write!(f, "advanced"),
            Self::Renyi => write!(f, "renyi"),
            Self::ZeroCdp => write!(f, "zcdp"),
        }
    }
}

/// Differential privacy budget semantics with hard fail-closed enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpBudgetSemantics {
    /// Privacy loss parameter per epoch (fixed-point millionths).
    pub epsilon_per_epoch_millionths: i64,
    /// Failure probability per epoch (fixed-point millionths).
    pub delta_per_epoch_millionths: i64,
    /// Composition method for multi-epoch accounting.
    pub composition_method: CompositionMethod,
    /// Total lifetime budget for epsilon (fixed-point millionths).
    /// Once exhausted, the system MUST fail closed.
    pub lifetime_epsilon_budget_millionths: i64,
    /// Total lifetime budget for delta (fixed-point millionths).
    pub lifetime_delta_budget_millionths: i64,
    /// Whether budget exhaustion triggers immediate hard stop.
    /// MUST be true per contract invariants.
    pub fail_closed_on_exhaustion: bool,
}

impl DpBudgetSemantics {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.epsilon_per_epoch_millionths <= 0 {
            return Err(ContractError::InvalidDpBudget {
                detail: "epsilon_per_epoch must be > 0".to_string(),
            });
        }
        if self.delta_per_epoch_millionths <= 0 {
            return Err(ContractError::InvalidDpBudget {
                detail: "delta_per_epoch must be > 0".to_string(),
            });
        }
        if self.lifetime_epsilon_budget_millionths <= 0 {
            return Err(ContractError::InvalidDpBudget {
                detail: "lifetime_epsilon_budget must be > 0".to_string(),
            });
        }
        if self.lifetime_delta_budget_millionths <= 0 {
            return Err(ContractError::InvalidDpBudget {
                detail: "lifetime_delta_budget must be > 0".to_string(),
            });
        }
        if !self.fail_closed_on_exhaustion {
            return Err(ContractError::InvalidDpBudget {
                detail: "fail_closed_on_exhaustion must be true".to_string(),
            });
        }
        // Per-epoch budget must not exceed lifetime budget.
        if self.epsilon_per_epoch_millionths > self.lifetime_epsilon_budget_millionths {
            return Err(ContractError::InvalidDpBudget {
                detail: "epsilon_per_epoch exceeds lifetime budget".to_string(),
            });
        }
        if self.delta_per_epoch_millionths > self.lifetime_delta_budget_millionths {
            return Err(ContractError::InvalidDpBudget {
                detail: "delta_per_epoch exceeds lifetime budget".to_string(),
            });
        }
        Ok(())
    }

    /// Compute the maximum number of epochs before budget exhaustion
    /// under the given composition method.
    pub fn max_epochs(&self) -> u64 {
        let eps_epochs = match self.composition_method {
            CompositionMethod::Basic => {
                // Linear composition: total = k * epsilon_per_epoch.
                (self.lifetime_epsilon_budget_millionths / self.epsilon_per_epoch_millionths) as u64
            }
            CompositionMethod::Advanced | CompositionMethod::Renyi | CompositionMethod::ZeroCdp => {
                // For advanced/Renyi/zCDP, epsilon grows as O(sqrt(k)).
                // max_k such that epsilon_per_epoch * sqrt(k) <= lifetime.
                // k <= (lifetime / epsilon_per_epoch)^2.
                let ratio =
                    self.lifetime_epsilon_budget_millionths / self.epsilon_per_epoch_millionths;
                ratio.checked_mul(ratio).unwrap_or(i64::MAX) as u64
            }
        };

        if self.delta_per_epoch_millionths > 0 {
            let delta_epochs =
                (self.lifetime_delta_budget_millionths / self.delta_per_epoch_millionths) as u64;
            eps_epochs.min(delta_epochs)
        } else {
            eps_epochs
        }
    }
}

// ---------------------------------------------------------------------------
// Secure aggregation requirements
// ---------------------------------------------------------------------------

/// Trust model for the aggregation coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CoordinatorTrustModel {
    /// Coordinator sees only aggregated results, never individual updates.
    HonestButCurious,
    /// Coordinator may behave arbitrarily; protocol is secure against
    /// malicious coordinator (requires heavier crypto).
    Malicious,
}

impl fmt::Display for CoordinatorTrustModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HonestButCurious => write!(f, "honest_but_curious"),
            Self::Malicious => write!(f, "malicious"),
        }
    }
}

/// Cryptographic protocol for secret sharing in secure aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecretSharingScheme {
    /// Additive secret sharing (lightweight, sufficient for honest-but-curious).
    Additive,
    /// Shamir secret sharing (threshold-based, stronger guarantees).
    Shamir,
}

impl fmt::Display for SecretSharingScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Additive => write!(f, "additive"),
            Self::Shamir => write!(f, "shamir"),
        }
    }
}

/// Requirements for secure aggregation of local updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecureAggregationRequirements {
    /// Minimum number of participants for aggregation to proceed.
    pub min_participants: u32,
    /// Maximum fraction of participants that may drop out (millionths).
    /// E.g., 200_000 = 20% dropout tolerance.
    pub dropout_tolerance_millionths: i64,
    /// Cryptographic protocol for secret sharing.
    pub secret_sharing_scheme: SecretSharingScheme,
    /// Threshold for Shamir sharing (k-of-n).  Only relevant when
    /// scheme is `Shamir`.
    pub sharing_threshold: Option<u32>,
    /// Trust model for the coordinator.
    pub coordinator_trust_model: CoordinatorTrustModel,
}

impl SecureAggregationRequirements {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.min_participants < 2 {
            return Err(ContractError::InvalidAggregation {
                detail: "min_participants must be >= 2".to_string(),
            });
        }
        if self.dropout_tolerance_millionths < 0 || self.dropout_tolerance_millionths >= 1_000_000 {
            return Err(ContractError::InvalidAggregation {
                detail: "dropout_tolerance must be in [0, 1_000_000)".to_string(),
            });
        }
        // Shamir requires a threshold.
        if self.secret_sharing_scheme == SecretSharingScheme::Shamir {
            match self.sharing_threshold {
                None => {
                    return Err(ContractError::InvalidAggregation {
                        detail: "Shamir scheme requires sharing_threshold".to_string(),
                    });
                }
                Some(t) if t < 2 => {
                    return Err(ContractError::InvalidAggregation {
                        detail: "sharing_threshold must be >= 2".to_string(),
                    });
                }
                Some(t) if t > self.min_participants => {
                    return Err(ContractError::InvalidAggregation {
                        detail: "sharing_threshold must be <= min_participants".to_string(),
                    });
                }
                _ => {}
            }
        }
        // Additive should not have threshold.
        if self.secret_sharing_scheme == SecretSharingScheme::Additive
            && self.sharing_threshold.is_some()
        {
            return Err(ContractError::InvalidAggregation {
                detail: "Additive scheme must not specify sharing_threshold".to_string(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Data retention
// ---------------------------------------------------------------------------

/// Data retention and deletion semantics for intermediate aggregation state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataRetentionPolicy {
    /// Maximum retention period for intermediate aggregation state
    /// (in deterministic timestamp units).
    pub max_intermediate_retention: u64,
    /// Maximum retention period for signed snapshot artifacts.
    pub max_snapshot_retention: u64,
    /// Whether local raw updates must be deleted after submission.
    pub delete_local_after_submission: bool,
    /// Whether intermediate shares must be deleted after aggregation completes.
    pub delete_shares_after_aggregation: bool,
}

impl DataRetentionPolicy {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.max_intermediate_retention == 0 {
            return Err(ContractError::InvalidRetention {
                detail: "max_intermediate_retention must be > 0".to_string(),
            });
        }
        if self.max_snapshot_retention == 0 {
            return Err(ContractError::InvalidRetention {
                detail: "max_snapshot_retention must be > 0".to_string(),
            });
        }
        // Snapshot retention should be >= intermediate retention.
        if self.max_snapshot_retention < self.max_intermediate_retention {
            return Err(ContractError::InvalidRetention {
                detail: "max_snapshot_retention must be >= max_intermediate_retention".to_string(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Randomness transcript commitments
// ---------------------------------------------------------------------------

const RANDOMNESS_COMMITMENT_SCHEMA_DEF: &[u8] = b"FrankenEngine.RandomnessCommitment.v1";
const RANDOMNESS_SNAPSHOT_SCHEMA_DEF: &[u8] = b"FrankenEngine.RandomnessSnapshotSummary.v1";
const RANDOMNESS_MERKLE_DOMAIN: &[u8] = b"FrankenEngine.RandomnessMerkle.v1";
const RANDOMNESS_PRNG_DOMAIN: &[u8] = b"FrankenEngine.RandomnessPrng.v1";
const RANDOMNESS_ESCROW_XOR_MASK: [u8; 32] = [
    0x42, 0x6F, 0x1A, 0xC9, 0x54, 0xD2, 0x31, 0x8E, 0x90, 0x17, 0xAB, 0xF0, 0x2D, 0x73, 0x4C, 0xE5,
    0x19, 0xBE, 0x67, 0xA1, 0x08, 0xDA, 0x3F, 0x95, 0xEE, 0x21, 0x58, 0xC4, 0x7B, 0x0D, 0xB2, 0x6A,
];

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *ContentHash::compute(data).as_bytes()
}

fn hash_optional(bytes: Option<[u8; 32]>) -> CanonicalValue {
    match bytes {
        Some(v) => CanonicalValue::Bytes(v.to_vec()),
        None => CanonicalValue::Null,
    }
}

fn xor_escrow(seed: &[u8]) -> Vec<u8> {
    seed.iter()
        .enumerate()
        .map(|(idx, byte)| {
            *byte ^ RANDOMNESS_ESCROW_XOR_MASK[idx % RANDOMNESS_ESCROW_XOR_MASK.len()]
        })
        .collect()
}

fn commitment_schema() -> SchemaHash {
    SchemaHash::from_definition(RANDOMNESS_COMMITMENT_SCHEMA_DEF)
}

fn snapshot_schema() -> SchemaHash {
    SchemaHash::from_definition(RANDOMNESS_SNAPSHOT_SCHEMA_DEF)
}

fn compute_merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.is_empty() {
        return [0u8; 32];
    }

    let mut level: Vec<[u8; 32]> = hashes.to_vec();
    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
        let mut idx = 0usize;
        while idx < level.len() {
            let left = level[idx];
            let right = if idx + 1 < level.len() {
                level[idx + 1]
            } else {
                level[idx]
            };

            let mut preimage = Vec::with_capacity(RANDOMNESS_MERKLE_DOMAIN.len() + 64);
            preimage.extend_from_slice(RANDOMNESS_MERKLE_DOMAIN);
            preimage.extend_from_slice(&left);
            preimage.extend_from_slice(&right);
            next_level.push(hash_bytes(&preimage));
            idx += 2;
        }
        level = next_level;
    }

    level[0]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PrngAlgorithm {
    /// Hash-counter PRNG with deterministic state transitions.
    ChaCha20LikeCounter,
}

impl fmt::Display for PrngAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChaCha20LikeCounter => write!(f, "chacha20_like_counter"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicPrng {
    phase_id: String,
    algorithm: PrngAlgorithm,
    seed: Vec<u8>,
    draw_counter: u64,
}

impl DeterministicPrng {
    pub fn new(
        phase_id: &str,
        algorithm: PrngAlgorithm,
        seed: &[u8],
    ) -> Result<Self, ContractError> {
        if phase_id.trim().is_empty() {
            return Err(ContractError::InvalidRandomnessTranscript {
                detail: "phase_id must not be empty".to_string(),
            });
        }
        if seed.is_empty() {
            return Err(ContractError::InvalidRandomnessTranscript {
                detail: "seed must not be empty".to_string(),
            });
        }
        Ok(Self {
            phase_id: phase_id.to_string(),
            algorithm,
            seed: seed.to_vec(),
            draw_counter: 0,
        })
    }

    pub fn draw_counter(&self) -> u64 {
        self.draw_counter
    }

    pub fn next_u64(&mut self) -> u64 {
        self.draw_counter += 1;
        let mut preimage = Vec::with_capacity(
            RANDOMNESS_PRNG_DOMAIN.len() + self.phase_id.len() + self.seed.len() + 16,
        );
        preimage.extend_from_slice(RANDOMNESS_PRNG_DOMAIN);
        preimage.extend_from_slice(self.phase_id.as_bytes());
        preimage.extend_from_slice(&(self.phase_id.len() as u32).to_be_bytes());
        preimage.extend_from_slice(&self.draw_counter.to_be_bytes());
        preimage.extend_from_slice(match self.algorithm {
            PrngAlgorithm::ChaCha20LikeCounter => b"chacha20-like-counter",
        });
        preimage.extend_from_slice(&self.seed);

        let block = hash_bytes(&preimage);
        let mut out = [0u8; 8];
        out.copy_from_slice(&block[..8]);
        u64::from_be_bytes(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandomnessCommitment {
    pub phase_id: String,
    pub seed_hash: [u8; 32],
    pub prng_algorithm: PrngAlgorithm,
    pub sequence_counter: u64,
    pub epoch_id: SecurityEpoch,
    pub previous_commitment_hash: Option<[u8; 32]>,
    pub evidence_object_id: EngineObjectId,
    pub commitment_hash: [u8; 32],
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RandomnessCommitmentHashInput {
    phase_id: String,
    seed_hash: [u8; 32],
    prng_algorithm: PrngAlgorithm,
    sequence_counter: u64,
    epoch_id: SecurityEpoch,
    previous_commitment_hash: Option<[u8; 32]>,
    evidence_object_id: EngineObjectId,
}

impl RandomnessCommitmentHashInput {
    fn from_commitment(commitment: &RandomnessCommitment) -> Self {
        Self {
            phase_id: commitment.phase_id.clone(),
            seed_hash: commitment.seed_hash,
            prng_algorithm: commitment.prng_algorithm,
            sequence_counter: commitment.sequence_counter,
            epoch_id: commitment.epoch_id,
            previous_commitment_hash: commitment.previous_commitment_hash,
            evidence_object_id: commitment.evidence_object_id.clone(),
        }
    }
}

impl RandomnessCommitment {
    fn canonical_view(input: &RandomnessCommitmentHashInput) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "epoch_id".to_string(),
            CanonicalValue::U64(input.epoch_id.as_u64()),
        );
        map.insert(
            "evidence_object_id".to_string(),
            CanonicalValue::Bytes(input.evidence_object_id.as_bytes().to_vec()),
        );
        map.insert(
            "phase_id".to_string(),
            CanonicalValue::String(input.phase_id.clone()),
        );
        map.insert(
            "prng_algorithm".to_string(),
            CanonicalValue::String(input.prng_algorithm.to_string()),
        );
        map.insert(
            "previous_commitment_hash".to_string(),
            hash_optional(input.previous_commitment_hash),
        );
        map.insert(
            "seed_hash".to_string(),
            CanonicalValue::Bytes(input.seed_hash.to_vec()),
        );
        map.insert(
            "sequence_counter".to_string(),
            CanonicalValue::U64(input.sequence_counter),
        );
        CanonicalValue::Map(map)
    }

    fn compute_hash_from_fields(input: &RandomnessCommitmentHashInput) -> [u8; 32] {
        let domain = ObjectDomain::EvidenceRecord.tag();
        let schema = commitment_schema();
        let value = Self::canonical_view(input);
        let encoded = deterministic_serde::encode_value(&value);
        let mut preimage = Vec::with_capacity(domain.len() + 32 + encoded.len());
        preimage.extend_from_slice(domain);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&encoded);
        hash_bytes(&preimage)
    }

    fn recompute_hash(&self) -> [u8; 32] {
        let input = RandomnessCommitmentHashInput::from_commitment(self);
        Self::compute_hash_from_fields(&input)
    }

    pub fn verify_integrity(
        &self,
        expected_sequence: u64,
        expected_previous_hash: Option<[u8; 32]>,
        verification_key: &VerificationKey,
    ) -> Result<(), ContractError> {
        if self.sequence_counter != expected_sequence {
            return Err(ContractError::InvalidRandomnessTranscript {
                detail: format!(
                    "sequence mismatch: expected {}, got {}",
                    expected_sequence, self.sequence_counter
                ),
            });
        }
        if self.previous_commitment_hash != expected_previous_hash {
            return Err(ContractError::InvalidRandomnessTranscript {
                detail: "previous commitment hash mismatch".to_string(),
            });
        }

        let recomputed = self.recompute_hash();
        if recomputed != self.commitment_hash {
            return Err(ContractError::InvalidRandomnessTranscript {
                detail: "commitment hash mismatch".to_string(),
            });
        }

        verify_signature(verification_key, &self.commitment_hash, &self.signature).map_err(
            |e| ContractError::SignatureInvalid {
                detail: format!("randomness commitment signature invalid: {e}"),
            },
        )?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandomnessSnapshotSummary {
    pub epoch_id: SecurityEpoch,
    pub start_sequence_counter: u64,
    pub end_sequence_counter: u64,
    pub commitment_count: u64,
    pub model_snapshot_id: String,
    pub policy_snapshot_id: String,
    pub previous_snapshot_root: Option<[u8; 32]>,
    pub merkle_root: [u8; 32],
    pub summary_hash: [u8; 32],
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RandomnessSnapshotHashInput {
    epoch_id: SecurityEpoch,
    start_sequence_counter: u64,
    end_sequence_counter: u64,
    commitment_count: u64,
    model_snapshot_id: String,
    policy_snapshot_id: String,
    previous_snapshot_root: Option<[u8; 32]>,
    merkle_root: [u8; 32],
}

impl RandomnessSnapshotHashInput {
    fn from_summary(summary: &RandomnessSnapshotSummary) -> Self {
        Self {
            epoch_id: summary.epoch_id,
            start_sequence_counter: summary.start_sequence_counter,
            end_sequence_counter: summary.end_sequence_counter,
            commitment_count: summary.commitment_count,
            model_snapshot_id: summary.model_snapshot_id.clone(),
            policy_snapshot_id: summary.policy_snapshot_id.clone(),
            previous_snapshot_root: summary.previous_snapshot_root,
            merkle_root: summary.merkle_root,
        }
    }
}

impl RandomnessSnapshotSummary {
    fn canonical_view(input: &RandomnessSnapshotHashInput) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "commitment_count".to_string(),
            CanonicalValue::U64(input.commitment_count),
        );
        map.insert(
            "end_sequence_counter".to_string(),
            CanonicalValue::U64(input.end_sequence_counter),
        );
        map.insert(
            "epoch_id".to_string(),
            CanonicalValue::U64(input.epoch_id.as_u64()),
        );
        map.insert(
            "merkle_root".to_string(),
            CanonicalValue::Bytes(input.merkle_root.to_vec()),
        );
        map.insert(
            "model_snapshot_id".to_string(),
            CanonicalValue::String(input.model_snapshot_id.clone()),
        );
        map.insert(
            "policy_snapshot_id".to_string(),
            CanonicalValue::String(input.policy_snapshot_id.clone()),
        );
        map.insert(
            "previous_snapshot_root".to_string(),
            hash_optional(input.previous_snapshot_root),
        );
        map.insert(
            "start_sequence_counter".to_string(),
            CanonicalValue::U64(input.start_sequence_counter),
        );
        CanonicalValue::Map(map)
    }

    fn compute_hash_from_fields(input: &RandomnessSnapshotHashInput) -> [u8; 32] {
        let domain = ObjectDomain::EvidenceRecord.tag();
        let schema = snapshot_schema();
        let value = Self::canonical_view(input);
        let encoded = deterministic_serde::encode_value(&value);
        let mut preimage = Vec::with_capacity(domain.len() + 32 + encoded.len());
        preimage.extend_from_slice(domain);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&encoded);
        hash_bytes(&preimage)
    }

    fn recompute_hash(&self) -> [u8; 32] {
        let input = RandomnessSnapshotHashInput::from_summary(self);
        Self::compute_hash_from_fields(&input)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedEscrowAccessEvent {
    pub principal: String,
    pub reason: String,
    pub approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedEscrowRecord {
    pub phase_id: String,
    pub epoch_id: SecurityEpoch,
    pub seed_hash: [u8; 32],
    pub encrypted_seed: Vec<u8>,
    pub authorized_auditors: BTreeSet<String>,
    pub access_log: Vec<SeedEscrowAccessEvent>,
}

impl SeedEscrowRecord {
    pub fn create(
        phase_id: &str,
        epoch_id: SecurityEpoch,
        seed: &[u8],
        authorized_auditors: BTreeSet<String>,
    ) -> Result<Self, ContractError> {
        if phase_id.trim().is_empty() {
            return Err(ContractError::InvalidRandomnessTranscript {
                detail: "seed escrow phase_id must not be empty".to_string(),
            });
        }
        if seed.is_empty() {
            return Err(ContractError::InvalidRandomnessTranscript {
                detail: "seed escrow seed must not be empty".to_string(),
            });
        }

        Ok(Self {
            phase_id: phase_id.to_string(),
            epoch_id,
            seed_hash: hash_bytes(seed),
            encrypted_seed: xor_escrow(seed),
            authorized_auditors,
            access_log: Vec::new(),
        })
    }

    pub fn open_for_audit(
        &mut self,
        principal: &str,
        reason: &str,
    ) -> Result<Vec<u8>, ContractError> {
        let allowed = self.authorized_auditors.contains(principal);
        self.access_log.push(SeedEscrowAccessEvent {
            principal: principal.to_string(),
            reason: reason.to_string(),
            approved: allowed,
        });

        if !allowed {
            return Err(ContractError::SeedEscrowAccessDenied {
                principal: principal.to_string(),
                phase_id: self.phase_id.clone(),
            });
        }

        let seed = xor_escrow(&self.encrypted_seed);
        let recomputed = hash_bytes(&seed);
        if recomputed != self.seed_hash {
            return Err(ContractError::InvalidRandomnessTranscript {
                detail: format!("escrow seed hash mismatch for phase {}", self.phase_id),
            });
        }

        Ok(seed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayOutput {
    pub phase_id: String,
    pub sequence_counter: u64,
    pub outputs: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RandomnessTranscript {
    pub commitments: Vec<RandomnessCommitment>,
    pub snapshot_summaries: Vec<RandomnessSnapshotSummary>,
}

impl RandomnessTranscript {
    pub fn new() -> Self {
        Self {
            commitments: Vec::new(),
            snapshot_summaries: Vec::new(),
        }
    }

    pub fn commit_seed(
        &mut self,
        signing_key: &SigningKey,
        phase_id: &str,
        seed: &[u8],
        prng_algorithm: PrngAlgorithm,
        epoch_id: SecurityEpoch,
        evidence_object_id: EngineObjectId,
    ) -> Result<&RandomnessCommitment, ContractError> {
        if phase_id.trim().is_empty() {
            return Err(ContractError::InvalidRandomnessTranscript {
                detail: "phase_id must not be empty".to_string(),
            });
        }
        if seed.is_empty() {
            return Err(ContractError::InvalidRandomnessTranscript {
                detail: "seed must not be empty".to_string(),
            });
        }

        let seed_hash = hash_bytes(seed);
        let sequence_counter = self.commitments.len() as u64 + 1;
        let previous_commitment_hash = self.commitments.last().map(|entry| entry.commitment_hash);
        let hash_input = RandomnessCommitmentHashInput {
            phase_id: phase_id.to_string(),
            seed_hash,
            prng_algorithm,
            sequence_counter,
            epoch_id,
            previous_commitment_hash,
            evidence_object_id: evidence_object_id.clone(),
        };
        let commitment_hash = RandomnessCommitment::compute_hash_from_fields(&hash_input);

        let signature = sign_preimage(signing_key, &commitment_hash).map_err(|e| {
            ContractError::SignatureFailed {
                detail: format!("failed to sign randomness commitment: {e}"),
            }
        })?;

        self.commitments.push(RandomnessCommitment {
            phase_id: phase_id.to_string(),
            seed_hash,
            prng_algorithm,
            sequence_counter,
            epoch_id,
            previous_commitment_hash,
            evidence_object_id,
            commitment_hash,
            signature,
        });

        Ok(self
            .commitments
            .last()
            .expect("commitment was just pushed and must exist"))
    }

    pub fn verify_chain(&self, verification_key: &VerificationKey) -> Result<(), ContractError> {
        let mut expected_sequence = 1u64;
        let mut previous_hash: Option<[u8; 32]> = None;
        for commitment in &self.commitments {
            commitment.verify_integrity(expected_sequence, previous_hash, verification_key)?;
            previous_hash = Some(commitment.commitment_hash);
            expected_sequence += 1;
        }
        Ok(())
    }

    pub fn emit_snapshot_summary(
        &mut self,
        signing_key: &SigningKey,
        model_snapshot_id: &str,
        policy_snapshot_id: &str,
    ) -> Result<&RandomnessSnapshotSummary, ContractError> {
        if model_snapshot_id.trim().is_empty() || policy_snapshot_id.trim().is_empty() {
            return Err(ContractError::InvalidRandomnessTranscript {
                detail: "snapshot identifiers must not be empty".to_string(),
            });
        }
        if self.commitments.is_empty() {
            return Err(ContractError::InvalidRandomnessTranscript {
                detail: "cannot emit snapshot summary for empty transcript".to_string(),
            });
        }

        let start_sequence_counter = match self.snapshot_summaries.last() {
            Some(last) => last.end_sequence_counter + 1,
            None => 1,
        };
        let end_sequence_counter = self
            .commitments
            .last()
            .map(|c| c.sequence_counter)
            .unwrap_or(0);
        if end_sequence_counter < start_sequence_counter {
            return Err(ContractError::InvalidRandomnessTranscript {
                detail: "no new commitments since the previous snapshot".to_string(),
            });
        }

        let start_idx = (start_sequence_counter - 1) as usize;
        let end_idx = end_sequence_counter as usize;
        let slice = &self.commitments[start_idx..end_idx];
        let leaves: Vec<[u8; 32]> = slice.iter().map(|c| c.commitment_hash).collect();
        let merkle_root = compute_merkle_root(&leaves);
        let commitment_count = leaves.len() as u64;
        let previous_snapshot_root = self.snapshot_summaries.last().map(|s| s.merkle_root);
        let epoch_id = slice[0].epoch_id;

        let hash_input = RandomnessSnapshotHashInput {
            epoch_id,
            start_sequence_counter,
            end_sequence_counter,
            commitment_count,
            model_snapshot_id: model_snapshot_id.to_string(),
            policy_snapshot_id: policy_snapshot_id.to_string(),
            previous_snapshot_root,
            merkle_root,
        };
        let summary_hash = RandomnessSnapshotSummary::compute_hash_from_fields(&hash_input);
        let signature = sign_preimage(signing_key, &summary_hash).map_err(|e| {
            ContractError::SignatureFailed {
                detail: format!("failed to sign randomness snapshot summary: {e}"),
            }
        })?;

        self.snapshot_summaries.push(RandomnessSnapshotSummary {
            epoch_id,
            start_sequence_counter,
            end_sequence_counter,
            commitment_count,
            model_snapshot_id: model_snapshot_id.to_string(),
            policy_snapshot_id: policy_snapshot_id.to_string(),
            previous_snapshot_root,
            merkle_root,
            summary_hash,
            signature,
        });

        Ok(self
            .snapshot_summaries
            .last()
            .expect("snapshot summary was just pushed and must exist"))
    }

    pub fn verify_snapshot_summaries(
        &self,
        verification_key: &VerificationKey,
    ) -> Result<(), ContractError> {
        let mut expected_start = 1u64;
        let mut previous_root: Option<[u8; 32]> = None;
        for summary in &self.snapshot_summaries {
            if summary.start_sequence_counter != expected_start {
                return Err(ContractError::InvalidRandomnessTranscript {
                    detail: format!(
                        "snapshot start sequence mismatch: expected {}, got {}",
                        expected_start, summary.start_sequence_counter
                    ),
                });
            }
            if summary.end_sequence_counter < summary.start_sequence_counter {
                return Err(ContractError::InvalidRandomnessTranscript {
                    detail: "snapshot end sequence is before start sequence".to_string(),
                });
            }
            if summary.previous_snapshot_root != previous_root {
                return Err(ContractError::InvalidRandomnessTranscript {
                    detail: "snapshot previous root mismatch".to_string(),
                });
            }
            let recomputed = summary.recompute_hash();
            if recomputed != summary.summary_hash {
                return Err(ContractError::InvalidRandomnessTranscript {
                    detail: "snapshot summary hash mismatch".to_string(),
                });
            }
            verify_signature(verification_key, &summary.summary_hash, &summary.signature).map_err(
                |e| ContractError::SignatureInvalid {
                    detail: format!("randomness snapshot summary signature invalid: {e}"),
                },
            )?;

            let start_idx = (summary.start_sequence_counter - 1) as usize;
            let end_idx = summary.end_sequence_counter as usize;
            if end_idx > self.commitments.len() {
                return Err(ContractError::InvalidRandomnessTranscript {
                    detail: "snapshot references commitments beyond transcript length".to_string(),
                });
            }
            let slice = &self.commitments[start_idx..end_idx];
            if slice.is_empty() {
                return Err(ContractError::InvalidRandomnessTranscript {
                    detail: "snapshot must contain at least one commitment".to_string(),
                });
            }
            let leaves: Vec<[u8; 32]> = slice.iter().map(|c| c.commitment_hash).collect();
            let recomputed_root = compute_merkle_root(&leaves);
            if recomputed_root != summary.merkle_root {
                return Err(ContractError::InvalidRandomnessTranscript {
                    detail: "snapshot Merkle root mismatch".to_string(),
                });
            }
            if summary.commitment_count != leaves.len() as u64 {
                return Err(ContractError::InvalidRandomnessTranscript {
                    detail: "snapshot commitment count mismatch".to_string(),
                });
            }

            expected_start = summary.end_sequence_counter + 1;
            previous_root = Some(summary.merkle_root);
        }

        Ok(())
    }

    pub fn replay_with_escrowed_seeds(
        &self,
        verification_key: &VerificationKey,
        escrow_records: &mut [SeedEscrowRecord],
        auditor: &str,
        draws_per_phase: usize,
    ) -> Result<Vec<ReplayOutput>, ContractError> {
        self.verify_chain(verification_key)?;
        self.verify_snapshot_summaries(verification_key)?;

        let mut outputs = Vec::with_capacity(self.commitments.len());
        for commitment in &self.commitments {
            let escrow = escrow_records
                .iter_mut()
                .find(|record| {
                    record.phase_id == commitment.phase_id && record.epoch_id == commitment.epoch_id
                })
                .ok_or_else(|| ContractError::MissingSeedEscrow {
                    phase_id: commitment.phase_id.clone(),
                    epoch_id: commitment.epoch_id,
                })?;

            let seed = escrow.open_for_audit(auditor, "deterministic-replay")?;
            let seed_hash = hash_bytes(&seed);
            if seed_hash != commitment.seed_hash {
                return Err(ContractError::SeedHashMismatch {
                    phase_id: commitment.phase_id.clone(),
                });
            }

            let mut prng =
                DeterministicPrng::new(&commitment.phase_id, commitment.prng_algorithm, &seed)?;
            let phase_outputs = (0..draws_per_phase).map(|_| prng.next_u64()).collect();
            outputs.push(ReplayOutput {
                phase_id: commitment.phase_id.clone(),
                sequence_counter: commitment.sequence_counter,
                outputs: phase_outputs,
            });
        }

        Ok(outputs)
    }
}

impl Default for RandomnessTranscript {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// The contract itself
// ---------------------------------------------------------------------------

/// A versioned, governance-signed privacy-learning contract.
///
/// Defines all privacy guarantees for fleet-wide calibration.
/// Live decision paths consume only signed snapshots from this contract,
/// never raw learning state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyLearningContract {
    /// Unique contract identity derived from canonical content.
    pub contract_id: EngineObjectId,
    /// The epoch in which this contract is effective.
    pub epoch: SecurityEpoch,
    /// Zone this contract governs.
    pub zone: String,
    /// Feature schema defining the local update fields.
    pub feature_schema: FeatureSchema,
    /// Rules governing update computation and submission.
    pub update_policy: UpdatePolicy,
    /// Sensitivity bounding strategy.
    pub clipping_strategy: ClippingStrategy,
    /// Differential privacy budget semantics.
    pub dp_budget: DpBudgetSemantics,
    /// Secure aggregation requirements.
    pub aggregation: SecureAggregationRequirements,
    /// Data retention and deletion policy.
    pub retention: DataRetentionPolicy,
    /// Governance signature over all fields (sentinel during signing).
    pub governance_signature: Signature,
    /// Set of participant node IDs authorized for this contract.
    pub authorized_participants: BTreeSet<EngineObjectId>,
}

impl PrivacyLearningContract {
    /// Derive the contract ID from canonical content.
    fn derive_contract_id(
        epoch: SecurityEpoch,
        zone: &str,
        schema_version: u32,
    ) -> Result<EngineObjectId, engine_object_id::IdError> {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&epoch.as_u64().to_be_bytes());
        canonical.extend_from_slice(zone.as_bytes());
        canonical.extend_from_slice(&schema_version.to_be_bytes());
        engine_object_id::derive_id(
            ObjectDomain::PolicyObject,
            zone,
            &contract_schema_id(),
            &canonical,
        )
    }

    /// Create and sign a new privacy-learning contract.
    pub fn create_signed(
        governance_key: &SigningKey,
        input: CreateContractInput<'_>,
    ) -> Result<Self, ContractError> {
        // Validate all sub-components.
        input.feature_schema.validate()?;
        input.update_policy.validate()?;
        input.clipping_strategy.validate(&input.feature_schema)?;
        input.dp_budget.validate()?;
        input.aggregation.validate()?;
        input.retention.validate()?;

        if input.authorized_participants.is_empty() {
            return Err(ContractError::NoAuthorizedParticipants);
        }

        let contract_id =
            Self::derive_contract_id(input.epoch, input.zone, input.feature_schema.version)
                .map_err(|e| ContractError::IdDerivationFailed {
                    detail: e.to_string(),
                })?;

        let mut contract = Self {
            contract_id,
            epoch: input.epoch,
            zone: input.zone.to_string(),
            feature_schema: input.feature_schema,
            update_policy: input.update_policy,
            clipping_strategy: input.clipping_strategy,
            dp_budget: input.dp_budget,
            aggregation: input.aggregation,
            retention: input.retention,
            governance_signature: Signature::from_bytes(SIGNATURE_SENTINEL),
            authorized_participants: input.authorized_participants,
        };

        let preimage = contract.preimage_bytes();
        let sig = sign_preimage(governance_key, &preimage).map_err(|e| {
            ContractError::SignatureFailed {
                detail: e.to_string(),
            }
        })?;
        contract.governance_signature = sig;

        Ok(contract)
    }

    /// Verify the governance signature on this contract.
    pub fn verify_governance_signature(
        &self,
        governance_vk: &VerificationKey,
    ) -> Result<(), ContractError> {
        let preimage = self.preimage_bytes();
        verify_signature(governance_vk, &preimage, &self.governance_signature).map_err(|e| {
            ContractError::SignatureInvalid {
                detail: e.to_string(),
            }
        })
    }

    /// Check whether a participant is authorized under this contract.
    pub fn is_authorized(&self, participant: &EngineObjectId) -> bool {
        self.authorized_participants.contains(participant)
    }

    /// Build the unsigned view for signature computation.
    fn build_unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "aggregation_min_participants".to_string(),
            CanonicalValue::U64(self.aggregation.min_participants as u64),
        );
        map.insert(
            "clipping_method".to_string(),
            CanonicalValue::String(self.clipping_strategy.method.to_string()),
        );
        map.insert(
            "contract_id".to_string(),
            CanonicalValue::Bytes(self.contract_id.as_bytes().to_vec()),
        );
        map.insert(
            "dp_composition".to_string(),
            CanonicalValue::String(self.dp_budget.composition_method.to_string()),
        );
        map.insert(
            "dp_epsilon_per_epoch".to_string(),
            CanonicalValue::I64(self.dp_budget.epsilon_per_epoch_millionths),
        );
        map.insert(
            "dp_lifetime_epsilon".to_string(),
            CanonicalValue::I64(self.dp_budget.lifetime_epsilon_budget_millionths),
        );
        map.insert(
            "dp_delta_per_epoch".to_string(),
            CanonicalValue::I64(self.dp_budget.delta_per_epoch_millionths),
        );
        map.insert(
            "dp_lifetime_delta".to_string(),
            CanonicalValue::I64(self.dp_budget.lifetime_delta_budget_millionths),
        );
        map.insert(
            "epoch".to_string(),
            CanonicalValue::U64(self.epoch.as_u64()),
        );
        map.insert(
            "feature_schema_version".to_string(),
            CanonicalValue::U64(self.feature_schema.version as u64),
        );
        map.insert(
            "governance_signature".to_string(),
            CanonicalValue::Bytes(SIGNATURE_SENTINEL.to_vec()),
        );
        map.insert(
            "zone".to_string(),
            CanonicalValue::String(self.zone.clone()),
        );
        CanonicalValue::Map(map)
    }
}

/// Input parameters for creating a signed privacy-learning contract.
#[derive(Debug, Clone)]
pub struct CreateContractInput<'a> {
    pub epoch: SecurityEpoch,
    pub zone: &'a str,
    pub feature_schema: FeatureSchema,
    pub update_policy: UpdatePolicy,
    pub clipping_strategy: ClippingStrategy,
    pub dp_budget: DpBudgetSemantics,
    pub aggregation: SecureAggregationRequirements,
    pub retention: DataRetentionPolicy,
    pub authorized_participants: BTreeSet<EngineObjectId>,
}

impl SignaturePreimage for PrivacyLearningContract {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::PolicyObject
    }

    fn signature_schema(&self) -> &SchemaHash {
        unreachable!("use preimage_bytes directly")
    }

    fn unsigned_view(&self) -> CanonicalValue {
        self.build_unsigned_view()
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let domain_tag = self.signature_domain().tag();
        let schema = contract_schema();
        let unsigned = self.unsigned_view();
        let value_bytes = deterministic_serde::encode_value(&unsigned);

        let mut preimage = Vec::with_capacity(domain_tag.len() + 32 + value_bytes.len());
        preimage.extend_from_slice(domain_tag);
        preimage.extend_from_slice(schema.as_bytes());
        preimage.extend_from_slice(&value_bytes);
        preimage
    }
}

impl fmt::Display for PrivacyLearningContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrivacyLearningContract(id={}, epoch={}, zone={}, schema_v={}, dp={}/{})",
            self.contract_id,
            self.epoch,
            self.zone,
            self.feature_schema.version,
            self.dp_budget.composition_method,
            self.dp_budget.epsilon_per_epoch_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// Contract registry — manages active contracts per zone
// ---------------------------------------------------------------------------

/// Manages privacy-learning contracts with epoch-based versioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRegistry {
    /// Active contracts indexed by contract ID.
    contracts: BTreeMap<EngineObjectId, PrivacyLearningContract>,
    /// Per-zone active contract: zone -> contract ID.
    zone_active: BTreeMap<String, EngineObjectId>,
    /// Audit events.
    audit_events: Vec<ContractEvent>,
}

impl ContractRegistry {
    pub fn new() -> Self {
        Self {
            contracts: BTreeMap::new(),
            zone_active: BTreeMap::new(),
            audit_events: Vec::new(),
        }
    }

    /// Register a new contract after full verification.
    pub fn register(
        &mut self,
        contract: PrivacyLearningContract,
        governance_vk: &VerificationKey,
        trace_id: &str,
    ) -> Result<EngineObjectId, ContractError> {
        // Verify governance signature.
        contract.verify_governance_signature(governance_vk)?;

        // Check for duplicate.
        if self.contracts.contains_key(&contract.contract_id) {
            return Err(ContractError::DuplicateContract {
                contract_id: contract.contract_id.clone(),
            });
        }

        // If a contract exists for this zone, the new one must have a
        // higher epoch.
        if let Some(existing_id) = self.zone_active.get(&contract.zone)
            && let Some(existing) = self.contracts.get(existing_id)
            && existing.epoch.as_u64() >= contract.epoch.as_u64()
        {
            return Err(ContractError::EpochNotAdvanced {
                zone: contract.zone.clone(),
                existing_epoch: existing.epoch,
                new_epoch: contract.epoch,
            });
        }

        let contract_id = contract.contract_id.clone();
        let zone = contract.zone.clone();
        let epoch = contract.epoch;

        self.zone_active.insert(zone.clone(), contract_id.clone());
        self.contracts.insert(contract_id.clone(), contract);

        self.emit_event(
            ContractEventType::Registered {
                contract_id: contract_id.clone(),
                zone: zone.clone(),
                epoch,
            },
            trace_id,
        );

        Ok(contract_id)
    }

    /// Look up a contract by ID.
    pub fn get(&self, contract_id: &EngineObjectId) -> Option<&PrivacyLearningContract> {
        self.contracts.get(contract_id)
    }

    /// Get the active contract for a zone.
    pub fn active_for_zone(&self, zone: &str) -> Option<&PrivacyLearningContract> {
        self.zone_active
            .get(zone)
            .and_then(|id| self.contracts.get(id))
    }

    /// Revoke a contract.
    pub fn revoke(
        &mut self,
        contract_id: &EngineObjectId,
        trace_id: &str,
    ) -> Result<(), ContractError> {
        let contract =
            self.contracts
                .remove(contract_id)
                .ok_or_else(|| ContractError::NotFound {
                    contract_id: contract_id.clone(),
                })?;

        // Remove from zone active if it was the active contract.
        if let Some(active_id) = self.zone_active.get(&contract.zone)
            && active_id == contract_id
        {
            self.zone_active.remove(&contract.zone);
        }

        self.emit_event(
            ContractEventType::Revoked {
                contract_id: contract_id.clone(),
                zone: contract.zone.clone(),
            },
            trace_id,
        );

        Ok(())
    }

    /// Total number of contracts.
    pub fn total_count(&self) -> usize {
        self.contracts.len()
    }

    /// Number of zones with active contracts.
    pub fn zone_count(&self) -> usize {
        self.zone_active.len()
    }

    /// Drain accumulated audit events.
    pub fn drain_events(&mut self) -> Vec<ContractEvent> {
        std::mem::take(&mut self.audit_events)
    }

    fn emit_event(&mut self, event_type: ContractEventType, trace_id: &str) {
        self.audit_events.push(ContractEvent {
            event_type,
            trace_id: trace_id.to_string(),
        });
    }
}

impl Default for ContractRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Shadow evaluation promotion gate
// ---------------------------------------------------------------------------

const SHADOW_PROMOTION_DECISION_SCHEMA_DEF: &[u8] = b"FrankenEngine.ShadowPromotionDecision.v1";
const SHADOW_OVERRIDE_SCHEMA_DEF: &[u8] = b"FrankenEngine.ShadowPromotionOverride.v1";
const SHADOW_ROLLBACK_RECEIPT_SCHEMA_DEF: &[u8] = b"FrankenEngine.ShadowRollbackReceipt.v1";

fn shadow_promotion_schema() -> SchemaHash {
    SchemaHash::from_definition(SHADOW_PROMOTION_DECISION_SCHEMA_DEF)
}

fn shadow_override_schema() -> SchemaHash {
    SchemaHash::from_definition(SHADOW_OVERRIDE_SCHEMA_DEF)
}

fn shadow_rollback_receipt_schema() -> SchemaHash {
    SchemaHash::from_definition(SHADOW_ROLLBACK_RECEIPT_SCHEMA_DEF)
}

/// Safety metrics evaluated by the shadow-promotion gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SafetyMetric {
    FalsePositiveRate,
    FalseNegativeRate,
    CalibrationError,
    DriftDetectionAccuracy,
    ContainmentTime,
}

impl SafetyMetric {
    pub const ALL: &'static [SafetyMetric] = &[
        SafetyMetric::FalsePositiveRate,
        SafetyMetric::FalseNegativeRate,
        SafetyMetric::CalibrationError,
        SafetyMetric::DriftDetectionAccuracy,
        SafetyMetric::ContainmentTime,
    ];

    fn higher_is_better(self) -> bool {
        matches!(self, Self::DriftDetectionAccuracy)
    }
}

impl fmt::Display for SafetyMetric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FalsePositiveRate => write!(f, "false_positive_rate"),
            Self::FalseNegativeRate => write!(f, "false_negative_rate"),
            Self::CalibrationError => write!(f, "calibration_error"),
            Self::DriftDetectionAccuracy => write!(f, "drift_detection_accuracy"),
            Self::ContainmentTime => write!(f, "containment_time"),
        }
    }
}

/// Snapshot of safety metrics in fixed-point millionths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyMetricSnapshot {
    pub values_millionths: BTreeMap<SafetyMetric, i64>,
}

impl SafetyMetricSnapshot {
    pub fn validate(&self) -> Result<(), ContractError> {
        for metric in SafetyMetric::ALL {
            if !self.values_millionths.contains_key(metric) {
                return Err(ContractError::InvalidShadowEvaluation {
                    detail: format!("missing safety metric in snapshot: {metric}"),
                });
            }
        }
        Ok(())
    }

    pub fn metric_value(&self, metric: SafetyMetric) -> i64 {
        self.values_millionths.get(&metric).copied().unwrap_or(0)
    }
}

/// Replay inputs proving the shadow evaluation is deterministic and reproducible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowReplayReference {
    pub replay_corpus_id: String,
    pub randomness_snapshot_id: String,
    pub replay_seed_hash: [u8; 32],
    pub replay_seed_counter: u64,
}

impl ShadowReplayReference {
    fn validate(&self) -> Result<(), ContractError> {
        if self.replay_corpus_id.trim().is_empty() {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "replay_corpus_id must not be empty".to_string(),
            });
        }
        if self.randomness_snapshot_id.trim().is_empty() {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "randomness_snapshot_id must not be empty".to_string(),
            });
        }
        if self.replay_seed_hash == [0u8; 32] {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "replay_seed_hash must not be all zeros".to_string(),
            });
        }
        Ok(())
    }
}

/// Extension risk class used to select burn-in thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowExtensionClass {
    LowRisk,
    #[default]
    Standard,
    HighRisk,
    Critical,
}

impl ShadowExtensionClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::LowRisk => "low_risk",
            Self::Standard => "standard",
            Self::HighRisk => "high_risk",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for ShadowExtensionClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Burn-in thresholds required before automatic enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowBurnInThresholdProfile {
    pub min_shadow_success_rate_millionths: u64,
    pub max_false_deny_rate_millionths: u64,
    pub min_burn_in_duration_ns: u64,
    pub require_verified_rollback_artifacts: bool,
}

impl ShadowBurnInThresholdProfile {
    fn validate(&self) -> Result<(), ContractError> {
        if self.min_shadow_success_rate_millionths == 0
            || self.min_shadow_success_rate_millionths > 1_000_000
        {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "min_shadow_success_rate_millionths must be in 1..=1_000_000".to_string(),
            });
        }
        if self.max_false_deny_rate_millionths > 1_000_000 {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "max_false_deny_rate_millionths must be <= 1_000_000".to_string(),
            });
        }
        if self.min_burn_in_duration_ns == 0 {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "min_burn_in_duration_ns must be > 0".to_string(),
            });
        }
        Ok(())
    }
}

impl Default for ShadowBurnInThresholdProfile {
    fn default() -> Self {
        Self {
            min_shadow_success_rate_millionths: 995_000,
            max_false_deny_rate_millionths: 5_000,
            min_burn_in_duration_ns: 3_600_000_000_000,
            require_verified_rollback_artifacts: true,
        }
    }
}

/// Rollback artifacts that must exist before auto-enforcement is allowed.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ShadowRollbackReadinessArtifacts {
    pub rollback_command_tested: bool,
    pub previous_policy_snapshot_id: String,
    pub transition_receipt_signed: bool,
    pub rollback_playbook_ref: String,
}

impl ShadowRollbackReadinessArtifacts {
    fn validate(&self) -> Result<(), ContractError> {
        if self.previous_policy_snapshot_id.trim().is_empty() {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "previous_policy_snapshot_id must not be empty".to_string(),
            });
        }
        if self.rollback_playbook_ref.trim().is_empty() {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "rollback_playbook_ref must not be empty".to_string(),
            });
        }
        Ok(())
    }

    fn is_verified_ready(&self) -> bool {
        self.rollback_command_tested && self.transition_receipt_signed
    }
}

/// Shadow-gate configuration thresholds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowEvaluationGateConfig {
    /// Maximum tolerated regression (millionths) before hard rejection.
    pub regression_tolerance_millionths: u64,
    /// Minimum significant improvement (millionths) for at least one metric.
    pub min_required_improvement_millionths: u64,
    /// Default burn-in threshold profile.
    #[serde(default)]
    pub default_burn_in_profile: ShadowBurnInThresholdProfile,
    /// Optional per-extension-class burn-in overrides.
    #[serde(default)]
    pub burn_in_profiles_by_extension_class:
        BTreeMap<ShadowExtensionClass, ShadowBurnInThresholdProfile>,
}

impl ShadowEvaluationGateConfig {
    fn validate(&self) -> Result<(), ContractError> {
        if self.min_required_improvement_millionths == 0 {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "min_required_improvement_millionths must be > 0".to_string(),
            });
        }
        self.default_burn_in_profile.validate()?;
        for profile in self.burn_in_profiles_by_extension_class.values() {
            profile.validate()?;
        }
        Ok(())
    }

    fn burn_in_profile_for(
        &self,
        extension_class: ShadowExtensionClass,
    ) -> &ShadowBurnInThresholdProfile {
        self.burn_in_profiles_by_extension_class
            .get(&extension_class)
            .unwrap_or(&self.default_burn_in_profile)
    }
}

impl Default for ShadowEvaluationGateConfig {
    fn default() -> Self {
        let mut burn_in_profiles_by_extension_class = BTreeMap::new();
        burn_in_profiles_by_extension_class.insert(
            ShadowExtensionClass::LowRisk,
            ShadowBurnInThresholdProfile {
                min_shadow_success_rate_millionths: 990_000,
                max_false_deny_rate_millionths: 10_000,
                min_burn_in_duration_ns: 900_000_000_000,
                require_verified_rollback_artifacts: true,
            },
        );
        burn_in_profiles_by_extension_class.insert(
            ShadowExtensionClass::HighRisk,
            ShadowBurnInThresholdProfile {
                min_shadow_success_rate_millionths: 998_000,
                max_false_deny_rate_millionths: 2_500,
                min_burn_in_duration_ns: 7_200_000_000_000,
                require_verified_rollback_artifacts: true,
            },
        );
        burn_in_profiles_by_extension_class.insert(
            ShadowExtensionClass::Critical,
            ShadowBurnInThresholdProfile {
                min_shadow_success_rate_millionths: 999_000,
                max_false_deny_rate_millionths: 1_000,
                min_burn_in_duration_ns: 14_400_000_000_000,
                require_verified_rollback_artifacts: true,
            },
        );
        Self {
            regression_tolerance_millionths: 5_000,
            min_required_improvement_millionths: 2_500,
            default_burn_in_profile: ShadowBurnInThresholdProfile::default(),
            burn_in_profiles_by_extension_class,
        }
    }
}

/// Candidate model/policy update evaluated by the shadow gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowEvaluationCandidate {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    #[serde(default)]
    pub extension_class: ShadowExtensionClass,
    pub candidate_version: String,
    pub baseline_snapshot_id: String,
    pub rollback_token: String,
    pub epoch_id: SecurityEpoch,
    pub shadow_started_at_ns: u64,
    pub evaluation_completed_at_ns: u64,
    pub shadow_success_rate_millionths: u64,
    pub false_deny_rate_millionths: u64,
    #[serde(default)]
    pub rollback_readiness: ShadowRollbackReadinessArtifacts,
    pub baseline_metrics: SafetyMetricSnapshot,
    pub candidate_metrics: SafetyMetricSnapshot,
    pub replay_reference: ShadowReplayReference,
    pub epsilon_spent_millionths: i64,
    pub delta_spent_millionths: i64,
}

impl ShadowEvaluationCandidate {
    fn validate(&self) -> Result<(), ContractError> {
        if self.trace_id.trim().is_empty() {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "trace_id must not be empty".to_string(),
            });
        }
        if self.decision_id.trim().is_empty() {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "decision_id must not be empty".to_string(),
            });
        }
        if self.policy_id.trim().is_empty() {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "policy_id must not be empty".to_string(),
            });
        }
        if self.candidate_version.trim().is_empty() {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "candidate_version must not be empty".to_string(),
            });
        }
        if self.rollback_token.trim().is_empty() {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "rollback_token must not be empty".to_string(),
            });
        }
        if self.evaluation_completed_at_ns <= self.shadow_started_at_ns {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "evaluation_completed_at_ns must be > shadow_started_at_ns".to_string(),
            });
        }
        if self.shadow_success_rate_millionths > 1_000_000 {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "shadow_success_rate_millionths must be <= 1_000_000".to_string(),
            });
        }
        if self.false_deny_rate_millionths > 1_000_000 {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "false_deny_rate_millionths must be <= 1_000_000".to_string(),
            });
        }
        if self.epsilon_spent_millionths < 0 || self.delta_spent_millionths < 0 {
            return Err(ContractError::InvalidShadowEvaluation {
                detail: "budget spend values must be >= 0".to_string(),
            });
        }
        self.baseline_metrics.validate()?;
        self.candidate_metrics.validate()?;
        self.replay_reference.validate()?;
        self.rollback_readiness.validate()?;
        Ok(())
    }

    fn burn_in_duration_ns(&self) -> u64 {
        self.evaluation_completed_at_ns
            .saturating_sub(self.shadow_started_at_ns)
    }
}

/// Per-metric assessment output from the shadow gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowMetricAssessment {
    pub baseline_value_millionths: i64,
    pub candidate_value_millionths: i64,
    pub improvement_millionths: i64,
    pub regressed: bool,
    pub significant_improvement: bool,
}

/// Privacy budget status attached to a promotion decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowPrivacyBudgetStatus {
    pub epsilon_spent_millionths: i64,
    pub epsilon_limit_millionths: i64,
    pub delta_spent_millionths: i64,
    pub delta_limit_millionths: i64,
    pub within_budget: bool,
}

/// Promotion verdict emitted by the shadow gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShadowPromotionVerdict {
    Pass,
    Reject,
    OverrideApproved,
}

impl fmt::Display for ShadowPromotionVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Reject => write!(f, "reject"),
            Self::OverrideApproved => write!(f, "override_approved"),
        }
    }
}

/// Human override request for rejected promotion candidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanOverrideRequest {
    pub operator_id: String,
    pub summary: String,
    pub bypassed_risk_criteria: Vec<String>,
    pub acknowledged_bypass: bool,
}

/// Signed human override artifact attached to promotion decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanOverrideJustificationArtifact {
    pub operator_id: String,
    pub summary: String,
    pub bypassed_risk_criteria: Vec<String>,
    pub acknowledged_bypass: bool,
    pub override_hash: [u8; 32],
    pub signature: Signature,
}

impl HumanOverrideJustificationArtifact {
    fn from_request(
        request: HumanOverrideRequest,
        decision_hash: [u8; 32],
        signing_key: &SigningKey,
    ) -> Result<Self, ContractError> {
        if request.operator_id.trim().is_empty() {
            return Err(ContractError::InvalidShadowOverride {
                detail: "operator_id must not be empty".to_string(),
            });
        }
        if request.summary.trim().is_empty() {
            return Err(ContractError::InvalidShadowOverride {
                detail: "summary must not be empty".to_string(),
            });
        }
        if request.bypassed_risk_criteria.is_empty() {
            return Err(ContractError::InvalidShadowOverride {
                detail: "bypassed_risk_criteria must not be empty".to_string(),
            });
        }
        if !request.acknowledged_bypass {
            return Err(ContractError::InvalidShadowOverride {
                detail: "acknowledged_bypass must be true".to_string(),
            });
        }

        let mut map = BTreeMap::new();
        map.insert(
            "decision_hash".to_string(),
            CanonicalValue::Bytes(decision_hash.to_vec()),
        );
        map.insert(
            "operator_id".to_string(),
            CanonicalValue::String(request.operator_id.clone()),
        );
        map.insert(
            "summary".to_string(),
            CanonicalValue::String(request.summary.clone()),
        );
        map.insert(
            "acknowledged_bypass".to_string(),
            CanonicalValue::Bool(request.acknowledged_bypass),
        );
        map.insert(
            "bypassed_risk_criteria".to_string(),
            CanonicalValue::Array(
                request
                    .bypassed_risk_criteria
                    .iter()
                    .map(|criterion| CanonicalValue::String(criterion.clone()))
                    .collect(),
            ),
        );
        let unsigned = CanonicalValue::Map(map);
        let encoded = deterministic_serde::encode_value(&unsigned);
        let mut preimage =
            Vec::with_capacity(ObjectDomain::EvidenceRecord.tag().len() + 32 + encoded.len());
        preimage.extend_from_slice(ObjectDomain::EvidenceRecord.tag());
        preimage.extend_from_slice(shadow_override_schema().as_bytes());
        preimage.extend_from_slice(&encoded);
        let override_hash = hash_bytes(&preimage);
        let signature = sign_preimage(signing_key, &override_hash).map_err(|e| {
            ContractError::SignatureFailed {
                detail: format!("failed to sign human override artifact: {e}"),
            }
        })?;

        Ok(Self {
            operator_id: request.operator_id,
            summary: request.summary,
            bypassed_risk_criteria: request.bypassed_risk_criteria,
            acknowledged_bypass: request.acknowledged_bypass,
            override_hash,
            signature,
        })
    }
}

/// Signed promotion decision artifact produced by the shadow gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowPromotionDecisionArtifact {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub extension_class: ShadowExtensionClass,
    pub candidate_version: String,
    pub baseline_snapshot_id: String,
    pub rollback_token: String,
    pub epoch_id: SecurityEpoch,
    pub burn_in_duration_ns: u64,
    pub shadow_success_rate_millionths: u64,
    pub false_deny_rate_millionths: u64,
    pub rollback_readiness: ShadowRollbackReadinessArtifacts,
    pub burn_in_profile: ShadowBurnInThresholdProfile,
    pub burn_in_early_terminated: bool,
    pub replay_reference: ShadowReplayReference,
    pub metric_assessments: BTreeMap<SafetyMetric, ShadowMetricAssessment>,
    pub privacy_budget_status: ShadowPrivacyBudgetStatus,
    pub deterministic_replay_ok: bool,
    pub significant_improvement_count: usize,
    pub failure_reasons: Vec<String>,
    pub verdict: ShadowPromotionVerdict,
    pub human_override: Option<HumanOverrideJustificationArtifact>,
    pub artifact_hash: [u8; 32],
    pub signature: Signature,
}

impl ShadowPromotionDecisionArtifact {
    fn unsigned_view(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "baseline_snapshot_id".to_string(),
            CanonicalValue::String(self.baseline_snapshot_id.clone()),
        );
        map.insert(
            "candidate_version".to_string(),
            CanonicalValue::String(self.candidate_version.clone()),
        );
        map.insert(
            "extension_class".to_string(),
            CanonicalValue::String(self.extension_class.to_string()),
        );
        map.insert(
            "decision_id".to_string(),
            CanonicalValue::String(self.decision_id.clone()),
        );
        map.insert(
            "burn_in_duration_ns".to_string(),
            CanonicalValue::U64(self.burn_in_duration_ns),
        );
        map.insert(
            "shadow_success_rate_millionths".to_string(),
            CanonicalValue::U64(self.shadow_success_rate_millionths),
        );
        map.insert(
            "false_deny_rate_millionths".to_string(),
            CanonicalValue::U64(self.false_deny_rate_millionths),
        );
        map.insert(
            "burn_in_early_terminated".to_string(),
            CanonicalValue::Bool(self.burn_in_early_terminated),
        );
        map.insert(
            "burn_in_profile".to_string(),
            CanonicalValue::Map(BTreeMap::from([
                (
                    "min_shadow_success_rate_millionths".to_string(),
                    CanonicalValue::U64(self.burn_in_profile.min_shadow_success_rate_millionths),
                ),
                (
                    "max_false_deny_rate_millionths".to_string(),
                    CanonicalValue::U64(self.burn_in_profile.max_false_deny_rate_millionths),
                ),
                (
                    "min_burn_in_duration_ns".to_string(),
                    CanonicalValue::U64(self.burn_in_profile.min_burn_in_duration_ns),
                ),
                (
                    "require_verified_rollback_artifacts".to_string(),
                    CanonicalValue::Bool(self.burn_in_profile.require_verified_rollback_artifacts),
                ),
            ])),
        );
        map.insert(
            "rollback_readiness".to_string(),
            CanonicalValue::Map(BTreeMap::from([
                (
                    "rollback_command_tested".to_string(),
                    CanonicalValue::Bool(self.rollback_readiness.rollback_command_tested),
                ),
                (
                    "previous_policy_snapshot_id".to_string(),
                    CanonicalValue::String(
                        self.rollback_readiness.previous_policy_snapshot_id.clone(),
                    ),
                ),
                (
                    "transition_receipt_signed".to_string(),
                    CanonicalValue::Bool(self.rollback_readiness.transition_receipt_signed),
                ),
                (
                    "rollback_playbook_ref".to_string(),
                    CanonicalValue::String(self.rollback_readiness.rollback_playbook_ref.clone()),
                ),
            ])),
        );
        map.insert(
            "deterministic_replay_ok".to_string(),
            CanonicalValue::Bool(self.deterministic_replay_ok),
        );
        map.insert(
            "epoch_id".to_string(),
            CanonicalValue::U64(self.epoch_id.as_u64()),
        );
        map.insert(
            "failure_reasons".to_string(),
            CanonicalValue::Array(
                self.failure_reasons
                    .iter()
                    .map(|reason| CanonicalValue::String(reason.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "policy_id".to_string(),
            CanonicalValue::String(self.policy_id.clone()),
        );
        map.insert(
            "privacy_budget_status".to_string(),
            CanonicalValue::Map(BTreeMap::from([
                (
                    "epsilon_limit_millionths".to_string(),
                    CanonicalValue::I64(self.privacy_budget_status.epsilon_limit_millionths),
                ),
                (
                    "epsilon_spent_millionths".to_string(),
                    CanonicalValue::I64(self.privacy_budget_status.epsilon_spent_millionths),
                ),
                (
                    "delta_limit_millionths".to_string(),
                    CanonicalValue::I64(self.privacy_budget_status.delta_limit_millionths),
                ),
                (
                    "delta_spent_millionths".to_string(),
                    CanonicalValue::I64(self.privacy_budget_status.delta_spent_millionths),
                ),
                (
                    "within_budget".to_string(),
                    CanonicalValue::Bool(self.privacy_budget_status.within_budget),
                ),
            ])),
        );
        map.insert(
            "replay_reference".to_string(),
            CanonicalValue::Map(BTreeMap::from([
                (
                    "replay_corpus_id".to_string(),
                    CanonicalValue::String(self.replay_reference.replay_corpus_id.clone()),
                ),
                (
                    "randomness_snapshot_id".to_string(),
                    CanonicalValue::String(self.replay_reference.randomness_snapshot_id.clone()),
                ),
                (
                    "replay_seed_hash".to_string(),
                    CanonicalValue::Bytes(self.replay_reference.replay_seed_hash.to_vec()),
                ),
                (
                    "replay_seed_counter".to_string(),
                    CanonicalValue::U64(self.replay_reference.replay_seed_counter),
                ),
            ])),
        );
        map.insert(
            "rollback_token".to_string(),
            CanonicalValue::String(self.rollback_token.clone()),
        );
        map.insert(
            "significant_improvement_count".to_string(),
            CanonicalValue::U64(self.significant_improvement_count as u64),
        );
        map.insert(
            "trace_id".to_string(),
            CanonicalValue::String(self.trace_id.clone()),
        );
        map.insert(
            "verdict".to_string(),
            CanonicalValue::String(self.verdict.to_string()),
        );
        map.insert(
            "metric_assessments".to_string(),
            CanonicalValue::Map(
                self.metric_assessments
                    .iter()
                    .map(|(metric, assessment)| {
                        (
                            metric.to_string(),
                            CanonicalValue::Map(BTreeMap::from([
                                (
                                    "baseline_value_millionths".to_string(),
                                    CanonicalValue::I64(assessment.baseline_value_millionths),
                                ),
                                (
                                    "candidate_value_millionths".to_string(),
                                    CanonicalValue::I64(assessment.candidate_value_millionths),
                                ),
                                (
                                    "improvement_millionths".to_string(),
                                    CanonicalValue::I64(assessment.improvement_millionths),
                                ),
                                (
                                    "regressed".to_string(),
                                    CanonicalValue::Bool(assessment.regressed),
                                ),
                                (
                                    "significant_improvement".to_string(),
                                    CanonicalValue::Bool(assessment.significant_improvement),
                                ),
                            ])),
                        )
                    })
                    .collect(),
            ),
        );
        map.insert(
            "human_override".to_string(),
            match &self.human_override {
                Some(override_artifact) => CanonicalValue::Map(BTreeMap::from([
                    (
                        "operator_id".to_string(),
                        CanonicalValue::String(override_artifact.operator_id.clone()),
                    ),
                    (
                        "summary".to_string(),
                        CanonicalValue::String(override_artifact.summary.clone()),
                    ),
                    (
                        "acknowledged_bypass".to_string(),
                        CanonicalValue::Bool(override_artifact.acknowledged_bypass),
                    ),
                    (
                        "bypassed_risk_criteria".to_string(),
                        CanonicalValue::Array(
                            override_artifact
                                .bypassed_risk_criteria
                                .iter()
                                .map(|criterion| CanonicalValue::String(criterion.clone()))
                                .collect(),
                        ),
                    ),
                    (
                        "override_hash".to_string(),
                        CanonicalValue::Bytes(override_artifact.override_hash.to_vec()),
                    ),
                ])),
                None => CanonicalValue::Null,
            },
        );
        CanonicalValue::Map(map)
    }

    fn refresh_signature(&mut self, signing_key: &SigningKey) -> Result<(), ContractError> {
        let value = self.unsigned_view();
        let encoded = deterministic_serde::encode_value(&value);
        let mut preimage =
            Vec::with_capacity(ObjectDomain::EvidenceRecord.tag().len() + 32 + encoded.len());
        preimage.extend_from_slice(ObjectDomain::EvidenceRecord.tag());
        preimage.extend_from_slice(shadow_promotion_schema().as_bytes());
        preimage.extend_from_slice(&encoded);
        self.artifact_hash = hash_bytes(&preimage);
        self.signature = sign_preimage(signing_key, &self.artifact_hash).map_err(|e| {
            ContractError::SignatureFailed {
                detail: format!("failed to sign shadow promotion decision: {e}"),
            }
        })?;
        Ok(())
    }
}

/// Governance-ready summary row for benchmark bundles and scorecards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowBurnInScorecardEntry {
    pub policy_id: String,
    pub candidate_version: String,
    pub extension_class: ShadowExtensionClass,
    pub verdict: ShadowPromotionVerdict,
    pub shadow_success_rate_millionths: u64,
    pub false_deny_rate_millionths: u64,
    pub burn_in_duration_ns: u64,
    pub rollback_ready: bool,
    pub burn_in_early_terminated: bool,
}

impl ShadowPromotionDecisionArtifact {
    pub fn to_scorecard_entry(&self) -> ShadowBurnInScorecardEntry {
        ShadowBurnInScorecardEntry {
            policy_id: self.policy_id.clone(),
            candidate_version: self.candidate_version.clone(),
            extension_class: self.extension_class,
            verdict: self.verdict,
            shadow_success_rate_millionths: self.shadow_success_rate_millionths,
            false_deny_rate_millionths: self.false_deny_rate_millionths,
            burn_in_duration_ns: self.burn_in_duration_ns,
            rollback_ready: self.rollback_readiness.is_verified_ready(),
            burn_in_early_terminated: self.burn_in_early_terminated,
        }
    }
}

/// Incident receipt emitted when automatic rollback is triggered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowRollbackIncidentReceipt {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub candidate_version: String,
    pub rollback_token: String,
    pub triggered_regressions: Vec<SafetyMetric>,
    pub reason: String,
    pub receipt_hash: [u8; 32],
    pub signature: Signature,
}

impl ShadowRollbackIncidentReceipt {
    fn sign(&mut self, signing_key: &SigningKey) -> Result<(), ContractError> {
        let mut map = BTreeMap::new();
        map.insert(
            "trace_id".to_string(),
            CanonicalValue::String(self.trace_id.clone()),
        );
        map.insert(
            "decision_id".to_string(),
            CanonicalValue::String(self.decision_id.clone()),
        );
        map.insert(
            "policy_id".to_string(),
            CanonicalValue::String(self.policy_id.clone()),
        );
        map.insert(
            "candidate_version".to_string(),
            CanonicalValue::String(self.candidate_version.clone()),
        );
        map.insert(
            "rollback_token".to_string(),
            CanonicalValue::String(self.rollback_token.clone()),
        );
        map.insert(
            "reason".to_string(),
            CanonicalValue::String(self.reason.clone()),
        );
        map.insert(
            "triggered_regressions".to_string(),
            CanonicalValue::Array(
                self.triggered_regressions
                    .iter()
                    .map(|metric| CanonicalValue::String(metric.to_string()))
                    .collect(),
            ),
        );
        let encoded = deterministic_serde::encode_value(&CanonicalValue::Map(map));
        let mut preimage =
            Vec::with_capacity(ObjectDomain::EvidenceRecord.tag().len() + 32 + encoded.len());
        preimage.extend_from_slice(ObjectDomain::EvidenceRecord.tag());
        preimage.extend_from_slice(shadow_rollback_receipt_schema().as_bytes());
        preimage.extend_from_slice(&encoded);
        self.receipt_hash = hash_bytes(&preimage);
        self.signature = sign_preimage(signing_key, &self.receipt_hash).map_err(|e| {
            ContractError::SignatureFailed {
                detail: format!("failed to sign rollback receipt: {e}"),
            }
        })?;
        Ok(())
    }
}

/// Structured gate event with stable fields for operational telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowGateEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Deterministic shadow-evaluation gate for policy/model promotions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowEvaluationGate {
    pub config: ShadowEvaluationGateConfig,
    events: Vec<ShadowGateEvent>,
    evaluated_artifacts: Vec<ShadowPromotionDecisionArtifact>,
    promoted_artifacts: BTreeMap<String, ShadowPromotionDecisionArtifact>,
}

impl ShadowEvaluationGate {
    pub fn new(config: ShadowEvaluationGateConfig) -> Result<Self, ContractError> {
        config.validate()?;
        Ok(Self {
            config,
            events: Vec::new(),
            evaluated_artifacts: Vec::new(),
            promoted_artifacts: BTreeMap::new(),
        })
    }

    pub fn events(&self) -> &[ShadowGateEvent] {
        &self.events
    }

    pub fn drain_events(&mut self) -> Vec<ShadowGateEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn active_artifact(&self, policy_id: &str) -> Option<&ShadowPromotionDecisionArtifact> {
        self.promoted_artifacts.get(policy_id)
    }

    pub fn scorecard_entries(&self) -> Vec<ShadowBurnInScorecardEntry> {
        self.evaluated_artifacts
            .iter()
            .map(ShadowPromotionDecisionArtifact::to_scorecard_entry)
            .collect()
    }

    pub fn evaluate_candidate(
        &mut self,
        contract: &PrivacyLearningContract,
        candidate: ShadowEvaluationCandidate,
        signing_key: &SigningKey,
    ) -> Result<ShadowPromotionDecisionArtifact, ContractError> {
        if let Err(err) = candidate.validate() {
            self.emit_event(
                &candidate.trace_id,
                &candidate.decision_id,
                &candidate.policy_id,
                "shadow_evaluation",
                "error",
                Some("FE-PLC-SHADOW-0001"),
            );
            return Err(err);
        }

        self.emit_event(
            &candidate.trace_id,
            &candidate.decision_id,
            &candidate.policy_id,
            "shadow_start",
            "started",
            None,
        );

        let burn_in_profile = self
            .config
            .burn_in_profile_for(candidate.extension_class)
            .clone();
        let burn_in_duration_ns = candidate.burn_in_duration_ns();
        let rollback_ready = candidate.rollback_readiness.is_verified_ready();

        let mut metric_assessments = BTreeMap::new();
        let mut regression_metrics = Vec::new();
        let mut significant_improvement_count = 0usize;

        for metric in SafetyMetric::ALL {
            let baseline = candidate.baseline_metrics.metric_value(*metric);
            let observed = candidate.candidate_metrics.metric_value(*metric);
            let improvement = if metric.higher_is_better() {
                observed - baseline
            } else {
                baseline - observed
            };
            let regressed = improvement < -(self.config.regression_tolerance_millionths as i64);
            let significant = improvement >= self.config.min_required_improvement_millionths as i64;
            if regressed {
                regression_metrics.push(*metric);
            }
            if significant {
                significant_improvement_count += 1;
            }
            metric_assessments.insert(
                *metric,
                ShadowMetricAssessment {
                    baseline_value_millionths: baseline,
                    candidate_value_millionths: observed,
                    improvement_millionths: improvement,
                    regressed,
                    significant_improvement: significant,
                },
            );
        }

        let budget_status = ShadowPrivacyBudgetStatus {
            epsilon_spent_millionths: candidate.epsilon_spent_millionths,
            epsilon_limit_millionths: contract.dp_budget.epsilon_per_epoch_millionths,
            delta_spent_millionths: candidate.delta_spent_millionths,
            delta_limit_millionths: contract.dp_budget.delta_per_epoch_millionths,
            within_budget: candidate.epsilon_spent_millionths
                <= contract.dp_budget.epsilon_per_epoch_millionths
                && candidate.delta_spent_millionths
                    <= contract.dp_budget.delta_per_epoch_millionths,
        };

        let deterministic_replay_ok = candidate.replay_reference.replay_seed_hash != [0u8; 32]
            && !candidate
                .replay_reference
                .replay_corpus_id
                .trim()
                .is_empty()
            && !candidate
                .replay_reference
                .randomness_snapshot_id
                .trim()
                .is_empty();

        let mut failure_reasons = Vec::new();
        let mut error_code: Option<&str> = None;
        let mut burn_in_early_terminated = false;

        if !budget_status.within_budget {
            failure_reasons.push("privacy budget exceeded for epoch".to_string());
            error_code.get_or_insert("FE-PLC-SHADOW-0002");
        }
        if !regression_metrics.is_empty() {
            failure_reasons.push(format!(
                "safety metric regression beyond tolerance: {}",
                regression_metrics
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            error_code.get_or_insert("FE-PLC-SHADOW-0004");
        }
        if significant_improvement_count == 0 {
            failure_reasons.push("no significant safety metric improvement".to_string());
            error_code.get_or_insert("FE-PLC-SHADOW-0005");
        }
        if !deterministic_replay_ok {
            failure_reasons.push("replay determinism inputs are incomplete or invalid".to_string());
            error_code.get_or_insert("FE-PLC-SHADOW-0003");
        }
        if burn_in_duration_ns < burn_in_profile.min_burn_in_duration_ns {
            failure_reasons.push(format!(
                "burn-in duration {}ns below required {}ns",
                burn_in_duration_ns, burn_in_profile.min_burn_in_duration_ns
            ));
            error_code.get_or_insert("FE-PLC-SHADOW-0008");
        }
        if candidate.shadow_success_rate_millionths
            < burn_in_profile.min_shadow_success_rate_millionths
        {
            failure_reasons.push(format!(
                "shadow success rate {} below required {}",
                candidate.shadow_success_rate_millionths,
                burn_in_profile.min_shadow_success_rate_millionths
            ));
            error_code.get_or_insert("FE-PLC-SHADOW-0009");
        }
        if candidate.false_deny_rate_millionths > burn_in_profile.max_false_deny_rate_millionths {
            failure_reasons.push(format!(
                "false-deny rate {} exceeds threshold {}",
                candidate.false_deny_rate_millionths,
                burn_in_profile.max_false_deny_rate_millionths
            ));
            burn_in_early_terminated = true;
            error_code.get_or_insert("FE-PLC-SHADOW-0010");
        }
        if burn_in_profile.require_verified_rollback_artifacts && !rollback_ready {
            failure_reasons
                .push("rollback readiness artifacts are incomplete or unverified".to_string());
            error_code.get_or_insert("FE-PLC-SHADOW-0011");
        }

        let verdict = if failure_reasons.is_empty() {
            ShadowPromotionVerdict::Pass
        } else {
            ShadowPromotionVerdict::Reject
        };

        let mut artifact = ShadowPromotionDecisionArtifact {
            trace_id: candidate.trace_id.clone(),
            decision_id: candidate.decision_id.clone(),
            policy_id: candidate.policy_id.clone(),
            extension_class: candidate.extension_class,
            candidate_version: candidate.candidate_version.clone(),
            baseline_snapshot_id: candidate.baseline_snapshot_id.clone(),
            rollback_token: candidate.rollback_token.clone(),
            epoch_id: candidate.epoch_id,
            burn_in_duration_ns,
            shadow_success_rate_millionths: candidate.shadow_success_rate_millionths,
            false_deny_rate_millionths: candidate.false_deny_rate_millionths,
            rollback_readiness: candidate.rollback_readiness.clone(),
            burn_in_profile,
            burn_in_early_terminated,
            replay_reference: candidate.replay_reference.clone(),
            metric_assessments,
            privacy_budget_status: budget_status,
            deterministic_replay_ok,
            significant_improvement_count,
            failure_reasons,
            verdict,
            human_override: None,
            artifact_hash: [0u8; 32],
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        artifact.refresh_signature(signing_key)?;

        let evaluation_outcome = if verdict == ShadowPromotionVerdict::Pass {
            "pass"
        } else if burn_in_early_terminated {
            "early_terminated"
        } else {
            "reject"
        };
        self.emit_event(
            &artifact.trace_id,
            &artifact.decision_id,
            &artifact.policy_id,
            "shadow_evaluation",
            evaluation_outcome,
            error_code,
        );

        if verdict == ShadowPromotionVerdict::Pass {
            self.emit_event(
                &artifact.trace_id,
                &artifact.decision_id,
                &artifact.policy_id,
                "promotion_gate",
                "pass",
                None,
            );
            self.promoted_artifacts
                .insert(artifact.policy_id.clone(), artifact.clone());
            self.emit_event(
                &artifact.trace_id,
                &artifact.decision_id,
                &artifact.policy_id,
                "auto_enforcement",
                "promoted",
                None,
            );
        } else {
            self.emit_event(
                &artifact.trace_id,
                &artifact.decision_id,
                &artifact.policy_id,
                "promotion_gate",
                "reject",
                error_code,
            );
            self.emit_event(
                &artifact.trace_id,
                &artifact.decision_id,
                &artifact.policy_id,
                "rejection",
                "rejected",
                error_code,
            );
        }

        self.evaluated_artifacts.push(artifact.clone());

        Ok(artifact)
    }

    pub fn apply_human_override(
        &mut self,
        artifact: &ShadowPromotionDecisionArtifact,
        request: HumanOverrideRequest,
        signing_key: &SigningKey,
    ) -> Result<ShadowPromotionDecisionArtifact, ContractError> {
        let override_artifact = HumanOverrideJustificationArtifact::from_request(
            request,
            artifact.artifact_hash,
            signing_key,
        )
        .inspect_err(|_| {
            self.emit_event(
                &artifact.trace_id,
                &artifact.decision_id,
                &artifact.policy_id,
                "human_override",
                "reject",
                Some("FE-PLC-SHADOW-0006"),
            );
        })?;

        let mut updated = artifact.clone();
        updated.verdict = ShadowPromotionVerdict::OverrideApproved;
        updated.human_override = Some(override_artifact);
        updated
            .failure_reasons
            .push("human override approved with signed justification".to_string());
        updated.refresh_signature(signing_key)?;

        self.promoted_artifacts
            .insert(updated.policy_id.clone(), updated.clone());
        self.emit_event(
            &updated.trace_id,
            &updated.decision_id,
            &updated.policy_id,
            "human_override",
            "override_approved",
            None,
        );

        Ok(updated)
    }

    pub fn evaluate_post_deployment_metrics(
        &mut self,
        artifact: &ShadowPromotionDecisionArtifact,
        post_metrics: SafetyMetricSnapshot,
        signing_key: &SigningKey,
    ) -> Result<Option<ShadowRollbackIncidentReceipt>, ContractError> {
        post_metrics.validate()?;

        let mut regressions = Vec::new();
        for metric in SafetyMetric::ALL {
            let baseline = artifact
                .metric_assessments
                .get(metric)
                .map(|assessment| assessment.candidate_value_millionths)
                .unwrap_or(0);
            let observed = post_metrics.metric_value(*metric);
            let improvement = if metric.higher_is_better() {
                observed - baseline
            } else {
                baseline - observed
            };
            if improvement < -(self.config.regression_tolerance_millionths as i64) {
                regressions.push(*metric);
            }
        }

        if regressions.is_empty() {
            self.emit_event(
                &artifact.trace_id,
                &artifact.decision_id,
                &artifact.policy_id,
                "post_deployment_guard",
                "pass",
                None,
            );
            return Ok(None);
        }

        let reason = format!(
            "automatic rollback triggered due to post-deployment regressions: {}",
            regressions
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
        let mut receipt = ShadowRollbackIncidentReceipt {
            trace_id: artifact.trace_id.clone(),
            decision_id: artifact.decision_id.clone(),
            policy_id: artifact.policy_id.clone(),
            candidate_version: artifact.candidate_version.clone(),
            rollback_token: artifact.rollback_token.clone(),
            triggered_regressions: regressions,
            reason,
            receipt_hash: [0u8; 32],
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        receipt.sign(signing_key)?;

        self.promoted_artifacts.remove(&artifact.policy_id);
        self.emit_event(
            &receipt.trace_id,
            &receipt.decision_id,
            &receipt.policy_id,
            "automatic_rollback",
            "rollback_triggered",
            Some("FE-PLC-SHADOW-0007"),
        );

        Ok(Some(receipt))
    }

    fn emit_event(
        &mut self,
        trace_id: &str,
        decision_id: &str,
        policy_id: &str,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
    ) {
        self.events.push(ShadowGateEvent {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_string(),
            component: "shadow_evaluation_gate".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(str::to_string),
        });
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors from privacy-learning contract operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractError {
    EmptyFeatureSchema,
    InvalidVersion {
        detail: String,
    },
    FieldNameMismatch {
        key: String,
        field_name: String,
    },
    BackwardCompatibilityViolation {
        detail: String,
    },
    InvalidUpdatePolicy {
        detail: String,
    },
    InvalidClippingStrategy {
        detail: String,
    },
    InvalidDpBudget {
        detail: String,
    },
    InvalidAggregation {
        detail: String,
    },
    InvalidRetention {
        detail: String,
    },
    InvalidRandomnessTranscript {
        detail: String,
    },
    MissingSeedEscrow {
        phase_id: String,
        epoch_id: SecurityEpoch,
    },
    SeedEscrowAccessDenied {
        principal: String,
        phase_id: String,
    },
    SeedHashMismatch {
        phase_id: String,
    },
    NoAuthorizedParticipants,
    IdDerivationFailed {
        detail: String,
    },
    SignatureFailed {
        detail: String,
    },
    SignatureInvalid {
        detail: String,
    },
    DuplicateContract {
        contract_id: EngineObjectId,
    },
    NotFound {
        contract_id: EngineObjectId,
    },
    EpochNotAdvanced {
        zone: String,
        existing_epoch: SecurityEpoch,
        new_epoch: SecurityEpoch,
    },
    InvalidShadowEvaluation {
        detail: String,
    },
    InvalidShadowOverride {
        detail: String,
    },
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyFeatureSchema => write!(f, "feature schema has no fields"),
            Self::InvalidVersion { detail } => write!(f, "invalid version: {detail}"),
            Self::FieldNameMismatch { key, field_name } => {
                write!(f, "field name mismatch: key={key}, field.name={field_name}")
            }
            Self::BackwardCompatibilityViolation { detail } => {
                write!(f, "backward compatibility violation: {detail}")
            }
            Self::InvalidUpdatePolicy { detail } => {
                write!(f, "invalid update policy: {detail}")
            }
            Self::InvalidClippingStrategy { detail } => {
                write!(f, "invalid clipping strategy: {detail}")
            }
            Self::InvalidDpBudget { detail } => write!(f, "invalid DP budget: {detail}"),
            Self::InvalidAggregation { detail } => {
                write!(f, "invalid aggregation: {detail}")
            }
            Self::InvalidRetention { detail } => write!(f, "invalid retention: {detail}"),
            Self::InvalidRandomnessTranscript { detail } => {
                write!(f, "invalid randomness transcript: {detail}")
            }
            Self::MissingSeedEscrow { phase_id, epoch_id } => write!(
                f,
                "missing seed escrow record for phase {phase_id} in epoch {epoch_id}"
            ),
            Self::SeedEscrowAccessDenied {
                principal,
                phase_id,
            } => write!(
                f,
                "seed escrow access denied for principal {principal} on phase {phase_id}"
            ),
            Self::SeedHashMismatch { phase_id } => {
                write!(f, "seed hash mismatch for phase {phase_id}")
            }
            Self::NoAuthorizedParticipants => write!(f, "no authorized participants"),
            Self::IdDerivationFailed { detail } => write!(f, "id derivation failed: {detail}"),
            Self::SignatureFailed { detail } => write!(f, "signature failed: {detail}"),
            Self::SignatureInvalid { detail } => write!(f, "signature invalid: {detail}"),
            Self::DuplicateContract { contract_id } => {
                write!(f, "duplicate contract: {contract_id}")
            }
            Self::NotFound { contract_id } => write!(f, "contract not found: {contract_id}"),
            Self::EpochNotAdvanced {
                zone,
                existing_epoch,
                new_epoch,
            } => write!(
                f,
                "epoch not advanced for zone {zone}: existing={existing_epoch}, new={new_epoch}"
            ),
            Self::InvalidShadowEvaluation { detail } => {
                write!(f, "invalid shadow evaluation: {detail}")
            }
            Self::InvalidShadowOverride { detail } => {
                write!(f, "invalid shadow override: {detail}")
            }
        }
    }
}

impl std::error::Error for ContractError {}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractEventType {
    Registered {
        contract_id: EngineObjectId,
        zone: String,
        epoch: SecurityEpoch,
    },
    Revoked {
        contract_id: EngineObjectId,
        zone: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractEvent {
    pub event_type: ContractEventType,
    pub trace_id: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ZONE: &str = "test-zone";

    fn governance_signing_key() -> SigningKey {
        SigningKey::from_bytes([0x01; 32])
    }

    fn governance_vk() -> VerificationKey {
        governance_signing_key().verification_key()
    }

    fn test_participant_ids() -> BTreeSet<EngineObjectId> {
        let mut set = BTreeSet::new();
        set.insert(EngineObjectId([0xAA; 32]));
        set.insert(EngineObjectId([0xBB; 32]));
        set.insert(EngineObjectId([0xCC; 32]));
        set
    }

    fn test_feature_schema() -> FeatureSchema {
        let mut fields = BTreeMap::new();
        fields.insert(
            "calibration_residual".to_string(),
            FeatureField {
                name: "calibration_residual".to_string(),
                field_type: FeatureFieldType::FixedPoint,
                description: "Residual from local calibration model".to_string(),
                existed_in_prior_version: false,
            },
        );
        fields.insert(
            "drift_indicator".to_string(),
            FeatureField {
                name: "drift_indicator".to_string(),
                field_type: FeatureFieldType::FixedPoint,
                description: "Distribution drift signal".to_string(),
                existed_in_prior_version: false,
            },
        );
        fields.insert(
            "false_positive_count".to_string(),
            FeatureField {
                name: "false_positive_count".to_string(),
                field_type: FeatureFieldType::Counter,
                description: "Number of false positive detections".to_string(),
                existed_in_prior_version: false,
            },
        );
        FeatureSchema {
            version: 1,
            fields,
            prior_version: None,
        }
    }

    fn test_update_policy() -> UpdatePolicy {
        UpdatePolicy {
            min_local_samples: 100,
            min_submission_interval: 3600,
            max_data_age: 86400,
            allow_skip: true,
            max_consecutive_skips: 3,
        }
    }

    fn test_clipping_strategy() -> ClippingStrategy {
        ClippingStrategy {
            method: ClippingMethod::L2Norm,
            global_bound_millionths: 1_000_000, // 1.0
            per_field_bounds: BTreeMap::new(),
        }
    }

    fn test_dp_budget() -> DpBudgetSemantics {
        DpBudgetSemantics {
            epsilon_per_epoch_millionths: 100_000, // 0.1
            delta_per_epoch_millionths: 1_000,     // 0.000001
            composition_method: CompositionMethod::Renyi,
            lifetime_epsilon_budget_millionths: 10_000_000, // 10.0
            lifetime_delta_budget_millionths: 100_000,      // 0.0001
            fail_closed_on_exhaustion: true,
        }
    }

    fn test_aggregation() -> SecureAggregationRequirements {
        SecureAggregationRequirements {
            min_participants: 10,
            dropout_tolerance_millionths: 200_000, // 20%
            secret_sharing_scheme: SecretSharingScheme::Additive,
            sharing_threshold: None,
            coordinator_trust_model: CoordinatorTrustModel::HonestButCurious,
        }
    }

    fn test_retention() -> DataRetentionPolicy {
        DataRetentionPolicy {
            max_intermediate_retention: 86400,
            max_snapshot_retention: 604800,
            delete_local_after_submission: true,
            delete_shares_after_aggregation: true,
        }
    }

    fn test_contract_input() -> CreateContractInput<'static> {
        CreateContractInput {
            epoch: SecurityEpoch::from_raw(1),
            zone: TEST_ZONE,
            feature_schema: test_feature_schema(),
            update_policy: test_update_policy(),
            clipping_strategy: test_clipping_strategy(),
            dp_budget: test_dp_budget(),
            aggregation: test_aggregation(),
            retention: test_retention(),
            authorized_participants: test_participant_ids(),
        }
    }

    fn create_test_contract() -> PrivacyLearningContract {
        PrivacyLearningContract::create_signed(&governance_signing_key(), test_contract_input())
            .expect("create test contract")
    }

    fn evidence_id(byte: u8) -> EngineObjectId {
        EngineObjectId([byte; 32])
    }

    fn baseline_metrics() -> SafetyMetricSnapshot {
        SafetyMetricSnapshot {
            values_millionths: BTreeMap::from([
                (SafetyMetric::FalsePositiveRate, 120_000),
                (SafetyMetric::FalseNegativeRate, 90_000),
                (SafetyMetric::CalibrationError, 70_000),
                (SafetyMetric::DriftDetectionAccuracy, 760_000),
                (SafetyMetric::ContainmentTime, 500_000),
            ]),
        }
    }

    fn improved_metrics() -> SafetyMetricSnapshot {
        SafetyMetricSnapshot {
            values_millionths: BTreeMap::from([
                (SafetyMetric::FalsePositiveRate, 115_000),
                (SafetyMetric::FalseNegativeRate, 88_000),
                (SafetyMetric::CalibrationError, 68_000),
                (SafetyMetric::DriftDetectionAccuracy, 780_000),
                (SafetyMetric::ContainmentTime, 495_000),
            ]),
        }
    }

    fn regressed_metrics() -> SafetyMetricSnapshot {
        SafetyMetricSnapshot {
            values_millionths: BTreeMap::from([
                (SafetyMetric::FalsePositiveRate, 145_000),
                (SafetyMetric::FalseNegativeRate, 95_000),
                (SafetyMetric::CalibrationError, 75_000),
                (SafetyMetric::DriftDetectionAccuracy, 740_000),
                (SafetyMetric::ContainmentTime, 520_000),
            ]),
        }
    }

    fn replay_reference() -> ShadowReplayReference {
        ShadowReplayReference {
            replay_corpus_id: "corpus-2026-02".to_string(),
            randomness_snapshot_id: "rng-snapshot-7".to_string(),
            replay_seed_hash: [0x5A; 32],
            replay_seed_counter: 42,
        }
    }

    fn rollback_readiness() -> ShadowRollbackReadinessArtifacts {
        ShadowRollbackReadinessArtifacts {
            rollback_command_tested: true,
            previous_policy_snapshot_id: "snapshot-2026-02-19".to_string(),
            transition_receipt_signed: true,
            rollback_playbook_ref: "playbook://shadow-gate/rollback-v1".to_string(),
        }
    }

    fn candidate_with_metrics(
        candidate_metrics: SafetyMetricSnapshot,
        epsilon_spent_millionths: i64,
        delta_spent_millionths: i64,
    ) -> ShadowEvaluationCandidate {
        ShadowEvaluationCandidate {
            trace_id: "trace-shadow-1".to_string(),
            decision_id: "decision-shadow-1".to_string(),
            policy_id: "policy-shadow-1".to_string(),
            extension_class: ShadowExtensionClass::Standard,
            candidate_version: "v2026.02.20".to_string(),
            baseline_snapshot_id: "snapshot-2026-02-19".to_string(),
            rollback_token: "rollback-token-shadow-1".to_string(),
            epoch_id: SecurityEpoch::from_raw(9),
            shadow_started_at_ns: 1_000_000_000,
            evaluation_completed_at_ns: 1_000_000_120,
            shadow_success_rate_millionths: 997_000,
            false_deny_rate_millionths: 4_000,
            rollback_readiness: rollback_readiness(),
            baseline_metrics: baseline_metrics(),
            candidate_metrics,
            replay_reference: replay_reference(),
            epsilon_spent_millionths,
            delta_spent_millionths,
        }
    }

    fn shadow_gate() -> ShadowEvaluationGate {
        ShadowEvaluationGate::new(ShadowEvaluationGateConfig {
            regression_tolerance_millionths: 5_000,
            min_required_improvement_millionths: 2_500,
            default_burn_in_profile: ShadowBurnInThresholdProfile {
                min_shadow_success_rate_millionths: 995_000,
                max_false_deny_rate_millionths: 5_000,
                min_burn_in_duration_ns: 100,
                require_verified_rollback_artifacts: true,
            },
            burn_in_profiles_by_extension_class: BTreeMap::new(),
        })
        .expect("shadow gate")
    }

    // -------------------------------------------------------------------
    // Feature schema tests
    // -------------------------------------------------------------------

    #[test]
    fn feature_schema_valid() {
        let schema = test_feature_schema();
        schema.validate().expect("valid schema");
    }

    #[test]
    fn feature_schema_empty_rejected() {
        let schema = FeatureSchema {
            version: 1,
            fields: BTreeMap::new(),
            prior_version: None,
        };
        assert!(matches!(
            schema.validate(),
            Err(ContractError::EmptyFeatureSchema)
        ));
    }

    #[test]
    fn feature_schema_version_zero_rejected() {
        let mut schema = test_feature_schema();
        schema.version = 0;
        assert!(matches!(
            schema.validate(),
            Err(ContractError::InvalidVersion { .. })
        ));
    }

    #[test]
    fn feature_schema_name_mismatch_rejected() {
        let mut schema = test_feature_schema();
        schema.fields.insert(
            "wrong_key".to_string(),
            FeatureField {
                name: "actual_name".to_string(),
                field_type: FeatureFieldType::Counter,
                description: "test".to_string(),
                existed_in_prior_version: false,
            },
        );
        assert!(matches!(
            schema.validate(),
            Err(ContractError::FieldNameMismatch { .. })
        ));
    }

    #[test]
    fn feature_schema_backward_compatible() {
        let v1 = test_feature_schema();
        let mut v2_fields = v1.fields.clone();
        for field in v2_fields.values_mut() {
            field.existed_in_prior_version = true;
        }
        v2_fields.insert(
            "new_field".to_string(),
            FeatureField {
                name: "new_field".to_string(),
                field_type: FeatureFieldType::Boolean,
                description: "New feature flag".to_string(),
                existed_in_prior_version: false,
            },
        );
        let v2 = FeatureSchema {
            version: 2,
            fields: v2_fields,
            prior_version: Some(1),
        };
        v2.validate().expect("valid v2");
        assert!(v2.is_backward_compatible_with(&v1));
    }

    #[test]
    fn feature_schema_not_backward_compatible_type_change() {
        let v1 = test_feature_schema();
        let mut v2_fields = v1.fields.clone();
        // Change type of an existing field.
        if let Some(field) = v2_fields.get_mut("calibration_residual") {
            field.field_type = FeatureFieldType::Counter; // was FixedPoint
            field.existed_in_prior_version = true;
        }
        let v2 = FeatureSchema {
            version: 2,
            fields: v2_fields,
            prior_version: Some(1),
        };
        assert!(!v2.is_backward_compatible_with(&v1));
    }

    #[test]
    fn feature_schema_not_backward_compatible_field_removed() {
        let v1 = test_feature_schema();
        let mut v2_fields = BTreeMap::new();
        // Only keep one field from v1.
        if let Some(field) = v1.fields.get("calibration_residual") {
            let mut f = field.clone();
            f.existed_in_prior_version = true;
            v2_fields.insert(f.name.clone(), f);
        }
        let v2 = FeatureSchema {
            version: 2,
            fields: v2_fields,
            prior_version: Some(1),
        };
        assert!(!v2.is_backward_compatible_with(&v1));
    }

    #[test]
    fn feature_schema_prior_version_must_retain_fields() {
        let mut schema = test_feature_schema();
        schema.version = 2;
        schema.prior_version = Some(1);
        // All fields marked as new (not prior) — violates rule.
        assert!(matches!(
            schema.validate(),
            Err(ContractError::BackwardCompatibilityViolation { .. })
        ));
    }

    #[test]
    fn feature_schema_version_must_exceed_prior() {
        let mut schema = test_feature_schema();
        schema.prior_version = Some(1); // same as version
        for field in schema.fields.values_mut() {
            field.existed_in_prior_version = true;
        }
        assert!(matches!(
            schema.validate(),
            Err(ContractError::InvalidVersion { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Update policy tests
    // -------------------------------------------------------------------

    #[test]
    fn update_policy_valid() {
        test_update_policy().validate().expect("valid");
    }

    #[test]
    fn update_policy_zero_samples_rejected() {
        let mut policy = test_update_policy();
        policy.min_local_samples = 0;
        assert!(matches!(
            policy.validate(),
            Err(ContractError::InvalidUpdatePolicy { .. })
        ));
    }

    #[test]
    fn update_policy_zero_interval_rejected() {
        let mut policy = test_update_policy();
        policy.min_submission_interval = 0;
        assert!(matches!(
            policy.validate(),
            Err(ContractError::InvalidUpdatePolicy { .. })
        ));
    }

    #[test]
    fn update_policy_zero_age_rejected() {
        let mut policy = test_update_policy();
        policy.max_data_age = 0;
        assert!(matches!(
            policy.validate(),
            Err(ContractError::InvalidUpdatePolicy { .. })
        ));
    }

    #[test]
    fn update_policy_skip_without_limit_rejected() {
        let mut policy = test_update_policy();
        policy.allow_skip = true;
        policy.max_consecutive_skips = 0;
        assert!(matches!(
            policy.validate(),
            Err(ContractError::InvalidUpdatePolicy { .. })
        ));
    }

    #[test]
    fn update_policy_no_skip_zero_limit_ok() {
        let mut policy = test_update_policy();
        policy.allow_skip = false;
        policy.max_consecutive_skips = 0;
        policy.validate().expect("valid when skips disabled");
    }

    // -------------------------------------------------------------------
    // Clipping strategy tests
    // -------------------------------------------------------------------

    #[test]
    fn clipping_strategy_l2_valid() {
        test_clipping_strategy()
            .validate(&test_feature_schema())
            .expect("valid");
    }

    #[test]
    fn clipping_strategy_zero_bound_rejected() {
        let mut clipping = test_clipping_strategy();
        clipping.global_bound_millionths = 0;
        assert!(matches!(
            clipping.validate(&test_feature_schema()),
            Err(ContractError::InvalidClippingStrategy { .. })
        ));
    }

    #[test]
    fn clipping_strategy_negative_bound_rejected() {
        let mut clipping = test_clipping_strategy();
        clipping.global_bound_millionths = -1;
        assert!(matches!(
            clipping.validate(&test_feature_schema()),
            Err(ContractError::InvalidClippingStrategy { .. })
        ));
    }

    #[test]
    fn clipping_strategy_per_field_with_l2_rejected() {
        let mut clipping = test_clipping_strategy();
        clipping.method = ClippingMethod::L2Norm;
        clipping
            .per_field_bounds
            .insert("calibration_residual".to_string(), 500_000);
        assert!(matches!(
            clipping.validate(&test_feature_schema()),
            Err(ContractError::InvalidClippingStrategy { .. })
        ));
    }

    #[test]
    fn clipping_strategy_per_coordinate_valid() {
        let mut clipping = test_clipping_strategy();
        clipping.method = ClippingMethod::PerCoordinate;
        clipping
            .per_field_bounds
            .insert("calibration_residual".to_string(), 500_000);
        clipping.validate(&test_feature_schema()).expect("valid");
    }

    #[test]
    fn clipping_strategy_unknown_field_rejected() {
        let mut clipping = test_clipping_strategy();
        clipping.method = ClippingMethod::PerCoordinate;
        clipping
            .per_field_bounds
            .insert("nonexistent_field".to_string(), 500_000);
        assert!(matches!(
            clipping.validate(&test_feature_schema()),
            Err(ContractError::InvalidClippingStrategy { .. })
        ));
    }

    #[test]
    fn clipping_strategy_per_field_negative_rejected() {
        let mut clipping = test_clipping_strategy();
        clipping.method = ClippingMethod::PerCoordinate;
        clipping
            .per_field_bounds
            .insert("calibration_residual".to_string(), -1);
        assert!(matches!(
            clipping.validate(&test_feature_schema()),
            Err(ContractError::InvalidClippingStrategy { .. })
        ));
    }

    // -------------------------------------------------------------------
    // DP budget tests
    // -------------------------------------------------------------------

    #[test]
    fn dp_budget_valid() {
        test_dp_budget().validate().expect("valid");
    }

    #[test]
    fn dp_budget_zero_epsilon_rejected() {
        let mut budget = test_dp_budget();
        budget.epsilon_per_epoch_millionths = 0;
        assert!(matches!(
            budget.validate(),
            Err(ContractError::InvalidDpBudget { .. })
        ));
    }

    #[test]
    fn dp_budget_negative_delta_rejected() {
        let mut budget = test_dp_budget();
        budget.delta_per_epoch_millionths = -1;
        assert!(matches!(
            budget.validate(),
            Err(ContractError::InvalidDpBudget { .. })
        ));
    }

    #[test]
    fn dp_budget_fail_open_rejected() {
        let mut budget = test_dp_budget();
        budget.fail_closed_on_exhaustion = false;
        assert!(matches!(
            budget.validate(),
            Err(ContractError::InvalidDpBudget { .. })
        ));
    }

    #[test]
    fn dp_budget_epoch_exceeds_lifetime_rejected() {
        let mut budget = test_dp_budget();
        budget.epsilon_per_epoch_millionths = budget.lifetime_epsilon_budget_millionths + 1;
        assert!(matches!(
            budget.validate(),
            Err(ContractError::InvalidDpBudget { .. })
        ));
    }

    #[test]
    fn dp_budget_max_epochs_basic() {
        let mut budget = test_dp_budget();
        budget.composition_method = CompositionMethod::Basic;
        budget.epsilon_per_epoch_millionths = 1_000_000; // 1.0
        budget.lifetime_epsilon_budget_millionths = 10_000_000; // 10.0
        assert_eq!(budget.max_epochs(), 10);
    }

    #[test]
    fn dp_budget_max_epochs_renyi() {
        let mut budget = test_dp_budget();
        budget.composition_method = CompositionMethod::Renyi;
        budget.epsilon_per_epoch_millionths = 1_000_000; // 1.0
        budget.lifetime_epsilon_budget_millionths = 10_000_000; // 10.0
        // sqrt composition: (10/1)^2 = 100
        assert_eq!(budget.max_epochs(), 100);
    }

    #[test]
    fn dp_budget_max_epochs_zcdp() {
        let mut budget = test_dp_budget();
        budget.composition_method = CompositionMethod::ZeroCdp;
        budget.epsilon_per_epoch_millionths = 500_000; // 0.5
        budget.lifetime_epsilon_budget_millionths = 5_000_000; // 5.0
        // (5_000_000 / 500_000)^2 = 100
        assert_eq!(budget.max_epochs(), 100);
    }

    // -------------------------------------------------------------------
    // Aggregation tests
    // -------------------------------------------------------------------

    #[test]
    fn aggregation_valid() {
        test_aggregation().validate().expect("valid");
    }

    #[test]
    fn aggregation_one_participant_rejected() {
        let mut agg = test_aggregation();
        agg.min_participants = 1;
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    #[test]
    fn aggregation_negative_dropout_rejected() {
        let mut agg = test_aggregation();
        agg.dropout_tolerance_millionths = -1;
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    #[test]
    fn aggregation_full_dropout_rejected() {
        let mut agg = test_aggregation();
        agg.dropout_tolerance_millionths = 1_000_000; // 100%
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    #[test]
    fn aggregation_shamir_valid() {
        let agg = SecureAggregationRequirements {
            min_participants: 10,
            dropout_tolerance_millionths: 200_000,
            secret_sharing_scheme: SecretSharingScheme::Shamir,
            sharing_threshold: Some(7),
            coordinator_trust_model: CoordinatorTrustModel::Malicious,
        };
        agg.validate().expect("valid shamir");
    }

    #[test]
    fn aggregation_shamir_no_threshold_rejected() {
        let agg = SecureAggregationRequirements {
            min_participants: 10,
            dropout_tolerance_millionths: 200_000,
            secret_sharing_scheme: SecretSharingScheme::Shamir,
            sharing_threshold: None,
            coordinator_trust_model: CoordinatorTrustModel::Malicious,
        };
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    #[test]
    fn aggregation_shamir_low_threshold_rejected() {
        let agg = SecureAggregationRequirements {
            min_participants: 10,
            dropout_tolerance_millionths: 200_000,
            secret_sharing_scheme: SecretSharingScheme::Shamir,
            sharing_threshold: Some(1),
            coordinator_trust_model: CoordinatorTrustModel::Malicious,
        };
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    #[test]
    fn aggregation_shamir_threshold_exceeds_participants_rejected() {
        let agg = SecureAggregationRequirements {
            min_participants: 5,
            dropout_tolerance_millionths: 200_000,
            secret_sharing_scheme: SecretSharingScheme::Shamir,
            sharing_threshold: Some(6),
            coordinator_trust_model: CoordinatorTrustModel::Malicious,
        };
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    #[test]
    fn aggregation_additive_with_threshold_rejected() {
        let agg = SecureAggregationRequirements {
            min_participants: 10,
            dropout_tolerance_millionths: 200_000,
            secret_sharing_scheme: SecretSharingScheme::Additive,
            sharing_threshold: Some(5),
            coordinator_trust_model: CoordinatorTrustModel::HonestButCurious,
        };
        assert!(matches!(
            agg.validate(),
            Err(ContractError::InvalidAggregation { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Retention tests
    // -------------------------------------------------------------------

    #[test]
    fn retention_valid() {
        test_retention().validate().expect("valid");
    }

    #[test]
    fn retention_zero_intermediate_rejected() {
        let mut ret = test_retention();
        ret.max_intermediate_retention = 0;
        assert!(matches!(
            ret.validate(),
            Err(ContractError::InvalidRetention { .. })
        ));
    }

    #[test]
    fn retention_snapshot_less_than_intermediate_rejected() {
        let mut ret = test_retention();
        ret.max_intermediate_retention = 1000;
        ret.max_snapshot_retention = 500;
        assert!(matches!(
            ret.validate(),
            Err(ContractError::InvalidRetention { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Randomness transcript commitment tests
    // -------------------------------------------------------------------

    #[test]
    fn randomness_commitment_chain_and_sequence_verified() {
        let mut transcript = RandomnessTranscript::new();
        let sk = governance_signing_key();
        let vk = governance_vk();
        let epoch = SecurityEpoch::from_raw(7);

        let c1 = transcript
            .commit_seed(
                &sk,
                "noise-addition",
                b"seed-noise-01",
                PrngAlgorithm::ChaCha20LikeCounter,
                epoch,
                evidence_id(0x11),
            )
            .expect("first commitment")
            .clone();
        let c2 = transcript
            .commit_seed(
                &sk,
                "dropout-selection",
                b"seed-dropout-02",
                PrngAlgorithm::ChaCha20LikeCounter,
                epoch,
                evidence_id(0x12),
            )
            .expect("second commitment")
            .clone();

        assert_eq!(c1.sequence_counter, 1);
        assert_eq!(c2.sequence_counter, 2);
        assert_eq!(c2.previous_commitment_hash, Some(c1.commitment_hash));

        transcript.verify_chain(&vk).expect("valid chain");
    }

    #[test]
    fn randomness_commitment_tamper_detected() {
        let mut transcript = RandomnessTranscript::new();
        let sk = governance_signing_key();
        let vk = governance_vk();
        let epoch = SecurityEpoch::from_raw(9);

        transcript
            .commit_seed(
                &sk,
                "random-sampling",
                b"sampling-seed",
                PrngAlgorithm::ChaCha20LikeCounter,
                epoch,
                evidence_id(0x21),
            )
            .expect("commitment");
        transcript
            .commit_seed(
                &sk,
                "noise-addition",
                b"noise-seed",
                PrngAlgorithm::ChaCha20LikeCounter,
                epoch,
                evidence_id(0x22),
            )
            .expect("commitment");

        // Tamper with linkage: this must fail deterministic chain verification.
        transcript.commitments[1].previous_commitment_hash = None;
        assert!(matches!(
            transcript.verify_chain(&vk),
            Err(ContractError::InvalidRandomnessTranscript { .. })
        ));
    }

    #[test]
    fn randomness_snapshot_merkle_root_and_signature_verified() {
        let mut transcript = RandomnessTranscript::new();
        let sk = governance_signing_key();
        let vk = governance_vk();
        let epoch = SecurityEpoch::from_raw(11);

        transcript
            .commit_seed(
                &sk,
                "phase-a",
                b"phase-a-seed",
                PrngAlgorithm::ChaCha20LikeCounter,
                epoch,
                evidence_id(0x31),
            )
            .expect("commitment");
        transcript
            .commit_seed(
                &sk,
                "phase-b",
                b"phase-b-seed",
                PrngAlgorithm::ChaCha20LikeCounter,
                epoch,
                evidence_id(0x32),
            )
            .expect("commitment");

        transcript
            .emit_snapshot_summary(&sk, "model-snap-001", "policy-snap-001")
            .expect("summary");
        transcript
            .verify_snapshot_summaries(&vk)
            .expect("summary verifies");

        // Tamper with a committed hash and ensure snapshot verification fails.
        transcript.commitments[0].commitment_hash = [0xFF; 32];
        assert!(matches!(
            transcript.verify_snapshot_summaries(&vk),
            Err(ContractError::InvalidRandomnessTranscript { .. })
        ));
    }

    #[test]
    fn deterministic_prng_is_reproducible() {
        let mut p1 = DeterministicPrng::new(
            "phase-prng",
            PrngAlgorithm::ChaCha20LikeCounter,
            b"deterministic-seed",
        )
        .expect("prng");
        let mut p2 = DeterministicPrng::new(
            "phase-prng",
            PrngAlgorithm::ChaCha20LikeCounter,
            b"deterministic-seed",
        )
        .expect("prng");

        let seq1: Vec<u64> = (0..8).map(|_| p1.next_u64()).collect();
        let seq2: Vec<u64> = (0..8).map(|_| p2.next_u64()).collect();
        assert_eq!(seq1, seq2);
    }

    #[test]
    fn randomness_replay_with_escrow_is_deterministic() {
        let mut transcript = RandomnessTranscript::new();
        let sk = governance_signing_key();
        let vk = governance_vk();
        let epoch = SecurityEpoch::from_raw(13);

        transcript
            .commit_seed(
                &sk,
                "noise-phase",
                b"noise-phase-seed",
                PrngAlgorithm::ChaCha20LikeCounter,
                epoch,
                evidence_id(0x41),
            )
            .expect("commitment");
        transcript
            .emit_snapshot_summary(&sk, "model-snap-002", "policy-snap-002")
            .expect("summary");

        let mut auditors = BTreeSet::new();
        auditors.insert("audit-bot".to_string());
        let escrow1 =
            SeedEscrowRecord::create("noise-phase", epoch, b"noise-phase-seed", auditors.clone())
                .expect("escrow");
        let escrow2 = SeedEscrowRecord::create("noise-phase", epoch, b"noise-phase-seed", auditors)
            .expect("escrow");

        let mut records_a = vec![escrow1];
        let mut records_b = vec![escrow2];
        let out_a = transcript
            .replay_with_escrowed_seeds(&vk, &mut records_a, "audit-bot", 5)
            .expect("replay A");
        let out_b = transcript
            .replay_with_escrowed_seeds(&vk, &mut records_b, "audit-bot", 5)
            .expect("replay B");

        assert_eq!(out_a, out_b);
        assert_eq!(out_a.len(), 1);
        assert_eq!(out_a[0].outputs.len(), 5);
    }

    #[test]
    fn randomness_replay_rejects_seed_hash_mismatch() {
        let mut transcript = RandomnessTranscript::new();
        let sk = governance_signing_key();
        let vk = governance_vk();
        let epoch = SecurityEpoch::from_raw(15);

        transcript
            .commit_seed(
                &sk,
                "sampling-phase",
                b"sampling-phase-seed",
                PrngAlgorithm::ChaCha20LikeCounter,
                epoch,
                evidence_id(0x51),
            )
            .expect("commitment");
        transcript
            .emit_snapshot_summary(&sk, "model-snap-003", "policy-snap-003")
            .expect("summary");

        let mut auditors = BTreeSet::new();
        auditors.insert("audit-bot".to_string());
        let mismatch = SeedEscrowRecord::create("sampling-phase", epoch, b"wrong-seed", auditors)
            .expect("escrow");
        let mut records = vec![mismatch];

        assert!(matches!(
            transcript.replay_with_escrowed_seeds(&vk, &mut records, "audit-bot", 3),
            Err(ContractError::SeedHashMismatch { .. })
        ));
    }

    #[test]
    fn seed_escrow_denies_unauthorized_principal() {
        let mut auditors = BTreeSet::new();
        auditors.insert("allowed-auditor".to_string());
        let mut escrow = SeedEscrowRecord::create(
            "dropout-phase",
            SecurityEpoch::from_raw(17),
            b"dropout-seed",
            auditors,
        )
        .expect("escrow");

        assert!(matches!(
            escrow.open_for_audit("untrusted-user", "investigation"),
            Err(ContractError::SeedEscrowAccessDenied { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Contract creation tests
    // -------------------------------------------------------------------

    #[test]
    fn create_contract_succeeds() {
        let contract = create_test_contract();
        assert_eq!(contract.zone, TEST_ZONE);
        assert_eq!(contract.epoch, SecurityEpoch::from_raw(1));
        assert_eq!(contract.feature_schema.version, 1);
        assert_eq!(contract.authorized_participants.len(), 3);
    }

    #[test]
    fn create_contract_deterministic() {
        let c1 = create_test_contract();
        let c2 = create_test_contract();
        assert_eq!(c1.contract_id, c2.contract_id);
        assert_eq!(c1.governance_signature, c2.governance_signature);
    }

    #[test]
    fn create_contract_no_participants_rejected() {
        let mut input = test_contract_input();
        input.authorized_participants = BTreeSet::new();
        let result = PrivacyLearningContract::create_signed(&governance_signing_key(), input);
        assert!(matches!(
            result,
            Err(ContractError::NoAuthorizedParticipants)
        ));
    }

    #[test]
    fn create_contract_invalid_schema_rejected() {
        let mut input = test_contract_input();
        input.feature_schema.version = 0;
        let result = PrivacyLearningContract::create_signed(&governance_signing_key(), input);
        assert!(matches!(result, Err(ContractError::InvalidVersion { .. })));
    }

    #[test]
    fn create_contract_invalid_dp_budget_rejected() {
        let mut input = test_contract_input();
        input.dp_budget.fail_closed_on_exhaustion = false;
        let result = PrivacyLearningContract::create_signed(&governance_signing_key(), input);
        assert!(matches!(result, Err(ContractError::InvalidDpBudget { .. })));
    }

    // -------------------------------------------------------------------
    // Signature verification
    // -------------------------------------------------------------------

    #[test]
    fn verify_governance_signature_succeeds() {
        let contract = create_test_contract();
        contract
            .verify_governance_signature(&governance_vk())
            .expect("valid");
    }

    #[test]
    fn verify_governance_signature_wrong_key_fails() {
        let contract = create_test_contract();
        let wrong_sk = SigningKey::from_bytes([0xFF; 32]);
        let wrong_vk = wrong_sk.verification_key();
        let result = contract.verify_governance_signature(&wrong_vk);
        assert!(matches!(
            result,
            Err(ContractError::SignatureInvalid { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Contract registry tests
    // -------------------------------------------------------------------

    #[test]
    fn registry_register_succeeds() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        let id = registry
            .register(contract, &governance_vk(), "t-reg")
            .expect("register");
        assert_eq!(registry.total_count(), 1);
        assert!(registry.get(&id).is_some());
    }

    #[test]
    fn registry_active_for_zone() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        registry
            .register(contract, &governance_vk(), "t-reg")
            .expect("register");
        let active = registry.active_for_zone(TEST_ZONE);
        assert!(active.is_some());
        assert_eq!(active.unwrap().zone, TEST_ZONE);
    }

    #[test]
    fn registry_duplicate_rejected() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        registry
            .register(contract.clone(), &governance_vk(), "t-1")
            .expect("first");
        let result = registry.register(contract, &governance_vk(), "t-2");
        assert!(matches!(
            result,
            Err(ContractError::DuplicateContract { .. })
        ));
    }

    #[test]
    fn registry_epoch_advance_required() {
        let mut registry = ContractRegistry::new();
        let contract1 = create_test_contract();
        registry
            .register(contract1, &governance_vk(), "t-1")
            .expect("first");

        // Same epoch contract should be rejected.
        let mut input = test_contract_input();
        input.feature_schema.version = 2;
        let contract2 =
            PrivacyLearningContract::create_signed(&governance_signing_key(), input).unwrap();
        let result = registry.register(contract2, &governance_vk(), "t-2");
        assert!(matches!(
            result,
            Err(ContractError::EpochNotAdvanced { .. })
        ));
    }

    #[test]
    fn registry_epoch_upgrade_succeeds() {
        let mut registry = ContractRegistry::new();
        let contract1 = create_test_contract();
        registry
            .register(contract1, &governance_vk(), "t-1")
            .expect("first");

        let mut input = test_contract_input();
        input.epoch = SecurityEpoch::from_raw(2);
        let contract2 =
            PrivacyLearningContract::create_signed(&governance_signing_key(), input).unwrap();
        let id2 = registry
            .register(contract2, &governance_vk(), "t-2")
            .expect("upgrade");

        let active = registry.active_for_zone(TEST_ZONE).unwrap();
        assert_eq!(active.contract_id, id2);
        assert_eq!(active.epoch, SecurityEpoch::from_raw(2));
    }

    #[test]
    fn registry_revoke_succeeds() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        let id = registry
            .register(contract, &governance_vk(), "t-reg")
            .expect("register");
        registry.revoke(&id, "t-revoke").expect("revoke");
        assert_eq!(registry.total_count(), 0);
        assert!(registry.active_for_zone(TEST_ZONE).is_none());
    }

    #[test]
    fn registry_revoke_not_found() {
        let mut registry = ContractRegistry::new();
        let fake_id = EngineObjectId([0xFF; 32]);
        let result = registry.revoke(&fake_id, "t-revoke");
        assert!(matches!(result, Err(ContractError::NotFound { .. })));
    }

    #[test]
    fn registry_wrong_signature_rejected() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        let wrong_sk = SigningKey::from_bytes([0xFF; 32]);
        let wrong_vk = wrong_sk.verification_key();
        let result = registry.register(contract, &wrong_vk, "t-sig");
        assert!(matches!(
            result,
            Err(ContractError::SignatureInvalid { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Audit event tests
    // -------------------------------------------------------------------

    #[test]
    fn events_on_register() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        registry
            .register(contract, &governance_vk(), "t-reg")
            .expect("register");
        let events = registry.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].event_type,
            ContractEventType::Registered { .. }
        ));
    }

    #[test]
    fn events_on_revoke() {
        let mut registry = ContractRegistry::new();
        let contract = create_test_contract();
        let id = registry
            .register(contract, &governance_vk(), "t-reg")
            .expect("register");
        registry.drain_events();
        registry.revoke(&id, "t-revoke").expect("revoke");
        let events = registry.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(
            events[0].event_type,
            ContractEventType::Revoked { .. }
        ));
    }

    // -------------------------------------------------------------------
    // Serialization tests
    // -------------------------------------------------------------------

    #[test]
    fn contract_serde_round_trip() {
        let contract = create_test_contract();
        let json = serde_json::to_string(&contract).expect("serialize");
        let restored: PrivacyLearningContract = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(contract, restored);
    }

    #[test]
    fn feature_schema_serde_round_trip() {
        let schema = test_feature_schema();
        let json = serde_json::to_string(&schema).expect("serialize");
        let restored: FeatureSchema = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(schema, restored);
    }

    #[test]
    fn dp_budget_serde_round_trip() {
        let budget = test_dp_budget();
        let json = serde_json::to_string(&budget).expect("serialize");
        let restored: DpBudgetSemantics = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(budget, restored);
    }

    #[test]
    fn error_serde_round_trip() {
        let errors: Vec<ContractError> = vec![
            ContractError::EmptyFeatureSchema,
            ContractError::InvalidDpBudget {
                detail: "test".to_string(),
            },
            ContractError::NoAuthorizedParticipants,
            ContractError::EpochNotAdvanced {
                zone: "z".to_string(),
                existing_epoch: SecurityEpoch::from_raw(1),
                new_epoch: SecurityEpoch::from_raw(1),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ContractError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -------------------------------------------------------------------
    // Shadow evaluation gate tests
    // -------------------------------------------------------------------

    #[test]
    fn shadow_gate_passes_candidate_with_budget_compliance_and_improvement() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let artifact = gate
            .evaluate_candidate(
                &contract,
                candidate_with_metrics(improved_metrics(), 90_000, 900),
                &governance_signing_key(),
            )
            .expect("shadow evaluation");

        assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);
        assert!(artifact.privacy_budget_status.within_budget);
        assert!(artifact.significant_improvement_count > 0);
        assert!(artifact.failure_reasons.is_empty());
        assert_eq!(gate.events().len(), 4);
        assert_eq!(gate.events()[0].event, "shadow_start");
        assert_eq!(gate.events()[0].outcome, "started");
        assert_eq!(gate.events()[1].event, "shadow_evaluation");
        assert_eq!(gate.events()[1].outcome, "pass");
        assert!(gate.events()[1].error_code.is_none());
        assert_eq!(gate.events()[2].event, "promotion_gate");
        assert_eq!(gate.events()[2].outcome, "pass");
        assert_eq!(gate.events()[3].event, "auto_enforcement");
        assert_eq!(gate.events()[3].outcome, "promoted");
        assert!(artifact.to_scorecard_entry().rollback_ready);
    }

    #[test]
    fn shadow_gate_rejects_candidate_on_budget_exhaustion() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let artifact = gate
            .evaluate_candidate(
                &contract,
                candidate_with_metrics(
                    improved_metrics(),
                    contract.dp_budget.epsilon_per_epoch_millionths + 1,
                    contract.dp_budget.delta_per_epoch_millionths + 1,
                ),
                &governance_signing_key(),
            )
            .expect("shadow evaluation");

        assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
        assert!(!artifact.privacy_budget_status.within_budget);
        assert!(
            artifact
                .failure_reasons
                .iter()
                .any(|reason| reason.contains("privacy budget exceeded"))
        );
        assert!(gate.events().iter().any(|event| {
            event.error_code.as_deref() == Some("FE-PLC-SHADOW-0002")
                && event.event == "shadow_evaluation"
        }));
        assert!(
            gate.events()
                .iter()
                .any(|event| event.event == "rejection" && event.outcome == "rejected")
        );
    }

    #[test]
    fn shadow_gate_rejects_regression_and_allows_signed_override() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let rejected = gate
            .evaluate_candidate(
                &contract,
                candidate_with_metrics(regressed_metrics(), 90_000, 900),
                &governance_signing_key(),
            )
            .expect("shadow evaluation");
        assert_eq!(rejected.verdict, ShadowPromotionVerdict::Reject);

        let overridden = gate
            .apply_human_override(
                &rejected,
                HumanOverrideRequest {
                    operator_id: "governor-operator-7".to_string(),
                    summary: "manual promotion required to preserve external SLA".to_string(),
                    bypassed_risk_criteria: vec![
                        "false_positive_rate <= baseline+5000".to_string(),
                    ],
                    acknowledged_bypass: true,
                },
                &governance_signing_key(),
            )
            .expect("override");

        assert_eq!(overridden.verdict, ShadowPromotionVerdict::OverrideApproved);
        assert!(overridden.human_override.is_some());
        assert_eq!(gate.events().last().expect("event").event, "human_override");
        assert_eq!(
            gate.events().last().expect("event").outcome,
            "override_approved"
        );
    }

    #[test]
    fn shadow_gate_triggers_automatic_rollback_on_post_deployment_regression() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let artifact = gate
            .evaluate_candidate(
                &contract,
                candidate_with_metrics(improved_metrics(), 90_000, 900),
                &governance_signing_key(),
            )
            .expect("shadow evaluation");
        assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);

        let rollback = gate
            .evaluate_post_deployment_metrics(
                &artifact,
                regressed_metrics(),
                &governance_signing_key(),
            )
            .expect("post deployment check")
            .expect("rollback must trigger");

        assert_eq!(rollback.policy_id, artifact.policy_id);
        assert!(!rollback.triggered_regressions.is_empty());
        assert_eq!(gate.active_artifact(&artifact.policy_id), None);
        assert_eq!(
            gate.events().last().expect("event").event,
            "automatic_rollback"
        );
        assert_eq!(
            gate.events().last().expect("event").error_code.as_deref(),
            Some("FE-PLC-SHADOW-0007")
        );
    }

    #[test]
    fn shadow_gate_events_have_stable_fields() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let artifact = gate
            .evaluate_candidate(
                &contract,
                candidate_with_metrics(improved_metrics(), 90_000, 900),
                &governance_signing_key(),
            )
            .expect("shadow evaluation");
        let event = gate
            .events()
            .iter()
            .find(|event| event.event == "shadow_evaluation")
            .expect("shadow evaluation event");

        assert_eq!(event.trace_id, artifact.trace_id);
        assert_eq!(event.decision_id, artifact.decision_id);
        assert_eq!(event.policy_id, artifact.policy_id);
        assert_eq!(event.component, "shadow_evaluation_gate");
        assert_eq!(event.event, "shadow_evaluation");
        assert_eq!(event.outcome, "pass");
        assert!(event.error_code.is_none());
    }

    #[test]
    fn shadow_gate_property_any_criterion_failure_prevents_pass() {
        let contract = create_test_contract();

        for budget_ok in [true, false] {
            for regression in [false, true] {
                for improvement in [false, true] {
                    for deterministic in [true, false] {
                        let mut gate = shadow_gate();

                        let mut metrics = if regression {
                            regressed_metrics()
                        } else if improvement {
                            improved_metrics()
                        } else {
                            baseline_metrics()
                        };

                        // Mixed case: include a significant improvement while also regressing one metric.
                        if regression && improvement {
                            metrics.values_millionths.insert(
                                SafetyMetric::DriftDetectionAccuracy,
                                baseline_metrics()
                                    .metric_value(SafetyMetric::DriftDetectionAccuracy)
                                    + 10_000,
                            );
                        }

                        let mut candidate = candidate_with_metrics(
                            metrics,
                            if budget_ok {
                                90_000
                            } else {
                                contract.dp_budget.epsilon_per_epoch_millionths + 1
                            },
                            if budget_ok {
                                900
                            } else {
                                contract.dp_budget.delta_per_epoch_millionths + 1
                            },
                        );
                        if !deterministic {
                            candidate.replay_reference.replay_seed_hash = [0u8; 32];
                        }

                        let result = gate.evaluate_candidate(
                            &contract,
                            candidate,
                            &governance_signing_key(),
                        );
                        let should_pass = budget_ok && !regression && improvement && deterministic;
                        match result {
                            Ok(artifact) => {
                                assert_eq!(
                                    artifact.verdict == ShadowPromotionVerdict::Pass,
                                    should_pass
                                );
                            }
                            Err(_) => {
                                assert!(!deterministic);
                            }
                        }
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // Display tests
    // -------------------------------------------------------------------

    #[test]
    fn contract_display() {
        let contract = create_test_contract();
        let display = contract.to_string();
        assert!(display.contains("PrivacyLearningContract"));
        assert!(display.contains(TEST_ZONE));
    }

    #[test]
    fn error_display() {
        let err = ContractError::EmptyFeatureSchema;
        assert_eq!(err.to_string(), "feature schema has no fields");

        let err = ContractError::NoAuthorizedParticipants;
        assert_eq!(err.to_string(), "no authorized participants");
    }

    #[test]
    fn clipping_method_display() {
        assert_eq!(ClippingMethod::L2Norm.to_string(), "l2_norm");
        assert_eq!(ClippingMethod::PerCoordinate.to_string(), "per_coordinate");
        assert_eq!(ClippingMethod::Adaptive.to_string(), "adaptive");
    }

    #[test]
    fn composition_method_display() {
        assert_eq!(CompositionMethod::Basic.to_string(), "basic");
        assert_eq!(CompositionMethod::Renyi.to_string(), "renyi");
        assert_eq!(CompositionMethod::ZeroCdp.to_string(), "zcdp");
    }

    // -------------------------------------------------------------------
    // Authorization tests
    // -------------------------------------------------------------------

    #[test]
    fn contract_is_authorized() {
        let contract = create_test_contract();
        assert!(contract.is_authorized(&EngineObjectId([0xAA; 32])));
        assert!(contract.is_authorized(&EngineObjectId([0xBB; 32])));
        assert!(!contract.is_authorized(&EngineObjectId([0xFF; 32])));
    }

    // -------------------------------------------------------------------
    // Schema determinism
    // -------------------------------------------------------------------

    #[test]
    fn schema_determinism() {
        let s1 = contract_schema();
        let s2 = contract_schema();
        assert_eq!(s1, s2);
    }

    #[test]
    fn schema_id_determinism() {
        let s1 = contract_schema_id();
        let s2 = contract_schema_id();
        assert_eq!(s1, s2);
    }

    // -------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------

    #[test]
    fn empty_registry_queries() {
        let registry = ContractRegistry::new();
        assert_eq!(registry.total_count(), 0);
        assert_eq!(registry.zone_count(), 0);
        assert!(registry.active_for_zone(TEST_ZONE).is_none());
    }

    #[test]
    fn multi_zone_contracts() {
        let mut registry = ContractRegistry::new();

        let contract1 = create_test_contract();
        registry
            .register(contract1, &governance_vk(), "t-1")
            .expect("zone1");

        let mut input2 = test_contract_input();
        input2.zone = "other-zone";
        let contract2 =
            PrivacyLearningContract::create_signed(&governance_signing_key(), input2).unwrap();
        registry
            .register(contract2, &governance_vk(), "t-2")
            .expect("zone2");

        assert_eq!(registry.total_count(), 2);
        assert_eq!(registry.zone_count(), 2);
        assert!(registry.active_for_zone(TEST_ZONE).is_some());
        assert!(registry.active_for_zone("other-zone").is_some());
        assert!(registry.active_for_zone("nonexistent").is_none());
    }

    #[test]
    fn field_type_display() {
        assert_eq!(FeatureFieldType::FixedPoint.to_string(), "fixed_point");
        assert_eq!(FeatureFieldType::Counter.to_string(), "counter");
        assert_eq!(FeatureFieldType::Boolean.to_string(), "boolean");
        assert_eq!(FeatureFieldType::Categorical.to_string(), "categorical");
    }

    #[test]
    fn coordinator_trust_model_display() {
        assert_eq!(
            CoordinatorTrustModel::HonestButCurious.to_string(),
            "honest_but_curious"
        );
        assert_eq!(CoordinatorTrustModel::Malicious.to_string(), "malicious");
    }

    #[test]
    fn secret_sharing_scheme_display() {
        assert_eq!(SecretSharingScheme::Additive.to_string(), "additive");
        assert_eq!(SecretSharingScheme::Shamir.to_string(), "shamir");
    }

    // -------------------------------------------------------------------
    // Enrichment: serde roundtrips for leaf enum types
    // -------------------------------------------------------------------

    #[test]
    fn feature_field_type_serde_roundtrip() {
        for variant in [
            FeatureFieldType::FixedPoint,
            FeatureFieldType::Counter,
            FeatureFieldType::Boolean,
            FeatureFieldType::Categorical,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            let restored: FeatureFieldType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, restored);
        }
    }

    #[test]
    fn clipping_method_serde_roundtrip() {
        for variant in [
            ClippingMethod::L2Norm,
            ClippingMethod::PerCoordinate,
            ClippingMethod::Adaptive,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            let restored: ClippingMethod = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, restored);
        }
    }

    #[test]
    fn composition_method_serde_roundtrip() {
        for variant in [
            CompositionMethod::Basic,
            CompositionMethod::Advanced,
            CompositionMethod::Renyi,
            CompositionMethod::ZeroCdp,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            let restored: CompositionMethod = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, restored);
        }
    }

    #[test]
    fn coordinator_trust_model_serde_roundtrip() {
        for variant in [
            CoordinatorTrustModel::HonestButCurious,
            CoordinatorTrustModel::Malicious,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            let restored: CoordinatorTrustModel = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, restored);
        }
    }

    #[test]
    fn secret_sharing_scheme_serde_roundtrip() {
        for variant in [SecretSharingScheme::Additive, SecretSharingScheme::Shamir] {
            let json = serde_json::to_string(&variant).expect("serialize");
            let restored: SecretSharingScheme = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, restored);
        }
    }

    #[test]
    fn prng_algorithm_serde_roundtrip_and_display() {
        let variant = PrngAlgorithm::ChaCha20LikeCounter;
        let json = serde_json::to_string(&variant).expect("serialize");
        let restored: PrngAlgorithm = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(variant, restored);
        assert_eq!(variant.to_string(), "chacha20_like_counter");
    }

    #[test]
    fn safety_metric_serde_roundtrip() {
        for variant in SafetyMetric::ALL {
            let json = serde_json::to_string(variant).expect("serialize");
            let restored: SafetyMetric = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*variant, restored);
        }
    }

    #[test]
    fn shadow_extension_class_serde_roundtrip() {
        for variant in [
            ShadowExtensionClass::LowRisk,
            ShadowExtensionClass::Standard,
            ShadowExtensionClass::HighRisk,
            ShadowExtensionClass::Critical,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            let restored: ShadowExtensionClass = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, restored);
        }
    }

    #[test]
    fn shadow_promotion_verdict_serde_roundtrip() {
        for variant in [
            ShadowPromotionVerdict::Pass,
            ShadowPromotionVerdict::Reject,
            ShadowPromotionVerdict::OverrideApproved,
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            let restored: ShadowPromotionVerdict =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(variant, restored);
        }
    }

    #[test]
    fn contract_event_type_serde_roundtrip() {
        let variants = vec![
            ContractEventType::Registered {
                contract_id: EngineObjectId([0xAA; 32]),
                zone: "zone-a".to_string(),
                epoch: SecurityEpoch::from_raw(5),
            },
            ContractEventType::Revoked {
                contract_id: EngineObjectId([0xBB; 32]),
                zone: "zone-b".to_string(),
            },
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).expect("serialize");
            let restored: ContractEventType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*variant, restored);
        }
    }

    #[test]
    fn contract_event_serde_roundtrip() {
        let event = ContractEvent {
            event_type: ContractEventType::Registered {
                contract_id: EngineObjectId([0xCC; 32]),
                zone: "z".to_string(),
                epoch: SecurityEpoch::from_raw(3),
            },
            trace_id: "trace-123".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: ContractEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: ContractError serde remaining variants
    // -------------------------------------------------------------------

    #[test]
    fn contract_error_serde_remaining_variants() {
        let errors: Vec<ContractError> = vec![
            ContractError::FieldNameMismatch {
                key: "k".to_string(),
                field_name: "f".to_string(),
            },
            ContractError::BackwardCompatibilityViolation {
                detail: "d".to_string(),
            },
            ContractError::InvalidUpdatePolicy {
                detail: "d".to_string(),
            },
            ContractError::InvalidClippingStrategy {
                detail: "d".to_string(),
            },
            ContractError::InvalidAggregation {
                detail: "d".to_string(),
            },
            ContractError::InvalidRetention {
                detail: "d".to_string(),
            },
            ContractError::InvalidRandomnessTranscript {
                detail: "d".to_string(),
            },
            ContractError::MissingSeedEscrow {
                phase_id: "p".to_string(),
                epoch_id: SecurityEpoch::from_raw(1),
            },
            ContractError::SeedEscrowAccessDenied {
                principal: "pr".to_string(),
                phase_id: "ph".to_string(),
            },
            ContractError::SeedHashMismatch {
                phase_id: "p".to_string(),
            },
            ContractError::IdDerivationFailed {
                detail: "d".to_string(),
            },
            ContractError::SignatureFailed {
                detail: "d".to_string(),
            },
            ContractError::SignatureInvalid {
                detail: "d".to_string(),
            },
            ContractError::InvalidVersion {
                detail: "d".to_string(),
            },
            ContractError::DuplicateContract {
                contract_id: EngineObjectId([0xAA; 32]),
            },
            ContractError::NotFound {
                contract_id: EngineObjectId([0xBB; 32]),
            },
            ContractError::InvalidShadowEvaluation {
                detail: "d".to_string(),
            },
            ContractError::InvalidShadowOverride {
                detail: "d".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let restored: ContractError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*err, restored);
        }
    }

    // -------------------------------------------------------------------
    // Enrichment: ContractError Display remaining variants
    // -------------------------------------------------------------------

    #[test]
    fn contract_error_display_all_variants() {
        let cases: Vec<(ContractError, &str)> = vec![
            (
                ContractError::EmptyFeatureSchema,
                "feature schema has no fields",
            ),
            (
                ContractError::InvalidVersion {
                    detail: "v0".to_string(),
                },
                "invalid version: v0",
            ),
            (
                ContractError::FieldNameMismatch {
                    key: "k".to_string(),
                    field_name: "f".to_string(),
                },
                "field name mismatch: key=k, field.name=f",
            ),
            (
                ContractError::BackwardCompatibilityViolation {
                    detail: "bc".to_string(),
                },
                "backward compatibility violation: bc",
            ),
            (
                ContractError::InvalidUpdatePolicy {
                    detail: "up".to_string(),
                },
                "invalid update policy: up",
            ),
            (
                ContractError::InvalidClippingStrategy {
                    detail: "cs".to_string(),
                },
                "invalid clipping strategy: cs",
            ),
            (
                ContractError::InvalidDpBudget {
                    detail: "dp".to_string(),
                },
                "invalid DP budget: dp",
            ),
            (
                ContractError::InvalidAggregation {
                    detail: "ag".to_string(),
                },
                "invalid aggregation: ag",
            ),
            (
                ContractError::InvalidRetention {
                    detail: "rt".to_string(),
                },
                "invalid retention: rt",
            ),
            (
                ContractError::InvalidRandomnessTranscript {
                    detail: "rn".to_string(),
                },
                "invalid randomness transcript: rn",
            ),
            (
                ContractError::NoAuthorizedParticipants,
                "no authorized participants",
            ),
            (
                ContractError::IdDerivationFailed {
                    detail: "id".to_string(),
                },
                "id derivation failed: id",
            ),
            (
                ContractError::SignatureFailed {
                    detail: "sf".to_string(),
                },
                "signature failed: sf",
            ),
            (
                ContractError::SignatureInvalid {
                    detail: "si".to_string(),
                },
                "signature invalid: si",
            ),
            (
                ContractError::InvalidShadowEvaluation {
                    detail: "se".to_string(),
                },
                "invalid shadow evaluation: se",
            ),
            (
                ContractError::InvalidShadowOverride {
                    detail: "so".to_string(),
                },
                "invalid shadow override: so",
            ),
        ];
        for (err, expected) in &cases {
            assert_eq!(err.to_string(), *expected, "mismatch for {err:?}");
        }
    }

    // -------------------------------------------------------------------
    // Enrichment: Display for shadow/safety types
    // -------------------------------------------------------------------

    #[test]
    fn safety_metric_display_all_variants() {
        assert_eq!(
            SafetyMetric::FalsePositiveRate.to_string(),
            "false_positive_rate"
        );
        assert_eq!(
            SafetyMetric::FalseNegativeRate.to_string(),
            "false_negative_rate"
        );
        assert_eq!(
            SafetyMetric::CalibrationError.to_string(),
            "calibration_error"
        );
        assert_eq!(
            SafetyMetric::DriftDetectionAccuracy.to_string(),
            "drift_detection_accuracy"
        );
        assert_eq!(
            SafetyMetric::ContainmentTime.to_string(),
            "containment_time"
        );
    }

    #[test]
    fn shadow_extension_class_display_all_variants() {
        assert_eq!(ShadowExtensionClass::LowRisk.to_string(), "low_risk");
        assert_eq!(ShadowExtensionClass::Standard.to_string(), "standard");
        assert_eq!(ShadowExtensionClass::HighRisk.to_string(), "high_risk");
        assert_eq!(ShadowExtensionClass::Critical.to_string(), "critical");
    }

    #[test]
    fn shadow_promotion_verdict_display_all_variants() {
        assert_eq!(ShadowPromotionVerdict::Pass.to_string(), "pass");
        assert_eq!(ShadowPromotionVerdict::Reject.to_string(), "reject");
        assert_eq!(
            ShadowPromotionVerdict::OverrideApproved.to_string(),
            "override_approved"
        );
    }

    #[test]
    fn composition_method_display_advanced() {
        assert_eq!(CompositionMethod::Advanced.to_string(), "advanced");
    }

    // -------------------------------------------------------------------
    // Enrichment: default values
    // -------------------------------------------------------------------

    #[test]
    fn shadow_burn_in_threshold_profile_default_values() {
        let d = ShadowBurnInThresholdProfile::default();
        assert_eq!(d.min_shadow_success_rate_millionths, 995_000);
        assert_eq!(d.max_false_deny_rate_millionths, 5_000);
        assert_eq!(d.min_burn_in_duration_ns, 3_600_000_000_000);
        assert!(d.require_verified_rollback_artifacts);
    }

    #[test]
    fn shadow_evaluation_gate_config_default_values() {
        let d = ShadowEvaluationGateConfig::default();
        assert_eq!(d.regression_tolerance_millionths, 5_000);
        assert_eq!(d.min_required_improvement_millionths, 2_500);
        // Default profile should match ShadowBurnInThresholdProfile::default().
        assert_eq!(
            d.default_burn_in_profile,
            ShadowBurnInThresholdProfile::default()
        );
        // Three extension class overrides: LowRisk, HighRisk, Critical.
        assert_eq!(d.burn_in_profiles_by_extension_class.len(), 3);
        assert!(
            d.burn_in_profiles_by_extension_class
                .contains_key(&ShadowExtensionClass::LowRisk)
        );
        assert!(
            d.burn_in_profiles_by_extension_class
                .contains_key(&ShadowExtensionClass::HighRisk)
        );
        assert!(
            d.burn_in_profiles_by_extension_class
                .contains_key(&ShadowExtensionClass::Critical)
        );
    }

    #[test]
    fn shadow_extension_class_default_is_standard() {
        assert_eq!(
            ShadowExtensionClass::default(),
            ShadowExtensionClass::Standard
        );
    }

    // -------------------------------------------------------------------
    // Enrichment: DeterministicPrng error paths
    // -------------------------------------------------------------------

    #[test]
    fn deterministic_prng_rejects_empty_phase_id() {
        let result = DeterministicPrng::new("  ", PrngAlgorithm::ChaCha20LikeCounter, b"some-seed");
        assert!(matches!(
            result,
            Err(ContractError::InvalidRandomnessTranscript { .. })
        ));
    }

    #[test]
    fn deterministic_prng_rejects_empty_seed() {
        let result = DeterministicPrng::new("valid-phase", PrngAlgorithm::ChaCha20LikeCounter, b"");
        assert!(matches!(
            result,
            Err(ContractError::InvalidRandomnessTranscript { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: SafetyMetric::ALL completeness
    // -------------------------------------------------------------------

    #[test]
    fn safety_metric_all_is_complete() {
        assert_eq!(SafetyMetric::ALL.len(), 5);
        let all_set: BTreeSet<SafetyMetric> = SafetyMetric::ALL.iter().copied().collect();
        assert!(all_set.contains(&SafetyMetric::FalsePositiveRate));
        assert!(all_set.contains(&SafetyMetric::FalseNegativeRate));
        assert!(all_set.contains(&SafetyMetric::CalibrationError));
        assert!(all_set.contains(&SafetyMetric::DriftDetectionAccuracy));
        assert!(all_set.contains(&SafetyMetric::ContainmentTime));
    }

    // -------------------------------------------------------------------
    // Enrichment: ordering tests
    // -------------------------------------------------------------------

    #[test]
    fn feature_field_type_ordering() {
        let mut types = [
            FeatureFieldType::Categorical,
            FeatureFieldType::Boolean,
            FeatureFieldType::Counter,
            FeatureFieldType::FixedPoint,
        ];
        types.sort();
        // Derived Ord follows declaration order.
        assert_eq!(types[0], FeatureFieldType::FixedPoint);
        assert_eq!(types[3], FeatureFieldType::Categorical);
    }

    #[test]
    fn safety_metric_ordering() {
        let mut metrics = [
            SafetyMetric::ContainmentTime,
            SafetyMetric::DriftDetectionAccuracy,
            SafetyMetric::CalibrationError,
            SafetyMetric::FalseNegativeRate,
            SafetyMetric::FalsePositiveRate,
        ];
        metrics.sort();
        assert_eq!(metrics[0], SafetyMetric::FalsePositiveRate);
        assert_eq!(metrics[4], SafetyMetric::ContainmentTime);
    }

    #[test]
    fn shadow_extension_class_ordering() {
        let mut classes = [
            ShadowExtensionClass::Critical,
            ShadowExtensionClass::LowRisk,
            ShadowExtensionClass::Standard,
            ShadowExtensionClass::HighRisk,
        ];
        classes.sort();
        assert_eq!(classes[0], ShadowExtensionClass::LowRisk);
        assert_eq!(classes[3], ShadowExtensionClass::Critical);
    }

    // -------------------------------------------------------------------
    // Enrichment: serde for struct types
    // -------------------------------------------------------------------

    #[test]
    fn update_policy_serde_roundtrip() {
        let policy = test_update_policy();
        let json = serde_json::to_string(&policy).expect("serialize");
        let restored: UpdatePolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, restored);
    }

    #[test]
    fn clipping_strategy_serde_roundtrip() {
        let strategy = test_clipping_strategy();
        let json = serde_json::to_string(&strategy).expect("serialize");
        let restored: ClippingStrategy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(strategy, restored);
    }

    #[test]
    fn aggregation_serde_roundtrip() {
        let agg = test_aggregation();
        let json = serde_json::to_string(&agg).expect("serialize");
        let restored: SecureAggregationRequirements =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(agg, restored);
    }

    #[test]
    fn retention_serde_roundtrip() {
        let ret = test_retention();
        let json = serde_json::to_string(&ret).expect("serialize");
        let restored: DataRetentionPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ret, restored);
    }

    #[test]
    fn safety_metric_snapshot_serde_roundtrip() {
        let snap = baseline_metrics();
        let json = serde_json::to_string(&snap).expect("serialize");
        let restored: SafetyMetricSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(snap, restored);
    }

    #[test]
    fn shadow_replay_reference_serde_roundtrip() {
        let rr = replay_reference();
        let json = serde_json::to_string(&rr).expect("serialize");
        let restored: ShadowReplayReference = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rr, restored);
    }

    #[test]
    fn shadow_gate_event_serde_roundtrip() {
        let event = ShadowGateEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "shadow_evaluation_gate".to_string(),
            event: "shadow_start".to_string(),
            outcome: "started".to_string(),
            error_code: Some("FE-PLC-SHADOW-0001".to_string()),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: ShadowGateEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    #[test]
    fn shadow_burn_in_scorecard_entry_serde_roundtrip() {
        let entry = ShadowBurnInScorecardEntry {
            policy_id: "p1".to_string(),
            candidate_version: "v1".to_string(),
            extension_class: ShadowExtensionClass::HighRisk,
            verdict: ShadowPromotionVerdict::Pass,
            shadow_success_rate_millionths: 998_000,
            false_deny_rate_millionths: 2_000,
            burn_in_duration_ns: 7_200_000_000_000,
            rollback_ready: true,
            burn_in_early_terminated: false,
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let restored: ShadowBurnInScorecardEntry =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(entry, restored);
    }

    #[test]
    fn replay_output_serde_roundtrip() {
        let output = ReplayOutput {
            phase_id: "noise-phase".to_string(),
            sequence_counter: 3,
            outputs: vec![100, 200, 300],
        };
        let json = serde_json::to_string(&output).expect("serialize");
        let restored: ReplayOutput = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(output, restored);
    }

    #[test]
    fn seed_escrow_access_event_serde_roundtrip() {
        let event = SeedEscrowAccessEvent {
            principal: "auditor-1".to_string(),
            reason: "investigation".to_string(),
            approved: true,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        let restored: SeedEscrowAccessEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, restored);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn compute_merkle_root_single_element_returns_leaf() {
        let leaf = hash_bytes(b"leaf-0");
        let root = compute_merkle_root(&[leaf]);
        // Single element: level.len() == 1 so loop doesn't execute
        assert_eq!(root, leaf);
    }

    #[test]
    fn compute_merkle_root_odd_elements_duplicate_last() {
        let leaves = [
            hash_bytes(b"leaf-0"),
            hash_bytes(b"leaf-1"),
            hash_bytes(b"leaf-2"),
        ];
        let root = compute_merkle_root(&leaves);
        // Level 1: hash(leaf0,leaf1), hash(leaf2,leaf2)
        let mut p01 = Vec::new();
        p01.extend_from_slice(RANDOMNESS_MERKLE_DOMAIN);
        p01.extend_from_slice(&leaves[0]);
        p01.extend_from_slice(&leaves[1]);
        let h01 = hash_bytes(&p01);
        let mut p22 = Vec::new();
        p22.extend_from_slice(RANDOMNESS_MERKLE_DOMAIN);
        p22.extend_from_slice(&leaves[2]);
        p22.extend_from_slice(&leaves[2]);
        let h22 = hash_bytes(&p22);
        // Level 2: hash(h01, h22)
        let mut final_p = Vec::new();
        final_p.extend_from_slice(RANDOMNESS_MERKLE_DOMAIN);
        final_p.extend_from_slice(&h01);
        final_p.extend_from_slice(&h22);
        let expected = hash_bytes(&final_p);
        assert_eq!(root, expected);
    }

    #[test]
    fn compute_merkle_root_empty_returns_zeros() {
        assert_eq!(compute_merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn xor_escrow_roundtrip_recovers_original() {
        let seed = b"secret-seed-data-for-testing";
        let encrypted = xor_escrow(seed);
        assert_ne!(encrypted.as_slice(), seed.as_slice());
        let decrypted = xor_escrow(&encrypted);
        assert_eq!(decrypted.as_slice(), seed.as_slice());
    }

    #[test]
    fn hash_optional_none_is_null() {
        assert_eq!(hash_optional(None), CanonicalValue::Null);
    }

    #[test]
    fn hash_optional_some_is_bytes() {
        let h = [0xAB; 32];
        let val = hash_optional(Some(h));
        assert_eq!(val, CanonicalValue::Bytes(h.to_vec()));
    }

    #[test]
    fn rollback_readiness_is_verified_ready_both_true() {
        let r = ShadowRollbackReadinessArtifacts {
            rollback_command_tested: true,
            previous_policy_snapshot_id: "snap-1".to_string(),
            transition_receipt_signed: true,
            rollback_playbook_ref: "playbook-ref".to_string(),
        };
        assert!(r.is_verified_ready());
    }

    #[test]
    fn rollback_readiness_is_verified_ready_command_not_tested() {
        let r = ShadowRollbackReadinessArtifacts {
            rollback_command_tested: false,
            previous_policy_snapshot_id: "snap-1".to_string(),
            transition_receipt_signed: true,
            rollback_playbook_ref: "playbook-ref".to_string(),
        };
        assert!(!r.is_verified_ready());
    }

    #[test]
    fn rollback_readiness_is_verified_ready_receipt_not_signed() {
        let r = ShadowRollbackReadinessArtifacts {
            rollback_command_tested: true,
            previous_policy_snapshot_id: "snap-1".to_string(),
            transition_receipt_signed: false,
            rollback_playbook_ref: "playbook-ref".to_string(),
        };
        assert!(!r.is_verified_ready());
    }

    #[test]
    fn safety_metric_higher_is_better_only_drift_detection() {
        assert!(!SafetyMetric::FalsePositiveRate.higher_is_better());
        assert!(!SafetyMetric::FalseNegativeRate.higher_is_better());
        assert!(!SafetyMetric::CalibrationError.higher_is_better());
        assert!(SafetyMetric::DriftDetectionAccuracy.higher_is_better());
        assert!(!SafetyMetric::ContainmentTime.higher_is_better());
    }

    #[test]
    fn safety_metric_snapshot_missing_key_returns_zero() {
        let snap = SafetyMetricSnapshot {
            values_millionths: BTreeMap::new(),
        };
        assert_eq!(snap.metric_value(SafetyMetric::CalibrationError), 0);
    }

    #[test]
    fn burn_in_profile_for_returns_override_when_present() {
        let custom = ShadowBurnInThresholdProfile {
            min_shadow_success_rate_millionths: 999_000,
            max_false_deny_rate_millionths: 500,
            min_burn_in_duration_ns: 100_000,
            require_verified_rollback_artifacts: true,
        };
        let mut profiles = BTreeMap::new();
        profiles.insert(ShadowExtensionClass::Critical, custom.clone());
        let config = ShadowEvaluationGateConfig {
            regression_tolerance_millionths: 5_000,
            min_required_improvement_millionths: 2_500,
            default_burn_in_profile: ShadowBurnInThresholdProfile::default(),
            burn_in_profiles_by_extension_class: profiles,
        };
        // Critical class should use override
        let profile = config.burn_in_profile_for(ShadowExtensionClass::Critical);
        assert_eq!(profile.min_shadow_success_rate_millionths, 999_000);
        // Standard class should fall back to default
        let default_profile = config.burn_in_profile_for(ShadowExtensionClass::Standard);
        assert_eq!(
            default_profile.min_shadow_success_rate_millionths,
            config
                .default_burn_in_profile
                .min_shadow_success_rate_millionths
        );
    }

    #[test]
    fn dp_budget_max_epochs_advanced_composition() {
        let budget = DpBudgetSemantics {
            epsilon_per_epoch_millionths: 100_000,
            delta_per_epoch_millionths: 10_000,
            composition_method: CompositionMethod::Advanced,
            lifetime_epsilon_budget_millionths: 1_000_000,
            lifetime_delta_budget_millionths: 1_000_000,
            fail_closed_on_exhaustion: true,
        };
        // Advanced: (lifetime/epoch)^2 = (10)^2 = 100
        // delta: 1_000_000/10_000 = 100
        // min(100, 100) = 100
        assert_eq!(budget.max_epochs(), 100);
    }

    #[test]
    fn seed_escrow_record_serde_roundtrip() {
        let record = SeedEscrowRecord {
            phase_id: "noise-phase-1".to_string(),
            epoch_id: SecurityEpoch::from_raw(5),
            seed_hash: hash_bytes(b"test-seed"),
            encrypted_seed: xor_escrow(b"test-seed"),
            authorized_auditors: BTreeSet::from([
                "auditor-alice".to_string(),
                "auditor-bob".to_string(),
            ]),
            access_log: vec![SeedEscrowAccessEvent {
                principal: "auditor-alice".to_string(),
                reason: "routine audit".to_string(),
                approved: true,
            }],
        };
        let json = serde_json::to_string(&record).expect("serialize");
        let restored: SeedEscrowRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(record, restored);
    }

    #[test]
    fn randomness_commitment_serde_roundtrip() {
        let signing_key = governance_signing_key();
        let mut transcript = RandomnessTranscript::new();
        transcript
            .commit_seed(
                &signing_key,
                "phase-serde",
                b"seed-for-serde-test",
                PrngAlgorithm::ChaCha20LikeCounter,
                SecurityEpoch::from_raw(1),
                EngineObjectId([0xDD; 32]),
            )
            .expect("commit seed");
        let commitment = &transcript.commitments[0];
        let json = serde_json::to_string(commitment).expect("serialize");
        let restored: RandomnessCommitment = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*commitment, restored);
    }

    #[test]
    fn contract_registry_serde_roundtrip() {
        let registry = ContractRegistry::new();
        let json = serde_json::to_string(&registry).expect("serialize");
        let restored: ContractRegistry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(registry.total_count(), restored.total_count());
        assert_eq!(registry.zone_count(), restored.zone_count());
    }

    #[test]
    fn shadow_gate_scorecard_entries_populated_after_evaluation() {
        let mut gate = shadow_gate();
        let contract = create_test_contract();
        let candidate = candidate_with_metrics(improved_metrics(), 90_000, 900);
        let artifact = gate
            .evaluate_candidate(&contract, candidate, &governance_signing_key())
            .expect("evaluate");
        assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);
        let scorecard = gate.scorecard_entries();
        assert_eq!(scorecard.len(), 1);
        assert_eq!(scorecard[0].policy_id, "policy-shadow-1");
        assert_eq!(scorecard[0].verdict, ShadowPromotionVerdict::Pass);
    }

    #[test]
    fn shadow_gate_active_artifact_after_promotion() {
        let mut gate = shadow_gate();
        let contract = create_test_contract();
        let candidate = candidate_with_metrics(improved_metrics(), 90_000, 900);
        let artifact = gate
            .evaluate_candidate(&contract, candidate, &governance_signing_key())
            .expect("evaluate");
        assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);
        let active = gate.active_artifact("policy-shadow-1");
        assert!(active.is_some());
        assert_eq!(active.unwrap().verdict, ShadowPromotionVerdict::Pass);
        // Non-existent policy returns None
        assert!(gate.active_artifact("nonexistent").is_none());
    }

    // -------------------------------------------------------------------
    // Enrichment: ShadowEvaluationCandidate::validate error paths
    // -------------------------------------------------------------------

    fn valid_candidate() -> ShadowEvaluationCandidate {
        candidate_with_metrics(improved_metrics(), 90_000, 900)
    }

    #[test]
    fn candidate_validate_empty_trace_id_rejected() {
        let mut c = valid_candidate();
        c.trace_id = "  ".to_string();
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    #[test]
    fn candidate_validate_empty_decision_id_rejected() {
        let mut c = valid_candidate();
        c.decision_id = "".to_string();
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    #[test]
    fn candidate_validate_empty_policy_id_rejected() {
        let mut c = valid_candidate();
        c.policy_id = "".to_string();
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    #[test]
    fn candidate_validate_empty_candidate_version_rejected() {
        let mut c = valid_candidate();
        c.candidate_version = "  ".to_string();
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    #[test]
    fn candidate_validate_empty_rollback_token_rejected() {
        let mut c = valid_candidate();
        c.rollback_token = "".to_string();
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    #[test]
    fn candidate_validate_timestamps_equal_rejected() {
        let mut c = valid_candidate();
        c.evaluation_completed_at_ns = c.shadow_started_at_ns;
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    #[test]
    fn candidate_validate_success_rate_over_million_rejected() {
        let mut c = valid_candidate();
        c.shadow_success_rate_millionths = 1_000_001;
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    #[test]
    fn candidate_validate_negative_epsilon_rejected() {
        let mut c = valid_candidate();
        c.epsilon_spent_millionths = -1;
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    #[test]
    fn candidate_validate_negative_delta_rejected() {
        let mut c = valid_candidate();
        c.delta_spent_millionths = -1;
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: ShadowReplayReference::validate error paths
    // -------------------------------------------------------------------

    #[test]
    fn replay_reference_empty_corpus_id_rejected() {
        let mut c = valid_candidate();
        c.replay_reference.replay_corpus_id = "  ".to_string();
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    #[test]
    fn replay_reference_empty_randomness_snapshot_id_rejected() {
        let mut c = valid_candidate();
        c.replay_reference.randomness_snapshot_id = "".to_string();
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    #[test]
    fn replay_reference_zero_seed_hash_rejected() {
        let mut c = valid_candidate();
        c.replay_reference.replay_seed_hash = [0u8; 32];
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: ShadowBurnInThresholdProfile::validate error paths
    // -------------------------------------------------------------------

    #[test]
    fn burn_in_profile_zero_success_rate_rejected() {
        let config = ShadowEvaluationGateConfig {
            regression_tolerance_millionths: 5_000,
            min_required_improvement_millionths: 2_500,
            default_burn_in_profile: ShadowBurnInThresholdProfile {
                min_shadow_success_rate_millionths: 0,
                max_false_deny_rate_millionths: 5_000,
                min_burn_in_duration_ns: 100,
                require_verified_rollback_artifacts: true,
            },
            burn_in_profiles_by_extension_class: BTreeMap::new(),
        };
        let result = ShadowEvaluationGate::new(config);
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    #[test]
    fn burn_in_profile_over_million_success_rate_rejected() {
        let config = ShadowEvaluationGateConfig {
            regression_tolerance_millionths: 5_000,
            min_required_improvement_millionths: 2_500,
            default_burn_in_profile: ShadowBurnInThresholdProfile {
                min_shadow_success_rate_millionths: 1_000_001,
                max_false_deny_rate_millionths: 5_000,
                min_burn_in_duration_ns: 100,
                require_verified_rollback_artifacts: true,
            },
            burn_in_profiles_by_extension_class: BTreeMap::new(),
        };
        let result = ShadowEvaluationGate::new(config);
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    #[test]
    fn burn_in_profile_zero_duration_rejected() {
        let config = ShadowEvaluationGateConfig {
            regression_tolerance_millionths: 5_000,
            min_required_improvement_millionths: 2_500,
            default_burn_in_profile: ShadowBurnInThresholdProfile {
                min_shadow_success_rate_millionths: 995_000,
                max_false_deny_rate_millionths: 5_000,
                min_burn_in_duration_ns: 0,
                require_verified_rollback_artifacts: true,
            },
            burn_in_profiles_by_extension_class: BTreeMap::new(),
        };
        let result = ShadowEvaluationGate::new(config);
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: ShadowRollbackReadinessArtifacts::validate error paths
    // -------------------------------------------------------------------

    #[test]
    fn rollback_readiness_empty_snapshot_id_rejected() {
        let mut c = valid_candidate();
        c.rollback_readiness.previous_policy_snapshot_id = "  ".to_string();
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    #[test]
    fn rollback_readiness_empty_playbook_ref_rejected() {
        let mut c = valid_candidate();
        c.rollback_readiness.rollback_playbook_ref = "".to_string();
        let mut gate = shadow_gate();
        let result = gate.evaluate_candidate(&create_test_contract(), c, &governance_signing_key());
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: SafetyMetricSnapshot::validate error path
    // -------------------------------------------------------------------

    #[test]
    fn safety_metric_snapshot_validate_missing_metric_rejected() {
        let mut snap = baseline_metrics();
        snap.values_millionths
            .remove(&SafetyMetric::CalibrationError);
        assert!(matches!(
            snap.validate(),
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: ShadowEvaluationGateConfig::validate error path
    // -------------------------------------------------------------------

    #[test]
    fn gate_config_zero_improvement_threshold_rejected() {
        let config = ShadowEvaluationGateConfig {
            regression_tolerance_millionths: 5_000,
            min_required_improvement_millionths: 0,
            default_burn_in_profile: ShadowBurnInThresholdProfile::default(),
            burn_in_profiles_by_extension_class: BTreeMap::new(),
        };
        let result = ShadowEvaluationGate::new(config);
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowEvaluation { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: shadow gate specific failure paths
    // -------------------------------------------------------------------

    #[test]
    fn shadow_gate_rejects_burn_in_duration_too_short() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let mut c = valid_candidate();
        // Make burn-in duration = 50ns, below min of 100ns
        c.shadow_started_at_ns = 1_000_000_000;
        c.evaluation_completed_at_ns = 1_000_000_050;
        let artifact = gate
            .evaluate_candidate(&contract, c, &governance_signing_key())
            .expect("evaluation should succeed");
        assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
        assert!(
            artifact
                .failure_reasons
                .iter()
                .any(|r| r.contains("burn-in duration"))
        );
    }

    #[test]
    fn shadow_gate_rejects_low_shadow_success_rate() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let mut c = valid_candidate();
        c.shadow_success_rate_millionths = 990_000; // below 995_000 threshold
        let artifact = gate
            .evaluate_candidate(&contract, c, &governance_signing_key())
            .expect("evaluation should succeed");
        assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
        assert!(
            artifact
                .failure_reasons
                .iter()
                .any(|r| r.contains("shadow success rate"))
        );
    }

    #[test]
    fn shadow_gate_rejects_high_false_deny_rate() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let mut c = valid_candidate();
        c.false_deny_rate_millionths = 6_000; // above 5_000 threshold
        let artifact = gate
            .evaluate_candidate(&contract, c, &governance_signing_key())
            .expect("evaluation should succeed");
        assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
        assert!(artifact.burn_in_early_terminated);
        assert!(
            artifact
                .failure_reasons
                .iter()
                .any(|r| r.contains("false-deny rate"))
        );
    }

    #[test]
    fn shadow_gate_rejects_unverified_rollback_artifacts() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let mut c = valid_candidate();
        c.rollback_readiness.rollback_command_tested = false;
        c.rollback_readiness.transition_receipt_signed = false;
        let artifact = gate
            .evaluate_candidate(&contract, c, &governance_signing_key())
            .expect("evaluation should succeed");
        assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
        assert!(
            artifact
                .failure_reasons
                .iter()
                .any(|r| r.contains("rollback readiness"))
        );
    }

    // -------------------------------------------------------------------
    // Enrichment: shadow gate drain_events
    // -------------------------------------------------------------------

    #[test]
    fn shadow_gate_drain_events_clears_and_returns() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        gate.evaluate_candidate(&contract, valid_candidate(), &governance_signing_key())
            .expect("evaluate");
        let events = gate.drain_events();
        assert!(!events.is_empty());
        assert!(gate.events().is_empty());
    }

    // -------------------------------------------------------------------
    // Enrichment: post-deployment pass path (no regression)
    // -------------------------------------------------------------------

    #[test]
    fn post_deployment_metrics_pass_when_no_regression() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let artifact = gate
            .evaluate_candidate(&contract, valid_candidate(), &governance_signing_key())
            .expect("evaluate");
        assert_eq!(artifact.verdict, ShadowPromotionVerdict::Pass);

        // Post-deployment metrics same as candidate (no regression)
        let receipt = gate
            .evaluate_post_deployment_metrics(
                &artifact,
                improved_metrics(),
                &governance_signing_key(),
            )
            .expect("post deployment check");
        assert!(
            receipt.is_none(),
            "no rollback expected when metrics stable"
        );
        assert!(gate.active_artifact("policy-shadow-1").is_some());
    }

    // -------------------------------------------------------------------
    // Enrichment: DeterministicPrng::draw_counter tracks draws
    // -------------------------------------------------------------------

    #[test]
    fn deterministic_prng_draw_counter_increments() {
        let mut prng = DeterministicPrng::new(
            "counter-test",
            PrngAlgorithm::ChaCha20LikeCounter,
            b"test-seed",
        )
        .expect("prng");
        assert_eq!(prng.draw_counter(), 0);
        prng.next_u64();
        assert_eq!(prng.draw_counter(), 1);
        prng.next_u64();
        prng.next_u64();
        assert_eq!(prng.draw_counter(), 3);
    }

    // -------------------------------------------------------------------
    // Enrichment: SeedEscrowRecord success and error paths
    // -------------------------------------------------------------------

    #[test]
    fn seed_escrow_open_for_audit_authorized_returns_seed() {
        let mut auditors = BTreeSet::new();
        auditors.insert("trusted-auditor".to_string());
        let mut escrow = SeedEscrowRecord::create(
            "test-phase",
            SecurityEpoch::from_raw(3),
            b"secret-seed",
            auditors,
        )
        .expect("escrow");
        let seed = escrow
            .open_for_audit("trusted-auditor", "routine check")
            .expect("access should be granted");
        assert_eq!(seed.as_slice(), b"secret-seed");
        assert_eq!(escrow.access_log.len(), 1);
        assert!(escrow.access_log[0].approved);
    }

    #[test]
    fn seed_escrow_create_empty_phase_id_rejected() {
        let auditors = BTreeSet::from(["a".to_string()]);
        let result = SeedEscrowRecord::create("  ", SecurityEpoch::from_raw(1), b"seed", auditors);
        assert!(matches!(
            result,
            Err(ContractError::InvalidRandomnessTranscript { .. })
        ));
    }

    #[test]
    fn seed_escrow_create_empty_seed_rejected() {
        let auditors = BTreeSet::from(["a".to_string()]);
        let result = SeedEscrowRecord::create("phase", SecurityEpoch::from_raw(1), b"", auditors);
        assert!(matches!(
            result,
            Err(ContractError::InvalidRandomnessTranscript { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: HumanOverrideJustificationArtifact error paths
    // -------------------------------------------------------------------

    #[test]
    fn human_override_empty_operator_id_rejected() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let rejected = gate
            .evaluate_candidate(
                &contract,
                candidate_with_metrics(regressed_metrics(), 90_000, 900),
                &governance_signing_key(),
            )
            .expect("evaluation");
        assert_eq!(rejected.verdict, ShadowPromotionVerdict::Reject);

        let result = gate.apply_human_override(
            &rejected,
            HumanOverrideRequest {
                operator_id: "  ".to_string(),
                summary: "valid summary".to_string(),
                bypassed_risk_criteria: vec!["criterion-1".to_string()],
                acknowledged_bypass: true,
            },
            &governance_signing_key(),
        );
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowOverride { .. })
        ));
    }

    #[test]
    fn human_override_empty_summary_rejected() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let rejected = gate
            .evaluate_candidate(
                &contract,
                candidate_with_metrics(regressed_metrics(), 90_000, 900),
                &governance_signing_key(),
            )
            .expect("evaluation");

        let result = gate.apply_human_override(
            &rejected,
            HumanOverrideRequest {
                operator_id: "op-1".to_string(),
                summary: "".to_string(),
                bypassed_risk_criteria: vec!["criterion-1".to_string()],
                acknowledged_bypass: true,
            },
            &governance_signing_key(),
        );
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowOverride { .. })
        ));
    }

    #[test]
    fn human_override_empty_criteria_rejected() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let rejected = gate
            .evaluate_candidate(
                &contract,
                candidate_with_metrics(regressed_metrics(), 90_000, 900),
                &governance_signing_key(),
            )
            .expect("evaluation");

        let result = gate.apply_human_override(
            &rejected,
            HumanOverrideRequest {
                operator_id: "op-1".to_string(),
                summary: "valid".to_string(),
                bypassed_risk_criteria: vec![],
                acknowledged_bypass: true,
            },
            &governance_signing_key(),
        );
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowOverride { .. })
        ));
    }

    #[test]
    fn human_override_not_acknowledged_rejected() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let rejected = gate
            .evaluate_candidate(
                &contract,
                candidate_with_metrics(regressed_metrics(), 90_000, 900),
                &governance_signing_key(),
            )
            .expect("evaluation");

        let result = gate.apply_human_override(
            &rejected,
            HumanOverrideRequest {
                operator_id: "op-1".to_string(),
                summary: "valid".to_string(),
                bypassed_risk_criteria: vec!["criterion-1".to_string()],
                acknowledged_bypass: false,
            },
            &governance_signing_key(),
        );
        assert!(matches!(
            result,
            Err(ContractError::InvalidShadowOverride { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: ShadowPromotionDecisionArtifact unsigned_view determinism
    // -------------------------------------------------------------------

    #[test]
    fn shadow_promotion_artifact_unsigned_view_is_deterministic() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let artifact = gate
            .evaluate_candidate(&contract, valid_candidate(), &governance_signing_key())
            .expect("evaluate");
        let view1 = artifact.unsigned_view();
        let view2 = artifact.unsigned_view();
        assert_eq!(view1, view2);
    }

    // -------------------------------------------------------------------
    // Enrichment: ShadowPromotionDecisionArtifact serde roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn shadow_promotion_decision_artifact_serde_roundtrip() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let artifact = gate
            .evaluate_candidate(&contract, valid_candidate(), &governance_signing_key())
            .expect("evaluate");
        let json = serde_json::to_string(&artifact).expect("serialize");
        let restored: ShadowPromotionDecisionArtifact =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(artifact, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: ShadowRollbackIncidentReceipt serde roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn shadow_rollback_incident_receipt_serde_roundtrip() {
        let contract = create_test_contract();
        let mut gate = shadow_gate();
        let artifact = gate
            .evaluate_candidate(&contract, valid_candidate(), &governance_signing_key())
            .expect("evaluate");
        let receipt = gate
            .evaluate_post_deployment_metrics(
                &artifact,
                regressed_metrics(),
                &governance_signing_key(),
            )
            .expect("post check")
            .expect("rollback receipt");
        let json = serde_json::to_string(&receipt).expect("serialize");
        let restored: ShadowRollbackIncidentReceipt =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: RandomnessSnapshotSummary serde roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn randomness_snapshot_summary_serde_roundtrip() {
        let sk = governance_signing_key();
        let mut transcript = RandomnessTranscript::new();
        transcript
            .commit_seed(
                &sk,
                "phase-serde-snap",
                b"snap-seed",
                PrngAlgorithm::ChaCha20LikeCounter,
                SecurityEpoch::from_raw(1),
                EngineObjectId([0xEE; 32]),
            )
            .expect("commit");
        transcript
            .emit_snapshot_summary(&sk, "model-1", "policy-1")
            .expect("summary");
        let summary = &transcript.snapshot_summaries[0];
        let json = serde_json::to_string(summary).expect("serialize");
        let restored: RandomnessSnapshotSummary = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*summary, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: RandomnessTranscript serde roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn randomness_transcript_serde_roundtrip() {
        let sk = governance_signing_key();
        let mut transcript = RandomnessTranscript::new();
        transcript
            .commit_seed(
                &sk,
                "phase-rt",
                b"seed-rt",
                PrngAlgorithm::ChaCha20LikeCounter,
                SecurityEpoch::from_raw(2),
                EngineObjectId([0xCC; 32]),
            )
            .expect("commit");
        let json = serde_json::to_string(&transcript).expect("serialize");
        let restored: RandomnessTranscript = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(transcript, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: PrivacyLearningContract preimage_bytes determinism
    // -------------------------------------------------------------------

    #[test]
    fn contract_preimage_bytes_deterministic() {
        let c = create_test_contract();
        let p1 = c.preimage_bytes();
        let p2 = c.preimage_bytes();
        assert_eq!(p1, p2);
        assert!(!p1.is_empty());
    }

    // -------------------------------------------------------------------
    // Enrichment: PrivacyLearningContract build_unsigned_view determinism
    // -------------------------------------------------------------------

    #[test]
    fn contract_build_unsigned_view_deterministic() {
        let c = create_test_contract();
        let v1 = c.build_unsigned_view();
        let v2 = c.build_unsigned_view();
        assert_eq!(v1, v2);
    }

    // -------------------------------------------------------------------
    // Enrichment: commit_seed error paths
    // -------------------------------------------------------------------

    #[test]
    fn commit_seed_empty_phase_id_rejected() {
        let mut transcript = RandomnessTranscript::new();
        let result = transcript.commit_seed(
            &governance_signing_key(),
            "  ",
            b"seed",
            PrngAlgorithm::ChaCha20LikeCounter,
            SecurityEpoch::from_raw(1),
            EngineObjectId([0x01; 32]),
        );
        assert!(matches!(
            result,
            Err(ContractError::InvalidRandomnessTranscript { .. })
        ));
    }

    #[test]
    fn commit_seed_empty_seed_rejected() {
        let mut transcript = RandomnessTranscript::new();
        let result = transcript.commit_seed(
            &governance_signing_key(),
            "phase",
            b"",
            PrngAlgorithm::ChaCha20LikeCounter,
            SecurityEpoch::from_raw(1),
            EngineObjectId([0x01; 32]),
        );
        assert!(matches!(
            result,
            Err(ContractError::InvalidRandomnessTranscript { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: emit_snapshot_summary error paths
    // -------------------------------------------------------------------

    #[test]
    fn emit_snapshot_summary_empty_model_id_rejected() {
        let sk = governance_signing_key();
        let mut transcript = RandomnessTranscript::new();
        transcript
            .commit_seed(
                &sk,
                "phase",
                b"seed",
                PrngAlgorithm::ChaCha20LikeCounter,
                SecurityEpoch::from_raw(1),
                EngineObjectId([0x01; 32]),
            )
            .expect("commit");
        let result = transcript.emit_snapshot_summary(&sk, "  ", "policy-1");
        assert!(matches!(
            result,
            Err(ContractError::InvalidRandomnessTranscript { .. })
        ));
    }

    #[test]
    fn emit_snapshot_summary_no_commitments_rejected() {
        let sk = governance_signing_key();
        let mut transcript = RandomnessTranscript::new();
        let result = transcript.emit_snapshot_summary(&sk, "model-1", "policy-1");
        assert!(matches!(
            result,
            Err(ContractError::InvalidRandomnessTranscript { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: ShadowMetricAssessment serde roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn shadow_metric_assessment_serde_roundtrip() {
        let assessment = ShadowMetricAssessment {
            baseline_value_millionths: 100_000,
            candidate_value_millionths: 95_000,
            improvement_millionths: 5_000,
            regressed: false,
            significant_improvement: true,
        };
        let json = serde_json::to_string(&assessment).expect("serialize");
        let restored: ShadowMetricAssessment = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(assessment, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: ShadowPrivacyBudgetStatus serde roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn shadow_privacy_budget_status_serde_roundtrip() {
        let status = ShadowPrivacyBudgetStatus {
            epsilon_spent_millionths: 50_000,
            epsilon_limit_millionths: 100_000,
            delta_spent_millionths: 500,
            delta_limit_millionths: 1_000,
            within_budget: true,
        };
        let json = serde_json::to_string(&status).expect("serialize");
        let restored: ShadowPrivacyBudgetStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: HumanOverrideRequest serde roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn human_override_request_serde_roundtrip() {
        let request = HumanOverrideRequest {
            operator_id: "op-1".to_string(),
            summary: "manual promotion".to_string(),
            bypassed_risk_criteria: vec!["cr-1".to_string(), "cr-2".to_string()],
            acknowledged_bypass: true,
        };
        let json = serde_json::to_string(&request).expect("serialize");
        let restored: HumanOverrideRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(request, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: ShadowEvaluationCandidate serde roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn shadow_evaluation_candidate_serde_roundtrip() {
        let candidate = valid_candidate();
        let json = serde_json::to_string(&candidate).expect("serialize");
        let restored: ShadowEvaluationCandidate = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(candidate, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: ShadowRollbackReadinessArtifacts serde roundtrip
    // -------------------------------------------------------------------

    #[test]
    fn shadow_rollback_readiness_serde_roundtrip() {
        let r = rollback_readiness();
        let json = serde_json::to_string(&r).expect("serialize");
        let restored: ShadowRollbackReadinessArtifacts =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(r, restored);
    }

    // -------------------------------------------------------------------
    // Enrichment: DataRetentionPolicy zero snapshot_retention rejected
    // -------------------------------------------------------------------

    #[test]
    fn retention_zero_snapshot_rejected() {
        let mut ret = test_retention();
        ret.max_snapshot_retention = 0;
        assert!(matches!(
            ret.validate(),
            Err(ContractError::InvalidRetention { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: DpBudget delta_epoch > delta_lifetime rejected
    // -------------------------------------------------------------------

    #[test]
    fn dp_budget_delta_epoch_exceeds_lifetime_rejected() {
        let mut budget = test_dp_budget();
        budget.delta_per_epoch_millionths = budget.lifetime_delta_budget_millionths + 1;
        assert!(matches!(
            budget.validate(),
            Err(ContractError::InvalidDpBudget { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Enrichment: DpBudget zero lifetime epsilon rejected
    // -------------------------------------------------------------------

    #[test]
    fn dp_budget_zero_lifetime_epsilon_rejected() {
        let mut budget = test_dp_budget();
        budget.lifetime_epsilon_budget_millionths = 0;
        // This should fail since epsilon_per_epoch > lifetime
        assert!(budget.validate().is_err());
    }

    // -------------------------------------------------------------------
    // Enrichment: ShadowEvaluationGate evaluate with extension class override
    // -------------------------------------------------------------------

    #[test]
    fn shadow_gate_uses_extension_class_burn_in_override() {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            ShadowExtensionClass::Critical,
            ShadowBurnInThresholdProfile {
                min_shadow_success_rate_millionths: 999_000,
                max_false_deny_rate_millionths: 500,
                min_burn_in_duration_ns: 50,
                require_verified_rollback_artifacts: true,
            },
        );
        let config = ShadowEvaluationGateConfig {
            regression_tolerance_millionths: 5_000,
            min_required_improvement_millionths: 2_500,
            default_burn_in_profile: ShadowBurnInThresholdProfile {
                min_shadow_success_rate_millionths: 995_000,
                max_false_deny_rate_millionths: 5_000,
                min_burn_in_duration_ns: 100,
                require_verified_rollback_artifacts: true,
            },
            burn_in_profiles_by_extension_class: profiles,
        };
        let mut gate = ShadowEvaluationGate::new(config).expect("gate");
        let contract = create_test_contract();
        let mut c = valid_candidate();
        c.extension_class = ShadowExtensionClass::Critical;
        c.shadow_success_rate_millionths = 998_000; // below 999_000 critical threshold
        let artifact = gate
            .evaluate_candidate(&contract, c, &governance_signing_key())
            .expect("evaluate");
        assert_eq!(artifact.verdict, ShadowPromotionVerdict::Reject);
        assert!(
            artifact
                .failure_reasons
                .iter()
                .any(|r| r.contains("shadow success rate"))
        );
        assert_eq!(
            artifact.burn_in_profile.min_shadow_success_rate_millionths,
            999_000
        );
    }
}
