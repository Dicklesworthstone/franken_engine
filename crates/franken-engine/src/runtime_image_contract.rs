//! Immutable runtime images, prewarmed snapshot contracts, and zygote/COW
//! warm-start lane abstractions for cold-start supremacy.
//!
//! This module defines the contract surface for building, registering,
//! evicting, and selecting immutable runtime images.  Each image captures a
//! deterministic snapshot of compiled or pre-warmed module state that can be
//! restored to eliminate cold-start latency.
//!
//! Plan references: Section 7.10 (RGC-610D), bead bd-1lsy.7.10.4.

#![forbid(unsafe_code)]

use std::fmt;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, SchemaHash};
use crate::engine_object_id::ObjectDomain;
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::{
    SIGNATURE_SENTINEL, Signature, SignaturePreimage, SigningKey, VerificationKey, sign_object,
    verify_object,
};

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

/// Schema version for the runtime image contract envelope.
pub const RUNTIME_IMAGE_SCHEMA_VERSION: &str = "franken-engine.runtime-image-contract.v1";

/// Schema version for signed runtime image acceptance envelopes.
pub const SIGNED_RUNTIME_IMAGE_SCHEMA_VERSION: &str =
    "franken-engine.signed-runtime-image-manifest.v1";

/// Bead identifier originating this module.
pub const RUNTIME_IMAGE_BEAD_ID: &str = "bd-1lsy.7.10.4";

const SIGNED_RUNTIME_IMAGE_SCHEMA_DEF: &[u8] = b"franken-engine.signed-runtime-image-manifest.v1";

// ---------------------------------------------------------------------------
// ImageKind
// ---------------------------------------------------------------------------

/// Discriminant for the kind of runtime image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ImageKind {
    /// Unoptimised baseline snapshot captured after initial module loading.
    Baseline,
    /// Snapshot captured after warming (e.g. running initialisation code).
    Prewarmed,
    /// Zygote image: a fork-ready parent process snapshot.
    Zygote,
    /// Ahead-of-time compiled image ready for direct mapping.
    AotCompiled,
    /// Opaque cached snapshot from a previous run.
    CachedSnapshot,
}

impl ImageKind {
    /// All variants for exhaustive iteration.
    pub const ALL: &'static [ImageKind] = &[
        ImageKind::Baseline,
        ImageKind::Prewarmed,
        ImageKind::Zygote,
        ImageKind::AotCompiled,
        ImageKind::CachedSnapshot,
    ];
}

impl fmt::Display for ImageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Baseline => write!(f, "Baseline"),
            Self::Prewarmed => write!(f, "Prewarmed"),
            Self::Zygote => write!(f, "Zygote"),
            Self::AotCompiled => write!(f, "AotCompiled"),
            Self::CachedSnapshot => write!(f, "CachedSnapshot"),
        }
    }
}

// ---------------------------------------------------------------------------
// ImageState
// ---------------------------------------------------------------------------

/// Lifecycle state of a runtime image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ImageState {
    /// Image is currently being assembled.
    Building,
    /// Image is ready for use.
    Ready,
    /// Image is usable but its source has changed; a rebuild is advised.
    Stale,
    /// Image has been explicitly invalidated and must not be used.
    Invalidated,
    /// Image creation is disabled by policy.
    Disabled,
}

impl ImageState {
    /// All variants for exhaustive iteration.
    pub const ALL: &'static [ImageState] = &[
        ImageState::Building,
        ImageState::Ready,
        ImageState::Stale,
        ImageState::Invalidated,
        ImageState::Disabled,
    ];
}

impl fmt::Display for ImageState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Building => write!(f, "Building"),
            Self::Ready => write!(f, "Ready"),
            Self::Stale => write!(f, "Stale"),
            Self::Invalidated => write!(f, "Invalidated"),
            Self::Disabled => write!(f, "Disabled"),
        }
    }
}

// ---------------------------------------------------------------------------
// WarmStartMode
// ---------------------------------------------------------------------------

/// Strategy used to warm-start an engine instance from an image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WarmStartMode {
    /// No warm-start; full cold initialisation.
    Cold,
    /// Fork from a zygote process image.
    ZygoteFork,
    /// Copy-on-write snapshot restore.
    CowSnapshot,
    /// Draw from a pool of pre-warmed instances.
    PrewarmedPool,
    /// Restore from an ahead-of-time compiled artifact.
    AotRestore,
}

impl WarmStartMode {
    /// All variants for exhaustive iteration.
    pub const ALL: &'static [WarmStartMode] = &[
        WarmStartMode::Cold,
        WarmStartMode::ZygoteFork,
        WarmStartMode::CowSnapshot,
        WarmStartMode::PrewarmedPool,
        WarmStartMode::AotRestore,
    ];
}

impl fmt::Display for WarmStartMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cold => write!(f, "Cold"),
            Self::ZygoteFork => write!(f, "ZygoteFork"),
            Self::CowSnapshot => write!(f, "CowSnapshot"),
            Self::PrewarmedPool => write!(f, "PrewarmedPool"),
            Self::AotRestore => write!(f, "AotRestore"),
        }
    }
}

// ---------------------------------------------------------------------------
// ImageIntegrityStatus
// ---------------------------------------------------------------------------

/// Result of an integrity check on a runtime image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ImageIntegrityStatus {
    /// Image integrity has been cryptographically verified.
    Verified,
    /// No integrity check has been performed yet.
    Unverified,
    /// Corruption was detected during verification.
    CorruptionDetected,
    /// The image has exceeded its time-to-live.
    Expired,
}

impl ImageIntegrityStatus {
    /// All variants for exhaustive iteration.
    pub const ALL: &'static [ImageIntegrityStatus] = &[
        ImageIntegrityStatus::Verified,
        ImageIntegrityStatus::Unverified,
        ImageIntegrityStatus::CorruptionDetected,
        ImageIntegrityStatus::Expired,
    ];
}

impl fmt::Display for ImageIntegrityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified => write!(f, "Verified"),
            Self::Unverified => write!(f, "Unverified"),
            Self::CorruptionDetected => write!(f, "CorruptionDetected"),
            Self::Expired => write!(f, "Expired"),
        }
    }
}

// ---------------------------------------------------------------------------
// ImageManifest
// ---------------------------------------------------------------------------

/// Manifest describing a single immutable runtime image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageManifest {
    /// Unique identifier for this image.
    pub image_id: String,
    /// Kind of runtime image.
    pub kind: ImageKind,
    /// Current lifecycle state.
    pub state: ImageState,
    /// Epoch at which the image was created.
    pub creation_epoch: SecurityEpoch,
    /// Hash of the source modules that were snapshotted.
    pub source_hash: ContentHash,
    /// Hash of the image content itself.
    pub image_hash: ContentHash,
    /// Number of modules captured in this image.
    pub module_count: u64,
    /// Total size of the image in bytes.
    pub total_size_bytes: u64,
    /// Warm-start strategy associated with this image.
    pub warm_start_mode: WarmStartMode,
    /// Integrity verification status.
    pub integrity_status: ImageIntegrityStatus,
    /// Optional time-to-live in seconds; `None` means no expiry.
    pub ttl_seconds: Option<u64>,
    /// Human-readable reason the image was created.
    pub creation_reason: String,
}

fn signed_runtime_image_schema() -> &'static SchemaHash {
    static HASH: LazyLock<SchemaHash> =
        LazyLock::new(|| SchemaHash::from_definition(SIGNED_RUNTIME_IMAGE_SCHEMA_DEF));
    &HASH
}

// ---------------------------------------------------------------------------
// SignedRuntimeImageManifest
// ---------------------------------------------------------------------------

/// Signed runtime-image acceptance envelope.
///
/// This wrapper is the security boundary for using an [`ImageManifest`] as a
/// runtime decision input. It binds the image manifest to an explicit epoch
/// validity window and revocation/checkpoint frontier before signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRuntimeImageManifest {
    /// Schema version tag for this signed envelope.
    pub schema_version: String,
    /// Runtime image manifest being accepted.
    pub manifest: ImageManifest,
    /// First epoch at which this image may be accepted.
    pub valid_from_epoch: SecurityEpoch,
    /// Last epoch at which this image may be accepted; `None` means open-ended.
    pub valid_until_epoch: Option<SecurityEpoch>,
    /// Trust frontier the image was built against.
    pub frontier_epoch: SecurityEpoch,
    /// Signer expected to authenticate this envelope.
    pub signer: VerificationKey,
    /// Signature over the unsigned view of this envelope.
    pub signature: Signature,
}

/// Verifier-supplied runtime image acceptance context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeImageAcceptanceContext {
    /// Authoritative current runtime epoch.
    pub current_epoch: SecurityEpoch,
    /// Highest durable policy/revocation frontier accepted by the verifier.
    pub accepted_frontier_epoch: SecurityEpoch,
    /// Signers trusted to authorize runtime image manifests.
    pub trusted_signers: Vec<VerificationKey>,
}

impl RuntimeImageAcceptanceContext {
    /// Build an explicit acceptance context for signed runtime image checks.
    pub fn new(
        current_epoch: SecurityEpoch,
        accepted_frontier_epoch: SecurityEpoch,
        trusted_signers: Vec<VerificationKey>,
    ) -> Self {
        Self {
            current_epoch,
            accepted_frontier_epoch,
            trusted_signers,
        }
    }
}

/// Fail-closed errors from signed runtime image acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeImageAcceptanceError {
    /// No trusted image signing keys were supplied.
    EmptyTrustedSignerSet,
    /// Envelope signer is not trusted by the verifier.
    UntrustedSigner { signer: VerificationKey },
    /// Envelope signature is absent.
    MissingSignature,
    /// Envelope signature verification failed.
    SignatureInvalid { detail: String },
    /// Validity window is inverted.
    InvalidValidityWindow {
        valid_from_epoch: SecurityEpoch,
        valid_until_epoch: SecurityEpoch,
    },
    /// Current epoch is before the artifact validity window.
    NotYetValid {
        current_epoch: SecurityEpoch,
        valid_from_epoch: SecurityEpoch,
    },
    /// Current epoch is after the artifact validity window.
    Expired {
        current_epoch: SecurityEpoch,
        valid_until_epoch: SecurityEpoch,
    },
    /// Artifact is bound to a future frontier.
    FutureFrontier {
        current_epoch: SecurityEpoch,
        frontier_epoch: SecurityEpoch,
    },
    /// Artifact is bound to a frontier older than the verifier's durable frontier.
    FrontierRegression {
        accepted_frontier_epoch: SecurityEpoch,
        artifact_frontier_epoch: SecurityEpoch,
    },
}

impl fmt::Display for RuntimeImageAcceptanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTrustedSignerSet => write!(f, "no trusted runtime image signers supplied"),
            Self::UntrustedSigner { signer } => {
                write!(f, "runtime image signer is not trusted: {signer}")
            }
            Self::MissingSignature => write!(f, "runtime image signature is missing"),
            Self::SignatureInvalid { detail } => {
                write!(f, "runtime image signature verification failed: {detail}")
            }
            Self::InvalidValidityWindow {
                valid_from_epoch,
                valid_until_epoch,
            } => write!(
                f,
                "invalid runtime image validity window: {valid_from_epoch} > {valid_until_epoch}"
            ),
            Self::NotYetValid {
                current_epoch,
                valid_from_epoch,
            } => write!(
                f,
                "runtime image is not yet valid: current {current_epoch} < valid_from {valid_from_epoch}"
            ),
            Self::Expired {
                current_epoch,
                valid_until_epoch,
            } => write!(
                f,
                "runtime image is expired: current {current_epoch} > valid_until {valid_until_epoch}"
            ),
            Self::FutureFrontier {
                current_epoch,
                frontier_epoch,
            } => write!(
                f,
                "runtime image frontier is in the future: current {current_epoch} < frontier {frontier_epoch}"
            ),
            Self::FrontierRegression {
                accepted_frontier_epoch,
                artifact_frontier_epoch,
            } => write!(
                f,
                "runtime image frontier regressed: accepted {accepted_frontier_epoch} > artifact {artifact_frontier_epoch}"
            ),
        }
    }
}

impl std::error::Error for RuntimeImageAcceptanceError {}

impl SignaturePreimage for SignedRuntimeImageManifest {
    fn signature_domain(&self) -> ObjectDomain {
        ObjectDomain::SignedManifest
    }

    fn signature_schema(&self) -> &SchemaHash {
        signed_runtime_image_schema()
    }

    fn unsigned_view(&self) -> CanonicalValue {
        let mut copy = self.clone();
        copy.signature = Signature::from_bytes(SIGNATURE_SENTINEL);
        CanonicalValue::Bytes(
            serde_json::to_vec(&copy).expect("signed runtime image should serialize"),
        )
    }
}

impl SignedRuntimeImageManifest {
    /// Create and sign a runtime image envelope.
    pub fn sign(
        manifest: ImageManifest,
        valid_from_epoch: SecurityEpoch,
        valid_until_epoch: Option<SecurityEpoch>,
        frontier_epoch: SecurityEpoch,
        signing_key: &SigningKey,
    ) -> Result<Self, crate::signature_preimage::SignatureError> {
        let signer = signing_key.verification_key();
        let mut envelope = Self {
            schema_version: SIGNED_RUNTIME_IMAGE_SCHEMA_VERSION.to_owned(),
            manifest,
            valid_from_epoch,
            valid_until_epoch,
            frontier_epoch,
            signer,
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        envelope.signature = sign_object(&envelope, signing_key)?;
        Ok(envelope)
    }

    /// Verify the envelope signature and epoch/frontier acceptance context.
    pub fn verify_for_acceptance(
        &self,
        context: &RuntimeImageAcceptanceContext,
    ) -> Result<&ImageManifest, RuntimeImageAcceptanceError> {
        self.verify_epoch_window(context.current_epoch)?;
        self.verify_frontier(context)?;
        self.verify_signature(context)?;
        Ok(&self.manifest)
    }

    fn verify_epoch_window(
        &self,
        current_epoch: SecurityEpoch,
    ) -> Result<(), RuntimeImageAcceptanceError> {
        if let Some(valid_until_epoch) = self.valid_until_epoch {
            if valid_until_epoch.as_u64() < self.valid_from_epoch.as_u64() {
                return Err(RuntimeImageAcceptanceError::InvalidValidityWindow {
                    valid_from_epoch: self.valid_from_epoch,
                    valid_until_epoch,
                });
            }
            if current_epoch.as_u64() > valid_until_epoch.as_u64() {
                return Err(RuntimeImageAcceptanceError::Expired {
                    current_epoch,
                    valid_until_epoch,
                });
            }
        }
        if current_epoch.as_u64() < self.valid_from_epoch.as_u64() {
            return Err(RuntimeImageAcceptanceError::NotYetValid {
                current_epoch,
                valid_from_epoch: self.valid_from_epoch,
            });
        }
        Ok(())
    }

    fn verify_frontier(
        &self,
        context: &RuntimeImageAcceptanceContext,
    ) -> Result<(), RuntimeImageAcceptanceError> {
        if self.frontier_epoch.as_u64() > context.current_epoch.as_u64() {
            return Err(RuntimeImageAcceptanceError::FutureFrontier {
                current_epoch: context.current_epoch,
                frontier_epoch: self.frontier_epoch,
            });
        }
        if self.frontier_epoch.as_u64() < context.accepted_frontier_epoch.as_u64() {
            return Err(RuntimeImageAcceptanceError::FrontierRegression {
                accepted_frontier_epoch: context.accepted_frontier_epoch,
                artifact_frontier_epoch: self.frontier_epoch,
            });
        }
        Ok(())
    }

    fn verify_signature(
        &self,
        context: &RuntimeImageAcceptanceContext,
    ) -> Result<(), RuntimeImageAcceptanceError> {
        if context.trusted_signers.is_empty() {
            return Err(RuntimeImageAcceptanceError::EmptyTrustedSignerSet);
        }
        if !context.trusted_signers.contains(&self.signer) {
            return Err(RuntimeImageAcceptanceError::UntrustedSigner {
                signer: self.signer.clone(),
            });
        }
        if self.signature.is_sentinel() {
            return Err(RuntimeImageAcceptanceError::MissingSignature);
        }
        verify_object(self, &self.signer, &self.signature).map_err(|error| {
            RuntimeImageAcceptanceError::SignatureInvalid {
                detail: error.to_string(),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// ImagePolicy
// ---------------------------------------------------------------------------

/// Policy governing image creation, retention, and capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImagePolicy {
    /// Maximum number of images that may exist simultaneously.
    pub max_image_count: u64,
    /// Maximum aggregate bytes across all images.
    pub max_total_bytes: u64,
    /// Default TTL (seconds) applied to newly created images.
    pub default_ttl_seconds: u64,
    /// Whether zygote-based images are permitted.
    pub allow_zygote: bool,
    /// Whether COW snapshot images are permitted.
    pub allow_cow: bool,
    /// Whether AOT-compiled images are permitted.
    pub allow_aot: bool,
    /// Whether an integrity check is required before using an image.
    pub require_integrity_check: bool,
    /// Minimum module count before an image is worth creating.
    pub min_module_count_for_image: u64,
}

impl Default for ImagePolicy {
    fn default() -> Self {
        Self {
            max_image_count: 16,
            max_total_bytes: 512 * 1024 * 1024, // 512 MiB
            default_ttl_seconds: 3600,
            allow_zygote: true,
            allow_cow: true,
            allow_aot: true,
            require_integrity_check: true,
            min_module_count_for_image: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// ImageEvictionReason
// ---------------------------------------------------------------------------

/// Reason an image was evicted from the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ImageEvictionReason {
    /// The image's TTL expired.
    TtlExpired,
    /// The source modules changed, invalidating the image.
    SourceChanged,
    /// The registry is at capacity; oldest image evicted.
    CapacityExceeded,
    /// Integrity verification failed.
    IntegrityFailure,
    /// The policy now disables this image kind.
    PolicyDisabled,
    /// An operator triggered manual eviction.
    ManualEviction,
}

impl ImageEvictionReason {
    /// All variants for exhaustive iteration.
    pub const ALL: &'static [ImageEvictionReason] = &[
        ImageEvictionReason::TtlExpired,
        ImageEvictionReason::SourceChanged,
        ImageEvictionReason::CapacityExceeded,
        ImageEvictionReason::IntegrityFailure,
        ImageEvictionReason::PolicyDisabled,
        ImageEvictionReason::ManualEviction,
    ];
}

impl fmt::Display for ImageEvictionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TtlExpired => write!(f, "TtlExpired"),
            Self::SourceChanged => write!(f, "SourceChanged"),
            Self::CapacityExceeded => write!(f, "CapacityExceeded"),
            Self::IntegrityFailure => write!(f, "IntegrityFailure"),
            Self::PolicyDisabled => write!(f, "PolicyDisabled"),
            Self::ManualEviction => write!(f, "ManualEviction"),
        }
    }
}

// ---------------------------------------------------------------------------
// ImageEvictionRecord
// ---------------------------------------------------------------------------

/// Record documenting a single image eviction event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageEvictionRecord {
    /// Identifier of the evicted image.
    pub image_id: String,
    /// Why the image was evicted.
    pub reason: ImageEvictionReason,
    /// Epoch at which the eviction occurred.
    pub evicted_epoch: SecurityEpoch,
    /// Number of bytes freed by this eviction.
    pub bytes_freed: u64,
}

// ---------------------------------------------------------------------------
// ImageSpecimenFamily
// ---------------------------------------------------------------------------

/// Specimen family classifier for test/evidence generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ImageSpecimenFamily {
    /// Baseline image specimens.
    Baseline,
    /// Prewarmed image specimens.
    Prewarmed,
    /// Zygote image specimens.
    Zygote,
    /// AOT-compiled image specimens.
    Aot,
    /// Eviction-related specimens.
    Eviction,
    /// Mixed / cross-cutting specimens.
    Mixed,
}

impl ImageSpecimenFamily {
    /// All variants for exhaustive iteration.
    pub const ALL: &'static [ImageSpecimenFamily] = &[
        ImageSpecimenFamily::Baseline,
        ImageSpecimenFamily::Prewarmed,
        ImageSpecimenFamily::Zygote,
        ImageSpecimenFamily::Aot,
        ImageSpecimenFamily::Eviction,
        ImageSpecimenFamily::Mixed,
    ];
}

impl fmt::Display for ImageSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Baseline => write!(f, "Baseline"),
            Self::Prewarmed => write!(f, "Prewarmed"),
            Self::Zygote => write!(f, "Zygote"),
            Self::Aot => write!(f, "Aot"),
            Self::Eviction => write!(f, "Eviction"),
            Self::Mixed => write!(f, "Mixed"),
        }
    }
}

// ---------------------------------------------------------------------------
// ImageRegistryError
// ---------------------------------------------------------------------------

/// Errors produced by [`ImageRegistry`] operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImageRegistryError {
    /// An image with the given ID already exists.
    ImageAlreadyExists { id: String },
    /// Registering the image would exceed the byte capacity limit.
    CapacityExceeded { current: u64, max: u64 },
    /// No image with the given ID was found.
    ImageNotFound { id: String },
    /// A policy constraint was violated.
    PolicyViolation { reason: String },
}

impl fmt::Display for ImageRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImageAlreadyExists { id } => {
                write!(f, "image already exists: {id}")
            }
            Self::CapacityExceeded { current, max } => {
                write!(f, "capacity exceeded: {current} bytes in use, max {max}")
            }
            Self::ImageNotFound { id } => {
                write!(f, "image not found: {id}")
            }
            Self::PolicyViolation { reason } => {
                write!(f, "policy violation: {reason}")
            }
        }
    }
}

impl std::error::Error for ImageRegistryError {}

// ---------------------------------------------------------------------------
// ImageRegistry
// ---------------------------------------------------------------------------

/// Registry of immutable runtime images with policy-driven eviction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageRegistry {
    /// Registered images (order-preserving).
    pub images: Vec<ImageManifest>,
    /// Active policy governing image lifecycle.
    pub policy: ImagePolicy,
    /// Log of all eviction events.
    pub eviction_log: Vec<ImageEvictionRecord>,
    /// Schema version tag.
    pub schema_version: String,
}

impl ImageRegistry {
    /// Create a new, empty registry with the given policy.
    pub fn new(policy: ImagePolicy) -> Self {
        Self {
            images: Vec::new(),
            policy,
            eviction_log: Vec::new(),
            schema_version: RUNTIME_IMAGE_SCHEMA_VERSION.to_owned(),
        }
    }

    /// Register a new image.
    ///
    /// Returns an error if the image ID already exists, the policy forbids
    /// the image kind, the module count is below the policy minimum, or the
    /// total bytes would exceed the policy limit.
    pub fn register(&mut self, manifest: ImageManifest) -> Result<(), ImageRegistryError> {
        // Duplicate check.
        if self.images.iter().any(|m| m.image_id == manifest.image_id) {
            return Err(ImageRegistryError::ImageAlreadyExists {
                id: manifest.image_id,
            });
        }

        // Policy: kind allowed?
        match manifest.kind {
            ImageKind::Zygote if !self.policy.allow_zygote => {
                return Err(ImageRegistryError::PolicyViolation {
                    reason: "zygote images are disabled by policy".to_owned(),
                });
            }
            ImageKind::AotCompiled if !self.policy.allow_aot => {
                return Err(ImageRegistryError::PolicyViolation {
                    reason: "AOT images are disabled by policy".to_owned(),
                });
            }
            _ => {}
        }

        // Policy: COW mode allowed?
        if manifest.warm_start_mode == WarmStartMode::CowSnapshot && !self.policy.allow_cow {
            return Err(ImageRegistryError::PolicyViolation {
                reason: "COW snapshots are disabled by policy".to_owned(),
            });
        }

        // Policy: minimum module count.
        if manifest.module_count < self.policy.min_module_count_for_image {
            return Err(ImageRegistryError::PolicyViolation {
                reason: format!(
                    "module count {} is below minimum {}",
                    manifest.module_count, self.policy.min_module_count_for_image
                ),
            });
        }

        // Capacity: image count.
        if self.images.len() as u64 >= self.policy.max_image_count {
            return Err(ImageRegistryError::CapacityExceeded {
                current: self.images.len() as u64,
                max: self.policy.max_image_count,
            });
        }

        // Capacity: total bytes.
        let new_total = self.total_bytes() + manifest.total_size_bytes;
        if new_total > self.policy.max_total_bytes {
            return Err(ImageRegistryError::CapacityExceeded {
                current: self.total_bytes(),
                max: self.policy.max_total_bytes,
            });
        }

        self.images.push(manifest);
        Ok(())
    }

    /// Look up an image by its identifier.
    pub fn lookup(&self, image_id: &str) -> Option<&ImageManifest> {
        self.images.iter().find(|m| m.image_id == image_id)
    }

    /// Return all images whose state is [`ImageState::Ready`].
    pub fn ready_images(&self) -> Vec<&ImageManifest> {
        self.images
            .iter()
            .filter(|m| m.state == ImageState::Ready)
            .collect()
    }

    /// Evict an image by ID, recording the eviction event.
    ///
    /// The image is removed from the registry and an
    /// [`ImageEvictionRecord`] is appended to the eviction log.
    pub fn evict(
        &mut self,
        image_id: &str,
        reason: ImageEvictionReason,
        epoch: SecurityEpoch,
    ) -> Result<ImageEvictionRecord, ImageRegistryError> {
        let pos = self
            .images
            .iter()
            .position(|m| m.image_id == image_id)
            .ok_or_else(|| ImageRegistryError::ImageNotFound {
                id: image_id.to_owned(),
            })?;
        let removed = self.images.remove(pos);
        let record = ImageEvictionRecord {
            image_id: removed.image_id,
            reason,
            evicted_epoch: epoch,
            bytes_freed: removed.total_size_bytes,
        };
        self.eviction_log.push(record.clone());
        Ok(record)
    }

    /// Select the best ready image for warm-starting.
    ///
    /// Preference order (highest to lowest):
    ///   1. `AotCompiled` with `AotRestore`
    ///   2. `Zygote` with `ZygoteFork`
    ///   3. `Prewarmed` with `PrewarmedPool`
    ///   4. Any other `Ready` image that is not `Cold`
    ///
    /// Among images of the same preference tier, the most recently created
    /// (highest `creation_epoch`) is preferred.
    pub fn best_warm_start(&self) -> Option<&ImageManifest> {
        let ready: Vec<&ImageManifest> = self.ready_images();

        let priority = |m: &ImageManifest| -> u64 {
            match m.warm_start_mode {
                WarmStartMode::AotRestore => 4,
                WarmStartMode::ZygoteFork => 3,
                WarmStartMode::PrewarmedPool => 2,
                WarmStartMode::CowSnapshot => 1,
                WarmStartMode::Cold => 0,
            }
        };

        ready
            .into_iter()
            .filter(|m| m.warm_start_mode != WarmStartMode::Cold)
            // Filter out images that don't meet integrity requirements
            .filter(|m| {
                if self.policy.require_integrity_check {
                    matches!(m.integrity_status, ImageIntegrityStatus::Verified)
                } else {
                    true
                }
            })
            .max_by_key(|m| (priority(m), m.creation_epoch.as_u64()))
    }

    /// Total bytes consumed by all registered images.
    pub fn total_bytes(&self) -> u64 {
        self.images.iter().map(|m| m.total_size_bytes).sum()
    }

    /// Deterministic content hash over the entire registry state.
    pub fn content_hash(&self) -> ContentHash {
        fn push_bytes(data: &mut Vec<u8>, bytes: &[u8]) {
            data.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            data.extend_from_slice(bytes);
        }

        fn push_str(data: &mut Vec<u8>, value: &str) {
            push_bytes(data, value.as_bytes());
        }

        fn push_bool(data: &mut Vec<u8>, value: bool) {
            data.push(u8::from(value));
        }

        fn push_u64(data: &mut Vec<u8>, value: u64) {
            data.extend_from_slice(&value.to_le_bytes());
        }

        let mut data = Vec::new();
        push_str(&mut data, &self.schema_version);
        push_u64(&mut data, self.policy.max_image_count);
        push_u64(&mut data, self.policy.max_total_bytes);
        push_u64(&mut data, self.policy.default_ttl_seconds);
        push_bool(&mut data, self.policy.allow_zygote);
        push_bool(&mut data, self.policy.allow_cow);
        push_bool(&mut data, self.policy.allow_aot);
        push_bool(&mut data, self.policy.require_integrity_check);
        push_u64(&mut data, self.policy.min_module_count_for_image);

        let mut sorted_images: Vec<_> = self.images.iter().collect();
        sorted_images.sort_by_key(|img| &img.image_id);
        for img in &sorted_images {
            push_str(&mut data, &img.image_id);
            push_str(&mut data, &img.kind.to_string());
            push_str(&mut data, &img.state.to_string());
            push_u64(&mut data, img.creation_epoch.as_u64());
            push_bytes(&mut data, img.source_hash.as_bytes());
            push_bytes(&mut data, img.image_hash.as_bytes());
            push_u64(&mut data, img.module_count);
            push_u64(&mut data, img.total_size_bytes);
            push_str(&mut data, &img.warm_start_mode.to_string());
            push_str(&mut data, &img.integrity_status.to_string());
            match img.ttl_seconds {
                Some(ttl_seconds) => {
                    data.push(1);
                    push_u64(&mut data, ttl_seconds);
                }
                None => data.push(0),
            }
            push_str(&mut data, &img.creation_reason);
        }
        for ev in &self.eviction_log {
            push_str(&mut data, &ev.image_id);
            push_str(&mut data, &ev.reason.to_string());
            push_u64(&mut data, ev.evicted_epoch.as_u64());
            push_u64(&mut data, ev.bytes_freed);
        }
        ContentHash::compute(&data)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers --

    fn test_hash(n: u8) -> ContentHash {
        ContentHash::compute(&[n])
    }

    fn test_manifest(id: &str) -> ImageManifest {
        ImageManifest {
            image_id: id.to_owned(),
            kind: ImageKind::Baseline,
            state: ImageState::Ready,
            creation_epoch: SecurityEpoch::from_raw(1),
            source_hash: test_hash(0),
            image_hash: test_hash(1),
            module_count: 5,
            total_size_bytes: 1024,
            warm_start_mode: WarmStartMode::Cold,
            integrity_status: ImageIntegrityStatus::Verified,
            ttl_seconds: Some(3600),
            creation_reason: "unit test".to_owned(),
        }
    }

    fn test_policy() -> ImagePolicy {
        ImagePolicy {
            max_image_count: 4,
            max_total_bytes: 8192,
            default_ttl_seconds: 600,
            allow_zygote: true,
            allow_cow: true,
            allow_aot: true,
            require_integrity_check: true,
            min_module_count_for_image: 1,
        }
    }

    fn test_keypair(seed: u8) -> (SigningKey, VerificationKey) {
        crate::signature_preimage::generate_keypair_from_seed(&[seed; 32])
    }

    fn signed_test_manifest(
        id: &str,
        valid_from_epoch: SecurityEpoch,
        valid_until_epoch: Option<SecurityEpoch>,
        frontier_epoch: SecurityEpoch,
    ) -> (SignedRuntimeImageManifest, VerificationKey) {
        let (signing_key, verification_key) = test_keypair(7);
        let envelope = SignedRuntimeImageManifest::sign(
            test_manifest(id),
            valid_from_epoch,
            valid_until_epoch,
            frontier_epoch,
            &signing_key,
        )
        .expect("signed runtime image should sign");
        (envelope, verification_key)
    }

    fn acceptance_context(
        current_epoch: SecurityEpoch,
        accepted_frontier_epoch: SecurityEpoch,
        trusted_signer: VerificationKey,
    ) -> RuntimeImageAcceptanceContext {
        RuntimeImageAcceptanceContext::new(
            current_epoch,
            accepted_frontier_epoch,
            vec![trusted_signer],
        )
    }

    // -- ImageKind --

    #[test]
    fn image_kind_display_roundtrip() {
        for kind in ImageKind::ALL {
            let s = kind.to_string();
            assert!(!s.is_empty(), "Display for {kind:?} should not be empty");
        }
    }

    #[test]
    fn image_kind_serde_roundtrip() {
        for kind in ImageKind::ALL {
            // SAFETY: ImageKind derives Serialize and has no non-serializable fields.
            // to_string on derived Serialize types only fails on writer errors (impossible with String).
            let json = serde_json::to_string(kind).expect("serialize derived Serialize");
            // SAFETY: JSON was just produced by to_string of a valid ImageKind,
            // so from_str back to ImageKind cannot fail (valid format + matching schema).
            let back: ImageKind =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn image_kind_all_count() {
        assert_eq!(ImageKind::ALL.len(), 5);
    }

    // -- ImageState --

    #[test]
    fn image_state_display_roundtrip() {
        for st in ImageState::ALL {
            let s = st.to_string();
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn image_state_serde_roundtrip() {
        for st in ImageState::ALL {
            let json = serde_json::to_string(st).expect("serialize derived Serialize");
            let back: ImageState =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*st, back);
        }
    }

    // -- WarmStartMode --

    #[test]
    fn warm_start_mode_display_all() {
        let expected = [
            "Cold",
            "ZygoteFork",
            "CowSnapshot",
            "PrewarmedPool",
            "AotRestore",
        ];
        for (mode, exp) in WarmStartMode::ALL.iter().zip(expected.iter()) {
            assert_eq!(mode.to_string(), *exp);
        }
    }

    #[test]
    fn warm_start_mode_serde() {
        for mode in WarmStartMode::ALL {
            let json = serde_json::to_string(mode).expect("serialize derived Serialize");
            let back: WarmStartMode =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*mode, back);
        }
    }

    // -- ImageIntegrityStatus --

    #[test]
    fn integrity_status_display() {
        assert_eq!(ImageIntegrityStatus::Verified.to_string(), "Verified");
        assert_eq!(
            ImageIntegrityStatus::CorruptionDetected.to_string(),
            "CorruptionDetected"
        );
    }

    #[test]
    fn integrity_status_serde() {
        for s in ImageIntegrityStatus::ALL {
            let json = serde_json::to_string(s).expect("serialize derived Serialize");
            let back: ImageIntegrityStatus =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*s, back);
        }
    }

    // -- ImageEvictionReason --

    #[test]
    fn eviction_reason_display() {
        assert_eq!(ImageEvictionReason::TtlExpired.to_string(), "TtlExpired");
        assert_eq!(
            ImageEvictionReason::ManualEviction.to_string(),
            "ManualEviction"
        );
    }

    #[test]
    fn eviction_reason_serde() {
        for r in ImageEvictionReason::ALL {
            let json = serde_json::to_string(r).expect("serialize derived Serialize");
            let back: ImageEvictionReason =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*r, back);
        }
    }

    // -- ImageSpecimenFamily --

    #[test]
    fn specimen_family_display() {
        assert_eq!(ImageSpecimenFamily::Baseline.to_string(), "Baseline");
        assert_eq!(ImageSpecimenFamily::Mixed.to_string(), "Mixed");
    }

    #[test]
    fn specimen_family_serde() {
        for fam in ImageSpecimenFamily::ALL {
            let json = serde_json::to_string(fam).expect("serialize derived Serialize");
            let back: ImageSpecimenFamily =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*fam, back);
        }
    }

    #[test]
    fn specimen_family_all_count() {
        assert_eq!(ImageSpecimenFamily::ALL.len(), 6);
    }

    // -- ImageManifest --

    #[test]
    fn manifest_construction() {
        let m = test_manifest("img-1");
        assert_eq!(m.image_id, "img-1");
        assert_eq!(m.kind, ImageKind::Baseline);
        assert_eq!(m.state, ImageState::Ready);
        assert_eq!(m.module_count, 5);
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = test_manifest("img-serde");
        let json = serde_json::to_string(&m).expect("serialize derived Serialize");
        let back: ImageManifest =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(m, back);
    }

    // -- SignedRuntimeImageManifest --

    #[test]
    fn signed_runtime_image_accepts_trusted_epoch_window() {
        let (envelope, signer) = signed_test_manifest(
            "signed-ok",
            SecurityEpoch::from_raw(10),
            Some(SecurityEpoch::from_raw(20)),
            SecurityEpoch::from_raw(12),
        );
        let context = acceptance_context(
            SecurityEpoch::from_raw(15),
            SecurityEpoch::from_raw(12),
            signer,
        );

        let accepted = envelope
            .verify_for_acceptance(&context)
            .expect("trusted signed runtime image should be accepted");

        assert_eq!(accepted.image_id, "signed-ok");
    }

    #[test]
    fn signed_runtime_image_rejects_future_validity_window() {
        let (envelope, signer) = signed_test_manifest(
            "signed-future",
            SecurityEpoch::from_raw(20),
            Some(SecurityEpoch::from_raw(30)),
            SecurityEpoch::from_raw(12),
        );
        let context = acceptance_context(
            SecurityEpoch::from_raw(15),
            SecurityEpoch::from_raw(12),
            signer,
        );

        let error = envelope.verify_for_acceptance(&context).unwrap_err();

        assert!(matches!(
            error,
            RuntimeImageAcceptanceError::NotYetValid { .. }
        ));
    }

    #[test]
    fn signed_runtime_image_rejects_expired_window() {
        let (envelope, signer) = signed_test_manifest(
            "signed-expired",
            SecurityEpoch::from_raw(5),
            Some(SecurityEpoch::from_raw(10)),
            SecurityEpoch::from_raw(8),
        );
        let context = acceptance_context(
            SecurityEpoch::from_raw(15),
            SecurityEpoch::from_raw(8),
            signer,
        );

        let error = envelope.verify_for_acceptance(&context).unwrap_err();

        assert!(matches!(error, RuntimeImageAcceptanceError::Expired { .. }));
    }

    #[test]
    fn signed_runtime_image_rejects_inverted_window() {
        let (envelope, signer) = signed_test_manifest(
            "signed-inverted",
            SecurityEpoch::from_raw(20),
            Some(SecurityEpoch::from_raw(10)),
            SecurityEpoch::from_raw(8),
        );
        let context = acceptance_context(
            SecurityEpoch::from_raw(15),
            SecurityEpoch::from_raw(8),
            signer,
        );

        let error = envelope.verify_for_acceptance(&context).unwrap_err();

        assert!(matches!(
            error,
            RuntimeImageAcceptanceError::InvalidValidityWindow { .. }
        ));
    }

    #[test]
    fn signed_runtime_image_rejects_frontier_regression() {
        let (envelope, signer) = signed_test_manifest(
            "signed-regressed-frontier",
            SecurityEpoch::from_raw(5),
            Some(SecurityEpoch::from_raw(20)),
            SecurityEpoch::from_raw(8),
        );
        let context = acceptance_context(
            SecurityEpoch::from_raw(15),
            SecurityEpoch::from_raw(10),
            signer,
        );

        let error = envelope.verify_for_acceptance(&context).unwrap_err();

        assert!(matches!(
            error,
            RuntimeImageAcceptanceError::FrontierRegression { .. }
        ));
    }

    #[test]
    fn signed_runtime_image_rejects_future_frontier() {
        let (envelope, signer) = signed_test_manifest(
            "signed-future-frontier",
            SecurityEpoch::from_raw(5),
            Some(SecurityEpoch::from_raw(30)),
            SecurityEpoch::from_raw(25),
        );
        let context = acceptance_context(
            SecurityEpoch::from_raw(15),
            SecurityEpoch::from_raw(10),
            signer,
        );

        let error = envelope.verify_for_acceptance(&context).unwrap_err();

        assert!(matches!(
            error,
            RuntimeImageAcceptanceError::FutureFrontier { .. }
        ));
    }

    #[test]
    fn signed_runtime_image_rejects_tampered_manifest() {
        let (mut envelope, signer) = signed_test_manifest(
            "signed-tampered",
            SecurityEpoch::from_raw(5),
            Some(SecurityEpoch::from_raw(20)),
            SecurityEpoch::from_raw(10),
        );
        envelope.manifest.image_hash = ContentHash::compute(b"tampered-image");
        let context = acceptance_context(
            SecurityEpoch::from_raw(15),
            SecurityEpoch::from_raw(10),
            signer,
        );

        let error = envelope.verify_for_acceptance(&context).unwrap_err();

        assert!(matches!(
            error,
            RuntimeImageAcceptanceError::SignatureInvalid { .. }
        ));
    }

    #[test]
    fn signed_runtime_image_rejects_untrusted_signer() {
        let (envelope, _) = signed_test_manifest(
            "signed-untrusted",
            SecurityEpoch::from_raw(5),
            Some(SecurityEpoch::from_raw(20)),
            SecurityEpoch::from_raw(10),
        );
        let (_, other_signer) = test_keypair(9);
        let context = acceptance_context(
            SecurityEpoch::from_raw(15),
            SecurityEpoch::from_raw(10),
            other_signer,
        );

        let error = envelope.verify_for_acceptance(&context).unwrap_err();

        assert!(matches!(
            error,
            RuntimeImageAcceptanceError::UntrustedSigner { .. }
        ));
    }

    // -- ImagePolicy --

    #[test]
    fn policy_defaults() {
        let p = ImagePolicy::default();
        assert_eq!(p.max_image_count, 16);
        assert!(p.allow_zygote);
        assert!(p.allow_cow);
        assert!(p.allow_aot);
        assert!(p.require_integrity_check);
    }

    #[test]
    fn policy_serde_roundtrip() {
        let p = test_policy();
        let json = serde_json::to_string(&p).expect("serialize derived Serialize");
        let back: ImagePolicy = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(p, back);
    }

    // -- ImageRegistryError --

    #[test]
    fn error_display_image_already_exists() {
        let e = ImageRegistryError::ImageAlreadyExists { id: "x".to_owned() };
        assert!(e.to_string().contains("already exists"));
    }

    #[test]
    fn error_display_capacity_exceeded() {
        let e = ImageRegistryError::CapacityExceeded {
            current: 100,
            max: 50,
        };
        let s = e.to_string();
        assert!(s.contains("100"));
        assert!(s.contains("50"));
    }

    #[test]
    fn error_display_not_found() {
        let e = ImageRegistryError::ImageNotFound { id: "z".to_owned() };
        assert!(e.to_string().contains("not found"));
    }

    #[test]
    fn error_display_policy_violation() {
        let e = ImageRegistryError::PolicyViolation {
            reason: "bad".to_owned(),
        };
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(ImageRegistryError::ImageNotFound {
            id: "test".to_owned(),
        });
        assert!(!e.to_string().is_empty());
    }

    // -- ImageRegistry: construction --

    #[test]
    fn registry_new_empty() {
        let reg = ImageRegistry::new(test_policy());
        assert!(reg.images.is_empty());
        assert!(reg.eviction_log.is_empty());
        assert_eq!(reg.schema_version, RUNTIME_IMAGE_SCHEMA_VERSION);
    }

    // -- ImageRegistry: register --

    #[test]
    fn registry_register_success() {
        let mut reg = ImageRegistry::new(test_policy());
        let m = test_manifest("img-1");
        assert!(reg.register(m).is_ok());
        assert_eq!(reg.images.len(), 1);
    }

    #[test]
    fn registry_register_duplicate_error() {
        let mut reg = ImageRegistry::new(test_policy());
        reg.register(test_manifest("dup"))
            .expect("serde deserialization should succeed");
        let err = reg.register(test_manifest("dup")).unwrap_err();
        assert!(matches!(err, ImageRegistryError::ImageAlreadyExists { .. }));
    }

    #[test]
    fn registry_register_capacity_count_exceeded() {
        let policy = ImagePolicy {
            max_image_count: 2,
            ..test_policy()
        };
        let mut reg = ImageRegistry::new(policy);
        reg.register(test_manifest("a"))
            .expect("serde deserialization should succeed");
        reg.register(test_manifest("b"))
            .expect("serde deserialization should succeed");
        let err = reg.register(test_manifest("c")).unwrap_err();
        assert!(matches!(err, ImageRegistryError::CapacityExceeded { .. }));
    }

    #[test]
    fn registry_register_capacity_bytes_exceeded() {
        let policy = ImagePolicy {
            max_total_bytes: 1500,
            ..test_policy()
        };
        let mut reg = ImageRegistry::new(policy);
        reg.register(test_manifest("a"))
            .expect("serde deserialization should succeed"); // 1024 bytes
        let err = reg.register(test_manifest("b")).unwrap_err(); // would be 2048
        assert!(matches!(err, ImageRegistryError::CapacityExceeded { .. }));
    }

    #[test]
    fn registry_register_policy_zygote_disabled() {
        let policy = ImagePolicy {
            allow_zygote: false,
            ..test_policy()
        };
        let mut reg = ImageRegistry::new(policy);
        let mut m = test_manifest("z");
        m.kind = ImageKind::Zygote;
        let err = reg.register(m).unwrap_err();
        assert!(matches!(err, ImageRegistryError::PolicyViolation { .. }));
    }

    #[test]
    fn registry_register_policy_aot_disabled() {
        let policy = ImagePolicy {
            allow_aot: false,
            ..test_policy()
        };
        let mut reg = ImageRegistry::new(policy);
        let mut m = test_manifest("aot");
        m.kind = ImageKind::AotCompiled;
        let err = reg.register(m).unwrap_err();
        assert!(matches!(err, ImageRegistryError::PolicyViolation { .. }));
    }

    #[test]
    fn registry_register_policy_cow_disabled() {
        let policy = ImagePolicy {
            allow_cow: false,
            ..test_policy()
        };
        let mut reg = ImageRegistry::new(policy);
        let mut m = test_manifest("cow");
        m.warm_start_mode = WarmStartMode::CowSnapshot;
        let err = reg.register(m).unwrap_err();
        assert!(matches!(err, ImageRegistryError::PolicyViolation { .. }));
    }

    #[test]
    fn registry_register_policy_min_modules() {
        let policy = ImagePolicy {
            min_module_count_for_image: 10,
            ..test_policy()
        };
        let mut reg = ImageRegistry::new(policy);
        let m = test_manifest("small"); // module_count = 5
        let err = reg.register(m).unwrap_err();
        assert!(matches!(err, ImageRegistryError::PolicyViolation { .. }));
    }

    // -- ImageRegistry: lookup --

    #[test]
    fn registry_lookup_found() {
        let mut reg = ImageRegistry::new(test_policy());
        reg.register(test_manifest("look"))
            .expect("serde deserialization should succeed");
        assert!(reg.lookup("look").is_some());
    }

    #[test]
    fn registry_lookup_not_found() {
        let reg = ImageRegistry::new(test_policy());
        assert!(reg.lookup("nope").is_none());
    }

    // -- ImageRegistry: ready_images --

    #[test]
    fn registry_ready_images() {
        let mut reg = ImageRegistry::new(test_policy());
        reg.register(test_manifest("r1"))
            .expect("serde deserialization should succeed");
        let mut m2 = test_manifest("r2");
        m2.state = ImageState::Building;
        reg.register(m2)
            .expect("serde deserialization should succeed");
        let ready = reg.ready_images();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].image_id, "r1");
    }

    // -- ImageRegistry: evict --

    #[test]
    fn registry_evict_success() {
        let mut reg = ImageRegistry::new(test_policy());
        reg.register(test_manifest("ev"))
            .expect("serde deserialization should succeed");
        let record = reg
            .evict(
                "ev",
                ImageEvictionReason::TtlExpired,
                SecurityEpoch::from_raw(5),
            )
            .expect("serde deserialization should succeed");
        assert_eq!(record.image_id, "ev");
        assert_eq!(record.reason, ImageEvictionReason::TtlExpired);
        assert_eq!(record.bytes_freed, 1024);
        assert!(reg.images.is_empty());
        assert_eq!(reg.eviction_log.len(), 1);
    }

    #[test]
    fn registry_evict_not_found() {
        let mut reg = ImageRegistry::new(test_policy());
        let err = reg
            .evict(
                "no",
                ImageEvictionReason::ManualEviction,
                SecurityEpoch::from_raw(1),
            )
            .unwrap_err();
        assert!(matches!(err, ImageRegistryError::ImageNotFound { .. }));
    }

    // -- ImageRegistry: best_warm_start --

    #[test]
    fn registry_best_warm_start_prefers_aot() {
        let mut reg = ImageRegistry::new(test_policy());
        let mut m1 = test_manifest("prewarm");
        m1.warm_start_mode = WarmStartMode::PrewarmedPool;
        m1.kind = ImageKind::Prewarmed;
        reg.register(m1)
            .expect("serde deserialization should succeed");

        let mut m2 = test_manifest("aot");
        m2.warm_start_mode = WarmStartMode::AotRestore;
        m2.kind = ImageKind::AotCompiled;
        reg.register(m2)
            .expect("serde deserialization should succeed");

        let best = reg
            .best_warm_start()
            .expect("serde deserialization should succeed");
        assert_eq!(best.image_id, "aot");
    }

    #[test]
    fn registry_best_warm_start_none_when_all_cold() {
        let mut reg = ImageRegistry::new(test_policy());
        reg.register(test_manifest("cold"))
            .expect("serde deserialization should succeed"); // WarmStartMode::Cold
        assert!(reg.best_warm_start().is_none());
    }

    #[test]
    fn registry_best_warm_start_skips_non_ready() {
        let mut reg = ImageRegistry::new(test_policy());
        let mut m = test_manifest("stale-aot");
        m.warm_start_mode = WarmStartMode::AotRestore;
        m.kind = ImageKind::AotCompiled;
        m.state = ImageState::Stale;
        reg.register(m)
            .expect("serde deserialization should succeed");
        assert!(reg.best_warm_start().is_none());
    }

    // -- ImageRegistry: total_bytes --

    #[test]
    fn registry_total_bytes() {
        let mut reg = ImageRegistry::new(test_policy());
        reg.register(test_manifest("a"))
            .expect("serde deserialization should succeed");
        reg.register(test_manifest("b"))
            .expect("serde deserialization should succeed");
        assert_eq!(reg.total_bytes(), 2048);
    }

    // -- ImageRegistry: content_hash determinism --

    #[test]
    fn registry_content_hash_determinism() {
        let mut r1 = ImageRegistry::new(test_policy());
        r1.register(test_manifest("x"))
            .expect("serde deserialization should succeed");
        let mut r2 = ImageRegistry::new(test_policy());
        r2.register(test_manifest("x"))
            .expect("serde deserialization should succeed");
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn registry_content_hash_differs_with_different_images() {
        let mut r1 = ImageRegistry::new(test_policy());
        r1.register(test_manifest("x"))
            .expect("serde deserialization should succeed");
        let mut r2 = ImageRegistry::new(test_policy());
        r2.register(test_manifest("y"))
            .expect("serde deserialization should succeed");
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn registry_content_hash_differs_with_warm_start_mode() {
        let mut r1 = ImageRegistry::new(test_policy());
        let mut x1 = test_manifest("x");
        x1.kind = ImageKind::Prewarmed;
        x1.warm_start_mode = WarmStartMode::PrewarmedPool;
        r1.register(x1)
            .expect("serde deserialization should succeed");

        let mut r2 = ImageRegistry::new(test_policy());
        let mut x2 = test_manifest("x");
        x2.kind = ImageKind::AotCompiled;
        x2.warm_start_mode = WarmStartMode::AotRestore;
        r2.register(x2)
            .expect("serde deserialization should succeed");

        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn registry_content_hash_differs_with_integrity_status() {
        let mut r1 = ImageRegistry::new(test_policy());
        let mut x1 = test_manifest("x");
        x1.integrity_status = ImageIntegrityStatus::Verified;
        r1.register(x1)
            .expect("serde deserialization should succeed");

        let mut r2 = ImageRegistry::new(test_policy());
        let mut x2 = test_manifest("x");
        x2.integrity_status = ImageIntegrityStatus::Unverified;
        r2.register(x2)
            .expect("serde deserialization should succeed");

        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    // -- schema constants --

    #[test]
    fn schema_constants() {
        assert!(RUNTIME_IMAGE_SCHEMA_VERSION.contains("runtime-image-contract"));
        assert_eq!(RUNTIME_IMAGE_BEAD_ID, "bd-1lsy.7.10.4");
    }

    // -- ImageEvictionRecord serde --

    #[test]
    fn eviction_record_serde_roundtrip() {
        let record = ImageEvictionRecord {
            image_id: "ev-1".to_owned(),
            reason: ImageEvictionReason::SourceChanged,
            evicted_epoch: SecurityEpoch::from_raw(42),
            bytes_freed: 9999,
        };
        let json = serde_json::to_string(&record).expect("serialize derived Serialize");
        let back: ImageEvictionRecord =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(record, back);
    }

    // -- ImageRegistry serde --

    #[test]
    fn registry_serde_roundtrip() {
        let mut reg = ImageRegistry::new(test_policy());
        reg.register(test_manifest("s1"))
            .expect("serde deserialization should succeed");
        reg.evict(
            "s1",
            ImageEvictionReason::ManualEviction,
            SecurityEpoch::from_raw(10),
        )
        .expect("serde deserialization should succeed");
        let json = serde_json::to_string(&reg).expect("serialize derived Serialize");
        let back: ImageRegistry =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(reg, back);
    }

    // -- best_warm_start tiebreak by epoch --

    #[test]
    fn best_warm_start_tiebreak_by_epoch() {
        let mut reg = ImageRegistry::new(test_policy());
        let mut m1 = test_manifest("z1");
        m1.warm_start_mode = WarmStartMode::ZygoteFork;
        m1.kind = ImageKind::Zygote;
        m1.creation_epoch = SecurityEpoch::from_raw(1);
        reg.register(m1)
            .expect("serde deserialization should succeed");

        let mut m2 = test_manifest("z2");
        m2.warm_start_mode = WarmStartMode::ZygoteFork;
        m2.kind = ImageKind::Zygote;
        m2.creation_epoch = SecurityEpoch::from_raw(5);
        reg.register(m2)
            .expect("serde deserialization should succeed");

        let best = reg
            .best_warm_start()
            .expect("serde deserialization should succeed");
        assert_eq!(best.image_id, "z2");
    }

    #[test]
    fn best_warm_start_rejects_unverified_when_integrity_required() {
        let mut reg = ImageRegistry::new(ImagePolicy::default()); // require_integrity_check = true
        let mut img = test_manifest("unverified-aot");
        img.kind = ImageKind::AotCompiled;
        img.warm_start_mode = WarmStartMode::AotRestore;
        img.integrity_status = ImageIntegrityStatus::Unverified;
        reg.register(img).unwrap();
        // Should fail-closed when integrity is required but image is unverified
        assert!(reg.best_warm_start().is_none());
    }

    #[test]
    fn best_warm_start_rejects_corrupted_when_integrity_required() {
        let mut reg = ImageRegistry::new(ImagePolicy::default()); // require_integrity_check = true
        let mut img = test_manifest("corrupted-aot");
        img.kind = ImageKind::AotCompiled;
        img.warm_start_mode = WarmStartMode::AotRestore;
        img.integrity_status = ImageIntegrityStatus::CorruptionDetected;
        reg.register(img).unwrap();
        // Should fail-closed when integrity is required but image is corrupted
        assert!(reg.best_warm_start().is_none());
    }

    #[test]
    fn best_warm_start_rejects_expired_when_integrity_required() {
        let mut reg = ImageRegistry::new(ImagePolicy::default()); // require_integrity_check = true
        let mut img = test_manifest("expired-aot");
        img.kind = ImageKind::AotCompiled;
        img.warm_start_mode = WarmStartMode::AotRestore;
        img.integrity_status = ImageIntegrityStatus::Expired;
        reg.register(img).unwrap();
        // Should fail-closed when integrity is required but image is expired
        assert!(reg.best_warm_start().is_none());
    }

    #[test]
    fn best_warm_start_allows_unverified_when_integrity_not_required() {
        let policy = ImagePolicy {
            require_integrity_check: false,
            ..ImagePolicy::default()
        };
        let mut reg = ImageRegistry::new(policy);
        let mut img = test_manifest("unverified-but-allowed");
        img.kind = ImageKind::AotCompiled;
        img.warm_start_mode = WarmStartMode::AotRestore;
        img.integrity_status = ImageIntegrityStatus::Unverified;
        reg.register(img).unwrap();
        // Should allow when integrity checking is disabled
        assert!(reg.best_warm_start().is_some());
    }
}
