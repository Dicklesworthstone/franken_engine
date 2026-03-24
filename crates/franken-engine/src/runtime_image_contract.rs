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

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

/// Schema version for the runtime image contract envelope.
pub const RUNTIME_IMAGE_SCHEMA_VERSION: &str = "franken-engine.runtime-image-contract.v1";

/// Bead identifier originating this module.
pub const RUNTIME_IMAGE_BEAD_ID: &str = "bd-1lsy.7.10.4";

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
            .max_by_key(|m| (priority(m), m.creation_epoch.as_u64()))
    }

    /// Total bytes consumed by all registered images.
    pub fn total_bytes(&self) -> u64 {
        self.images.iter().map(|m| m.total_size_bytes).sum()
    }

    /// Deterministic content hash over the entire registry state.
    pub fn content_hash(&self) -> ContentHash {
        let mut data = Vec::new();
        data.extend_from_slice(self.schema_version.as_bytes());
        let mut sorted_images: Vec<_> = self.images.iter().collect();
        sorted_images.sort_by_key(|img| &img.image_id);
        for img in &sorted_images {
            data.extend_from_slice(img.image_id.as_bytes());
            data.extend_from_slice(img.image_hash.as_bytes());
            data.extend_from_slice(&img.total_size_bytes.to_le_bytes());
            data.extend_from_slice(&img.module_count.to_le_bytes());
            data.extend_from_slice(&img.creation_epoch.as_u64().to_le_bytes());
        }
        for ev in &self.eviction_log {
            data.extend_from_slice(ev.image_id.as_bytes());
            data.extend_from_slice(&ev.bytes_freed.to_le_bytes());
            data.extend_from_slice(&ev.evicted_epoch.as_u64().to_le_bytes());
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
            let json = serde_json::to_string(kind).unwrap();
            let back: ImageKind = serde_json::from_str(&json).unwrap();
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
            let json = serde_json::to_string(st).unwrap();
            let back: ImageState = serde_json::from_str(&json).unwrap();
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
            let json = serde_json::to_string(mode).unwrap();
            let back: WarmStartMode = serde_json::from_str(&json).unwrap();
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
            let json = serde_json::to_string(s).unwrap();
            let back: ImageIntegrityStatus = serde_json::from_str(&json).unwrap();
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
            let json = serde_json::to_string(r).unwrap();
            let back: ImageEvictionReason = serde_json::from_str(&json).unwrap();
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
            let json = serde_json::to_string(fam).unwrap();
            let back: ImageSpecimenFamily = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&m).unwrap();
        let back: ImageManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
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
        let json = serde_json::to_string(&p).unwrap();
        let back: ImagePolicy = serde_json::from_str(&json).unwrap();
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
        reg.register(test_manifest("dup")).unwrap();
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
        reg.register(test_manifest("a")).unwrap();
        reg.register(test_manifest("b")).unwrap();
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
        reg.register(test_manifest("a")).unwrap(); // 1024 bytes
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
        reg.register(test_manifest("look")).unwrap();
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
        reg.register(test_manifest("r1")).unwrap();
        let mut m2 = test_manifest("r2");
        m2.state = ImageState::Building;
        reg.register(m2).unwrap();
        let ready = reg.ready_images();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].image_id, "r1");
    }

    // -- ImageRegistry: evict --

    #[test]
    fn registry_evict_success() {
        let mut reg = ImageRegistry::new(test_policy());
        reg.register(test_manifest("ev")).unwrap();
        let record = reg
            .evict(
                "ev",
                ImageEvictionReason::TtlExpired,
                SecurityEpoch::from_raw(5),
            )
            .unwrap();
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
        reg.register(m1).unwrap();

        let mut m2 = test_manifest("aot");
        m2.warm_start_mode = WarmStartMode::AotRestore;
        m2.kind = ImageKind::AotCompiled;
        reg.register(m2).unwrap();

        let best = reg.best_warm_start().unwrap();
        assert_eq!(best.image_id, "aot");
    }

    #[test]
    fn registry_best_warm_start_none_when_all_cold() {
        let mut reg = ImageRegistry::new(test_policy());
        reg.register(test_manifest("cold")).unwrap(); // WarmStartMode::Cold
        assert!(reg.best_warm_start().is_none());
    }

    #[test]
    fn registry_best_warm_start_skips_non_ready() {
        let mut reg = ImageRegistry::new(test_policy());
        let mut m = test_manifest("stale-aot");
        m.warm_start_mode = WarmStartMode::AotRestore;
        m.kind = ImageKind::AotCompiled;
        m.state = ImageState::Stale;
        reg.register(m).unwrap();
        assert!(reg.best_warm_start().is_none());
    }

    // -- ImageRegistry: total_bytes --

    #[test]
    fn registry_total_bytes() {
        let mut reg = ImageRegistry::new(test_policy());
        reg.register(test_manifest("a")).unwrap();
        reg.register(test_manifest("b")).unwrap();
        assert_eq!(reg.total_bytes(), 2048);
    }

    // -- ImageRegistry: content_hash determinism --

    #[test]
    fn registry_content_hash_determinism() {
        let mut r1 = ImageRegistry::new(test_policy());
        r1.register(test_manifest("x")).unwrap();
        let mut r2 = ImageRegistry::new(test_policy());
        r2.register(test_manifest("x")).unwrap();
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn registry_content_hash_differs_with_different_images() {
        let mut r1 = ImageRegistry::new(test_policy());
        r1.register(test_manifest("x")).unwrap();
        let mut r2 = ImageRegistry::new(test_policy());
        r2.register(test_manifest("y")).unwrap();
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
        let json = serde_json::to_string(&record).unwrap();
        let back: ImageEvictionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    // -- ImageRegistry serde --

    #[test]
    fn registry_serde_roundtrip() {
        let mut reg = ImageRegistry::new(test_policy());
        reg.register(test_manifest("s1")).unwrap();
        reg.evict(
            "s1",
            ImageEvictionReason::ManualEviction,
            SecurityEpoch::from_raw(10),
        )
        .unwrap();
        let json = serde_json::to_string(&reg).unwrap();
        let back: ImageRegistry = serde_json::from_str(&json).unwrap();
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
        reg.register(m1).unwrap();

        let mut m2 = test_manifest("z2");
        m2.warm_start_mode = WarmStartMode::ZygoteFork;
        m2.kind = ImageKind::Zygote;
        m2.creation_epoch = SecurityEpoch::from_raw(5);
        reg.register(m2).unwrap();

        let best = reg.best_warm_start().unwrap();
        assert_eq!(best.image_id, "z2");
    }
}
