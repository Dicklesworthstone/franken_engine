//! Deep integration tests for runtime_image_contract module.
//!
//! Covers: image kind/state/warm-start/integrity enums, Display impls,
//! serde roundtrips, ALL constant coverage, and manifest structure.

use frankenengine_engine::runtime_image_contract::{
    ImageIntegrityStatus, ImageKind, ImageState, RUNTIME_IMAGE_BEAD_ID,
    RUNTIME_IMAGE_SCHEMA_VERSION, WarmStartMode,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn deep_constants_nonempty() {
    assert!(!RUNTIME_IMAGE_SCHEMA_VERSION.is_empty());
    assert!(!RUNTIME_IMAGE_BEAD_ID.is_empty());
    assert!(RUNTIME_IMAGE_BEAD_ID.starts_with("bd-"));
}

// ---------------------------------------------------------------------------
// ImageKind
// ---------------------------------------------------------------------------

#[test]
fn deep_image_kind_all_count() {
    assert_eq!(ImageKind::ALL.len(), 5);
}

#[test]
fn deep_image_kind_display_all() {
    let expected = [
        (ImageKind::Baseline, "Baseline"),
        (ImageKind::Prewarmed, "Prewarmed"),
        (ImageKind::Zygote, "Zygote"),
        (ImageKind::AotCompiled, "AotCompiled"),
        (ImageKind::CachedSnapshot, "CachedSnapshot"),
    ];
    for (kind, name) in expected {
        assert_eq!(format!("{kind}"), name);
    }
}

#[test]
fn deep_image_kind_serde_roundtrip() {
    for kind in ImageKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let decoded: ImageKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, decoded);
    }
}

// ---------------------------------------------------------------------------
// ImageState
// ---------------------------------------------------------------------------

#[test]
fn deep_image_state_all_count() {
    assert_eq!(ImageState::ALL.len(), 5);
}

#[test]
fn deep_image_state_display_all() {
    let expected = [
        (ImageState::Building, "Building"),
        (ImageState::Ready, "Ready"),
        (ImageState::Stale, "Stale"),
        (ImageState::Invalidated, "Invalidated"),
        (ImageState::Disabled, "Disabled"),
    ];
    for (state, name) in expected {
        assert_eq!(format!("{state}"), name);
    }
}

#[test]
fn deep_image_state_serde_roundtrip() {
    for state in ImageState::ALL {
        let json = serde_json::to_string(state).unwrap();
        let decoded: ImageState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, decoded);
    }
}

// ---------------------------------------------------------------------------
// WarmStartMode
// ---------------------------------------------------------------------------

#[test]
fn deep_warm_start_all_count() {
    assert_eq!(WarmStartMode::ALL.len(), 5);
}

#[test]
fn deep_warm_start_display_all() {
    let expected = [
        (WarmStartMode::Cold, "Cold"),
        (WarmStartMode::ZygoteFork, "ZygoteFork"),
        (WarmStartMode::CowSnapshot, "CowSnapshot"),
        (WarmStartMode::PrewarmedPool, "PrewarmedPool"),
        (WarmStartMode::AotRestore, "AotRestore"),
    ];
    for (mode, name) in expected {
        assert_eq!(format!("{mode}"), name);
    }
}

#[test]
fn deep_warm_start_serde_roundtrip() {
    for mode in WarmStartMode::ALL {
        let json = serde_json::to_string(mode).unwrap();
        let decoded: WarmStartMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, decoded);
    }
}

// ---------------------------------------------------------------------------
// ImageIntegrityStatus
// ---------------------------------------------------------------------------

#[test]
fn deep_integrity_all_count() {
    assert_eq!(ImageIntegrityStatus::ALL.len(), 4);
}

#[test]
fn deep_integrity_display_all() {
    let expected = [
        (ImageIntegrityStatus::Verified, "Verified"),
        (ImageIntegrityStatus::Unverified, "Unverified"),
        (
            ImageIntegrityStatus::CorruptionDetected,
            "CorruptionDetected",
        ),
        (ImageIntegrityStatus::Expired, "Expired"),
    ];
    for (status, name) in expected {
        assert_eq!(format!("{status}"), name);
    }
}

#[test]
fn deep_integrity_serde_roundtrip() {
    for status in ImageIntegrityStatus::ALL {
        let json = serde_json::to_string(status).unwrap();
        let decoded: ImageIntegrityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, decoded);
    }
}

// ---------------------------------------------------------------------------
// Cross-type uniqueness
// ---------------------------------------------------------------------------

#[test]
fn deep_image_kind_display_unique() {
    let mut names = std::collections::BTreeSet::new();
    for kind in ImageKind::ALL {
        assert!(names.insert(format!("{kind}")), "Duplicate: {kind}");
    }
}

#[test]
fn deep_image_state_display_unique() {
    let mut names = std::collections::BTreeSet::new();
    for state in ImageState::ALL {
        assert!(names.insert(format!("{state}")), "Duplicate: {state}");
    }
}

#[test]
fn deep_warm_start_display_unique() {
    let mut names = std::collections::BTreeSet::new();
    for mode in WarmStartMode::ALL {
        assert!(names.insert(format!("{mode}")), "Duplicate: {mode}");
    }
}

#[test]
fn deep_integrity_display_unique() {
    let mut names = std::collections::BTreeSet::new();
    for status in ImageIntegrityStatus::ALL {
        assert!(names.insert(format!("{status}")), "Duplicate: {status}");
    }
}

// ===========================================================================
// Additional deep tests: ImageRegistry and ImageManifest
// ===========================================================================

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_image_contract::{
    ImageEvictionReason, ImageManifest, ImagePolicy, ImageRegistry,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn test_manifest(id: &str, size: u64) -> ImageManifest {
    ImageManifest {
        image_id: id.to_string(),
        kind: ImageKind::Baseline,
        state: ImageState::Ready,
        creation_epoch: SecurityEpoch::from_raw(1),
        source_hash: ContentHash::compute(b"source"),
        image_hash: ContentHash::compute(id.as_bytes()),
        module_count: 5,
        total_size_bytes: size,
        warm_start_mode: WarmStartMode::PrewarmedPool,
        integrity_status: ImageIntegrityStatus::Verified,
        ttl_seconds: Some(3600),
        creation_reason: format!("test-{id}"),
    }
}

#[test]
fn deep_registry_new_is_empty() {
    let reg = ImageRegistry::new(ImagePolicy::default());
    assert!(reg.ready_images().is_empty());
    assert_eq!(reg.total_bytes(), 0);
}

#[test]
fn deep_registry_register_and_lookup() {
    let mut reg = ImageRegistry::new(ImagePolicy::default());
    reg.register(test_manifest("img-1", 1000)).unwrap();
    assert!(reg.lookup("img-1").is_some());
    assert!(reg.lookup("img-nonexistent").is_none());
}

#[test]
fn deep_registry_duplicate_id_rejected() {
    let mut reg = ImageRegistry::new(ImagePolicy::default());
    reg.register(test_manifest("img-dup", 500)).unwrap();
    let result = reg.register(test_manifest("img-dup", 500));
    assert!(result.is_err());
}

#[test]
fn deep_registry_total_bytes_tracks() {
    let mut reg = ImageRegistry::new(ImagePolicy::default());
    reg.register(test_manifest("a", 100)).unwrap();
    reg.register(test_manifest("b", 200)).unwrap();
    assert_eq!(reg.total_bytes(), 300);
}

#[test]
fn deep_registry_ready_images_only_returns_ready() {
    let mut reg = ImageRegistry::new(ImagePolicy::default());
    reg.register(test_manifest("r1", 100)).unwrap();
    let ready = reg.ready_images();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].image_id, "r1");
}

#[test]
fn deep_registry_content_hash_deterministic() {
    let mut r1 = ImageRegistry::new(ImagePolicy::default());
    let mut r2 = ImageRegistry::new(ImagePolicy::default());
    r1.register(test_manifest("x", 50)).unwrap();
    r2.register(test_manifest("x", 50)).unwrap();
    assert_eq!(r1.content_hash(), r2.content_hash());
}

#[test]
fn deep_registry_best_warm_start_selects_ready() {
    let mut reg = ImageRegistry::new(ImagePolicy::default());
    reg.register(test_manifest("warm-1", 100)).unwrap();
    let best = reg.best_warm_start();
    assert!(best.is_some());
    assert_eq!(best.unwrap().image_id, "warm-1");
}

#[test]
fn deep_eviction_reason_serde_roundtrip() {
    for reason in ImageEvictionReason::ALL {
        let json = serde_json::to_string(reason).unwrap();
        let back: ImageEvictionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

#[test]
fn deep_eviction_reason_display_all_distinct() {
    let mut names = std::collections::BTreeSet::new();
    for reason in ImageEvictionReason::ALL {
        assert!(names.insert(format!("{reason}")));
    }
    assert_eq!(names.len(), ImageEvictionReason::ALL.len());
}
