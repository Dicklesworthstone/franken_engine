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
