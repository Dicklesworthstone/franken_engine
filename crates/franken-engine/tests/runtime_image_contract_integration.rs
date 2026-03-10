//! Integration tests for the `runtime_image_contract` module.
//!
//! Covers all public enums (Display + serde roundtrip), struct construction,
//! registry operations (register, lookup, evict, best_warm_start), policy
//! enforcement, content hashing, and edge cases.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_image_contract::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ImageKind
// ---------------------------------------------------------------------------

#[test]
fn image_kind_display_all() {
    let expected = [
        "Baseline",
        "Prewarmed",
        "Zygote",
        "AotCompiled",
        "CachedSnapshot",
    ];
    for (kind, exp) in ImageKind::ALL.iter().zip(expected.iter()) {
        assert_eq!(kind.to_string(), *exp);
    }
}

#[test]
fn image_kind_serde_roundtrip_all() {
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

// ---------------------------------------------------------------------------
// ImageState
// ---------------------------------------------------------------------------

#[test]
fn image_state_display_all() {
    let expected = ["Building", "Ready", "Stale", "Invalidated", "Disabled"];
    for (state, exp) in ImageState::ALL.iter().zip(expected.iter()) {
        assert_eq!(state.to_string(), *exp);
    }
}

#[test]
fn image_state_serde_roundtrip_all() {
    for state in ImageState::ALL {
        let json = serde_json::to_string(state).unwrap();
        let back: ImageState = serde_json::from_str(&json).unwrap();
        assert_eq!(*state, back);
    }
}

#[test]
fn image_state_all_count() {
    assert_eq!(ImageState::ALL.len(), 5);
}

// ---------------------------------------------------------------------------
// WarmStartMode
// ---------------------------------------------------------------------------

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
fn warm_start_mode_serde_roundtrip_all() {
    for mode in WarmStartMode::ALL {
        let json = serde_json::to_string(mode).unwrap();
        let back: WarmStartMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, back);
    }
}

#[test]
fn warm_start_mode_all_count() {
    assert_eq!(WarmStartMode::ALL.len(), 5);
}

// ---------------------------------------------------------------------------
// ImageIntegrityStatus
// ---------------------------------------------------------------------------

#[test]
fn integrity_status_display_all() {
    let expected = ["Verified", "Unverified", "CorruptionDetected", "Expired"];
    for (status, exp) in ImageIntegrityStatus::ALL.iter().zip(expected.iter()) {
        assert_eq!(status.to_string(), *exp);
    }
}

#[test]
fn integrity_status_serde_roundtrip_all() {
    for status in ImageIntegrityStatus::ALL {
        let json = serde_json::to_string(status).unwrap();
        let back: ImageIntegrityStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, back);
    }
}

#[test]
fn integrity_status_all_count() {
    assert_eq!(ImageIntegrityStatus::ALL.len(), 4);
}

// ---------------------------------------------------------------------------
// ImageEvictionReason
// ---------------------------------------------------------------------------

#[test]
fn eviction_reason_display_all() {
    let expected = [
        "TtlExpired",
        "SourceChanged",
        "CapacityExceeded",
        "IntegrityFailure",
        "PolicyDisabled",
        "ManualEviction",
    ];
    for (reason, exp) in ImageEvictionReason::ALL.iter().zip(expected.iter()) {
        assert_eq!(reason.to_string(), *exp);
    }
}

#[test]
fn eviction_reason_serde_roundtrip_all() {
    for reason in ImageEvictionReason::ALL {
        let json = serde_json::to_string(reason).unwrap();
        let back: ImageEvictionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*reason, back);
    }
}

#[test]
fn eviction_reason_all_count() {
    assert_eq!(ImageEvictionReason::ALL.len(), 6);
}

// ---------------------------------------------------------------------------
// ImageSpecimenFamily
// ---------------------------------------------------------------------------

#[test]
fn specimen_family_display_all() {
    let expected = [
        "Baseline",
        "Prewarmed",
        "Zygote",
        "Aot",
        "Eviction",
        "Mixed",
    ];
    for (fam, exp) in ImageSpecimenFamily::ALL.iter().zip(expected.iter()) {
        assert_eq!(fam.to_string(), *exp);
    }
}

#[test]
fn specimen_family_serde_roundtrip_all() {
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

// ---------------------------------------------------------------------------
// ImageManifest
// ---------------------------------------------------------------------------

#[test]
fn manifest_construction_and_fields() {
    let m = test_manifest("img-1");
    assert_eq!(m.image_id, "img-1");
    assert_eq!(m.kind, ImageKind::Baseline);
    assert_eq!(m.state, ImageState::Ready);
    assert_eq!(m.module_count, 5);
    assert_eq!(m.total_size_bytes, 1024);
    assert_eq!(m.warm_start_mode, WarmStartMode::Cold);
    assert_eq!(m.integrity_status, ImageIntegrityStatus::Verified);
    assert_eq!(m.ttl_seconds, Some(3600));
}

#[test]
fn manifest_serde_roundtrip() {
    let m = test_manifest("img-serde");
    let json = serde_json::to_string(&m).unwrap();
    let back: ImageManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn manifest_no_ttl() {
    let mut m = test_manifest("no-ttl");
    m.ttl_seconds = None;
    let json = serde_json::to_string(&m).unwrap();
    let back: ImageManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.ttl_seconds, None);
}

// ---------------------------------------------------------------------------
// ImagePolicy
// ---------------------------------------------------------------------------

#[test]
fn policy_defaults() {
    let p = ImagePolicy::default();
    assert_eq!(p.max_image_count, 16);
    assert_eq!(p.max_total_bytes, 512 * 1024 * 1024);
    assert_eq!(p.default_ttl_seconds, 3600);
    assert!(p.allow_zygote);
    assert!(p.allow_cow);
    assert!(p.allow_aot);
    assert!(p.require_integrity_check);
    assert_eq!(p.min_module_count_for_image, 1);
}

#[test]
fn policy_serde_roundtrip() {
    let p = test_policy();
    let json = serde_json::to_string(&p).unwrap();
    let back: ImagePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// ImageRegistryError
// ---------------------------------------------------------------------------

#[test]
fn error_display_image_already_exists() {
    let e = ImageRegistryError::ImageAlreadyExists { id: "x".to_owned() };
    assert!(e.to_string().contains("already exists"));
    assert!(e.to_string().contains("x"));
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

#[test]
fn error_serde_roundtrip() {
    let e = ImageRegistryError::CapacityExceeded {
        current: 42,
        max: 10,
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: ImageRegistryError = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// ImageEvictionRecord
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ImageRegistry — construction
// ---------------------------------------------------------------------------

#[test]
fn registry_new_empty() {
    let reg = ImageRegistry::new(test_policy());
    assert!(reg.images.is_empty());
    assert!(reg.eviction_log.is_empty());
    assert_eq!(reg.schema_version, RUNTIME_IMAGE_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// ImageRegistry — register
// ---------------------------------------------------------------------------

#[test]
fn registry_register_success() {
    let mut reg = ImageRegistry::new(test_policy());
    assert!(reg.register(test_manifest("img-1")).is_ok());
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
    reg.register(test_manifest("a")).unwrap();
    let err = reg.register(test_manifest("b")).unwrap_err();
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

// ---------------------------------------------------------------------------
// ImageRegistry — lookup
// ---------------------------------------------------------------------------

#[test]
fn registry_lookup_found() {
    let mut reg = ImageRegistry::new(test_policy());
    reg.register(test_manifest("look")).unwrap();
    assert!(reg.lookup("look").is_some());
    assert_eq!(reg.lookup("look").unwrap().image_id, "look");
}

#[test]
fn registry_lookup_not_found() {
    let reg = ImageRegistry::new(test_policy());
    assert!(reg.lookup("nope").is_none());
}

// ---------------------------------------------------------------------------
// ImageRegistry — ready_images
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ImageRegistry — evict
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ImageRegistry — best_warm_start
// ---------------------------------------------------------------------------

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
    reg.register(test_manifest("cold")).unwrap();
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

#[test]
fn registry_best_warm_start_tiebreak_by_epoch() {
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

// ---------------------------------------------------------------------------
// ImageRegistry — total_bytes
// ---------------------------------------------------------------------------

#[test]
fn registry_total_bytes() {
    let mut reg = ImageRegistry::new(test_policy());
    reg.register(test_manifest("a")).unwrap();
    reg.register(test_manifest("b")).unwrap();
    assert_eq!(reg.total_bytes(), 2048);
}

// ---------------------------------------------------------------------------
// ImageRegistry — content_hash
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ImageRegistry — serde roundtrip
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_constants() {
    assert!(RUNTIME_IMAGE_SCHEMA_VERSION.contains("runtime-image-contract"));
    assert_eq!(RUNTIME_IMAGE_BEAD_ID, "bd-1lsy.7.10.4");
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn registry_register_baseline_cow_allowed_by_default() {
    let mut reg = ImageRegistry::new(test_policy());
    let mut m = test_manifest("cow-baseline");
    m.warm_start_mode = WarmStartMode::CowSnapshot;
    assert!(reg.register(m).is_ok());
}

#[test]
fn registry_evict_updates_total_bytes() {
    let mut reg = ImageRegistry::new(test_policy());
    reg.register(test_manifest("a")).unwrap();
    reg.register(test_manifest("b")).unwrap();
    assert_eq!(reg.total_bytes(), 2048);
    reg.evict(
        "a",
        ImageEvictionReason::TtlExpired,
        SecurityEpoch::from_raw(1),
    )
    .unwrap();
    assert_eq!(reg.total_bytes(), 1024);
}

#[test]
fn registry_content_hash_includes_eviction_log() {
    let mut r1 = ImageRegistry::new(test_policy());
    r1.register(test_manifest("x")).unwrap();
    let h1 = r1.content_hash();

    let mut r2 = ImageRegistry::new(test_policy());
    r2.register(test_manifest("x")).unwrap();
    r2.evict(
        "x",
        ImageEvictionReason::ManualEviction,
        SecurityEpoch::from_raw(1),
    )
    .unwrap();
    let h2 = r2.content_hash();

    assert_ne!(h1, h2);
}
