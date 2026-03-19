//! Enrichment integration tests for the `runtime_image_contract` module.
//!
//! Covers deeper edge cases, cross-enum interactions, Display uniqueness,
//! ordering guarantees, registry lifecycle sequences, content hash sensitivity,
//! eviction log accumulation, warm-start priority ladder, and serde stability
//! beyond the base integration test suite.

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

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::runtime_image_contract::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_hash(n: u8) -> ContentHash {
    ContentHash::compute(&[n])
}

fn make_manifest(
    id: &str,
    kind: ImageKind,
    mode: WarmStartMode,
    epoch: u64,
    size: u64,
) -> ImageManifest {
    ImageManifest {
        image_id: id.to_owned(),
        kind,
        state: ImageState::Ready,
        creation_epoch: SecurityEpoch::from_raw(epoch),
        source_hash: test_hash(0),
        image_hash: test_hash(1),
        module_count: 5,
        total_size_bytes: size,
        warm_start_mode: mode,
        integrity_status: ImageIntegrityStatus::Verified,
        ttl_seconds: Some(3600),
        creation_reason: "enrichment test".to_owned(),
    }
}

fn small_policy() -> ImagePolicy {
    ImagePolicy {
        max_image_count: 8,
        max_total_bytes: 16384,
        default_ttl_seconds: 600,
        allow_zygote: true,
        allow_cow: true,
        allow_aot: true,
        require_integrity_check: true,
        min_module_count_for_image: 1,
    }
}

// ---------------------------------------------------------------------------
// Enum Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_display_image_kind_all_unique() {
    let mut seen = BTreeSet::new();
    for kind in ImageKind::ALL {
        let s = kind.to_string();
        assert!(
            seen.insert(s.clone()),
            "duplicate Display for ImageKind: {s}"
        );
    }
    assert_eq!(seen.len(), ImageKind::ALL.len());
}

#[test]
fn enrichment_display_image_state_all_unique() {
    let mut seen = BTreeSet::new();
    for state in ImageState::ALL {
        let s = state.to_string();
        assert!(
            seen.insert(s.clone()),
            "duplicate Display for ImageState: {s}"
        );
    }
    assert_eq!(seen.len(), ImageState::ALL.len());
}

#[test]
fn enrichment_display_warm_start_mode_all_unique() {
    let mut seen = BTreeSet::new();
    for mode in WarmStartMode::ALL {
        let s = mode.to_string();
        assert!(
            seen.insert(s.clone()),
            "duplicate Display for WarmStartMode: {s}"
        );
    }
    assert_eq!(seen.len(), WarmStartMode::ALL.len());
}

#[test]
fn enrichment_display_integrity_status_all_unique() {
    let mut seen = BTreeSet::new();
    for status in ImageIntegrityStatus::ALL {
        let s = status.to_string();
        assert!(
            seen.insert(s.clone()),
            "duplicate Display for ImageIntegrityStatus: {s}"
        );
    }
    assert_eq!(seen.len(), ImageIntegrityStatus::ALL.len());
}

#[test]
fn enrichment_display_eviction_reason_all_unique() {
    let mut seen = BTreeSet::new();
    for reason in ImageEvictionReason::ALL {
        let s = reason.to_string();
        assert!(
            seen.insert(s.clone()),
            "duplicate Display for ImageEvictionReason: {s}"
        );
    }
    assert_eq!(seen.len(), ImageEvictionReason::ALL.len());
}

#[test]
fn enrichment_display_specimen_family_all_unique() {
    let mut seen = BTreeSet::new();
    for fam in ImageSpecimenFamily::ALL {
        let s = fam.to_string();
        assert!(
            seen.insert(s.clone()),
            "duplicate Display for ImageSpecimenFamily: {s}"
        );
    }
    assert_eq!(seen.len(), ImageSpecimenFamily::ALL.len());
}

// ---------------------------------------------------------------------------
// Enum ordering (Ord derives)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ordering_image_kind_follows_declaration_order() {
    for window in ImageKind::ALL.windows(2) {
        assert!(
            window[0] < window[1],
            "{:?} should be < {:?}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn enrichment_ordering_image_state_follows_declaration_order() {
    for window in ImageState::ALL.windows(2) {
        assert!(
            window[0] < window[1],
            "{:?} should be < {:?}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn enrichment_ordering_warm_start_mode_follows_declaration_order() {
    for window in WarmStartMode::ALL.windows(2) {
        assert!(
            window[0] < window[1],
            "{:?} should be < {:?}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn enrichment_ordering_eviction_reason_follows_declaration_order() {
    for window in ImageEvictionReason::ALL.windows(2) {
        assert!(
            window[0] < window[1],
            "{:?} should be < {:?}",
            window[0],
            window[1]
        );
    }
}

// ---------------------------------------------------------------------------
// Enum serde: cross-variant JSON distinctness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_image_kind_json_values_distinct() {
    let jsons: BTreeSet<String> = ImageKind::ALL
        .iter()
        .map(|k| serde_json::to_string(k).unwrap())
        .collect();
    assert_eq!(jsons.len(), ImageKind::ALL.len());
}

#[test]
fn enrichment_serde_warm_start_mode_json_values_distinct() {
    let jsons: BTreeSet<String> = WarmStartMode::ALL
        .iter()
        .map(|m| serde_json::to_string(m).unwrap())
        .collect();
    assert_eq!(jsons.len(), WarmStartMode::ALL.len());
}

#[test]
fn enrichment_serde_eviction_reason_json_values_distinct() {
    let jsons: BTreeSet<String> = ImageEvictionReason::ALL
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect();
    assert_eq!(jsons.len(), ImageEvictionReason::ALL.len());
}

// ---------------------------------------------------------------------------
// Struct construction edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_struct_manifest_zero_size_image() {
    let m = make_manifest("zero-size", ImageKind::Baseline, WarmStartMode::Cold, 1, 0);
    assert_eq!(m.total_size_bytes, 0);
    let json = serde_json::to_string(&m).unwrap();
    let back: ImageManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.total_size_bytes, 0);
}

#[test]
fn enrichment_struct_manifest_max_epoch() {
    let m = ImageManifest {
        image_id: "max-epoch".to_owned(),
        kind: ImageKind::CachedSnapshot,
        state: ImageState::Ready,
        creation_epoch: SecurityEpoch::from_raw(u64::MAX),
        source_hash: test_hash(10),
        image_hash: test_hash(11),
        module_count: 1,
        total_size_bytes: 1,
        warm_start_mode: WarmStartMode::Cold,
        integrity_status: ImageIntegrityStatus::Unverified,
        ttl_seconds: None,
        creation_reason: "boundary".to_owned(),
    };
    assert_eq!(m.creation_epoch.as_u64(), u64::MAX);
    let json = serde_json::to_string(&m).unwrap();
    let back: ImageManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.creation_epoch.as_u64(), u64::MAX);
}

#[test]
fn enrichment_struct_manifest_empty_id() {
    let m = make_manifest("", ImageKind::Baseline, WarmStartMode::Cold, 0, 0);
    assert!(m.image_id.is_empty());
    let json = serde_json::to_string(&m).unwrap();
    let back: ImageManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.image_id, "");
}

#[test]
fn enrichment_struct_manifest_large_module_count() {
    let mut m = make_manifest(
        "large-mc",
        ImageKind::Prewarmed,
        WarmStartMode::PrewarmedPool,
        1,
        4096,
    );
    m.module_count = 1_000_000;
    let json = serde_json::to_string(&m).unwrap();
    let back: ImageManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back.module_count, 1_000_000);
}

#[test]
fn enrichment_struct_policy_all_disabled() {
    let p = ImagePolicy {
        max_image_count: 0,
        max_total_bytes: 0,
        default_ttl_seconds: 0,
        allow_zygote: false,
        allow_cow: false,
        allow_aot: false,
        require_integrity_check: false,
        min_module_count_for_image: u64::MAX,
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: ImagePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
    assert!(!back.allow_zygote);
    assert!(!back.allow_cow);
    assert!(!back.allow_aot);
}

// ---------------------------------------------------------------------------
// Registry lifecycle: register-then-evict sequences
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_register_evict_reregister() {
    let mut reg = ImageRegistry::new(small_policy());
    let m = make_manifest("cycle", ImageKind::Baseline, WarmStartMode::Cold, 1, 1024);
    reg.register(m).unwrap();
    assert_eq!(reg.images.len(), 1);

    reg.evict(
        "cycle",
        ImageEvictionReason::ManualEviction,
        SecurityEpoch::from_raw(2),
    )
    .unwrap();
    assert!(reg.images.is_empty());
    assert_eq!(reg.eviction_log.len(), 1);

    // Re-register same ID after eviction should succeed.
    let m2 = make_manifest("cycle", ImageKind::Baseline, WarmStartMode::Cold, 3, 512);
    reg.register(m2).unwrap();
    assert_eq!(reg.images.len(), 1);
    assert_eq!(reg.lookup("cycle").unwrap().total_size_bytes, 512);
}

#[test]
fn enrichment_lifecycle_multiple_evictions_accumulate() {
    let mut reg = ImageRegistry::new(small_policy());
    for i in 0u8..4 {
        let id = format!("img-{i}");
        let m = make_manifest(
            &id,
            ImageKind::Baseline,
            WarmStartMode::Cold,
            u64::from(i),
            100,
        );
        reg.register(m).unwrap();
    }
    assert_eq!(reg.images.len(), 4);

    for i in 0u8..4 {
        let id = format!("img-{i}");
        reg.evict(
            &id,
            ImageEvictionReason::SourceChanged,
            SecurityEpoch::from_raw(10 + u64::from(i)),
        )
        .unwrap();
    }
    assert!(reg.images.is_empty());
    assert_eq!(reg.eviction_log.len(), 4);
    // Eviction log preserves insertion order.
    for (i, record) in reg.eviction_log.iter().enumerate() {
        assert_eq!(record.image_id, format!("img-{i}"));
        assert_eq!(record.evicted_epoch.as_u64(), 10 + i as u64);
    }
}

#[test]
fn enrichment_lifecycle_evict_middle_preserves_others() {
    let mut reg = ImageRegistry::new(small_policy());
    reg.register(make_manifest(
        "a",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        1,
        100,
    ))
    .unwrap();
    reg.register(make_manifest(
        "b",
        ImageKind::Prewarmed,
        WarmStartMode::PrewarmedPool,
        2,
        200,
    ))
    .unwrap();
    reg.register(make_manifest(
        "c",
        ImageKind::Zygote,
        WarmStartMode::ZygoteFork,
        3,
        300,
    ))
    .unwrap();
    assert_eq!(reg.images.len(), 3);

    reg.evict(
        "b",
        ImageEvictionReason::TtlExpired,
        SecurityEpoch::from_raw(5),
    )
    .unwrap();
    assert_eq!(reg.images.len(), 2);
    assert!(reg.lookup("a").is_some());
    assert!(reg.lookup("b").is_none());
    assert!(reg.lookup("c").is_some());
    assert_eq!(reg.total_bytes(), 400);
}

// ---------------------------------------------------------------------------
// Registry: ready_images filtering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_ready_images_excludes_all_non_ready_states() {
    let mut reg = ImageRegistry::new(small_policy());

    let non_ready_states = [
        ImageState::Building,
        ImageState::Stale,
        ImageState::Invalidated,
        ImageState::Disabled,
    ];
    for (i, state) in non_ready_states.iter().enumerate() {
        let mut m = make_manifest(
            &format!("nr-{i}"),
            ImageKind::Baseline,
            WarmStartMode::Cold,
            u64::try_from(i).unwrap(),
            64,
        );
        m.state = *state;
        reg.register(m).unwrap();
    }

    let mut ready_m = make_manifest(
        "ready-one",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        10,
        64,
    );
    ready_m.state = ImageState::Ready;
    reg.register(ready_m).unwrap();

    let ready = reg.ready_images();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].image_id, "ready-one");
}

#[test]
fn enrichment_lifecycle_ready_images_empty_when_no_ready() {
    let mut reg = ImageRegistry::new(small_policy());
    let mut m = make_manifest("building", ImageKind::Baseline, WarmStartMode::Cold, 1, 64);
    m.state = ImageState::Building;
    reg.register(m).unwrap();
    assert!(reg.ready_images().is_empty());
}

// ---------------------------------------------------------------------------
// best_warm_start: full priority ladder
// ---------------------------------------------------------------------------

#[test]
fn enrichment_warmstart_priority_ladder_all_tiers() {
    let mut reg = ImageRegistry::new(small_policy());

    // Register one of each warm-start mode (all Ready).
    reg.register(make_manifest(
        "cow",
        ImageKind::Baseline,
        WarmStartMode::CowSnapshot,
        1,
        100,
    ))
    .unwrap();
    reg.register(make_manifest(
        "pool",
        ImageKind::Prewarmed,
        WarmStartMode::PrewarmedPool,
        2,
        100,
    ))
    .unwrap();
    reg.register(make_manifest(
        "zyg",
        ImageKind::Zygote,
        WarmStartMode::ZygoteFork,
        3,
        100,
    ))
    .unwrap();
    reg.register(make_manifest(
        "aot",
        ImageKind::AotCompiled,
        WarmStartMode::AotRestore,
        4,
        100,
    ))
    .unwrap();

    let best = reg.best_warm_start().unwrap();
    assert_eq!(
        best.image_id, "aot",
        "AotRestore should be highest priority"
    );
}

#[test]
fn enrichment_warmstart_zygote_over_prewarmed() {
    let mut reg = ImageRegistry::new(small_policy());
    reg.register(make_manifest(
        "pool",
        ImageKind::Prewarmed,
        WarmStartMode::PrewarmedPool,
        5,
        100,
    ))
    .unwrap();
    reg.register(make_manifest(
        "zyg",
        ImageKind::Zygote,
        WarmStartMode::ZygoteFork,
        1,
        100,
    ))
    .unwrap();

    let best = reg.best_warm_start().unwrap();
    assert_eq!(
        best.image_id, "zyg",
        "ZygoteFork (priority 3) should beat PrewarmedPool (priority 2) regardless of epoch"
    );
}

#[test]
fn enrichment_warmstart_cow_is_lowest_non_cold() {
    let mut reg = ImageRegistry::new(small_policy());
    reg.register(make_manifest(
        "cold",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        10,
        100,
    ))
    .unwrap();
    reg.register(make_manifest(
        "cow",
        ImageKind::Baseline,
        WarmStartMode::CowSnapshot,
        1,
        100,
    ))
    .unwrap();

    let best = reg.best_warm_start().unwrap();
    assert_eq!(
        best.image_id, "cow",
        "CowSnapshot should be selected over Cold"
    );
}

#[test]
fn enrichment_warmstart_epoch_tiebreak_within_same_tier() {
    let mut reg = ImageRegistry::new(small_policy());
    reg.register(make_manifest(
        "p1",
        ImageKind::Prewarmed,
        WarmStartMode::PrewarmedPool,
        3,
        100,
    ))
    .unwrap();
    reg.register(make_manifest(
        "p2",
        ImageKind::Prewarmed,
        WarmStartMode::PrewarmedPool,
        7,
        100,
    ))
    .unwrap();
    reg.register(make_manifest(
        "p3",
        ImageKind::Prewarmed,
        WarmStartMode::PrewarmedPool,
        5,
        100,
    ))
    .unwrap();

    let best = reg.best_warm_start().unwrap();
    assert_eq!(best.image_id, "p2", "Highest epoch within same tier wins");
}

#[test]
fn enrichment_warmstart_empty_registry_returns_none() {
    let reg = ImageRegistry::new(small_policy());
    assert!(reg.best_warm_start().is_none());
}

// ---------------------------------------------------------------------------
// Content hash: sensitivity and determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_hash_empty_registry_is_deterministic() {
    let r1 = ImageRegistry::new(small_policy());
    let r2 = ImageRegistry::new(small_policy());
    assert_eq!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_hash_sensitive_to_image_size() {
    let mut r1 = ImageRegistry::new(small_policy());
    r1.register(make_manifest(
        "x",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        1,
        100,
    ))
    .unwrap();

    let mut r2 = ImageRegistry::new(small_policy());
    r2.register(make_manifest(
        "x",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        1,
        200,
    ))
    .unwrap();

    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_hash_sensitive_to_module_count() {
    let mut r1 = ImageRegistry::new(small_policy());
    let mut m1 = make_manifest("x", ImageKind::Baseline, WarmStartMode::Cold, 1, 100);
    m1.module_count = 5;
    r1.register(m1).unwrap();

    let mut r2 = ImageRegistry::new(small_policy());
    let mut m2 = make_manifest("x", ImageKind::Baseline, WarmStartMode::Cold, 1, 100);
    m2.module_count = 10;
    r2.register(m2).unwrap();

    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_hash_sensitive_to_creation_epoch() {
    let mut r1 = ImageRegistry::new(small_policy());
    r1.register(make_manifest(
        "x",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        1,
        100,
    ))
    .unwrap();

    let mut r2 = ImageRegistry::new(small_policy());
    r2.register(make_manifest(
        "x",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        2,
        100,
    ))
    .unwrap();

    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_hash_sensitive_to_image_hash() {
    let mut r1 = ImageRegistry::new(small_policy());
    let mut m1 = make_manifest("x", ImageKind::Baseline, WarmStartMode::Cold, 1, 100);
    m1.image_hash = ContentHash::compute(&[42]);
    r1.register(m1).unwrap();

    let mut r2 = ImageRegistry::new(small_policy());
    let mut m2 = make_manifest("x", ImageKind::Baseline, WarmStartMode::Cold, 1, 100);
    m2.image_hash = ContentHash::compute(&[99]);
    r2.register(m2).unwrap();

    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_hash_sensitive_to_eviction_epoch() {
    let mut r1 = ImageRegistry::new(small_policy());
    r1.register(make_manifest(
        "x",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        1,
        100,
    ))
    .unwrap();
    r1.evict(
        "x",
        ImageEvictionReason::TtlExpired,
        SecurityEpoch::from_raw(10),
    )
    .unwrap();

    let mut r2 = ImageRegistry::new(small_policy());
    r2.register(make_manifest(
        "x",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        1,
        100,
    ))
    .unwrap();
    r2.evict(
        "x",
        ImageEvictionReason::TtlExpired,
        SecurityEpoch::from_raw(20),
    )
    .unwrap();

    assert_ne!(r1.content_hash(), r2.content_hash());
}

#[test]
fn enrichment_hash_sensitive_to_image_order() {
    let mut r1 = ImageRegistry::new(small_policy());
    r1.register(make_manifest(
        "a",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        1,
        100,
    ))
    .unwrap();
    r1.register(make_manifest(
        "b",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        2,
        200,
    ))
    .unwrap();

    let mut r2 = ImageRegistry::new(small_policy());
    r2.register(make_manifest(
        "b",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        2,
        200,
    ))
    .unwrap();
    r2.register(make_manifest(
        "a",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        1,
        100,
    ))
    .unwrap();

    // Image order matters because the hash iterates in Vec insertion order.
    assert_ne!(r1.content_hash(), r2.content_hash());
}

// ---------------------------------------------------------------------------
// Registry: total_bytes arithmetic
// ---------------------------------------------------------------------------

#[test]
fn enrichment_arithmetic_total_bytes_empty() {
    let reg = ImageRegistry::new(small_policy());
    assert_eq!(reg.total_bytes(), 0);
}

#[test]
fn enrichment_arithmetic_total_bytes_accumulates() {
    let mut reg = ImageRegistry::new(small_policy());
    reg.register(make_manifest(
        "a",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        1,
        1000,
    ))
    .unwrap();
    reg.register(make_manifest(
        "b",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        2,
        2000,
    ))
    .unwrap();
    reg.register(make_manifest(
        "c",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        3,
        3000,
    ))
    .unwrap();
    assert_eq!(reg.total_bytes(), 6000);
}

#[test]
fn enrichment_arithmetic_total_bytes_after_evict_is_consistent() {
    let mut reg = ImageRegistry::new(small_policy());
    reg.register(make_manifest(
        "a",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        1,
        500,
    ))
    .unwrap();
    reg.register(make_manifest(
        "b",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        2,
        700,
    ))
    .unwrap();
    assert_eq!(reg.total_bytes(), 1200);

    let record = reg
        .evict(
            "a",
            ImageEvictionReason::CapacityExceeded,
            SecurityEpoch::from_raw(5),
        )
        .unwrap();
    assert_eq!(record.bytes_freed, 500);
    assert_eq!(reg.total_bytes(), 700);
}

// ---------------------------------------------------------------------------
// Registry: policy enforcement edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_edge_policy_max_image_count_exactly_at_limit() {
    let policy = ImagePolicy {
        max_image_count: 3,
        ..small_policy()
    };
    let mut reg = ImageRegistry::new(policy);
    reg.register(make_manifest(
        "a",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        1,
        100,
    ))
    .unwrap();
    reg.register(make_manifest(
        "b",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        2,
        100,
    ))
    .unwrap();
    reg.register(make_manifest(
        "c",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        3,
        100,
    ))
    .unwrap();
    // Exactly at limit; next should fail.
    let err = reg
        .register(make_manifest(
            "d",
            ImageKind::Baseline,
            WarmStartMode::Cold,
            4,
            100,
        ))
        .unwrap_err();
    assert!(matches!(err, ImageRegistryError::CapacityExceeded { .. }));
}

#[test]
fn enrichment_edge_policy_max_bytes_exactly_at_limit() {
    let policy = ImagePolicy {
        max_total_bytes: 200,
        ..small_policy()
    };
    let mut reg = ImageRegistry::new(policy);
    // First image uses exactly all capacity.
    reg.register(make_manifest(
        "a",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        1,
        200,
    ))
    .unwrap();
    // Even a 1-byte image should fail.
    let err = reg
        .register(make_manifest(
            "b",
            ImageKind::Baseline,
            WarmStartMode::Cold,
            2,
            1,
        ))
        .unwrap_err();
    assert!(matches!(err, ImageRegistryError::CapacityExceeded { .. }));
}

#[test]
fn enrichment_edge_policy_min_module_count_boundary() {
    let policy = ImagePolicy {
        min_module_count_for_image: 5,
        ..small_policy()
    };
    let mut reg = ImageRegistry::new(policy);

    // module_count = 4 should fail.
    let mut m4 = make_manifest("below", ImageKind::Baseline, WarmStartMode::Cold, 1, 100);
    m4.module_count = 4;
    let err = reg.register(m4).unwrap_err();
    assert!(matches!(err, ImageRegistryError::PolicyViolation { .. }));

    // module_count = 5 should succeed (boundary).
    let mut m5 = make_manifest("exact", ImageKind::Baseline, WarmStartMode::Cold, 2, 100);
    m5.module_count = 5;
    assert!(reg.register(m5).is_ok());
}

// ---------------------------------------------------------------------------
// Serde roundtrip: complex registry state
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_registry_with_mixed_state() {
    let mut reg = ImageRegistry::new(small_policy());

    let mut m1 = make_manifest(
        "ready",
        ImageKind::Prewarmed,
        WarmStartMode::PrewarmedPool,
        1,
        512,
    );
    m1.state = ImageState::Ready;
    reg.register(m1).unwrap();

    let mut m2 = make_manifest(
        "building",
        ImageKind::Zygote,
        WarmStartMode::ZygoteFork,
        2,
        256,
    );
    m2.state = ImageState::Building;
    reg.register(m2).unwrap();

    let mut m3 = make_manifest(
        "stale",
        ImageKind::AotCompiled,
        WarmStartMode::AotRestore,
        3,
        768,
    );
    m3.state = ImageState::Stale;
    reg.register(m3).unwrap();

    // Evict the building image.
    reg.evict(
        "building",
        ImageEvictionReason::IntegrityFailure,
        SecurityEpoch::from_raw(10),
    )
    .unwrap();

    let json = serde_json::to_string(&reg).unwrap();
    let back: ImageRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(reg, back);
    assert_eq!(back.images.len(), 2);
    assert_eq!(back.eviction_log.len(), 1);
    assert_eq!(
        back.eviction_log[0].reason,
        ImageEvictionReason::IntegrityFailure
    );
}

#[test]
fn enrichment_serde_eviction_record_all_reasons() {
    for reason in ImageEvictionReason::ALL {
        let record = ImageEvictionRecord {
            image_id: format!("ev-{reason}"),
            reason: *reason,
            evicted_epoch: SecurityEpoch::from_raw(42),
            bytes_freed: 1234,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: ImageEvictionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }
}

// ---------------------------------------------------------------------------
// Error: serde and display for all variants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_serde_error_all_variants_roundtrip() {
    let errors: Vec<ImageRegistryError> = vec![
        ImageRegistryError::ImageAlreadyExists {
            id: "dup-123".to_owned(),
        },
        ImageRegistryError::CapacityExceeded {
            current: 9999,
            max: 5000,
        },
        ImageRegistryError::ImageNotFound {
            id: "ghost".to_owned(),
        },
        ImageRegistryError::PolicyViolation {
            reason: "test violation".to_owned(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ImageRegistryError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_display_error_all_variants_non_empty() {
    let errors: Vec<ImageRegistryError> = vec![
        ImageRegistryError::ImageAlreadyExists { id: "a".to_owned() },
        ImageRegistryError::CapacityExceeded { current: 0, max: 0 },
        ImageRegistryError::ImageNotFound { id: "b".to_owned() },
        ImageRegistryError::PolicyViolation {
            reason: "r".to_owned(),
        },
    ];
    for err in &errors {
        let s = err.to_string();
        assert!(!s.is_empty(), "Display for {err:?} should not be empty");
    }
}

// ---------------------------------------------------------------------------
// Clone and equality
// ---------------------------------------------------------------------------

#[test]
fn enrichment_edge_manifest_clone_is_equal() {
    let m = make_manifest(
        "clone-test",
        ImageKind::AotCompiled,
        WarmStartMode::AotRestore,
        7,
        4096,
    );
    let cloned = m.clone();
    assert_eq!(m, cloned);
}

#[test]
fn enrichment_edge_registry_clone_is_equal() {
    let mut reg = ImageRegistry::new(small_policy());
    reg.register(make_manifest(
        "x",
        ImageKind::Baseline,
        WarmStartMode::Cold,
        1,
        100,
    ))
    .unwrap();
    reg.evict(
        "x",
        ImageEvictionReason::ManualEviction,
        SecurityEpoch::from_raw(5),
    )
    .unwrap();
    let cloned = reg.clone();
    assert_eq!(reg, cloned);
    assert_eq!(reg.content_hash(), cloned.content_hash());
}

// ---------------------------------------------------------------------------
// Schema version propagation
// ---------------------------------------------------------------------------

#[test]
fn enrichment_edge_schema_version_in_new_registry() {
    let reg = ImageRegistry::new(ImagePolicy::default());
    assert_eq!(
        reg.schema_version,
        "franken-engine.runtime-image-contract.v1"
    );
}
