#![forbid(unsafe_code)]
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

use frankenengine_engine::metadata_substrate_optimized::{
    FallbackPath, OptimizationLevel, OverrideConfig, RollbackStrategy, SUBSTRATE_OPT_COMPONENT,
    SUBSTRATE_OPT_POLICY_ID, SUBSTRATE_OPT_SCHEMA_VERSION, SubstrateError,
    SubstrateEvidenceManifest, SubstrateInventoryReport, SubstrateKind, SubstrateProfile,
    SubstrateTransition, TransitionTrigger, apply_override, build_canonical_inventory,
    certify_substrate, compute_transition_cost, evaluate_substrate, recommend_substrate_kind,
    run_substrate_evidence,
};

fn hot_profile(id: &str, kind: SubstrateKind, accesses: u64) -> SubstrateProfile {
    SubstrateProfile {
        id: id.into(),
        kind,
        access_count: accesses,
        hit_rate_millionths: 900_000,
        avg_latency_millionths: 100,
        memory_bytes: 32_768,
        is_hot: true,
    }
}

// =========================================================================
// A. SubstrateKind ordering in BTreeSet
// =========================================================================

#[test]
fn enrichment_substrate_kind_btree_set_dedup() {
    let mut set = BTreeSet::new();
    set.insert(SubstrateKind::SwissTable);
    set.insert(SubstrateKind::ArtTree);
    set.insert(SubstrateKind::SwissTable); // dup
    set.insert(SubstrateKind::FlatArray);
    set.insert(SubstrateKind::CompactBitmap);
    set.insert(SubstrateKind::InlineCache);
    set.insert(SubstrateKind::Swizzled);
    set.insert(SubstrateKind::GenericFallback);
    assert_eq!(set.len(), 7);
}

#[test]
fn enrichment_substrate_kind_ordering() {
    assert!(SubstrateKind::SwissTable < SubstrateKind::ArtTree);
    assert!(SubstrateKind::ArtTree < SubstrateKind::FlatArray);
    assert!(SubstrateKind::GenericFallback > SubstrateKind::Swizzled);
}

// =========================================================================
// B. OptimizationLevel ordering and BTreeSet
// =========================================================================

#[test]
fn enrichment_optimization_level_ordering() {
    assert!(OptimizationLevel::Unoptimized < OptimizationLevel::LocalityAware);
    assert!(OptimizationLevel::LocalityAware < OptimizationLevel::CacheLine);
    assert!(OptimizationLevel::CacheLine < OptimizationLevel::Prefetched);
    assert!(OptimizationLevel::Prefetched < OptimizationLevel::FullySwizzled);
}

#[test]
fn enrichment_optimization_level_btree_set() {
    let mut set = BTreeSet::new();
    set.insert(OptimizationLevel::Unoptimized);
    set.insert(OptimizationLevel::LocalityAware);
    set.insert(OptimizationLevel::CacheLine);
    set.insert(OptimizationLevel::Prefetched);
    set.insert(OptimizationLevel::FullySwizzled);
    set.insert(OptimizationLevel::Unoptimized); // dup
    assert_eq!(set.len(), 5);
}

// =========================================================================
// C. FallbackPath ordering
// =========================================================================

#[test]
fn enrichment_fallback_path_ordering() {
    assert!(FallbackPath::GenericScan < FallbackPath::SortedArray);
    assert!(FallbackPath::SortedArray < FallbackPath::BTreeLookup);
    assert!(FallbackPath::Abstain > FallbackPath::LinearProbe);
}

// =========================================================================
// D. Display all variants of each enum
// =========================================================================

#[test]
fn enrichment_substrate_kind_display_all_variants() {
    let displays = [
        (SubstrateKind::SwissTable, "swiss_table"),
        (SubstrateKind::ArtTree, "art_tree"),
        (SubstrateKind::FlatArray, "flat_array"),
        (SubstrateKind::CompactBitmap, "compact_bitmap"),
        (SubstrateKind::InlineCache, "inline_cache"),
        (SubstrateKind::Swizzled, "swizzled"),
        (SubstrateKind::GenericFallback, "generic_fallback"),
    ];
    for (kind, expected) in displays {
        assert_eq!(kind.to_string(), expected);
    }
}

#[test]
fn enrichment_optimization_level_display_all_variants() {
    let displays = [
        (OptimizationLevel::Unoptimized, "unoptimized"),
        (OptimizationLevel::LocalityAware, "locality_aware"),
        (OptimizationLevel::CacheLine, "cache_line"),
        (OptimizationLevel::Prefetched, "prefetched"),
        (OptimizationLevel::FullySwizzled, "fully_swizzled"),
    ];
    for (level, expected) in displays {
        assert_eq!(level.to_string(), expected);
    }
}

#[test]
fn enrichment_fallback_path_display_all_variants() {
    let displays = [
        (FallbackPath::GenericScan, "generic_scan"),
        (FallbackPath::SortedArray, "sorted_array"),
        (FallbackPath::BTreeLookup, "btree_lookup"),
        (FallbackPath::LinearProbe, "linear_probe"),
        (FallbackPath::Abstain, "abstain"),
    ];
    for (path, expected) in displays {
        assert_eq!(path.to_string(), expected);
    }
}

#[test]
fn enrichment_rollback_strategy_display_all_variants() {
    let displays = [
        (RollbackStrategy::SnapshotRestore, "snapshot_restore"),
        (RollbackStrategy::EpochInvalidate, "epoch_invalidate"),
        (RollbackStrategy::CowClone, "cow_clone"),
        (RollbackStrategy::Rebuild, "rebuild"),
        (RollbackStrategy::NoRollback, "no_rollback"),
    ];
    for (strategy, expected) in displays {
        assert_eq!(strategy.to_string(), expected);
    }
}

#[test]
fn enrichment_transition_trigger_display_all_variants() {
    let displays = [
        (TransitionTrigger::HotnessThreshold, "hotness_threshold"),
        (TransitionTrigger::MemoryPressure, "memory_pressure"),
        (TransitionTrigger::LatencySpike, "latency_spike"),
        (TransitionTrigger::ManualOverride, "manual_override"),
        (TransitionTrigger::FallbackTriggered, "fallback_triggered"),
        (TransitionTrigger::PortabilityCheck, "portability_check"),
    ];
    for (trigger, expected) in displays {
        assert_eq!(trigger.to_string(), expected);
    }
}

// =========================================================================
// E. Display strings for all enum variants are distinct
// =========================================================================

#[test]
fn enrichment_substrate_kind_display_distinct() {
    let kinds = [
        SubstrateKind::SwissTable,
        SubstrateKind::ArtTree,
        SubstrateKind::FlatArray,
        SubstrateKind::CompactBitmap,
        SubstrateKind::InlineCache,
        SubstrateKind::Swizzled,
        SubstrateKind::GenericFallback,
    ];
    let strs: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(strs.len(), 7);
}

#[test]
fn enrichment_transition_trigger_display_distinct() {
    let triggers = [
        TransitionTrigger::HotnessThreshold,
        TransitionTrigger::MemoryPressure,
        TransitionTrigger::LatencySpike,
        TransitionTrigger::ManualOverride,
        TransitionTrigger::FallbackTriggered,
        TransitionTrigger::PortabilityCheck,
    ];
    let strs: BTreeSet<String> = triggers.iter().map(|t| t.to_string()).collect();
    assert_eq!(strs.len(), 6);
}

// =========================================================================
// F. SubstrateError Display all variants
// =========================================================================

#[test]
fn enrichment_substrate_error_display_all_variants() {
    let e1 = SubstrateError::EmptyInventory;
    assert_eq!(e1.to_string(), "empty inventory");

    let e2 = SubstrateError::InvalidProfile {
        reason: "negative accesses".to_string(),
    };
    assert!(e2.to_string().contains("negative accesses"));

    let e3 = SubstrateError::TransitionForbidden {
        from: SubstrateKind::ArtTree,
        to: SubstrateKind::CompactBitmap,
    };
    let s3 = e3.to_string();
    assert!(s3.contains("art_tree"));
    assert!(s3.contains("compact_bitmap"));

    let e4 = SubstrateError::OverrideConflict {
        reason: "conflicting force".to_string(),
    };
    assert!(e4.to_string().contains("conflicting force"));
}

// =========================================================================
// G. OverrideConfig Display
// =========================================================================

#[test]
fn enrichment_override_config_display_default() {
    let config = OverrideConfig::default();
    let display = format!("{config}");
    assert!(display.contains("OverrideConfig"));
    assert!(display.contains("false")); // disable_optimization=false
}

#[test]
fn enrichment_override_config_display_with_force_kind() {
    let config = OverrideConfig {
        force_kind: Some(SubstrateKind::SwissTable),
        ..OverrideConfig::default()
    };
    let display = format!("{config}");
    assert!(display.contains("SwissTable") || display.contains("swiss_table"));
}

// =========================================================================
// H. Complex type Display
// =========================================================================

#[test]
fn enrichment_substrate_profile_display_cold() {
    let profile = SubstrateProfile {
        id: "cold-disp".into(),
        kind: SubstrateKind::GenericFallback,
        access_count: 50,
        hit_rate_millionths: 400_000,
        avg_latency_millionths: 1000,
        memory_bytes: 2048,
        is_hot: false,
    };
    let display = format!("{profile}");
    assert!(display.contains("cold-disp"));
    assert!(display.contains("generic_fallback"));
    assert!(display.contains("hot=false"));
}

#[test]
fn enrichment_optimization_decision_display_contains_kinds() {
    let profile = hot_profile("dec-disp-full", SubstrateKind::FlatArray, 50_000);
    let decision = evaluate_substrate(&profile, None);
    let display = format!("{decision}");
    assert!(display.contains("dec-disp-full"));
    assert!(display.contains("flat_array"));
}

#[test]
fn enrichment_substrate_transition_display_fields() {
    let transition = SubstrateTransition {
        from_kind: SubstrateKind::ArtTree,
        to_kind: SubstrateKind::SwissTable,
        trigger: TransitionTrigger::LatencySpike,
        cost_millionths: 500_000,
    };
    let display = format!("{transition}");
    assert!(display.contains("art_tree"));
    assert!(display.contains("swiss_table"));
    assert!(display.contains("latency_spike"));
}

#[test]
fn enrichment_substrate_certificate_display() {
    let profile = hot_profile("cert-disp", SubstrateKind::FlatArray, 50_000);
    let decision = evaluate_substrate(&profile, None);
    let cert = certify_substrate(&profile, &decision);
    let display = format!("{cert}");
    assert!(display.contains("cert-disp"));
    assert!(display.contains("SubstrateCertificate"));
}

// =========================================================================
// I. Certificate hash changes when input differs
// =========================================================================

#[test]
fn enrichment_certificate_hash_differs_for_different_profiles() {
    let p1 = hot_profile("diff-a", SubstrateKind::FlatArray, 50_000);
    let d1 = evaluate_substrate(&p1, None);
    let c1 = certify_substrate(&p1, &d1);

    let p2 = hot_profile("diff-b", SubstrateKind::FlatArray, 50_000);
    let d2 = evaluate_substrate(&p2, None);
    let c2 = certify_substrate(&p2, &d2);

    assert_ne!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn enrichment_certificate_hash_differs_with_override() {
    let profile = hot_profile("hash-ov", SubstrateKind::FlatArray, 50_000);
    let d_no_override = evaluate_substrate(&profile, None);
    let c_no = certify_substrate(&profile, &d_no_override);

    let override_cfg = OverrideConfig {
        disable_optimization: true,
        ..OverrideConfig::default()
    };
    let d_override = evaluate_substrate(&profile, Some(&override_cfg));
    let c_yes = certify_substrate(&profile, &d_override);

    assert_ne!(c_no.certificate_hash, c_yes.certificate_hash);
}

// =========================================================================
// J. Transition cost properties
// =========================================================================

#[test]
fn enrichment_transition_cost_all_same_kind_zero() {
    let kinds = [
        SubstrateKind::SwissTable,
        SubstrateKind::ArtTree,
        SubstrateKind::FlatArray,
        SubstrateKind::CompactBitmap,
        SubstrateKind::InlineCache,
        SubstrateKind::Swizzled,
        SubstrateKind::GenericFallback,
    ];
    for kind in kinds {
        assert_eq!(
            compute_transition_cost(kind, kind),
            0,
            "same-kind cost should be 0 for {kind}"
        );
    }
}

#[test]
fn enrichment_transition_cost_positive_for_different_kinds() {
    let kinds = [
        SubstrateKind::SwissTable,
        SubstrateKind::ArtTree,
        SubstrateKind::FlatArray,
        SubstrateKind::CompactBitmap,
        SubstrateKind::InlineCache,
        SubstrateKind::Swizzled,
        SubstrateKind::GenericFallback,
    ];
    for i in 0..kinds.len() {
        for j in 0..kinds.len() {
            if i != j {
                assert!(
                    compute_transition_cost(kinds[i], kinds[j]) > 0,
                    "transition from {} to {} should have positive cost",
                    kinds[i],
                    kinds[j]
                );
            }
        }
    }
}

// =========================================================================
// K. Override with all fields set
// =========================================================================

#[test]
fn enrichment_override_all_fields_set() {
    let config = OverrideConfig {
        force_kind: Some(SubstrateKind::Swizzled),
        force_fallback: Some(FallbackPath::LinearProbe),
        force_rollback: Some(RollbackStrategy::CowClone),
        disable_optimization: false,
        debug_mode: true,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: OverrideConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
    assert_eq!(back.force_kind, Some(SubstrateKind::Swizzled));
    assert_eq!(back.force_fallback, Some(FallbackPath::LinearProbe));
    assert_eq!(back.force_rollback, Some(RollbackStrategy::CowClone));
    assert!(back.debug_mode);
}

// =========================================================================
// L. evaluate_substrate with combined overrides
// =========================================================================

#[test]
fn enrichment_evaluate_with_force_kind_and_rollback() {
    let profile = hot_profile("combo", SubstrateKind::FlatArray, 50_000);
    let override_cfg = OverrideConfig {
        force_kind: Some(SubstrateKind::ArtTree),
        force_rollback: Some(RollbackStrategy::EpochInvalidate),
        ..OverrideConfig::default()
    };
    let decision = evaluate_substrate(&profile, Some(&override_cfg));
    assert_eq!(decision.recommended_kind, SubstrateKind::ArtTree);
    assert_eq!(decision.rollback, RollbackStrategy::EpochInvalidate);
}

#[test]
fn enrichment_evaluate_disable_overrides_force_kind() {
    // disable_optimization should take precedence over force_kind
    let profile = hot_profile("precedence", SubstrateKind::FlatArray, 50_000);
    let override_cfg = OverrideConfig {
        force_kind: Some(SubstrateKind::SwissTable),
        disable_optimization: true,
        ..OverrideConfig::default()
    };
    let decision = evaluate_substrate(&profile, Some(&override_cfg));
    assert_eq!(decision.recommended_kind, SubstrateKind::GenericFallback);
}

// =========================================================================
// M. apply_override combinations
// =========================================================================

#[test]
fn enrichment_apply_override_empty_is_noop() {
    let profile = hot_profile("noop", SubstrateKind::FlatArray, 50_000);
    let original = evaluate_substrate(&profile, None);
    let mut decision = original.clone();
    apply_override(&mut decision, &OverrideConfig::default());
    assert_eq!(decision, original);
}

// =========================================================================
// N. Debug nonempty for all types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", SubstrateKind::SwissTable).is_empty());
    assert!(!format!("{:?}", OptimizationLevel::CacheLine).is_empty());
    assert!(!format!("{:?}", FallbackPath::BTreeLookup).is_empty());
    assert!(!format!("{:?}", RollbackStrategy::CowClone).is_empty());
    assert!(!format!("{:?}", TransitionTrigger::LatencySpike).is_empty());
    assert!(!format!("{:?}", SubstrateError::EmptyInventory).is_empty());
    assert!(!format!("{:?}", OverrideConfig::default()).is_empty());
}

// =========================================================================
// O. Clone independence for SubstrateProfile
// =========================================================================

#[test]
fn enrichment_substrate_profile_clone_independent() {
    let p1 = hot_profile("clone-test", SubstrateKind::SwissTable, 100_000);
    let mut p2 = p1.clone();
    assert_eq!(p1, p2);
    p2.access_count = 999;
    assert_ne!(p1, p2);
    assert_eq!(p1.access_count, 100_000);
}

// =========================================================================
// P. Evidence manifest certificates link back to profiles
// =========================================================================

#[test]
fn enrichment_evidence_manifest_certificates_have_unique_ids() {
    let manifest = run_substrate_evidence();
    let ids: BTreeSet<&str> = manifest
        .certificates
        .iter()
        .map(|c| c.substrate_id.as_str())
        .collect();
    assert_eq!(ids.len(), manifest.certificates.len());
}

// =========================================================================
// Q. Canonical inventory report properties
// =========================================================================

#[test]
fn enrichment_canonical_inventory_hot_count_le_total() {
    let report = build_canonical_inventory();
    assert!(report.hot_count as usize <= report.profiles.len());
}

#[test]
fn enrichment_canonical_inventory_optimized_plus_fallback_le_total() {
    let report = build_canonical_inventory();
    assert!((report.optimized_count + report.fallback_count) as usize <= report.profiles.len());
}

#[test]
fn enrichment_canonical_inventory_display() {
    let report = build_canonical_inventory();
    let display = format!("{report}");
    assert!(!display.is_empty());
    assert!(display.contains("SubstrateInventoryReport"));
}

// =========================================================================
// R. SubstrateTransition clone independence
// =========================================================================

#[test]
fn enrichment_substrate_transition_clone_independent() {
    let t1 = SubstrateTransition {
        from_kind: SubstrateKind::FlatArray,
        to_kind: SubstrateKind::SwissTable,
        trigger: TransitionTrigger::HotnessThreshold,
        cost_millionths: 200_000,
    };
    let t2 = t1.clone();
    assert_eq!(t1, t2);
}

// =========================================================================
// S. Evaluate returns confidence > 0 for hot profiles
// =========================================================================

#[test]
fn enrichment_evaluate_hot_profile_confidence_positive() {
    let kinds = [
        SubstrateKind::SwissTable,
        SubstrateKind::ArtTree,
        SubstrateKind::FlatArray,
        SubstrateKind::CompactBitmap,
        SubstrateKind::InlineCache,
    ];
    for kind in kinds {
        let profile = hot_profile("conf", kind, 50_000);
        let decision = evaluate_substrate(&profile, None);
        assert!(
            decision.confidence_millionths > 0,
            "hot profile with kind {kind} should have positive confidence"
        );
    }
}

// =========================================================================
// T. RollbackStrategy and TransitionTrigger ordering in BTreeSet
// =========================================================================

#[test]
fn enrichment_rollback_strategy_btree_set() {
    let mut set = BTreeSet::new();
    set.insert(RollbackStrategy::SnapshotRestore);
    set.insert(RollbackStrategy::EpochInvalidate);
    set.insert(RollbackStrategy::CowClone);
    set.insert(RollbackStrategy::Rebuild);
    set.insert(RollbackStrategy::NoRollback);
    set.insert(RollbackStrategy::CowClone); // dup
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_transition_trigger_btree_set() {
    let mut set = BTreeSet::new();
    set.insert(TransitionTrigger::HotnessThreshold);
    set.insert(TransitionTrigger::MemoryPressure);
    set.insert(TransitionTrigger::LatencySpike);
    set.insert(TransitionTrigger::ManualOverride);
    set.insert(TransitionTrigger::FallbackTriggered);
    set.insert(TransitionTrigger::PortabilityCheck);
    set.insert(TransitionTrigger::HotnessThreshold); // dup
    assert_eq!(set.len(), 6);
}

// =========================================================================
// U. Evidence manifest error field is None on success
// =========================================================================

#[test]
fn enrichment_evidence_manifest_error_none() {
    let manifest = run_substrate_evidence();
    assert!(manifest.error.is_none());
}

// =========================================================================
// V. Constants are consistent
// =========================================================================

#[test]
fn enrichment_constants_not_empty_and_consistent() {
    assert!(!SUBSTRATE_OPT_COMPONENT.is_empty());
    assert!(!SUBSTRATE_OPT_POLICY_ID.is_empty());
    assert!(!SUBSTRATE_OPT_SCHEMA_VERSION.is_empty());
    // Schema version contains the component concept
    assert!(SUBSTRATE_OPT_SCHEMA_VERSION.contains("substrate"));
}

// =========================================================================
// W. recommend_substrate_kind — untested heuristic paths
// =========================================================================

#[test]
fn test_recommend_compact_bitmap_for_high_hit_rate_small_memory() {
    // hit_rate >= 950_000 AND memory_bytes < 4096 => CompactBitmap
    let profile = SubstrateProfile {
        id: "bitmap-path".into(),
        kind: SubstrateKind::FlatArray,
        access_count: 50_000,
        hit_rate_millionths: 960_000,
        avg_latency_millionths: 20,
        memory_bytes: 2048,
        is_hot: true,
    };
    assert_eq!(
        recommend_substrate_kind(&profile),
        SubstrateKind::CompactBitmap
    );
}

#[test]
fn test_recommend_art_tree_for_large_memory() {
    // memory_bytes > 1_048_576 (and not caught by earlier conditions) => ArtTree
    let profile = SubstrateProfile {
        id: "art-path".into(),
        kind: SubstrateKind::FlatArray,
        access_count: 5_000,
        hit_rate_millionths: 750_000,
        avg_latency_millionths: 200,
        memory_bytes: 2_097_152,
        is_hot: true,
    };
    assert_eq!(recommend_substrate_kind(&profile), SubstrateKind::ArtTree);
}

#[test]
fn test_recommend_swizzled_for_moderate_access() {
    // access_count > 10_000, not caught by earlier conditions => Swizzled
    let profile = SubstrateProfile {
        id: "swizzled-path".into(),
        kind: SubstrateKind::FlatArray,
        access_count: 15_000,
        hit_rate_millionths: 750_000,
        avg_latency_millionths: 150,
        memory_bytes: 131_072,
        is_hot: true,
    };
    assert_eq!(recommend_substrate_kind(&profile), SubstrateKind::Swizzled);
}

#[test]
fn test_recommend_flat_array_for_low_access_hot() {
    // hot but access_count <= 10_000, moderate memory => FlatArray
    let profile = SubstrateProfile {
        id: "flatarray-path".into(),
        kind: SubstrateKind::SwissTable,
        access_count: 500,
        hit_rate_millionths: 600_000,
        avg_latency_millionths: 300,
        memory_bytes: 16_384,
        is_hot: true,
    };
    assert_eq!(recommend_substrate_kind(&profile), SubstrateKind::FlatArray);
}

#[test]
fn test_recommend_generic_fallback_for_cold_profile() {
    let profile = SubstrateProfile {
        id: "cold-rec".into(),
        kind: SubstrateKind::SwissTable,
        access_count: 1_000_000,
        hit_rate_millionths: 999_000,
        avg_latency_millionths: 10,
        memory_bytes: 512,
        is_hot: false,
    };
    // Even very high stats, if not hot => GenericFallback
    assert_eq!(
        recommend_substrate_kind(&profile),
        SubstrateKind::GenericFallback
    );
}

// =========================================================================
// X. certify_substrate — overrides_applied and empty transitions
// =========================================================================

#[test]
fn test_certify_substrate_no_transition_when_kind_unchanged() {
    // If the profile kind equals the recommended kind, transitions should be empty
    let profile = SubstrateProfile {
        id: "no-trans".into(),
        kind: SubstrateKind::SwissTable,
        access_count: 200_000,
        hit_rate_millionths: 900_000,
        avg_latency_millionths: 40,
        memory_bytes: 32_768,
        is_hot: true,
    };
    let decision = evaluate_substrate(&profile, None);
    // Only certify if the recommended kind matches the current kind
    if decision.recommended_kind == profile.kind {
        let cert = certify_substrate(&profile, &decision);
        assert!(cert.transitions.is_empty());
    }
}

#[test]
fn test_certify_substrate_overrides_applied_hot_generic_fallback() {
    // overrides_applied = true when the profile is hot and recommended is GenericFallback
    let profile = hot_profile("ov-applied", SubstrateKind::FlatArray, 50_000);
    let override_cfg = OverrideConfig {
        disable_optimization: true,
        ..OverrideConfig::default()
    };
    let decision = evaluate_substrate(&profile, Some(&override_cfg));
    assert_eq!(decision.recommended_kind, SubstrateKind::GenericFallback);
    let cert = certify_substrate(&profile, &decision);
    assert!(cert.overrides_applied);
}

#[test]
fn test_certify_substrate_overrides_not_applied_for_cold_profile() {
    // Cold profile legitimately gets GenericFallback, overrides_applied = false
    let profile = SubstrateProfile {
        id: "cold-cert".into(),
        kind: SubstrateKind::FlatArray,
        access_count: 100,
        hit_rate_millionths: 300_000,
        avg_latency_millionths: 500,
        memory_bytes: 65_536,
        is_hot: false,
    };
    let decision = evaluate_substrate(&profile, None);
    assert_eq!(decision.recommended_kind, SubstrateKind::GenericFallback);
    let cert = certify_substrate(&profile, &decision);
    // Cold => not hot => overrides_applied = false
    assert!(!cert.overrides_applied);
}

// =========================================================================
// Y. apply_override — debug_mode confidence cap
// =========================================================================

#[test]
fn test_apply_override_debug_mode_caps_confidence() {
    let profile = hot_profile("debug-cap", SubstrateKind::FlatArray, 50_000);
    let mut decision = evaluate_substrate(&profile, None);
    // Ensure initial confidence is above 500_000
    assert!(decision.confidence_millionths > 500_000);

    let cfg = OverrideConfig {
        debug_mode: true,
        ..OverrideConfig::default()
    };
    apply_override(&mut decision, &cfg);
    assert!(decision.confidence_millionths <= 500_000);
}

#[test]
fn test_apply_override_force_fallback_only() {
    let profile = hot_profile("fb-only", SubstrateKind::ArtTree, 50_000);
    let original = evaluate_substrate(&profile, None);
    let mut decision = original.clone();

    let cfg = OverrideConfig {
        force_fallback: Some(FallbackPath::Abstain),
        ..OverrideConfig::default()
    };
    apply_override(&mut decision, &cfg);
    assert_eq!(decision.fallback, FallbackPath::Abstain);
    // kind should be unchanged
    assert_eq!(decision.recommended_kind, original.recommended_kind);
}

// =========================================================================
// Z. Serde roundtrips for remaining types
// =========================================================================

#[test]
fn test_substrate_profile_serde_roundtrip() {
    let profile = hot_profile("serde-prof", SubstrateKind::CompactBitmap, 77_777);
    let json = serde_json::to_string(&profile).unwrap();
    let back: SubstrateProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile, back);
}

#[test]
fn test_substrate_error_serde_roundtrip_all_variants() {
    let errors = vec![
        SubstrateError::EmptyInventory,
        SubstrateError::InvalidProfile {
            reason: "bad data".into(),
        },
        SubstrateError::TransitionForbidden {
            from: SubstrateKind::Swizzled,
            to: SubstrateKind::InlineCache,
        },
        SubstrateError::OverrideConflict {
            reason: "conflict reason".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: SubstrateError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, &back);
    }
}

#[test]
fn test_substrate_transition_serde_roundtrip() {
    let trans = SubstrateTransition {
        from_kind: SubstrateKind::Swizzled,
        to_kind: SubstrateKind::ArtTree,
        trigger: TransitionTrigger::MemoryPressure,
        cost_millionths: 900_000,
    };
    let json = serde_json::to_string(&trans).unwrap();
    let back: SubstrateTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(trans, back);
}

#[test]
fn test_substrate_inventory_report_serde_roundtrip() {
    let report = build_canonical_inventory();
    let json = serde_json::to_string(&report).unwrap();
    let back: SubstrateInventoryReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn test_substrate_evidence_manifest_serde_roundtrip() {
    let manifest = run_substrate_evidence();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: SubstrateEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// =========================================================================
// AA. SubstrateInventoryReport — profiles and decisions counts match
// =========================================================================

#[test]
fn test_inventory_report_profiles_decisions_count_match() {
    let report = build_canonical_inventory();
    assert_eq!(report.profiles.len(), report.decisions.len());
}

#[test]
fn test_inventory_report_has_at_least_eight_profiles() {
    let report = build_canonical_inventory();
    assert!(report.profiles.len() >= 8);
}

// =========================================================================
// AB. SubstrateEvidenceManifest — schema_version matches constant
// =========================================================================

#[test]
fn test_evidence_manifest_schema_version_matches_constant() {
    let manifest = run_substrate_evidence();
    assert_eq!(manifest.schema_version, SUBSTRATE_OPT_SCHEMA_VERSION);
}

#[test]
fn test_evidence_manifest_evaluated_equals_certificate_count() {
    let manifest = run_substrate_evidence();
    assert_eq!(
        manifest.substrates_evaluated as usize,
        manifest.certificates.len()
    );
}

#[test]
fn test_evidence_manifest_display_nonempty() {
    let manifest = run_substrate_evidence();
    let display = format!("{manifest}");
    assert!(!display.is_empty());
    assert!(display.contains("SubstrateEvidenceManifest"));
}

// =========================================================================
// AC. compute_transition_cost asymmetry — swizzled is most expensive
// =========================================================================

#[test]
fn test_transition_cost_swizzled_from_is_most_expensive_direction() {
    // Swizzled -> anything costs 900_000 (base + 800_000)
    // Anything -> Swizzled costs 800_000 (base + 700_000)
    let cost_from = compute_transition_cost(SubstrateKind::Swizzled, SubstrateKind::FlatArray);
    let cost_to = compute_transition_cost(SubstrateKind::FlatArray, SubstrateKind::Swizzled);
    assert!(cost_from > cost_to);
}

#[test]
fn test_transition_cost_to_generic_fallback_is_cheap() {
    // Tear-down cost (to GenericFallback) should be less than rebuild cost (from GenericFallback)
    let cost_down =
        compute_transition_cost(SubstrateKind::SwissTable, SubstrateKind::GenericFallback);
    let cost_up =
        compute_transition_cost(SubstrateKind::GenericFallback, SubstrateKind::SwissTable);
    assert!(cost_down < cost_up);
}

// =========================================================================
// AD. evaluate_substrate — zero access count confidence is zero
// =========================================================================

#[test]
fn test_evaluate_zero_access_count_confidence_is_zero() {
    let profile = SubstrateProfile {
        id: "zero-acc".into(),
        kind: SubstrateKind::FlatArray,
        access_count: 0,
        hit_rate_millionths: 900_000,
        avg_latency_millionths: 100,
        memory_bytes: 32_768,
        is_hot: true,
    };
    let decision = evaluate_substrate(&profile, None);
    assert_eq!(decision.confidence_millionths, 0);
}

// =========================================================================
// AE. SubstrateCertificate — schema_version matches constant
// =========================================================================

#[test]
fn test_certificate_schema_version_matches_constant() {
    let profile = hot_profile("cert-schema", SubstrateKind::ArtTree, 60_000);
    let decision = evaluate_substrate(&profile, None);
    let cert = certify_substrate(&profile, &decision);
    assert_eq!(cert.schema_version, SUBSTRATE_OPT_SCHEMA_VERSION);
}

// =========================================================================
// AF. OverrideConfig default has all fields at their zero/None values
// =========================================================================

#[test]
fn test_override_config_default_all_none_and_false() {
    let cfg = OverrideConfig::default();
    assert!(cfg.force_kind.is_none());
    assert!(cfg.force_fallback.is_none());
    assert!(cfg.force_rollback.is_none());
    assert!(!cfg.disable_optimization);
    assert!(!cfg.debug_mode);
}

// =========================================================================
// AG. SubstrateInventoryReport Display contains counts
// =========================================================================

#[test]
fn test_inventory_report_display_contains_counts() {
    let report = build_canonical_inventory();
    let display = format!("{report}");
    assert!(display.contains("SubstrateInventoryReport"));
    // Display should include numeric values for the hot count
    let hot_str = report.hot_count.to_string();
    assert!(display.contains(&hot_str));
}
