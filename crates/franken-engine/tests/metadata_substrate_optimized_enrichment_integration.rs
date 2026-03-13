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
    FallbackPath, OptimizationLevel, OverrideConfig, RollbackStrategy,
    SUBSTRATE_OPT_COMPONENT, SUBSTRATE_OPT_POLICY_ID, SUBSTRATE_OPT_SCHEMA_VERSION,
    SubstrateError, SubstrateKind, SubstrateProfile, SubstrateTransition,
    TransitionTrigger, apply_override, build_canonical_inventory, certify_substrate,
    compute_transition_cost, evaluate_substrate, run_substrate_evidence,
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
    assert!(
        (report.optimized_count + report.fallback_count) as usize <= report.profiles.len()
    );
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
