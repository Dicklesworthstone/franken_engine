//! Integration tests for the metadata substrate optimized module (RGC-626B).

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

use frankenengine_engine::metadata_substrate_optimized::{
    FallbackPath, OptimizationDecision, OptimizationLevel, OverrideConfig, RollbackStrategy,
    SUBSTRATE_OPT_COMPONENT, SUBSTRATE_OPT_POLICY_ID, SUBSTRATE_OPT_SCHEMA_VERSION,
    SubstrateCertificate, SubstrateError, SubstrateEvidenceManifest, SubstrateInventoryReport,
    SubstrateKind, SubstrateProfile, SubstrateTransition, TransitionTrigger, apply_override,
    build_canonical_inventory, certify_substrate, compute_transition_cost, evaluate_substrate,
    recommend_substrate_kind, run_substrate_evidence,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn cold_profile(id: &str) -> SubstrateProfile {
    SubstrateProfile {
        id: id.into(),
        kind: SubstrateKind::GenericFallback,
        access_count: 100,
        hit_rate_millionths: 500_000,
        avg_latency_millionths: 500,
        memory_bytes: 4096,
        is_hot: false,
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn integration_schema_version_nonempty() {
    assert!(!SUBSTRATE_OPT_SCHEMA_VERSION.is_empty());
    assert!(SUBSTRATE_OPT_SCHEMA_VERSION.contains("metadata-substrate-optimized"));
}

#[test]
fn integration_component_name() {
    assert_eq!(SUBSTRATE_OPT_COMPONENT, "metadata_substrate_optimized");
}

#[test]
fn integration_policy_id() {
    assert_eq!(SUBSTRATE_OPT_POLICY_ID, "RGC-626B");
}

// ---------------------------------------------------------------------------
// SubstrateKind serde roundtrip + display
// ---------------------------------------------------------------------------

#[test]
fn integration_substrate_kind_serde_all_variants() {
    let kinds = [
        SubstrateKind::SwissTable,
        SubstrateKind::ArtTree,
        SubstrateKind::FlatArray,
        SubstrateKind::CompactBitmap,
        SubstrateKind::InlineCache,
        SubstrateKind::Swizzled,
        SubstrateKind::GenericFallback,
    ];
    for k in kinds {
        let json = serde_json::to_string(&k).unwrap();
        let back: SubstrateKind = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }
}

#[test]
fn integration_substrate_kind_display() {
    assert_eq!(SubstrateKind::SwissTable.to_string(), "swiss_table");
    assert_eq!(
        SubstrateKind::GenericFallback.to_string(),
        "generic_fallback"
    );
}

// ---------------------------------------------------------------------------
// OptimizationLevel serde + display
// ---------------------------------------------------------------------------

#[test]
fn integration_optimization_level_serde_all_variants() {
    let levels = [
        OptimizationLevel::Unoptimized,
        OptimizationLevel::LocalityAware,
        OptimizationLevel::CacheLine,
        OptimizationLevel::Prefetched,
        OptimizationLevel::FullySwizzled,
    ];
    for l in levels {
        let json = serde_json::to_string(&l).unwrap();
        let back: OptimizationLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(l, back);
    }
}

#[test]
fn integration_optimization_level_display() {
    assert_eq!(OptimizationLevel::Unoptimized.to_string(), "unoptimized");
    assert_eq!(
        OptimizationLevel::FullySwizzled.to_string(),
        "fully_swizzled"
    );
}

// ---------------------------------------------------------------------------
// FallbackPath serde + display
// ---------------------------------------------------------------------------

#[test]
fn integration_fallback_path_serde_all_variants() {
    let paths = [
        FallbackPath::GenericScan,
        FallbackPath::SortedArray,
        FallbackPath::BTreeLookup,
        FallbackPath::LinearProbe,
        FallbackPath::Abstain,
    ];
    for p in paths {
        let json = serde_json::to_string(&p).unwrap();
        let back: FallbackPath = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}

#[test]
fn integration_fallback_path_display() {
    assert_eq!(FallbackPath::GenericScan.to_string(), "generic_scan");
    assert_eq!(FallbackPath::Abstain.to_string(), "abstain");
}

// ---------------------------------------------------------------------------
// RollbackStrategy serde + display
// ---------------------------------------------------------------------------

#[test]
fn integration_rollback_strategy_serde_all_variants() {
    let strategies = [
        RollbackStrategy::SnapshotRestore,
        RollbackStrategy::EpochInvalidate,
        RollbackStrategy::CowClone,
        RollbackStrategy::Rebuild,
        RollbackStrategy::NoRollback,
    ];
    for s in strategies {
        let json = serde_json::to_string(&s).unwrap();
        let back: RollbackStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn integration_rollback_strategy_display() {
    assert_eq!(
        RollbackStrategy::SnapshotRestore.to_string(),
        "snapshot_restore"
    );
    assert_eq!(RollbackStrategy::NoRollback.to_string(), "no_rollback");
}

// ---------------------------------------------------------------------------
// TransitionTrigger serde + display
// ---------------------------------------------------------------------------

#[test]
fn integration_transition_trigger_serde_all_variants() {
    let triggers = [
        TransitionTrigger::HotnessThreshold,
        TransitionTrigger::MemoryPressure,
        TransitionTrigger::LatencySpike,
        TransitionTrigger::ManualOverride,
        TransitionTrigger::FallbackTriggered,
        TransitionTrigger::PortabilityCheck,
    ];
    for t in triggers {
        let json = serde_json::to_string(&t).unwrap();
        let back: TransitionTrigger = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}

// ---------------------------------------------------------------------------
// SubstrateError serde + display
// ---------------------------------------------------------------------------

#[test]
fn integration_error_serde_roundtrip() {
    let errors = vec![
        SubstrateError::EmptyInventory,
        SubstrateError::InvalidProfile {
            reason: "bad".into(),
        },
        SubstrateError::TransitionForbidden {
            from: SubstrateKind::SwissTable,
            to: SubstrateKind::GenericFallback,
        },
        SubstrateError::OverrideConflict {
            reason: "conflict".into(),
        },
    ];
    for e in errors {
        let json = serde_json::to_string(&e).unwrap();
        let back: SubstrateError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }
}

#[test]
fn integration_error_display() {
    assert_eq!(
        SubstrateError::EmptyInventory.to_string(),
        "empty inventory"
    );
    let tf = SubstrateError::TransitionForbidden {
        from: SubstrateKind::SwissTable,
        to: SubstrateKind::GenericFallback,
    };
    assert!(tf.to_string().contains("swiss_table"));
}

// ---------------------------------------------------------------------------
// recommend_substrate_kind
// ---------------------------------------------------------------------------

#[test]
fn integration_recommend_cold_profile_generic_fallback() {
    let profile = cold_profile("cold1");
    let kind = recommend_substrate_kind(&profile);
    assert_eq!(kind, SubstrateKind::GenericFallback);
}

#[test]
fn integration_recommend_high_access_high_hit_rate_swiss_table() {
    let profile = SubstrateProfile {
        access_count: 200_000,
        hit_rate_millionths: 900_000,
        ..hot_profile("hot1", SubstrateKind::FlatArray, 200_000)
    };
    let kind = recommend_substrate_kind(&profile);
    assert_eq!(kind, SubstrateKind::SwissTable);
}

#[test]
fn integration_recommend_very_high_hit_compact_memory_bitmap() {
    let profile = SubstrateProfile {
        access_count: 5_000,
        hit_rate_millionths: 960_000,
        memory_bytes: 2048,
        ..hot_profile("hot2", SubstrateKind::FlatArray, 5_000)
    };
    let kind = recommend_substrate_kind(&profile);
    assert_eq!(kind, SubstrateKind::CompactBitmap);
}

#[test]
fn integration_recommend_high_hit_rate_inline_cache() {
    let profile = SubstrateProfile {
        access_count: 50_000,
        hit_rate_millionths: 920_000,
        memory_bytes: 8_192,
        ..hot_profile("hot3", SubstrateKind::FlatArray, 50_000)
    };
    let kind = recommend_substrate_kind(&profile);
    assert_eq!(kind, SubstrateKind::InlineCache);
}

#[test]
fn integration_recommend_large_memory_art_tree() {
    let profile = SubstrateProfile {
        access_count: 50_000,
        hit_rate_millionths: 850_000,
        memory_bytes: 2_097_152,
        ..hot_profile("hot4", SubstrateKind::GenericFallback, 50_000)
    };
    let kind = recommend_substrate_kind(&profile);
    assert_eq!(kind, SubstrateKind::ArtTree);
}

#[test]
fn integration_recommend_low_access_hot_flat_array() {
    let profile = SubstrateProfile {
        access_count: 500,
        hit_rate_millionths: 700_000,
        memory_bytes: 4096,
        ..hot_profile("hot5", SubstrateKind::GenericFallback, 500)
    };
    let kind = recommend_substrate_kind(&profile);
    assert_eq!(kind, SubstrateKind::FlatArray);
}

// ---------------------------------------------------------------------------
// compute_transition_cost
// ---------------------------------------------------------------------------

#[test]
fn integration_transition_cost_same_kind_zero() {
    assert_eq!(
        compute_transition_cost(SubstrateKind::SwissTable, SubstrateKind::SwissTable),
        0
    );
}

#[test]
fn integration_transition_cost_swizzled_expensive() {
    let cost_from = compute_transition_cost(SubstrateKind::Swizzled, SubstrateKind::FlatArray);
    let cost_to = compute_transition_cost(SubstrateKind::FlatArray, SubstrateKind::Swizzled);
    assert!(cost_from > 0);
    assert!(cost_to > 0);
}

#[test]
fn integration_transition_cost_to_generic_cheap() {
    let to_generic =
        compute_transition_cost(SubstrateKind::SwissTable, SubstrateKind::GenericFallback);
    let from_generic =
        compute_transition_cost(SubstrateKind::GenericFallback, SubstrateKind::SwissTable);
    assert!(to_generic < from_generic);
}

// ---------------------------------------------------------------------------
// evaluate_substrate
// ---------------------------------------------------------------------------

#[test]
fn integration_evaluate_substrate_no_override() {
    let profile = hot_profile("eval1", SubstrateKind::FlatArray, 50_000);
    let decision = evaluate_substrate(&profile, None);
    assert_eq!(decision.substrate_id, "eval1");
    assert_eq!(decision.current_kind, SubstrateKind::FlatArray);
    assert!(decision.expected_speedup_millionths >= 1_000_000);
    assert!(decision.confidence_millionths > 0);
}

#[test]
fn integration_evaluate_substrate_with_override_disable() {
    let profile = hot_profile("eval2", SubstrateKind::FlatArray, 50_000);
    let override_config = OverrideConfig {
        disable_optimization: true,
        ..OverrideConfig::default()
    };
    let decision = evaluate_substrate(&profile, Some(&override_config));
    assert_eq!(decision.recommended_kind, SubstrateKind::GenericFallback);
    assert_eq!(decision.optimization_level, OptimizationLevel::Unoptimized);
    assert_eq!(decision.fallback, FallbackPath::Abstain);
}

#[test]
fn integration_evaluate_substrate_with_force_kind() {
    let profile = hot_profile("eval3", SubstrateKind::FlatArray, 50_000);
    let override_config = OverrideConfig {
        force_kind: Some(SubstrateKind::CompactBitmap),
        ..OverrideConfig::default()
    };
    let decision = evaluate_substrate(&profile, Some(&override_config));
    assert_eq!(decision.recommended_kind, SubstrateKind::CompactBitmap);
}

#[test]
fn integration_evaluate_substrate_cold_unoptimized() {
    let profile = cold_profile("eval4");
    let decision = evaluate_substrate(&profile, None);
    assert_eq!(decision.recommended_kind, SubstrateKind::GenericFallback);
}

// ---------------------------------------------------------------------------
// apply_override
// ---------------------------------------------------------------------------

#[test]
fn integration_apply_override_debug_mode_caps_confidence() {
    let profile = hot_profile("ov1", SubstrateKind::FlatArray, 50_000);
    let mut decision = evaluate_substrate(&profile, None);
    let override_config = OverrideConfig {
        debug_mode: true,
        ..OverrideConfig::default()
    };
    apply_override(&mut decision, &override_config);
    assert!(decision.confidence_millionths <= 500_000);
}

#[test]
fn integration_apply_override_force_fallback() {
    let profile = hot_profile("ov2", SubstrateKind::FlatArray, 50_000);
    let mut decision = evaluate_substrate(&profile, None);
    let override_config = OverrideConfig {
        force_fallback: Some(FallbackPath::BTreeLookup),
        ..OverrideConfig::default()
    };
    apply_override(&mut decision, &override_config);
    assert_eq!(decision.fallback, FallbackPath::BTreeLookup);
}

#[test]
fn integration_apply_override_force_rollback() {
    let profile = hot_profile("ov3", SubstrateKind::FlatArray, 50_000);
    let mut decision = evaluate_substrate(&profile, None);
    let override_config = OverrideConfig {
        force_rollback: Some(RollbackStrategy::Rebuild),
        ..OverrideConfig::default()
    };
    apply_override(&mut decision, &override_config);
    assert_eq!(decision.rollback, RollbackStrategy::Rebuild);
}

// ---------------------------------------------------------------------------
// certify_substrate
// ---------------------------------------------------------------------------

#[test]
fn integration_certify_substrate_produces_certificate() {
    let profile = hot_profile("cert1", SubstrateKind::FlatArray, 50_000);
    let decision = evaluate_substrate(&profile, None);
    let cert = certify_substrate(&profile, &decision);
    assert_eq!(cert.schema_version, SUBSTRATE_OPT_SCHEMA_VERSION);
    assert_eq!(cert.substrate_id, "cert1");
}

#[test]
fn integration_certify_substrate_hash_determinism() {
    let profile = hot_profile("cert2", SubstrateKind::FlatArray, 50_000);
    let decision = evaluate_substrate(&profile, None);
    let c1 = certify_substrate(&profile, &decision);
    let c2 = certify_substrate(&profile, &decision);
    assert_eq!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn integration_certify_substrate_serde_roundtrip() {
    let profile = hot_profile("cert3", SubstrateKind::FlatArray, 50_000);
    let decision = evaluate_substrate(&profile, None);
    let cert = certify_substrate(&profile, &decision);
    let json = serde_json::to_string(&cert).unwrap();
    let back: SubstrateCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

#[test]
fn integration_certify_substrate_no_transition_when_same_kind() {
    let profile = hot_profile("cert4", SubstrateKind::InlineCache, 50_000);
    let decision = evaluate_substrate(&profile, None);
    if decision.recommended_kind == SubstrateKind::InlineCache {
        let cert = certify_substrate(&profile, &decision);
        assert!(cert.transitions.is_empty());
    }
}

// ---------------------------------------------------------------------------
// build_canonical_inventory
// ---------------------------------------------------------------------------

#[test]
fn integration_canonical_inventory_has_profiles() {
    let report = build_canonical_inventory();
    assert!(report.profiles.len() >= 8);
    assert_eq!(report.profiles.len(), report.decisions.len());
}

#[test]
fn integration_canonical_inventory_hash_determinism() {
    let r1 = build_canonical_inventory();
    let r2 = build_canonical_inventory();
    assert_eq!(r1.report_hash, r2.report_hash);
}

#[test]
fn integration_canonical_inventory_serde_roundtrip() {
    let report = build_canonical_inventory();
    let json = serde_json::to_string(&report).unwrap();
    let back: SubstrateInventoryReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

#[test]
fn integration_canonical_inventory_counts() {
    let report = build_canonical_inventory();
    assert!(report.hot_count > 0);
    assert!(report.optimized_count > 0);
    // At least one cold profile leads to fallback
    assert!(report.fallback_count >= 1);
}

// ---------------------------------------------------------------------------
// Evidence manifest
// ---------------------------------------------------------------------------

#[test]
fn integration_run_evidence_produces_manifest() {
    let manifest = run_substrate_evidence();
    assert_eq!(manifest.schema_version, SUBSTRATE_OPT_SCHEMA_VERSION);
    assert!(manifest.substrates_evaluated >= 8);
    assert!(manifest.error.is_none());
    assert!(!manifest.certificates.is_empty());
}

#[test]
fn integration_evidence_hash_determinism() {
    let m1 = run_substrate_evidence();
    let m2 = run_substrate_evidence();
    assert_eq!(m1.manifest_hash, m2.manifest_hash);
}

#[test]
fn integration_evidence_serde_roundtrip() {
    let manifest = run_substrate_evidence();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: SubstrateEvidenceManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn integration_evidence_certificates_have_schema_version() {
    let manifest = run_substrate_evidence();
    for cert in &manifest.certificates {
        assert_eq!(cert.schema_version, SUBSTRATE_OPT_SCHEMA_VERSION);
    }
}

#[test]
fn integration_evidence_counts() {
    let m = run_substrate_evidence();
    assert_eq!(m.optimized_count + m.fallback_count, m.substrates_evaluated);
}

// ---------------------------------------------------------------------------
// OverrideConfig serde
// ---------------------------------------------------------------------------

#[test]
fn integration_override_config_default_serde_roundtrip() {
    let config = OverrideConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: OverrideConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// SubstrateProfile serde + display
// ---------------------------------------------------------------------------

#[test]
fn integration_substrate_profile_serde_roundtrip() {
    let profile = hot_profile("serde-p", SubstrateKind::SwissTable, 100_000);
    let json = serde_json::to_string(&profile).unwrap();
    let back: SubstrateProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile, back);
}

#[test]
fn integration_substrate_profile_display() {
    let profile = hot_profile("disp", SubstrateKind::SwissTable, 100_000);
    let display = format!("{}", profile);
    assert!(display.contains("disp"));
    assert!(display.contains("swiss_table"));
}

// ---------------------------------------------------------------------------
// SubstrateTransition serde + display
// ---------------------------------------------------------------------------

#[test]
fn integration_substrate_transition_serde_roundtrip() {
    let transition = SubstrateTransition {
        from_kind: SubstrateKind::FlatArray,
        to_kind: SubstrateKind::SwissTable,
        trigger: TransitionTrigger::HotnessThreshold,
        cost_millionths: 300_000,
    };
    let json = serde_json::to_string(&transition).unwrap();
    let back: SubstrateTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(transition, back);
}

#[test]
fn integration_substrate_transition_display() {
    let transition = SubstrateTransition {
        from_kind: SubstrateKind::FlatArray,
        to_kind: SubstrateKind::SwissTable,
        trigger: TransitionTrigger::HotnessThreshold,
        cost_millionths: 300_000,
    };
    let display = format!("{}", transition);
    assert!(display.contains("flat_array"));
    assert!(display.contains("swiss_table"));
}

// ---------------------------------------------------------------------------
// OptimizationDecision serde + display
// ---------------------------------------------------------------------------

#[test]
fn integration_optimization_decision_serde_roundtrip() {
    let profile = hot_profile("dec-serde", SubstrateKind::FlatArray, 50_000);
    let decision = evaluate_substrate(&profile, None);
    let json = serde_json::to_string(&decision).unwrap();
    let back: OptimizationDecision = serde_json::from_str(&json).unwrap();
    assert_eq!(decision, back);
}

#[test]
fn integration_optimization_decision_display() {
    let profile = hot_profile("dec-disp", SubstrateKind::FlatArray, 50_000);
    let decision = evaluate_substrate(&profile, None);
    let display = format!("{}", decision);
    assert!(display.contains("dec-disp"));
}
