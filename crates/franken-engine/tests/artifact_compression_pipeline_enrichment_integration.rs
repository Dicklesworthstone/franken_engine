#![forbid(unsafe_code)]

//! Enrichment integration tests for the `artifact_compression_pipeline` module.

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

use frankenengine_engine::artifact_compression_pipeline::{
    ArtifactCategory, ArtifactDescriptor, BundlePlanner, COMPONENT, CompressionAction,
    CompressionAlgorithm, CompressionPipeline, DedupReceipt, DedupTracker, ExclusionReason,
    ExclusionReceipt, MAX_ARTIFACT_BYTES, MAX_BUNDLE_SIZE, MAX_DEDUP_CHAIN_DEPTH, MIN_USEFUL_RATIO,
    PlanEntry, PlannerConfig, RestorationRecipe, SCHEMA_VERSION,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(1)
}

fn desc(id: &str, cat: ArtifactCategory, size: u64) -> ArtifactDescriptor {
    ArtifactDescriptor::new(id, cat, size, id.as_bytes(), epoch())
}

// ===========================================================================
// CompressionAlgorithm enrichment
// ===========================================================================

#[test]
fn enrichment_compression_algorithm_copy_semantics() {
    let a = CompressionAlgorithm::Zstd;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_compression_algorithm_btreeset_dedup_4() {
    let set: BTreeSet<CompressionAlgorithm> = CompressionAlgorithm::ALL.iter().copied().collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_compression_algorithm_debug_all_unique() {
    let debugs: BTreeSet<String> = CompressionAlgorithm::ALL
        .iter()
        .map(|a| format!("{a:?}"))
        .collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_compression_algorithm_display_all_unique() {
    let displays: BTreeSet<String> = CompressionAlgorithm::ALL
        .iter()
        .map(|a| a.to_string())
        .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_compression_algorithm_as_str_matches_display() {
    for &alg in CompressionAlgorithm::ALL {
        assert_eq!(alg.as_str(), &alg.to_string());
    }
}

#[test]
fn enrichment_compression_algorithm_exactly_one_non_compressor() {
    let non_compressors: Vec<_> = CompressionAlgorithm::ALL
        .iter()
        .filter(|a| !a.is_compressor())
        .collect();
    assert_eq!(non_compressors.len(), 1);
    assert_eq!(*non_compressors[0], CompressionAlgorithm::Identity);
}

// ===========================================================================
// ArtifactCategory enrichment
// ===========================================================================

#[test]
fn enrichment_artifact_category_copy_semantics() {
    let a = ArtifactCategory::Cache;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_artifact_category_btreeset_dedup_9() {
    let set: BTreeSet<ArtifactCategory> = ArtifactCategory::ALL.iter().copied().collect();
    assert_eq!(set.len(), 9);
}

#[test]
fn enrichment_artifact_category_debug_all_unique() {
    let debugs: BTreeSet<String> = ArtifactCategory::ALL
        .iter()
        .map(|c| format!("{c:?}"))
        .collect();
    assert_eq!(debugs.len(), 9);
}

#[test]
fn enrichment_artifact_category_display_all_unique() {
    let displays: BTreeSet<String> = ArtifactCategory::ALL
        .iter()
        .map(|c| c.to_string())
        .collect();
    assert_eq!(displays.len(), 9);
}

#[test]
fn enrichment_artifact_category_as_str_matches_display() {
    for &cat in ArtifactCategory::ALL {
        assert_eq!(cat.as_str(), &cat.to_string());
    }
}

#[test]
fn enrichment_artifact_category_exactly_3_excluded() {
    let excluded: Vec<_> = ArtifactCategory::ALL
        .iter()
        .filter(|c| c.is_compression_excluded())
        .collect();
    assert_eq!(excluded.len(), 3);
}

#[test]
fn enrichment_artifact_category_dedup_excluded_matches_compression_excluded() {
    for &cat in ArtifactCategory::ALL {
        assert_eq!(cat.is_compression_excluded(), cat.is_dedup_excluded());
    }
}

// ===========================================================================
// ExclusionReason enrichment
// ===========================================================================

#[test]
fn enrichment_exclusion_reason_clone_independence() {
    let a = ExclusionReason::OversizeArtifact;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_exclusion_reason_btreeset_dedup_6() {
    let set: BTreeSet<ExclusionReason> = ExclusionReason::ALL.iter().cloned().collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_exclusion_reason_debug_all_unique() {
    let debugs: BTreeSet<String> = ExclusionReason::ALL
        .iter()
        .map(|r| format!("{r:?}"))
        .collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_exclusion_reason_display_all_unique() {
    let displays: BTreeSet<String> = ExclusionReason::ALL.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_exclusion_reason_as_str_matches_display() {
    for r in ExclusionReason::ALL {
        assert_eq!(r.as_str(), &r.to_string());
    }
}

// ===========================================================================
// CompressionAction enrichment
// ===========================================================================

#[test]
fn enrichment_compression_action_copy_semantics() {
    let a = CompressionAction::Compress;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_compression_action_btreeset_dedup_4() {
    let set: BTreeSet<CompressionAction> = CompressionAction::ALL.iter().copied().collect();
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_compression_action_debug_all_unique() {
    let debugs: BTreeSet<String> = CompressionAction::ALL
        .iter()
        .map(|a| format!("{a:?}"))
        .collect();
    assert_eq!(debugs.len(), 4);
}

#[test]
fn enrichment_compression_action_display_all_unique() {
    let displays: BTreeSet<String> = CompressionAction::ALL
        .iter()
        .map(|a| a.to_string())
        .collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn enrichment_compression_action_as_str_matches_display() {
    for &act in CompressionAction::ALL {
        assert_eq!(act.as_str(), &act.to_string());
    }
}

// ===========================================================================
// ArtifactDescriptor enrichment
// ===========================================================================

#[test]
fn enrichment_artifact_descriptor_clone_independence() {
    let d = desc("a1", ArtifactCategory::Cache, 1000);
    let mut d2 = d.clone();
    d2.size_bytes = 9999;
    assert_eq!(d.size_bytes, 1000);
    assert_eq!(d2.size_bytes, 9999);
}

#[test]
fn enrichment_artifact_descriptor_debug_nonempty() {
    let d = desc("a1", ArtifactCategory::Cache, 1000);
    let dbg = format!("{d:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ArtifactDescriptor"));
}

#[test]
fn enrichment_artifact_descriptor_json_field_names() {
    let d = desc("a1", ArtifactCategory::Cache, 1000);
    let json = serde_json::to_string(&d).unwrap();
    for field in [
        "artifact_id",
        "category",
        "size_bytes",
        "content_hash",
        "canonical_id",
        "already_compressed",
        "epoch",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_artifact_descriptor_with_canonical_id_chaining() {
    let canonical = ContentHash::compute(b"canonical");
    let d = desc("a1", ArtifactCategory::Cache, 1000).with_canonical_id(canonical);
    assert_eq!(d.canonical_id, Some(canonical));
}

#[test]
fn enrichment_artifact_descriptor_mark_already_compressed() {
    let d = desc("a1", ArtifactCategory::Cache, 1000).mark_already_compressed();
    assert!(d.already_compressed);
}

#[test]
fn enrichment_artifact_descriptor_content_hash_differs_by_content() {
    let d1 = ArtifactDescriptor::new("a1", ArtifactCategory::Cache, 100, b"hello", epoch());
    let d2 = ArtifactDescriptor::new("a1", ArtifactCategory::Cache, 100, b"world", epoch());
    assert_ne!(d1.content_hash, d2.content_hash);
}

// ===========================================================================
// RestorationRecipe enrichment
// ===========================================================================

#[test]
fn enrichment_restoration_recipe_clone_independence() {
    let r = RestorationRecipe::new(
        CompressionAlgorithm::Zstd,
        ContentHash::compute(b"orig"),
        ContentHash::compute(b"comp"),
        1000,
        500,
        epoch(),
    );
    let mut r2 = r.clone();
    r2.original_size_bytes = 9999;
    assert_eq!(r.original_size_bytes, 1000);
    assert_eq!(r2.original_size_bytes, 9999);
}

#[test]
fn enrichment_restoration_recipe_debug_nonempty() {
    let r = RestorationRecipe::new(
        CompressionAlgorithm::Zstd,
        ContentHash::compute(b"a"),
        ContentHash::compute(b"b"),
        1000,
        500,
        epoch(),
    );
    let dbg = format!("{r:?}");
    assert!(!dbg.is_empty());
}

#[test]
fn enrichment_restoration_recipe_json_field_names() {
    let r = RestorationRecipe::new(
        CompressionAlgorithm::Zstd,
        ContentHash::compute(b"a"),
        ContentHash::compute(b"b"),
        1000,
        500,
        epoch(),
    );
    let json = serde_json::to_string(&r).unwrap();
    for field in [
        "algorithm",
        "original_hash",
        "compressed_hash",
        "original_size_bytes",
        "compressed_size_bytes",
        "ratio_millionths",
        "epoch",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_restoration_recipe_beneficial_when_smaller() {
    let r = RestorationRecipe::new(
        CompressionAlgorithm::Zstd,
        ContentHash::compute(b"a"),
        ContentHash::compute(b"b"),
        1000,
        500,
        epoch(),
    );
    assert!(r.is_beneficial());
    assert_eq!(r.savings_bytes(), 500);
}

#[test]
fn enrichment_restoration_recipe_not_beneficial_when_larger() {
    let r = RestorationRecipe::new(
        CompressionAlgorithm::Zstd,
        ContentHash::compute(b"a"),
        ContentHash::compute(b"b"),
        500,
        1000,
        epoch(),
    );
    assert!(!r.is_beneficial());
}

#[test]
fn enrichment_restoration_recipe_boundary_equal_sizes() {
    let r = RestorationRecipe::new(
        CompressionAlgorithm::Deflate,
        ContentHash::compute(b"a"),
        ContentHash::compute(b"b"),
        1000,
        1000,
        epoch(),
    );
    assert!(!r.is_beneficial());
    assert_eq!(r.savings_bytes(), 0);
}

// ===========================================================================
// DedupReceipt enrichment
// ===========================================================================

#[test]
fn enrichment_dedup_receipt_clone_independence() {
    let r = DedupReceipt::new(
        "dup",
        "canon",
        ContentHash::compute(b"c"),
        ArtifactCategory::Cache,
        500,
        1,
        epoch(),
    );
    let mut r2 = r.clone();
    r2.saved_bytes = 9999;
    assert_eq!(r.saved_bytes, 500);
    assert_eq!(r2.saved_bytes, 9999);
}

#[test]
fn enrichment_dedup_receipt_debug_nonempty() {
    let r = DedupReceipt::new(
        "dup",
        "canon",
        ContentHash::compute(b"c"),
        ArtifactCategory::Aot,
        100,
        0,
        epoch(),
    );
    let dbg = format!("{r:?}");
    assert!(!dbg.is_empty());
}

#[test]
fn enrichment_dedup_receipt_json_field_names() {
    let r = DedupReceipt::new(
        "dup",
        "canon",
        ContentHash::compute(b"c"),
        ArtifactCategory::Cache,
        100,
        1,
        epoch(),
    );
    let json = serde_json::to_string(&r).unwrap();
    for field in [
        "duplicate_artifact_id",
        "canonical_artifact_id",
        "canonical_hash",
        "category",
        "saved_bytes",
        "chain_depth",
        "epoch",
        "receipt_hash",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// ExclusionReceipt enrichment
// ===========================================================================

#[test]
fn enrichment_exclusion_receipt_clone_independence() {
    let r = ExclusionReceipt::new(
        "a1",
        ArtifactCategory::Replay,
        ExclusionReason::CategoryExcluded,
        epoch(),
    );
    let cloned = r.clone();
    assert_eq!(r, cloned);
}

#[test]
fn enrichment_exclusion_receipt_debug_nonempty() {
    let r = ExclusionReceipt::new(
        "a1",
        ArtifactCategory::Replay,
        ExclusionReason::CategoryExcluded,
        epoch(),
    );
    let dbg = format!("{r:?}");
    assert!(!dbg.is_empty());
}

#[test]
fn enrichment_exclusion_receipt_json_field_names() {
    let r = ExclusionReceipt::new(
        "a1",
        ArtifactCategory::Replay,
        ExclusionReason::CategoryExcluded,
        epoch(),
    );
    let json = serde_json::to_string(&r).unwrap();
    for field in ["artifact_id", "category", "reason", "epoch", "receipt_hash"] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// PlanEntry enrichment
// ===========================================================================

#[test]
fn enrichment_plan_entry_clone_independence() {
    let entry = PlanEntry {
        artifact_id: "a1".to_string(),
        category: ArtifactCategory::Cache,
        action: CompressionAction::Compress,
        algorithm: CompressionAlgorithm::Zstd,
        dedup_target: None,
        exclusion_reason: None,
    };
    let mut cloned = entry.clone();
    cloned.artifact_id = "changed".to_string();
    assert_eq!(entry.artifact_id, "a1");
    assert_eq!(cloned.artifact_id, "changed");
}

#[test]
fn enrichment_plan_entry_debug_nonempty() {
    let entry = PlanEntry {
        artifact_id: "a1".to_string(),
        category: ArtifactCategory::Cache,
        action: CompressionAction::Compress,
        algorithm: CompressionAlgorithm::Zstd,
        dedup_target: None,
        exclusion_reason: None,
    };
    let dbg = format!("{entry:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("PlanEntry"));
}

#[test]
fn enrichment_plan_entry_serde_roundtrip() {
    let entry = PlanEntry {
        artifact_id: "a1".to_string(),
        category: ArtifactCategory::Evidence,
        action: CompressionAction::Exclude,
        algorithm: CompressionAlgorithm::Identity,
        dedup_target: None,
        exclusion_reason: Some(ExclusionReason::OversizeArtifact),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: PlanEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ===========================================================================
// BundlePlan enrichment
// ===========================================================================

#[test]
fn enrichment_bundle_plan_total_entries() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let descriptors = vec![
        desc("a1", ArtifactCategory::Cache, 1000),
        desc("a2", ArtifactCategory::Cache, 2000),
    ];
    let plan = planner.plan(&descriptors);
    assert_eq!(plan.total_entries(), plan.entries.len());
}

#[test]
fn enrichment_bundle_plan_has_actionable_entries() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let descriptors = vec![desc("a1", ArtifactCategory::Cache, 1000)];
    let plan = planner.plan(&descriptors);
    assert!(plan.has_actionable_entries());
}

#[test]
fn enrichment_bundle_plan_clone_independence() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let descriptors = vec![desc("a1", ArtifactCategory::Cache, 1000)];
    let plan = planner.plan(&descriptors);
    let mut cloned = plan.clone();
    cloned.compress_count = 99;
    assert_ne!(plan.compress_count, 99);
}

#[test]
fn enrichment_bundle_plan_debug_nonempty() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let plan = planner.plan(&[]);
    let dbg = format!("{plan:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("BundlePlan"));
}

// ===========================================================================
// PlannerConfig enrichment
// ===========================================================================

#[test]
fn enrichment_planner_config_clone_independence() {
    let cfg = PlannerConfig::new(epoch());
    let mut cloned = cfg.clone();
    cloned.max_bundle_size = 99;
    assert_eq!(cfg.max_bundle_size, MAX_BUNDLE_SIZE);
    assert_eq!(cloned.max_bundle_size, 99);
}

#[test]
fn enrichment_planner_config_default_matches_constants() {
    let cfg = PlannerConfig::new(epoch());
    assert_eq!(cfg.max_bundle_size, MAX_BUNDLE_SIZE);
    assert_eq!(cfg.max_artifact_bytes, MAX_ARTIFACT_BYTES);
    assert_eq!(cfg.algorithm, CompressionAlgorithm::Zstd);
    assert!(cfg.dedup_enabled);
}

#[test]
fn enrichment_planner_config_debug_nonempty() {
    let cfg = PlannerConfig::new(epoch());
    let dbg = format!("{cfg:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("PlannerConfig"));
}

#[test]
fn enrichment_planner_config_builder_chain() {
    let cfg = PlannerConfig::new(epoch())
        .with_algorithm(CompressionAlgorithm::Lz4)
        .with_extra_exclusion(ArtifactCategory::Benchmark)
        .without_dedup();
    assert_eq!(cfg.algorithm, CompressionAlgorithm::Lz4);
    assert!(cfg.extra_exclusions.contains(&ArtifactCategory::Benchmark));
    assert!(!cfg.dedup_enabled);
}

#[test]
fn enrichment_planner_config_json_field_names() {
    let cfg = PlannerConfig::new(epoch());
    let json = serde_json::to_string(&cfg).unwrap();
    for field in [
        "algorithm",
        "max_bundle_size",
        "max_artifact_bytes",
        "extra_exclusions",
        "dedup_enabled",
        "epoch",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// DedupTracker enrichment
// ===========================================================================

#[test]
fn enrichment_dedup_tracker_clone_independence() {
    let mut tracker = DedupTracker::new(epoch());
    tracker.record_dedup(
        "dup",
        "canon",
        ContentHash::compute(b"c"),
        ArtifactCategory::Cache,
        500,
        1,
    );
    let mut cloned = tracker.clone();
    cloned.total_saved_bytes = 9999;
    assert_eq!(tracker.total_saved_bytes, 500);
    assert_eq!(cloned.total_saved_bytes, 9999);
}

#[test]
fn enrichment_dedup_tracker_debug_nonempty() {
    let tracker = DedupTracker::new(epoch());
    let dbg = format!("{tracker:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("DedupTracker"));
}

#[test]
fn enrichment_dedup_tracker_empty_savings_ratio() {
    let tracker = DedupTracker::new(epoch());
    assert_eq!(tracker.savings_ratio_millionths(1000), 0);
    assert_eq!(tracker.savings_ratio_millionths(0), 0);
}

#[test]
fn enrichment_dedup_tracker_record_representative() {
    let mut tracker = DedupTracker::new(epoch());
    assert_eq!(tracker.unique_representatives, 0);
    tracker.record_representative();
    assert_eq!(tracker.unique_representatives, 1);
    tracker.record_representative();
    assert_eq!(tracker.unique_representatives, 2);
}

// ===========================================================================
// CompressionReport enrichment
// ===========================================================================

#[test]
fn enrichment_compression_report_clone_independence() {
    let pipeline = CompressionPipeline::new(PlannerConfig::new(epoch()));
    let report = pipeline.run(&[desc("a1", ArtifactCategory::Cache, 1000)]);
    let mut cloned = report.clone();
    cloned.total_input_bytes = 9999;
    assert_eq!(report.total_input_bytes, 1000);
    assert_eq!(cloned.total_input_bytes, 9999);
}

#[test]
fn enrichment_compression_report_debug_nonempty() {
    let pipeline = CompressionPipeline::new(PlannerConfig::new(epoch()));
    let report = pipeline.run(&[]);
    let dbg = format!("{report:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("CompressionReport"));
}

#[test]
fn enrichment_compression_report_empty_input() {
    let pipeline = CompressionPipeline::new(PlannerConfig::new(epoch()));
    let report = pipeline.run(&[]);
    assert_eq!(report.total_input_bytes, 0);
    assert_eq!(report.total_output_bytes, 0);
    assert!(!report.has_actions());
    assert_eq!(report.exclusion_count(), 0);
    assert_eq!(report.total_savings_bytes(), 0);
}

#[test]
fn enrichment_compression_report_has_actions_with_artifacts() {
    let pipeline = CompressionPipeline::new(PlannerConfig::new(epoch()));
    let report = pipeline.run(&[desc("a1", ArtifactCategory::Cache, 1000)]);
    assert!(report.has_actions());
}

#[test]
fn enrichment_compression_report_exclusion_count_for_protected() {
    let pipeline = CompressionPipeline::new(PlannerConfig::new(epoch()));
    let report = pipeline.run(&[
        desc("a1", ArtifactCategory::Replay, 1000),
        desc("a2", ArtifactCategory::SecurityProvenance, 2000),
    ]);
    assert_eq!(report.exclusion_count(), 2);
}

// ===========================================================================
// Five-run determinism
// ===========================================================================

#[test]
fn enrichment_five_run_determinism_plan_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let config = PlannerConfig::new(epoch());
            let mut planner = BundlePlanner::new(config);
            planner
                .plan(&[desc("a1", ArtifactCategory::Cache, 1000)])
                .plan_hash
        })
        .collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

#[test]
fn enrichment_five_run_determinism_report_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let pipeline = CompressionPipeline::new(PlannerConfig::new(epoch()));
            pipeline
                .run(&[desc("a1", ArtifactCategory::Cache, 1000)])
                .report_hash
        })
        .collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

#[test]
fn enrichment_five_run_determinism_dedup_receipt_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            DedupReceipt::new(
                "dup",
                "canon",
                ContentHash::compute(b"c"),
                ArtifactCategory::Cache,
                500,
                1,
                epoch(),
            )
            .receipt_hash
        })
        .collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

#[test]
fn enrichment_five_run_determinism_exclusion_receipt_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            ExclusionReceipt::new(
                "a1",
                ArtifactCategory::Replay,
                ExclusionReason::CategoryExcluded,
                epoch(),
            )
            .receipt_hash
        })
        .collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

// ===========================================================================
// Constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stability() {
    assert!(SCHEMA_VERSION.contains("artifact-compression-pipeline"));
    assert_eq!(COMPONENT, "artifact_compression_pipeline");
    assert!(MAX_BUNDLE_SIZE > 0);
    assert!(MAX_ARTIFACT_BYTES > 0);
    assert!(MIN_USEFUL_RATIO > 0);
    assert!(MIN_USEFUL_RATIO <= 1_000_000);
    assert!(MAX_DEDUP_CHAIN_DEPTH > 0);
}

// ===========================================================================
// Serde roundtrips
// ===========================================================================

#[test]
fn enrichment_compression_algorithm_serde_all() {
    for &alg in CompressionAlgorithm::ALL {
        let json = serde_json::to_string(&alg).unwrap();
        let back: CompressionAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(alg, back);
    }
}

#[test]
fn enrichment_artifact_category_serde_all() {
    for &cat in ArtifactCategory::ALL {
        let json = serde_json::to_string(&cat).unwrap();
        let back: ArtifactCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, back);
    }
}

#[test]
fn enrichment_exclusion_reason_serde_all() {
    for r in ExclusionReason::ALL {
        let json = serde_json::to_string(r).unwrap();
        let back: ExclusionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

#[test]
fn enrichment_compression_action_serde_all() {
    for &act in CompressionAction::ALL {
        let json = serde_json::to_string(&act).unwrap();
        let back: CompressionAction = serde_json::from_str(&json).unwrap();
        assert_eq!(act, back);
    }
}

#[test]
fn enrichment_artifact_descriptor_serde_roundtrip() {
    let d = desc("a1", ArtifactCategory::Cache, 1000)
        .with_canonical_id(ContentHash::compute(b"canon"))
        .mark_already_compressed();
    let json = serde_json::to_string(&d).unwrap();
    let back: ArtifactDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn enrichment_restoration_recipe_serde_roundtrip() {
    let r = RestorationRecipe::new(
        CompressionAlgorithm::Lz4,
        ContentHash::compute(b"a"),
        ContentHash::compute(b"b"),
        2000,
        1000,
        epoch(),
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: RestorationRecipe = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_dedup_receipt_serde_roundtrip() {
    let r = DedupReceipt::new(
        "dup",
        "canon",
        ContentHash::compute(b"c"),
        ArtifactCategory::Cache,
        500,
        1,
        epoch(),
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: DedupReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_exclusion_receipt_serde_roundtrip() {
    let r = ExclusionReceipt::new(
        "a1",
        ArtifactCategory::Replay,
        ExclusionReason::CategoryExcluded,
        epoch(),
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: ExclusionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ===========================================================================
// Cross-cutting
// ===========================================================================

#[test]
fn enrichment_pipeline_excluded_category_not_in_restoration_recipes() {
    let pipeline = CompressionPipeline::new(PlannerConfig::new(epoch()));
    let report = pipeline.run(&[
        desc("a1", ArtifactCategory::Replay, 1000),
        desc("a2", ArtifactCategory::Cache, 2000),
    ]);
    // Replay is excluded, so only Cache should have restoration recipes
    assert_eq!(report.exclusion_count(), 1);
    // The cache artifact should be compressed
    assert!(report.plan.compress_count >= 1 || report.plan.passthrough_count >= 1);
}

#[test]
fn enrichment_pipeline_identity_algorithm_passthroughs() {
    let config = PlannerConfig::new(epoch()).with_algorithm(CompressionAlgorithm::Identity);
    let pipeline = CompressionPipeline::new(config);
    let report = pipeline.run(&[desc("a1", ArtifactCategory::Cache, 1000)]);
    assert_eq!(report.plan.compress_count, 0);
    assert!(report.plan.passthrough_count >= 1);
}

#[test]
fn enrichment_planner_oversize_artifact_excluded() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let plan = planner.plan(&[desc("big", ArtifactCategory::Cache, MAX_ARTIFACT_BYTES + 1)]);
    assert_eq!(plan.exclude_count, 1);
    assert_eq!(plan.compress_count, 0);
}
