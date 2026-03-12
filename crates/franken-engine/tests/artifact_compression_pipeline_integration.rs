//! Integration tests for `artifact_compression_pipeline` module.
//!
//! Validates public API, serde contracts, determinism, pipeline orchestration,
//! exclusion policy, dedup tracking, and restoration recipes.

#![allow(clippy::field_reassign_with_default)]

use std::collections::BTreeSet;

use frankenengine_engine::artifact_compression_pipeline::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn desc(id: &str, cat: ArtifactCategory, size: u64) -> ArtifactDescriptor {
    ArtifactDescriptor::new(id, cat, size, id.as_bytes(), epoch())
}

fn desc_canonical(id: &str, cat: ArtifactCategory, size: u64, seed: &[u8]) -> ArtifactDescriptor {
    desc(id, cat, size).with_canonical_id(ContentHash::compute(seed))
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_matches_module_convention() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    assert!(SCHEMA_VERSION.contains("compression"));
}

#[test]
fn bead_id_matches_expected() {
    assert_eq!(BEAD_ID, "bd-1lsy.7.18.2");
}

#[test]
fn component_is_snake_case() {
    assert_eq!(COMPONENT, "artifact_compression_pipeline");
}

#[test]
fn max_bundle_size_reasonable() {
    const {
        assert!(MAX_BUNDLE_SIZE >= 256);
        assert!(MAX_BUNDLE_SIZE <= 65_536);
    }
}

#[test]
fn max_artifact_bytes_reasonable() {
    const {
        assert!(MAX_ARTIFACT_BYTES >= 1024 * 1024);
    }
}

// ---------------------------------------------------------------------------
// CompressionAlgorithm
// ---------------------------------------------------------------------------

#[test]
fn algorithm_all_variants_covered() {
    let all: BTreeSet<CompressionAlgorithm> = CompressionAlgorithm::ALL.iter().copied().collect();
    assert!(all.contains(&CompressionAlgorithm::Identity));
    assert!(all.contains(&CompressionAlgorithm::Deflate));
    assert!(all.contains(&CompressionAlgorithm::Zstd));
    assert!(all.contains(&CompressionAlgorithm::Lz4));
}

#[test]
fn algorithm_is_compressor_identity_false() {
    assert!(!CompressionAlgorithm::Identity.is_compressor());
}

#[test]
fn algorithm_is_compressor_others_true() {
    for alg in CompressionAlgorithm::ALL {
        if *alg != CompressionAlgorithm::Identity {
            assert!(alg.is_compressor(), "{alg} should be a compressor");
        }
    }
}

#[test]
fn algorithm_serde_all() {
    for alg in CompressionAlgorithm::ALL {
        let json = serde_json::to_string(alg).unwrap();
        let back: CompressionAlgorithm = serde_json::from_str(&json).unwrap();
        assert_eq!(*alg, back, "serde roundtrip failed for {alg}");
    }
}

#[test]
fn algorithm_display_matches_as_str() {
    for alg in CompressionAlgorithm::ALL {
        assert_eq!(alg.to_string(), alg.as_str());
    }
}

// ---------------------------------------------------------------------------
// ArtifactCategory
// ---------------------------------------------------------------------------

#[test]
fn category_all_variants_covered() {
    assert_eq!(ArtifactCategory::ALL.len(), 9);
}

#[test]
fn category_excluded_set_is_correct() {
    let excluded: BTreeSet<ArtifactCategory> = ArtifactCategory::ALL
        .iter()
        .filter(|c| c.is_compression_excluded())
        .copied()
        .collect();
    assert_eq!(excluded.len(), 3);
    assert!(excluded.contains(&ArtifactCategory::Replay));
    assert!(excluded.contains(&ArtifactCategory::SecurityProvenance));
    assert!(excluded.contains(&ArtifactCategory::LegalProvenance));
}

#[test]
fn category_dedup_excluded_matches_compression_excluded() {
    for cat in ArtifactCategory::ALL {
        assert_eq!(
            cat.is_compression_excluded(),
            cat.is_dedup_excluded(),
            "dedup/compression exclusion mismatch for {cat}"
        );
    }
}

#[test]
fn category_serde_all() {
    for cat in ArtifactCategory::ALL {
        let json = serde_json::to_string(cat).unwrap();
        let back: ArtifactCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(*cat, back, "serde roundtrip failed for {cat}");
    }
}

#[test]
fn category_non_excluded_are_compressible() {
    let compressible = [
        ArtifactCategory::Cache,
        ArtifactCategory::Aot,
        ArtifactCategory::Evidence,
        ArtifactCategory::Benchmark,
        ArtifactCategory::RewritePack,
        ArtifactCategory::SupportBundle,
    ];
    for cat in &compressible {
        assert!(
            !cat.is_compression_excluded(),
            "{cat} should be compressible"
        );
    }
}

// ---------------------------------------------------------------------------
// ExclusionReason
// ---------------------------------------------------------------------------

#[test]
fn exclusion_reason_all_length() {
    assert_eq!(ExclusionReason::ALL.len(), 6);
}

#[test]
fn exclusion_reason_names_unique() {
    let names: BTreeSet<&str> = ExclusionReason::ALL.iter().map(|r| r.as_str()).collect();
    assert_eq!(names.len(), ExclusionReason::ALL.len());
}

// ---------------------------------------------------------------------------
// CompressionAction
// ---------------------------------------------------------------------------

#[test]
fn action_all_length() {
    assert_eq!(CompressionAction::ALL.len(), 4);
}

#[test]
fn action_serde_all() {
    for action in CompressionAction::ALL {
        let json = serde_json::to_string(action).unwrap();
        let back: CompressionAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*action, back);
    }
}

// ---------------------------------------------------------------------------
// ArtifactDescriptor
// ---------------------------------------------------------------------------

#[test]
fn descriptor_basic_construction() {
    let d = desc("test-art", ArtifactCategory::Cache, 2048);
    assert_eq!(d.artifact_id, "test-art");
    assert_eq!(d.size_bytes, 2048);
    assert!(!d.already_compressed);
    assert!(d.canonical_id.is_none());
}

#[test]
fn descriptor_canonical_attachment() {
    let d = desc_canonical("art-c", ArtifactCategory::Cache, 1024, b"seed");
    assert!(d.canonical_id.is_some());
}

#[test]
fn descriptor_already_compressed_flag() {
    let d = desc("art-z", ArtifactCategory::Aot, 512).mark_already_compressed();
    assert!(d.already_compressed);
}

#[test]
fn descriptor_serde_roundtrip() {
    let d = desc_canonical("art-s", ArtifactCategory::Evidence, 4096, b"x");
    let json = serde_json::to_string(&d).unwrap();
    let back: ArtifactDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(d, back);
}

#[test]
fn descriptor_content_hash_deterministic() {
    let d1 = desc("art-d", ArtifactCategory::Cache, 100);
    let d2 = desc("art-d", ArtifactCategory::Cache, 100);
    assert_eq!(d1.content_hash, d2.content_hash);
}

// ---------------------------------------------------------------------------
// RestorationRecipe
// ---------------------------------------------------------------------------

#[test]
fn recipe_ratio_correct() {
    let recipe = RestorationRecipe::new(
        CompressionAlgorithm::Zstd,
        ContentHash::compute(b"orig"),
        ContentHash::compute(b"comp"),
        2000,
        1100,
        epoch(),
    );
    assert_eq!(recipe.ratio_millionths, 550_000);
}

#[test]
fn recipe_beneficial_check() {
    let r = RestorationRecipe::new(
        CompressionAlgorithm::Deflate,
        ContentHash::compute(b"a"),
        ContentHash::compute(b"b"),
        1000,
        800,
        epoch(),
    );
    assert!(r.is_beneficial());
    assert_eq!(r.savings_bytes(), 200);
}

#[test]
fn recipe_not_beneficial_when_expanded() {
    let r = RestorationRecipe::new(
        CompressionAlgorithm::Lz4,
        ContentHash::compute(b"a"),
        ContentHash::compute(b"b"),
        100,
        150,
        epoch(),
    );
    assert!(!r.is_beneficial());
    assert_eq!(r.savings_bytes(), 0);
}

#[test]
fn recipe_zero_input_ratio() {
    let r = RestorationRecipe::new(
        CompressionAlgorithm::Zstd,
        ContentHash::compute(b""),
        ContentHash::compute(b""),
        0,
        0,
        epoch(),
    );
    assert_eq!(r.ratio_millionths, 1_000_000);
}

#[test]
fn recipe_serde_roundtrip() {
    let r = RestorationRecipe::new(
        CompressionAlgorithm::Lz4,
        ContentHash::compute(b"a"),
        ContentHash::compute(b"b"),
        5000,
        3500,
        epoch(),
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: RestorationRecipe = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// DedupReceipt
// ---------------------------------------------------------------------------

#[test]
fn dedup_receipt_deterministic_hash() {
    let r1 = DedupReceipt::new(
        "dup",
        "canon",
        ContentHash::compute(b"x"),
        ArtifactCategory::Cache,
        256,
        1,
        epoch(),
    );
    let r2 = DedupReceipt::new(
        "dup",
        "canon",
        ContentHash::compute(b"x"),
        ArtifactCategory::Cache,
        256,
        1,
        epoch(),
    );
    assert_eq!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn dedup_receipt_different_for_different_inputs() {
    let r1 = DedupReceipt::new(
        "dup-a",
        "canon",
        ContentHash::compute(b"x"),
        ArtifactCategory::Cache,
        256,
        1,
        epoch(),
    );
    let r2 = DedupReceipt::new(
        "dup-b",
        "canon",
        ContentHash::compute(b"x"),
        ArtifactCategory::Cache,
        256,
        1,
        epoch(),
    );
    assert_ne!(r1.receipt_hash, r2.receipt_hash);
}

#[test]
fn dedup_receipt_serde() {
    let r = DedupReceipt::new(
        "d",
        "c",
        ContentHash::compute(b"h"),
        ArtifactCategory::Aot,
        512,
        2,
        epoch(),
    );
    let json = serde_json::to_string(&r).unwrap();
    let back: DedupReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// ExclusionReceipt
// ---------------------------------------------------------------------------

#[test]
fn exclusion_receipt_deterministic() {
    let e1 = ExclusionReceipt::new(
        "art-x",
        ArtifactCategory::Replay,
        ExclusionReason::CategoryExcluded,
        epoch(),
    );
    let e2 = ExclusionReceipt::new(
        "art-x",
        ArtifactCategory::Replay,
        ExclusionReason::CategoryExcluded,
        epoch(),
    );
    assert_eq!(e1.receipt_hash, e2.receipt_hash);
}

#[test]
fn exclusion_receipt_serde() {
    let e = ExclusionReceipt::new(
        "art-e",
        ArtifactCategory::SecurityProvenance,
        ExclusionReason::CategoryExcluded,
        epoch(),
    );
    let json = serde_json::to_string(&e).unwrap();
    let back: ExclusionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ---------------------------------------------------------------------------
// BundlePlanner — exclusion policy
// ---------------------------------------------------------------------------

#[test]
fn planner_excludes_all_protected_categories() {
    let protected = [
        ArtifactCategory::Replay,
        ArtifactCategory::SecurityProvenance,
        ArtifactCategory::LegalProvenance,
    ];
    for cat in &protected {
        let config = PlannerConfig::new(epoch());
        let mut planner = BundlePlanner::new(config);
        let d = desc("protected", *cat, 4096);
        let plan = planner.plan(&[d]);
        assert_eq!(plan.exclude_count, 1, "expected exclusion for {cat}");
        assert_eq!(
            plan.entries[0].exclusion_reason,
            Some(ExclusionReason::CategoryExcluded),
        );
    }
}

#[test]
fn planner_oversize_exclusion() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let d = desc("big", ArtifactCategory::Cache, MAX_ARTIFACT_BYTES + 1);
    let plan = planner.plan(&[d]);
    assert_eq!(
        plan.entries[0].exclusion_reason,
        Some(ExclusionReason::OversizeArtifact)
    );
}

#[test]
fn planner_already_compressed_exclusion() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let d = desc("recomp", ArtifactCategory::Aot, 2048).mark_already_compressed();
    let plan = planner.plan(&[d]);
    assert_eq!(
        plan.entries[0].exclusion_reason,
        Some(ExclusionReason::AlreadyCompressed)
    );
}

#[test]
fn planner_epoch_mismatch_exclusion() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let mut d = desc("mismatch", ArtifactCategory::Cache, 1024);
    d.epoch = SecurityEpoch::from_raw(999);
    let plan = planner.plan(&[d]);
    assert_eq!(
        plan.entries[0].exclusion_reason,
        Some(ExclusionReason::EpochMismatch)
    );
}

#[test]
fn planner_extra_exclusion_category() {
    let config = PlannerConfig::new(epoch()).with_extra_exclusion(ArtifactCategory::SupportBundle);
    let mut planner = BundlePlanner::new(config);
    let d = desc("support-1", ArtifactCategory::SupportBundle, 4096);
    let plan = planner.plan(&[d]);
    assert_eq!(plan.exclude_count, 1);
}

// ---------------------------------------------------------------------------
// BundlePlanner — compression
// ---------------------------------------------------------------------------

#[test]
fn planner_default_zstd() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let d = desc("cache-1", ArtifactCategory::Cache, 8192);
    let plan = planner.plan(&[d]);
    assert_eq!(plan.entries[0].algorithm, CompressionAlgorithm::Zstd);
}

#[test]
fn planner_custom_algorithm() {
    let config = PlannerConfig::new(epoch()).with_algorithm(CompressionAlgorithm::Lz4);
    let mut planner = BundlePlanner::new(config);
    let d = desc("cache-1", ArtifactCategory::Cache, 8192);
    let plan = planner.plan(&[d]);
    assert_eq!(plan.entries[0].algorithm, CompressionAlgorithm::Lz4);
}

#[test]
fn planner_identity_passthrough() {
    let config = PlannerConfig::new(epoch()).with_algorithm(CompressionAlgorithm::Identity);
    let mut planner = BundlePlanner::new(config);
    let d = desc("cache-1", ArtifactCategory::Cache, 8192);
    let plan = planner.plan(&[d]);
    assert_eq!(plan.entries[0].action, CompressionAction::Passthrough);
}

// ---------------------------------------------------------------------------
// BundlePlanner — dedup
// ---------------------------------------------------------------------------

#[test]
fn planner_dedup_second_occurrence() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let d1 = desc_canonical("a1", ArtifactCategory::Cache, 1024, b"same");
    let d2 = desc_canonical("a2", ArtifactCategory::Cache, 1024, b"same");
    let plan = planner.plan(&[d1, d2]);

    assert_eq!(plan.compress_count, 1);
    assert_eq!(plan.dedup_count, 1);
    assert_eq!(plan.entries[0].artifact_id, "a1");
    assert_eq!(plan.entries[0].action, CompressionAction::Compress);
    assert_eq!(plan.entries[1].artifact_id, "a2");
    assert_eq!(plan.entries[1].action, CompressionAction::Dedup);
    assert_eq!(plan.entries[1].dedup_target, Some("a1".to_string()));
}

#[test]
fn planner_dedup_third_occurrence() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let d1 = desc_canonical("a1", ArtifactCategory::Cache, 1024, b"same");
    let d2 = desc_canonical("a2", ArtifactCategory::Cache, 1024, b"same");
    let d3 = desc_canonical("a3", ArtifactCategory::Cache, 1024, b"same");
    let plan = planner.plan(&[d1, d2, d3]);

    assert_eq!(plan.compress_count, 1);
    assert_eq!(plan.dedup_count, 2);
}

#[test]
fn planner_dedup_different_canonical_no_dedup() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let d1 = desc_canonical("a1", ArtifactCategory::Cache, 1024, b"alpha");
    let d2 = desc_canonical("a2", ArtifactCategory::Cache, 1024, b"beta");
    let plan = planner.plan(&[d1, d2]);

    assert_eq!(plan.compress_count, 2);
    assert_eq!(plan.dedup_count, 0);
}

#[test]
fn planner_no_dedup_without_canonical_id() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let d1 = desc("a1", ArtifactCategory::Cache, 1024);
    let d2 = desc("a2", ArtifactCategory::Cache, 1024);
    let plan = planner.plan(&[d1, d2]);

    assert_eq!(plan.compress_count, 2);
    assert_eq!(plan.dedup_count, 0);
}

#[test]
fn planner_dedup_disabled() {
    let config = PlannerConfig::new(epoch()).without_dedup();
    let mut planner = BundlePlanner::new(config);
    let d1 = desc_canonical("a1", ArtifactCategory::Cache, 1024, b"same");
    let d2 = desc_canonical("a2", ArtifactCategory::Cache, 1024, b"same");
    let plan = planner.plan(&[d1, d2]);

    assert_eq!(plan.compress_count, 2);
    assert_eq!(plan.dedup_count, 0);
}

// ---------------------------------------------------------------------------
// BundlePlanner — plan hash determinism
// ---------------------------------------------------------------------------

#[test]
fn plan_hash_deterministic() {
    let descriptors = vec![
        desc("c1", ArtifactCategory::Cache, 4096),
        desc("a1", ArtifactCategory::Aot, 8192),
    ];

    let config = PlannerConfig::new(epoch());
    let mut p1 = BundlePlanner::new(config.clone());
    let plan1 = p1.plan(&descriptors);
    let mut p2 = BundlePlanner::new(config);
    let plan2 = p2.plan(&descriptors);

    assert_eq!(plan1.plan_hash, plan2.plan_hash);
}

#[test]
fn plan_hash_changes_with_different_input() {
    let config = PlannerConfig::new(epoch());
    let mut p1 = BundlePlanner::new(config.clone());
    let plan1 = p1.plan(&[desc("a", ArtifactCategory::Cache, 100)]);
    let mut p2 = BundlePlanner::new(config);
    let plan2 = p2.plan(&[desc("b", ArtifactCategory::Cache, 100)]);

    assert_ne!(plan1.plan_hash, plan2.plan_hash);
}

// ---------------------------------------------------------------------------
// BundlePlanner — mixed batches
// ---------------------------------------------------------------------------

#[test]
fn planner_large_mixed_batch() {
    let config = PlannerConfig::new(epoch());
    let mut planner = BundlePlanner::new(config);
    let mut descriptors = Vec::new();

    // 10 cache (compressible)
    for i in 0..10 {
        descriptors.push(desc(
            &format!("cache-{i}"),
            ArtifactCategory::Cache,
            1024 * (i as u64 + 1),
        ));
    }
    // 5 replay (excluded)
    for i in 0..5 {
        descriptors.push(desc(&format!("replay-{i}"), ArtifactCategory::Replay, 2048));
    }
    // 3 dedup candidates
    for i in 0..3 {
        descriptors.push(desc_canonical(
            &format!("dedup-{i}"),
            ArtifactCategory::Aot,
            4096,
            b"shared-canon",
        ));
    }

    let plan = planner.plan(&descriptors);

    assert_eq!(plan.total_entries(), 18);
    assert_eq!(plan.compress_count, 11); // 10 cache + 1 first dedup (aot)
    assert_eq!(plan.dedup_count, 2); // 2nd and 3rd dedup candidates
    assert_eq!(plan.exclude_count, 5); // 5 replay
    assert!(plan.has_actionable_entries());
}

// ---------------------------------------------------------------------------
// DedupTracker
// ---------------------------------------------------------------------------

#[test]
fn tracker_accumulates_savings() {
    let mut t = DedupTracker::new(epoch());
    t.record_dedup(
        "d1",
        "c1",
        ContentHash::compute(b"a"),
        ArtifactCategory::Cache,
        100,
        1,
    );
    t.record_dedup(
        "d2",
        "c2",
        ContentHash::compute(b"b"),
        ArtifactCategory::Cache,
        200,
        1,
    );
    assert_eq!(t.total_saved_bytes, 300);
    assert_eq!(t.duplicates_resolved, 2);
    assert_eq!(t.receipts.len(), 2);
}

#[test]
fn tracker_per_category_accumulation() {
    let mut t = DedupTracker::new(epoch());
    t.record_dedup(
        "d1",
        "c1",
        ContentHash::compute(b"a"),
        ArtifactCategory::Cache,
        50,
        1,
    );
    t.record_dedup(
        "d2",
        "c2",
        ContentHash::compute(b"b"),
        ArtifactCategory::Aot,
        75,
        1,
    );
    t.record_dedup(
        "d3",
        "c3",
        ContentHash::compute(b"c"),
        ArtifactCategory::Cache,
        25,
        1,
    );

    assert_eq!(t.savings_by_category.get("cache"), Some(&75));
    assert_eq!(t.savings_by_category.get("aot"), Some(&75));
}

#[test]
fn tracker_savings_ratio_calculation() {
    let mut t = DedupTracker::new(epoch());
    t.record_dedup(
        "d",
        "c",
        ContentHash::compute(b"x"),
        ArtifactCategory::Cache,
        250,
        1,
    );
    assert_eq!(t.savings_ratio_millionths(1000), 250_000); // 25%
}

#[test]
fn tracker_serde_roundtrip() {
    let mut t = DedupTracker::new(epoch());
    t.record_dedup(
        "d",
        "c",
        ContentHash::compute(b"x"),
        ArtifactCategory::Cache,
        100,
        1,
    );
    t.record_representative();
    let json = serde_json::to_string(&t).unwrap();
    let back: DedupTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

// ---------------------------------------------------------------------------
// CompressionPipeline — full runs
// ---------------------------------------------------------------------------

#[test]
fn pipeline_single_artifact_compression() {
    let config = PlannerConfig::new(epoch());
    let pipeline = CompressionPipeline::new(config);
    let report = pipeline.run(&[desc("c1", ArtifactCategory::Cache, 10_000)]);

    assert_eq!(report.total_input_bytes, 10_000);
    assert!(report.total_output_bytes < 10_000);
    assert!(report.overall_ratio_millionths < 1_000_000);
    assert_eq!(report.restoration_recipes.len(), 1);
    assert!(report.restoration_recipes[0].is_beneficial());
    assert!(report.has_actions());
}

#[test]
fn pipeline_excluded_only() {
    let config = PlannerConfig::new(epoch());
    let pipeline = CompressionPipeline::new(config);
    let report = pipeline.run(&[
        desc("r1", ArtifactCategory::Replay, 1000),
        desc("s1", ArtifactCategory::SecurityProvenance, 2000),
    ]);

    assert_eq!(report.exclusion_count(), 2);
    assert!(report.restoration_recipes.is_empty());
    assert_eq!(report.total_output_bytes, 3000);
    assert!(!report.has_actions());
}

#[test]
fn pipeline_dedup_reduces_output() {
    let config = PlannerConfig::new(epoch());
    let pipeline = CompressionPipeline::new(config);
    let d1 = desc_canonical("a1", ArtifactCategory::Cache, 5000, b"same");
    let d2 = desc_canonical("a2", ArtifactCategory::Cache, 5000, b"same");
    let report = pipeline.run(&[d1, d2]);

    assert_eq!(report.total_input_bytes, 10_000);
    // art-1: compressed (~55%=2750), art-2: deduped (0)
    assert!(report.total_output_bytes < 5000);
    assert_eq!(report.dedup_tracker.duplicates_resolved, 1);
    assert_eq!(report.dedup_tracker.total_saved_bytes, 5000);
}

#[test]
fn pipeline_mixed_workload() {
    let config = PlannerConfig::new(epoch());
    let pipeline = CompressionPipeline::new(config);
    let report = pipeline.run(&[
        desc("cache-1", ArtifactCategory::Cache, 10_000),
        desc("aot-1", ArtifactCategory::Aot, 20_000),
        desc("replay-1", ArtifactCategory::Replay, 5_000),
        desc("evidence-1", ArtifactCategory::Evidence, 8_000),
        desc("legal-1", ArtifactCategory::LegalProvenance, 3_000),
    ]);

    assert_eq!(report.total_input_bytes, 46_000);
    assert_eq!(report.restoration_recipes.len(), 3); // cache, aot, evidence
    assert_eq!(report.exclusion_count(), 2); // replay, legal
    assert!(report.overall_ratio_millionths < 1_000_000);
}

#[test]
fn pipeline_empty_input() {
    let config = PlannerConfig::new(epoch());
    let pipeline = CompressionPipeline::new(config);
    let report = pipeline.run(&[]);

    assert_eq!(report.total_input_bytes, 0);
    assert_eq!(report.total_output_bytes, 0);
    assert!(!report.has_actions());
    assert_eq!(report.exclusion_count(), 0);
}

#[test]
fn pipeline_report_hash_deterministic() {
    let config = PlannerConfig::new(epoch());
    let descriptors = vec![
        desc("c1", ArtifactCategory::Cache, 4096),
        desc("a1", ArtifactCategory::Aot, 8192),
    ];

    let r1 = CompressionPipeline::new(config.clone()).run(&descriptors);
    let r2 = CompressionPipeline::new(config).run(&descriptors);

    assert_eq!(r1.report_hash, r2.report_hash);
    assert_eq!(r1.total_output_bytes, r2.total_output_bytes);
}

#[test]
fn pipeline_report_total_savings() {
    let config = PlannerConfig::new(epoch());
    let pipeline = CompressionPipeline::new(config);
    let report = pipeline.run(&[desc("c1", ArtifactCategory::Cache, 10_000)]);
    assert!(report.total_savings_bytes() > 0);
    assert_eq!(
        report.total_savings_bytes(),
        report.total_input_bytes - report.total_output_bytes
    );
}

// ---------------------------------------------------------------------------
// PlannerConfig builder
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let config = PlannerConfig::new(epoch());
    assert_eq!(config.algorithm, CompressionAlgorithm::Zstd);
    assert_eq!(config.max_bundle_size, MAX_BUNDLE_SIZE);
    assert_eq!(config.max_artifact_bytes, MAX_ARTIFACT_BYTES);
    assert!(config.extra_exclusions.is_empty());
    assert!(config.dedup_enabled);
}

#[test]
fn config_builder_chain() {
    let config = PlannerConfig::new(epoch())
        .with_algorithm(CompressionAlgorithm::Deflate)
        .with_extra_exclusion(ArtifactCategory::Benchmark)
        .with_extra_exclusion(ArtifactCategory::SupportBundle)
        .without_dedup();

    assert_eq!(config.algorithm, CompressionAlgorithm::Deflate);
    assert_eq!(config.extra_exclusions.len(), 2);
    assert!(!config.dedup_enabled);
}

#[test]
fn config_serde_roundtrip() {
    let config = PlannerConfig::new(epoch())
        .with_algorithm(CompressionAlgorithm::Lz4)
        .with_extra_exclusion(ArtifactCategory::Benchmark);
    let json = serde_json::to_string(&config).unwrap();
    let back: PlannerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

// ---------------------------------------------------------------------------
// Cross-module integration: canonical IDs drive dedup
// ---------------------------------------------------------------------------

#[test]
fn dedup_works_across_categories() {
    let config = PlannerConfig::new(epoch());
    let pipeline = CompressionPipeline::new(config);
    // Same canonical ID but different categories: dedup still fires
    let d1 = desc_canonical("cache-1", ArtifactCategory::Cache, 4096, b"same-id");
    let d2 = desc_canonical("aot-1", ArtifactCategory::Aot, 4096, b"same-id");
    let report = pipeline.run(&[d1, d2]);

    assert_eq!(report.dedup_tracker.duplicates_resolved, 1);
}

#[test]
fn dedup_does_not_cross_when_excluded() {
    let config = PlannerConfig::new(epoch());
    let pipeline = CompressionPipeline::new(config);
    // Replay (excluded) with canonical ID shouldn't trigger dedup
    let d1 = desc_canonical("cache-1", ArtifactCategory::Cache, 4096, b"same-id");
    let d2 = desc_canonical("replay-1", ArtifactCategory::Replay, 4096, b"same-id");
    let report = pipeline.run(&[d1, d2]);

    // replay-1 is excluded before dedup check, so no dedup
    assert_eq!(report.dedup_tracker.duplicates_resolved, 0);
    assert_eq!(report.exclusion_count(), 1);
}

// ---------------------------------------------------------------------------
// Adversarial / edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn pipeline_zero_size_artifacts() {
    let config = PlannerConfig::new(epoch());
    let pipeline = CompressionPipeline::new(config);
    let report = pipeline.run(&[desc("zero", ArtifactCategory::Cache, 0)]);

    assert_eq!(report.total_input_bytes, 0);
    assert_eq!(report.total_output_bytes, 0);
    assert_eq!(report.restoration_recipes.len(), 1);
}

#[test]
fn pipeline_one_byte_artifact() {
    let config = PlannerConfig::new(epoch());
    let pipeline = CompressionPipeline::new(config);
    let report = pipeline.run(&[desc("tiny", ArtifactCategory::Cache, 1)]);

    assert_eq!(report.total_input_bytes, 1);
    // Compression may not save anything, but the pipeline should not crash
    assert_eq!(report.restoration_recipes.len(), 1);
}

#[test]
fn pipeline_max_boundary_size() {
    let config = PlannerConfig::new(epoch());
    let pipeline = CompressionPipeline::new(config);
    // Exactly at the boundary — should compress, not exclude
    let report = pipeline.run(&[desc(
        "boundary",
        ArtifactCategory::Cache,
        MAX_ARTIFACT_BYTES,
    )]);
    assert_eq!(report.restoration_recipes.len(), 1);
    assert_eq!(report.exclusion_count(), 0);
}

#[test]
fn pipeline_just_over_boundary_excluded() {
    let config = PlannerConfig::new(epoch());
    let pipeline = CompressionPipeline::new(config);
    let report = pipeline.run(&[desc(
        "over",
        ArtifactCategory::Cache,
        MAX_ARTIFACT_BYTES + 1,
    )]);
    assert_eq!(report.exclusion_count(), 1);
    assert!(report.restoration_recipes.is_empty());
}

#[test]
fn pipeline_many_duplicates() {
    let config = PlannerConfig::new(epoch());
    let pipeline = CompressionPipeline::new(config);
    let mut descs = Vec::new();
    for i in 0..20 {
        descs.push(desc_canonical(
            &format!("art-{i}"),
            ArtifactCategory::Cache,
            1024,
            b"all-same",
        ));
    }
    let report = pipeline.run(&descs);

    assert_eq!(report.dedup_tracker.duplicates_resolved, 19);
    assert_eq!(report.restoration_recipes.len(), 1); // only the first
}
