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
//! Integration tests for benchmark_coverage_saturation module.
//!
//! Bead: bd-1lsy.8.5.5 [RGC-705E]

use std::collections::BTreeSet;

use frankenengine_engine::benchmark_coverage_saturation::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn tags(ts: &[&str]) -> BTreeSet<String> {
    ts.iter().map(|s| (*s).to_string()).collect()
}

fn make_entry(
    name: &str,
    family: WorkloadFamily,
    complexity: u64,
    feature_tags: &[&str],
) -> BenchmarkEntry {
    BenchmarkEntry::new(name, family, complexity, tags(feature_tags))
}

/// Populate a board with entries across all 12 families (count entries each).
fn populate_board_all_families(board: &mut SaturationBoard, count: u64, tag_count: usize) {
    for family in WorkloadFamily::ALL {
        for i in 0..count {
            let name = format!("{}_{}", family.as_str(), i);
            let complexity = 100 + i * 50;
            let tag_names: Vec<String> = (0..tag_count)
                .map(|t| format!("tag_{}_{}", family.as_str(), t))
                .collect();
            let tag_refs: Vec<&str> = tag_names.iter().map(|s| s.as_str()).collect();
            let entry = make_entry(&name, *family, complexity, &tag_refs);
            board.add_entry(entry).unwrap();
        }
    }
}

// -------------------------------------------------------------------------
// 1. WorkloadFamily
// -------------------------------------------------------------------------

#[test]
fn workload_family_all_has_12_variants() {
    assert_eq!(WorkloadFamily::ALL.len(), 12);
    assert_eq!(WorkloadFamily::COUNT, 12);
}

#[test]
fn workload_family_as_str_branch_heavy() {
    assert_eq!(WorkloadFamily::BranchHeavy.as_str(), "branch_heavy");
}

#[test]
fn workload_family_as_str_vectorizable() {
    assert_eq!(WorkloadFamily::Vectorizable.as_str(), "vectorizable");
}

#[test]
fn workload_family_as_str_proof_specialized() {
    assert_eq!(
        WorkloadFamily::ProofSpecialized.as_str(),
        "proof_specialized"
    );
}

#[test]
fn workload_family_as_str_native_addon() {
    assert_eq!(WorkloadFamily::NativeAddon.as_str(), "native_addon");
}

#[test]
fn workload_family_as_str_hostcall_boundary() {
    assert_eq!(
        WorkloadFamily::HostcallBoundary.as_str(),
        "hostcall_boundary"
    );
}

#[test]
fn workload_family_as_str_startup_image() {
    assert_eq!(WorkloadFamily::StartupImage.as_str(), "startup_image");
}

#[test]
fn workload_family_as_str_metadata_locality() {
    assert_eq!(
        WorkloadFamily::MetadataLocality.as_str(),
        "metadata_locality"
    );
}

#[test]
fn workload_family_as_str_observability_sensitive() {
    assert_eq!(
        WorkloadFamily::ObservabilitySensitive.as_str(),
        "observability_sensitive"
    );
}

#[test]
fn workload_family_as_str_resource_bounded() {
    assert_eq!(WorkloadFamily::ResourceBounded.as_str(), "resource_bounded");
}

#[test]
fn workload_family_as_str_string_regexp() {
    assert_eq!(WorkloadFamily::StringRegexp.as_str(), "string_regexp");
}

#[test]
fn workload_family_as_str_react_lifecycle() {
    assert_eq!(WorkloadFamily::ReactLifecycle.as_str(), "react_lifecycle");
}

#[test]
fn workload_family_as_str_async_iterator() {
    assert_eq!(WorkloadFamily::AsyncIterator.as_str(), "async_iterator");
}

#[test]
fn workload_family_is_performance_critical_true_variants() {
    assert!(WorkloadFamily::BranchHeavy.is_performance_critical());
    assert!(WorkloadFamily::Vectorizable.is_performance_critical());
    assert!(WorkloadFamily::StartupImage.is_performance_critical());
    assert!(WorkloadFamily::MetadataLocality.is_performance_critical());
    assert!(WorkloadFamily::StringRegexp.is_performance_critical());
}

#[test]
fn workload_family_is_performance_critical_false_variants() {
    assert!(!WorkloadFamily::ProofSpecialized.is_performance_critical());
    assert!(!WorkloadFamily::NativeAddon.is_performance_critical());
    assert!(!WorkloadFamily::HostcallBoundary.is_performance_critical());
    assert!(!WorkloadFamily::ObservabilitySensitive.is_performance_critical());
    assert!(!WorkloadFamily::ResourceBounded.is_performance_critical());
    assert!(!WorkloadFamily::ReactLifecycle.is_performance_critical());
    assert!(!WorkloadFamily::AsyncIterator.is_performance_critical());
}

#[test]
fn workload_family_display_matches_as_str() {
    for family in WorkloadFamily::ALL {
        assert_eq!(format!("{family}"), family.as_str());
    }
}

#[test]
fn workload_family_serde_round_trip() {
    for family in WorkloadFamily::ALL {
        let json = serde_json::to_string(family).unwrap();
        let recovered: WorkloadFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*family, recovered);
    }
}

#[test]
fn workload_family_all_variants_unique() {
    let mut seen = BTreeSet::new();
    for family in WorkloadFamily::ALL {
        assert!(
            seen.insert(family.as_str()),
            "duplicate family: {}",
            family.as_str()
        );
    }
}

// -------------------------------------------------------------------------
// 2. CoverageStatus
// -------------------------------------------------------------------------

#[test]
fn coverage_status_all_has_4_variants() {
    assert_eq!(CoverageStatus::ALL.len(), 4);
}

#[test]
fn coverage_status_as_str() {
    assert_eq!(CoverageStatus::Uncovered.as_str(), "uncovered");
    assert_eq!(CoverageStatus::Sparse.as_str(), "sparse");
    assert_eq!(CoverageStatus::Adequate.as_str(), "adequate");
    assert_eq!(CoverageStatus::Saturated.as_str(), "saturated");
}

#[test]
fn coverage_status_is_acceptable() {
    assert!(!CoverageStatus::Uncovered.is_acceptable());
    assert!(!CoverageStatus::Sparse.is_acceptable());
    assert!(CoverageStatus::Adequate.is_acceptable());
    assert!(CoverageStatus::Saturated.is_acceptable());
}

#[test]
fn coverage_status_blocks_gate() {
    assert!(CoverageStatus::Uncovered.blocks_gate());
    assert!(CoverageStatus::Sparse.blocks_gate());
    assert!(!CoverageStatus::Adequate.blocks_gate());
    assert!(!CoverageStatus::Saturated.blocks_gate());
}

#[test]
fn coverage_status_is_acceptable_and_blocks_gate_complementary() {
    for status in CoverageStatus::ALL {
        assert_ne!(status.is_acceptable(), status.blocks_gate());
    }
}

#[test]
fn coverage_status_display_matches_as_str() {
    for status in CoverageStatus::ALL {
        assert_eq!(format!("{status}"), status.as_str());
    }
}

#[test]
fn coverage_status_serde_round_trip() {
    for status in CoverageStatus::ALL {
        let json = serde_json::to_string(status).unwrap();
        let recovered: CoverageStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*status, recovered);
    }
}

// -------------------------------------------------------------------------
// 3. RepresentativenessMetric
// -------------------------------------------------------------------------

#[test]
fn representativeness_metric_all_has_4_variants() {
    assert_eq!(RepresentativenessMetric::ALL.len(), 4);
}

#[test]
fn representativeness_metric_as_str() {
    assert_eq!(
        RepresentativenessMetric::CorpusRatio.as_str(),
        "corpus_ratio"
    );
    assert_eq!(
        RepresentativenessMetric::FeatureEntropy.as_str(),
        "feature_entropy"
    );
    assert_eq!(
        RepresentativenessMetric::DomainJaccardSimilarity.as_str(),
        "domain_jaccard_similarity"
    );
    assert_eq!(
        RepresentativenessMetric::ComplexityHistogramKl.as_str(),
        "complexity_histogram_kl"
    );
}

#[test]
fn representativeness_metric_display_matches_as_str() {
    for metric in RepresentativenessMetric::ALL {
        assert_eq!(format!("{metric}"), metric.as_str());
    }
}

#[test]
fn representativeness_metric_serde_round_trip() {
    for metric in RepresentativenessMetric::ALL {
        let json = serde_json::to_string(metric).unwrap();
        let recovered: RepresentativenessMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(*metric, recovered);
    }
}

// -------------------------------------------------------------------------
// 4. SaturationVerdict
// -------------------------------------------------------------------------

#[test]
fn saturation_verdict_all_has_5_variants() {
    assert_eq!(SaturationVerdict::ALL.len(), 5);
}

#[test]
fn saturation_verdict_as_str() {
    assert_eq!(SaturationVerdict::Saturated.as_str(), "saturated");
    assert_eq!(SaturationVerdict::Adequate.as_str(), "adequate");
    assert_eq!(SaturationVerdict::Sparse.as_str(), "sparse");
    assert_eq!(SaturationVerdict::Insufficient.as_str(), "insufficient");
    assert_eq!(
        SaturationVerdict::ConfigViolation.as_str(),
        "config_violation"
    );
}

#[test]
fn saturation_verdict_allows_publication() {
    assert!(SaturationVerdict::Saturated.allows_publication());
    assert!(SaturationVerdict::Adequate.allows_publication());
    assert!(!SaturationVerdict::Sparse.allows_publication());
    assert!(!SaturationVerdict::Insufficient.allows_publication());
    assert!(!SaturationVerdict::ConfigViolation.allows_publication());
}

#[test]
fn saturation_verdict_blocks_gate() {
    assert!(!SaturationVerdict::Saturated.blocks_gate());
    assert!(!SaturationVerdict::Adequate.blocks_gate());
    assert!(SaturationVerdict::Sparse.blocks_gate());
    assert!(SaturationVerdict::Insufficient.blocks_gate());
    assert!(SaturationVerdict::ConfigViolation.blocks_gate());
}

#[test]
fn saturation_verdict_allows_and_blocks_complementary() {
    for verdict in SaturationVerdict::ALL {
        assert_ne!(verdict.allows_publication(), verdict.blocks_gate());
    }
}

#[test]
fn saturation_verdict_display_matches_as_str() {
    for verdict in SaturationVerdict::ALL {
        assert_eq!(format!("{verdict}"), verdict.as_str());
    }
}

#[test]
fn saturation_verdict_serde_round_trip() {
    for verdict in SaturationVerdict::ALL {
        let json = serde_json::to_string(verdict).unwrap();
        let recovered: SaturationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*verdict, recovered);
    }
}

// -------------------------------------------------------------------------
// 5. BoardError
// -------------------------------------------------------------------------

#[test]
fn board_error_too_many_entries_tag() {
    let err = BoardError::TooManyEntries {
        count: 5000,
        max: 4096,
    };
    assert_eq!(err.tag(), "too_many_entries");
}

#[test]
fn board_error_too_many_feature_tags_tag() {
    let err = BoardError::TooManyFeatureTags {
        name: "test".to_string(),
        count: 100,
        max: 64,
    };
    assert_eq!(err.tag(), "too_many_feature_tags");
}

#[test]
fn board_error_duplicate_entry_name_tag() {
    let err = BoardError::DuplicateEntryName {
        name: "bench_a".to_string(),
    };
    assert_eq!(err.tag(), "duplicate_entry_name");
}

#[test]
fn board_error_integrity_failure_tag() {
    let err = BoardError::IntegrityFailure {
        name: "bench_b".to_string(),
    };
    assert_eq!(err.tag(), "integrity_failure");
}

#[test]
fn board_error_display_too_many_entries() {
    let err = BoardError::TooManyEntries {
        count: 5000,
        max: 4096,
    };
    let msg = format!("{err}");
    assert!(msg.contains("5000"));
    assert!(msg.contains("4096"));
}

#[test]
fn board_error_display_too_many_feature_tags() {
    let err = BoardError::TooManyFeatureTags {
        name: "bench_x".to_string(),
        count: 70,
        max: 64,
    };
    let msg = format!("{err}");
    assert!(msg.contains("bench_x"));
    assert!(msg.contains("70"));
}

#[test]
fn board_error_display_duplicate_entry_name() {
    let err = BoardError::DuplicateEntryName {
        name: "dup".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("dup"));
}

#[test]
fn board_error_display_integrity_failure() {
    let err = BoardError::IntegrityFailure {
        name: "corrupt".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("corrupt"));
}

#[test]
fn board_error_serde_round_trip() {
    let errors = vec![
        BoardError::TooManyEntries { count: 10, max: 5 },
        BoardError::TooManyFeatureTags {
            name: "x".to_string(),
            count: 100,
            max: 64,
        },
        BoardError::DuplicateEntryName {
            name: "y".to_string(),
        },
        BoardError::IntegrityFailure {
            name: "z".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let recovered: BoardError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, recovered);
    }
}

// -------------------------------------------------------------------------
// 6. BenchmarkEntry
// -------------------------------------------------------------------------

#[test]
fn benchmark_entry_new_sets_name() {
    let entry = make_entry("my_bench", WorkloadFamily::BranchHeavy, 42, &["default"]);
    assert_eq!(entry.name, "my_bench");
}

#[test]
fn benchmark_entry_new_sets_family() {
    let entry = make_entry("b", WorkloadFamily::Vectorizable, 100, &["default"]);
    assert_eq!(entry.family, WorkloadFamily::Vectorizable);
}

#[test]
fn benchmark_entry_new_sets_complexity() {
    let entry = make_entry("b", WorkloadFamily::NativeAddon, 999, &["default"]);
    assert_eq!(entry.complexity_score, 999);
}

#[test]
fn benchmark_entry_new_sets_feature_tags() {
    let entry = make_entry("b", WorkloadFamily::AsyncIterator, 10, &["a", "b", "c"]);
    assert_eq!(entry.feature_tags.len(), 3);
    assert!(entry.feature_tags.contains("a"));
    assert!(entry.feature_tags.contains("b"));
    assert!(entry.feature_tags.contains("c"));
}

#[test]
fn benchmark_entry_verify_hash_succeeds_after_new() {
    let entry = make_entry("check", WorkloadFamily::ReactLifecycle, 500, &["tag"]);
    assert!(entry.verify_hash());
}

#[test]
fn benchmark_entry_verify_hash_fails_after_tampering() {
    let mut entry = make_entry("tamper", WorkloadFamily::ResourceBounded, 100, &["tag"]);
    entry.complexity_score = 9999;
    assert!(!entry.verify_hash());
}

#[test]
fn benchmark_entry_hash_determinism() {
    let e1 = make_entry("det", WorkloadFamily::StringRegexp, 77, &["tag"]);
    let e2 = make_entry("det", WorkloadFamily::StringRegexp, 77, &["tag"]);
    assert_eq!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn benchmark_entry_hash_varies_with_name() {
    let e1 = make_entry("name_a", WorkloadFamily::BranchHeavy, 10, &["tag"]);
    let e2 = make_entry("name_b", WorkloadFamily::BranchHeavy, 10, &["tag"]);
    assert_ne!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn benchmark_entry_hash_varies_with_family() {
    let e1 = make_entry("same", WorkloadFamily::BranchHeavy, 10, &["tag"]);
    let e2 = make_entry("same", WorkloadFamily::Vectorizable, 10, &["tag"]);
    assert_ne!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn benchmark_entry_hash_varies_with_complexity() {
    let e1 = make_entry("same", WorkloadFamily::BranchHeavy, 10, &["tag"]);
    let e2 = make_entry("same", WorkloadFamily::BranchHeavy, 20, &["tag"]);
    assert_ne!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn benchmark_entry_hash_varies_with_tags() {
    let e1 = make_entry("same", WorkloadFamily::BranchHeavy, 10, &["a"]);
    let e2 = make_entry("same", WorkloadFamily::BranchHeavy, 10, &["b"]);
    assert_ne!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn benchmark_entry_display_contains_name_and_family() {
    let entry = make_entry(
        "display_test",
        WorkloadFamily::HostcallBoundary,
        42,
        &["tag"],
    );
    let display = format!("{entry}");
    assert!(display.contains("display_test"));
    assert!(display.contains("hostcall_boundary"));
}

#[test]
fn benchmark_entry_serde_round_trip() {
    let entry = make_entry("serde_test", WorkloadFamily::StartupImage, 123, &["x", "y"]);
    let json = serde_json::to_string(&entry).unwrap();
    let recovered: BenchmarkEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, recovered);
    assert!(recovered.verify_hash());
}

// -------------------------------------------------------------------------
// 7. FamilyCoverage
// -------------------------------------------------------------------------

#[test]
fn family_coverage_compute_empty_entries() {
    let config = SaturationConfig::default_config();
    let coverage = FamilyCoverage::compute(WorkloadFamily::BranchHeavy, &[], &config);
    assert_eq!(coverage.entry_count, 0);
    assert_eq!(coverage.coverage_status, CoverageStatus::Uncovered);
    assert_eq!(coverage.saturation_score_millionths, 0);
    assert_eq!(coverage.feature_diversity, 0);
}

#[test]
fn family_coverage_compute_one_entry_sparse() {
    let config = SaturationConfig::default_config();
    let entry = make_entry("one", WorkloadFamily::Vectorizable, 50, &["tag"]);
    let coverage = FamilyCoverage::compute(WorkloadFamily::Vectorizable, &[&entry], &config);
    assert_eq!(coverage.entry_count, 1);
    assert_eq!(coverage.coverage_status, CoverageStatus::Sparse);
}

#[test]
fn family_coverage_compute_adequate_entries() {
    let config = SaturationConfig::default_config();
    let e1 = make_entry("a", WorkloadFamily::BranchHeavy, 10, &["t1"]);
    let e2 = make_entry("b", WorkloadFamily::BranchHeavy, 20, &["t2"]);
    let e3 = make_entry("c", WorkloadFamily::BranchHeavy, 30, &["t1"]);
    let refs: Vec<&BenchmarkEntry> = vec![&e1, &e2, &e3];
    let coverage = FamilyCoverage::compute(WorkloadFamily::BranchHeavy, &refs, &config);
    assert_eq!(coverage.entry_count, 3);
    assert!(coverage.coverage_status.is_acceptable());
}

#[test]
fn family_coverage_compute_complexity_stats() {
    let config = SaturationConfig::relaxed();
    let e1 = make_entry("x1", WorkloadFamily::NativeAddon, 100, &["tag"]);
    let e2 = make_entry("x2", WorkloadFamily::NativeAddon, 300, &["tag"]);
    let coverage = FamilyCoverage::compute(WorkloadFamily::NativeAddon, &[&e1, &e2], &config);
    assert_eq!(coverage.min_complexity, 100);
    assert_eq!(coverage.max_complexity, 300);
    assert_eq!(coverage.total_complexity, 400);
    assert_eq!(coverage.mean_complexity_millionths, 200_000_000);
}

#[test]
fn family_coverage_compute_feature_diversity() {
    let config = SaturationConfig::relaxed();
    let e1 = make_entry("f1", WorkloadFamily::BranchHeavy, 10, &["alpha", "beta"]);
    let e2 = make_entry("f2", WorkloadFamily::BranchHeavy, 20, &["beta", "gamma"]);
    let coverage = FamilyCoverage::compute(WorkloadFamily::BranchHeavy, &[&e1, &e2], &config);
    assert_eq!(coverage.feature_diversity, 3);
}

#[test]
fn family_coverage_display_contains_family_name() {
    let config = SaturationConfig::relaxed();
    let e1 = make_entry("d1", WorkloadFamily::AsyncIterator, 10, &["tag"]);
    let coverage = FamilyCoverage::compute(WorkloadFamily::AsyncIterator, &[&e1], &config);
    let display = format!("{coverage}");
    assert!(display.contains("async_iterator"));
}

#[test]
fn family_coverage_saturated_when_score_exceeds_threshold() {
    let mut config = SaturationConfig::relaxed();
    config.min_entries_per_family = 1;
    config.min_feature_diversity = 1;
    config.min_saturation_score_millionths = 100_000;

    let e1 = make_entry("sat1", WorkloadFamily::BranchHeavy, 100, &["a", "b"]);
    let e2 = make_entry("sat2", WorkloadFamily::BranchHeavy, 500, &["c", "d"]);
    let coverage = FamilyCoverage::compute(WorkloadFamily::BranchHeavy, &[&e1, &e2], &config);
    assert_eq!(coverage.coverage_status, CoverageStatus::Saturated);
}

// -------------------------------------------------------------------------
// 8. SaturationConfig
// -------------------------------------------------------------------------

#[test]
fn saturation_config_default_config_values() {
    let config = SaturationConfig::default_config();
    assert_eq!(
        config.min_entries_per_family,
        DEFAULT_MIN_ENTRIES_PER_FAMILY
    );
    assert_eq!(config.min_families_covered, DEFAULT_MIN_FAMILIES_COVERED);
    assert_eq!(
        config.min_saturation_score_millionths,
        DEFAULT_MIN_SATURATION_SCORE_MILLIONTHS
    );
    assert_eq!(config.min_feature_diversity, DEFAULT_MIN_FEATURE_DIVERSITY);
    assert_eq!(config.target_families.len(), 12);
}

#[test]
fn saturation_config_strict_higher_thresholds() {
    let strict = SaturationConfig::strict();
    let default = SaturationConfig::default_config();
    assert!(strict.min_entries_per_family > default.min_entries_per_family);
    assert!(strict.min_saturation_score_millionths > default.min_saturation_score_millionths);
    assert!(strict.min_feature_diversity > default.min_feature_diversity);
    assert_eq!(strict.min_families_covered, WorkloadFamily::COUNT as u64);
}

#[test]
fn saturation_config_relaxed_lower_thresholds() {
    let relaxed = SaturationConfig::relaxed();
    let default = SaturationConfig::default_config();
    assert!(relaxed.min_entries_per_family < default.min_entries_per_family);
    assert!(relaxed.min_families_covered < default.min_families_covered);
    assert!(relaxed.min_saturation_score_millionths < default.min_saturation_score_millionths);
}

#[test]
fn saturation_config_effective_targets_when_nonempty() {
    let config = SaturationConfig::default_config();
    let targets = config.effective_targets();
    assert_eq!(targets.len(), 12);
}

#[test]
fn saturation_config_effective_targets_when_empty_returns_all() {
    let config = SaturationConfig::relaxed();
    assert!(config.target_families.is_empty());
    let targets = config.effective_targets();
    assert_eq!(targets.len(), 12);
}

#[test]
fn saturation_config_default_trait_matches_default_config() {
    let from_trait: SaturationConfig = Default::default();
    let from_method = SaturationConfig::default_config();
    assert_eq!(from_trait, from_method);
}

#[test]
fn saturation_config_serde_round_trip() {
    let config = SaturationConfig::strict();
    let json = serde_json::to_string(&config).unwrap();
    let recovered: SaturationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, recovered);
}

// -------------------------------------------------------------------------
// 9. SaturationBoard
// -------------------------------------------------------------------------

#[test]
fn saturation_board_new_is_empty() {
    let board = SaturationBoard::new();
    assert!(board.is_empty());
    assert_eq!(board.entry_count(), 0);
}

#[test]
fn saturation_board_default_is_empty() {
    let board = SaturationBoard::default();
    assert!(board.is_empty());
}

#[test]
fn saturation_board_add_entry_increments_count() {
    let mut board = SaturationBoard::new();
    let entry = make_entry("b1", WorkloadFamily::BranchHeavy, 50, &["tag"]);
    board.add_entry(entry).unwrap();
    assert_eq!(board.entry_count(), 1);
    assert!(!board.is_empty());
}

#[test]
fn saturation_board_add_multiple_entries() {
    let mut board = SaturationBoard::new();
    for i in 0..10 {
        let entry = make_entry(
            &format!("e_{i}"),
            WorkloadFamily::Vectorizable,
            i * 10,
            &["tag"],
        );
        board.add_entry(entry).unwrap();
    }
    assert_eq!(board.entry_count(), 10);
}

#[test]
fn saturation_board_add_entry_duplicate_name_error() {
    let mut board = SaturationBoard::new();
    let e1 = make_entry("dup", WorkloadFamily::BranchHeavy, 10, &["tag"]);
    let e2 = make_entry("dup", WorkloadFamily::Vectorizable, 20, &["tag"]);
    board.add_entry(e1).unwrap();
    let err = board.add_entry(e2).unwrap_err();
    assert_eq!(err.tag(), "duplicate_entry_name");
}

#[test]
fn saturation_board_add_entry_too_many_feature_tags_error() {
    let mut board = SaturationBoard::new();
    let mut tag_set = BTreeSet::new();
    for i in 0..=MAX_FEATURE_TAGS_PER_ENTRY {
        tag_set.insert(format!("tag_{i}"));
    }
    let entry = BenchmarkEntry::new("over_tagged", WorkloadFamily::BranchHeavy, 10, tag_set);
    let err = board.add_entry(entry).unwrap_err();
    assert_eq!(err.tag(), "too_many_feature_tags");
}

#[test]
fn saturation_board_add_entry_integrity_failure() {
    let mut board = SaturationBoard::new();
    let mut entry = make_entry("corrupt", WorkloadFamily::BranchHeavy, 10, &["tag"]);
    entry.name = "tampered".to_string();
    let err = board.add_entry(entry).unwrap_err();
    assert_eq!(err.tag(), "integrity_failure");
}

#[test]
fn saturation_board_entries_for_family_filters_correctly() {
    let mut board = SaturationBoard::new();
    board
        .add_entry(make_entry("a", WorkloadFamily::BranchHeavy, 10, &["tag"]))
        .unwrap();
    board
        .add_entry(make_entry("b", WorkloadFamily::Vectorizable, 20, &["tag"]))
        .unwrap();
    board
        .add_entry(make_entry("c", WorkloadFamily::BranchHeavy, 30, &["tag"]))
        .unwrap();

    let branch_entries = board.entries_for_family(WorkloadFamily::BranchHeavy);
    assert_eq!(branch_entries.len(), 2);

    let vec_entries = board.entries_for_family(WorkloadFamily::Vectorizable);
    assert_eq!(vec_entries.len(), 1);

    let addon_entries = board.entries_for_family(WorkloadFamily::NativeAddon);
    assert_eq!(addon_entries.len(), 0);
}

#[test]
fn saturation_board_compute_family_coverages_covers_all_targets() {
    let mut board = SaturationBoard::new();
    board
        .add_entry(make_entry("x", WorkloadFamily::BranchHeavy, 10, &["tag"]))
        .unwrap();
    let config = SaturationConfig::default_config();
    let coverages = board.compute_family_coverages(&config);
    assert_eq!(coverages.len(), 12);
    assert_eq!(coverages[&WorkloadFamily::BranchHeavy].entry_count, 1);
    assert_eq!(coverages[&WorkloadFamily::Vectorizable].entry_count, 0);
}

#[test]
fn saturation_board_evaluate_empty_board_config_violation() {
    let board = SaturationBoard::new();
    let config = SaturationConfig::default_config();
    let report = board.evaluate(&config);
    assert_eq!(report.verdict, SaturationVerdict::ConfigViolation);
    assert!(!report.passes_gate());
}

#[test]
fn saturation_board_evaluate_insufficient_families() {
    let mut board = SaturationBoard::new();
    for i in 0..5 {
        board
            .add_entry(make_entry(
                &format!("bh_{i}"),
                WorkloadFamily::BranchHeavy,
                i * 100,
                &["tag_a", "tag_b"],
            ))
            .unwrap();
    }
    let config = SaturationConfig::default_config();
    let report = board.evaluate(&config);
    assert_eq!(report.verdict, SaturationVerdict::Insufficient);
    assert!(!report.passes_gate());
}

#[test]
fn saturation_board_evaluate_sparse_families() {
    let mut board = SaturationBoard::new();
    let mut config = SaturationConfig::relaxed();
    config.min_families_covered = 2;
    config.min_entries_per_family = 3;
    board
        .add_entry(make_entry("a1", WorkloadFamily::BranchHeavy, 10, &["tag"]))
        .unwrap();
    board
        .add_entry(make_entry("b1", WorkloadFamily::Vectorizable, 20, &["tag"]))
        .unwrap();
    let report = board.evaluate(&config);
    assert_eq!(report.verdict, SaturationVerdict::Sparse);
}

#[test]
fn saturation_board_evaluate_report_metadata() {
    let board = SaturationBoard::new();
    let config = SaturationConfig::default_config();
    let report = board.evaluate(&config);
    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.policy_id, POLICY_ID);
    assert_eq!(report.component, COMPONENT);
    assert_eq!(report.epoch, epoch(1));
}

#[test]
fn saturation_board_evaluate_representativeness_scores_present() {
    let mut board = SaturationBoard::new();
    board
        .add_entry(make_entry("r1", WorkloadFamily::BranchHeavy, 50, &["tag"]))
        .unwrap();
    let config = SaturationConfig::default_config();
    let report = board.evaluate(&config);
    assert_eq!(report.representativeness_scores.len(), 4);
    let metrics: BTreeSet<_> = report
        .representativeness_scores
        .iter()
        .map(|s| s.metric)
        .collect();
    assert!(metrics.contains(&RepresentativenessMetric::CorpusRatio));
    assert!(metrics.contains(&RepresentativenessMetric::FeatureEntropy));
    assert!(metrics.contains(&RepresentativenessMetric::DomainJaccardSimilarity));
    assert!(metrics.contains(&RepresentativenessMetric::ComplexityHistogramKl));
}

#[test]
fn saturation_board_serde_round_trip() {
    let mut board = SaturationBoard::new();
    board
        .add_entry(make_entry("s1", WorkloadFamily::BranchHeavy, 10, &["tag"]))
        .unwrap();
    board
        .add_entry(make_entry("s2", WorkloadFamily::Vectorizable, 20, &["tag"]))
        .unwrap();
    let json = serde_json::to_string(&board).unwrap();
    let recovered: SaturationBoard = serde_json::from_str(&json).unwrap();
    assert_eq!(board, recovered);
}

// -------------------------------------------------------------------------
// 10. SaturationGate
// -------------------------------------------------------------------------

#[test]
fn saturation_gate_new_sets_gate_id() {
    let gate = SaturationGate::new("test-gate", SaturationConfig::relaxed());
    assert_eq!(gate.gate_id, "test-gate");
}

#[test]
fn saturation_gate_evaluate_returns_report() {
    let gate = SaturationGate::new("g1", SaturationConfig::relaxed());
    let board = SaturationBoard::new();
    let report = gate.evaluate(&board);
    assert_eq!(report.verdict, SaturationVerdict::ConfigViolation);
}

#[test]
fn saturation_gate_evaluate_with_receipt_returns_both() {
    let gate = SaturationGate::new("g2", SaturationConfig::relaxed());
    let mut board = SaturationBoard::new();
    board
        .add_entry(make_entry("rr1", WorkloadFamily::BranchHeavy, 10, &["tag"]))
        .unwrap();
    let prev_hash = ContentHash::compute(b"genesis");
    let (report, receipt) = gate.evaluate_with_receipt(&board, prev_hash.clone());
    assert_eq!(receipt.report_hash, report.content_hash);
    assert_eq!(receipt.previous_receipt_hash, prev_hash);
    assert_eq!(receipt.verdict, report.verdict);
    assert!(receipt.verify());
}

#[test]
fn saturation_gate_passes_empty_board_false() {
    let gate = SaturationGate::new("g3", SaturationConfig::relaxed());
    let board = SaturationBoard::new();
    assert!(!gate.passes(&board));
}

#[test]
fn saturation_gate_passes_with_saturated_board() {
    let mut config = SaturationConfig::relaxed();
    config.min_families_covered = 4;
    config.min_entries_per_family = 1;
    config.min_saturation_score_millionths = 100_000;
    config.min_feature_diversity = 1;
    let gate = SaturationGate::new("g4", config);

    let mut board = SaturationBoard::new();
    populate_board_all_families(&mut board, 3, 3);
    assert!(gate.passes(&board));
}

#[test]
fn saturation_gate_display_contains_gate_id() {
    let gate = SaturationGate::new("display-gate", SaturationConfig::default_config());
    let display = format!("{gate}");
    assert!(display.contains("display-gate"));
}

#[test]
fn saturation_gate_serde_round_trip() {
    let gate = SaturationGate::new("serde-gate", SaturationConfig::strict());
    let json = serde_json::to_string(&gate).unwrap();
    let recovered: SaturationGate = serde_json::from_str(&json).unwrap();
    assert_eq!(gate, recovered);
}

// -------------------------------------------------------------------------
// 11. DecisionReceipt
// -------------------------------------------------------------------------

#[test]
fn decision_receipt_new_verify_succeeds() {
    let mut board = SaturationBoard::new();
    board
        .add_entry(make_entry("dr1", WorkloadFamily::BranchHeavy, 10, &["tag"]))
        .unwrap();
    let config = SaturationConfig::default_config();
    let report = board.evaluate(&config);
    let prev_hash = ContentHash::compute(b"prev");
    let receipt = DecisionReceipt::new("receipt-1", &report, prev_hash.clone());
    assert!(receipt.verify());
    assert_eq!(receipt.receipt_id, "receipt-1");
    assert_eq!(receipt.report_hash, report.content_hash);
    assert_eq!(receipt.previous_receipt_hash, prev_hash);
    assert_eq!(receipt.verdict, report.verdict);
    assert_eq!(receipt.epoch, report.epoch);
}

#[test]
fn decision_receipt_verify_fails_after_tampering() {
    let mut board = SaturationBoard::new();
    board
        .add_entry(make_entry(
            "dr2",
            WorkloadFamily::Vectorizable,
            20,
            &["tag"],
        ))
        .unwrap();
    let config = SaturationConfig::default_config();
    let report = board.evaluate(&config);
    let prev_hash = ContentHash::compute(b"genesis");
    let mut receipt = DecisionReceipt::new("receipt-2", &report, prev_hash);
    receipt.receipt_id = "tampered-id".to_string();
    assert!(!receipt.verify());
}

#[test]
fn decision_receipt_chain_two_receipts() {
    let mut board = SaturationBoard::new();
    board
        .add_entry(make_entry(
            "chain1",
            WorkloadFamily::BranchHeavy,
            10,
            &["tag"],
        ))
        .unwrap();
    let config = SaturationConfig::default_config();
    let report1 = board.evaluate(&config);
    let genesis = ContentHash::compute(b"genesis");
    let receipt1 = DecisionReceipt::new("r1", &report1, genesis);

    board
        .add_entry(make_entry(
            "chain2",
            WorkloadFamily::Vectorizable,
            20,
            &["tag"],
        ))
        .unwrap();
    let report2 = board.evaluate(&config);
    let receipt2 = DecisionReceipt::new("r2", &report2, receipt1.receipt_hash.clone());

    assert!(receipt1.verify());
    assert!(receipt2.verify());
    assert_eq!(receipt2.previous_receipt_hash, receipt1.receipt_hash);
}

#[test]
fn decision_receipt_serde_round_trip() {
    let board = SaturationBoard::new();
    let config = SaturationConfig::default_config();
    let report = board.evaluate(&config);
    let receipt = DecisionReceipt::new("serde-r", &report, ContentHash::compute(b"g"));
    let json = serde_json::to_string(&receipt).unwrap();
    let recovered: DecisionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, recovered);
    assert!(recovered.verify());
}

// -------------------------------------------------------------------------
// 12. RepresentativenessScore
// -------------------------------------------------------------------------

#[test]
fn representativeness_score_new_sets_fields() {
    let score = RepresentativenessScore::new(
        RepresentativenessMetric::CorpusRatio,
        750_000,
        "9/12 families",
    );
    assert_eq!(score.metric, RepresentativenessMetric::CorpusRatio);
    assert_eq!(score.score_millionths, 750_000);
    assert_eq!(score.detail, "9/12 families");
}

#[test]
fn representativeness_score_display_contains_metric_and_score() {
    let score =
        RepresentativenessScore::new(RepresentativenessMetric::FeatureEntropy, 500_000, "detail");
    let display = format!("{score}");
    assert!(display.contains("feature_entropy"));
    assert!(display.contains("500000"));
}

#[test]
fn representativeness_score_serde_round_trip() {
    let score = RepresentativenessScore::new(
        RepresentativenessMetric::DomainJaccardSimilarity,
        123_456,
        "intersection test",
    );
    let json = serde_json::to_string(&score).unwrap();
    let recovered: RepresentativenessScore = serde_json::from_str(&json).unwrap();
    assert_eq!(score, recovered);
}

// -------------------------------------------------------------------------
// 13. SaturationReport
// -------------------------------------------------------------------------

#[test]
fn saturation_report_passes_gate_for_adequate_verdict() {
    let mut board = SaturationBoard::new();
    let mut config = SaturationConfig::relaxed();
    config.min_families_covered = 1;
    config.min_entries_per_family = 1;
    config.min_saturation_score_millionths = 999_999;
    board
        .add_entry(make_entry("rp1", WorkloadFamily::BranchHeavy, 10, &["tag"]))
        .unwrap();
    let report = board.evaluate(&config);
    if report.verdict == SaturationVerdict::Adequate {
        assert!(report.passes_gate());
    }
}

#[test]
fn saturation_report_does_not_pass_gate_for_sparse() {
    let mut board = SaturationBoard::new();
    let mut config = SaturationConfig::relaxed();
    config.min_families_covered = 1;
    config.min_entries_per_family = 5;
    board
        .add_entry(make_entry("sp1", WorkloadFamily::BranchHeavy, 10, &["tag"]))
        .unwrap();
    let report = board.evaluate(&config);
    assert_eq!(report.verdict, SaturationVerdict::Sparse);
    assert!(!report.passes_gate());
}

#[test]
fn saturation_report_blocking_family_count_zero_when_all_covered() {
    let mut board = SaturationBoard::new();
    let mut config = SaturationConfig::relaxed();
    config.min_families_covered = 1;
    config.min_entries_per_family = 1;
    populate_board_all_families(&mut board, 3, 3);
    let report = board.evaluate(&config);
    assert_eq!(report.blocking_family_count(), 0);
}

#[test]
fn saturation_report_blocking_family_count_nonzero_when_sparse() {
    let mut board = SaturationBoard::new();
    let config = SaturationConfig::default_config();
    board
        .add_entry(make_entry("bf1", WorkloadFamily::BranchHeavy, 10, &["tag"]))
        .unwrap();
    let report = board.evaluate(&config);
    assert!(report.blocking_family_count() > 0);
}

#[test]
fn saturation_report_display_contains_verdict() {
    let board = SaturationBoard::new();
    let config = SaturationConfig::default_config();
    let report = board.evaluate(&config);
    let display = format!("{report}");
    assert!(display.contains("config_violation"));
}

#[test]
fn saturation_report_uncovered_families_populated() {
    let mut board = SaturationBoard::new();
    let config = SaturationConfig::default_config();
    board
        .add_entry(make_entry("uf1", WorkloadFamily::BranchHeavy, 10, &["tag"]))
        .unwrap();
    let report = board.evaluate(&config);
    assert_eq!(report.uncovered_families.len(), 11);
    assert!(
        !report
            .uncovered_families
            .contains(&WorkloadFamily::BranchHeavy)
    );
}

#[test]
fn saturation_report_serde_round_trip() {
    let mut board = SaturationBoard::new();
    board
        .add_entry(make_entry("sr1", WorkloadFamily::BranchHeavy, 10, &["tag"]))
        .unwrap();
    let config = SaturationConfig::default_config();
    let report = board.evaluate(&config);
    let json = serde_json::to_string(&report).unwrap();
    let recovered: SaturationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, recovered);
}

// -------------------------------------------------------------------------
// 14. End-to-end
// -------------------------------------------------------------------------

#[test]
fn e2e_fully_saturated_board() {
    let mut board = SaturationBoard::new();
    let mut config = SaturationConfig::relaxed();
    config.min_families_covered = 12;
    config.min_entries_per_family = 2;
    config.min_feature_diversity = 2;
    config.min_saturation_score_millionths = 300_000;

    populate_board_all_families(&mut board, 3, 3);

    let gate = SaturationGate::new("e2e-saturated", config);
    let report = gate.evaluate(&board);
    assert!(
        report.passes_gate(),
        "verdict: {}, blocking: {}",
        report.verdict,
        report.blocking_family_count()
    );
    assert_eq!(report.total_entries, 36);
    assert_eq!(report.covered_families, 12);
    assert_eq!(report.uncovered_families.len(), 0);
}

#[test]
fn e2e_sparse_board_fails_gate() {
    let mut board = SaturationBoard::new();
    let config = SaturationConfig::strict();

    board
        .add_entry(make_entry(
            "sp1",
            WorkloadFamily::BranchHeavy,
            100,
            &["tag"],
        ))
        .unwrap();
    board
        .add_entry(make_entry(
            "sp2",
            WorkloadFamily::Vectorizable,
            200,
            &["tag"],
        ))
        .unwrap();
    board
        .add_entry(make_entry(
            "sp3",
            WorkloadFamily::NativeAddon,
            300,
            &["tag"],
        ))
        .unwrap();

    let gate = SaturationGate::new("e2e-sparse", config);
    assert!(!gate.passes(&board));
    let report = gate.evaluate(&board);
    assert_eq!(report.verdict, SaturationVerdict::Insufficient);
}

#[test]
fn e2e_receipt_chain_across_multiple_evaluations() {
    let mut board = SaturationBoard::new();
    let mut config = SaturationConfig::relaxed();
    config.min_families_covered = 1;
    config.min_entries_per_family = 1;

    let gate = SaturationGate::new("chain-gate", config);
    let genesis = ContentHash::compute(b"genesis-hash");

    board
        .add_entry(make_entry("c1", WorkloadFamily::BranchHeavy, 10, &["tag"]))
        .unwrap();
    let (report1, receipt1) = gate.evaluate_with_receipt(&board, genesis);
    assert!(receipt1.verify());
    assert_eq!(receipt1.verdict, report1.verdict);

    board
        .add_entry(make_entry("c2", WorkloadFamily::Vectorizable, 20, &["tag"]))
        .unwrap();
    let (_report2, receipt2) = gate.evaluate_with_receipt(&board, receipt1.receipt_hash.clone());
    assert!(receipt2.verify());
    assert_eq!(receipt2.previous_receipt_hash, receipt1.receipt_hash);

    board
        .add_entry(make_entry("c3", WorkloadFamily::NativeAddon, 30, &["tag"]))
        .unwrap();
    let (_report3, receipt3) = gate.evaluate_with_receipt(&board, receipt2.receipt_hash.clone());
    assert!(receipt3.verify());
    assert_eq!(receipt3.previous_receipt_hash, receipt2.receipt_hash);
}

#[test]
fn e2e_progression_from_empty_to_saturated() {
    let mut config = SaturationConfig::relaxed();
    config.min_families_covered = 2;
    config.min_entries_per_family = 2;
    config.min_saturation_score_millionths = 200_000;
    config.min_feature_diversity = 1;

    let mut board = SaturationBoard::new();

    let r1 = board.evaluate(&config);
    assert_eq!(r1.verdict, SaturationVerdict::ConfigViolation);

    board
        .add_entry(make_entry(
            "prog1",
            WorkloadFamily::BranchHeavy,
            100,
            &["tag"],
        ))
        .unwrap();
    let r2 = board.evaluate(&config);
    assert_eq!(r2.verdict, SaturationVerdict::Insufficient);

    board
        .add_entry(make_entry(
            "prog2",
            WorkloadFamily::Vectorizable,
            200,
            &["tag"],
        ))
        .unwrap();
    let r3 = board.evaluate(&config);
    assert_eq!(r3.verdict, SaturationVerdict::Sparse);

    board
        .add_entry(make_entry(
            "prog3",
            WorkloadFamily::BranchHeavy,
            300,
            &["tag_extra"],
        ))
        .unwrap();
    board
        .add_entry(make_entry(
            "prog4",
            WorkloadFamily::Vectorizable,
            400,
            &["tag_extra"],
        ))
        .unwrap();
    let r4 = board.evaluate(&config);
    assert!(r4.verdict.allows_publication());
}

#[test]
fn e2e_report_content_hash_determinism() {
    let mut board = SaturationBoard::new();
    board
        .add_entry(make_entry(
            "det1",
            WorkloadFamily::BranchHeavy,
            10,
            &["tag"],
        ))
        .unwrap();
    let config = SaturationConfig::default_config();
    let report1 = board.evaluate(&config);
    let report2 = board.evaluate(&config);
    assert_eq!(report1.content_hash, report2.content_hash);
}

#[test]
fn e2e_corpus_ratio_score_full_coverage() {
    let mut board = SaturationBoard::new();
    let mut config = SaturationConfig::relaxed();
    config.min_families_covered = 1;
    config.min_entries_per_family = 1;
    populate_board_all_families(&mut board, 1, 1);
    let report = board.evaluate(&config);
    let corpus_score = report
        .representativeness_scores
        .iter()
        .find(|s| s.metric == RepresentativenessMetric::CorpusRatio)
        .unwrap();
    assert_eq!(corpus_score.score_millionths, 1_000_000);
}

#[test]
fn e2e_corpus_ratio_score_partial_coverage() {
    let mut board = SaturationBoard::new();
    let config = SaturationConfig::default_config();
    let families = &[
        WorkloadFamily::BranchHeavy,
        WorkloadFamily::Vectorizable,
        WorkloadFamily::NativeAddon,
        WorkloadFamily::StartupImage,
        WorkloadFamily::StringRegexp,
        WorkloadFamily::AsyncIterator,
    ];
    for (i, family) in families.iter().enumerate() {
        board
            .add_entry(make_entry(&format!("partial_{i}"), *family, 100, &["tag"]))
            .unwrap();
    }
    let report = board.evaluate(&config);
    let corpus_score = report
        .representativeness_scores
        .iter()
        .find(|s| s.metric == RepresentativenessMetric::CorpusRatio)
        .unwrap();
    assert_eq!(corpus_score.score_millionths, 500_000);
}

#[test]
fn e2e_jaccard_similarity_all_families_covered() {
    let mut board = SaturationBoard::new();
    let config = SaturationConfig::default_config();
    populate_board_all_families(&mut board, 1, 1);
    let report = board.evaluate(&config);
    let jaccard = report
        .representativeness_scores
        .iter()
        .find(|s| s.metric == RepresentativenessMetric::DomainJaccardSimilarity)
        .unwrap();
    assert_eq!(jaccard.score_millionths, 1_000_000);
}

#[test]
fn e2e_complexity_histogram_kl_uniform_complexity() {
    let mut board = SaturationBoard::new();
    let config = SaturationConfig::default_config();
    for (i, family) in WorkloadFamily::ALL.iter().enumerate() {
        board
            .add_entry(make_entry(&format!("unif_{i}"), *family, 100, &["tag"]))
            .unwrap();
    }
    let report = board.evaluate(&config);
    let kl = report
        .representativeness_scores
        .iter()
        .find(|s| s.metric == RepresentativenessMetric::ComplexityHistogramKl)
        .unwrap();
    assert_eq!(kl.score_millionths, 0);
}

#[test]
fn e2e_complexity_histogram_kl_varied_complexity() {
    let mut board = SaturationBoard::new();
    let config = SaturationConfig::default_config();
    for (i, family) in WorkloadFamily::ALL.iter().enumerate() {
        let complexity = (i as u64 + 1) * 100;
        board
            .add_entry(make_entry(
                &format!("var_{i}"),
                *family,
                complexity,
                &["tag"],
            ))
            .unwrap();
    }
    let report = board.evaluate(&config);
    let kl = report
        .representativeness_scores
        .iter()
        .find(|s| s.metric == RepresentativenessMetric::ComplexityHistogramKl)
        .unwrap();
    assert!(kl.score_millionths > 0);
}

#[test]
fn e2e_adequate_when_not_all_saturated() {
    let mut board = SaturationBoard::new();
    let mut config = SaturationConfig::relaxed();
    config.min_families_covered = 2;
    config.min_entries_per_family = 1;
    config.min_saturation_score_millionths = 999_999;

    board
        .add_entry(make_entry(
            "adeq1",
            WorkloadFamily::BranchHeavy,
            10,
            &["tag"],
        ))
        .unwrap();
    board
        .add_entry(make_entry(
            "adeq2",
            WorkloadFamily::Vectorizable,
            20,
            &["tag"],
        ))
        .unwrap();

    let report = board.evaluate(&config);
    assert_eq!(report.verdict, SaturationVerdict::Adequate);
    assert!(report.passes_gate());
}

// -------------------------------------------------------------------------
// 15. Edge cases
// -------------------------------------------------------------------------

#[test]
fn edge_case_zero_complexity_entries() {
    let mut board = SaturationBoard::new();
    let mut config = SaturationConfig::relaxed();
    config.min_families_covered = 1;
    config.min_entries_per_family = 1;
    board
        .add_entry(make_entry(
            "zero_comp",
            WorkloadFamily::BranchHeavy,
            0,
            &["tag"],
        ))
        .unwrap();
    let report = board.evaluate(&config);
    assert!(report.total_entries > 0);
}

#[test]
fn edge_case_very_high_complexity() {
    let entry = make_entry("high", WorkloadFamily::Vectorizable, u64::MAX / 2, &["tag"]);
    assert!(entry.verify_hash());
}

#[test]
fn edge_case_empty_feature_tags() {
    let entry = BenchmarkEntry::new("no_tags", WorkloadFamily::BranchHeavy, 10, BTreeSet::new());
    assert!(entry.verify_hash());
    assert_eq!(entry.feature_tags.len(), 0);
}

#[test]
fn edge_case_max_feature_tags_exactly() {
    let mut tag_set = BTreeSet::new();
    for i in 0..MAX_FEATURE_TAGS_PER_ENTRY {
        tag_set.insert(format!("tag_{i}"));
    }
    let entry = BenchmarkEntry::new("max_tags", WorkloadFamily::BranchHeavy, 10, tag_set);
    let mut board = SaturationBoard::new();
    board.add_entry(entry).unwrap();
    assert_eq!(board.entry_count(), 1);
}

#[test]
fn edge_case_single_entry_all_families_relaxed() {
    let mut board = SaturationBoard::new();
    let mut config = SaturationConfig::relaxed();
    config.min_families_covered = 12;
    config.min_entries_per_family = 1;
    config.min_saturation_score_millionths = 0;
    for (i, family) in WorkloadFamily::ALL.iter().enumerate() {
        board
            .add_entry(make_entry(&format!("single_{i}"), *family, 10, &["tag"]))
            .unwrap();
    }
    let report = board.evaluate(&config);
    assert_eq!(report.covered_families, 12);
    assert!(report.passes_gate());
}

#[test]
fn edge_case_board_with_identical_complexity_zero_spread() {
    let config = SaturationConfig::relaxed();
    let e1 = make_entry("eq1", WorkloadFamily::BranchHeavy, 50, &["tag"]);
    let e2 = make_entry("eq2", WorkloadFamily::BranchHeavy, 50, &["tag"]);
    let coverage = FamilyCoverage::compute(WorkloadFamily::BranchHeavy, &[&e1, &e2], &config);
    assert_eq!(coverage.min_complexity, 50);
    assert_eq!(coverage.max_complexity, 50);
}

#[test]
fn edge_case_custom_target_families_subset() {
    let mut config = SaturationConfig::default_config();
    let mut targets = BTreeSet::new();
    targets.insert(WorkloadFamily::BranchHeavy);
    targets.insert(WorkloadFamily::Vectorizable);
    config.target_families = targets;
    config.min_families_covered = 2;
    config.min_entries_per_family = 1;
    config.min_saturation_score_millionths = 0;

    let mut board = SaturationBoard::new();
    board
        .add_entry(make_entry(
            "custom1",
            WorkloadFamily::BranchHeavy,
            100,
            &["tag"],
        ))
        .unwrap();
    board
        .add_entry(make_entry(
            "custom2",
            WorkloadFamily::Vectorizable,
            200,
            &["tag"],
        ))
        .unwrap();

    let report = board.evaluate(&config);
    assert_eq!(report.family_coverages.len(), 2);
    assert!(report.passes_gate());
}

#[test]
fn edge_case_overall_saturation_is_mean_of_family_scores() {
    let mut board = SaturationBoard::new();
    let mut config = SaturationConfig::relaxed();
    let mut targets = BTreeSet::new();
    targets.insert(WorkloadFamily::BranchHeavy);
    targets.insert(WorkloadFamily::Vectorizable);
    config.target_families = targets;
    config.min_families_covered = 1;
    config.min_entries_per_family = 1;

    board
        .add_entry(make_entry(
            "mean1",
            WorkloadFamily::BranchHeavy,
            100,
            &["tag"],
        ))
        .unwrap();

    let report = board.evaluate(&config);
    let bh_score =
        report.family_coverages[&WorkloadFamily::BranchHeavy].saturation_score_millionths;
    let vec_score =
        report.family_coverages[&WorkloadFamily::Vectorizable].saturation_score_millionths;
    assert_eq!(vec_score, 0);
    assert_eq!(
        report.overall_saturation_millionths,
        (bh_score + vec_score) / 2
    );
}

#[test]
fn edge_case_entry_name_with_special_characters() {
    let entry = make_entry(
        "bench/test-case_v2.0",
        WorkloadFamily::BranchHeavy,
        10,
        &["tag"],
    );
    assert!(entry.verify_hash());
    let mut board = SaturationBoard::new();
    board.add_entry(entry).unwrap();
    assert_eq!(board.entry_count(), 1);
}

#[test]
fn edge_case_entry_name_empty_string() {
    let entry = make_entry("", WorkloadFamily::BranchHeavy, 10, &["tag"]);
    assert!(entry.verify_hash());
    let mut board = SaturationBoard::new();
    board.add_entry(entry).unwrap();
    assert_eq!(board.entry_count(), 1);
}

#[test]
fn edge_case_config_min_entries_zero() {
    let mut config = SaturationConfig::relaxed();
    config.min_entries_per_family = 0;
    config.min_families_covered = 1;
    let e1 = make_entry("z1", WorkloadFamily::BranchHeavy, 50, &["tag"]);
    let coverage = FamilyCoverage::compute(WorkloadFamily::BranchHeavy, &[&e1], &config);
    assert!(coverage.coverage_status.is_acceptable());
}

#[test]
fn edge_case_config_min_feature_diversity_zero() {
    let mut config = SaturationConfig::relaxed();
    config.min_feature_diversity = 0;
    let e1 = BenchmarkEntry::new("div0", WorkloadFamily::BranchHeavy, 10, BTreeSet::new());
    let coverage = FamilyCoverage::compute(WorkloadFamily::BranchHeavy, &[&e1], &config);
    // Should not panic with division by zero
    let _ = coverage.saturation_score_millionths;
}

#[test]
fn constants_schema_version() {
    assert!(SCHEMA_VERSION.contains("benchmark-coverage-saturation"));
}

#[test]
fn constants_component() {
    assert_eq!(COMPONENT, "benchmark_coverage_saturation");
}

#[test]
fn constants_bead_id() {
    assert_eq!(BEAD_ID, "bd-1lsy.8.5.5");
}

#[test]
fn constants_policy_id() {
    assert_eq!(POLICY_ID, "RGC-705E");
}

#[test]
fn constants_default_values() {
    assert_eq!(DEFAULT_MIN_ENTRIES_PER_FAMILY, 3);
    assert_eq!(DEFAULT_MIN_FAMILIES_COVERED, 8);
    assert_eq!(DEFAULT_MIN_SATURATION_SCORE_MILLIONTHS, 700_000);
    assert_eq!(DEFAULT_MIN_FEATURE_DIVERSITY, 2);
    assert_eq!(MAX_ENTRIES_PER_BOARD, 4096);
    assert_eq!(MAX_FEATURE_TAGS_PER_ENTRY, 64);
}
