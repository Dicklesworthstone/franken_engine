#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::identity_op
)]
//! Enrichment integration tests for benchmark_coverage_saturation module.
//!
//! Covers board lifecycle, gate evaluation, verdict classification,
//! decision receipts, and representativeness scoring.

use std::collections::BTreeSet;

use frankenengine_engine::benchmark_coverage_saturation::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn default_config() -> SaturationConfig {
    SaturationConfig::default()
}

fn populate_board(board: &mut SaturationBoard, count: u64, tag_count: usize) {
    for family in WorkloadFamily::ALL {
        for i in 0..count {
            let name = format!("{}_{i}", family.as_str());
            let complexity = 100 + i * 50;
            let tag_names: Vec<String> = (0..tag_count)
                .map(|t| format!("tag_{}_{t}", family.as_str()))
                .collect();
            let tag_refs: Vec<&str> = tag_names.iter().map(|s| s.as_str()).collect();
            board
                .add_entry(make_entry(&name, *family, complexity, &tag_refs))
                .unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// WorkloadFamily
// ---------------------------------------------------------------------------

#[test]
fn workload_family_all_12_variants() {
    assert_eq!(WorkloadFamily::ALL.len(), 12);
}

#[test]
fn workload_family_as_str_all_distinct() {
    let strs: BTreeSet<_> = WorkloadFamily::ALL.iter().map(|f| f.as_str()).collect();
    assert_eq!(strs.len(), 12);
}

#[test]
fn workload_family_display_all_distinct() {
    let displays: BTreeSet<String> = WorkloadFamily::ALL.iter().map(|f| format!("{f}")).collect();
    assert_eq!(displays.len(), 12);
}

#[test]
fn workload_family_serde_roundtrip() {
    for family in WorkloadFamily::ALL {
        let json = serde_json::to_string(family).unwrap();
        let restored: WorkloadFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*family, restored);
    }
}

// ---------------------------------------------------------------------------
// CoverageStatus
// ---------------------------------------------------------------------------

#[test]
fn coverage_status_display_all_distinct() {
    let displays: BTreeSet<String> = CoverageStatus::ALL.iter().map(|s| format!("{s}")).collect();
    assert_eq!(displays.len(), CoverageStatus::ALL.len());
}

// ---------------------------------------------------------------------------
// BenchmarkEntry
// ---------------------------------------------------------------------------

#[test]
fn benchmark_entry_new_basic() {
    let entry = make_entry(
        "test-bench",
        WorkloadFamily::BranchHeavy,
        500,
        &["loop", "if"],
    );
    assert_eq!(entry.name, "test-bench");
    assert_eq!(entry.family, WorkloadFamily::BranchHeavy);
    assert_eq!(entry.complexity_score, 500);
    assert_eq!(entry.feature_tags.len(), 2);
}

#[test]
fn benchmark_entry_hash_deterministic() {
    let e1 = make_entry("bench-1", WorkloadFamily::Vectorizable, 100, &["simd"]);
    let e2 = make_entry("bench-1", WorkloadFamily::Vectorizable, 100, &["simd"]);
    assert_eq!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn benchmark_entry_different_names_different_hashes() {
    let e1 = make_entry("bench-a", WorkloadFamily::Vectorizable, 100, &["simd"]);
    let e2 = make_entry("bench-b", WorkloadFamily::Vectorizable, 100, &["simd"]);
    assert_ne!(e1.entry_hash, e2.entry_hash);
}

#[test]
fn benchmark_entry_serde_roundtrip() {
    let entry = make_entry("serde-bench", WorkloadFamily::NativeAddon, 200, &["ffi"]);
    let json = serde_json::to_string(&entry).unwrap();
    let restored: BenchmarkEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

#[test]
fn benchmark_entry_verify_hash() {
    let entry = make_entry("verify-bench", WorkloadFamily::BranchHeavy, 300, &["x"]);
    assert!(entry.verify_hash());
}

// ---------------------------------------------------------------------------
// SaturationConfig
// ---------------------------------------------------------------------------

#[test]
fn saturation_config_default_values() {
    let cfg = default_config();
    assert_eq!(cfg.min_entries_per_family, DEFAULT_MIN_ENTRIES_PER_FAMILY);
    assert_eq!(cfg.min_families_covered, DEFAULT_MIN_FAMILIES_COVERED);
    assert_eq!(
        cfg.min_saturation_score_millionths,
        DEFAULT_MIN_SATURATION_SCORE_MILLIONTHS
    );
    assert_eq!(cfg.min_feature_diversity, DEFAULT_MIN_FEATURE_DIVERSITY);
}

#[test]
fn saturation_config_serde_roundtrip() {
    let cfg = default_config();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: SaturationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ---------------------------------------------------------------------------
// SaturationBoard
// ---------------------------------------------------------------------------

#[test]
fn board_new_empty() {
    let board = SaturationBoard::new();
    assert_eq!(board.entry_count(), 0);
    assert!(board.is_empty());
}

#[test]
fn board_add_entry() {
    let mut board = SaturationBoard::new();
    let entry = make_entry("b1", WorkloadFamily::BranchHeavy, 100, &["tag1"]);
    board.add_entry(entry).unwrap();
    assert_eq!(board.entry_count(), 1);
}

#[test]
fn board_duplicate_entry_error() {
    let mut board = SaturationBoard::new();
    let e1 = make_entry("dup", WorkloadFamily::BranchHeavy, 100, &["tag1"]);
    let e2 = make_entry("dup", WorkloadFamily::BranchHeavy, 200, &["tag2"]);
    board.add_entry(e1).unwrap();
    let result = board.add_entry(e2);
    assert!(result.is_err());
}

#[test]
fn board_evaluate_empty_config_violation() {
    let board = SaturationBoard::new();
    let cfg = default_config();
    let report = board.evaluate(&cfg);
    assert_eq!(report.verdict, SaturationVerdict::ConfigViolation);
}

#[test]
fn board_evaluate_fully_populated() {
    let mut board = SaturationBoard::new();
    populate_board(&mut board, 5, 3);
    let cfg = default_config();
    let report = board.evaluate(&cfg);
    assert!(
        report.verdict == SaturationVerdict::Saturated
            || report.verdict == SaturationVerdict::Adequate
            || report.verdict == SaturationVerdict::Sparse,
        "populated board verdict: {:?}",
        report.verdict
    );
}

#[test]
fn board_evaluate_deterministic() {
    let cfg = default_config();

    let mut board1 = SaturationBoard::new();
    populate_board(&mut board1, 4, 2);
    let r1 = board1.evaluate(&cfg);

    let mut board2 = SaturationBoard::new();
    populate_board(&mut board2, 4, 2);
    let r2 = board2.evaluate(&cfg);

    assert_eq!(r1.verdict, r2.verdict);
    assert_eq!(r1.content_hash, r2.content_hash);
}

#[test]
fn board_entries_for_family() {
    let mut board = SaturationBoard::new();
    populate_board(&mut board, 3, 1);
    let branch = board.entries_for_family(WorkloadFamily::BranchHeavy);
    assert_eq!(branch.len(), 3);
}

// ---------------------------------------------------------------------------
// SaturationVerdict
// ---------------------------------------------------------------------------

#[test]
fn saturation_verdict_display_all_distinct() {
    let displays: BTreeSet<String> = SaturationVerdict::ALL
        .iter()
        .map(|v| format!("{v}"))
        .collect();
    assert_eq!(displays.len(), SaturationVerdict::ALL.len());
}

#[test]
fn saturation_verdict_serde_roundtrip() {
    for verdict in SaturationVerdict::ALL {
        let json = serde_json::to_string(verdict).unwrap();
        let restored: SaturationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*verdict, restored);
    }
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

// ---------------------------------------------------------------------------
// SaturationReport
// ---------------------------------------------------------------------------

#[test]
fn report_serde_roundtrip() {
    let mut board = SaturationBoard::new();
    populate_board(&mut board, 3, 2);
    let cfg = default_config();
    let report = board.evaluate(&cfg);
    let json = serde_json::to_string(&report).unwrap();
    let restored: SaturationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

#[test]
fn report_display_nonempty() {
    let mut board = SaturationBoard::new();
    populate_board(&mut board, 3, 2);
    let cfg = default_config();
    let report = board.evaluate(&cfg);
    let s = format!("{report}");
    assert!(!s.is_empty());
}

// ---------------------------------------------------------------------------
// BoardError
// ---------------------------------------------------------------------------

#[test]
fn board_error_display_distinct() {
    let errs = vec![
        BoardError::TooManyEntries {
            count: 5000,
            max: 4096,
        },
        BoardError::TooManyFeatureTags {
            name: "bench".into(),
            count: 100,
            max: 64,
        },
        BoardError::DuplicateEntryName { name: "dup".into() },
        BoardError::IntegrityFailure { name: "bad".into() },
    ];
    let displays: BTreeSet<String> = errs.iter().map(|e| format!("{e}")).collect();
    assert_eq!(displays.len(), 4);
}

#[test]
fn board_error_tags_all_distinct() {
    let errs = vec![
        BoardError::TooManyEntries { count: 1, max: 1 },
        BoardError::TooManyFeatureTags {
            name: "x".into(),
            count: 1,
            max: 1,
        },
        BoardError::DuplicateEntryName { name: "x".into() },
        BoardError::IntegrityFailure { name: "x".into() },
    ];
    let tags: BTreeSet<_> = errs.iter().map(|e| e.tag()).collect();
    assert_eq!(tags.len(), 4);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn constants_valid() {
    assert!(SCHEMA_VERSION.contains("benchmark"));
    assert!(BEAD_ID.starts_with("bd-"));
    assert_eq!(COMPONENT, "benchmark_coverage_saturation");
    assert!(POLICY_ID.starts_with("RGC-"));
    assert!(DEFAULT_MIN_ENTRIES_PER_FAMILY > 0);
    assert!(DEFAULT_MIN_FAMILIES_COVERED > 0);
    assert!(MAX_ENTRIES_PER_BOARD > 0);
}

// ---------------------------------------------------------------------------
// RepresentativenessMetric
// ---------------------------------------------------------------------------

#[test]
fn representativeness_metric_display_all_distinct() {
    let displays: BTreeSet<String> = RepresentativenessMetric::ALL
        .iter()
        .map(|m| format!("{m}"))
        .collect();
    assert_eq!(displays.len(), RepresentativenessMetric::ALL.len());
}
