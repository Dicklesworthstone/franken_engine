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

fn populate_board(board: &mut SaturationBoard, count: u64, tag_count: usize) {
    for family in WorkloadFamily::ALL {
        for i in 0..count {
            let name = format!("{}_{i}", family.as_str());
            let complexity = 100 + i * 50;
            let tag_names: Vec<String> = (0..tag_count)
                .map(|t| format!("tag_{}_{t}", family.as_str()))
                .collect();
            let tag_refs: Vec<&str> = tag_names.iter().map(|s| s.as_str()).collect();
            board.add_entry(make_entry(&name, *family, complexity, &tag_refs)).unwrap();
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
    let statuses = [
        CoverageStatus::Full,
        CoverageStatus::Partial,
        CoverageStatus::Minimal,
        CoverageStatus::Missing,
    ];
    let displays: BTreeSet<String> = statuses.iter().map(|s| format!("{s}")).collect();
    assert_eq!(displays.len(), 4);
}

// ---------------------------------------------------------------------------
// BenchmarkEntry
// ---------------------------------------------------------------------------

#[test]
fn benchmark_entry_new_basic() {
    let entry = make_entry("test-bench", WorkloadFamily::BranchHeavy, 500, &["loop", "if"]);
    assert_eq!(entry.name, "test-bench");
    assert_eq!(entry.family, WorkloadFamily::BranchHeavy);
    assert_eq!(entry.complexity, 500);
    assert_eq!(entry.feature_tags.len(), 2);
}

#[test]
fn benchmark_entry_content_hash_deterministic() {
    let e1 = make_entry("bench-1", WorkloadFamily::Vectorizable, 100, &["simd"]);
    let e2 = make_entry("bench-1", WorkloadFamily::Vectorizable, 100, &["simd"]);
    assert_eq!(e1.content_hash(), e2.content_hash());
}

#[test]
fn benchmark_entry_different_names_different_hashes() {
    let e1 = make_entry("bench-a", WorkloadFamily::Vectorizable, 100, &["simd"]);
    let e2 = make_entry("bench-b", WorkloadFamily::Vectorizable, 100, &["simd"]);
    assert_ne!(e1.content_hash(), e2.content_hash());
}

#[test]
fn benchmark_entry_serde_roundtrip() {
    let entry = make_entry("serde-bench", WorkloadFamily::NativeAddon, 200, &["ffi"]);
    let json = serde_json::to_string(&entry).unwrap();
    let restored: BenchmarkEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, restored);
}

// ---------------------------------------------------------------------------
// SaturationConfig
// ---------------------------------------------------------------------------

#[test]
fn saturation_config_default_values() {
    let cfg = SaturationConfig::default();
    assert_eq!(cfg.min_entries_per_family, DEFAULT_MIN_ENTRIES_PER_FAMILY);
    assert_eq!(cfg.min_families_covered, DEFAULT_MIN_FAMILIES_COVERED);
    assert_eq!(cfg.min_saturation_score_millionths, DEFAULT_MIN_SATURATION_SCORE_MILLIONTHS);
    assert_eq!(cfg.min_feature_diversity, DEFAULT_MIN_FEATURE_DIVERSITY);
}

#[test]
fn saturation_config_serde_roundtrip() {
    let cfg = SaturationConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let restored: SaturationConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, restored);
}

// ---------------------------------------------------------------------------
// SaturationBoard
// ---------------------------------------------------------------------------

#[test]
fn board_new_empty() {
    let board = SaturationBoard::new(epoch(1), SaturationConfig::default());
    assert_eq!(board.entry_count(), 0);
}

#[test]
fn board_add_entry() {
    let mut board = SaturationBoard::new(epoch(1), SaturationConfig::default());
    let entry = make_entry("b1", WorkloadFamily::BranchHeavy, 100, &["tag1"]);
    board.add_entry(entry).unwrap();
    assert_eq!(board.entry_count(), 1);
}

#[test]
fn board_add_entry_exceeds_max() {
    let mut board = SaturationBoard::new(epoch(1), SaturationConfig::default());
    for i in 0..MAX_ENTRIES_PER_BOARD {
        let entry = make_entry(&format!("b{i}"), WorkloadFamily::BranchHeavy, i as u64, &["t"]);
        board.add_entry(entry).unwrap();
    }
    let overflow = make_entry("overflow", WorkloadFamily::BranchHeavy, 0, &["t"]);
    let result = board.add_entry(overflow);
    assert!(result.is_err());
}

#[test]
fn board_evaluate_empty_fails() {
    let board = SaturationBoard::new(epoch(1), SaturationConfig::default());
    let report = board.evaluate();
    // Empty board should produce a failing verdict
    assert!(
        report.verdict == SaturationVerdict::Fail
            || report.verdict == SaturationVerdict::InsufficientData
    );
}

#[test]
fn board_evaluate_fully_populated_passes() {
    let mut board = SaturationBoard::new(epoch(1), SaturationConfig::default());
    populate_board(&mut board, 5, 3);
    let report = board.evaluate();
    assert!(
        report.verdict == SaturationVerdict::Pass
            || report.verdict == SaturationVerdict::PassWithWarnings,
        "fully populated board should pass: {:?}",
        report.verdict
    );
}

#[test]
fn board_evaluate_deterministic() {
    let mut board1 = SaturationBoard::new(epoch(1), SaturationConfig::default());
    populate_board(&mut board1, 4, 2);
    let r1 = board1.evaluate();

    let mut board2 = SaturationBoard::new(epoch(1), SaturationConfig::default());
    populate_board(&mut board2, 4, 2);
    let r2 = board2.evaluate();

    assert_eq!(r1.verdict, r2.verdict);
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// SaturationVerdict
// ---------------------------------------------------------------------------

#[test]
fn saturation_verdict_display_all_distinct() {
    let verdicts = [
        SaturationVerdict::Pass,
        SaturationVerdict::PassWithWarnings,
        SaturationVerdict::Fail,
        SaturationVerdict::InsufficientData,
        SaturationVerdict::Blocked,
    ];
    let displays: BTreeSet<String> = verdicts.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn saturation_verdict_serde_roundtrip() {
    for verdict in [
        SaturationVerdict::Pass,
        SaturationVerdict::Fail,
        SaturationVerdict::Blocked,
    ] {
        let json = serde_json::to_string(&verdict).unwrap();
        let restored: SaturationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(verdict, restored);
    }
}

// ---------------------------------------------------------------------------
// SaturationReport
// ---------------------------------------------------------------------------

#[test]
fn report_serde_roundtrip() {
    let mut board = SaturationBoard::new(epoch(42), SaturationConfig::default());
    populate_board(&mut board, 3, 2);
    let report = board.evaluate();
    let json = serde_json::to_string(&report).unwrap();
    let restored: SaturationReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

#[test]
fn report_display_nonempty() {
    let mut board = SaturationBoard::new(epoch(1), SaturationConfig::default());
    populate_board(&mut board, 3, 2);
    let report = board.evaluate();
    let s = format!("{report}");
    assert!(!s.is_empty());
}

// ---------------------------------------------------------------------------
// SaturationGate
// ---------------------------------------------------------------------------

#[test]
fn gate_new_and_evaluate() {
    let mut board = SaturationBoard::new(epoch(1), SaturationConfig::default());
    populate_board(&mut board, 4, 3);
    let gate = SaturationGate::new(board);
    let receipt = gate.evaluate();
    // Receipt should have a valid hash
    assert_ne!(receipt.content_hash.as_bytes(), &[0u8; 32]);
}

#[test]
fn gate_evaluate_deterministic() {
    let build = || {
        let mut board = SaturationBoard::new(epoch(1), SaturationConfig::default());
        populate_board(&mut board, 4, 3);
        let gate = SaturationGate::new(board);
        gate.evaluate()
    };
    let r1 = build();
    let r2 = build();
    assert_eq!(r1.content_hash, r2.content_hash);
}

// ---------------------------------------------------------------------------
// BoardError
// ---------------------------------------------------------------------------

#[test]
fn board_error_display_distinct() {
    let errs = vec![
        BoardError::BoardFull { max: 4096 },
        BoardError::TooManyTags { max: 64 },
        BoardError::DuplicateEntry { name: "dup".into() },
    ];
    let displays: BTreeSet<String> = errs.iter().map(|e| format!("{e}")).collect();
    assert_eq!(displays.len(), 3);
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
    let metrics = [
        RepresentativenessMetric::FamilyCoverage,
        RepresentativenessMetric::FeatureDiversity,
        RepresentativenessMetric::ComplexitySpread,
    ];
    let displays: BTreeSet<String> = metrics.iter().map(|m| format!("{m}")).collect();
    assert_eq!(displays.len(), 3);
}
