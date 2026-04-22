#![forbid(unsafe_code)]

//! Benchmark CI Surface Conformance Harness
//!
//! Validates that benchmark coverage saturation and CI quality gates maintain
//! fail-closed behavior and cannot be bypassed through configuration manipulation
//! or representativeness gaming.
//!
//! Specification: Benchmark quality gates MUST fail closed on:
//! - Configuration bypasses (min thresholds set to 0)
//! - Representativeness gaming (artificially inflated scores)
//! - CI gate circumvention (environment variable escapes)
//!
//! Pattern: Spec-Derived Test Matrix (Pattern 4 from testing-conformance-harnesses)

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::benchmark_coverage_saturation::{
    BenchmarkEntry, DEFAULT_MIN_REPRESENTATIVENESS_SCORE_MILLIONTHS, RepresentativenessMetric,
    RepresentativenessScore, SaturationBoard, SaturationConfig, SaturationReport, WorkloadFamily,
};
use frankenengine_engine::hash_tiers::ContentHash;
use serde::{Deserialize, Serialize};

/// Conformance requirement levels from RFC-style specifications
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum RequirementLevel {
    Must,   // MUST - mandatory for conformance
    Should, // SHOULD - recommended but not mandatory
    May,    // MAY - optional
}

/// Conformance test case following spec-derived pattern
#[derive(Debug, Clone)]
struct ConformanceCase {
    id: &'static str,
    section: &'static str,
    level: RequirementLevel,
    description: &'static str,
    test_fn: fn() -> ConformanceResult,
}

/// Test execution result
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status")]
enum ConformanceResult {
    Pass,
    Fail { reason: String },
    ExpectedFailure { reason: String }, // Known divergence (XFAIL)
}

impl ConformanceResult {
    fn is_success(&self) -> bool {
        matches!(
            self,
            ConformanceResult::Pass | ConformanceResult::ExpectedFailure { .. }
        )
    }
}

/// Benchmark CI surface fail-closed conformance requirements
const BENCHMARK_CI_CONFORMANCE_CASES: &[ConformanceCase] = &[
    // Section 1: SaturationConfig Fail-Closed Requirements
    ConformanceCase {
        id: "BCS-1.1",
        section: "1",
        level: RequirementLevel::Must,
        description: "default() config MUST have non-zero representativeness threshold",
        test_fn: test_default_config_non_zero_representativeness,
    },
    ConformanceCase {
        id: "BCS-1.2",
        section: "1",
        level: RequirementLevel::Must,
        description: "strict() config MUST have higher thresholds than default()",
        test_fn: test_strict_config_higher_thresholds,
    },
    ConformanceCase {
        id: "BCS-1.3",
        section: "1",
        level: RequirementLevel::Must,
        description: "relaxed() config zero representativeness threshold MUST be documented as bypass",
        test_fn: test_relaxed_config_zero_representativeness_documented,
    },
    // Section 2: Representativeness Gaming Prevention
    ConformanceCase {
        id: "BCS-2.1",
        section: "2",
        level: RequirementLevel::Must,
        description: "uniform workload distribution MUST fail representativeness checks",
        test_fn: test_uniform_distribution_fails_representativeness,
    },
    ConformanceCase {
        id: "BCS-2.2",
        section: "2",
        level: RequirementLevel::Must,
        description: "single-tag workloads MUST fail diversity requirements",
        test_fn: test_single_tag_fails_diversity,
    },
    ConformanceCase {
        id: "BCS-2.3",
        section: "2",
        level: RequirementLevel::Must,
        description: "representativeness_passed MUST be false when floor not met",
        test_fn: test_representativeness_passed_requires_floor,
    },
    // Section 3: Gate Bypass Prevention
    ConformanceCase {
        id: "BCS-3.1",
        section: "3",
        level: RequirementLevel::Must,
        description: "passes_gate() MUST require both verdict AND representativeness",
        test_fn: test_passes_gate_requires_both_conditions,
    },
    ConformanceCase {
        id: "BCS-3.2",
        section: "3",
        level: RequirementLevel::Must,
        description: "content_hash MUST change when representativeness changes",
        test_fn: test_content_hash_includes_representativeness,
    },
];

// ── Test Implementation Functions ────────────────────────────────────────

fn test_default_config_non_zero_representativeness() -> ConformanceResult {
    let config = SaturationConfig::default();

    if config.min_representativeness_score_millionths == 0 {
        return ConformanceResult::Fail {
            reason: "Default config has zero representativeness threshold - fail-open bypass"
                .to_string(),
        };
    }

    if config.min_representativeness_score_millionths < 100_000 {
        return ConformanceResult::Fail {
            reason: format!(
                "Default representativeness threshold {} is too low (< 100k millionths)",
                config.min_representativeness_score_millionths
            ),
        };
    }

    ConformanceResult::Pass
}

fn test_strict_config_higher_thresholds() -> ConformanceResult {
    let default = SaturationConfig::default();
    let strict = SaturationConfig::strict();

    if strict.min_representativeness_score_millionths
        <= default.min_representativeness_score_millionths
    {
        return ConformanceResult::Fail {
            reason: format!(
                "Strict representativeness {} not higher than default {}",
                strict.min_representativeness_score_millionths,
                default.min_representativeness_score_millionths
            ),
        };
    }

    if strict.min_saturation_score_millionths <= default.min_saturation_score_millionths {
        return ConformanceResult::Fail {
            reason: "Strict saturation score not higher than default".to_string(),
        };
    }

    ConformanceResult::Pass
}

fn test_relaxed_config_zero_representativeness_documented() -> ConformanceResult {
    let relaxed = SaturationConfig::relaxed();

    if relaxed.min_representativeness_score_millionths != 0 {
        return ConformanceResult::Fail {
            reason: "Expected relaxed config to have zero representativeness (this test validates the bypass exists)".to_string(),
        };
    }

    // This is an EXPECTED FAILURE - we're documenting that relaxed config is a known bypass
    ConformanceResult::ExpectedFailure {
        reason: "relaxed_config() sets min_representativeness_score_millionths=0 creating fail-open bypass (bd-1aq56)".to_string(),
    }
}

fn test_uniform_distribution_fails_representativeness() -> ConformanceResult {
    let mut board = SaturationBoard::new();

    // Create uniform workload - same execution time for all entries
    for (i, family) in WorkloadFamily::ALL.iter().enumerate() {
        let entry = BenchmarkEntry {
            workload_id: format!("uniform_{i}"),
            family: *family,
            execution_time_ns: 100_000, // Uniform time - no diversity
            tags: BTreeMap::from([("same_tag".to_string(), "same_value".to_string())]),
            content_hash: ContentHash::compute(format!("uniform_{i}").as_bytes()),
        };
        if let Err(e) = board.add_entry(entry) {
            return ConformanceResult::Fail {
                reason: format!("Failed to add uniform entry: {e}"),
            };
        }
    }

    let mut config = SaturationConfig::default();
    config.min_families_covered = WorkloadFamily::COUNT as u64;
    config.min_representativeness_score_millionths =
        DEFAULT_MIN_REPRESENTATIVENESS_SCORE_MILLIONTHS;
    config.target_families = WorkloadFamily::ALL.iter().copied().collect();

    let report = board.evaluate(&config);

    if report.representativeness_passed {
        return ConformanceResult::Fail {
            reason: "Uniform distribution should fail representativeness checks but passed"
                .to_string(),
        };
    }

    // Verify at least one score is below threshold
    let below_threshold = report
        .representativeness_scores
        .iter()
        .any(|score| score.score_millionths < config.min_representativeness_score_millionths);

    if !below_threshold {
        return ConformanceResult::Fail {
            reason:
                "Expected some representativeness scores below threshold for uniform distribution"
                    .to_string(),
        };
    }

    ConformanceResult::Pass
}

fn test_single_tag_fails_diversity() -> ConformanceResult {
    let mut board = SaturationBoard::new();

    // Create entries with only one tag - no diversity
    for (i, family) in WorkloadFamily::ALL.iter().enumerate() {
        let entry = BenchmarkEntry {
            workload_id: format!("single_tag_{i}"),
            family: *family,
            execution_time_ns: (i as u64 + 1) * 50_000, // Varied execution time
            tags: BTreeMap::from([("only_tag".to_string(), "only_value".to_string())]),
            content_hash: ContentHash::compute(format!("single_tag_{i}").as_bytes()),
        };
        if let Err(e) = board.add_entry(entry) {
            return ConformanceResult::Fail {
                reason: format!("Failed to add single-tag entry: {e}"),
            };
        }
    }

    let mut config = SaturationConfig::default();
    config.min_families_covered = WorkloadFamily::COUNT as u64;
    config.min_representativeness_score_millionths = 200_000; // Moderate threshold
    config.target_families = WorkloadFamily::ALL.iter().copied().collect();

    let report = board.evaluate(&config);

    // Single-tag workloads should have poor tag diversity even with execution time variety
    let tag_diversity_score = report
        .representativeness_scores
        .iter()
        .find(|score| score.metric == RepresentativenessMetric::TagDiversity)
        .map(|score| score.score_millionths);

    if let Some(score) = tag_diversity_score {
        if score >= config.min_representativeness_score_millionths {
            return ConformanceResult::Fail {
                reason: format!(
                    "Tag diversity score {score} should be below threshold {}",
                    config.min_representativeness_score_millionths
                ),
            };
        }
    } else {
        return ConformanceResult::Fail {
            reason: "TagDiversity metric missing from representativeness scores".to_string(),
        };
    }

    ConformanceResult::Pass
}

fn test_representativeness_passed_requires_floor() -> ConformanceResult {
    let mut board = SaturationBoard::new();

    // Create good coverage but configure impossibly high threshold
    for (i, family) in WorkloadFamily::ALL.iter().enumerate() {
        for variant in 0..3 {
            let entry = BenchmarkEntry {
                workload_id: format!("diverse_{i}_{variant}"),
                family: *family,
                execution_time_ns: (variant as u64 + 1) * 100_000,
                tags: BTreeMap::from([
                    ("category".to_string(), format!("cat_{}", variant % 2)),
                    ("complexity".to_string(), format!("level_{}", variant)),
                ]),
                content_hash: ContentHash::compute(format!("diverse_{i}_{variant}").as_bytes()),
            };
            if let Err(e) = board.add_entry(entry) {
                return ConformanceResult::Fail {
                    reason: format!("Failed to add diverse entry: {e}"),
                };
            }
        }
    }

    let mut config = SaturationConfig::default();
    config.min_families_covered = WorkloadFamily::COUNT as u64;
    config.min_representativeness_score_millionths = 950_000; // Impossibly high threshold
    config.target_families = WorkloadFamily::ALL.iter().copied().collect();

    let report = board.evaluate(&config);

    if report.representativeness_passed {
        return ConformanceResult::Fail {
            reason: "representativeness_passed should be false with impossibly high threshold"
                .to_string(),
        };
    }

    if report.min_representativeness_score_millionths != 950_000 {
        return ConformanceResult::Fail {
            reason: "Report should record the configured minimum threshold".to_string(),
        };
    }

    ConformanceResult::Pass
}

fn test_passes_gate_requires_both_conditions() -> ConformanceResult {
    let mut board = SaturationBoard::new();

    // Create workload that satisfies publication verdict but fails representativeness
    for (i, family) in WorkloadFamily::ALL.iter().enumerate().take(8) {
        for entries in 0..5 {
            let entry = BenchmarkEntry {
                workload_id: format!("verdict_pass_{i}_{entries}"),
                family: *family,
                execution_time_ns: 100_000, // Uniform - bad representativeness
                tags: BTreeMap::from([("uniform_tag".to_string(), "same".to_string())]),
                content_hash: ContentHash::compute(
                    format!("verdict_pass_{i}_{entries}").as_bytes(),
                ),
            };
            if let Err(e) = board.add_entry(entry) {
                return ConformanceResult::Fail {
                    reason: format!("Failed to add entry: {e}"),
                };
            }
        }
    }

    let mut config = SaturationConfig::default();
    config.min_families_covered = 8;
    config.min_entries_per_family = 3;
    config.min_saturation_score_millionths = 100_000; // Low - should pass verdict
    config.min_representativeness_score_millionths = 400_000; // High - should fail representativeness
    config.target_families = WorkloadFamily::ALL.iter().take(8).copied().collect();

    let report = board.evaluate(&config);

    // Verdict should allow publication (good coverage)
    if !report.verdict.allows_publication() {
        return ConformanceResult::Fail {
            reason: "Expected verdict to allow publication with good coverage".to_string(),
        };
    }

    // But representativeness should fail (uniform distribution)
    if report.representativeness_passed {
        return ConformanceResult::Fail {
            reason: "Expected representativeness to fail with uniform distribution".to_string(),
        };
    }

    // Overall gate should fail (requires BOTH conditions)
    if report.passes_gate() {
        return ConformanceResult::Fail {
            reason:
                "passes_gate() should fail when representativeness fails, even if verdict passes"
                    .to_string(),
        };
    }

    ConformanceResult::Pass
}

fn test_content_hash_includes_representativeness() -> ConformanceResult {
    let mut uniform_board = SaturationBoard::new();
    let mut diverse_board = SaturationBoard::new();

    // Create two boards with different representativeness characteristics
    for (i, family) in WorkloadFamily::ALL.iter().enumerate().take(4) {
        // Uniform board - same execution time
        let uniform_entry = BenchmarkEntry {
            workload_id: format!("uniform_{i}"),
            family: *family,
            execution_time_ns: 100_000,
            tags: BTreeMap::from([("type".to_string(), "uniform".to_string())]),
            content_hash: ContentHash::compute(format!("uniform_{i}").as_bytes()),
        };

        // Diverse board - varied execution time
        let diverse_entry = BenchmarkEntry {
            workload_id: format!("diverse_{i}"),
            family: *family,
            execution_time_ns: (i as u64 + 1) * 100_000,
            tags: BTreeMap::from([("type".to_string(), format!("diverse_{i}"))]),
            content_hash: ContentHash::compute(format!("diverse_{i}").as_bytes()),
        };

        if let Err(e) = uniform_board.add_entry(uniform_entry) {
            return ConformanceResult::Fail {
                reason: format!("Failed to add uniform entry: {e}"),
            };
        }

        if let Err(e) = diverse_board.add_entry(diverse_entry) {
            return ConformanceResult::Fail {
                reason: format!("Failed to add diverse entry: {e}"),
            };
        }
    }

    let mut config = SaturationConfig::relaxed();
    config.min_families_covered = 4;
    config.target_families = WorkloadFamily::ALL.iter().take(4).copied().collect();

    let uniform_report = uniform_board.evaluate(&config);
    let diverse_report = diverse_board.evaluate(&config);

    // Reports should have different representativeness scores
    if uniform_report.representativeness_scores == diverse_report.representativeness_scores {
        return ConformanceResult::Fail {
            reason: "Uniform and diverse workloads should have different representativeness scores"
                .to_string(),
        };
    }

    // Content hashes must be different (includes representativeness data)
    if uniform_report.content_hash == diverse_report.content_hash {
        return ConformanceResult::Fail {
            reason: "Content hash should change when representativeness changes - bypass detection failed".to_string(),
        };
    }

    ConformanceResult::Pass
}

// ── Conformance Test Runner ─────────────────────────────────────────────

fn run_conformance_suite() -> (u32, u32, u32) {
    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut xfail = 0u32;

    println!("=== Benchmark CI Surface Conformance Harness ===");
    println!("Validating fail-closed requirements for benchmark coverage saturation\n");

    for case in BENCHMARK_CI_CONFORMANCE_CASES {
        let result = (case.test_fn)();

        let (verdict_str, is_pass) = match &result {
            ConformanceResult::Pass => {
                pass += 1;
                ("PASS", true)
            }
            ConformanceResult::ExpectedFailure { reason } => {
                xfail += 1;
                println!("XFAIL {}: {} ({})", case.id, case.description, reason);
                ("XFAIL", true)
            }
            ConformanceResult::Fail { reason } => {
                fail += 1;
                println!(
                    "FAIL {}: {}\n  Reason: {}",
                    case.id, case.description, reason
                );
                ("FAIL", false)
            }
        };

        // Structured JSON-line output for CI parsing
        println!(
            "{{\"id\":\"{}\",\"verdict\":\"{verdict_str}\",\"level\":\"{:?}\",\"section\":\"{}\"}}",
            case.id, case.level, case.section
        );

        if matches!(result, ConformanceResult::Pass) {
            println!("PASS {}: {}", case.id, case.description);
        }
    }

    let total = pass + fail + xfail;
    println!("\n=== Benchmark CI Surface Conformance Summary ===");
    println!("Total: {total} tests");
    println!("Pass: {pass}");
    println!("Fail: {fail}");
    println!("Expected Failures (documented bypasses): {xfail}");

    if fail > 0 {
        println!("\n🚨 CONFORMANCE FAILURE: {fail} test(s) failed");
        println!(
            "Benchmark CI surface has undocumented fail-open bypasses or gaming vulnerabilities"
        );
    } else {
        println!("\n✅ CONFORMANCE VERIFIED: All fail-closed requirements satisfied");
        println!("({xfail} documented bypass(es) marked as expected failures)");
    }

    (pass, fail, xfail)
}

// ── Integration Tests ───────────────────────────────────────────────────

#[test]
fn benchmark_ci_surface_conformance_full_suite() {
    let (pass, fail, _xfail) = run_conformance_suite();

    assert!(
        pass > 0,
        "Conformance suite must have at least some passing tests (got {pass})"
    );

    assert_eq!(
        fail, 0,
        "{fail} benchmark CI surface conformance tests failed - fail-closed violations detected"
    );
}

#[test]
fn conformance_coverage_completeness() {
    // Verify we test all critical surfaces
    let sections: BTreeSet<&str> = BENCHMARK_CI_CONFORMANCE_CASES
        .iter()
        .map(|case| case.section)
        .collect();

    assert!(sections.contains("1"), "Missing SaturationConfig tests");
    assert!(
        sections.contains("2"),
        "Missing representativeness gaming tests"
    );
    assert!(
        sections.contains("3"),
        "Missing gate bypass prevention tests"
    );

    let must_requirements: Vec<_> = BENCHMARK_CI_CONFORMANCE_CASES
        .iter()
        .filter(|case| case.level == RequirementLevel::Must)
        .collect();

    assert!(
        must_requirements.len() >= 7,
        "Need at least 7 MUST requirements for comprehensive coverage (got {})",
        must_requirements.len()
    );
}

#[test]
fn representativeness_bypass_detection_regression() {
    // Regression test for bd-1aq56: relaxed_config representativeness bypass
    let relaxed = SaturationConfig::relaxed();

    // This test documents the known bypass - relaxed config allows min_representativeness_score = 0
    assert_eq!(
        relaxed.min_representativeness_score_millionths, 0,
        "Expected relaxed config zero representativeness bypass (bd-1aq56) - \
         if this changed, update conformance case BCS-1.3"
    );

    // Verify this actually creates a bypass
    let mut board = SaturationBoard::new();
    for (i, family) in WorkloadFamily::ALL.iter().enumerate().take(3) {
        let entry = BenchmarkEntry {
            workload_id: format!("bypass_test_{i}"),
            family: *family,
            execution_time_ns: 100_000, // Uniform - should fail representativeness
            tags: BTreeMap::from([("bypass".to_string(), "uniform".to_string())]),
            content_hash: ContentHash::compute(format!("bypass_test_{i}").as_bytes()),
        };
        board.add_entry(entry).unwrap();
    }

    let mut bypass_config = relaxed;
    bypass_config.min_families_covered = 3;
    bypass_config.target_families = WorkloadFamily::ALL.iter().take(3).copied().collect();

    let report = board.evaluate(&bypass_config);

    // With zero threshold, representativeness should always pass (bypass behavior)
    assert!(
        report.representativeness_passed,
        "Zero representativeness threshold should bypass quality gates (documenting bd-1aq56)"
    );

    // But with non-zero threshold, same workload should fail
    let mut proper_config = bypass_config;
    proper_config.min_representativeness_score_millionths =
        DEFAULT_MIN_REPRESENTATIVENESS_SCORE_MILLIONTHS;

    let proper_report = board.evaluate(&proper_config);
    assert!(
        !proper_report.representativeness_passed,
        "Non-zero representativeness threshold should catch uniform distributions"
    );
}
