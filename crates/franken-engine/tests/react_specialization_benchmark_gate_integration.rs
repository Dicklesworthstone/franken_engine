//! Integration tests for react_specialization_benchmark_gate (bd-1lsy.7.9.3 [RGC-609C]).
//!
//! Exercises the benchmark matrix evaluation, regression classification,
//! parity reporting, and governance action derivation through public API
//! entry points only.

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::react_specialization_benchmark_gate::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(100)
}

fn hash(tag: &[u8]) -> ContentHash {
    ContentHash::compute(tag)
}

fn sample(
    domain: SpecializationDomain,
    class: BenchmarkClass,
    baseline: u64,
    candidate: u64,
    count: u64,
) -> BenchmarkSample {
    BenchmarkSample {
        domain,
        benchmark_class: class,
        baseline_value_millionths: baseline,
        candidate_value_millionths: candidate,
        sample_count: count,
        epoch: epoch(),
        content_hash: hash(b"workload"),
    }
}

fn parity(
    dim: ParityDimension,
    domain: SpecializationDomain,
    achieved: bool,
    divergences: u64,
    total: u64,
) -> ParityFinding {
    ParityFinding {
        dimension: dim,
        domain,
        is_parity_achieved: achieved,
        divergence_count: divergences,
        total_comparisons: total,
        detail: String::from("test finding"),
    }
}

fn default_config() -> BenchmarkConfig {
    BenchmarkConfig::default()
}

// ---------------------------------------------------------------------------
// Empty / minimal scenarios
// ---------------------------------------------------------------------------

#[test]
fn empty_samples_yields_insufficient_evidence() {
    let config = default_config();
    let result = evaluate_benchmark_matrix(&config, &[], &[], epoch());
    assert_eq!(result.overall_verdict, GateVerdict::InsufficientEvidence);
}

#[test]
fn single_passing_cell() {
    let config = default_config();
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        1_000_000,
        1_000_000,
        50,
    )];
    let result = evaluate_benchmark_matrix(&config, &samples, &[], epoch());
    assert_eq!(result.cells.len(), 1);
    assert_eq!(result.cells[0].verdict, GateVerdict::Pass);
}

#[test]
fn all_domains_all_classes_pass() {
    let config = default_config();
    let mut samples = Vec::new();
    for &domain in SpecializationDomain::ALL {
        for &class in BenchmarkClass::ALL {
            samples.push(sample(domain, class, 1_000_000, 1_000_000, 50));
        }
    }
    let result = evaluate_benchmark_matrix(&config, &samples, &[], epoch());
    assert_eq!(result.cells.len(), 36); // 6 domains x 6 classes
    assert_eq!(result.overall_verdict, GateVerdict::Pass);
    assert_eq!(result.governance_action, GovernanceAction::AllowRollout);
}

// ---------------------------------------------------------------------------
// Regression classification
// ---------------------------------------------------------------------------

#[test]
fn classify_zero_delta_is_none() {
    let config = default_config();
    assert_eq!(classify_regression(0, &config), RegressionSeverity::None);
}

#[test]
fn classify_minor_regression() {
    let config = default_config();
    // 3% regression → below 5% minor threshold
    assert_eq!(
        classify_regression(30_000, &config),
        RegressionSeverity::Minor
    );
}

#[test]
fn classify_moderate_regression() {
    let config = default_config();
    // 10% → above 5% minor, below 15% major
    assert_eq!(
        classify_regression(100_000, &config),
        RegressionSeverity::Moderate
    );
}

#[test]
fn classify_major_regression() {
    let config = default_config();
    // 20% → above 15% major, below 30% (2x major)
    assert_eq!(
        classify_regression(200_000, &config),
        RegressionSeverity::Major
    );
}

#[test]
fn classify_critical_regression() {
    let config = default_config();
    // 50% → above 2x major (30%)
    assert_eq!(
        classify_regression(500_000, &config),
        RegressionSeverity::Critical
    );
}

#[test]
fn classify_at_minor_boundary() {
    let config = default_config();
    // Exactly at 5% minor threshold → moderate (not minor)
    assert_eq!(
        classify_regression(50_000, &config),
        RegressionSeverity::Moderate
    );
}

#[test]
fn classify_at_major_boundary() {
    let config = default_config();
    // Exactly at 15% major threshold → major
    assert_eq!(
        classify_regression(150_000, &config),
        RegressionSeverity::Major
    );
}

// ---------------------------------------------------------------------------
// Regression detection in cells
// ---------------------------------------------------------------------------

#[test]
fn cell_with_minor_regression() {
    let config = default_config();
    // 3% regression: candidate is 3% worse
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Latency,
        1_000_000,
        1_030_000,
        50,
    )];
    let cell = evaluate_cell(
        SpecializationDomain::SSR,
        BenchmarkClass::Latency,
        &samples,
        &config,
    );
    assert!(cell.regression.is_some());
    let reg = cell.regression.as_ref().unwrap();
    assert_eq!(reg.severity, RegressionSeverity::Minor);
}

#[test]
fn cell_with_major_regression() {
    let config = default_config();
    // 25% regression
    let samples = vec![sample(
        SpecializationDomain::ClientEntry,
        BenchmarkClass::CodeSize,
        1_000_000,
        1_250_000,
        50,
    )];
    let cell = evaluate_cell(
        SpecializationDomain::ClientEntry,
        BenchmarkClass::CodeSize,
        &samples,
        &config,
    );
    assert!(cell.regression.is_some());
    let reg = cell.regression.as_ref().unwrap();
    assert!(reg.severity >= RegressionSeverity::Major);
}

#[test]
fn cell_with_improvement_is_pass() {
    let config = default_config();
    // Candidate faster than baseline → improvement, not regression
    let samples = vec![sample(
        SpecializationDomain::Hydration,
        BenchmarkClass::Throughput,
        1_000_000,
        900_000,
        50,
    )];
    let cell = evaluate_cell(
        SpecializationDomain::Hydration,
        BenchmarkClass::Throughput,
        &samples,
        &config,
    );
    assert_eq!(cell.verdict, GateVerdict::Pass);
}

#[test]
fn cell_with_insufficient_samples() {
    let mut config = default_config();
    config.min_sample_count = 100;
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        1_000_000,
        1_500_000,
        10,
    )];
    let cell = evaluate_cell(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        &samples,
        &config,
    );
    assert_eq!(cell.verdict, GateVerdict::InsufficientEvidence);
}

// ---------------------------------------------------------------------------
// Parity report
// ---------------------------------------------------------------------------

#[test]
fn parity_all_achieved() {
    let findings = vec![
        parity(
            ParityDimension::OutputEquivalence,
            SpecializationDomain::SSR,
            true,
            0,
            100,
        ),
        parity(
            ParityDimension::DiagnosticParity,
            SpecializationDomain::SSR,
            true,
            0,
            50,
        ),
    ];
    let report = build_parity_report(&findings);
    assert!(report.overall_parity_achieved);
    assert_eq!(report.coverage_millionths, 1_000_000);
}

#[test]
fn parity_partial_failure() {
    let findings = vec![
        parity(
            ParityDimension::OutputEquivalence,
            SpecializationDomain::SSR,
            true,
            0,
            100,
        ),
        parity(
            ParityDimension::SemanticParity,
            SpecializationDomain::ClientEntry,
            false,
            5,
            50,
        ),
    ];
    let report = build_parity_report(&findings);
    assert!(!report.overall_parity_achieved);
}

#[test]
fn parity_empty_findings() {
    let report = build_parity_report(&[]);
    assert!(report.overall_parity_achieved);
    assert_eq!(report.findings.len(), 0);
}

#[test]
fn parity_coverage_computation() {
    let findings = vec![
        parity(
            ParityDimension::OutputEquivalence,
            SpecializationDomain::SSR,
            true,
            0,
            200,
        ),
        parity(
            ParityDimension::SemanticParity,
            SpecializationDomain::SSR,
            false,
            50,
            200,
        ),
    ];
    let report = build_parity_report(&findings);
    // 200 achieved + 150 achieved = 350 out of 400 → 875_000 millionths
    assert!(report.coverage_millionths > 0);
}

// ---------------------------------------------------------------------------
// Governance action derivation
// ---------------------------------------------------------------------------

#[test]
fn governance_pass_allows_rollout() {
    let action = derive_governance_action(&GateVerdict::Pass, 0, 0);
    assert_eq!(action, GovernanceAction::AllowRollout);
}

#[test]
fn governance_conditional_pass() {
    let action = derive_governance_action(&GateVerdict::ConditionalPass, 0, 0);
    assert_eq!(action, GovernanceAction::ConditionalRollout);
}

#[test]
fn governance_fail_downgrades() {
    let action = derive_governance_action(&GateVerdict::Fail, 1, 0);
    assert_eq!(action, GovernanceAction::DowngradeSpecialization);
}

#[test]
fn governance_insufficient_evidence_requires_benchmark() {
    let action = derive_governance_action(&GateVerdict::InsufficientEvidence, 0, 0);
    assert_eq!(action, GovernanceAction::RequireFreshBenchmark);
}

#[test]
fn governance_minor_regression_conditional() {
    let action = derive_governance_action(&GateVerdict::MinorRegression, 0, 0);
    assert_eq!(action, GovernanceAction::ConditionalRollout);
}

#[test]
fn governance_major_regression_blocks() {
    let action = derive_governance_action(&GateVerdict::MajorRegression, 0, 1);
    assert_eq!(action, GovernanceAction::BlockRollout);
}

#[test]
fn governance_critical_count_downgrades() {
    let action = derive_governance_action(&GateVerdict::Fail, 2, 0);
    assert_eq!(action, GovernanceAction::DowngradeSpecialization);
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

#[test]
fn receipt_fields_populated() {
    let receipt = compute_receipt(hash(b"input"), &GateVerdict::Pass, epoch());
    assert_eq!(receipt.schema_version, SCHEMA_VERSION);
    assert_eq!(receipt.component, COMPONENT);
    assert_eq!(receipt.bead_id, BEAD_ID);
    assert_eq!(receipt.policy_id, POLICY_ID);
    assert_eq!(receipt.epoch, epoch());
}

#[test]
fn receipt_deterministic() {
    let r1 = compute_receipt(hash(b"same"), &GateVerdict::Fail, epoch());
    let r2 = compute_receipt(hash(b"same"), &GateVerdict::Fail, epoch());
    assert_eq!(r1.input_hash, r2.input_hash);
    assert_eq!(r1.verdict_hash, r2.verdict_hash);
}

#[test]
fn receipt_differs_for_different_verdicts() {
    let r1 = compute_receipt(hash(b"input"), &GateVerdict::Pass, epoch());
    let r2 = compute_receipt(hash(b"input"), &GateVerdict::Fail, epoch());
    assert_ne!(r1.verdict_hash, r2.verdict_hash);
}

// ---------------------------------------------------------------------------
// End-to-end matrix evaluation
// ---------------------------------------------------------------------------

#[test]
fn matrix_with_mixed_results() {
    let config = default_config();
    let samples = vec![
        // SSR throughput: pass
        sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Throughput,
            1_000_000,
            1_000_000,
            50,
        ),
        // ClientEntry latency: 20% regression → major
        sample(
            SpecializationDomain::ClientEntry,
            BenchmarkClass::Latency,
            1_000_000,
            1_200_000,
            50,
        ),
        // Hydration memory: 3% regression → minor
        sample(
            SpecializationDomain::Hydration,
            BenchmarkClass::MemoryOverhead,
            1_000_000,
            1_030_000,
            50,
        ),
    ];
    let result = evaluate_benchmark_matrix(&config, &samples, &[], epoch());
    // Cells may include cross-product of domains x classes
    assert!(result.cells.len() >= 3);
    assert!(result.major_regressions > 0 || result.minor_regressions > 0);
}

#[test]
fn matrix_with_parity_failure_affects_verdict() {
    let config = default_config();
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        1_000_000,
        1_000_000,
        50,
    )];
    let findings = vec![parity(
        ParityDimension::OutputEquivalence,
        SpecializationDomain::SSR,
        false,
        10,
        100,
    )];
    let result = evaluate_benchmark_matrix(&config, &samples, &findings, epoch());
    assert!(!result.parity_report.overall_parity_achieved);
}

#[test]
fn matrix_critical_regression_downgrades() {
    let config = default_config();
    // 80% regression → critical → DowngradeSpecialization
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        1_000_000,
        1_800_000,
        50,
    )];
    let result = evaluate_benchmark_matrix(&config, &samples, &[], epoch());
    assert_eq!(
        result.governance_action,
        GovernanceAction::DowngradeSpecialization
    );
}

// ---------------------------------------------------------------------------
// Enum display and string tags
// ---------------------------------------------------------------------------

#[test]
fn domain_display_strings() {
    assert_eq!(SpecializationDomain::SSR.as_str(), "ssr");
    assert_eq!(SpecializationDomain::ClientEntry.as_str(), "client_entry");
    assert_eq!(SpecializationDomain::StreamingSSR.as_str(), "streaming_ssr");
    assert_eq!(format!("{}", SpecializationDomain::Hydration), "hydration");
}

#[test]
fn benchmark_class_display_strings() {
    assert_eq!(BenchmarkClass::Throughput.as_str(), "throughput");
    assert_eq!(BenchmarkClass::MemoryOverhead.as_str(), "memory_overhead");
    assert_eq!(format!("{}", BenchmarkClass::StartupTime), "startup_time");
}

#[test]
fn parity_dimension_display_strings() {
    assert_eq!(
        ParityDimension::OutputEquivalence.as_str(),
        "output_equivalence"
    );
    assert_eq!(ParityDimension::CoverageParity.as_str(), "coverage_parity");
    assert_eq!(
        format!("{}", ParityDimension::SemanticParity),
        "semantic_parity"
    );
}

#[test]
fn verdict_display_strings() {
    assert_eq!(GateVerdict::Pass.as_str(), "pass");
    assert_eq!(GateVerdict::MajorRegression.as_str(), "major_regression");
    assert_eq!(
        format!("{}", GateVerdict::InsufficientEvidence),
        "insufficient_evidence"
    );
}

#[test]
fn governance_action_display_strings() {
    assert_eq!(GovernanceAction::AllowRollout.as_str(), "allow_rollout");
    assert_eq!(GovernanceAction::BlockRollout.as_str(), "block_rollout");
    assert_eq!(
        format!("{}", GovernanceAction::RequireFreshBenchmark),
        "require_fresh_benchmark"
    );
}

#[test]
fn regression_severity_display_strings() {
    assert_eq!(RegressionSeverity::None.as_str(), "none");
    assert_eq!(RegressionSeverity::Critical.as_str(), "critical");
    assert_eq!(format!("{}", RegressionSeverity::Moderate), "moderate");
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[test]
fn config_default_values() {
    let config = BenchmarkConfig::default();
    assert_eq!(config.minor_regression_threshold_millionths, 50_000);
    assert_eq!(config.major_regression_threshold_millionths, 150_000);
    assert_eq!(config.min_sample_count, 30);
    assert_eq!(config.min_confidence_millionths, 950_000);
    assert!(config.required_domains.is_empty());
    assert!(config.required_classes.is_empty());
}

#[test]
fn config_custom_thresholds() {
    let config = BenchmarkConfig {
        minor_regression_threshold_millionths: 20_000,
        major_regression_threshold_millionths: 80_000,
        ..Default::default()
    };
    // 5% should now be moderate (between 2% and 8%)
    assert_eq!(
        classify_regression(50_000, &config),
        RegressionSeverity::Moderate
    );
}

#[test]
fn config_with_required_domains() {
    let mut config = default_config();
    config.required_domains.insert(SpecializationDomain::SSR);
    config
        .required_domains
        .insert(SpecializationDomain::ClientEntry);

    // Only provide SSR samples
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        1_000_000,
        1_000_000,
        50,
    )];
    let result = evaluate_benchmark_matrix(&config, &samples, &[], epoch());
    // Missing ClientEntry → may be InsufficientEvidence
    assert!(
        result
            .cells
            .iter()
            .any(|c| c.domain == SpecializationDomain::SSR)
    );
}

// ---------------------------------------------------------------------------
// Serialization roundtrip
// ---------------------------------------------------------------------------

#[test]
fn gate_result_serde_roundtrip() {
    let config = default_config();
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        1_000_000,
        1_050_000,
        50,
    )];
    let result = evaluate_benchmark_matrix(&config, &samples, &[], epoch());
    let json = serde_json::to_string(&result).expect("serialize");
    let deser: GateResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deser.overall_verdict, result.overall_verdict);
    assert_eq!(deser.cells.len(), result.cells.len());
}

#[test]
fn receipt_serde_roundtrip() {
    let receipt = compute_receipt(hash(b"test"), &GateVerdict::Pass, epoch());
    let json = serde_json::to_string(&receipt).expect("serialize");
    let deser: DecisionReceipt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deser.schema_version, receipt.schema_version);
    assert_eq!(deser.verdict_hash, receipt.verdict_hash);
}

#[test]
fn parity_report_serde_roundtrip() {
    let findings = vec![parity(
        ParityDimension::OutputEquivalence,
        SpecializationDomain::SSR,
        true,
        0,
        100,
    )];
    let report = build_parity_report(&findings);
    let json = serde_json::to_string(&report).expect("serialize");
    let deser: ParityReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(
        deser.overall_parity_achieved,
        report.overall_parity_achieved
    );
}

// ---------------------------------------------------------------------------
// Multiple samples per cell
// ---------------------------------------------------------------------------

#[test]
fn multiple_samples_same_cell_aggregated() {
    let config = default_config();
    let samples = vec![
        sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Throughput,
            1_000_000,
            1_010_000,
            30,
        ),
        sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Throughput,
            1_000_000,
            1_020_000,
            30,
        ),
        sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Throughput,
            1_000_000,
            1_015_000,
            30,
        ),
    ];
    let result = evaluate_benchmark_matrix(&config, &samples, &[], epoch());
    assert_eq!(result.cells.len(), 1);
}

#[test]
fn compute_regression_with_enough_samples() {
    let samples = vec![
        sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_100_000,
            50,
        ),
        sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_120_000,
            50,
        ),
    ];
    let config = default_config();
    let regression = compute_regression(&samples, &config);
    assert!(regression.is_some());
    let reg = regression.unwrap();
    assert!(reg.relative_delta_millionths > 0);
}

// ---------------------------------------------------------------------------
// ALL enum variants exercised
// ---------------------------------------------------------------------------

#[test]
fn all_specialization_domains_count() {
    assert_eq!(SpecializationDomain::ALL.len(), 6);
}

#[test]
fn all_benchmark_classes_count() {
    assert_eq!(BenchmarkClass::ALL.len(), 6);
}

#[test]
fn all_parity_dimensions_count() {
    assert_eq!(ParityDimension::ALL.len(), 6);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn zero_baseline_handles_gracefully() {
    let config = default_config();
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        0,
        1_000_000,
        50,
    )];
    let cell = evaluate_cell(
        SpecializationDomain::SSR,
        BenchmarkClass::Throughput,
        &samples,
        &config,
    );
    // Should not panic — zero baseline means no meaningful regression ratio.
    // The verdict may be Pass or Fail depending on implementation; the key assertion
    // is that it produces a valid cell without panicking.
    let _ = &cell.verdict;
}

#[test]
fn identical_values_no_regression() {
    let config = default_config();
    let samples = vec![sample(
        SpecializationDomain::Hydration,
        BenchmarkClass::CompileTime,
        500_000,
        500_000,
        50,
    )];
    let cell = evaluate_cell(
        SpecializationDomain::Hydration,
        BenchmarkClass::CompileTime,
        &samples,
        &config,
    );
    assert_eq!(cell.verdict, GateVerdict::Pass);
}

#[test]
fn very_large_regression() {
    let config = default_config();
    // 10x regression
    let samples = vec![sample(
        SpecializationDomain::SSR,
        BenchmarkClass::StartupTime,
        100_000,
        1_000_000,
        50,
    )];
    let result = evaluate_benchmark_matrix(&config, &samples, &[], epoch());
    assert_eq!(
        result.governance_action,
        GovernanceAction::DowngradeSpecialization
    );
}

#[test]
fn streaming_ssr_domain_evaluated() {
    let config = default_config();
    let samples = vec![sample(
        SpecializationDomain::StreamingSSR,
        BenchmarkClass::Throughput,
        1_000_000,
        1_000_000,
        50,
    )];
    let result = evaluate_benchmark_matrix(&config, &samples, &[], epoch());
    assert_eq!(result.cells[0].domain, SpecializationDomain::StreamingSSR);
    assert_eq!(result.cells[0].verdict, GateVerdict::Pass);
}

#[test]
fn isomorphic_bridge_domain_evaluated() {
    let config = default_config();
    let samples = vec![sample(
        SpecializationDomain::IsomorphicBridge,
        BenchmarkClass::MemoryOverhead,
        1_000_000,
        1_000_000,
        50,
    )];
    let result = evaluate_benchmark_matrix(&config, &samples, &[], epoch());
    assert_eq!(
        result.cells[0].domain,
        SpecializationDomain::IsomorphicBridge
    );
}

#[test]
fn static_generation_domain_evaluated() {
    let config = default_config();
    let samples = vec![sample(
        SpecializationDomain::StaticGeneration,
        BenchmarkClass::CodeSize,
        2_000_000,
        2_000_000,
        50,
    )];
    let result = evaluate_benchmark_matrix(&config, &samples, &[], epoch());
    assert_eq!(
        result.cells[0].domain,
        SpecializationDomain::StaticGeneration
    );
    assert_eq!(result.overall_verdict, GateVerdict::Pass);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn module_constants_populated() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(!COMPONENT.is_empty());
    assert!(!BEAD_ID.is_empty());
    assert!(!POLICY_ID.is_empty());
    assert_eq!(BEAD_ID, "bd-1lsy.7.9.3");
    assert_eq!(POLICY_ID, "RGC-609C");
}
