//! Integration tests for compromise rate disruptive-floor metric gate.
//!
//! Verifies the red-team compromise-rate metric calculation and reduction analysis
//! for security evaluation against Node.js and Bun baselines.

#![forbid(unsafe_code)]

use frankenengine_engine::compromise_rate_disruptive_floor_metric_gate::{
    analyze_compromise_rate_metric_input, generate_compromise_rate_metric_artifact,
    CompromiseRateEvidence, CompromiseRateMetricInput, RuntimeDenominator, BEAD_ID,
    DEFAULT_REDUCTION_THRESHOLD_FACTOR, SCHEMA_VERSION,
};
use frankenengine_engine::disruptive_floor_metric_gate::{
    DisruptiveMetricId, DEFAULT_MAX_FRESHNESS_DAYS,
};
use serde_json;
use std::path::PathBuf;

const FIXTURE_PATH: &str = "tests/fixtures/compromise_rate_disruptive_floor_metric_input_v1.json";

#[test]
fn test_compromise_rate_metric_fixture_loads() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_PATH);
    let fixture_content = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|_| panic!("Could not read fixture: {}", fixture_path.display()));

    let input: CompromiseRateMetricInput = serde_json::from_str(&fixture_content)
        .unwrap_or_else(|e| panic!("Failed to parse fixture: {}", e));

    assert_eq!(input.schema_version, SCHEMA_VERSION);
    assert_eq!(input.bead_id, BEAD_ID);
    assert!(!input.evidence.is_empty());
    assert_eq!(input.reduction_threshold_factor, DEFAULT_REDUCTION_THRESHOLD_FACTOR);
}

#[test]
fn test_compromise_rate_metric_analysis() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_PATH);
    let fixture_content = std::fs::read_to_string(&fixture_path)
        .expect("Could not read compromise rate fixture");

    let input: CompromiseRateMetricInput = serde_json::from_str(&fixture_content)
        .expect("Failed to parse compromise rate fixture");

    let report = analyze_compromise_rate_metric_input(&input)
        .expect("Failed to analyze compromise rate input");

    assert_eq!(report.schema_version, SCHEMA_VERSION);
    assert_eq!(report.bead_id, BEAD_ID);
    assert!(report.overall_outcome == "pass" || report.overall_outcome == "fail");
    assert_eq!(report.evidence_count, input.evidence.len() as u64);
    assert!(report.weighted_reduction_ratio_millionths > 0);
    assert_eq!(report.threshold_factor, DEFAULT_REDUCTION_THRESHOLD_FACTOR);
}

#[test]
fn test_compromise_rate_metric_artifact_generation() {
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_PATH);
    let fixture_content = std::fs::read_to_string(&fixture_path)
        .expect("Could not read compromise rate fixture");

    let input: CompromiseRateMetricInput = serde_json::from_str(&fixture_content)
        .expect("Failed to parse compromise rate fixture");

    let artifact = generate_compromise_rate_metric_artifact(&input)
        .expect("Failed to generate compromise rate artifact");

    assert_eq!(artifact.metric_id, DisruptiveMetricId::RedTeamCompromiseRateReduction);
    assert!(artifact.outcome == "pass" || artifact.outcome == "fail");
    assert!(artifact.value_millionths > 0);
    assert!(artifact.confidence_millionths > 0);
    assert!(artifact.coverage_millionths > 0);
    assert_eq!(
        artifact.threshold_millionths,
        DEFAULT_REDUCTION_THRESHOLD_FACTOR * 1_000_000
    );
}

#[test]
fn test_compromise_rate_evidence_validation() {
    let evidence = CompromiseRateEvidence::new(
        "phishing_email_scenario".to_string(),
        RuntimeDenominator::Node,
        "node_default_security".to_string(),
        "frankenengine_hardened".to_string(),
        1000, // 1000 trials
        850,  // 850 compromises in baseline (85%)
        85,   // 85 compromises in FrankenEngine (8.5% = 10x reduction)
        "/test/scenarios/phishing_email".to_string(),
        "/test/output/phishing_results.json".to_string(),
        "sha256:abc123def456".to_string(),
        "verify_compromise_results.sh".to_string(),
        "host_compromise_within_24h".to_string(),
        "run_phishing_campaign.sh --target-count 1000".to_string(),
    );

    assert_eq!(evidence.baseline_compromise_rate_millionths, 850_000); // 85%
    assert_eq!(evidence.frankenengine_compromise_rate_millionths, 85_000); // 8.5%
    assert_eq!(evidence.reduction_ratio_millionths, 10_000_000); // 10x reduction
    assert!(evidence.meets_reduction_threshold(10)); // Meets 10x threshold
}

#[test]
fn test_compromise_rate_denominator_specific_analysis() {
    let node_evidence = CompromiseRateEvidence::new(
        "node_scenario".to_string(),
        RuntimeDenominator::Node,
        "node_baseline".to_string(),
        "frankenengine".to_string(),
        100,
        80, // 80% compromise rate
        8,  // 8% compromise rate (10x reduction)
        "node_path".to_string(),
        "node_output".to_string(),
        "node_hash".to_string(),
        "node_verify".to_string(),
        "host_compromise".to_string(),
        "node_repro".to_string(),
    );

    let bun_evidence = CompromiseRateEvidence::new(
        "bun_scenario".to_string(),
        RuntimeDenominator::Bun,
        "bun_baseline".to_string(),
        "frankenengine".to_string(),
        100,
        75, // 75% compromise rate
        3,  // 3% compromise rate (25x reduction)
        "bun_path".to_string(),
        "bun_output".to_string(),
        "bun_hash".to_string(),
        "bun_verify".to_string(),
        "host_compromise".to_string(),
        "bun_repro".to_string(),
    );

    let input = CompromiseRateMetricInput {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        scenario_set: "security_evaluation_v1".to_string(),
        reduction_threshold_factor: DEFAULT_REDUCTION_THRESHOLD_FACTOR,
        max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
        evidence: vec![node_evidence, bun_evidence],
        code_revision: "test123".to_string(),
        generated_at_utc: "2026-05-01T05:00:00Z".to_string(),
    };

    let report = analyze_compromise_rate_metric_input(&input)
        .expect("Failed to analyze mixed denominator input");

    assert_eq!(report.node_evidence_count, 1);
    assert_eq!(report.bun_evidence_count, 1);
    assert_eq!(report.evidence_count, 2);
    assert_eq!(report.passing_evidence_count, 2); // Both should pass 10x threshold
    assert_eq!(report.overall_outcome, "pass");

    // Verify denominator-specific reduction ratios
    assert_eq!(report.node_reduction_ratio_millionths, 10_000_000); // 10x
    assert_eq!(report.bun_reduction_ratio_millionths, 25_000_000); // 25x

    // Weighted geometric mean should be sqrt(10 * 25) = sqrt(250) ≈ 15.81
    assert!(report.weighted_reduction_ratio_millionths >= 15_000_000);
    assert!(report.weighted_reduction_ratio_millionths <= 16_000_000);
}

#[test]
fn test_compromise_rate_edge_cases() {
    // Test perfect security (0 compromises)
    let perfect_evidence = CompromiseRateEvidence::new(
        "perfect_scenario".to_string(),
        RuntimeDenominator::Node,
        "vulnerable_baseline".to_string(),
        "perfect_frankenengine".to_string(),
        100,
        80, // 80% baseline
        0,  // 0% frankenengine (perfect security)
        "perfect_path".to_string(),
        "perfect_output".to_string(),
        "perfect_hash".to_string(),
        "perfect_verify".to_string(),
        "no_compromise".to_string(),
        "perfect_repro".to_string(),
    );

    assert_eq!(perfect_evidence.frankenengine_compromise_rate_millionths, 0);
    assert_eq!(perfect_evidence.reduction_ratio_millionths, u64::MAX); // Infinite reduction
    assert!(perfect_evidence.meets_reduction_threshold(1000)); // Exceeds any threshold

    // Test baseline with 0 compromises (edge case)
    let zero_baseline_evidence = CompromiseRateEvidence::new(
        "zero_baseline".to_string(),
        RuntimeDenominator::Bun,
        "secure_baseline".to_string(),
        "frankenengine".to_string(),
        100,
        0, // 0% baseline
        0, // 0% frankenengine
        "zero_path".to_string(),
        "zero_output".to_string(),
        "zero_hash".to_string(),
        "zero_verify".to_string(),
        "no_baseline_compromise".to_string(),
        "zero_repro".to_string(),
    );

    assert_eq!(zero_baseline_evidence.baseline_compromise_rate_millionths, 0);
    assert_eq!(zero_baseline_evidence.frankenengine_compromise_rate_millionths, 0);
    // When both are 0, reduction ratio should be 1x (no improvement needed)
    assert_eq!(zero_baseline_evidence.reduction_ratio_millionths, 1_000_000);
}

#[test]
fn test_compromise_rate_insufficient_reduction() {
    let insufficient_evidence = CompromiseRateEvidence::new(
        "insufficient_scenario".to_string(),
        RuntimeDenominator::Node,
        "baseline".to_string(),
        "frankenengine".to_string(),
        100,
        80, // 80% baseline
        50, // 50% frankenengine (1.6x reduction - insufficient)
        "insufficient_path".to_string(),
        "insufficient_output".to_string(),
        "insufficient_hash".to_string(),
        "insufficient_verify".to_string(),
        "partial_compromise".to_string(),
        "insufficient_repro".to_string(),
    );

    let input = CompromiseRateMetricInput {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        scenario_set: "insufficient_test".to_string(),
        reduction_threshold_factor: DEFAULT_REDUCTION_THRESHOLD_FACTOR,
        max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
        evidence: vec![insufficient_evidence],
        code_revision: "test123".to_string(),
        generated_at_utc: "2026-05-01T05:00:00Z".to_string(),
    };

    let report = analyze_compromise_rate_metric_input(&input)
        .expect("Failed to analyze insufficient reduction input");

    assert_eq!(report.overall_outcome, "fail");
    assert_eq!(report.passing_evidence_count, 0);
    assert!(report.weighted_reduction_ratio_millionths < 10_000_000); // Below 10x threshold
}

#[test]
fn test_parent_child_bead_relationship() {
    // This test verifies that the compromise rate metric integrates with the parent disruptive floor gate
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_PATH);
    let fixture_content = std::fs::read_to_string(&fixture_path)
        .expect("Could not read compromise rate fixture");

    let input: CompromiseRateMetricInput = serde_json::from_str(&fixture_content)
        .expect("Failed to parse compromise rate fixture");

    // Verify parent bead integration
    assert_eq!(input.bead_id, BEAD_ID); // Child bead ID
    assert_eq!(
        input.reduction_threshold_factor,
        DEFAULT_REDUCTION_THRESHOLD_FACTOR
    ); // 10x reduction claim

    // Generate artifact for parent consumption
    let artifact = generate_compromise_rate_metric_artifact(&input)
        .expect("Failed to generate artifact for parent");

    assert_eq!(artifact.metric_id, DisruptiveMetricId::RedTeamCompromiseRateReduction);
    assert!(artifact.value_millionths >= 1_000_000); // At least 1x reduction
    assert_eq!(
        artifact.threshold_millionths,
        DEFAULT_REDUCTION_THRESHOLD_FACTOR * 1_000_000
    );

    // Verify artifact can be consumed by parent gate
    let artifact_json = serde_json::to_string(&artifact)
        .expect("Failed to serialize artifact for parent consumption");
    assert!(!artifact_json.is_empty());

    // Parse back to verify schema compatibility
    let parsed_artifact: frankenengine_engine::disruptive_floor_metric_gate::MetricArtifact =
        serde_json::from_str(&artifact_json)
            .expect("Failed to parse artifact - schema incompatibility");

    assert_eq!(parsed_artifact.metric_id, artifact.metric_id);
    assert_eq!(parsed_artifact.outcome, artifact.outcome);
    assert_eq!(parsed_artifact.value_millionths, artifact.value_millionths);
}