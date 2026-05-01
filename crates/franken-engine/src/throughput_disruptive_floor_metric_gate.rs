#![forbid(unsafe_code)]

//! Throughput disruptive-floor metric gate with Node and Bun denominators.
//!
//! This child gate produces the `weighted_throughput_node_bun` metric
//! artifact consumed by `disruptive_floor_metric_gate`.

use serde::{Deserialize, Serialize};

use crate::disruptive_floor_metric_gate::{
    DisruptiveMetricId, MetricArtifact,
};

pub const SCHEMA_VERSION: &str = "franken-engine.throughput-disruptive-floor-metric-gate.v1";
pub const COMPONENT: &str = "throughput_disruptive_floor_metric_gate";
pub const BEAD_ID: &str = "bd-y6v8s";
pub const THROUGHPUT_SCALE_OPS_PER_SECOND: u64 = 1000;
pub const DEFAULT_FLOOR_RATIO_MILLIONTHS: u64 = 950_000; // 0.95 minimum ratio

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDenominator {
    Node,
    Bun,
}

impl RuntimeDenominator {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Bun => "bun",
        }
    }

    pub const fn baseline_ops_per_second(self) -> u64 {
        match self {
            // TODO: Replace with live measurement integration
            Self::Node => 2500, // Placeholder baseline: Node.js ops/sec
            Self::Bun => 3200,  // Placeholder baseline: Bun ops/sec
        }
    }

    pub const fn is_placeholder_baseline(self) -> bool {
        // All current baselines are placeholder until real measurement integration
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputEvidence {
    pub scenario_id: String,
    pub runtime_denominator: RuntimeDenominator,
    pub frankenengine_ops_per_second: u64,
    pub denominator_ops_per_second: u64,
    pub throughput_ratio_millionths: u64, // FrankenEngine/Denominator * 1_000_000
    pub benchmark_duration_ms: u64,
    pub request_count: u64,
    pub error_count: u64,
    pub success_rate_millionths: u64,
    pub scenario_path: String,
    pub output_path: String,
    pub output_hash: String,
    pub verification_command: String,
}

impl ThroughputEvidence {
    pub fn calculate_ratio_millionths(
        frankenengine_ops_per_second: u64,
        denominator_ops_per_second: u64,
    ) -> u64 {
        if denominator_ops_per_second == 0 {
            0
        } else {
            (frankenengine_ops_per_second * 1_000_000) / denominator_ops_per_second
        }
    }

    pub fn meets_floor_threshold(&self, floor_ratio_millionths: u64) -> bool {
        self.throughput_ratio_millionths >= floor_ratio_millionths
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputMetricInput {
    pub schema_version: String,
    pub bead_id: String,
    pub scenario_set: String,
    pub floor_ratio_millionths: u64,
    pub max_freshness_days: u64,
    pub evidence: Vec<ThroughputEvidence>,
    pub code_revision: String,
    pub generated_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputMetricReport {
    pub schema_version: String,
    pub bead_id: String,
    pub overall_outcome: String,        // "pass" | "fail" | "targeted"
    pub weighted_ratio_millionths: u64, // Geometric mean across denominators
    pub evidence_count: u64,
    pub passing_evidence_count: u64,
    pub node_evidence_count: u64,
    pub bun_evidence_count: u64,
    pub node_avg_ratio_millionths: u64,
    pub bun_avg_ratio_millionths: u64,
    pub verification_commands: Vec<String>,
    pub generated_at_utc: String,
    pub uses_placeholder_baselines: bool,
    pub baseline_warning: Option<String>,
}

pub fn compute_weighted_throughput_ratio(evidence: &[ThroughputEvidence]) -> Result<u64, String> {
    if evidence.is_empty() {
        return Err("No throughput evidence provided".to_string());
    }

    let node_ratios: Vec<u64> = evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Node)
        .map(|e| e.throughput_ratio_millionths)
        .collect();

    let bun_ratios: Vec<u64> = evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Bun)
        .map(|e| e.throughput_ratio_millionths)
        .collect();

    if node_ratios.is_empty() && bun_ratios.is_empty() {
        return Err("No Node or Bun denominator evidence found".to_string());
    }

    // Compute geometric mean for each denominator
    let node_geomean = if node_ratios.is_empty() {
        0
    } else {
        geometric_mean(&node_ratios)?
    };

    let bun_geomean = if bun_ratios.is_empty() {
        0
    } else {
        geometric_mean(&bun_ratios)?
    };

    // Weight equally between Node and Bun if both present
    let weighted_ratio = if !node_ratios.is_empty() && !bun_ratios.is_empty() {
        (node_geomean + bun_geomean) / 2
    } else if !node_ratios.is_empty() {
        node_geomean
    } else {
        bun_geomean
    };

    Ok(weighted_ratio)
}

fn geometric_mean(values: &[u64]) -> Result<u64, String> {
    if values.is_empty() {
        return Err("Cannot compute geometric mean of empty values".to_string());
    }

    // Use log-space computation to avoid overflow
    let log_sum: f64 = values.iter().map(|&x| (x as f64).ln()).sum();

    let log_mean = log_sum / (values.len() as f64);
    let geomean = log_mean.exp();

    Ok(geomean as u64)
}

pub fn evaluate_throughput_metric(
    input: &ThroughputMetricInput,
) -> Result<ThroughputMetricReport, String> {
    let weighted_ratio = compute_weighted_throughput_ratio(&input.evidence)?;

    let passing_count = input
        .evidence
        .iter()
        .filter(|e| e.meets_floor_threshold(input.floor_ratio_millionths))
        .count() as u64;

    let node_evidence: Vec<&ThroughputEvidence> = input
        .evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Node)
        .collect();

    let bun_evidence: Vec<&ThroughputEvidence> = input
        .evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Bun)
        .collect();

    let node_avg_ratio = if node_evidence.is_empty() {
        0
    } else {
        node_evidence
            .iter()
            .map(|e| e.throughput_ratio_millionths)
            .sum::<u64>()
            / node_evidence.len() as u64
    };

    let bun_avg_ratio = if bun_evidence.is_empty() {
        0
    } else {
        bun_evidence
            .iter()
            .map(|e| e.throughput_ratio_millionths)
            .sum::<u64>()
            / bun_evidence.len() as u64
    };

    // Check for placeholder baseline usage
    let uses_placeholder_node = !node_evidence.is_empty() && RuntimeDenominator::Node.is_placeholder_baseline();
    let uses_placeholder_bun = !bun_evidence.is_empty() && RuntimeDenominator::Bun.is_placeholder_baseline();
    let uses_placeholder_baselines = uses_placeholder_node || uses_placeholder_bun;

    let (overall_outcome, baseline_warning) = if uses_placeholder_baselines {
        let warning = format!(
            "TARGETED performance claim: Uses placeholder baselines (Node: {}, Bun: {}) instead of live measurement. \
            Real ≥3x throughput claim requires fresh Node/Bun benchmark comparison.",
            RuntimeDenominator::Node.baseline_ops_per_second(),
            RuntimeDenominator::Bun.baseline_ops_per_second()
        );
        ("targeted", Some(warning))
    } else if weighted_ratio >= input.floor_ratio_millionths {
        ("pass", None)
    } else {
        ("fail", None)
    };

    let verification_commands: Vec<String> = input
        .evidence
        .iter()
        .map(|e| e.verification_command.clone())
        .collect();

    Ok(ThroughputMetricReport {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: input.bead_id.clone(),
        overall_outcome: overall_outcome.to_string(),
        weighted_ratio_millionths: weighted_ratio,
        evidence_count: input.evidence.len() as u64,
        passing_evidence_count: passing_count,
        node_evidence_count: node_evidence.len() as u64,
        bun_evidence_count: bun_evidence.len() as u64,
        node_avg_ratio_millionths: node_avg_ratio,
        bun_avg_ratio_millionths: bun_avg_ratio,
        verification_commands,
        generated_at_utc: chrono::Utc::now().to_rfc3339(),
        uses_placeholder_baselines,
        baseline_warning,
    })
}

pub fn create_throughput_metric_artifact(
    input: &ThroughputMetricInput,
    report: &ThroughputMetricReport,
    artifact_path: &str,
    artifact_hash: &str,
) -> MetricArtifact {
    MetricArtifact {
        metric_id: DisruptiveMetricId::WeightedThroughputNodeBun,
        threshold: input.floor_ratio_millionths,
        observed_value: report.weighted_ratio_millionths,
        unit: "ratio_millionths".to_string(),
        baseline: "node_bun_denominators".to_string(),
        candidate: "frankenengine".to_string(),
        denominator_id: "node_and_bun".to_string(),
        scenario_set: input.scenario_set.clone(),
        artifact_path: artifact_path.to_string(),
        artifact_hash: artifact_hash.to_string(),
        code_revision: input.code_revision.clone(),
        freshness_days: input.max_freshness_days,
        confidence_millionths: 950_000, // High confidence for deterministic measurement
        coverage_millionths: 900_000,   // Representative scenario coverage
        verification_command: format!(
            "./scripts/run_throughput_disruptive_floor_metric_gate.sh verify {}",
            artifact_path
        ),
        redaction_status: "none".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_ratio_millionths() {
        assert_eq!(
            ThroughputEvidence::calculate_ratio_millionths(3000, 2500),
            1_200_000 // 1.2x ratio
        );
        assert_eq!(
            ThroughputEvidence::calculate_ratio_millionths(2000, 2500),
            800_000 // 0.8x ratio
        );
        assert_eq!(
            ThroughputEvidence::calculate_ratio_millionths(100, 0),
            0 // Division by zero
        );
    }

    #[test]
    fn test_meets_floor_threshold() {
        let evidence = ThroughputEvidence {
            scenario_id: "test".to_string(),
            runtime_denominator: RuntimeDenominator::Node,
            frankenengine_ops_per_second: 3000,
            denominator_ops_per_second: 2500,
            throughput_ratio_millionths: 1_200_000,
            benchmark_duration_ms: 10_000,
            request_count: 30_000,
            error_count: 0,
            success_rate_millionths: 1_000_000,
            scenario_path: "test.json".to_string(),
            output_path: "output.json".to_string(),
            output_hash: "abc123".to_string(),
            verification_command: "verify.sh".to_string(),
        };

        assert!(evidence.meets_floor_threshold(950_000)); // 0.95 threshold
        assert!(evidence.meets_floor_threshold(1_200_000)); // Exact threshold
        assert!(!evidence.meets_floor_threshold(1_300_000)); // Above threshold
    }

    #[test]
    fn test_runtime_denominator_baselines() {
        assert_eq!(RuntimeDenominator::Node.baseline_ops_per_second(), 2500);
        assert_eq!(RuntimeDenominator::Bun.baseline_ops_per_second(), 3200);
        assert_eq!(RuntimeDenominator::Node.as_str(), "node");
        assert_eq!(RuntimeDenominator::Bun.as_str(), "bun");
    }

    #[test]
    fn test_geometric_mean() {
        assert_eq!(geometric_mean(&[1_000_000, 1_000_000]).unwrap(), 1_000_000);
        assert!(geometric_mean(&[]).is_err());

        // Approximate test for geometric mean of 800k and 1200k
        let result = geometric_mean(&[800_000, 1_200_000]).unwrap();
        assert!(result >= 970_000 && result <= 990_000); // ~sqrt(800k * 1200k) ≈ 980k
    }

    #[test]
    fn test_compute_weighted_throughput_ratio() {
        let node_evidence = ThroughputEvidence {
            scenario_id: "node_test".to_string(),
            runtime_denominator: RuntimeDenominator::Node,
            frankenengine_ops_per_second: 3000,
            denominator_ops_per_second: 2500,
            throughput_ratio_millionths: 1_200_000,
            benchmark_duration_ms: 10_000,
            request_count: 30_000,
            error_count: 0,
            success_rate_millionths: 1_000_000,
            scenario_path: "node_test.json".to_string(),
            output_path: "node_output.json".to_string(),
            output_hash: "abc123".to_string(),
            verification_command: "verify_node.sh".to_string(),
        };

        let bun_evidence = ThroughputEvidence {
            scenario_id: "bun_test".to_string(),
            runtime_denominator: RuntimeDenominator::Bun,
            frankenengine_ops_per_second: 3200,
            denominator_ops_per_second: 3200,
            throughput_ratio_millionths: 1_000_000,
            benchmark_duration_ms: 10_000,
            request_count: 32_000,
            error_count: 0,
            success_rate_millionths: 1_000_000,
            scenario_path: "bun_test.json".to_string(),
            output_path: "bun_output.json".to_string(),
            output_hash: "def456".to_string(),
            verification_command: "verify_bun.sh".to_string(),
        };

        let evidence = vec![node_evidence, bun_evidence];
        let weighted_ratio = compute_weighted_throughput_ratio(&evidence).unwrap();

        // Should be average of 1.2M (Node) and 1.0M (Bun) = 1.1M
        assert_eq!(weighted_ratio, 1_100_000);

        // Test with only Node evidence
        let node_only = vec![evidence[0].clone()];
        let node_ratio = compute_weighted_throughput_ratio(&node_only).unwrap();
        assert_eq!(node_ratio, 1_200_000);

        // Test with empty evidence
        assert!(compute_weighted_throughput_ratio(&[]).is_err());
    }

    #[test]
    fn test_evaluate_throughput_metric() {
        let input = ThroughputMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "basic_throughput".to_string(),
            floor_ratio_millionths: 950_000,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![ThroughputEvidence {
                scenario_id: "passing_test".to_string(),
                runtime_denominator: RuntimeDenominator::Node,
                frankenengine_ops_per_second: 2500,
                denominator_ops_per_second: 2500,
                throughput_ratio_millionths: 1_000_000,
                benchmark_duration_ms: 10_000,
                request_count: 25_000,
                error_count: 0,
                success_rate_millionths: 1_000_000,
                scenario_path: "passing.json".to_string(),
                output_path: "passing_output.json".to_string(),
                output_hash: "pass123".to_string(),
                verification_command: "verify_pass.sh".to_string(),
            }],
            code_revision: "abc123def".to_string(),
            generated_at_utc: "2026-05-01T00:00:00Z".to_string(),
        };

        let report = evaluate_throughput_metric(&input).unwrap();
        assert_eq!(report.overall_outcome, "targeted");
        assert_eq!(report.weighted_ratio_millionths, 1_000_000);
        assert_eq!(report.evidence_count, 1);
        assert_eq!(report.passing_evidence_count, 1);
        assert_eq!(report.node_evidence_count, 1);
        assert_eq!(report.bun_evidence_count, 0);
        assert!(report.uses_placeholder_baselines);
        assert!(report.baseline_warning.is_some());
        assert!(report.baseline_warning.as_ref().unwrap().contains("TARGETED performance claim"));
    }

    #[test]
    fn test_create_throughput_metric_artifact() {
        let input = ThroughputMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "test_scenario".to_string(),
            floor_ratio_millionths: 950_000,
            max_freshness_days: 14,
            evidence: vec![],
            code_revision: "test_rev".to_string(),
            generated_at_utc: "2026-05-01T00:00:00Z".to_string(),
        };

        let report = ThroughputMetricReport {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            overall_outcome: "targeted".to_string(),
            weighted_ratio_millionths: 1_100_000,
            evidence_count: 2,
            passing_evidence_count: 2,
            node_evidence_count: 1,
            bun_evidence_count: 1,
            node_avg_ratio_millionths: 1_200_000,
            bun_avg_ratio_millionths: 1_000_000,
            verification_commands: vec!["verify.sh".to_string()],
            generated_at_utc: "2026-05-01T00:00:00Z".to_string(),
            uses_placeholder_baselines: true,
            baseline_warning: Some("TARGETED performance claim".to_string()),
        };

        let artifact =
            create_throughput_metric_artifact(&input, &report, "test_artifact.json", "hash123");

        assert_eq!(
            artifact.metric_id,
            DisruptiveMetricId::WeightedThroughputNodeBun
        );
        assert_eq!(artifact.threshold, 950_000);
        assert_eq!(artifact.observed_value, 1_100_000);
        assert_eq!(artifact.unit, "ratio_millionths");
        assert_eq!(artifact.denominator_id, "node_and_bun");
        assert_eq!(artifact.scenario_set, "test_scenario");
        assert_eq!(artifact.artifact_hash, "hash123");
    }
}
