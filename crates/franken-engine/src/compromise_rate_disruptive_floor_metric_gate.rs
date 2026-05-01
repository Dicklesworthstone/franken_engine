#![forbid(unsafe_code)]

//! Red-team compromise-rate disruptive-floor metric gate with baseline comparison.
//!
//! This child gate produces the `compromise_rate_reduction` metric
//! artifact consumed by `disruptive_floor_metric_gate`.

use serde::{Deserialize, Serialize};

use crate::disruptive_floor_metric_gate::{
    DEFAULT_MAX_FRESHNESS_DAYS, DisruptiveMetricId, MetricArtifact,
};
use crate::proof_artifact::validate_sha256;

pub const SCHEMA_VERSION: &str = "franken-engine.compromise-rate-disruptive-floor-metric-gate.v1";
pub const COMPONENT: &str = "compromise_rate_disruptive_floor_metric_gate";
pub const BEAD_ID: &str = "bd-1vwza";
pub const DEFAULT_REDUCTION_THRESHOLD_FACTOR: u64 = 10; // >=10x reduction claim

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

    pub const fn baseline_compromise_rate_millionths(self) -> u64 {
        match self {
            // TODO: Replace with live red-team measurement integration
            Self::Node => 850_000,  // Placeholder: 85% compromise rate for Node baseline
            Self::Bun => 750_000,   // Placeholder: 75% compromise rate for Bun baseline
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompromiseRateEvidence {
    pub scenario_id: String,
    pub runtime_denominator: RuntimeDenominator,
    pub baseline_posture: String,
    pub frankenengine_posture: String,
    pub trial_count: u64,
    pub baseline_compromises: u64,
    pub frankenengine_compromises: u64,
    pub baseline_compromise_rate_millionths: u64,
    pub frankenengine_compromise_rate_millionths: u64,
    pub reduction_ratio_millionths: u64, // baseline_rate/frankenengine_rate * 1_000_000
    pub scenario_path: String,
    pub output_path: String,
    pub output_hash: String,
    pub verification_command: String,
    pub success_criteria: String,
    pub reproducibility_command: String,
}

impl CompromiseRateEvidence {
    pub fn calculate_compromise_rate_millionths(compromises: u64, trials: u64) -> u64 {
        if trials == 0 {
            0
        } else {
            (compromises * 1_000_000) / trials
        }
    }

    pub fn calculate_reduction_ratio_millionths(
        baseline_rate_millionths: u64,
        frankenengine_rate_millionths: u64,
    ) -> u64 {
        if frankenengine_rate_millionths == 0 {
            // Perfect security - infinite reduction
            u64::MAX
        } else {
            (baseline_rate_millionths * 1_000_000) / frankenengine_rate_millionths
        }
    }

    pub fn meets_reduction_threshold(&self, threshold_factor: u64) -> bool {
        self.reduction_ratio_millionths >= (threshold_factor * 1_000_000)
    }

    pub fn new(
        scenario_id: String,
        runtime_denominator: RuntimeDenominator,
        baseline_posture: String,
        frankenengine_posture: String,
        trial_count: u64,
        baseline_compromises: u64,
        frankenengine_compromises: u64,
        scenario_path: String,
        output_path: String,
        output_hash: String,
        verification_command: String,
        success_criteria: String,
        reproducibility_command: String,
    ) -> Self {
        let baseline_compromise_rate_millionths =
            Self::calculate_compromise_rate_millionths(baseline_compromises, trial_count);
        let frankenengine_compromise_rate_millionths =
            Self::calculate_compromise_rate_millionths(frankenengine_compromises, trial_count);
        let reduction_ratio_millionths = Self::calculate_reduction_ratio_millionths(
            baseline_compromise_rate_millionths,
            frankenengine_compromise_rate_millionths,
        );

        Self {
            scenario_id,
            runtime_denominator,
            baseline_posture,
            frankenengine_posture,
            trial_count,
            baseline_compromises,
            frankenengine_compromises,
            baseline_compromise_rate_millionths,
            frankenengine_compromise_rate_millionths,
            reduction_ratio_millionths,
            scenario_path,
            output_path,
            output_hash,
            verification_command,
            success_criteria,
            reproducibility_command,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompromiseRateMetricInput {
    pub schema_version: String,
    pub bead_id: String,
    pub scenario_set: String,
    pub reduction_threshold_factor: u64,
    pub max_freshness_days: u64,
    pub evidence: Vec<CompromiseRateEvidence>,
    pub code_revision: String,
    pub generated_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompromiseRateMetricReport {
    pub schema_version: String,
    pub bead_id: String,
    pub overall_outcome: String,                    // "pass" | "fail"
    pub weighted_reduction_ratio_millionths: u64,  // Geometric mean across denominators
    pub evidence_count: u64,
    pub passing_evidence_count: u64,
    pub node_evidence_count: u64,
    pub bun_evidence_count: u64,
    pub node_reduction_ratio_millionths: u64,
    pub bun_reduction_ratio_millionths: u64,
    pub threshold_factor: u64,
    pub uncertainty_notes: String,
    pub coverage_notes: String,
    pub scenario_set: String,
    pub code_revision: String,
    pub generated_at_utc: String,
}

pub fn compute_weighted_geometric_mean_reduction(evidence: &[CompromiseRateEvidence]) -> u64 {
    if evidence.is_empty() {
        return 0;
    }

    // Separate by runtime denominator
    let node_evidence: Vec<_> = evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Node)
        .collect();
    let bun_evidence: Vec<_> = evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Bun)
        .collect();

    let node_mean = if node_evidence.is_empty() {
        1_000_000 // 1x reduction if no evidence
    } else {
        geometric_mean_reduction(&node_evidence)
    };

    let bun_mean = if bun_evidence.is_empty() {
        1_000_000 // 1x reduction if no evidence
    } else {
        geometric_mean_reduction(&bun_evidence)
    };

    // Weighted geometric mean of the two denominators
    geometric_mean_of_two(node_mean, bun_mean)
}

fn geometric_mean_reduction(evidence: &[&CompromiseRateEvidence]) -> u64 {
    if evidence.is_empty() {
        return 1_000_000;
    }

    let mut product_log_sum = 0.0;
    for e in evidence {
        let ratio = e.reduction_ratio_millionths as f64 / 1_000_000.0;
        if ratio > 0.0 {
            product_log_sum += ratio.ln();
        }
    }

    let mean_log = product_log_sum / evidence.len() as f64;
    let geometric_mean = mean_log.exp();

    // Convert back to millionths with deterministic rounding
    (geometric_mean * 1_000_000.0).round() as u64
}

fn geometric_mean_of_two(a: u64, b: u64) -> u64 {
    let a_f = a as f64 / 1_000_000.0;
    let b_f = b as f64 / 1_000_000.0;

    if a_f <= 0.0 || b_f <= 0.0 {
        return 0;
    }

    let geometric_mean = (a_f * b_f).sqrt();
    (geometric_mean * 1_000_000.0).round() as u64
}

pub fn analyze_compromise_rate_metric_input(
    input: &CompromiseRateMetricInput,
) -> Result<CompromiseRateMetricReport, String> {
    if input.evidence.is_empty() {
        return Err("No evidence provided".to_string());
    }

    // Validate scenario set consistency
    let first_scenario_set = &input.scenario_set;
    for evidence in &input.evidence {
        // Additional validation could be added here
        if evidence.trial_count == 0 {
            return Err(format!(
                "Invalid trial count 0 for scenario {}",
                evidence.scenario_id
            ));
        }
    }

    let weighted_reduction_ratio = compute_weighted_geometric_mean_reduction(&input.evidence);

    // Count by denominator
    let node_count = input
        .evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Node)
        .count() as u64;
    let bun_count = input
        .evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Bun)
        .count() as u64;

    // Calculate denominator-specific reduction ratios
    let node_evidence: Vec<_> = input
        .evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Node)
        .collect();
    let node_reduction_ratio = if node_evidence.is_empty() {
        1_000_000
    } else {
        geometric_mean_reduction(&node_evidence)
    };

    let bun_evidence: Vec<_> = input
        .evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Bun)
        .collect();
    let bun_reduction_ratio = if bun_evidence.is_empty() {
        1_000_000
    } else {
        geometric_mean_reduction(&bun_evidence)
    };

    // Count passing evidence
    let passing_count = input
        .evidence
        .iter()
        .filter(|e| e.meets_reduction_threshold(input.reduction_threshold_factor))
        .count() as u64;

    // Determine overall outcome
    let required_reduction_millionths = input.reduction_threshold_factor * 1_000_000;
    let overall_outcome = if weighted_reduction_ratio >= required_reduction_millionths {
        "pass"
    } else {
        "fail"
    };

    let uncertainty_notes = format!(
        "Baseline measurements TODO: live integration. Geometric mean across {} scenarios.",
        input.evidence.len()
    );

    let coverage_notes = format!(
        "Coverage: {} Node, {} Bun scenarios. Threshold: {}x reduction.",
        node_count, bun_count, input.reduction_threshold_factor
    );

    Ok(CompromiseRateMetricReport {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: input.bead_id.clone(),
        overall_outcome: overall_outcome.to_string(),
        weighted_reduction_ratio_millionths: weighted_reduction_ratio,
        evidence_count: input.evidence.len() as u64,
        passing_evidence_count: passing_count,
        node_evidence_count: node_count,
        bun_evidence_count: bun_count,
        node_reduction_ratio_millionths: node_reduction_ratio,
        bun_reduction_ratio_millionths: bun_reduction_ratio,
        threshold_factor: input.reduction_threshold_factor,
        uncertainty_notes,
        coverage_notes,
        scenario_set: input.scenario_set.clone(),
        code_revision: input.code_revision.clone(),
        generated_at_utc: input.generated_at_utc.clone(),
    })
}

pub fn generate_compromise_rate_metric_artifact(
    input: &CompromiseRateMetricInput,
) -> Result<MetricArtifact, String> {
    let report = analyze_compromise_rate_metric_input(input)?;

    Ok(MetricArtifact {
        metric_id: DisruptiveMetricId::RedTeamCompromiseRateReduction,
        outcome: report.overall_outcome,
        value_millionths: report.weighted_reduction_ratio_millionths,
        confidence_millionths: 950_000, // 95% confidence placeholder
        coverage_millionths: 900_000,   // 90% coverage placeholder
        freshness_days: 0,              // TODO: Calculate from timestamps
        threshold_millionths: report.threshold_factor * 1_000_000,
        artifact_hash: "TODO".to_string(), // TODO: Compute from actual artifacts
        generated_at_utc: input.generated_at_utc.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_compromise_rate_millionths() {
        assert_eq!(
            CompromiseRateEvidence::calculate_compromise_rate_millionths(85, 100),
            850_000
        );
        assert_eq!(
            CompromiseRateEvidence::calculate_compromise_rate_millionths(0, 100),
            0
        );
        assert_eq!(
            CompromiseRateEvidence::calculate_compromise_rate_millionths(100, 0),
            0
        );
    }

    #[test]
    fn test_calculate_reduction_ratio_millionths() {
        // 10x reduction: 80% -> 8%
        assert_eq!(
            CompromiseRateEvidence::calculate_reduction_ratio_millionths(800_000, 80_000),
            10_000_000
        );

        // Perfect security (0% compromise rate)
        assert_eq!(
            CompromiseRateEvidence::calculate_reduction_ratio_millionths(800_000, 0),
            u64::MAX
        );

        // No reduction (same rates)
        assert_eq!(
            CompromiseRateEvidence::calculate_reduction_ratio_millionths(800_000, 800_000),
            1_000_000
        );
    }

    #[test]
    fn test_meets_reduction_threshold() {
        let evidence = CompromiseRateEvidence::new(
            "test_scenario".to_string(),
            RuntimeDenominator::Node,
            "default".to_string(),
            "frankenengine".to_string(),
            100,
            80, // 80% baseline
            8,  // 8% frankenengine (10x reduction)
            "test_path".to_string(),
            "output_path".to_string(),
            "hash123".to_string(),
            "verify_cmd".to_string(),
            "host_compromise".to_string(),
            "repro_cmd".to_string(),
        );

        assert!(evidence.meets_reduction_threshold(10)); // Meets 10x threshold
        assert!(!evidence.meets_reduction_threshold(11)); // Doesn't meet 11x threshold
    }

    #[test]
    fn test_geometric_mean_reduction_empty() {
        assert_eq!(geometric_mean_reduction(&[]), 1_000_000);
    }

    #[test]
    fn test_geometric_mean_reduction_single() {
        let evidence = CompromiseRateEvidence::new(
            "test".to_string(),
            RuntimeDenominator::Node,
            "default".to_string(),
            "frankenengine".to_string(),
            100,
            80,
            8,
            "path".to_string(),
            "output".to_string(),
            "hash".to_string(),
            "verify".to_string(),
            "criteria".to_string(),
            "repro".to_string(),
        );

        let result = geometric_mean_reduction(&[&evidence]);
        assert_eq!(result, 10_000_000); // 10x reduction
    }

    #[test]
    fn test_analyze_compromise_rate_metric_input_empty() {
        let input = CompromiseRateMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "test_set".to_string(),
            reduction_threshold_factor: 10,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![],
            code_revision: "abc123".to_string(),
            generated_at_utc: "2026-05-01T05:00:00Z".to_string(),
        };

        assert!(analyze_compromise_rate_metric_input(&input).is_err());
    }

    #[test]
    fn test_analyze_compromise_rate_metric_input_passing() {
        let evidence = CompromiseRateEvidence::new(
            "scenario_1".to_string(),
            RuntimeDenominator::Node,
            "default_posture".to_string(),
            "frankenengine_posture".to_string(),
            100,
            80, // 80% baseline compromise rate
            4,  // 4% frankenengine rate (20x reduction)
            "scenario_path".to_string(),
            "output_path".to_string(),
            "output_hash".to_string(),
            "verify_cmd".to_string(),
            "host_compromise".to_string(),
            "repro_cmd".to_string(),
        );

        let input = CompromiseRateMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "red_team_v1".to_string(),
            reduction_threshold_factor: 10,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![evidence],
            code_revision: "abc123".to_string(),
            generated_at_utc: "2026-05-01T05:00:00Z".to_string(),
        };

        let report = analyze_compromise_rate_metric_input(&input).unwrap();
        assert_eq!(report.overall_outcome, "pass");
        assert_eq!(report.evidence_count, 1);
        assert_eq!(report.passing_evidence_count, 1);
        assert!(report.weighted_reduction_ratio_millionths >= 10_000_000);
    }

    #[test]
    fn test_analyze_compromise_rate_metric_input_failing() {
        let evidence = CompromiseRateEvidence::new(
            "scenario_1".to_string(),
            RuntimeDenominator::Node,
            "default_posture".to_string(),
            "frankenengine_posture".to_string(),
            100,
            80, // 80% baseline
            40, // 40% frankenengine (2x reduction - fails 10x threshold)
            "scenario_path".to_string(),
            "output_path".to_string(),
            "output_hash".to_string(),
            "verify_cmd".to_string(),
            "host_compromise".to_string(),
            "repro_cmd".to_string(),
        );

        let input = CompromiseRateMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "red_team_v1".to_string(),
            reduction_threshold_factor: 10,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![evidence],
            code_revision: "abc123".to_string(),
            generated_at_utc: "2026-05-01T05:00:00Z".to_string(),
        };

        let report = analyze_compromise_rate_metric_input(&input).unwrap();
        assert_eq!(report.overall_outcome, "fail");
        assert_eq!(report.passing_evidence_count, 0);
    }

    #[test]
    fn test_zero_trial_count_rejection() {
        let evidence = CompromiseRateEvidence::new(
            "scenario_1".to_string(),
            RuntimeDenominator::Node,
            "default_posture".to_string(),
            "frankenengine_posture".to_string(),
            0, // Invalid trial count
            0,
            0,
            "scenario_path".to_string(),
            "output_path".to_string(),
            "output_hash".to_string(),
            "verify_cmd".to_string(),
            "host_compromise".to_string(),
            "repro_cmd".to_string(),
        );

        let input = CompromiseRateMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "red_team_v1".to_string(),
            reduction_threshold_factor: 10,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![evidence],
            code_revision: "abc123".to_string(),
            generated_at_utc: "2026-05-01T05:00:00Z".to_string(),
        };

        assert!(analyze_compromise_rate_metric_input(&input).is_err());
    }
}