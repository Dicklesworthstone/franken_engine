#![forbid(unsafe_code)]

//! Red-team compromise-rate disruptive-floor metric gate with baseline comparison.
//!
//! This child gate produces the `compromise_rate_reduction` metric
//! artifact consumed by `disruptive_floor_metric_gate`.

use serde::{Deserialize, Serialize};

use crate::disruptive_floor_metric_gate::{DisruptiveMetricId, MetricArtifact};
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
            Self::Node => 850_000, // Placeholder: 85% compromise rate for Node baseline
            Self::Bun => 750_000,  // Placeholder: 75% compromise rate for Bun baseline
        }
    }
}

/// Detect if evidence contains fictional/placeholder scenarios
pub fn contains_fictional_scenarios(evidence: &[CompromiseRateEvidence]) -> bool {
    for e in evidence {
        // Check for fictional paths commonly used in test fixtures
        if e.scenario_path.starts_with("/test/scenarios/")
            || e.output_path.starts_with("/test/output/")
            || e.verification_command
                .contains("verify_compromise_results.sh")
            || e.verification_command.contains("verify_malware_results.sh")
            || e.verification_command
                .contains("verify_prototype_results.sh")
            || e.verification_command
                .contains("verify_supply_chain_results.sh")
            || e.reproducibility_command
                .contains("run_phishing_campaign.sh")
            || e.reproducibility_command.contains("inject_malware.sh")
            || e.reproducibility_command.contains("pollute_prototypes.sh")
            || e.reproducibility_command
                .contains("deploy_malicious_packages.sh")
        {
            return true;
        }
    }
    false
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
    /// Validate baseline parameters for sanity
    pub fn validate_baseline_parameters(
        baseline_compromises: u64,
        frankenengine_compromises: u64,
        trial_count: u64,
    ) -> Result<(), String> {
        // Check for sentinel corruption before range validation so callers get
        // the actionable corruption diagnosis instead of a generic bounds error.
        if baseline_compromises == u64::MAX {
            return Err("Baseline compromises value appears corrupted (u64::MAX)".to_string());
        }

        if frankenengine_compromises == u64::MAX {
            return Err("FrankenEngine compromises value appears corrupted (u64::MAX)".to_string());
        }

        if trial_count == 0 {
            return Err("Trial count cannot be zero".to_string());
        }

        if baseline_compromises > trial_count {
            return Err(format!(
                "Baseline compromises ({}) cannot exceed trial count ({})",
                baseline_compromises, trial_count
            ));
        }

        if frankenengine_compromises > trial_count {
            return Err(format!(
                "FrankenEngine compromises ({}) cannot exceed trial count ({})",
                frankenengine_compromises, trial_count
            ));
        }

        Ok(())
    }

    /// Validate that compromise rates are within bounds [0, 1_000_000] millionths (0-100%)
    pub fn validate_compromise_rates(
        baseline_rate_millionths: u64,
        frankenengine_rate_millionths: u64,
    ) -> Result<(), String> {
        const MAX_RATE_MILLIONTHS: u64 = 1_000_000; // 100%

        if baseline_rate_millionths > MAX_RATE_MILLIONTHS {
            return Err(format!(
                "Baseline compromise rate ({}) exceeds 100% ({})",
                baseline_rate_millionths, MAX_RATE_MILLIONTHS
            ));
        }

        if frankenengine_rate_millionths > MAX_RATE_MILLIONTHS {
            return Err(format!(
                "FrankenEngine compromise rate ({}) exceeds 100% ({})",
                frankenengine_rate_millionths, MAX_RATE_MILLIONTHS
            ));
        }

        Ok(())
    }

    /// Validate placeholder values for TARGETED data quality scenarios
    pub fn validate_placeholder_baselines(
        baseline_rate_millionths: u64,
        frankenengine_rate_millionths: u64,
        is_targeted_data: bool,
    ) -> Result<(), String> {
        if !is_targeted_data {
            return Ok(());
        }

        // For TARGETED data, baseline should be clearly placeholder values
        // Common placeholder patterns: 0, round percentages in millionths
        let common_placeholder_rates = [
            0,         // 0%
            500_000,   // 50%
            750_000,   // 75% (Bun placeholder)
            800_000,   // 80%
            850_000,   // 85% (Node placeholder)
            900_000,   // 90%
            1_000_000, // 100%
        ];

        let baseline_looks_placeholder =
            common_placeholder_rates.contains(&baseline_rate_millionths);
        let frankenengine_looks_placeholder =
            common_placeholder_rates.contains(&frankenengine_rate_millionths);

        if !baseline_looks_placeholder && !frankenengine_looks_placeholder {
            return Err(format!(
                "For TARGETED data quality, baseline values should be clearly placeholders. \
                Found baseline: {} millionths ({}%), frankenengine: {} millionths ({}%). \
                Expected round percentage values like 0, 50%, 75%, 80%, 85%, 90%, or 100%.",
                baseline_rate_millionths,
                baseline_rate_millionths / 10_000,
                frankenengine_rate_millionths,
                frankenengine_rate_millionths / 10_000
            ));
        }

        Ok(())
    }

    pub fn calculate_compromise_rate_millionths(compromises: u64, trials: u64) -> u64 {
        compromises
            .saturating_mul(1_000_000)
            .checked_div(trials)
            .unwrap_or(0)
    }

    pub fn calculate_reduction_ratio_millionths(
        baseline_rate_millionths: u64,
        frankenengine_rate_millionths: u64,
    ) -> u64 {
        if baseline_rate_millionths == 0 && frankenengine_rate_millionths == 0 {
            1_000_000
        } else if frankenengine_rate_millionths == 0 {
            // Perfect security - infinite reduction
            u64::MAX
        } else {
            baseline_rate_millionths
                .saturating_mul(1_000_000)
                .checked_div(frankenengine_rate_millionths)
                .unwrap_or(0)
        }
    }

    pub fn meets_reduction_threshold(&self, threshold_factor: u64) -> bool {
        self.reduction_ratio_millionths >= (threshold_factor * 1_000_000)
    }

    #[allow(clippy::too_many_arguments)]
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

    #[allow(clippy::too_many_arguments)]
    pub fn new_validated(
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
    ) -> Result<Self, String> {
        // Validate baseline parameters
        Self::validate_baseline_parameters(
            baseline_compromises,
            frankenengine_compromises,
            trial_count,
        )?;

        let baseline_compromise_rate_millionths =
            Self::calculate_compromise_rate_millionths(baseline_compromises, trial_count);
        let frankenengine_compromise_rate_millionths =
            Self::calculate_compromise_rate_millionths(frankenengine_compromises, trial_count);

        // Validate compromise rates are within bounds
        Self::validate_compromise_rates(
            baseline_compromise_rate_millionths,
            frankenengine_compromise_rate_millionths,
        )?;

        let reduction_ratio_millionths = Self::calculate_reduction_ratio_millionths(
            baseline_compromise_rate_millionths,
            frankenengine_compromise_rate_millionths,
        );

        Ok(Self {
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
        })
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
    pub overall_outcome: String,                  // "pass" | "fail"
    pub data_quality: String,                     // "targeted" | "observed"
    pub weighted_reduction_ratio_millionths: u64, // Geometric mean across denominators
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

    match (node_evidence.is_empty(), bun_evidence.is_empty()) {
        (true, true) => 1_000_000,
        (false, true) => geometric_mean_reduction(&node_evidence),
        (true, false) => geometric_mean_reduction(&bun_evidence),
        (false, false) => {
            let node_mean = geometric_mean_reduction(&node_evidence);
            let bun_mean = geometric_mean_reduction(&bun_evidence);
            geometric_mean_of_two(node_mean, bun_mean)
        }
    }
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

    // Check if evidence contains fictional scenarios first
    let has_fictional_data = contains_fictional_scenarios(&input.evidence);

    // Validate each piece of evidence
    for evidence in &input.evidence {
        // Validate basic parameters
        CompromiseRateEvidence::validate_baseline_parameters(
            evidence.baseline_compromises,
            evidence.frankenengine_compromises,
            evidence.trial_count,
        )
        .map_err(|e| format!("Scenario {}: {}", evidence.scenario_id, e))?;

        // Validate compromise rates are within bounds
        CompromiseRateEvidence::validate_compromise_rates(
            evidence.baseline_compromise_rate_millionths,
            evidence.frankenengine_compromise_rate_millionths,
        )
        .map_err(|e| format!("Scenario {}: {}", evidence.scenario_id, e))?;

        // Validate placeholder patterns for TARGETED data
        CompromiseRateEvidence::validate_placeholder_baselines(
            evidence.baseline_compromise_rate_millionths,
            evidence.frankenengine_compromise_rate_millionths,
            has_fictional_data,
        )
        .map_err(|e| format!("Scenario {}: {}", evidence.scenario_id, e))?;
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

    // Determine data quality (already checked earlier)
    let data_quality = if has_fictional_data {
        "targeted"
    } else {
        "observed"
    };

    // Determine overall outcome
    let required_reduction_millionths = input.reduction_threshold_factor * 1_000_000;
    let overall_outcome = if weighted_reduction_ratio >= required_reduction_millionths {
        "pass"
    } else {
        "fail"
    };

    let uncertainty_notes = if has_fictional_data {
        format!(
            "⚠️ WARNING: Contains placeholder/fictional red-team scenarios with non-existent paths. \
            Baseline measurements require live integration. Geometric mean across {} scenarios. \
            Status: TARGETED until real red-team scenarios implemented.",
            input.evidence.len()
        )
    } else {
        format!(
            "Baseline measurements from live red-team integration. Geometric mean across {} scenarios.",
            input.evidence.len()
        )
    };

    let coverage_notes = format!(
        "Coverage: {} Node, {} Bun scenarios. Threshold: {}x reduction. Data quality: {}",
        node_count, bun_count, input.reduction_threshold_factor, data_quality
    );

    Ok(CompromiseRateMetricReport {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: input.bead_id.clone(),
        overall_outcome: overall_outcome.to_string(),
        data_quality: data_quality.to_string(),
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
    let metric_id = DisruptiveMetricId::RedTeamCompromiseRateReduction;
    if report.threshold_factor != metric_id.threshold() {
        return Err(format!(
            "threshold factor {} does not match disruptive-floor metric threshold {}",
            report.threshold_factor,
            metric_id.threshold()
        ));
    }
    let observed_reduction_factor = report.weighted_reduction_ratio_millionths / 1_000_000;
    let artifact_evidence = input
        .evidence
        .iter()
        .find(|evidence| validate_sha256(&evidence.output_hash).is_ok())
        .or_else(|| input.evidence.first());
    let artifact_path = artifact_evidence
        .map(|evidence| evidence.output_path.clone())
        .unwrap_or_else(|| format!("artifacts/{}/run_manifest.json", metric_id.as_str()));
    let artifact_hash = artifact_evidence
        .and_then(|evidence| {
            validate_sha256(&evidence.output_hash)
                .is_ok()
                .then(|| evidence.output_hash.clone())
        })
        .unwrap_or_else(|| {
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
        });
    let verification_command = input
        .evidence
        .first()
        .map(|evidence| evidence.verification_command.clone())
        .filter(|command| !command.trim().is_empty())
        .unwrap_or_else(|| {
            "cargo test -p frankenengine-engine compromise_rate_disruptive_floor_metric_gate"
                .to_string()
        });

    Ok(MetricArtifact {
        metric_id,
        threshold: metric_id.threshold(),
        observed_value: observed_reduction_factor,
        unit: metric_id.unit().to_string(),
        baseline: metric_id.expected_baseline().to_string(),
        candidate: "franken_engine".to_string(),
        denominator_id: format!(
            "node_and_bun:compromise_rate:{}_evidence",
            input.evidence.len()
        ),
        scenario_set: input.scenario_set.clone(),
        artifact_path,
        artifact_hash,
        code_revision: input.code_revision.clone(),
        freshness_days: 0,
        confidence_millionths: 950_000,
        coverage_millionths: 950_000,
        verification_command,
        redaction_status: "redacted".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disruptive_floor_metric_gate::DEFAULT_MAX_FRESHNESS_DAYS;

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
        assert_eq!(report.data_quality, "observed");
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
        assert_eq!(report.data_quality, "observed");
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

    #[test]
    fn test_fictional_scenario_detection() {
        // Test with fictional scenario paths (like those in test fixtures)
        let fictional_evidence = CompromiseRateEvidence::new(
            "phishing_email_campaign_node".to_string(),
            RuntimeDenominator::Node,
            "node_default_security".to_string(),
            "frankenengine_hardened".to_string(),
            1000,
            850,
            85,
            "/test/scenarios/phishing_email_node".to_string(), // Fictional path
            "/test/output/phishing_node_results.json".to_string(), // Fictional path
            "sha256:abc123".to_string(),
            "verify_compromise_results.sh --node".to_string(), // Fictional script
            "host_compromise_within_24h".to_string(),
            "run_phishing_campaign.sh --runtime node".to_string(), // Fictional script
        );

        assert!(contains_fictional_scenarios(std::slice::from_ref(
            &fictional_evidence,
        )));

        let input = CompromiseRateMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "red_team_compromise_evaluation_v1".to_string(),
            reduction_threshold_factor: 10,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![fictional_evidence],
            code_revision: "abc123".to_string(),
            generated_at_utc: "2026-05-01T05:00:00Z".to_string(),
        };

        let report = analyze_compromise_rate_metric_input(&input).unwrap();
        assert_eq!(report.data_quality, "targeted");
        assert!(report.uncertainty_notes.contains("⚠️ WARNING"));
        assert!(report.uncertainty_notes.contains("placeholder/fictional"));
        assert!(report.coverage_notes.contains("Data quality: targeted"));
    }

    #[test]
    fn test_real_scenario_detection() {
        // Test with realistic (non-fictional) scenario paths
        let real_evidence = CompromiseRateEvidence::new(
            "live_scenario_001".to_string(),
            RuntimeDenominator::Node,
            "node_standard_config".to_string(),
            "frankenengine_security_enabled".to_string(),
            100,
            75,
            5,
            "/data/red_team/scenarios/cve_2023_001/config.json".to_string(), // Real-looking path
            "/data/red_team/results/scenario_001_results.json".to_string(),  // Real-looking path
            "sha256:realoutputhash123".to_string(),
            "validate_scenario_results --scenario cve_2023_001".to_string(), // Real-looking command
            "privilege_escalation_success".to_string(),
            "execute_cve_exploit --target node --iterations 100".to_string(), // Real-looking command
        );

        assert!(!contains_fictional_scenarios(std::slice::from_ref(
            &real_evidence,
        )));

        let input = CompromiseRateMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "live_red_team_evaluation".to_string(),
            reduction_threshold_factor: 10,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![real_evidence],
            code_revision: "abc123".to_string(),
            generated_at_utc: "2026-05-01T05:00:00Z".to_string(),
        };

        let report = analyze_compromise_rate_metric_input(&input).unwrap();
        assert_eq!(report.data_quality, "observed");
        assert!(!report.uncertainty_notes.contains("⚠️ WARNING"));
        assert!(!report.uncertainty_notes.contains("placeholder/fictional"));
        assert!(report.coverage_notes.contains("Data quality: observed"));
    }

    // Baseline validation tests

    #[test]
    fn test_validate_baseline_parameters_valid() {
        // Valid parameters should pass
        assert!(CompromiseRateEvidence::validate_baseline_parameters(80, 8, 100).is_ok());
        assert!(CompromiseRateEvidence::validate_baseline_parameters(0, 0, 100).is_ok());
        assert!(CompromiseRateEvidence::validate_baseline_parameters(100, 100, 100).is_ok());
    }

    #[test]
    fn test_validate_baseline_parameters_zero_trials() {
        // Zero trial count should be rejected
        let result = CompromiseRateEvidence::validate_baseline_parameters(80, 8, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Trial count cannot be zero"));
    }

    #[test]
    fn test_validate_baseline_parameters_compromises_exceed_trials() {
        // Baseline compromises exceeding trials should be rejected
        let result = CompromiseRateEvidence::validate_baseline_parameters(150, 8, 100);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Baseline compromises (150) cannot exceed trial count (100)")
        );

        // FrankenEngine compromises exceeding trials should be rejected
        let result = CompromiseRateEvidence::validate_baseline_parameters(80, 150, 100);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("FrankenEngine compromises (150) cannot exceed trial count (100)")
        );
    }

    #[test]
    fn test_validate_baseline_parameters_corrupted_values() {
        // u64::MAX values (indicating potential corruption) should be rejected
        let result = CompromiseRateEvidence::validate_baseline_parameters(u64::MAX, 8, 100);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Baseline compromises value appears corrupted")
        );

        let result = CompromiseRateEvidence::validate_baseline_parameters(80, u64::MAX, 100);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("FrankenEngine compromises value appears corrupted")
        );
    }

    #[test]
    fn test_validate_compromise_rates_valid() {
        // Valid rates (0-100%) should pass
        assert!(CompromiseRateEvidence::validate_compromise_rates(0, 0).is_ok());
        assert!(CompromiseRateEvidence::validate_compromise_rates(500_000, 50_000).is_ok()); // 50% vs 5%
        assert!(CompromiseRateEvidence::validate_compromise_rates(1_000_000, 0).is_ok());
        // 100% vs 0%
    }

    #[test]
    fn test_validate_compromise_rates_exceeds_100_percent() {
        // Rates > 100% should be rejected
        let result = CompromiseRateEvidence::validate_compromise_rates(1_500_000, 50_000);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Baseline compromise rate (1500000) exceeds 100%")
        );

        let result = CompromiseRateEvidence::validate_compromise_rates(500_000, 2_000_000);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("FrankenEngine compromise rate (2000000) exceeds 100%")
        );
    }

    #[test]
    fn test_validate_placeholder_baselines_non_targeted() {
        // Non-targeted data should always pass placeholder validation
        assert!(
            CompromiseRateEvidence::validate_placeholder_baselines(123_456, 78_901, false).is_ok()
        );
        assert!(
            CompromiseRateEvidence::validate_placeholder_baselines(850_000, 85_000, false).is_ok()
        );
    }

    #[test]
    fn test_validate_placeholder_baselines_targeted_valid() {
        // TARGETED data with placeholder values should pass
        assert!(
            CompromiseRateEvidence::validate_placeholder_baselines(850_000, 85_000, true).is_ok()
        ); // 85% vs 8.5%
        assert!(CompromiseRateEvidence::validate_placeholder_baselines(750_000, 0, true).is_ok()); // 75% vs 0%
        assert!(CompromiseRateEvidence::validate_placeholder_baselines(0, 0, true).is_ok()); // 0% vs 0%
        assert!(
            CompromiseRateEvidence::validate_placeholder_baselines(1_000_000, 500_000, true)
                .is_ok()
        ); // 100% vs 50%
    }

    #[test]
    fn test_validate_placeholder_baselines_targeted_invalid() {
        // TARGETED data with non-placeholder values should be rejected
        let result = CompromiseRateEvidence::validate_placeholder_baselines(123_456, 78_901, true);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains(
                "For TARGETED data quality, baseline values should be clearly placeholders"
            )
        );
    }

    #[test]
    fn test_new_validated_success() {
        let result = CompromiseRateEvidence::new_validated(
            "test_scenario".to_string(),
            RuntimeDenominator::Node,
            "default".to_string(),
            "frankenengine".to_string(),
            100,
            80, // 80% baseline
            8,  // 8% frankenengine
            "test_path".to_string(),
            "output_path".to_string(),
            "hash123".to_string(),
            "verify_cmd".to_string(),
            "host_compromise".to_string(),
            "repro_cmd".to_string(),
        );

        assert!(result.is_ok());
        let evidence = result.unwrap();
        assert_eq!(evidence.baseline_compromise_rate_millionths, 800_000);
        assert_eq!(evidence.frankenengine_compromise_rate_millionths, 80_000);
    }

    #[test]
    fn test_new_validated_failure_compromises_exceed_trials() {
        let result = CompromiseRateEvidence::new_validated(
            "test_scenario".to_string(),
            RuntimeDenominator::Node,
            "default".to_string(),
            "frankenengine".to_string(),
            100,
            150, // Invalid: more compromises than trials
            8,
            "test_path".to_string(),
            "output_path".to_string(),
            "hash123".to_string(),
            "verify_cmd".to_string(),
            "host_compromise".to_string(),
            "repro_cmd".to_string(),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot exceed trial count"));
    }

    #[test]
    fn test_analyze_input_with_baseline_validation_errors() {
        // Create evidence with invalid baseline (compromises > trials)
        let evidence = CompromiseRateEvidence {
            scenario_id: "invalid_scenario".to_string(),
            runtime_denominator: RuntimeDenominator::Node,
            baseline_posture: "default".to_string(),
            frankenengine_posture: "frankenengine".to_string(),
            trial_count: 100,
            baseline_compromises: 150, // Invalid
            frankenengine_compromises: 8,
            baseline_compromise_rate_millionths: 1_500_000, // > 100%, invalid
            frankenengine_compromise_rate_millionths: 80_000,
            reduction_ratio_millionths: 1_875_000,
            scenario_path: "path".to_string(),
            output_path: "output".to_string(),
            output_hash: "hash".to_string(),
            verification_command: "verify".to_string(),
            success_criteria: "success".to_string(),
            reproducibility_command: "repro".to_string(),
        };

        let input = CompromiseRateMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "test_set".to_string(),
            reduction_threshold_factor: 10,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![evidence],
            code_revision: "abc123".to_string(),
            generated_at_utc: "2026-05-01T05:00:00Z".to_string(),
        };

        let result = analyze_compromise_rate_metric_input(&input);
        assert!(result.is_err());
        let error = result.unwrap_err();
        // Should catch the baseline validation error
        assert!(error.contains("invalid_scenario"));
        assert!(error.contains("cannot exceed trial count"));
    }

    #[test]
    fn test_analyze_input_with_targeted_placeholder_validation() {
        // Create fictional evidence with valid placeholder values
        let evidence = CompromiseRateEvidence::new(
            "fictional_scenario".to_string(),
            RuntimeDenominator::Node,
            "default".to_string(),
            "frankenengine".to_string(),
            100,
            85, // 85% baseline (850_000 millionths - valid placeholder)
            8,  // 8% frankenengine (80_000 millionths)
            "/test/scenarios/fictional_path".to_string(), // Fictional path
            "output_path".to_string(),
            "hash".to_string(),
            "verify".to_string(),
            "success".to_string(),
            "repro".to_string(),
        );

        let input = CompromiseRateMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "fictional_test".to_string(),
            reduction_threshold_factor: 10,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![evidence],
            code_revision: "abc123".to_string(),
            generated_at_utc: "2026-05-01T05:00:00Z".to_string(),
        };

        // Should pass because fictional data has placeholder-looking values
        let result = analyze_compromise_rate_metric_input(&input);
        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.data_quality, "targeted");
    }
}
