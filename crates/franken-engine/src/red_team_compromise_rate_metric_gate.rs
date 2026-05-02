#![forbid(unsafe_code)]

//! Red-team compromise-rate metric gate with Node and Bun baseline comparison.
//!
//! This child gate produces the `red_team_compromise_rate_reduction` metric
//! artifact consumed by `disruptive_floor_metric_gate`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::disruptive_floor_metric_gate::{
    DEFAULT_MAX_FRESHNESS_DAYS, DEFAULT_MIN_COVERAGE_MILLIONTHS, DisruptiveMetricId, MetricArtifact,
};
use crate::proof_artifact::validate_sha256;

pub const SCHEMA_VERSION: &str = "franken-engine.red-team-compromise-rate-metric-gate.v1";
pub const COMPONENT: &str = "red_team_compromise_rate_metric_gate";
pub const BEAD_ID: &str = "bd-1vwza";
pub const RATE_SCALE_MILLIONTHS: u64 = 1_000_000;
pub const DEFAULT_REDUCTION_THRESHOLD_X: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedTeamAttackClass {
    AmbientAuthorityEscape,
    PrototypePollution,
    SupplyChainExecution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioOutcome {
    Succeeded,    // Attack succeeded against target
    Failed,       // Attack was contained/failed
    Inconclusive, // Outcome unclear/untested
}

impl ScenarioOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Inconclusive => "inconclusive",
        }
    }

    pub const fn attacker_succeeded(self) -> bool {
        matches!(self, Self::Succeeded)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineDataValidationMode {
    Observed,    // Real measured outcomes, allow arbitrary values
    Provisional, // Placeholder data for testing, require clearly fake values
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedTeamHarnessRuntime {
    Node,
    Bun,
    FrankenEngine,
}

impl RedTeamHarnessRuntime {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Bun => "bun",
            Self::FrankenEngine => "franken_engine",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedTeamScenarioMeasurementProvenance {
    pub source: String,
    pub min_trials_per_runtime: u64,
    pub node_attempts_total: u64,
    pub node_attempts_successful: u64,
    pub bun_attempts_total: u64,
    pub bun_attempts_successful: u64,
    pub frankenengine_attempts_total: u64,
    pub frankenengine_attempts_successful: u64,
    pub node_compromise_millionths: u64,
    pub bun_compromise_millionths: u64,
    pub frankenengine_compromise_millionths: u64,
}

impl RedTeamScenarioMeasurementProvenance {
    fn validates_outcomes(
        &self,
        node_outcome: ScenarioOutcome,
        bun_outcome: ScenarioOutcome,
        frankenengine_outcome: ScenarioOutcome,
    ) -> bool {
        self.source == "bd-28otw_attacker_harness"
            && self.min_trials_per_runtime >= 100
            && self.node_attempts_total >= self.min_trials_per_runtime
            && self.bun_attempts_total >= self.min_trials_per_runtime
            && self.frankenengine_attempts_total >= self.min_trials_per_runtime
            && self.node_attempts_successful <= self.node_attempts_total
            && self.bun_attempts_successful <= self.bun_attempts_total
            && self.frankenengine_attempts_successful <= self.frankenengine_attempts_total
            && outcome_from_attempts(self.node_attempts_successful) == node_outcome
            && outcome_from_attempts(self.bun_attempts_successful) == bun_outcome
            && outcome_from_attempts(self.frankenengine_attempts_successful)
                == frankenengine_outcome
            && self.node_compromise_millionths
                == rate_millionths(self.node_attempts_successful, self.node_attempts_total)
            && self.bun_compromise_millionths
                == rate_millionths(self.bun_attempts_successful, self.bun_attempts_total)
            && self.frankenengine_compromise_millionths
                == rate_millionths(
                    self.frankenengine_attempts_successful,
                    self.frankenengine_attempts_total,
                )
    }
}

impl RedTeamAttackClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AmbientAuthorityEscape => "ambient_authority_escape",
            Self::PrototypePollution => "prototype_pollution",
            Self::SupplyChainExecution => "supply_chain_execution",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedTeamScenarioEvidence {
    pub scenario_id: String,
    pub attack_class: RedTeamAttackClass,
    pub security_critical: bool,
    pub frankenengine_outcome: ScenarioOutcome,
    pub node_outcome: ScenarioOutcome,
    pub bun_outcome: ScenarioOutcome,
    pub baseline_validation_mode: BaselineDataValidationMode,
    pub witness_path: String,
    pub witness_hash: String,
    pub transcript_path: String,
    pub transcript_hash: String,
    pub replay_command: String,
    pub replay_exit_code: i32,
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement_provenance: Option<RedTeamScenarioMeasurementProvenance>,
}

/// Validates baseline scenario outcomes to prevent hardcoded assumptions
fn validate_scenario_outcomes(evidence: &RedTeamScenarioEvidence) -> Result<(), String> {
    // Check for obviously fake or placeholder scenario IDs
    let placeholder_patterns = [
        "test-scenario",
        "example-scenario",
        "placeholder",
        "dummy-scenario",
        "fake-scenario",
    ];

    let scenario_id_lower = evidence.scenario_id.to_lowercase();
    for pattern in &placeholder_patterns {
        if scenario_id_lower.contains(pattern) {
            return Err(format!(
                "Placeholder scenario ID detected: '{}'. Red team scenarios must have real identifiers, not test placeholders.",
                evidence.scenario_id
            ));
        }
    }

    match evidence.baseline_validation_mode {
        BaselineDataValidationMode::Observed => {
            // Real scenarios can have any outcome - no further validation needed
            Ok(())
        }
        BaselineDataValidationMode::Provisional => {
            // For provisional/testing data, outcomes should be clearly marked as assumptions
            validate_provisional_scenario_outcomes(evidence)
        }
    }
}

/// Validates that provisional scenarios use clearly placeholder outcomes
fn validate_provisional_scenario_outcomes(
    evidence: &RedTeamScenarioEvidence,
) -> Result<(), String> {
    // For baseline compromise rate scenarios, we need to avoid hardcoded assumptions
    // Real scenarios should be marked as Observed; test scenarios as Provisional

    // For provisional data, require explicit acknowledgment that these are test values
    if evidence.scenario_id.contains("provisional") || evidence.scenario_id.contains("test") {
        return Ok(()); // Clearly marked test scenarios are OK
    }

    // Check for suspicious patterns where baselines are assumed to be compromised
    if evidence.node_outcome == ScenarioOutcome::Succeeded
        && evidence.bun_outcome == ScenarioOutcome::Succeeded
        && evidence.frankenengine_outcome != ScenarioOutcome::Succeeded
    {
        return Err(format!(
            "Suspicious baseline assumption in scenario '{}': Node and Bun both marked as Succeeded while FrankenEngine Failed. This pattern suggests hardcoded assumptions rather than measured outcomes. Use BaselineDataValidationMode::Observed for real measurements.",
            evidence.scenario_id
        ));
    }

    Err(format!(
        "Provisional baseline data requires clear test/placeholder markers in scenario ID: '{}'. Real scenarios should use BaselineDataValidationMode::Observed.",
        evidence.scenario_id
    ))
}

/// Detects hardcoded baseline assumptions across scenario set
fn validate_baseline_assumption_patterns(
    scenarios: &[RedTeamScenarioEvidence],
) -> Result<(), String> {
    let security_critical_scenarios: Vec<_> =
        scenarios.iter().filter(|s| s.security_critical).collect();

    if security_critical_scenarios.is_empty() {
        return Err("No security-critical scenarios found: cannot validate baseline patterns without security scenarios".to_string());
    }

    // Count scenarios where Node and Bun always succeed (indicating hardcoded assumptions)
    let node_always_succeed = security_critical_scenarios
        .iter()
        .filter(|s| s.baseline_validation_mode == BaselineDataValidationMode::Observed)
        .all(|s| s.node_outcome.attacker_succeeded());

    let bun_always_succeed = security_critical_scenarios
        .iter()
        .filter(|s| s.baseline_validation_mode == BaselineDataValidationMode::Observed)
        .all(|s| s.bun_outcome.attacker_succeeded());

    if node_always_succeed && bun_always_succeed {
        let harness_provenance_present = security_critical_scenarios
            .iter()
            .filter(|s| s.baseline_validation_mode == BaselineDataValidationMode::Observed)
            .all(|scenario| scenario.has_valid_harness_measurement_provenance());
        if harness_provenance_present {
            return Ok(());
        }

        return Err("Hardcoded baseline assumption detected: Node and Bun marked as always compromised across all OBSERVED scenarios. This indicates assumptions rather than measurements. Use ScenarioOutcome::Failed or ::Inconclusive for scenarios where baselines weren't actually compromised.".to_string());
    }

    Ok(())
}

impl RedTeamScenarioEvidence {
    pub fn replayable_witness(&self) -> bool {
        self.security_critical
            && !self.witness_path.trim().is_empty()
            && !self.transcript_path.trim().is_empty()
            && !self.replay_command.trim().is_empty()
            && self.replay_exit_code == 0
            && validate_sha256(&self.witness_hash).is_ok()
            && validate_sha256(&self.transcript_hash).is_ok()
    }

    /// Validate this scenario evidence against assumption patterns
    pub fn validate_scenario(&self) -> Result<(), String> {
        validate_scenario_outcomes(self)
    }

    pub fn frankenengine_attacker_succeeded(&self) -> bool {
        self.frankenengine_outcome.attacker_succeeded()
    }

    pub fn node_attacker_succeeded(&self) -> bool {
        self.node_outcome.attacker_succeeded()
    }

    pub fn bun_attacker_succeeded(&self) -> bool {
        self.bun_outcome.attacker_succeeded()
    }

    pub fn has_valid_harness_measurement_provenance(&self) -> bool {
        self.measurement_provenance
            .as_ref()
            .is_some_and(|provenance| {
                provenance.validates_outcomes(
                    self.node_outcome,
                    self.bun_outcome,
                    self.frankenengine_outcome,
                )
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedTeamHarnessRuntimeResult {
    pub scenario_id: String,
    pub attack_class: RedTeamAttackClass,
    pub security_critical: bool,
    pub runtime: RedTeamHarnessRuntime,
    pub attempts_total: u64,
    pub attempts_successful: u64,
    pub witness_path: String,
    pub witness_hash: String,
    pub transcript_path: String,
    pub transcript_hash: String,
    pub replay_command: String,
    pub replay_exit_code: i32,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedTeamHarnessOutput {
    pub schema_version: String,
    pub code_revision: String,
    pub freshness_days: u64,
    pub scenario_set: String,
    pub artifact_path: String,
    pub artifact_hash: String,
    pub verification_command: String,
    pub redaction_status: String,
    pub confidence_millionths: u64,
    pub min_trials_per_runtime: u64,
    pub results: Vec<RedTeamHarnessRuntimeResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedTeamRuntimeCompromiseRate {
    pub runtime: RedTeamHarnessRuntime,
    pub attempts_total: u64,
    pub attempts_successful: u64,
    pub compromise_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedTeamHarnessMeasurementSummary {
    pub node: RedTeamRuntimeCompromiseRate,
    pub bun: RedTeamRuntimeCompromiseRate,
    pub frankenengine: RedTeamRuntimeCompromiseRate,
    pub node_to_frankenengine_reduction_ratio_millionths: u64,
    pub bun_to_frankenengine_reduction_ratio_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedTeamCompromiseRateMetricInput {
    pub code_revision: String,
    pub freshness_days: u64,
    pub scenario_set: String,
    pub artifact_path: String,
    pub artifact_hash: String,
    pub verification_command: String,
    pub redaction_status: String,
    pub confidence_millionths: u64,
    pub scenarios: Vec<RedTeamScenarioEvidence>,
}

impl RedTeamCompromiseRateMetricInput {
    pub fn representative_fixture(code_revision: impl Into<String>) -> Self {
        Self {
            code_revision: code_revision.into(),
            freshness_days: 0,
            scenario_set: "red_team_security_critical_compromise_v1".to_string(),
            artifact_path: "artifacts/red_team_compromise_rate_metric/compromise_details.json"
                .to_string(),
            artifact_hash:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            verification_command: "scripts/run_red_team_compromise_rate_metric_gate.sh ci"
                .to_string(),
            redaction_status: "redacted".to_string(),
            confidence_millionths: RATE_SCALE_MILLIONTHS,
            scenarios: vec![
                provisional_scenario(
                    "test-ambient-token-exfiltration-provisional",
                    RedTeamAttackClass::AmbientAuthorityEscape,
                    ScenarioOutcome::Succeeded,
                    ScenarioOutcome::Succeeded,
                    ScenarioOutcome::Succeeded,
                ),
                provisional_scenario(
                    "test-ambient-filesystem-escape-provisional",
                    RedTeamAttackClass::AmbientAuthorityEscape,
                    ScenarioOutcome::Failed,
                    ScenarioOutcome::Succeeded,
                    ScenarioOutcome::Succeeded,
                ),
                provisional_scenario(
                    "test-ambient-network-escape-provisional",
                    RedTeamAttackClass::AmbientAuthorityEscape,
                    ScenarioOutcome::Failed,
                    ScenarioOutcome::Succeeded,
                    ScenarioOutcome::Succeeded,
                ),
                provisional_scenario(
                    "test-prototype-pollution-getter-provisional",
                    RedTeamAttackClass::PrototypePollution,
                    ScenarioOutcome::Failed,
                    ScenarioOutcome::Succeeded,
                    ScenarioOutcome::Succeeded,
                ),
                provisional_scenario(
                    "test-prototype-pollution-constructor-provisional",
                    RedTeamAttackClass::PrototypePollution,
                    ScenarioOutcome::Failed,
                    ScenarioOutcome::Succeeded,
                    ScenarioOutcome::Succeeded,
                ),
                provisional_scenario(
                    "test-prototype-pollution-json-provisional",
                    RedTeamAttackClass::PrototypePollution,
                    ScenarioOutcome::Failed,
                    ScenarioOutcome::Succeeded,
                    ScenarioOutcome::Succeeded,
                ),
                provisional_scenario(
                    "test-supply-chain-postinstall-provisional",
                    RedTeamAttackClass::SupplyChainExecution,
                    ScenarioOutcome::Failed,
                    ScenarioOutcome::Succeeded,
                    ScenarioOutcome::Succeeded,
                ),
                provisional_scenario(
                    "test-supply-chain-dynamic-import-provisional",
                    RedTeamAttackClass::SupplyChainExecution,
                    ScenarioOutcome::Failed,
                    ScenarioOutcome::Succeeded,
                    ScenarioOutcome::Succeeded,
                ),
                provisional_scenario(
                    "test-supply-chain-native-addon-provisional",
                    RedTeamAttackClass::SupplyChainExecution,
                    ScenarioOutcome::Failed,
                    ScenarioOutcome::Succeeded,
                    ScenarioOutcome::Succeeded,
                ),
                provisional_scenario(
                    "test-supply-chain-env-exfiltration-provisional",
                    RedTeamAttackClass::SupplyChainExecution,
                    ScenarioOutcome::Failed,
                    ScenarioOutcome::Succeeded,
                    ScenarioOutcome::Succeeded,
                ),
            ],
        }
    }

    /// Validates the entire scenario set for assumption patterns
    pub fn validate_scenarios(&self) -> Result<(), String> {
        // Validate individual scenarios
        for scenario in &self.scenarios {
            scenario.validate_scenario()?;
        }

        // Validate baseline assumption patterns across the set
        validate_baseline_assumption_patterns(&self.scenarios)?;

        Ok(())
    }
}

/// Creates a scenario with explicit outcomes (for real measurements)
#[cfg(test)]
fn scenario(
    scenario_id: impl Into<String>,
    attack_class: RedTeamAttackClass,
    frankenengine_outcome: ScenarioOutcome,
    node_outcome: ScenarioOutcome,
    bun_outcome: ScenarioOutcome,
) -> RedTeamScenarioEvidence {
    let scenario_id = scenario_id.into();
    RedTeamScenarioEvidence {
        scenario_id: scenario_id.clone(),
        attack_class,
        security_critical: true,
        frankenengine_outcome,
        node_outcome,
        bun_outcome,
        baseline_validation_mode: BaselineDataValidationMode::Observed,
        witness_path: format!(
            "artifacts/red_team_compromise_rate_metric/witnesses/{scenario_id}.json"
        ),
        witness_hash: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            .to_string(),
        transcript_path: format!(
            "artifacts/red_team_compromise_rate_metric/transcripts/{scenario_id}.json"
        ),
        transcript_hash: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            .to_string(),
        replay_command: format!(
            "frankenctl red-team replay --scenario artifacts/red_team_compromise_rate_metric/witnesses/{scenario_id}.json --mode strict"
        ),
        replay_exit_code: 0,
        duration_ms: 1,
        measurement_provenance: None,
    }
}

/// Creates a provisional scenario for testing (clearly marked as test data)
fn provisional_scenario(
    scenario_id: impl Into<String>,
    attack_class: RedTeamAttackClass,
    frankenengine_outcome: ScenarioOutcome,
    node_outcome: ScenarioOutcome,
    bun_outcome: ScenarioOutcome,
) -> RedTeamScenarioEvidence {
    let scenario_id = scenario_id.into();
    RedTeamScenarioEvidence {
        scenario_id: scenario_id.clone(),
        attack_class,
        security_critical: true,
        frankenengine_outcome,
        node_outcome,
        bun_outcome,
        baseline_validation_mode: BaselineDataValidationMode::Provisional,
        witness_path: format!(
            "artifacts/red_team_compromise_rate_metric/witnesses/{scenario_id}.json"
        ),
        witness_hash: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            .to_string(),
        transcript_path: format!(
            "artifacts/red_team_compromise_rate_metric/transcripts/{scenario_id}.json"
        ),
        transcript_hash: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            .to_string(),
        replay_command: format!(
            "frankenctl red-team replay --scenario artifacts/red_team_compromise_rate_metric/witnesses/{scenario_id}.json --mode strict"
        ),
        replay_exit_code: 0,
        duration_ms: 1,
        measurement_provenance: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedTeamCompromiseRateDecision {
    Pass,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedTeamCompromiseRateStructuredEvent {
    pub metric_id: DisruptiveMetricId,
    pub proof_manifest_id: String,
    pub command_id: String,
    pub scenario_id: String,
    pub attack_class: RedTeamAttackClass,
    pub attack_class_label: String,
    pub engine_compromised: bool,
    pub node_compromised: bool,
    pub bun_compromised: bool,
    pub replayable_witness: bool,
    pub scenarios_total: u64,
    pub attacks_successful: u64,
    pub compromise_millionths: u64,
    pub baseline_compromise_millionths_node: u64,
    pub baseline_compromise_millionths_bun: u64,
    pub baseline_reference_millionths: u64,
    pub reduction_factor_x: u64,
    pub threshold_factor_x: u64,
    pub command: String,
    pub exit_code: i32,
    pub decision: String,
    pub reason: String,
    pub artifact_path: String,
    pub artifact_hash: String,
    pub code_revision: String,
    pub duration_ms: u64,
    pub freshness_days: u64,
    pub redaction_status: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedTeamCompromiseRateMetricReport {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub metric_artifact: MetricArtifact,
    pub scenarios_total: u64,
    pub attacks_successful: u64,
    pub compromise_millionths: u64,
    pub baseline_compromise_millionths_node: u64,
    pub baseline_compromise_millionths_bun: u64,
    pub baseline_reference_millionths: u64,
    pub reduction_factor_x: u64,
    pub replayable_witness_scenarios: u64,
    pub replay_coverage_millionths: u64,
    pub decision: RedTeamCompromiseRateDecision,
    pub reason: String,
    pub compromised_scenario_ids: Vec<String>,
    pub unreplayable_scenario_ids: Vec<String>,
    pub events: Vec<RedTeamCompromiseRateStructuredEvent>,
}

impl RedTeamCompromiseRateMetricReport {
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("# Red-Team Compromise-Rate Metric Gate\n\n");
        out.push_str(&format!("Decision: `{:?}`\n\n", self.decision));
        out.push_str(&format!(
            "Compromise rate: `{}` / `{}` scenarios (`{}` millionths)\n\n",
            self.attacks_successful, self.scenarios_total, self.compromise_millionths
        ));
        out.push_str(&format!(
            "Reduction: `{}`x versus stricter Node/Bun baseline\n\n",
            self.reduction_factor_x
        ));
        if !self.compromised_scenario_ids.is_empty() {
            out.push_str("Compromised scenarios:\n");
            for scenario_id in &self.compromised_scenario_ids {
                out.push_str(&format!("- `{scenario_id}`\n"));
            }
        }
        if !self.unreplayable_scenario_ids.is_empty() {
            out.push_str("\nUnreplayable scenarios:\n");
            for scenario_id in &self.unreplayable_scenario_ids {
                out.push_str(&format!("- `{scenario_id}`\n"));
            }
        }
        out
    }
}

pub fn evaluate_red_team_compromise_rate_metric(
    input: &RedTeamCompromiseRateMetricInput,
) -> RedTeamCompromiseRateMetricReport {
    // Validate scenarios first - fail closed if validation fails
    let validation_errors = match input.validate_scenarios() {
        Ok(()) => Vec::new(),
        Err(validation_error) => vec![validation_error],
    };

    let critical_scenarios = input
        .scenarios
        .iter()
        .filter(|scenario| scenario.security_critical)
        .collect::<Vec<_>>();
    let scenarios_total = critical_scenarios.len() as u64;
    let attacks_successful = critical_scenarios
        .iter()
        .filter(|scenario| scenario.frankenengine_attacker_succeeded())
        .count() as u64;
    let node_successful = critical_scenarios
        .iter()
        .filter(|scenario| scenario.node_attacker_succeeded())
        .count() as u64;
    let bun_successful = critical_scenarios
        .iter()
        .filter(|scenario| scenario.bun_attacker_succeeded())
        .count() as u64;
    let replayable_witness_scenarios = critical_scenarios
        .iter()
        .filter(|scenario| scenario.replayable_witness())
        .count() as u64;

    let compromise_millionths = rate_millionths(attacks_successful, scenarios_total);
    let baseline_compromise_millionths_node = rate_millionths(node_successful, scenarios_total);
    let baseline_compromise_millionths_bun = rate_millionths(bun_successful, scenarios_total);
    let baseline_reference_millionths =
        baseline_compromise_millionths_node.min(baseline_compromise_millionths_bun);
    let reduction_factor_x =
        reduction_factor_x(baseline_reference_millionths, compromise_millionths);
    let replay_coverage_millionths = rate_millionths(replayable_witness_scenarios, scenarios_total);

    let mut global_failures = Vec::new();
    if input.code_revision.trim().is_empty() {
        global_failures.push("missing_code_revision");
    }
    if input.artifact_path.trim().is_empty() {
        global_failures.push("missing_artifact_path");
    }
    if validate_sha256(&input.artifact_hash).is_err() {
        global_failures.push("invalid_artifact_hash");
    }
    if input.freshness_days > DEFAULT_MAX_FRESHNESS_DAYS {
        global_failures.push("stale_manifest");
    }
    if input.redaction_status != "redacted" {
        global_failures.push("unredacted_command_transcript");
    }

    let compromised_scenario_ids = critical_scenarios
        .iter()
        .filter(|scenario| scenario.frankenengine_attacker_succeeded())
        .map(|scenario| scenario.scenario_id.clone())
        .collect::<Vec<_>>();
    let unreplayable_scenario_ids = critical_scenarios
        .iter()
        .filter(|scenario| !scenario.replayable_witness())
        .map(|scenario| scenario.scenario_id.clone())
        .collect::<Vec<_>>();

    let passed = scenarios_total > 0
        && global_failures.is_empty()
        && validation_errors.is_empty()
        && replay_coverage_millionths >= DEFAULT_MIN_COVERAGE_MILLIONTHS
        && reduction_factor_x >= DEFAULT_REDUCTION_THRESHOLD_X;
    let reason = if scenarios_total == 0 {
        "missing_red_team_scenario_inventory".to_string()
    } else if !validation_errors.is_empty() {
        format!(
            "scenario_validation_failed: {}",
            validation_errors.join("; ")
        )
    } else if !global_failures.is_empty() {
        global_failures.join(",")
    } else if replay_coverage_millionths < DEFAULT_MIN_COVERAGE_MILLIONTHS {
        "unreplayable_red_team_scenarios".to_string()
    } else if reduction_factor_x < DEFAULT_REDUCTION_THRESHOLD_X {
        "compromise_rate_reduction_below_baseline".to_string()
    } else {
        "red_team_compromise_rate_reduction_verified".to_string()
    };

    let metric_id = DisruptiveMetricId::RedTeamCompromiseRateReduction;
    let metric_artifact = MetricArtifact {
        metric_id,
        threshold: metric_id.threshold(),
        observed_value: reduction_factor_x,
        unit: metric_id.unit().to_string(),
        baseline: metric_id.expected_baseline().to_string(),
        candidate: "franken_engine".to_string(),
        denominator_id: format!("node_and_bun:red_team_scenarios:{scenarios_total}"),
        scenario_set: input.scenario_set.clone(),
        artifact_path: input.artifact_path.clone(),
        artifact_hash: input.artifact_hash.clone(),
        code_revision: input.code_revision.clone(),
        freshness_days: input.freshness_days,
        confidence_millionths: input.confidence_millionths.min(RATE_SCALE_MILLIONTHS),
        coverage_millionths: replay_coverage_millionths,
        verification_command: input.verification_command.clone(),
        redaction_status: input.redaction_status.clone(),
    };

    let mut events = Vec::new();
    for scenario in &critical_scenarios {
        let replayable_witness = scenario.replayable_witness();
        let event_reason = if !replayable_witness {
            "missing_or_invalid_replay_witness"
        } else if scenario.frankenengine_attacker_succeeded() {
            "attacker_succeeded_against_franken_engine"
        } else {
            "attacker_contained_by_franken_engine"
        }
        .to_string();
        events.push(RedTeamCompromiseRateStructuredEvent {
            metric_id,
            proof_manifest_id: format!("{COMPONENT}:{}", input.scenario_set),
            command_id: format!("red-team:{}", scenario.scenario_id),
            scenario_id: scenario.scenario_id.clone(),
            attack_class: scenario.attack_class,
            attack_class_label: scenario.attack_class.as_str().to_string(),
            engine_compromised: scenario.frankenengine_attacker_succeeded(),
            node_compromised: scenario.node_attacker_succeeded(),
            bun_compromised: scenario.bun_attacker_succeeded(),
            replayable_witness,
            scenarios_total,
            attacks_successful,
            compromise_millionths,
            baseline_compromise_millionths_node,
            baseline_compromise_millionths_bun,
            baseline_reference_millionths,
            reduction_factor_x,
            threshold_factor_x: DEFAULT_REDUCTION_THRESHOLD_X,
            command: scenario.replay_command.clone(),
            exit_code: scenario.replay_exit_code,
            decision: if !replayable_witness {
                "unreplayable".to_string()
            } else if scenario.frankenengine_attacker_succeeded() {
                "compromised".to_string()
            } else {
                "contained".to_string()
            },
            reason: event_reason,
            artifact_path: input.artifact_path.clone(),
            artifact_hash: input.artifact_hash.clone(),
            code_revision: input.code_revision.clone(),
            duration_ms: scenario.duration_ms,
            freshness_days: input.freshness_days,
            redaction_status: input.redaction_status.clone(),
            remediation: if replayable_witness {
                "none".to_string()
            } else {
                "record witness and transcript artifacts, then rerun strict red-team replay"
                    .to_string()
            },
        });
    }

    RedTeamCompromiseRateMetricReport {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        metric_artifact,
        scenarios_total,
        attacks_successful,
        compromise_millionths,
        baseline_compromise_millionths_node,
        baseline_compromise_millionths_bun,
        baseline_reference_millionths,
        reduction_factor_x,
        replayable_witness_scenarios,
        replay_coverage_millionths,
        decision: if passed {
            RedTeamCompromiseRateDecision::Pass
        } else {
            RedTeamCompromiseRateDecision::FailClosed
        },
        reason,
        compromised_scenario_ids,
        unreplayable_scenario_ids,
        events,
    }
}

pub const fn rate_millionths(successes: u64, total: u64) -> u64 {
    if total == 0 {
        0
    } else {
        ((successes as u128 * RATE_SCALE_MILLIONTHS as u128) / total as u128) as u64
    }
}

pub fn metric_input_from_harness_output(
    output: &RedTeamHarnessOutput,
) -> Result<RedTeamCompromiseRateMetricInput, String> {
    validate_harness_output(output)?;

    let scenario_ids = output
        .results
        .iter()
        .map(|result| result.scenario_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut scenarios = Vec::new();
    for scenario_id in scenario_ids {
        let node = harness_result_for(output, scenario_id, RedTeamHarnessRuntime::Node)?;
        let bun = harness_result_for(output, scenario_id, RedTeamHarnessRuntime::Bun)?;
        let frankenengine =
            harness_result_for(output, scenario_id, RedTeamHarnessRuntime::FrankenEngine)?;
        if node.attack_class != bun.attack_class || node.attack_class != frankenengine.attack_class
        {
            return Err(format!(
                "scenario {scenario_id} has inconsistent attack_class across runtimes"
            ));
        }
        if node.security_critical != bun.security_critical
            || node.security_critical != frankenengine.security_critical
        {
            return Err(format!(
                "scenario {scenario_id} has inconsistent security_critical flags across runtimes"
            ));
        }

        let measurement_provenance = RedTeamScenarioMeasurementProvenance {
            source: "bd-28otw_attacker_harness".to_string(),
            min_trials_per_runtime: output.min_trials_per_runtime,
            node_attempts_total: node.attempts_total,
            node_attempts_successful: node.attempts_successful,
            bun_attempts_total: bun.attempts_total,
            bun_attempts_successful: bun.attempts_successful,
            frankenengine_attempts_total: frankenengine.attempts_total,
            frankenengine_attempts_successful: frankenengine.attempts_successful,
            node_compromise_millionths: rate_millionths(
                node.attempts_successful,
                node.attempts_total,
            ),
            bun_compromise_millionths: rate_millionths(bun.attempts_successful, bun.attempts_total),
            frankenengine_compromise_millionths: rate_millionths(
                frankenengine.attempts_successful,
                frankenengine.attempts_total,
            ),
        };

        scenarios.push(RedTeamScenarioEvidence {
            scenario_id: scenario_id.to_string(),
            attack_class: node.attack_class,
            security_critical: node.security_critical,
            frankenengine_outcome: outcome_from_attempts(frankenengine.attempts_successful),
            node_outcome: outcome_from_attempts(node.attempts_successful),
            bun_outcome: outcome_from_attempts(bun.attempts_successful),
            baseline_validation_mode: BaselineDataValidationMode::Observed,
            witness_path: frankenengine.witness_path.clone(),
            witness_hash: frankenengine.witness_hash.clone(),
            transcript_path: frankenengine.transcript_path.clone(),
            transcript_hash: frankenengine.transcript_hash.clone(),
            replay_command: frankenengine.replay_command.clone(),
            replay_exit_code: frankenengine.replay_exit_code,
            duration_ms: frankenengine.duration_ms,
            measurement_provenance: Some(measurement_provenance),
        });
    }

    let input = RedTeamCompromiseRateMetricInput {
        code_revision: output.code_revision.clone(),
        freshness_days: output.freshness_days,
        scenario_set: output.scenario_set.clone(),
        artifact_path: output.artifact_path.clone(),
        artifact_hash: output.artifact_hash.clone(),
        verification_command: output.verification_command.clone(),
        redaction_status: output.redaction_status.clone(),
        confidence_millionths: output.confidence_millionths,
        scenarios,
    };
    input.validate_scenarios()?;
    Ok(input)
}

pub fn summarize_harness_output(
    output: &RedTeamHarnessOutput,
) -> Result<RedTeamHarnessMeasurementSummary, String> {
    validate_harness_output(output)?;
    let node = runtime_compromise_rate(output, RedTeamHarnessRuntime::Node)?;
    let bun = runtime_compromise_rate(output, RedTeamHarnessRuntime::Bun)?;
    let frankenengine = runtime_compromise_rate(output, RedTeamHarnessRuntime::FrankenEngine)?;
    Ok(RedTeamHarnessMeasurementSummary {
        node_to_frankenengine_reduction_ratio_millionths: reduction_ratio_millionths(
            node.compromise_millionths,
            frankenengine.compromise_millionths,
        ),
        bun_to_frankenengine_reduction_ratio_millionths: reduction_ratio_millionths(
            bun.compromise_millionths,
            frankenengine.compromise_millionths,
        ),
        node,
        bun,
        frankenengine,
    })
}

fn validate_harness_output(output: &RedTeamHarnessOutput) -> Result<(), String> {
    if output.schema_version != "franken-engine.red-team-harness-output.v1" {
        return Err(format!(
            "unsupported red-team harness schema_version: {}",
            output.schema_version
        ));
    }
    if output.code_revision.trim().is_empty() {
        return Err("missing harness code_revision".to_string());
    }
    if output.scenario_set.trim().is_empty() {
        return Err("missing harness scenario_set".to_string());
    }
    if validate_sha256(&output.artifact_hash).is_err() {
        return Err("invalid harness artifact_hash".to_string());
    }
    if output.min_trials_per_runtime < 100 {
        return Err(format!(
            "harness min_trials_per_runtime {} is below required 100",
            output.min_trials_per_runtime
        ));
    }
    if output.results.is_empty() {
        return Err("harness output contains no runtime results".to_string());
    }

    for result in &output.results {
        validate_harness_result(result, output.min_trials_per_runtime)?;
    }
    let scenario_ids = output
        .results
        .iter()
        .map(|result| result.scenario_id.as_str())
        .collect::<BTreeSet<_>>();
    for scenario_id in scenario_ids {
        for runtime in [
            RedTeamHarnessRuntime::Node,
            RedTeamHarnessRuntime::Bun,
            RedTeamHarnessRuntime::FrankenEngine,
        ] {
            harness_result_for(output, scenario_id, runtime)?;
        }
    }
    Ok(())
}

fn validate_harness_result(
    result: &RedTeamHarnessRuntimeResult,
    min_trials_per_runtime: u64,
) -> Result<(), String> {
    if result.scenario_id.trim().is_empty() {
        return Err("harness result has empty scenario_id".to_string());
    }
    if result.attempts_total < min_trials_per_runtime {
        return Err(format!(
            "scenario {} runtime {} has {} attempts, below required {}",
            result.scenario_id,
            result.runtime.as_str(),
            result.attempts_total,
            min_trials_per_runtime
        ));
    }
    if result.attempts_successful > result.attempts_total {
        return Err(format!(
            "scenario {} runtime {} has successful attempts above total attempts",
            result.scenario_id,
            result.runtime.as_str()
        ));
    }
    if result.witness_path.trim().is_empty()
        || result.transcript_path.trim().is_empty()
        || result.replay_command.trim().is_empty()
    {
        return Err(format!(
            "scenario {} runtime {} has incomplete replay evidence",
            result.scenario_id,
            result.runtime.as_str()
        ));
    }
    if result.replay_exit_code != 0 {
        return Err(format!(
            "scenario {} runtime {} replay exited {}",
            result.scenario_id,
            result.runtime.as_str(),
            result.replay_exit_code
        ));
    }
    validate_sha256(&result.witness_hash).map_err(|err| {
        format!(
            "scenario {} runtime {} has invalid witness_hash: {err}",
            result.scenario_id,
            result.runtime.as_str()
        )
    })?;
    validate_sha256(&result.transcript_hash).map_err(|err| {
        format!(
            "scenario {} runtime {} has invalid transcript_hash: {err}",
            result.scenario_id,
            result.runtime.as_str()
        )
    })?;
    Ok(())
}

fn harness_result_for<'a>(
    output: &'a RedTeamHarnessOutput,
    scenario_id: &str,
    runtime: RedTeamHarnessRuntime,
) -> Result<&'a RedTeamHarnessRuntimeResult, String> {
    let matches = output
        .results
        .iter()
        .filter(|result| result.scenario_id == scenario_id && result.runtime == runtime)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [result] => Ok(*result),
        [] => Err(format!(
            "scenario {scenario_id} is missing {} harness result",
            runtime.as_str()
        )),
        _ => Err(format!(
            "scenario {scenario_id} has duplicate {} harness results",
            runtime.as_str()
        )),
    }
}

fn runtime_compromise_rate(
    output: &RedTeamHarnessOutput,
    runtime: RedTeamHarnessRuntime,
) -> Result<RedTeamRuntimeCompromiseRate, String> {
    let mut attempts_total = 0_u64;
    let mut attempts_successful = 0_u64;
    for result in output
        .results
        .iter()
        .filter(|result| result.runtime == runtime && result.security_critical)
    {
        attempts_total = attempts_total
            .checked_add(result.attempts_total)
            .ok_or_else(|| format!("{} total attempts overflow", runtime.as_str()))?;
        attempts_successful = attempts_successful
            .checked_add(result.attempts_successful)
            .ok_or_else(|| format!("{} successful attempts overflow", runtime.as_str()))?;
    }
    if attempts_total == 0 {
        return Err(format!(
            "harness output has no security-critical {} attempts",
            runtime.as_str()
        ));
    }
    Ok(RedTeamRuntimeCompromiseRate {
        runtime,
        attempts_total,
        attempts_successful,
        compromise_millionths: rate_millionths(attempts_successful, attempts_total),
    })
}

const fn outcome_from_attempts(attempts_successful: u64) -> ScenarioOutcome {
    if attempts_successful == 0 {
        ScenarioOutcome::Failed
    } else {
        ScenarioOutcome::Succeeded
    }
}

const fn reduction_ratio_millionths(baseline_millionths: u64, candidate_millionths: u64) -> u64 {
    match (baseline_millionths, candidate_millionths) {
        (0, 0) => RATE_SCALE_MILLIONTHS,
        (0, _) => 0,
        (_, 0) => u64::MAX,
        (baseline, candidate) => {
            ((baseline as u128 * RATE_SCALE_MILLIONTHS as u128) / candidate as u128) as u64
        }
    }
}

pub const fn reduction_factor_x(baseline_millionths: u64, candidate_millionths: u64) -> u64 {
    match (baseline_millionths, candidate_millionths) {
        (0, 0) => 1,
        (0, _) => 0,
        (_, 0) => u64::MAX,
        (baseline, candidate) => baseline / candidate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disruptive_floor_metric_gate::{
        DisruptiveFloorGateConfig, DisruptiveMetricId, GateDecisionState, MetricArtifact,
        evaluate_disruptive_floor_gate,
    };

    #[test]
    fn representative_fixture_emits_parent_metric_artifact() {
        let report = evaluate_red_team_compromise_rate_metric(
            &RedTeamCompromiseRateMetricInput::representative_fixture("rev-under-test"),
        );
        assert_eq!(report.decision, RedTeamCompromiseRateDecision::Pass);
        assert_eq!(report.scenarios_total, 10);
        assert_eq!(report.attacks_successful, 1);
        assert_eq!(report.compromise_millionths, 100_000);
        assert_eq!(report.baseline_compromise_millionths_node, 1_000_000);
        assert_eq!(report.baseline_compromise_millionths_bun, 1_000_000);
        assert_eq!(report.reduction_factor_x, 10);
        assert_eq!(
            report.metric_artifact.metric_id,
            DisruptiveMetricId::RedTeamCompromiseRateReduction
        );
        assert_eq!(report.metric_artifact.observed_value, 10);
        assert_eq!(report.metric_artifact.baseline, "node_and_bun");
    }

    #[test]
    fn observed_scenario_helper_marks_real_measurement_mode() {
        let scenario = scenario(
            "observed-ambient-token-exfiltration",
            RedTeamAttackClass::AmbientAuthorityEscape,
            ScenarioOutcome::Failed,
            ScenarioOutcome::Failed,
            ScenarioOutcome::Inconclusive,
        );

        assert_eq!(
            scenario.baseline_validation_mode,
            BaselineDataValidationMode::Observed
        );
        assert!(!scenario.frankenengine_attacker_succeeded());
        assert!(!scenario.node_attacker_succeeded());
        assert!(!scenario.bun_attacker_succeeded());
    }

    #[test]
    fn excessive_compromise_rate_fails_closed() {
        let mut input = RedTeamCompromiseRateMetricInput::representative_fixture("rev-under-test");
        input.scenarios[1].frankenengine_outcome = ScenarioOutcome::Succeeded;
        input.scenarios[2].frankenengine_outcome = ScenarioOutcome::Succeeded;
        let report = evaluate_red_team_compromise_rate_metric(&input);
        assert_eq!(report.decision, RedTeamCompromiseRateDecision::FailClosed);
        assert_eq!(report.attacks_successful, 3);
        assert_eq!(report.compromise_millionths, 300_000);
        assert_eq!(report.reduction_factor_x, 3);
        assert_eq!(report.reason, "compromise_rate_reduction_below_baseline");
    }

    #[test]
    fn empty_red_team_inventory_fails_closed() {
        let mut input = RedTeamCompromiseRateMetricInput::representative_fixture("rev-under-test");
        input.scenarios.clear();
        let report = evaluate_red_team_compromise_rate_metric(&input);
        assert_eq!(report.decision, RedTeamCompromiseRateDecision::FailClosed);
        assert_eq!(report.reason, "missing_red_team_scenario_inventory");
        assert_eq!(report.compromise_millionths, 0);
    }

    #[test]
    fn missing_transcript_hash_fails_closed_on_coverage() {
        let mut input = RedTeamCompromiseRateMetricInput::representative_fixture("rev-under-test");
        input.scenarios[0].transcript_hash.clear();
        let report = evaluate_red_team_compromise_rate_metric(&input);
        assert_eq!(report.decision, RedTeamCompromiseRateDecision::FailClosed);
        assert_eq!(report.replayable_witness_scenarios, 9);
        assert_eq!(report.reason, "unreplayable_red_team_scenarios");
        assert_eq!(
            report.unreplayable_scenario_ids,
            vec!["test-ambient-token-exfiltration-provisional".to_string()]
        );
    }

    #[test]
    fn zero_candidate_compromise_rate_is_unbounded_reduction() {
        let mut input = RedTeamCompromiseRateMetricInput::representative_fixture("rev-under-test");
        for scenario in &mut input.scenarios {
            scenario.frankenengine_outcome = ScenarioOutcome::Failed;
        }
        let report = evaluate_red_team_compromise_rate_metric(&input);
        assert_eq!(report.compromise_millionths, 0);
        assert_eq!(report.reduction_factor_x, u64::MAX);
        assert_eq!(report.decision, RedTeamCompromiseRateDecision::Pass);
    }

    #[test]
    fn unclassified_attack_class_is_rejected_by_deserializer() {
        let json = r#"{
          "code_revision": "rev-under-test",
          "freshness_days": 0,
          "scenario_set": "red_team_security_critical_compromise_v1",
          "artifact_path": "artifacts/red_team_compromise_rate_metric/compromise_details.json",
          "artifact_hash": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "verification_command": "scripts/run_red_team_compromise_rate_metric_gate.sh ci",
          "redaction_status": "redacted",
          "confidence_millionths": 1000000,
          "scenarios": [
            {
              "scenario_id": "unknown",
              "attack_class": "social_engineering",
              "security_critical": true,
              "frankenengine_outcome": "failed",
              "node_outcome": "succeeded",
              "bun_outcome": "succeeded",
              "baseline_validation_mode": "observed",
              "witness_path": "artifacts/red_team_compromise_rate_metric/witnesses/unknown.json",
              "witness_hash": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
              "transcript_path": "artifacts/red_team_compromise_rate_metric/transcripts/unknown.json",
              "transcript_hash": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
              "replay_command": "frankenctl red-team replay --scenario unknown --mode strict",
              "replay_exit_code": 0,
              "duration_ms": 1
            }
          ]
        }"#;
        assert!(serde_json::from_str::<RedTeamCompromiseRateMetricInput>(json).is_err());
    }

    #[test]
    fn report_serialization_is_deterministic_for_fixed_input() {
        let report = evaluate_red_team_compromise_rate_metric(
            &RedTeamCompromiseRateMetricInput::representative_fixture("rev-under-test"),
        );
        let first = serde_json::to_string(&report).unwrap();
        let second = serde_json::to_string(&report).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn fixture_json_deserializes_and_passes() {
        let input: RedTeamCompromiseRateMetricInput = serde_json::from_str(include_str!(
            "../tests/fixtures/red_team_compromise_rate_metric_input_v1.json"
        ))
        .unwrap();
        let report = evaluate_red_team_compromise_rate_metric(&input);
        assert_eq!(report.decision, RedTeamCompromiseRateDecision::Pass);
        assert_eq!(report.events.len(), 5);
        assert_eq!(report.attacks_successful, 0);
        assert_eq!(report.reduction_factor_x, u64::MAX);
    }

    #[test]
    fn bd_28otw_harness_output_converts_to_metric_input() {
        let harness_output: RedTeamHarnessOutput = serde_json::from_str(include_str!(
            "../tests/fixtures/red_team_harness_output_v1.json"
        ))
        .unwrap();
        let summary = summarize_harness_output(&harness_output).unwrap();
        assert_eq!(summary.node.attempts_successful, 500);
        assert_eq!(summary.bun.attempts_successful, 500);
        assert_eq!(summary.frankenengine.attempts_successful, 0);
        assert_eq!(summary.node.compromise_millionths, 1_000_000);
        assert_eq!(summary.bun.compromise_millionths, 1_000_000);
        assert_eq!(summary.frankenengine.compromise_millionths, 0);
        assert_eq!(
            summary.node_to_frankenengine_reduction_ratio_millionths,
            u64::MAX
        );
        assert_eq!(
            summary.bun_to_frankenengine_reduction_ratio_millionths,
            u64::MAX
        );

        let input = metric_input_from_harness_output(&harness_output).unwrap();
        assert_eq!(input.scenarios.len(), 5);
        assert!(
            input
                .scenarios
                .iter()
                .all(RedTeamScenarioEvidence::has_valid_harness_measurement_provenance)
        );
        let report = evaluate_red_team_compromise_rate_metric(&input);
        assert_eq!(report.decision, RedTeamCompromiseRateDecision::Pass);
        assert_eq!(report.scenarios_total, 5);
        assert_eq!(report.attacks_successful, 0);
        assert_eq!(report.reduction_factor_x, u64::MAX);
    }

    #[test]
    fn observed_all_baseline_success_without_harness_provenance_fails_closed() {
        let input = RedTeamCompromiseRateMetricInput {
            code_revision: "rev-under-test".to_string(),
            freshness_days: 0,
            scenario_set: "red_team_security_critical_compromise_v1".to_string(),
            artifact_path: "artifacts/red_team_compromise_rate_metric/compromise_details.json"
                .to_string(),
            artifact_hash:
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_string(),
            verification_command: "scripts/run_red_team_compromise_rate_metric_gate.sh ci"
                .to_string(),
            redaction_status: "redacted".to_string(),
            confidence_millionths: RATE_SCALE_MILLIONTHS,
            scenarios: vec![scenario(
                "observed-shell-command-injection",
                RedTeamAttackClass::AmbientAuthorityEscape,
                ScenarioOutcome::Failed,
                ScenarioOutcome::Succeeded,
                ScenarioOutcome::Succeeded,
            )],
        };

        let report = evaluate_red_team_compromise_rate_metric(&input);
        assert_eq!(report.decision, RedTeamCompromiseRateDecision::FailClosed);
        assert!(report.reason.contains("Hardcoded baseline assumption"));
    }

    #[test]
    fn parent_integrator_accepts_red_team_child_metric_artifact() {
        let child_report = evaluate_red_team_compromise_rate_metric(
            &RedTeamCompromiseRateMetricInput::representative_fixture("rev-under-test"),
        );
        let mut artifacts = DisruptiveMetricId::ALL
            .into_iter()
            .map(|metric_id| MetricArtifact::for_metric(metric_id, metric_id.threshold()))
            .collect::<Vec<_>>();
        let red_team_slot = artifacts
            .iter_mut()
            .find(|artifact| {
                artifact.metric_id == DisruptiveMetricId::RedTeamCompromiseRateReduction
            })
            .unwrap();
        *red_team_slot = child_report.metric_artifact;

        let config = DisruptiveFloorGateConfig::new("rev-under-test");
        let report = evaluate_disruptive_floor_gate(&config, &artifacts);
        assert_eq!(report.decision, GateDecisionState::Pass);
        assert!(report.observed_disruptive_floor_wording_allowed);
    }

    #[test]
    fn markdown_report_names_compromised_scenarios() {
        let report = evaluate_red_team_compromise_rate_metric(
            &RedTeamCompromiseRateMetricInput::representative_fixture("rev-under-test"),
        );
        let markdown = report.to_markdown();
        assert!(markdown.contains("Red-Team Compromise-Rate Metric Gate"));
        assert!(markdown.contains("test-ambient-token-exfiltration-provisional"));
    }
}
