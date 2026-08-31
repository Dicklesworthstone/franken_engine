#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use frankenengine_engine::disruptive_floor_metric_gate::{
    DEFAULT_MAX_FRESHNESS_DAYS, DEFAULT_MIN_CONFIDENCE_MILLIONTHS,
    DisruptiveMetricId, MetricArtifact,
};
use frankenengine_engine::red_team_compromise_rate_metric_gate::{
    RATE_SCALE_MILLIONTHS, RedTeamAttackClass, RedTeamCompromiseRateDecision,
    RedTeamHarnessMeasurementSummary, RedTeamHarnessOutput, RedTeamHarnessRuntime,
    RedTeamHarnessRuntimeResult, rate_millionths, reduction_factor_x, summarize_harness_output,
};
use serde::Serialize;

const OUTPUT_SCHEMA: &str = "franken-engine.red-team-harness-gate-output.v2";
const REPORT_SCHEMA: &str = "franken-engine.red-team-scenario-corpus-gate.v1";
const MIN_DISTINCT_SCENARIOS: u64 = 10;
const MIN_ATTACK_CLASSES: u64 = 3;
const ZERO_CELL_GUARD_COUNT: u64 = 1;
const USAGE: &str =
    "usage: franken_red_team_harness_gate --input PATH|- [--output PATH] [--markdown PATH]";

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedArgs {
    Run(Args),
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    input: String,
    output: Option<PathBuf>,
    markdown: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ScenarioCorpusMetricReport {
    schema_version: &'static str,
    claim_scope: &'static str,
    confidence_interpretation: &'static str,
    zero_cell_guard: &'static str,
    metric_artifact: MetricArtifact,
    scenario_count: u64,
    attack_class_count: u64,
    trials_per_runtime_scenario: u64,
    stability_coverage_millionths: u64,
    node_compromised_scenarios: u64,
    bun_compromised_scenarios: u64,
    baseline_reference_compromised_scenarios: u64,
    frankenengine_compromised_scenarios: u64,
    guarded_frankenengine_compromised_scenarios: u64,
    raw_reduction_factor_x: u64,
    conservative_reduction_floor_x: u64,
    decision: RedTeamCompromiseRateDecision,
    reason: String,
    mixed_outcome_pairs: Vec<String>,
}

impl ScenarioCorpusMetricReport {
    fn to_markdown(&self) -> String {
        let mut out = format!(
            "# Red-Team Scenario-Corpus Compromise-Rate Gate\n\nDecision: `{:?}`\n\nReason: `{}`\n\n",
            self.decision, self.reason
        );
        out.push_str(
            "The denominator is the declared distinct adversarial scenario corpus. Repeated executions qualify stability and replayability; they are not treated as independent population samples.\n\n",
        );
        out.push_str("| Measure | Value |\n|---|---:|\n");
        for (name, value) in [
            ("Distinct security-critical scenarios", self.scenario_count),
            ("Attack classes", self.attack_class_count),
            (
                "Stability trials per runtime/scenario",
                self.trials_per_runtime_scenario,
            ),
            ("Node compromised scenarios", self.node_compromised_scenarios),
            ("Bun compromised scenarios", self.bun_compromised_scenarios),
            (
                "FrankenEngine compromised scenarios",
                self.frankenengine_compromised_scenarios,
            ),
            ("Raw reduction", self.raw_reduction_factor_x),
            (
                "Zero-cell-guarded reduction floor",
                self.conservative_reduction_floor_x,
            ),
        ] {
            out.push_str(&format!("| {name} | {value} |\n"));
        }
        if !self.mixed_outcome_pairs.is_empty() {
            out.push_str("\nMixed runtime/scenario outcomes:\n");
            for pair in &self.mixed_outcome_pairs {
                out.push_str(&format!("- `{pair}`\n"));
            }
        }
        out
    }
}

#[derive(Debug, Serialize)]
struct GateOutput {
    schema_version: &'static str,
    input: String,
    summary: RedTeamHarnessMeasurementSummary,
    report: ScenarioCorpusMetricReport,
}

#[derive(Debug)]
struct ScenarioFacts {
    node_compromised: bool,
    bun_compromised: bool,
    frankenengine_compromised: bool,
}

#[derive(Debug)]
struct MatrixFacts {
    scenarios: Vec<ScenarioFacts>,
    attack_classes: BTreeSet<RedTeamAttackClass>,
    trials_per_runtime_scenario: u64,
    stable_pairs: u64,
    total_pairs: u64,
    mixed_pairs: Vec<String>,
}

fn parse_args(arguments: impl IntoIterator<Item = String>) -> Result<ParsedArgs, String> {
    let mut input = None;
    let mut output = None;
    let mut markdown = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--input" => {
                input = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--input requires a value".to_string())?,
                );
            }
            "--output" => {
                output = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--output requires a value".to_string())?,
                ));
            }
            "--markdown" => {
                markdown = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--markdown requires a value".to_string())?,
                ));
            }
            "-h" | "--help" => return Ok(ParsedArgs::Help),
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok(ParsedArgs::Run(Args {
        input: input.ok_or_else(|| "--input is required".to_string())?,
        output,
        markdown,
    }))
}

fn read_input(input: &str) -> Result<Vec<u8>, String> {
    if input == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read harness JSON from stdin: {error}"))?;
        Ok(bytes)
    } else {
        fs::read(input).map_err(|error| format!("failed to read harness JSON from {input}: {error}"))
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create output directory {}: {error}",
            parent.display()
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("output path has no UTF-8 file name: {}", path.display()))?;
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    fs::write(&temporary, bytes)
        .map_err(|error| format!("failed to write {}: {error}", temporary.display()))?;
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| format!("failed to replace {}: {error}", path.display()))?;
    }
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        format!(
            "failed to publish {} as {}: {error}",
            temporary.display(),
            path.display()
        )
    })
}

fn result_for<'a>(
    rows: &[&'a RedTeamHarnessRuntimeResult],
    scenario_id: &str,
    runtime: RedTeamHarnessRuntime,
) -> Result<&'a RedTeamHarnessRuntimeResult, String> {
    let matches = rows
        .iter()
        .copied()
        .filter(|result| result.runtime == runtime)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [result] => Ok(*result),
        [] => Err(format!(
            "scenario {scenario_id} is missing {} result",
            runtime.as_str()
        )),
        _ => Err(format!(
            "scenario {scenario_id} has duplicate {} results",
            runtime.as_str()
        )),
    }
}

fn validate_metadata(harness: &RedTeamHarnessOutput) -> Result<(), String> {
    if harness.artifact_path.trim().is_empty() || harness.verification_command.trim().is_empty() {
        return Err("harness artifact_path and verification_command must be non-empty".to_string());
    }
    if harness.freshness_days > DEFAULT_MAX_FRESHNESS_DAYS {
        return Err(format!(
            "harness freshness_days {} exceeds maximum {}",
            harness.freshness_days, DEFAULT_MAX_FRESHNESS_DAYS
        ));
    }
    if harness.redaction_status != "redacted" {
        return Err("harness command transcript is not marked redacted".to_string());
    }
    if !(DEFAULT_MIN_CONFIDENCE_MILLIONTHS..=RATE_SCALE_MILLIONTHS)
        .contains(&harness.confidence_millionths)
    {
        return Err(format!(
            "harness confidence_millionths {} is outside accepted range",
            harness.confidence_millionths
        ));
    }
    Ok(())
}

fn matrix_facts(harness: &RedTeamHarnessOutput) -> Result<MatrixFacts, String> {
    let mut grouped: BTreeMap<&str, Vec<&RedTeamHarnessRuntimeResult>> = BTreeMap::new();
    for result in &harness.results {
        if !result.security_critical {
            return Err(format!(
                "scenario {} contains a non-security-critical result",
                result.scenario_id
            ));
        }
        grouped
            .entry(result.scenario_id.as_str())
            .or_default()
            .push(result);
    }

    let mut scenarios = Vec::new();
    let mut attack_classes = BTreeSet::new();
    let mut common_trials = None;
    let mut stable_pairs = 0;
    let mut total_pairs = 0;
    let mut mixed_pairs = Vec::new();
    for (scenario_id, rows) in grouped {
        let node = result_for(&rows, scenario_id, RedTeamHarnessRuntime::Node)?;
        let bun = result_for(&rows, scenario_id, RedTeamHarnessRuntime::Bun)?;
        let frankenengine = result_for(
            &rows,
            scenario_id,
            RedTeamHarnessRuntime::FrankenEngine,
        )?;
        if node.attack_class != bun.attack_class || node.attack_class != frankenengine.attack_class
        {
            return Err(format!(
                "scenario {scenario_id} has inconsistent attack_class across runtimes"
            ));
        }
        if node.attempts_total != bun.attempts_total
            || node.attempts_total != frankenengine.attempts_total
        {
            return Err(format!(
                "scenario {scenario_id} has unequal runtime attempt denominators"
            ));
        }
        match common_trials {
            None => common_trials = Some(node.attempts_total),
            Some(expected) if expected == node.attempts_total => {}
            Some(expected) => {
                return Err(format!(
                    "scenario {scenario_id} has {} attempts per runtime; expected {expected}",
                    node.attempts_total
                ));
            }
        }
        for result in [node, bun, frankenengine] {
            total_pairs += 1;
            if result.attempts_successful == 0
                || result.attempts_successful == result.attempts_total
            {
                stable_pairs += 1;
            } else {
                mixed_pairs.push(format!(
                    "{}/{}:{}/{}",
                    scenario_id,
                    result.runtime.as_str(),
                    result.attempts_successful,
                    result.attempts_total
                ));
            }
        }
        attack_classes.insert(node.attack_class);
        scenarios.push(ScenarioFacts {
            node_compromised: node.attempts_successful > 0,
            bun_compromised: bun.attempts_successful > 0,
            frankenengine_compromised: frankenengine.attempts_successful > 0,
        });
    }
    let trials_per_runtime_scenario =
        common_trials.ok_or_else(|| "harness contains no security-critical scenarios".to_string())?;
    if trials_per_runtime_scenario < harness.min_trials_per_runtime {
        return Err(format!(
            "attempt denominator {trials_per_runtime_scenario} is below declared minimum {}",
            harness.min_trials_per_runtime
        ));
    }
    Ok(MatrixFacts {
        scenarios,
        attack_classes,
        trials_per_runtime_scenario,
        stable_pairs,
        total_pairs,
        mixed_pairs,
    })
}

fn evaluate(harness: &RedTeamHarnessOutput) -> Result<ScenarioCorpusMetricReport, String> {
    validate_metadata(harness)?;
    summarize_harness_output(harness)?;
    let facts = matrix_facts(harness)?;
    let scenario_count = facts.scenarios.len() as u64;
    let attack_class_count = facts.attack_classes.len() as u64;
    let node_compromised_scenarios = facts
        .scenarios
        .iter()
        .filter(|scenario| scenario.node_compromised)
        .count() as u64;
    let bun_compromised_scenarios = facts
        .scenarios
        .iter()
        .filter(|scenario| scenario.bun_compromised)
        .count() as u64;
    let frankenengine_compromised_scenarios = facts
        .scenarios
        .iter()
        .filter(|scenario| scenario.frankenengine_compromised)
        .count() as u64;
    let baseline_reference_compromised_scenarios =
        node_compromised_scenarios.min(bun_compromised_scenarios);
    let guarded_frankenengine_compromised_scenarios =
        frankenengine_compromised_scenarios.max(ZERO_CELL_GUARD_COUNT);
    let baseline_rate = rate_millionths(
        baseline_reference_compromised_scenarios,
        scenario_count,
    );
    let candidate_rate = rate_millionths(frankenengine_compromised_scenarios, scenario_count);
    let raw_reduction_factor_x = reduction_factor_x(baseline_rate, candidate_rate);
    let conservative_reduction_floor_x = baseline_reference_compromised_scenarios
        / guarded_frankenengine_compromised_scenarios;
    let stability_coverage_millionths = rate_millionths(facts.stable_pairs, facts.total_pairs);
    let threshold = DisruptiveMetricId::RedTeamCompromiseRateReduction.threshold();

    let (decision, reason) = if scenario_count < MIN_DISTINCT_SCENARIOS {
        (
            RedTeamCompromiseRateDecision::FailClosed,
            "insufficient_distinct_scenario_denominator",
        )
    } else if attack_class_count < MIN_ATTACK_CLASSES {
        (
            RedTeamCompromiseRateDecision::FailClosed,
            "insufficient_attack_class_diversity",
        )
    } else if !facts.mixed_pairs.is_empty() {
        (
            RedTeamCompromiseRateDecision::FailClosed,
            "unstable_runtime_scenario_outcomes",
        )
    } else if conservative_reduction_floor_x < threshold {
        (
            RedTeamCompromiseRateDecision::FailClosed,
            "zero_cell_guarded_reduction_below_threshold",
        )
    } else {
        (
            RedTeamCompromiseRateDecision::Pass,
            "red_team_compromise_rate_reduction_verified_on_declared_scenario_corpus",
        )
    };

    let metric_id = DisruptiveMetricId::RedTeamCompromiseRateReduction;
    let metric_artifact = MetricArtifact {
        metric_id,
        threshold,
        observed_value: conservative_reduction_floor_x,
        unit: metric_id.unit().to_string(),
        baseline: metric_id.expected_baseline().to_string(),
        candidate: "franken_engine".to_string(),
        denominator_id: format!(
            "node_and_bun:red_team_scenarios:{scenario_count}:stability_trials_per_pair:{}:zero_cell_guard:{}",
            facts.trials_per_runtime_scenario, ZERO_CELL_GUARD_COUNT
        ),
        scenario_set: harness.scenario_set.clone(),
        artifact_path: harness.artifact_path.clone(),
        artifact_hash: harness.artifact_hash.clone(),
        code_revision: harness.code_revision.clone(),
        freshness_days: harness.freshness_days,
        confidence_millionths: harness.confidence_millionths,
        coverage_millionths: stability_coverage_millionths,
        verification_command: harness.verification_command.clone(),
        redaction_status: harness.redaction_status.clone(),
    };

    Ok(ScenarioCorpusMetricReport {
        schema_version: REPORT_SCHEMA,
        claim_scope: "exact declared scenario corpus and pinned runtime identities only",
        confidence_interpretation: "receipt completeness and outcome stability; not statistical population confidence",
        zero_cell_guard: "zero observed FrankenEngine compromises count as one hypothetical compromise for threshold gating",
        metric_artifact,
        scenario_count,
        attack_class_count,
        trials_per_runtime_scenario: facts.trials_per_runtime_scenario,
        stability_coverage_millionths,
        node_compromised_scenarios,
        bun_compromised_scenarios,
        baseline_reference_compromised_scenarios,
        frankenengine_compromised_scenarios,
        guarded_frankenengine_compromised_scenarios,
        raw_reduction_factor_x,
        conservative_reduction_floor_x,
        decision,
        reason: reason.to_string(),
        mixed_outcome_pairs: facts.mixed_pairs,
    })
}

fn evaluate_args(args: &Args) -> Result<GateOutput, String> {
    let bytes = read_input(&args.input)?;
    let harness: RedTeamHarnessOutput = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid RedTeamHarnessOutput JSON: {error}"))?;
    let summary = summarize_harness_output(&harness)
        .map_err(|error| format!("invalid repeated-trial harness output: {error}"))?;
    let report = evaluate(&harness)?;
    Ok(GateOutput {
        schema_version: OUTPUT_SCHEMA,
        input: args.input.clone(),
        summary,
        report,
    })
}

fn run() -> Result<ExitCode, String> {
    let args = match parse_args(env::args().skip(1))? {
        ParsedArgs::Run(args) => args,
        ParsedArgs::Help => {
            println!("{USAGE}");
            return Ok(ExitCode::SUCCESS);
        }
    };
    let output = evaluate_args(&args)?;
    let mut json = serde_json::to_vec_pretty(&output)
        .map_err(|error| format!("failed to serialize gate output: {error}"))?;
    json.push(b'\n');
    if let Some(path) = &args.output {
        write_atomic(path, &json)?;
    } else {
        print!("{}", String::from_utf8_lossy(&json));
    }
    if let Some(path) = &args.markdown {
        write_atomic(path, output.report.to_markdown().as_bytes())?;
    }
    Ok(match output.report.decision {
        RedTeamCompromiseRateDecision::Pass => ExitCode::SUCCESS,
        RedTeamCompromiseRateDecision::FailClosed => ExitCode::from(1),
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("franken_red_team_harness_gate: {error}");
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
