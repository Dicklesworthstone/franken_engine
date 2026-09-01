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
    RATE_SCALE_MILLIONTHS, RedTeamCompromiseRateDecision, RedTeamHarnessMeasurementSummary,
    RedTeamHarnessOutput, RedTeamHarnessRuntime, RedTeamHarnessRuntimeResult, rate_millionths,
    reduction_factor_x, summarize_harness_output,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const OUTPUT_SCHEMA: &str = "franken-engine.red-team-harness-gate-output.v2";
const REPORT_SCHEMA: &str = "franken-engine.red-team-scenario-corpus-gate.v1";
const CONTRACT_SCHEMA: &str = "franken-engine.red-team-scenario-corpus.v2";
const CONTRACT_PATH: &str = "docs/red_team_scenario_corpus_v2.json";
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

#[derive(Debug, Clone, Deserialize)]
struct CorpusScenario {
    scenario_id: String,
    attack_class: String,
}

#[derive(Debug, Clone, Deserialize)]
struct CorpusContract {
    schema_version: String,
    corpus_id: String,
    denominator_semantics: String,
    repetition_role: String,
    confidence_interpretation: String,
    zero_cell_guard: String,
    zero_cell_guard_count: u64,
    required_stability_repetitions_per_runtime_scenario: u64,
    aggregate_verdict_scope: String,
    claim_verdict_producer: String,
    runtimes: Vec<String>,
    scenarios: Vec<CorpusScenario>,
}

impl CorpusContract {
    fn load() -> Result<Self, String> {
        let contract: Self = serde_json::from_str(include_str!(
            "../../../../docs/red_team_scenario_corpus_v2.json"
        ))
        .map_err(|error| format!("invalid embedded {CONTRACT_PATH}: {error}"))?;
        contract.validate()?;
        Ok(contract)
    }

    fn validate(&self) -> Result<(), String> {
        if self.schema_version != CONTRACT_SCHEMA {
            return Err(format!(
                "unsupported corpus contract schema {:?}; expected {CONTRACT_SCHEMA:?}",
                self.schema_version
            ));
        }
        let expected_runtimes = ["node", "bun", "franken_engine"];
        if self.runtimes.iter().map(String::as_str).collect::<Vec<_>>() != expected_runtimes {
            return Err(format!(
                "corpus runtime inventory/order mismatch: {:?}",
                self.runtimes
            ));
        }
        if self.scenarios.len() != 10 {
            return Err(format!(
                "corpus must contain exactly 10 scenarios; found {}",
                self.scenarios.len()
            ));
        }
        let scenario_ids = self
            .scenarios
            .iter()
            .map(|scenario| scenario.scenario_id.as_str())
            .collect::<BTreeSet<_>>();
        if scenario_ids.len() != self.scenarios.len() {
            return Err("corpus scenario IDs are not unique".to_string());
        }
        let attack_classes = self
            .scenarios
            .iter()
            .map(|scenario| scenario.attack_class.as_str())
            .collect::<BTreeSet<_>>();
        let expected_attack_classes = BTreeSet::from([
            "ambient_authority_escape",
            "prototype_pollution",
            "supply_chain_execution",
        ]);
        if attack_classes != expected_attack_classes {
            return Err(format!(
                "corpus attack-class inventory mismatch: {attack_classes:?}"
            ));
        }
        if self.zero_cell_guard_count != 1 {
            return Err(format!(
                "zero_cell_guard_count must be 1; found {}",
                self.zero_cell_guard_count
            ));
        }
        if self.required_stability_repetitions_per_runtime_scenario != 100 {
            return Err(format!(
                "stability repetition floor must be 100; found {}",
                self.required_stability_repetitions_per_runtime_scenario
            ));
        }
        if self.claim_verdict_producer != "franken_red_team_harness_gate" {
            return Err(format!(
                "unexpected claim verdict producer {:?}",
                self.claim_verdict_producer
            ));
        }
        Ok(())
    }

    fn scenario_map(&self) -> BTreeMap<&str, &str> {
        self.scenarios
            .iter()
            .map(|scenario| {
                (
                    scenario.scenario_id.as_str(),
                    scenario.attack_class.as_str(),
                )
            })
            .collect()
    }

    fn runtime_scenario_pair_count(&self) -> u64 {
        (self.runtimes.len() * self.scenarios.len()) as u64
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ScenarioCorpusMetricReport {
    schema_version: &'static str,
    corpus_id: String,
    corpus_contract_path: &'static str,
    claim_scope: &'static str,
    confidence_interpretation: &'static str,
    zero_cell_guard: String,
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
            "# Red-Team Scenario-Corpus Compromise-Rate Gate\n\nDecision: `{:?}`\n\nReason: `{}`\n\nCorpus: `{}`\n\n",
            self.decision, self.reason, self.corpus_id
        );
        out.push_str(
            "The denominator is the exact contract-declared adversarial scenario corpus. Repeated executions qualify stability and replayability; they are not independent population samples.\n\n",
        );
        out.push_str("| Measure | Value |\n|---|---:|\n");
        for (name, value) in [
            ("Distinct security-critical scenarios", self.scenario_count),
            ("Attack classes", self.attack_class_count),
            (
                "Stability repetitions per runtime/scenario",
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

fn raw_string<'a>(object: &'a serde_json::Map<String, Value>, field: &str) -> Option<&'a str> {
    object.get(field).and_then(Value::as_str)
}

fn validate_semantic_annotations(value: &Value, contract: &CorpusContract) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "harness output must be a JSON object".to_string())?;
    for (field, expected) in [
        ("corpus_id", contract.corpus_id.as_str()),
        ("scenario_set", contract.corpus_id.as_str()),
        (
            "denominator_semantics",
            contract.denominator_semantics.as_str(),
        ),
        ("repetition_role", contract.repetition_role.as_str()),
        (
            "confidence_interpretation",
            contract.confidence_interpretation.as_str(),
        ),
        ("zero_cell_guard", contract.zero_cell_guard.as_str()),
        (
            "verdict_scope",
            contract.aggregate_verdict_scope.as_str(),
        ),
        (
            "claim_verdict_producer",
            contract.claim_verdict_producer.as_str(),
        ),
        ("corpus_contract_path", CONTRACT_PATH),
    ] {
        let actual = raw_string(object, field).unwrap_or("<missing>");
        if actual != expected {
            return Err(format!(
                "harness semantic field {field} mismatch: expected {expected:?}, got {actual:?}"
            ));
        }
    }
    if object
        .get("claim_verdict_eligible")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return Err("harness input must set claim_verdict_eligible=false".to_string());
    }
    let expected_numbers = [
        ("zero_cell_guard_count", contract.zero_cell_guard_count),
        (
            "required_stability_repetitions_per_runtime_scenario",
            contract.required_stability_repetitions_per_runtime_scenario,
        ),
        ("distinct_scenario_count", contract.scenarios.len() as u64),
        (
            "attack_class_count",
            contract
                .scenarios
                .iter()
                .map(|scenario| scenario.attack_class.as_str())
                .collect::<BTreeSet<_>>()
                .len() as u64,
        ),
        (
            "runtime_scenario_pair_count",
            contract.runtime_scenario_pair_count(),
        ),
    ];
    for (field, expected) in expected_numbers {
        let actual = object.get(field).and_then(Value::as_u64);
        if actual != Some(expected) {
            return Err(format!(
                "harness semantic field {field} mismatch: expected {expected}, got {actual:?}"
            ));
        }
    }

    let results = object
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| "harness output must contain a results array".to_string())?;
    let expected_scenarios = contract.scenario_map();
    let expected_runtimes = contract
        .runtimes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut observed_scenarios = BTreeMap::new();
    let mut runtime_pairs = BTreeSet::new();
    for (index, row) in results.iter().enumerate() {
        let row = row
            .as_object()
            .ok_or_else(|| format!("results[{index}] must be an object"))?;
        let scenario_id = raw_string(row, "scenario_id")
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("results[{index}].scenario_id must be non-empty"))?;
        let attack_class = raw_string(row, "attack_class")
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("results[{index}].attack_class must be non-empty"))?;
        let runtime = raw_string(row, "runtime")
            .filter(|value| expected_runtimes.contains(*value))
            .ok_or_else(|| format!("results[{index}].runtime is invalid"))?;
        if let Some(previous) = observed_scenarios.insert(scenario_id, attack_class)
            && previous != attack_class
        {
            return Err(format!(
                "scenario {scenario_id} has inconsistent attack classes"
            ));
        }
        if !runtime_pairs.insert((scenario_id, runtime)) {
            return Err(format!("duplicate runtime row for {scenario_id}/{runtime}"));
        }
    }
    if observed_scenarios != expected_scenarios {
        let missing = expected_scenarios
            .keys()
            .filter(|scenario_id| !observed_scenarios.contains_key(*scenario_id))
            .copied()
            .collect::<Vec<_>>();
        let extra = observed_scenarios
            .keys()
            .filter(|scenario_id| !expected_scenarios.contains_key(*scenario_id))
            .copied()
            .collect::<Vec<_>>();
        let wrong_class = observed_scenarios
            .iter()
            .filter_map(|(scenario_id, actual)| {
                expected_scenarios
                    .get(scenario_id)
                    .filter(|expected| *expected != actual)
                    .map(|expected| (*scenario_id, *expected, *actual))
            })
            .collect::<Vec<_>>();
        return Err(format!(
            "harness corpus identity mismatch: missing={missing:?}, extra={extra:?}, wrong_class={wrong_class:?}"
        ));
    }
    let expected_pairs = expected_scenarios
        .keys()
        .flat_map(|scenario_id| {
            expected_runtimes
                .iter()
                .map(move |runtime| (*scenario_id, *runtime))
        })
        .collect::<BTreeSet<_>>();
    if runtime_pairs != expected_pairs {
        return Err(format!(
            "harness runtime matrix mismatch: missing={:?}, extra={:?}",
            expected_pairs.difference(&runtime_pairs).collect::<Vec<_>>(),
            runtime_pairs.difference(&expected_pairs).collect::<Vec<_>>()
        ));
    }
    Ok(())
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

fn validate_metadata(
    harness: &RedTeamHarnessOutput,
    contract: &CorpusContract,
) -> Result<(), String> {
    if harness.scenario_set != contract.corpus_id {
        return Err(format!(
            "typed scenario_set mismatch: expected {:?}, got {:?}",
            contract.corpus_id, harness.scenario_set
        ));
    }
    if harness.min_trials_per_runtime
        < contract.required_stability_repetitions_per_runtime_scenario
    {
        return Err(format!(
            "declared stability repetitions {} are below contract floor {}",
            harness.min_trials_per_runtime,
            contract.required_stability_repetitions_per_runtime_scenario
        ));
    }
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

fn matrix_facts(
    harness: &RedTeamHarnessOutput,
    contract: &CorpusContract,
) -> Result<MatrixFacts, String> {
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

    let expected_scenarios = contract.scenario_map();
    if grouped.keys().copied().collect::<BTreeSet<_>>()
        != expected_scenarios.keys().copied().collect::<BTreeSet<_>>()
    {
        return Err("typed scenario inventory does not match corpus contract".to_string());
    }

    let mut scenarios = Vec::new();
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
        let expected_attack_class = expected_scenarios[scenario_id];
        for result in [node, bun, frankenengine] {
            if result.attack_class.as_str() != expected_attack_class {
                return Err(format!(
                    "scenario {scenario_id} has typed attack class {}, expected {expected_attack_class}",
                    result.attack_class.as_str()
                ));
            }
        }
        if node.attempts_total != bun.attempts_total
            || node.attempts_total != frankenengine.attempts_total
        {
            return Err(format!(
                "scenario {scenario_id} has unequal runtime repetition denominators"
            ));
        }
        match common_trials {
            None => common_trials = Some(node.attempts_total),
            Some(expected) if expected == node.attempts_total => {}
            Some(expected) => {
                return Err(format!(
                    "scenario {scenario_id} has {} repetitions per runtime; expected {expected}",
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
            "repetition denominator {trials_per_runtime_scenario} is below declared minimum {}",
            harness.min_trials_per_runtime
        ));
    }
    Ok(MatrixFacts {
        scenarios,
        trials_per_runtime_scenario,
        stable_pairs,
        total_pairs,
        mixed_pairs,
    })
}

fn evaluate(
    harness: &RedTeamHarnessOutput,
    contract: &CorpusContract,
) -> Result<ScenarioCorpusMetricReport, String> {
    validate_metadata(harness, contract)?;
    summarize_harness_output(harness)?;
    let facts = matrix_facts(harness, contract)?;
    let scenario_count = facts.scenarios.len() as u64;
    let attack_class_count = contract
        .scenarios
        .iter()
        .map(|scenario| scenario.attack_class.as_str())
        .collect::<BTreeSet<_>>()
        .len() as u64;
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
    let guarded_frankenengine_compromised_scenarios = frankenengine_compromised_scenarios
        .max(contract.zero_cell_guard_count);
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

    let (decision, reason) = if !facts.mixed_pairs.is_empty() {
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
            "{}:distinct_scenarios:{scenario_count}:stability_repetitions_per_pair:{}:zero_cell_guard:{}",
            contract.corpus_id,
            facts.trials_per_runtime_scenario,
            contract.zero_cell_guard_count
        ),
        scenario_set: contract.corpus_id.clone(),
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
        corpus_id: contract.corpus_id.clone(),
        corpus_contract_path: CONTRACT_PATH,
        claim_scope: "exact contract-declared scenario corpus and pinned runtime identities only",
        confidence_interpretation: "receipt completeness and outcome stability; not statistical population confidence",
        zero_cell_guard: contract.zero_cell_guard.clone(),
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
    let contract = CorpusContract::load()?;
    let bytes = read_input(&args.input)?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid RedTeamHarnessOutput JSON: {error}"))?;
    validate_semantic_annotations(&value, &contract)?;
    let harness: RedTeamHarnessOutput = serde_json::from_value(value)
        .map_err(|error| format!("invalid RedTeamHarnessOutput schema: {error}"))?;
    let summary = summarize_harness_output(&harness)
        .map_err(|error| format!("invalid scenario-corpus stability input: {error}"))?;
    let report = evaluate(&harness, &contract)?;
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
