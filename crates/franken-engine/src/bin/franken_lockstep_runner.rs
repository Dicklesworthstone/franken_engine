#![forbid(unsafe_code)]

//! `franken_lockstep_runner` is the canonical lockstep harness entrypoint.
//!
//! It reuses the parser multi-engine harness substrate so lockstep runs can
//! compare FrankenEngine against pinned external engines with deterministic
//! seeds, stable drift taxonomy, and replayable JSON reports.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
};

use frankenengine_engine::parser_multi_engine_harness::{
    DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH, DriftGovernanceAction, HarnessEngineKind,
    HarnessEngineSpec, MultiEngineHarnessConfig, MultiEngineHarnessReport,
    build_drift_governance_action_report, has_critical_drift, run_multi_engine_harness,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LOCKSTEP_RUNTIME_SPECS_SCHEMA_VERSION: &str = "franken-engine.lockstep-runtimes.v1";
const LOCKSTEP_PREFLIGHT_SCHEMA_VERSION: &str = "franken-engine.lockstep-preflight.v1";
const LOCKSTEP_EVIDENCE_SCHEMA_VERSION: &str = "franken-engine.lockstep-evidence.v1";
const LOCKSTEP_GOVERNANCE_SCHEMA_VERSION: &str = "franken-engine.lockstep-governance.v1";
const LOCKSTEP_CANON_RULES_SCHEMA_VERSION: &str = "franken-engine.lockstep-canon-rules.v1";
const DEFAULT_LOCKSTEP_RUNTIME_SPECS_PATH: &str =
    "crates/franken-engine/tests/fixtures/lockstep_runtimes.toml";
const DEFAULT_LOCKSTEP_CANON_RULES_PATH: &str =
    "crates/franken-engine/tests/fixtures/lockstep_canon_rules.toml";
const DEFAULT_LOCKSTEP_CANON_RULES_CONTENT: &str = r#"schema_version = "franken-engine.lockstep-canon-rules.v1"

[[rules]]
rule_id = "normalize-newlines"
kind = "newline_normalization"
description = "Normalize CRLF and CR line endings before observable output comparison."

[[rules]]
rule_id = "trim-engine-stack-noise"
kind = "stack_trace_noise"
description = "Strip engine-specific stack-frame prefixes and locations from thrown error output."

[[rules]]
rule_id = "collapse-whitespace-runs"
kind = "whitespace_normalization"
description = "Collapse repeated whitespace in diagnostic and console output comparison surfaces."
"#;

#[derive(Debug)]
struct CliArgs {
    config: MultiEngineHarnessConfig,
    out_path: Option<PathBuf>,
    evidence_jsonl_path: Option<PathBuf>,
    governance_actions_out_path: Option<PathBuf>,
    canon_rules_path: Option<PathBuf>,
    fail_on_divergence: bool,
    allow_critical_drift: bool,
    max_retries: u32,
    quarantine_flaky_fixtures: bool,
    preflight_only: bool,
    print_help: bool,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EngineSpecFile {
    Array(Vec<HarnessEngineSpec>),
    Wrapped { engines: Vec<HarnessEngineSpec> },
}

#[derive(Debug, Deserialize)]
struct LockstepRuntimeSpecsFile {
    schema_version: String,
    runtimes: Vec<LockstepRuntimeSpec>,
}

#[derive(Debug, Deserialize)]
struct LockstepRuntimeSpec {
    runtime_id: String,
    display_name: String,
    version_pin: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default = "default_runtime_enabled")]
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct LockstepRuntimeVersion {
    engine_id: String,
    version_pin: String,
}

#[derive(Debug, Serialize)]
struct LockstepCategoryMatchRate {
    total_fixtures: u64,
    equivalent_fixtures: u64,
    match_rate_ppm: u64,
}

#[derive(Debug)]
struct LockstepCanonRules {
    hash: String,
}

#[derive(Debug, Serialize)]
struct LockstepEvidenceRecord {
    schema_version: String,
    generated_at_utc: String,
    run_id: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    fixture_catalog_hash: String,
    canon_rules_hash: String,
    environment_fingerprint: String,
    parser_mode: String,
    seed: u64,
    locale: String,
    timezone: String,
    fixture_count: u64,
    equivalent_fixtures: u64,
    divergent_fixtures: u64,
    nondeterministic_fixtures: u64,
    drift_minor_fixtures: u64,
    drift_critical_fixtures: u64,
    retry_attempts: u32,
    max_retries: u32,
    observed_flaky_fixture_ids: Vec<String>,
    quarantined_fixture_ids: Vec<String>,
    governance_action_count: u64,
    divergence_class_distribution: BTreeMap<String, u64>,
    runtime_versions: Vec<LockstepRuntimeVersion>,
    category_match_rates: BTreeMap<String, LockstepCategoryMatchRate>,
}

#[derive(Debug, Serialize)]
struct LockstepGovernanceRecord {
    schema_version: String,
    generated_at_utc: String,
    run_id: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    retry_attempts: u32,
    max_retries: u32,
    observed_flaky_fixture_ids: Vec<String>,
    quarantined_fixture_ids: Vec<String>,
    critical_drift_detected: bool,
    actions: Vec<DriftGovernanceAction>,
}

#[derive(Debug)]
struct HarnessRunWithRetries {
    report: MultiEngineHarnessReport,
    retry_attempts: u32,
    observed_flaky_fixture_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum PreflightCheckOutcome {
    Pass,
    Fail,
}

#[derive(Debug, Serialize)]
struct PreflightCheck {
    engine_id: String,
    check: String,
    outcome: PreflightCheckOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    detail: String,
}

#[derive(Debug, Serialize)]
struct PreflightReport {
    schema_version: String,
    preflight_passed: bool,
    engine_count: usize,
    checked_external_engines: usize,
    checks: Vec<PreflightCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
}

fn default_runtime_enabled() -> bool {
    true
}

fn main() {
    match run() {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32, Box<dyn Error>> {
    let args = parse_args(std::env::args().skip(1))?;
    if args.print_help {
        return Ok(0);
    }
    let canon_rules = resolve_lockstep_canon_rules(args.canon_rules_path.as_deref())?;
    if args.preflight_only {
        let report = run_preflight(&args.config);
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(if report.preflight_passed { 0 } else { 4 });
    }

    let harness = run_harness_with_retries(&args.config, args.max_retries)?;
    let mut report = harness.report;
    let final_flaky_fixture_ids = collect_flaky_fixture_ids(&report);
    let quarantined_fixture_ids = if args.quarantine_flaky_fixtures {
        final_flaky_fixture_ids.clone()
    } else {
        Vec::new()
    };
    let governance_action_count =
        if let Some(governance_actions_out_path) = args.governance_actions_out_path.as_ref() {
            write_lockstep_governance_report(
                governance_actions_out_path,
                &report,
                harness.retry_attempts,
                args.max_retries,
                harness.observed_flaky_fixture_ids.as_slice(),
                quarantined_fixture_ids.as_slice(),
            )?
        } else {
            build_drift_governance_action_report(&report).actions.len() as u64
        };

    rewrite_replay_commands_for_lockstep_runner(&mut report);
    if let Some(evidence_jsonl_path) = &args.evidence_jsonl_path {
        append_lockstep_evidence_jsonl(
            evidence_jsonl_path,
            &report,
            harness.retry_attempts,
            args.max_retries,
            harness.observed_flaky_fixture_ids.as_slice(),
            quarantined_fixture_ids.as_slice(),
            governance_action_count,
            canon_rules.hash.as_str(),
        )?;
    }
    let json = serde_json::to_string_pretty(&report)?;

    if let Some(out_path) = &args.out_path {
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out_path, json.as_bytes())?;
    }

    println!("{json}");

    if !args.allow_critical_drift && has_critical_drift(&report) {
        return Ok(3);
    }

    let (gate_divergent_fixtures, gate_nondeterministic_fixtures) =
        effective_gate_summary_counts(&report, args.quarantine_flaky_fixtures);
    if args.fail_on_divergence
        && (gate_divergent_fixtures > 0 || gate_nondeterministic_fixtures > 0)
    {
        Ok(2)
    } else {
        Ok(0)
    }
}

fn run_harness_with_retries(
    config: &MultiEngineHarnessConfig,
    max_retries: u32,
) -> Result<HarnessRunWithRetries, Box<dyn Error>> {
    let mut retry_attempts = 0_u32;
    let mut observed_flaky_fixture_ids = BTreeSet::new();
    loop {
        let report = run_multi_engine_harness(config)?;
        let flaky_fixture_ids = collect_flaky_fixture_ids(&report);
        for fixture_id in &flaky_fixture_ids {
            observed_flaky_fixture_ids.insert(fixture_id.clone());
        }
        if flaky_fixture_ids.is_empty() || retry_attempts >= max_retries {
            return Ok(HarnessRunWithRetries {
                report,
                retry_attempts,
                observed_flaky_fixture_ids: observed_flaky_fixture_ids.into_iter().collect(),
            });
        }
        retry_attempts = retry_attempts.saturating_add(1);
    }
}

fn collect_flaky_fixture_ids(report: &MultiEngineHarnessReport) -> Vec<String> {
    let mut fixture_ids = report
        .fixture_results
        .iter()
        .filter(|result| result.nondeterministic_engine_count > 0)
        .map(|result| result.fixture_id.clone())
        .collect::<Vec<_>>();
    fixture_ids.sort();
    fixture_ids.dedup();
    fixture_ids
}

fn effective_gate_summary_counts(
    report: &MultiEngineHarnessReport,
    quarantine_flaky_fixtures: bool,
) -> (u64, u64) {
    if !quarantine_flaky_fixtures {
        return (
            report.summary.divergent_fixtures,
            report.summary.fixtures_with_nondeterminism,
        );
    }
    let quarantined = report
        .fixture_results
        .iter()
        .filter(|result| result.nondeterministic_engine_count > 0)
        .count() as u64;
    (
        report
            .summary
            .divergent_fixtures
            .saturating_sub(quarantined),
        0,
    )
}

fn rewrite_replay_commands_for_lockstep_runner(report: &mut MultiEngineHarnessReport) {
    for fixture in &mut report.fixture_results {
        fixture.replay_command = fixture.replay_command.replace(
            "--bin franken_parser_multi_engine_harness",
            "--bin franken_lockstep_runner",
        );
    }
}

fn parse_args<I>(args: I) -> Result<CliArgs, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut seed = 1_u64;
    let mut fixture_catalog = PathBuf::from(DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH);
    let mut fixture_limit = Some(8_usize);
    let mut fixture_id_filter = None::<String>;
    let mut trace_id = None::<String>;
    let mut decision_id = None::<String>;
    let mut policy_id = None::<String>;
    let mut locale = None::<String>;
    let mut timezone = None::<String>;
    let mut engine_specs = None::<Vec<HarnessEngineSpec>>;
    let mut runtime_specs_path = None::<PathBuf>;
    let mut canon_rules_path = None::<PathBuf>;
    let mut out_path = None::<PathBuf>;
    let mut evidence_jsonl_path = None::<PathBuf>;
    let mut governance_actions_out_path = None::<PathBuf>;
    let mut fail_on_divergence = false;
    let mut allow_critical_drift = false;
    let mut max_retries = 0_u32;
    let mut quarantine_flaky_fixtures = false;
    let mut preflight_only = false;
    let mut print_help_flag = false;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--fixture-catalog" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --fixture-catalog".to_string())?;
                fixture_catalog = PathBuf::from(value);
            }
            "--fixture-limit" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --fixture-limit".to_string())?;
                fixture_limit = parse_fixture_limit(value.as_str())?;
            }
            "--fixture-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --fixture-id".to_string())?;
                fixture_id_filter = Some(value);
            }
            "--seed" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --seed".to_string())?;
                seed = value.parse::<u64>()?;
            }
            "--trace-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --trace-id".to_string())?;
                trace_id = Some(value);
            }
            "--decision-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --decision-id".to_string())?;
                decision_id = Some(value);
            }
            "--policy-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --policy-id".to_string())?;
                policy_id = Some(value);
            }
            "--locale" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --locale".to_string())?;
                locale = Some(value);
            }
            "--timezone" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --timezone".to_string())?;
                timezone = Some(value);
            }
            "--engine-specs" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --engine-specs".to_string())?;
                engine_specs = Some(load_engine_specs(Path::new(value.as_str()))?);
            }
            "--runtime-specs" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --runtime-specs".to_string())?;
                runtime_specs_path = Some(PathBuf::from(value));
            }
            "--canon-rules" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --canon-rules".to_string())?;
                canon_rules_path = Some(PathBuf::from(value));
            }
            "--fail-on-divergence" => {
                fail_on_divergence = true;
            }
            "--preflight-only" => {
                preflight_only = true;
            }
            "--out" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --out".to_string())?;
                out_path = Some(PathBuf::from(value));
            }
            "--evidence-jsonl" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --evidence-jsonl".to_string())?;
                evidence_jsonl_path = Some(PathBuf::from(value));
            }
            "--governance-actions-out" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --governance-actions-out".to_string())?;
                governance_actions_out_path = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                print_help();
                print_help_flag = true;
            }
            "--allow-critical-drift" => {
                allow_critical_drift = true;
            }
            "--max-retries" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --max-retries".to_string())?;
                max_retries = value.parse::<u32>()?;
            }
            "--quarantine-flaky" => {
                quarantine_flaky_fixtures = true;
            }
            other => {
                return Err(format!("unknown argument `{other}`").into());
            }
        }
    }

    let mut config = MultiEngineHarnessConfig::with_defaults(seed);
    config.fixture_catalog_path = fixture_catalog;
    config.fixture_limit = fixture_limit;
    config.fixture_id_filter = fixture_id_filter;
    if let Some(value) = trace_id {
        config.trace_id = value;
    }
    if let Some(value) = decision_id {
        config.decision_id = value;
    }
    if let Some(value) = policy_id {
        config.policy_id = value;
    }
    if let Some(value) = locale {
        config.locale = value;
    }
    if let Some(value) = timezone {
        config.timezone = value;
    }
    if engine_specs.is_some() && runtime_specs_path.is_some() {
        return Err("cannot combine --engine-specs with --runtime-specs".into());
    }
    if let Some(path) = runtime_specs_path {
        config.engines = load_runtime_engine_specs(path.as_path())?;
    } else if let Some(specs) = engine_specs {
        config.engines = specs;
    } else if Path::new(DEFAULT_LOCKSTEP_RUNTIME_SPECS_PATH).exists() {
        config.engines = load_runtime_engine_specs(Path::new(DEFAULT_LOCKSTEP_RUNTIME_SPECS_PATH))?;
    }

    Ok(CliArgs {
        config,
        out_path,
        evidence_jsonl_path,
        governance_actions_out_path,
        canon_rules_path,
        fail_on_divergence,
        allow_critical_drift,
        max_retries,
        quarantine_flaky_fixtures,
        preflight_only,
        print_help: print_help_flag,
    })
}

fn parse_fixture_limit(value: &str) -> Result<Option<usize>, Box<dyn Error>> {
    if value.eq_ignore_ascii_case("none") {
        Ok(None)
    } else {
        Ok(Some(value.parse::<usize>()?))
    }
}

fn run_preflight(config: &MultiEngineHarnessConfig) -> PreflightReport {
    let mut checks = Vec::<PreflightCheck>::new();
    let mut first_error_code = None::<String>;
    let mut first_error_message = None::<String>;
    let current_dir = std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<unknown>".to_string());
    let mut checked_external_engines = 0usize;

    for engine in &config.engines {
        if !matches!(engine.kind, HarnessEngineKind::ExternalCommand) {
            continue;
        }
        checked_external_engines = checked_external_engines.saturating_add(1);

        let Some(command) = engine.command.as_deref() else {
            let detail = format!("external engine `{}` has no command", engine.engine_id);
            checks.push(PreflightCheck {
                engine_id: engine.engine_id.clone(),
                check: "command_configured".to_string(),
                outcome: PreflightCheckOutcome::Fail,
                error_code: Some("FE-LOCKSTEP-PREFLIGHT-0003".to_string()),
                detail: detail.clone(),
            });
            if first_error_code.is_none() {
                first_error_code = Some("FE-LOCKSTEP-PREFLIGHT-0003".to_string());
                first_error_message = Some(detail);
            }
            continue;
        };

        if !command_exists(command) {
            let detail = format!(
                "external engine `{}` command `{}` not found in PATH",
                engine.engine_id, command
            );
            checks.push(PreflightCheck {
                engine_id: engine.engine_id.clone(),
                check: "command_exists".to_string(),
                outcome: PreflightCheckOutcome::Fail,
                error_code: Some("FE-LOCKSTEP-PREFLIGHT-0001".to_string()),
                detail: detail.clone(),
            });
            if first_error_code.is_none() {
                first_error_code = Some("FE-LOCKSTEP-PREFLIGHT-0001".to_string());
                first_error_message = Some(detail);
            }
            continue;
        }

        checks.push(PreflightCheck {
            engine_id: engine.engine_id.clone(),
            check: "command_exists".to_string(),
            outcome: PreflightCheckOutcome::Pass,
            error_code: None,
            detail: format!(
                "external engine `{}` command `{}` is available",
                engine.engine_id, command
            ),
        });

        for arg in &engine.args {
            if !looks_like_script_path(arg) {
                continue;
            }
            let script_path = Path::new(arg);
            if !script_path.exists() {
                let detail = format!(
                    "external engine `{}` expected script path `{}` to exist (cwd: {})",
                    engine.engine_id,
                    script_path.display(),
                    current_dir
                );
                checks.push(PreflightCheck {
                    engine_id: engine.engine_id.clone(),
                    check: "script_path_exists".to_string(),
                    outcome: PreflightCheckOutcome::Fail,
                    error_code: Some("FE-LOCKSTEP-PREFLIGHT-0002".to_string()),
                    detail: detail.clone(),
                });
                if first_error_code.is_none() {
                    first_error_code = Some("FE-LOCKSTEP-PREFLIGHT-0002".to_string());
                    first_error_message = Some(detail);
                }
            } else {
                checks.push(PreflightCheck {
                    engine_id: engine.engine_id.clone(),
                    check: "script_path_exists".to_string(),
                    outcome: PreflightCheckOutcome::Pass,
                    error_code: None,
                    detail: format!(
                        "external engine `{}` script path `{}` is available",
                        engine.engine_id,
                        script_path.display()
                    ),
                });
            }
        }
    }

    PreflightReport {
        schema_version: LOCKSTEP_PREFLIGHT_SCHEMA_VERSION.to_string(),
        preflight_passed: first_error_code.is_none(),
        engine_count: config.engines.len(),
        checked_external_engines,
        checks,
        error_code: first_error_code,
        error_message: first_error_message,
    }
}

fn command_exists(command: &str) -> bool {
    if command.trim().is_empty() {
        return false;
    }

    let command_path = Path::new(command);
    if command_path.is_absolute()
        || command.contains(std::path::MAIN_SEPARATOR)
        || command.contains('/')
        || command.contains('\\')
    {
        return command_path.is_file()
            || candidate_paths_with_suffixes(command_path)
                .iter()
                .any(|path| path.is_file());
    }

    let command_candidates = command_name_candidates(command);
    std::env::var_os("PATH").is_some_and(|path_value| {
        std::env::split_paths(&path_value).any(|entry| {
            command_candidates
                .iter()
                .any(|candidate| entry.join(candidate).is_file())
        })
    })
}

fn command_name_candidates(command: &str) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();
    let command_lower = command.to_ascii_lowercase();

    if seen.insert(command_lower.clone()) {
        candidates.push(command.to_string());
    }

    for suffix in executable_suffixes() {
        let suffix_lower = suffix.to_ascii_lowercase();
        if suffix_lower.is_empty() || command_lower.ends_with(&suffix_lower) {
            continue;
        }
        let candidate = format!("{command}{suffix}");
        if seen.insert(candidate.to_ascii_lowercase()) {
            candidates.push(candidate);
        }
    }

    candidates
}

fn candidate_paths_with_suffixes(command_path: &Path) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();
    let command = command_path.as_os_str().to_string_lossy().to_string();
    let command_lower = command.to_ascii_lowercase();

    for suffix in executable_suffixes() {
        let suffix_lower = suffix.to_ascii_lowercase();
        if suffix_lower.is_empty() || command_lower.ends_with(&suffix_lower) {
            continue;
        }
        let candidate = PathBuf::from(format!("{command}{suffix}"));
        if seen.insert(candidate.as_os_str().to_string_lossy().to_ascii_lowercase()) {
            candidates.push(candidate);
        }
    }

    candidates
}

fn executable_suffixes() -> Vec<String> {
    if let Some(path_ext) = std::env::var_os("PATHEXT") {
        let mut suffixes = Vec::new();
        for value in path_ext.to_string_lossy().split(';') {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                continue;
            }
            let normalized = if trimmed.starts_with('.') {
                trimmed.to_ascii_lowercase()
            } else {
                format!(".{}", trimmed.to_ascii_lowercase())
            };
            if !suffixes
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(&normalized))
            {
                suffixes.push(normalized);
            }
        }
        return suffixes;
    }

    if cfg!(windows) {
        return vec![
            ".exe".to_string(),
            ".cmd".to_string(),
            ".bat".to_string(),
            ".com".to_string(),
        ];
    }

    Vec::new()
}

fn looks_like_script_path(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]
        .iter()
        .any(|suffix| lowered.ends_with(suffix))
}

#[allow(clippy::too_many_arguments)]
fn append_lockstep_evidence_jsonl(
    path: &Path,
    report: &MultiEngineHarnessReport,
    retry_attempts: u32,
    max_retries: u32,
    observed_flaky_fixture_ids: &[String],
    quarantined_fixture_ids: &[String],
    governance_action_count: u64,
    canon_rules_hash: &str,
) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let evidence = build_lockstep_evidence_record(
        report,
        retry_attempts,
        max_retries,
        observed_flaky_fixture_ids,
        quarantined_fixture_ids,
        governance_action_count,
        canon_rules_hash,
    );
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    serde_json::to_writer(&mut file, &evidence)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn build_lockstep_evidence_record(
    report: &MultiEngineHarnessReport,
    retry_attempts: u32,
    max_retries: u32,
    observed_flaky_fixture_ids: &[String],
    quarantined_fixture_ids: &[String],
    governance_action_count: u64,
    canon_rules_hash: &str,
) -> LockstepEvidenceRecord {
    let runtime_versions = collect_runtime_versions(report);
    let category_match_rates = collect_category_match_rates(report);
    LockstepEvidenceRecord {
        schema_version: LOCKSTEP_EVIDENCE_SCHEMA_VERSION.to_string(),
        generated_at_utc: report.generated_at_utc.clone(),
        run_id: report.run_id.clone(),
        trace_id: report.trace_id.clone(),
        decision_id: report.decision_id.clone(),
        policy_id: report.policy_id.clone(),
        fixture_catalog_hash: report.fixture_catalog_hash.clone(),
        canon_rules_hash: canon_rules_hash.to_string(),
        environment_fingerprint: lockstep_environment_fingerprint(report),
        parser_mode: report.parser_mode.clone(),
        seed: report.seed,
        locale: report.locale.clone(),
        timezone: report.timezone.clone(),
        fixture_count: report.fixture_count,
        equivalent_fixtures: report.summary.equivalent_fixtures,
        divergent_fixtures: report.summary.divergent_fixtures,
        nondeterministic_fixtures: report.summary.fixtures_with_nondeterminism,
        drift_minor_fixtures: report.summary.drift_minor_fixtures,
        drift_critical_fixtures: report.summary.drift_critical_fixtures,
        retry_attempts,
        max_retries,
        observed_flaky_fixture_ids: observed_flaky_fixture_ids.to_vec(),
        quarantined_fixture_ids: quarantined_fixture_ids.to_vec(),
        governance_action_count,
        divergence_class_distribution: report.summary.drift_counts_by_category.clone(),
        runtime_versions,
        category_match_rates,
    }
}

fn write_lockstep_governance_report(
    path: &Path,
    report: &MultiEngineHarnessReport,
    retry_attempts: u32,
    max_retries: u32,
    observed_flaky_fixture_ids: &[String],
    quarantined_fixture_ids: &[String],
) -> Result<u64, Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let governance = build_drift_governance_action_report(report);
    let action_count = governance.actions.len() as u64;
    let envelope = LockstepGovernanceRecord {
        schema_version: LOCKSTEP_GOVERNANCE_SCHEMA_VERSION.to_string(),
        generated_at_utc: governance.generated_at_utc,
        run_id: governance.run_id,
        trace_id: governance.trace_id,
        decision_id: governance.decision_id,
        policy_id: governance.policy_id,
        retry_attempts,
        max_retries,
        observed_flaky_fixture_ids: observed_flaky_fixture_ids.to_vec(),
        quarantined_fixture_ids: quarantined_fixture_ids.to_vec(),
        critical_drift_detected: has_critical_drift(report),
        actions: governance.actions,
    };
    fs::write(path, serde_json::to_vec_pretty(&envelope)?)?;
    Ok(action_count)
}

fn collect_runtime_versions(report: &MultiEngineHarnessReport) -> Vec<LockstepRuntimeVersion> {
    let mut runtime_versions = report
        .engine_specs
        .iter()
        .map(|engine| LockstepRuntimeVersion {
            engine_id: engine.engine_id.clone(),
            version_pin: engine.version_pin.clone(),
        })
        .collect::<Vec<_>>();
    runtime_versions.sort_by(|left, right| left.engine_id.cmp(&right.engine_id));
    runtime_versions
}

fn collect_category_match_rates(
    report: &MultiEngineHarnessReport,
) -> BTreeMap<String, LockstepCategoryMatchRate> {
    let mut counts = BTreeMap::<String, (u64, u64)>::new();
    for fixture in &report.fixture_results {
        let entry = counts.entry(fixture.family_id.clone()).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        if fixture.equivalent_across_engines {
            entry.1 = entry.1.saturating_add(1);
        }
    }

    counts
        .into_iter()
        .map(|(family_id, (total, equivalent))| {
            let match_rate_ppm = if total == 0 {
                0
            } else {
                ((equivalent as u128 * 1_000_000) / total as u128) as u64
            };
            (
                family_id,
                LockstepCategoryMatchRate {
                    total_fixtures: total,
                    equivalent_fixtures: equivalent,
                    match_rate_ppm,
                },
            )
        })
        .collect()
}

fn resolve_lockstep_canon_rules(path: Option<&Path>) -> Result<LockstepCanonRules, Box<dyn Error>> {
    let (source_path, content) = if let Some(path) = path {
        (path.display().to_string(), fs::read_to_string(path)?)
    } else if Path::new(DEFAULT_LOCKSTEP_CANON_RULES_PATH).exists() {
        (
            DEFAULT_LOCKSTEP_CANON_RULES_PATH.to_string(),
            fs::read_to_string(DEFAULT_LOCKSTEP_CANON_RULES_PATH)?,
        )
    } else {
        (
            DEFAULT_LOCKSTEP_CANON_RULES_PATH.to_string(),
            DEFAULT_LOCKSTEP_CANON_RULES_CONTENT.to_string(),
        )
    };
    validate_lockstep_canon_rules(content.as_str(), source_path.as_str())?;
    Ok(LockstepCanonRules {
        hash: sha256_prefixed(content.as_bytes()),
    })
}

fn validate_lockstep_canon_rules(content: &str, source_path: &str) -> Result<(), Box<dyn Error>> {
    let parsed = toml::from_str::<toml::Value>(content)?;
    let Some(schema_version) = parsed.get("schema_version").and_then(toml::Value::as_str) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("canon rules file `{source_path}` is missing `schema_version`"),
        )
        .into());
    };
    if schema_version != LOCKSTEP_CANON_RULES_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "canon rules file `{source_path}` has schema_version `{schema_version}` (expected `{LOCKSTEP_CANON_RULES_SCHEMA_VERSION}`)"
            ),
        )
        .into());
    }
    Ok(())
}

fn lockstep_environment_fingerprint(report: &MultiEngineHarnessReport) -> String {
    let mut kv = BTreeMap::new();
    kv.insert("arch", std::env::consts::ARCH.to_string());
    kv.insert("locale", report.locale.clone());
    kv.insert("os", std::env::consts::OS.to_string());
    kv.insert(
        "rust_toolchain",
        std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "unknown".to_string()),
    );
    kv.insert("timezone", report.timezone.clone());
    sha256_prefixed(&serde_json::to_vec(&kv).unwrap_or_default())
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn load_engine_specs(path: &Path) -> Result<Vec<HarnessEngineSpec>, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let parsed = serde_json::from_slice::<EngineSpecFile>(&bytes)?;
    let specs = match parsed {
        EngineSpecFile::Array(specs) => specs,
        EngineSpecFile::Wrapped { engines } => engines,
    };
    if specs.is_empty() {
        return Err(format!("engine spec file `{}` must not be empty", path.display()).into());
    }
    Ok(specs)
}

fn load_runtime_engine_specs(path: &Path) -> Result<Vec<HarnessEngineSpec>, Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let parsed = toml::from_str::<LockstepRuntimeSpecsFile>(&content)?;
    if parsed.schema_version != LOCKSTEP_RUNTIME_SPECS_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime spec file `{}` has schema_version `{}` (expected `{}`)",
                path.display(),
                parsed.schema_version,
                LOCKSTEP_RUNTIME_SPECS_SCHEMA_VERSION
            ),
        )
        .into());
    }
    if parsed.runtimes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("runtime spec file `{}` must not be empty", path.display()),
        )
        .into());
    }

    let mut engines = vec![HarnessEngineSpec::franken_canonical(
        "frankenengine-engine@workspace",
    )];
    let mut ids = BTreeSet::new();
    ids.insert("franken_canonical".to_string());

    for runtime in parsed
        .runtimes
        .into_iter()
        .filter(|runtime| runtime.enabled)
    {
        if runtime.runtime_id.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime spec file `{}` has entry with empty runtime_id",
                    path.display()
                ),
            )
            .into());
        }
        if runtime.version_pin.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime `{}` in `{}` has empty version_pin",
                    runtime.runtime_id,
                    path.display()
                ),
            )
            .into());
        }
        if runtime.command.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime `{}` in `{}` has empty command",
                    runtime.runtime_id,
                    path.display()
                ),
            )
            .into());
        }
        if !ids.insert(runtime.runtime_id.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "runtime `{}` appears more than once in `{}`",
                    runtime.runtime_id,
                    path.display()
                ),
            )
            .into());
        }
        engines.push(HarnessEngineSpec {
            engine_id: runtime.runtime_id,
            display_name: runtime.display_name,
            kind: HarnessEngineKind::ExternalCommand,
            version_pin: runtime.version_pin,
            command: Some(runtime.command),
            args: runtime.args,
        });
    }

    let mut missing_required = Vec::new();
    for required_runtime in ["node", "bun"] {
        if !ids.contains(required_runtime) {
            missing_required.push(required_runtime);
        }
    }
    if !missing_required.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime spec file `{}` must include enabled runtime_id entries for {}",
                path.display(),
                missing_required.join(", ")
            ),
        )
        .into());
    }

    if engines.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime spec file `{}` must include at least one enabled runtime",
                path.display()
            ),
        )
        .into());
    }

    Ok(engines)
}

fn print_help() {
    println!("franken_lockstep_runner");
    println!("  --fixture-catalog <path>");
    println!("  --fixture-limit <usize|none>");
    println!("  --fixture-id <fixture-id>");
    println!("  --seed <u64>");
    println!("  --trace-id <id>");
    println!("  --decision-id <id>");
    println!("  --policy-id <id>");
    println!("  --locale <locale>");
    println!("  --timezone <timezone>");
    println!("  --engine-specs <path>");
    println!("  --runtime-specs <path>");
    println!("  --canon-rules <path>");
    println!("  --fail-on-divergence");
    println!("  --allow-critical-drift");
    println!("  --max-retries <count>");
    println!("  --quarantine-flaky");
    println!("  --preflight-only");
    println!("  --out <path>");
    println!("  --evidence-jsonl <path>");
    println!("  --governance-actions-out <path>");
    println!("  default runtime-specs path: {DEFAULT_LOCKSTEP_RUNTIME_SPECS_PATH}");
    println!("  default canon-rules path: {DEFAULT_LOCKSTEP_CANON_RULES_PATH}");
}
