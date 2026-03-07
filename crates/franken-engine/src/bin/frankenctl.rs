#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::benchmark_denominator::{
    PublicationContext, PublicationGateInput, evaluate_publication_gate,
};
use frankenengine_engine::benchmark_e2e::{
    BenchmarkFamily, BenchmarkSuiteConfig, ScaleProfile, run_benchmark_suite,
    write_evidence_artifacts,
};
use frankenengine_engine::deterministic_replay::{NondeterminismTrace, ReplayEngine, ReplayMode};
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{
    LoweringContext, LoweringPipelineOutput, lower_ir0_to_ir3,
};
use frankenengine_engine::module_compatibility_matrix::CompatibilityScenarioReport;
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParseEventIr, ParserOptions};
use frankenengine_engine::receipt_verifier_pipeline::{
    ReceiptVerifierCliInput, render_verdict_summary, verify_receipt_by_id,
};
use frankenengine_engine::region_lifecycle::FinalizeResult;
use frankenengine_engine::runtime_diagnostics_cli::{
    CompatibilityAdvisoryInput, CompatibilityAdvisoryOutput, EvidenceExportFilter,
    OnboardingReadinessClass, OnboardingScorecardInput, OnboardingScorecardOutput,
    OnboardingScorecardSignal, PreflightDoctorOutput, RolloutDecisionArtifactInput,
    RolloutDecisionArtifactOutput, RolloutRecommendation, RuntimeDiagnosticsCliInput,
    SupportBundleFile, SupportBundleOutput, SupportBundleRedactionPolicy,
    build_compatibility_advisories, build_onboarding_scorecard, build_rollout_decision_artifact,
    parse_decision_type, parse_evidence_severity, run_preflight_doctor,
};
use frankenengine_engine::third_party_verifier::{
    BenchmarkClaimBundle, ClaimedBenchmarkOutcome, THIRD_PARTY_VERIFIER_COMPONENT,
    ThirdPartyVerificationReport, VerificationCheckResult, VerificationVerdict, VerifierEvent,
    render_report_summary, verify_benchmark_claim,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const FRANKENCTL_SCHEMA_VERSION: &str = "franken-engine.frankenctl.v1";
const COMPILE_ARTIFACT_SCHEMA_VERSION: &str = "franken-engine.frankenctl.compile-artifact.v1";
const CODE_BUNDLE_MISSING_FILE: &str = "FE-TPV-BUNDLE-0001";
const CODE_BUNDLE_PARSE_ERROR: &str = "FE-TPV-BUNDLE-0002";
const CODE_BUNDLE_CONTEXT_MISMATCH: &str = "FE-TPV-BUNDLE-0003";
const CODE_BUNDLE_REMOTE_EXEC: &str = "FE-TPV-BUNDLE-0004";

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandSpec {
    Version,
    Help,
    Compile(CompileArgs),
    Run(RunArgs),
    Doctor(Box<DoctorArgs>),
    Verify(VerifyArgs),
    Benchmark(BenchmarkArgs),
    Replay(ReplayArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CompileArgs {
    input: PathBuf,
    out: PathBuf,
    parse_goal: ParseGoal,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunArgs {
    input: PathBuf,
    extension_id: String,
    parse_goal: ParseGoal,
    out: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DoctorArgs {
    input: PathBuf,
    summary: bool,
    out_dir: Option<PathBuf>,
    workload_id: Option<String>,
    package_name: Option<String>,
    target_platforms: Vec<String>,
    signals: Option<PathBuf>,
    advisories: Option<PathBuf>,
    scenario_report: Option<PathBuf>,
    platform_signals: Option<PathBuf>,
    filter: EvidenceExportFilter,
    redact_keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerifyArgs {
    CompileArtifact {
        input: PathBuf,
    },
    Receipt {
        input: PathBuf,
        receipt_id: String,
        summary: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchmarkArgs {
    mode: BenchmarkMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BenchmarkMode {
    Run(BenchmarkRunArgs),
    Score(BenchmarkScoreArgs),
    Verify(BenchmarkVerifyArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchmarkRunArgs {
    run_id: String,
    run_date: String,
    seed: u64,
    out_dir: PathBuf,
    profiles: Vec<ScaleProfile>,
    families: Vec<BenchmarkFamily>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchmarkScoreArgs {
    input: PathBuf,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BenchmarkVerifyArgs {
    bundle: PathBuf,
    output: Option<PathBuf>,
    summary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayArgs {
    trace: PathBuf,
    mode: ReplayMode,
    out: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompileArtifactHashes {
    parse_event_ir: String,
    ir0: String,
    ir1: String,
    ir2: String,
    ir3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompileArtifact {
    schema_version: String,
    generated_unix_ns: u64,
    source_path: String,
    parse_goal: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    hashes: CompileArtifactHashes,
    parse_event_ir: ParseEventIr,
    ir0: Ir0Module,
    lowering: LoweringPipelineOutput,
}

#[derive(Debug, Clone, Serialize)]
struct CompileCommandOutput {
    schema_version: String,
    artifact_path: String,
    parse_goal: String,
    hashes: CompileArtifactHashes,
    lowering_event_count: usize,
    lowering_witness_count: usize,
}

#[derive(Debug, Clone, Serialize)]
struct RunCommandOutput {
    schema_version: String,
    extension_id: String,
    trace_id: String,
    decision_id: String,
    lane: String,
    lane_reason: String,
    containment_action: String,
    expected_loss_millionths: i64,
    execution_value: String,
    instructions_executed: u64,
    evidence_entries: usize,
    cell_events: usize,
    saga_id: Option<String>,
    finalize_result: Option<FinalizeResult>,
}

#[derive(Debug, Clone, Serialize)]
struct CompileArtifactVerificationOutput {
    schema_version: String,
    artifact_path: String,
    passed: bool,
    errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkCommandOutput {
    schema_version: String,
    run_id: String,
    run_date: String,
    seed: u64,
    blocked: bool,
    total_operations: u64,
    total_duration_us: u64,
    invariant_violations: u64,
    profiles: Vec<String>,
    families: Vec<String>,
    artifacts: BenchmarkArtifactPaths,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkScoreCommandOutput {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    score_vs_node: f64,
    score_vs_bun: f64,
    publish_allowed: bool,
    blockers: Vec<String>,
    output: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct BenchmarkArtifactPaths {
    run_manifest: String,
    evidence_jsonl: String,
    events_jsonl: String,
    commands_txt: String,
    benchmark_env_manifest: String,
    raw_results_archive: String,
    summary: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReplayCommandOutput {
    schema_version: String,
    trace_path: String,
    mode: String,
    session_id: String,
    event_count: usize,
    replayed_events: u64,
    divergence_count: usize,
    critical_divergences: usize,
    complete: bool,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorSignalCounts {
    external_signals: usize,
    compatibility_signals: usize,
    platform_signals: usize,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorCommandOutput {
    schema_version: String,
    input_path: String,
    workload_id: String,
    package_name: String,
    target_platforms: Vec<String>,
    preflight_verdict: String,
    readiness: String,
    remediation_effort: String,
    rollout_recommendation: String,
    blocked: bool,
    signal_counts: DoctorSignalCounts,
    output_dir: Option<String>,
    preflight: PreflightDoctorOutput,
    onboarding_scorecard: OnboardingScorecardOutput,
    rollout_decision: RolloutDecisionArtifactOutput,
}

fn main() {
    let code = match run(env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("{error}");
            2
        }
    };
    std::process::exit(code);
}

fn run(raw_args: Vec<String>) -> Result<i32, String> {
    let invocation_trace_id = default_run_id("frankenctl");
    let command = parse_command(&raw_args).map_err(|error| {
        format_cli_error(
            invocation_trace_id.as_str(),
            "parse",
            error.as_str(),
            "Run `frankenctl --help` for full command usage and required arguments.",
        )
    })?;
    let command_name = command_label(&command);
    let remediation = command_remediation(command_name);

    let outcome = match command {
        CommandSpec::Version => {
            println!("frankenctl {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        CommandSpec::Help => {
            println!("{}", usage());
            Ok(0)
        }
        CommandSpec::Compile(args) => execute_compile(args),
        CommandSpec::Run(args) => execute_run(args),
        CommandSpec::Doctor(args) => execute_doctor(*args),
        CommandSpec::Verify(args) => execute_verify(args),
        CommandSpec::Benchmark(args) => execute_benchmark(args),
        CommandSpec::Replay(args) => execute_replay(args),
    };

    outcome.map_err(|error| {
        format_cli_error(
            invocation_trace_id.as_str(),
            command_name,
            error.as_str(),
            remediation,
        )
    })
}

fn parse_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::Help);
    }
    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::Help),
        "version" => Ok(CommandSpec::Version),
        "compile" => parse_compile_args(&args[1..]).map(CommandSpec::Compile),
        "run" => parse_run_args(&args[1..]).map(CommandSpec::Run),
        "doctor" => parse_doctor_args(&args[1..]).map(|args| CommandSpec::Doctor(Box::new(args))),
        "verify" => parse_verify_args(&args[1..]).map(CommandSpec::Verify),
        "benchmark" => parse_benchmark_args(&args[1..]).map(CommandSpec::Benchmark),
        "replay" => parse_replay_args(&args[1..]).map(CommandSpec::Replay),
        other => Err(format!("unknown command `{other}`\n\n{}", usage())),
    }
}

fn parse_compile_args(args: &[String]) -> Result<CompileArgs, String> {
    let mut input: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut goal = ParseGoal::Script;
    let mut trace_id = "trace-frankenctl-compile".to_string();
    let mut decision_id = "decision-frankenctl-compile".to_string();
    let mut policy_id = "frankenctl.compile.v1".to_string();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--goal" => goal = parse_goal(&next_arg(args, &mut index, "--goal")?)?,
            "--trace-id" => trace_id = next_arg(args, &mut index, "--trace-id")?,
            "--decision-id" => decision_id = next_arg(args, &mut index, "--decision-id")?,
            "--policy-id" => policy_id = next_arg(args, &mut index, "--policy-id")?,
            "--help" | "-h" => return Ok(default_compile_help()),
            flag => return Err(format!("unknown compile flag `{flag}`")),
        }
        index += 1;
    }

    let input = input.ok_or_else(|| "compile requires --input <path>".to_string())?;
    let out = out.ok_or_else(|| "compile requires --out <path>".to_string())?;

    Ok(CompileArgs {
        input,
        out,
        parse_goal: goal,
        trace_id,
        decision_id,
        policy_id,
    })
}

fn default_compile_help() -> CompileArgs {
    CompileArgs {
        input: PathBuf::from(""),
        out: PathBuf::from(""),
        parse_goal: ParseGoal::Script,
        trace_id: String::new(),
        decision_id: String::new(),
        policy_id: String::new(),
    }
}

fn parse_run_args(args: &[String]) -> Result<RunArgs, String> {
    let mut input: Option<PathBuf> = None;
    let mut extension_id: Option<String> = None;
    let mut goal = ParseGoal::Script;
    let mut out: Option<PathBuf> = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--extension-id" => extension_id = Some(next_arg(args, &mut index, "--extension-id")?),
            "--goal" => goal = parse_goal(&next_arg(args, &mut index, "--goal")?)?,
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            flag => return Err(format!("unknown run flag `{flag}`")),
        }
        index += 1;
    }

    Ok(RunArgs {
        input: input.ok_or_else(|| "run requires --input <path>".to_string())?,
        extension_id: extension_id.ok_or_else(|| "run requires --extension-id <id>".to_string())?,
        parse_goal: goal,
        out,
    })
}

fn parse_doctor_args(args: &[String]) -> Result<DoctorArgs, String> {
    let mut input: Option<PathBuf> = None;
    let mut summary = false;
    let mut out_dir: Option<PathBuf> = None;
    let mut workload_id: Option<String> = None;
    let mut package_name: Option<String> = None;
    let mut target_platforms = Vec::<String>::new();
    let mut signals: Option<PathBuf> = None;
    let mut advisories: Option<PathBuf> = None;
    let mut scenario_report: Option<PathBuf> = None;
    let mut platform_signals: Option<PathBuf> = None;
    let mut filter = EvidenceExportFilter::default();
    let mut redact_keys = Vec::<String>::new();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--summary" => summary = true,
            "--out-dir" => out_dir = Some(PathBuf::from(next_arg(args, &mut index, "--out-dir")?)),
            "--workload-id" => workload_id = Some(next_arg(args, &mut index, "--workload-id")?),
            "--package-name" => package_name = Some(next_arg(args, &mut index, "--package-name")?),
            "--target-platform" => {
                target_platforms.push(next_arg(args, &mut index, "--target-platform")?)
            }
            "--signals" => signals = Some(PathBuf::from(next_arg(args, &mut index, "--signals")?)),
            "--advisories" => {
                advisories = Some(PathBuf::from(next_arg(args, &mut index, "--advisories")?))
            }
            "--scenario-report" => {
                scenario_report = Some(PathBuf::from(next_arg(
                    args,
                    &mut index,
                    "--scenario-report",
                )?))
            }
            "--platform-signals" => {
                platform_signals = Some(PathBuf::from(next_arg(
                    args,
                    &mut index,
                    "--platform-signals",
                )?))
            }
            "--extension-id" => {
                filter.extension_id = Some(next_arg(args, &mut index, "--extension-id")?)
            }
            "--trace-id" => filter.trace_id = Some(next_arg(args, &mut index, "--trace-id")?),
            "--start-ns" => {
                filter.start_timestamp_ns = Some(parse_u64(
                    &next_arg(args, &mut index, "--start-ns")?,
                    "--start-ns",
                )?)
            }
            "--end-ns" => {
                filter.end_timestamp_ns = Some(parse_u64(
                    &next_arg(args, &mut index, "--end-ns")?,
                    "--end-ns",
                )?)
            }
            "--severity" => {
                let value = next_arg(args, &mut index, "--severity")?;
                filter.severity =
                    Some(parse_evidence_severity(value.as_str()).ok_or_else(|| {
                        format!("invalid --severity `{value}` (expected info|warning|critical)")
                    })?);
            }
            "--decision-type" => {
                let value = next_arg(args, &mut index, "--decision-type")?;
                filter.decision_type = Some(
                    parse_decision_type(value.as_str())
                        .ok_or_else(|| format!("invalid --decision-type `{value}`"))?,
                );
            }
            "--redact-key" => redact_keys.push(next_arg(args, &mut index, "--redact-key")?),
            flag => return Err(format!("unknown doctor flag `{flag}`")),
        }
        index += 1;
    }

    Ok(DoctorArgs {
        input: input.ok_or_else(|| "doctor requires --input <runtime_input.json>".to_string())?,
        summary,
        out_dir,
        workload_id,
        package_name,
        target_platforms,
        signals,
        advisories,
        scenario_report,
        platform_signals,
        filter,
        redact_keys,
    })
}

fn parse_verify_args(args: &[String]) -> Result<VerifyArgs, String> {
    if args.is_empty() {
        return Err("verify requires a subcommand: compile-artifact | receipt".to_string());
    }
    match args[0].as_str() {
        "compile-artifact" => {
            let mut input: Option<PathBuf> = None;
            let mut index = 1usize;
            while index < args.len() {
                match args[index].as_str() {
                    "--input" => {
                        input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?))
                    }
                    flag => return Err(format!("unknown verify compile-artifact flag `{flag}`")),
                }
                index += 1;
            }
            Ok(VerifyArgs::CompileArtifact {
                input: input.ok_or_else(|| {
                    "verify compile-artifact requires --input <artifact.json>".to_string()
                })?,
            })
        }
        "receipt" => {
            let mut input: Option<PathBuf> = None;
            let mut receipt_id: Option<String> = None;
            let mut summary = false;
            let mut index = 1usize;
            while index < args.len() {
                match args[index].as_str() {
                    "--input" => {
                        input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?))
                    }
                    "--receipt-id" => {
                        receipt_id = Some(next_arg(args, &mut index, "--receipt-id")?)
                    }
                    "--summary" => summary = true,
                    flag => return Err(format!("unknown verify receipt flag `{flag}`")),
                }
                index += 1;
            }
            Ok(VerifyArgs::Receipt {
                input: input.ok_or_else(|| "verify receipt requires --input <path>".to_string())?,
                receipt_id: receipt_id
                    .ok_or_else(|| "verify receipt requires --receipt-id <id>".to_string())?,
                summary,
            })
        }
        other => Err(format!(
            "unknown verify subcommand `{other}` (expected compile-artifact | receipt)"
        )),
    }
}

fn parse_benchmark_args(args: &[String]) -> Result<BenchmarkArgs, String> {
    if args.is_empty() {
        return Err("benchmark requires a subcommand: run | score | verify".to_string());
    }
    match args[0].as_str() {
        "run" => parse_benchmark_run_args(&args[1..]).map(|run| BenchmarkArgs {
            mode: BenchmarkMode::Run(run),
        }),
        "score" => parse_benchmark_score_args(&args[1..]).map(|score| BenchmarkArgs {
            mode: BenchmarkMode::Score(score),
        }),
        "verify" => parse_benchmark_verify_args(&args[1..]).map(|verify| BenchmarkArgs {
            mode: BenchmarkMode::Verify(verify),
        }),
        other => Err(format!(
            "unknown benchmark subcommand `{other}` (expected run | score | verify)"
        )),
    }
}

fn parse_benchmark_run_args(args: &[String]) -> Result<BenchmarkRunArgs, String> {
    let mut run_id = default_run_id("benchmark");
    let mut run_date = "1970-01-01".to_string();
    let mut seed = 42_u64;
    let mut out_dir: Option<PathBuf> = None;
    let mut profiles: Vec<ScaleProfile> = Vec::new();
    let mut families: Vec<BenchmarkFamily> = Vec::new();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--run-id" => run_id = next_arg(args, &mut index, "--run-id")?,
            "--run-date" => run_date = next_arg(args, &mut index, "--run-date")?,
            "--seed" => seed = parse_u64(&next_arg(args, &mut index, "--seed")?, "--seed")?,
            "--out-dir" => out_dir = Some(PathBuf::from(next_arg(args, &mut index, "--out-dir")?)),
            "--profile" => profiles.push(parse_profile(&next_arg(args, &mut index, "--profile")?)?),
            "--family" => families.push(parse_family(&next_arg(args, &mut index, "--family")?)?),
            flag => return Err(format!("unknown benchmark run flag `{flag}`")),
        }
        index += 1;
    }

    let out_dir = out_dir.unwrap_or_else(|| default_benchmark_out_dir(&run_id));

    if profiles.is_empty() {
        profiles = vec![
            ScaleProfile::Small,
            ScaleProfile::Medium,
            ScaleProfile::Large,
        ];
    }
    if families.is_empty() {
        families = BenchmarkFamily::all().to_vec();
    }

    Ok(BenchmarkRunArgs {
        run_id,
        run_date,
        seed,
        out_dir,
        profiles,
        families,
    })
}

fn parse_benchmark_score_args(args: &[String]) -> Result<BenchmarkScoreArgs, String> {
    let mut input: Option<PathBuf> = None;
    let mut trace_id = "trace-frankenctl-benchmark-score".to_string();
    let mut decision_id = "decision-frankenctl-benchmark-score".to_string();
    let mut policy_id = "frankenctl.benchmark.score.v1".to_string();
    let mut output: Option<PathBuf> = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--trace-id" => trace_id = next_arg(args, &mut index, "--trace-id")?,
            "--decision-id" => decision_id = next_arg(args, &mut index, "--decision-id")?,
            "--policy-id" => policy_id = next_arg(args, &mut index, "--policy-id")?,
            "--output" => output = Some(PathBuf::from(next_arg(args, &mut index, "--output")?)),
            flag => return Err(format!("unknown benchmark score flag `{flag}`")),
        }
        index += 1;
    }

    Ok(BenchmarkScoreArgs {
        input: input.ok_or_else(|| "benchmark score requires --input <path>".to_string())?,
        trace_id,
        decision_id,
        policy_id,
        output,
    })
}

fn parse_benchmark_verify_args(args: &[String]) -> Result<BenchmarkVerifyArgs, String> {
    let mut bundle: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut summary = false;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--bundle" => bundle = Some(PathBuf::from(next_arg(args, &mut index, "--bundle")?)),
            "--output" => output = Some(PathBuf::from(next_arg(args, &mut index, "--output")?)),
            "--summary" => summary = true,
            flag => return Err(format!("unknown benchmark verify flag `{flag}`")),
        }
        index += 1;
    }

    Ok(BenchmarkVerifyArgs {
        bundle: bundle.ok_or_else(|| "benchmark verify requires --bundle <dir>".to_string())?,
        output,
        summary,
    })
}

fn parse_replay_args(args: &[String]) -> Result<ReplayArgs, String> {
    if args.first().map(|value| value.as_str()) != Some("run") {
        return Err("replay requires subcommand `run`".to_string());
    }

    let mut trace: Option<PathBuf> = None;
    let mut mode = ReplayMode::Strict;
    let mut out: Option<PathBuf> = None;

    let mut index = 1usize;
    while index < args.len() {
        match args[index].as_str() {
            "--trace" => trace = Some(PathBuf::from(next_arg(args, &mut index, "--trace")?)),
            "--mode" => mode = parse_replay_mode(&next_arg(args, &mut index, "--mode")?)?,
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            flag => return Err(format!("unknown replay run flag `{flag}`")),
        }
        index += 1;
    }

    Ok(ReplayArgs {
        trace: trace.ok_or_else(|| "replay run requires --trace <path>".to_string())?,
        mode,
        out,
    })
}

fn execute_compile(args: CompileArgs) -> Result<i32, String> {
    if args.input.as_os_str().is_empty() && args.out.as_os_str().is_empty() {
        println!("{}", compile_usage());
        return Ok(0);
    }

    let source = fs::read_to_string(&args.input)
        .map_err(|error| format!("failed to read source `{}`: {error}", args.input.display()))?;
    let parser_options = ParserOptions::default();
    let parser = CanonicalEs2020Parser;
    let (parse_result, parse_event_ir) =
        parser.parse_with_event_ir(source.as_str(), args.parse_goal, &parser_options);
    let syntax_tree = parse_result.map_err(|error| format!("parse failed: {error}"))?;

    let source_label = args.input.display().to_string();
    let ir0 = Ir0Module::from_syntax_tree(syntax_tree, &source_label);
    let lowering = lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new(
            args.trace_id.clone(),
            args.decision_id.clone(),
            args.policy_id.clone(),
        ),
    )
    .map_err(|error| format!("lowering failed: {error}"))?;

    let hashes = CompileArtifactHashes {
        parse_event_ir: parse_event_ir.canonical_hash(),
        ir0: ir0.content_hash().to_string(),
        ir1: lowering.ir1.content_hash().to_string(),
        ir2: lowering.ir2.content_hash().to_string(),
        ir3: lowering.ir3.content_hash().to_string(),
    };

    let artifact = CompileArtifact {
        schema_version: COMPILE_ARTIFACT_SCHEMA_VERSION.to_string(),
        generated_unix_ns: current_unix_ns(),
        source_path: source_label,
        parse_goal: args.parse_goal.as_str().to_string(),
        trace_id: args.trace_id,
        decision_id: args.decision_id,
        policy_id: args.policy_id,
        hashes: hashes.clone(),
        parse_event_ir,
        ir0,
        lowering,
    };

    write_json_file(&args.out, &artifact)?;

    let output = CompileCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        artifact_path: args.out.display().to_string(),
        parse_goal: artifact.parse_goal,
        hashes,
        lowering_event_count: artifact.lowering.events.len(),
        lowering_witness_count: artifact.lowering.witnesses.len(),
    };
    print_json(&output)?;
    Ok(0)
}

fn execute_run(args: RunArgs) -> Result<i32, String> {
    let source = fs::read_to_string(&args.input)
        .map_err(|error| format!("failed to read source `{}`: {error}", args.input.display()))?;

    let package = ExtensionPackage {
        extension_id: args.extension_id.clone(),
        source,
        capabilities: Vec::new(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        metadata: BTreeMap::new(),
    };

    let config = OrchestratorConfig {
        parse_goal: args.parse_goal,
        ..OrchestratorConfig::default()
    };
    let mut orchestrator = ExecutionOrchestrator::new(config);
    let result = orchestrator
        .execute(&package)
        .map_err(|error| format!("run failed: {error}"))?;

    let output = RunCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        extension_id: result.extension_id,
        trace_id: result.trace_id,
        decision_id: result.decision_id,
        lane: result.lane.to_string(),
        lane_reason: result.lane_reason.to_string(),
        containment_action: result.containment_action.to_string(),
        expected_loss_millionths: result.expected_loss_millionths,
        execution_value: result.execution_value,
        instructions_executed: result.instructions_executed,
        evidence_entries: result.evidence_entries.len(),
        cell_events: result.cell_events.len(),
        saga_id: result.saga_id,
        finalize_result: result.finalize_result,
    };

    if let Some(out) = args.out {
        write_json_file(&out, &output)?;
    }
    print_json(&output)?;
    Ok(0)
}

fn execute_doctor(args: DoctorArgs) -> Result<i32, String> {
    let input = load_json_file::<RuntimeDiagnosticsCliInput>(&args.input)?;
    let redaction_policy = if args.redact_keys.is_empty() {
        SupportBundleRedactionPolicy::default()
    } else {
        SupportBundleRedactionPolicy::with_additional_fragments(args.redact_keys.clone())
    };

    let preflight = run_preflight_doctor(&input, args.filter.clone(), redaction_policy);

    let mut external_signals = match &args.signals {
        Some(path) => load_onboarding_signals(path)?,
        None => Vec::new(),
    };
    sort_and_dedup_signals(&mut external_signals);

    let mut compatibility_signals = match &args.advisories {
        Some(path) => load_onboarding_signals(path)?,
        None => Vec::new(),
    };
    if let Some(path) = &args.scenario_report {
        let scenario_report = load_json_file::<CompatibilityScenarioReport>(path)?;
        let advisory_output = build_compatibility_advisories(&CompatibilityAdvisoryInput {
            source_report: path.display().to_string(),
            scenario_report,
        });
        compatibility_signals.extend(advisory_output.signals);
    }
    sort_and_dedup_signals(&mut compatibility_signals);

    let mut platform_signals = match &args.platform_signals {
        Some(path) => load_onboarding_signals(path)?,
        None => Vec::new(),
    };
    sort_and_dedup_signals(&mut platform_signals);

    let workload_id = args
        .workload_id
        .clone()
        .unwrap_or_else(|| input.trace_id.clone());
    let package_name = args
        .package_name
        .clone()
        .unwrap_or_else(|| workload_id.clone());
    let onboarding_scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
        workload_id,
        package_name,
        target_platforms: args.target_platforms.clone(),
        preflight: preflight.clone(),
        external_signals: external_signals.clone(),
    });
    let rollout_decision = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
        onboarding_scorecard: onboarding_scorecard.clone(),
        compatibility_advisories: compatibility_signals.clone(),
        platform_matrix_signals: platform_signals.clone(),
    });

    let blocked = onboarding_scorecard.readiness == OnboardingReadinessClass::Blocked
        || !rollout_decision.pilot_gate_consumable
        || matches!(
            rollout_decision.recommendation,
            RolloutRecommendation::Rollback | RolloutRecommendation::Defer
        );

    let output = DoctorCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        input_path: args.input.display().to_string(),
        workload_id: onboarding_scorecard.workload_id.clone(),
        package_name: onboarding_scorecard.package_name.clone(),
        target_platforms: onboarding_scorecard.target_platforms.clone(),
        preflight_verdict: preflight.verdict.to_string(),
        readiness: onboarding_scorecard.readiness.to_string(),
        remediation_effort: onboarding_scorecard.remediation_effort.to_string(),
        rollout_recommendation: rollout_decision.recommendation.to_string(),
        blocked,
        signal_counts: DoctorSignalCounts {
            external_signals: external_signals.len(),
            compatibility_signals: compatibility_signals.len(),
            platform_signals: platform_signals.len(),
        },
        output_dir: args.out_dir.as_ref().map(|path| path.display().to_string()),
        preflight,
        onboarding_scorecard,
        rollout_decision,
    };

    if let Some(out_dir) = &args.out_dir {
        write_support_bundle_files(&output.preflight.support_bundle, out_dir)?;
        write_json_file(
            &out_dir.join("support_bundle/preflight_report.json"),
            &output.preflight,
        )?;
        write_json_file(
            &out_dir.join("support_bundle/onboarding_scorecard.json"),
            &output.onboarding_scorecard,
        )?;
        write_json_file(
            &out_dir.join("support_bundle/rollout_decision_artifact.json"),
            &output.rollout_decision,
        )?;
        write_json_file(
            &out_dir.join("support_bundle/frankenctl_doctor_report.json"),
            &output,
        )?;
    }

    if args.summary {
        println!("{}", render_doctor_summary(&output));
    } else {
        print_json(&output)?;
    }

    if blocked { Ok(25) } else { Ok(0) }
}

fn execute_verify(args: VerifyArgs) -> Result<i32, String> {
    match args {
        VerifyArgs::CompileArtifact { input } => {
            let artifact = load_json_file::<CompileArtifact>(&input)?;
            let errors = validate_compile_artifact(&artifact);
            let output = CompileArtifactVerificationOutput {
                schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
                artifact_path: input.display().to_string(),
                passed: errors.is_empty(),
                errors,
            };
            print_json(&output)?;
            if output.passed { Ok(0) } else { Ok(25) }
        }
        VerifyArgs::Receipt {
            input,
            receipt_id,
            summary,
        } => {
            let verifier_input = load_json_file::<ReceiptVerifierCliInput>(&input)?;
            let verdict = verify_receipt_by_id(&verifier_input, &receipt_id)
                .map_err(|error| format!("receipt verification failed: {error}"))?;
            if summary {
                println!("{}", render_verdict_summary(&verdict));
            } else {
                print_json(&verdict)?;
            }
            Ok(verdict.exit_code)
        }
    }
}

fn execute_benchmark(args: BenchmarkArgs) -> Result<i32, String> {
    match args.mode {
        BenchmarkMode::Run(run_args) => execute_benchmark_run(run_args),
        BenchmarkMode::Score(score_args) => execute_benchmark_score(score_args),
        BenchmarkMode::Verify(verify_args) => execute_benchmark_verify(verify_args),
    }
}

fn execute_benchmark_run(args: BenchmarkRunArgs) -> Result<i32, String> {
    let config = BenchmarkSuiteConfig {
        seed: args.seed,
        profiles: args.profiles.clone(),
        families: args.families.clone(),
        run_id: args.run_id.clone(),
        run_date: args.run_date.clone(),
        ..BenchmarkSuiteConfig::default()
    };

    let result = run_benchmark_suite(&config);
    let artifacts = write_evidence_artifacts(&result, &args.out_dir).map_err(|error| {
        format!(
            "failed to write benchmark artifacts to `{}`: {error}",
            args.out_dir.display()
        )
    })?;

    let output = BenchmarkCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        run_id: config.run_id.clone(),
        run_date: config.run_date.clone(),
        seed: config.seed,
        blocked: result.blocked,
        total_operations: result.total_operations,
        total_duration_us: result.total_duration_us,
        invariant_violations: result.invariant_violations,
        profiles: config
            .profiles
            .iter()
            .map(|profile| profile.as_str().to_string())
            .collect(),
        families: config
            .families
            .iter()
            .map(|family| family.as_str().to_string())
            .collect(),
        artifacts: BenchmarkArtifactPaths {
            run_manifest: artifacts.run_manifest_path.display().to_string(),
            evidence_jsonl: artifacts.evidence_path.display().to_string(),
            events_jsonl: artifacts.events_path.display().to_string(),
            commands_txt: artifacts.commands_path.display().to_string(),
            benchmark_env_manifest: artifacts.benchmark_env_manifest_path.display().to_string(),
            raw_results_archive: artifacts.raw_results_archive_path.display().to_string(),
            summary: artifacts.summary_path.display().to_string(),
        },
    };

    print_json(&output)?;
    if result.blocked { Ok(25) } else { Ok(0) }
}

fn execute_benchmark_score(args: BenchmarkScoreArgs) -> Result<i32, String> {
    let input = load_json_file::<PublicationGateInput>(&args.input)?;
    let ctx = PublicationContext::new(
        args.trace_id.clone(),
        args.decision_id.clone(),
        args.policy_id.clone(),
    );
    let decision = evaluate_publication_gate(&input, &ctx)
        .map_err(|error| format!("benchmark score evaluation failed: {error}"))?;

    let claim_bundle = BenchmarkClaimBundle {
        trace_id: ctx.trace_id.clone(),
        decision_id: ctx.decision_id.clone(),
        policy_id: ctx.policy_id.clone(),
        input,
        claimed: ClaimedBenchmarkOutcome {
            score_vs_node: decision.score_vs_node,
            score_vs_bun: decision.score_vs_bun,
            publish_allowed: decision.publish_allowed,
            blockers: decision.blockers.clone(),
        },
    };

    if let Some(path) = &args.output {
        write_json_file(path, &claim_bundle)?;
    }

    let output = BenchmarkScoreCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        trace_id: ctx.trace_id,
        decision_id: ctx.decision_id,
        policy_id: ctx.policy_id,
        score_vs_node: claim_bundle.claimed.score_vs_node,
        score_vs_bun: claim_bundle.claimed.score_vs_bun,
        publish_allowed: claim_bundle.claimed.publish_allowed,
        blockers: claim_bundle.claimed.blockers,
        output: args.output.map(|path| path.display().to_string()),
    };

    print_json(&output)?;
    if output.publish_allowed {
        Ok(0)
    } else {
        Ok(25)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct BenchmarkBundleManifest {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

fn execute_benchmark_verify(args: BenchmarkVerifyArgs) -> Result<i32, String> {
    let results_path = args.bundle.join("results.json");
    if !results_path.is_file() {
        return Err(format!(
            "benchmark verify requires --bundle <dir> containing env.json, manifest.json, repro.lock, commands.txt, and results.json (missing `{}`)",
            results_path.display()
        ));
    }

    let input = load_json_file::<BenchmarkClaimBundle>(&results_path)?;
    let mut report = verify_benchmark_claim(&input);
    validate_benchmark_bundle_contract(&args.bundle, &input, &mut report);

    if let Some(path) = &args.output {
        write_json_file(path, &report)?;
    }
    if args.summary {
        println!("{}", render_report_summary(&report));
    } else {
        print_json(&report)?;
    }
    Ok(report.exit_code())
}

fn validate_benchmark_bundle_contract(
    bundle_dir: &Path,
    input: &BenchmarkClaimBundle,
    report: &mut ThirdPartyVerificationReport,
) {
    let required_files = [
        "env.json",
        "manifest.json",
        "repro.lock",
        "commands.txt",
        "results.json",
    ];

    let mut bundle_violations = false;
    for file in required_files {
        let path = bundle_dir.join(file);
        let present = path.is_file();
        append_benchmark_bundle_check(
            report,
            format!("bundle_file_{file}_present"),
            present,
            CODE_BUNDLE_MISSING_FILE,
            if present {
                format!("required bundle file present: {}", path.display())
            } else {
                format!("required bundle file missing: {}", path.display())
            },
        );
        if !present {
            bundle_violations = true;
        }
    }

    let manifest_path = bundle_dir.join("manifest.json");
    let manifest = if manifest_path.is_file() {
        match load_json_file::<BenchmarkBundleManifest>(&manifest_path) {
            Ok(manifest) => {
                let schema_ok = !manifest.schema_version.trim().is_empty();
                append_benchmark_bundle_check(
                    report,
                    "bundle_manifest_schema_version_present".to_string(),
                    schema_ok,
                    CODE_BUNDLE_PARSE_ERROR,
                    if schema_ok {
                        format!(
                            "bundle manifest schema_version present: {}",
                            manifest.schema_version
                        )
                    } else {
                        "bundle manifest schema_version must be non-empty".to_string()
                    },
                );
                if !schema_ok {
                    bundle_violations = true;
                }

                let context_matches = manifest.trace_id == input.trace_id
                    && manifest.decision_id == input.decision_id
                    && manifest.policy_id == input.policy_id;
                append_benchmark_bundle_check(
                    report,
                    "bundle_manifest_context_matches_claim".to_string(),
                    context_matches,
                    CODE_BUNDLE_CONTEXT_MISMATCH,
                    if context_matches {
                        "bundle manifest trace/decision/policy context matches results.json claim"
                            .to_string()
                    } else {
                        format!(
                            "bundle manifest context mismatch: manifest=({}, {}, {}), results=({}, {}, {})",
                            manifest.trace_id,
                            manifest.decision_id,
                            manifest.policy_id,
                            input.trace_id,
                            input.decision_id,
                            input.policy_id
                        )
                    },
                );
                if !context_matches {
                    bundle_violations = true;
                }

                Some(manifest)
            }
            Err(error) => {
                append_benchmark_bundle_check(
                    report,
                    "bundle_manifest_parses".to_string(),
                    false,
                    CODE_BUNDLE_PARSE_ERROR,
                    error,
                );
                bundle_violations = true;
                None
            }
        }
    } else {
        None
    };

    let env_path = bundle_dir.join("env.json");
    if env_path.is_file() {
        match load_json_file::<serde_json::Value>(&env_path) {
            Ok(value) => {
                let env_obj = value.as_object().cloned().unwrap_or_default();
                let env_ok = !env_obj.is_empty()
                    && env_obj.contains_key("os")
                    && env_obj.contains_key("arch")
                    && (env_obj.contains_key("toolchain") || env_obj.contains_key("runtime_pins"));
                append_benchmark_bundle_check(
                    report,
                    "bundle_env_has_core_fields".to_string(),
                    env_ok,
                    CODE_BUNDLE_PARSE_ERROR,
                    if env_ok {
                        "env.json includes required fields: os, arch, and toolchain/runtime_pins"
                            .to_string()
                    } else {
                        "env.json must include os/arch and either toolchain or runtime_pins"
                            .to_string()
                    },
                );
                if !env_ok {
                    bundle_violations = true;
                }
            }
            Err(error) => {
                append_benchmark_bundle_check(
                    report,
                    "bundle_env_parses".to_string(),
                    false,
                    CODE_BUNDLE_PARSE_ERROR,
                    error,
                );
                bundle_violations = true;
            }
        }
    }

    let repro_path = bundle_dir.join("repro.lock");
    if repro_path.is_file() {
        let repro_ok = fs::read_to_string(&repro_path)
            .map(|content| {
                let trimmed = content.trim();
                if trimmed.is_empty() {
                    return false;
                }
                if trimmed.starts_with('{') || trimmed.starts_with('[') {
                    serde_json::from_str::<serde_json::Value>(trimmed)
                        .map(|value| value.is_object() || value.is_array())
                        .unwrap_or(false)
                } else {
                    true
                }
            })
            .unwrap_or(false);
        append_benchmark_bundle_check(
            report,
            "bundle_repro_lock_present_and_non_empty".to_string(),
            repro_ok,
            CODE_BUNDLE_PARSE_ERROR,
            if repro_ok {
                format!(
                    "repro.lock is present and parseable: {}",
                    repro_path.display()
                )
            } else {
                format!("repro.lock is missing or invalid: {}", repro_path.display())
            },
        );
        if !repro_ok {
            bundle_violations = true;
        }
    }

    let commands_path = bundle_dir.join("commands.txt");
    if commands_path.is_file() {
        match fs::read_to_string(&commands_path) {
            Ok(content) => {
                let non_empty = !content.trim().is_empty();
                append_benchmark_bundle_check(
                    report,
                    "bundle_commands_non_empty".to_string(),
                    non_empty,
                    CODE_BUNDLE_PARSE_ERROR,
                    if non_empty {
                        format!(
                            "commands.txt contains command transcript: {}",
                            commands_path.display()
                        )
                    } else {
                        format!("commands.txt is empty: {}", commands_path.display())
                    },
                );
                if !non_empty {
                    bundle_violations = true;
                }

                let remote_only = content.lines().any(|line| line.contains("rch exec --"));
                append_benchmark_bundle_check(
                    report,
                    "bundle_commands_include_rch_exec".to_string(),
                    remote_only,
                    CODE_BUNDLE_REMOTE_EXEC,
                    if remote_only {
                        "commands.txt includes rch-wrapped execution evidence".to_string()
                    } else {
                        "commands.txt must include at least one `rch exec --` command".to_string()
                    },
                );
                if !remote_only {
                    bundle_violations = true;
                }
            }
            Err(error) => {
                append_benchmark_bundle_check(
                    report,
                    "bundle_commands_readable".to_string(),
                    false,
                    CODE_BUNDLE_PARSE_ERROR,
                    format!(
                        "failed to read commands.txt '{}': {error}",
                        commands_path.display()
                    ),
                );
                bundle_violations = true;
            }
        }
    }

    let scope = if let Some(manifest) = manifest {
        format!(
            "bundle={} schema={} trace={} decision={} policy={}",
            bundle_dir.display(),
            manifest.schema_version,
            manifest.trace_id,
            manifest.decision_id,
            manifest.policy_id
        )
    } else {
        format!("bundle={}", bundle_dir.display())
    };
    report.events.push(VerifierEvent {
        trace_id: report.trace_id.clone(),
        decision_id: report.decision_id.clone(),
        policy_id: report.policy_id.clone(),
        component: THIRD_PARTY_VERIFIER_COMPONENT.to_string(),
        event: "benchmark_bundle_contract_checked".to_string(),
        outcome: if bundle_violations {
            "fail".to_string()
        } else {
            "pass".to_string()
        },
        error_code: if bundle_violations {
            Some(CODE_BUNDLE_PARSE_ERROR.to_string())
        } else {
            None
        },
    });

    if bundle_violations {
        report.verdict = VerificationVerdict::Failed;
        report.confidence_statement =
            "verification failed: benchmark bundle contract violations detected".to_string();
        report.scope_limitations.push(scope);
    } else if report.confidence_statement.trim().is_empty() {
        report.confidence_statement =
            "bundle contract checks passed alongside benchmark claim recomputation".to_string();
    }
}

fn append_benchmark_bundle_check(
    report: &mut ThirdPartyVerificationReport,
    name: String,
    passed: bool,
    error_code: &'static str,
    detail: String,
) {
    report.checks.push(VerificationCheckResult {
        name,
        passed,
        error_code: if passed {
            None
        } else {
            Some(error_code.to_string())
        },
        detail,
    });
}

fn execute_replay(args: ReplayArgs) -> Result<i32, String> {
    let trace = load_json_file::<NondeterminismTrace>(&args.trace)?;
    let replay_events = trace.events.clone();
    let session_id = trace.session_id.clone();
    let event_count = trace.events.len();

    let mut engine = ReplayEngine::new(trace, args.mode);
    for event in replay_events {
        engine
            .replay_next(event.source.clone(), &event.value)
            .map_err(|error| format!("replay failed at sequence {}: {error:?}", event.sequence))?;
    }

    let output = ReplayCommandOutput {
        schema_version: FRANKENCTL_SCHEMA_VERSION.to_string(),
        trace_path: args.trace.display().to_string(),
        mode: replay_mode_name(args.mode).to_string(),
        session_id,
        event_count,
        replayed_events: engine.replayed_events,
        divergence_count: engine.divergence_count(),
        critical_divergences: engine.critical_divergences(),
        complete: engine.is_complete(),
    };

    if let Some(path) = args.out {
        write_json_file(&path, &output)?;
    }
    print_json(&output)?;
    Ok(0)
}

fn validate_compile_artifact(artifact: &CompileArtifact) -> Vec<String> {
    let mut errors = Vec::new();

    let expected_parse_hash = artifact.parse_event_ir.canonical_hash();
    if artifact.hashes.parse_event_ir != expected_parse_hash {
        errors.push(format!(
            "parse_event_ir hash mismatch: expected `{expected_parse_hash}`, got `{}`",
            artifact.hashes.parse_event_ir
        ));
    }

    let expected_ir0_hash = artifact.ir0.content_hash().to_string();
    if artifact.hashes.ir0 != expected_ir0_hash {
        errors.push(format!(
            "ir0 hash mismatch: expected `{expected_ir0_hash}`, got `{}`",
            artifact.hashes.ir0
        ));
    }

    let expected_ir1_hash = artifact.lowering.ir1.content_hash().to_string();
    if artifact.hashes.ir1 != expected_ir1_hash {
        errors.push(format!(
            "ir1 hash mismatch: expected `{expected_ir1_hash}`, got `{}`",
            artifact.hashes.ir1
        ));
    }

    let expected_ir2_hash = artifact.lowering.ir2.content_hash().to_string();
    if artifact.hashes.ir2 != expected_ir2_hash {
        errors.push(format!(
            "ir2 hash mismatch: expected `{expected_ir2_hash}`, got `{}`",
            artifact.hashes.ir2
        ));
    }

    let expected_ir3_hash = artifact.lowering.ir3.content_hash().to_string();
    if artifact.hashes.ir3 != expected_ir3_hash {
        errors.push(format!(
            "ir3 hash mismatch: expected `{expected_ir3_hash}`, got `{}`",
            artifact.hashes.ir3
        ));
    }

    for event in &artifact.parse_event_ir.events {
        if event.trace_id.trim().is_empty()
            || event.decision_id.trim().is_empty()
            || event.policy_id.trim().is_empty()
            || event.component.trim().is_empty()
            || event.outcome.trim().is_empty()
        {
            errors.push("parse_event_ir contains event with missing structured fields".to_string());
            break;
        }
    }

    for event in &artifact.lowering.events {
        if event.trace_id.trim().is_empty()
            || event.decision_id.trim().is_empty()
            || event.policy_id.trim().is_empty()
            || event.component.trim().is_empty()
            || event.event.trim().is_empty()
            || event.outcome.trim().is_empty()
        {
            errors.push("lowering event contains missing structured fields".to_string());
            break;
        }
    }

    errors
}

fn parse_goal(value: &str) -> Result<ParseGoal, String> {
    match value {
        "script" => Ok(ParseGoal::Script),
        "module" => Ok(ParseGoal::Module),
        other => Err(format!(
            "invalid parse goal `{other}` (expected script|module)"
        )),
    }
}

fn parse_profile(value: &str) -> Result<ScaleProfile, String> {
    match value {
        "small" | "S" => Ok(ScaleProfile::Small),
        "medium" | "M" => Ok(ScaleProfile::Medium),
        "large" | "L" => Ok(ScaleProfile::Large),
        other => Err(format!(
            "invalid benchmark profile `{other}` (expected small|medium|large)"
        )),
    }
}

fn parse_family(value: &str) -> Result<BenchmarkFamily, String> {
    match value {
        "boot-storm" => Ok(BenchmarkFamily::BootStorm),
        "capability-churn" => Ok(BenchmarkFamily::CapabilityChurn),
        "mixed-cpu-io-agent-mesh" => Ok(BenchmarkFamily::MixedCpuIoAgentMesh),
        "reload-revoke-churn" => Ok(BenchmarkFamily::ReloadRevokeChurn),
        "adversarial-noise-under-load" => Ok(BenchmarkFamily::AdversarialNoiseUnderLoad),
        other => Err(format!("invalid benchmark family `{other}`")),
    }
}

fn parse_replay_mode(value: &str) -> Result<ReplayMode, String> {
    match value {
        "strict" => Ok(ReplayMode::Strict),
        "best-effort" => Ok(ReplayMode::BestEffort),
        "validate" => Ok(ReplayMode::Validate),
        other => Err(format!(
            "invalid replay mode `{other}` (expected strict|best-effort|validate)"
        )),
    }
}

fn replay_mode_name(mode: ReplayMode) -> &'static str {
    match mode {
        ReplayMode::Strict => "strict",
        ReplayMode::BestEffort => "best-effort",
        ReplayMode::Validate => "validate",
    }
}

fn parse_u64(value: &str, flag: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|error| format!("invalid {flag} value `{value}`: {error}"))
}

fn next_arg(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn default_run_id(prefix: &str) -> String {
    format!("{prefix}-{}", current_unix_ns())
}

fn default_benchmark_out_dir(run_id: &str) -> PathBuf {
    PathBuf::from(format!("artifacts/frankenctl_benchmark/{run_id}"))
}

fn current_unix_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let encoded = serde_json::to_string_pretty(value)
        .map_err(|error| format!("failed to encode JSON output: {error}"))?;
    println!("{encoded}");
    Ok(())
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create `{}`: {error}", parent.display()))?;
    }
    let encoded = serde_json::to_string_pretty(value)
        .map_err(|error| format!("failed to encode JSON for `{}`: {error}", path.display()))?;
    fs::write(path, encoded)
        .map_err(|error| format!("failed to write `{}`: {error}", path.display()))?;
    Ok(())
}

fn load_json_file<T: DeserializeOwned>(path: &Path) -> Result<T, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read `{}`: {error}", path.display()))?;
    serde_json::from_str::<T>(&content)
        .map_err(|error| format!("failed to parse JSON `{}`: {error}", path.display()))
}

fn load_onboarding_signals(path: &Path) -> Result<Vec<OnboardingScorecardSignal>, String> {
    let content = fs::read_to_string(path)
        .map_err(|error| format!("failed to read signal file `{}`: {error}", path.display()))?;
    if let Ok(signals) = serde_json::from_str::<Vec<OnboardingScorecardSignal>>(&content) {
        return Ok(signals);
    }
    if let Ok(bundle) = serde_json::from_str::<CompatibilityAdvisoryOutput>(&content) {
        return Ok(bundle.signals);
    }
    Err(format!(
        "failed to parse signal file `{}` as JSON array or compatibility advisory bundle",
        path.display()
    ))
}

fn sort_and_dedup_signals(signals: &mut Vec<OnboardingScorecardSignal>) {
    signals.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(left.signal_id.cmp(&right.signal_id))
            .then(left.source.cmp(&right.source))
    });
    signals.dedup();
}

fn write_materialized_files(files: &[SupportBundleFile], out_dir: &Path) -> Result<(), String> {
    for file in files {
        let destination = out_dir.join(&file.path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("failed to create `{}`: {error}", parent.display()))?;
        }
        fs::write(&destination, file.content.as_bytes())
            .map_err(|error| format!("failed to write `{}`: {error}", destination.display()))?;
    }
    Ok(())
}

fn write_support_bundle_files(output: &SupportBundleOutput, out_dir: &Path) -> Result<(), String> {
    write_materialized_files(&output.files, out_dir)
}

fn render_doctor_summary(output: &DoctorCommandOutput) -> String {
    let mut lines = vec![
        format!("schema_version: {}", output.schema_version),
        format!("workload_id: {}", output.workload_id),
        format!("package_name: {}", output.package_name),
        format!("preflight_verdict: {}", output.preflight_verdict),
        format!("readiness: {}", output.readiness),
        format!("remediation_effort: {}", output.remediation_effort),
        format!("recommendation: {}", output.rollout_recommendation),
        format!("blocked: {}", output.blocked),
        format!(
            "signal_counts: external={} compatibility={} platform={}",
            output.signal_counts.external_signals,
            output.signal_counts.compatibility_signals,
            output.signal_counts.platform_signals
        ),
        format!(
            "mandatory_fields_valid: {}",
            output.rollout_decision.mandatory_field_status.valid
        ),
        format!(
            "next_steps: {}",
            output.onboarding_scorecard.next_steps.len()
        ),
    ];

    for step in &output.onboarding_scorecard.next_steps {
        lines.push(format!(
            "  - [{}] {} owner={} cmd={}",
            step.severity, step.step_id, step.owner, step.reproducible_command
        ));
    }

    lines.push("reproducible_commands:".to_string());
    for command in &output.rollout_decision.reproducible_commands {
        lines.push(format!("  - {command}"));
    }

    lines.join("\n")
}

fn usage() -> String {
    [
        "frankenctl usage:",
        "  frankenctl version",
        "  frankenctl compile --input <source.js> --out <artifact.json> [--goal script|module]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "  frankenctl run --input <source.js> --extension-id <id> [--goal script|module] [--out <report.json>]",
        "  frankenctl doctor --input <runtime_input.json> [--summary] [--out-dir <path>]",
        "      [--workload-id <id>] [--package-name <name>] [--target-platform <value>]...",
        "      [--signals <signals.json>] [--advisories <signals_or_bundle.json>]",
        "      [--scenario-report <compatibility_scenario_report.json>] [--platform-signals <signals.json>]",
        "      [--extension-id <id>] [--trace-id <id>] [--start-ns <u64>] [--end-ns <u64>]",
        "      [--severity info|warning|critical] [--decision-type <snake_case_decision_type>]",
        "      [--redact-key <key_fragment>]...",
        "  frankenctl verify compile-artifact --input <artifact.json>",
        "  frankenctl verify receipt --input <verifier_input.json> --receipt-id <id> [--summary]",
        "  frankenctl benchmark run [--seed <u64>] [--run-id <id>] [--run-date <YYYY-MM-DD>]",
        "      [--profile small|medium|large]... [--family <name>]... [--out-dir <path>]",
        "  frankenctl benchmark score --input <publication_gate_input.json>",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>] [--output <results.json>]",
        "  frankenctl benchmark verify --bundle <dir> [--summary] [--output <report.json>]",
        "  frankenctl replay run --trace <trace.json> [--mode strict|best-effort|validate] [--out <report.json>]",
        "",
        "benchmark families:",
        "  boot-storm",
        "  capability-churn",
        "  mixed-cpu-io-agent-mesh",
        "  reload-revoke-churn",
        "  adversarial-noise-under-load",
    ]
    .join("\n")
}

fn command_label(command: &CommandSpec) -> &'static str {
    match command {
        CommandSpec::Version => "version",
        CommandSpec::Help => "help",
        CommandSpec::Compile(_) => "compile",
        CommandSpec::Run(_) => "run",
        CommandSpec::Doctor(_) => "doctor",
        CommandSpec::Verify(_) => "verify",
        CommandSpec::Benchmark(_) => "benchmark",
        CommandSpec::Replay(_) => "replay",
    }
}

fn command_remediation(command: &str) -> &'static str {
    match command {
        "compile" => "Verify --input/--out paths and parse goal, then rerun `frankenctl compile`.",
        "run" => "Verify extension source path and `--extension-id`, then rerun `frankenctl run`.",
        "doctor" => {
            "Verify runtime diagnostics input, optional signal paths, and then rerun `frankenctl doctor`."
        }
        "verify" => "Inspect input artifact/receipt payload and rerun `frankenctl verify ...`.",
        "benchmark" => {
            "Validate benchmark subcommand args (run|score|verify), then rerun `frankenctl benchmark ...`."
        }
        "replay" => "Validate trace JSON and mode, then rerun `frankenctl replay run`.",
        _ => "Run `frankenctl --help` for command usage details.",
    }
}

fn format_cli_error(trace_id: &str, command: &str, error: &str, remediation: &str) -> String {
    format!(
        "[frankenctl trace_id={trace_id} command={command}] {error}\nremediation: {remediation}"
    )
}

fn compile_usage() -> String {
    [
        "compile usage:",
        "  frankenctl compile --input <source.js> --out <artifact.json> [--goal script|module]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_command() {
        let args = vec!["version".to_string()];
        let parsed = parse_command(&args).expect("version command should parse");
        assert_eq!(parsed, CommandSpec::Version);
    }

    #[test]
    fn parse_compile_command() {
        let args = vec![
            "compile".to_string(),
            "--input".to_string(),
            "demo.js".to_string(),
            "--out".to_string(),
            "out.json".to_string(),
            "--goal".to_string(),
            "module".to_string(),
        ];
        let parsed = parse_command(&args).expect("compile command should parse");
        match parsed {
            CommandSpec::Compile(spec) => {
                assert_eq!(spec.input, PathBuf::from("demo.js"));
                assert_eq!(spec.out, PathBuf::from("out.json"));
                assert_eq!(spec.parse_goal, ParseGoal::Module);
            }
            other => panic!("expected compile command, got {other:?}"),
        }
    }

    #[test]
    fn parse_verify_receipt_command() {
        let args = vec![
            "verify".to_string(),
            "receipt".to_string(),
            "--input".to_string(),
            "receipts.json".to_string(),
            "--receipt-id".to_string(),
            "rcpt-1".to_string(),
            "--summary".to_string(),
        ];
        let parsed = parse_command(&args).expect("verify receipt should parse");
        match parsed {
            CommandSpec::Verify(VerifyArgs::Receipt {
                input,
                receipt_id,
                summary,
            }) => {
                assert_eq!(input, PathBuf::from("receipts.json"));
                assert_eq!(receipt_id, "rcpt-1");
                assert!(summary);
            }
            other => panic!("expected verify receipt command, got {other:?}"),
        }
    }

    #[test]
    fn parse_doctor_command() {
        let args = vec![
            "doctor".to_string(),
            "--input".to_string(),
            "runtime_input.json".to_string(),
            "--summary".to_string(),
            "--out-dir".to_string(),
            "artifacts/doctor".to_string(),
            "--workload-id".to_string(),
            "demo-workload".to_string(),
            "--package-name".to_string(),
            "demo-package".to_string(),
            "--target-platform".to_string(),
            "linux-x86_64".to_string(),
            "--scenario-report".to_string(),
            "compatibility_report.json".to_string(),
            "--severity".to_string(),
            "warning".to_string(),
        ];
        let parsed = parse_command(&args).expect("doctor command should parse");
        match parsed {
            CommandSpec::Doctor(spec) => {
                assert_eq!(spec.input, PathBuf::from("runtime_input.json"));
                assert!(spec.summary);
                assert_eq!(spec.out_dir, Some(PathBuf::from("artifacts/doctor")));
                assert_eq!(spec.workload_id.as_deref(), Some("demo-workload"));
                assert_eq!(spec.package_name.as_deref(), Some("demo-package"));
                assert_eq!(spec.target_platforms, vec!["linux-x86_64".to_string()]);
                assert_eq!(
                    spec.scenario_report,
                    Some(PathBuf::from("compatibility_report.json"))
                );
                assert_eq!(spec.filter.severity, parse_evidence_severity("warning"));
            }
            other => panic!("expected doctor command, got {other:?}"),
        }
    }

    #[test]
    fn parse_benchmark_with_filters() {
        let args = vec![
            "benchmark".to_string(),
            "run".to_string(),
            "--seed".to_string(),
            "123".to_string(),
            "--profile".to_string(),
            "small".to_string(),
            "--profile".to_string(),
            "large".to_string(),
            "--family".to_string(),
            "boot-storm".to_string(),
            "--family".to_string(),
            "reload-revoke-churn".to_string(),
            "--out-dir".to_string(),
            "artifacts/custom".to_string(),
        ];
        let parsed = parse_command(&args).expect("benchmark command should parse");
        match parsed {
            CommandSpec::Benchmark(BenchmarkArgs {
                mode: BenchmarkMode::Run(spec),
            }) => {
                assert_eq!(spec.seed, 123);
                assert_eq!(
                    spec.profiles,
                    vec![ScaleProfile::Small, ScaleProfile::Large]
                );
                assert_eq!(
                    spec.families,
                    vec![
                        BenchmarkFamily::BootStorm,
                        BenchmarkFamily::ReloadRevokeChurn
                    ]
                );
                assert_eq!(spec.out_dir, PathBuf::from("artifacts/custom"));
            }
            other => panic!("expected benchmark command, got {other:?}"),
        }
    }

    #[test]
    fn parse_benchmark_score_command() {
        let args = vec![
            "benchmark".to_string(),
            "score".to_string(),
            "--input".to_string(),
            "artifacts/input.json".to_string(),
            "--trace-id".to_string(),
            "trace-score".to_string(),
            "--decision-id".to_string(),
            "decision-score".to_string(),
            "--policy-id".to_string(),
            "policy-score".to_string(),
            "--output".to_string(),
            "artifacts/results.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("benchmark score should parse");
        match parsed {
            CommandSpec::Benchmark(BenchmarkArgs {
                mode: BenchmarkMode::Score(spec),
            }) => {
                assert_eq!(spec.input, PathBuf::from("artifacts/input.json"));
                assert_eq!(spec.trace_id, "trace-score");
                assert_eq!(spec.decision_id, "decision-score");
                assert_eq!(spec.policy_id, "policy-score");
                assert_eq!(spec.output, Some(PathBuf::from("artifacts/results.json")));
            }
            other => panic!("expected benchmark score command, got {other:?}"),
        }
    }

    #[test]
    fn parse_benchmark_verify_command() {
        let args = vec![
            "benchmark".to_string(),
            "verify".to_string(),
            "--bundle".to_string(),
            "artifacts/bundle".to_string(),
            "--summary".to_string(),
            "--output".to_string(),
            "artifacts/verify_report.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("benchmark verify should parse");
        match parsed {
            CommandSpec::Benchmark(BenchmarkArgs {
                mode: BenchmarkMode::Verify(spec),
            }) => {
                assert_eq!(spec.bundle, PathBuf::from("artifacts/bundle"));
                assert_eq!(
                    spec.output,
                    Some(PathBuf::from("artifacts/verify_report.json"))
                );
                assert!(spec.summary);
            }
            other => panic!("expected benchmark verify command, got {other:?}"),
        }
    }
}
