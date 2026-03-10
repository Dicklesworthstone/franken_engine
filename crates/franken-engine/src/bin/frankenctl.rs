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
use frankenengine_engine::hash_tiers::ContentHash;
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
use frankenengine_engine::ts_normalization::{
    SourceIngestionSummary, prepare_source_entry_for_public_entrypoints,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

const FRANKENCTL_SCHEMA_VERSION: &str = "franken-engine.frankenctl.v1";
const COMPILE_ARTIFACT_SCHEMA_VERSION: &str = "franken-engine.frankenctl.compile-artifact.v1";
const REACT_CLI_CONTRACT_SCHEMA_VERSION: &str = "franken-engine.frankenctl.react-cli-contract.v1";
const REACT_CLI_REPORT_SCHEMA_VERSION: &str = "franken-engine.frankenctl.react-cli-report.v1";
const REACT_CAPABILITY_CONTRACT_JSON: &str =
    include_str!("../../../../docs/rgc_react_capability_contract_v1.json");
const CODE_BUNDLE_MISSING_FILE: &str = "FE-TPV-BUNDLE-0001";
const CODE_BUNDLE_PARSE_ERROR: &str = "FE-TPV-BUNDLE-0002";
const CODE_BUNDLE_CONTEXT_MISMATCH: &str = "FE-TPV-BUNDLE-0003";
const CODE_BUNDLE_REMOTE_EXEC: &str = "FE-TPV-BUNDLE-0004";

#[derive(Debug, Clone, PartialEq, Eq)]
enum CommandSpec {
    Version,
    Help,
    HelpTopic(HelpTopic),
    Compile(CompileArgs),
    Run(RunArgs),
    Doctor(Box<DoctorArgs>),
    Verify(VerifyArgs),
    Benchmark(BenchmarkArgs),
    Replay(ReplayArgs),
    React(ReactArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelpTopic {
    Compile,
    Run,
    Doctor,
    Verify,
    VerifyCompileArtifact,
    VerifyReceipt,
    Benchmark,
    BenchmarkRun,
    BenchmarkScore,
    BenchmarkVerify,
    Replay,
    ReplayRun,
    React,
    ReactCompile,
    ReactBuild,
    ReactContract,
}

impl HelpTopic {
    fn render(self) -> String {
        match self {
            Self::Compile => compile_usage(),
            Self::Run => run_usage(),
            Self::Doctor => doctor_usage(),
            Self::Verify => verify_usage(),
            Self::VerifyCompileArtifact => verify_compile_artifact_usage(),
            Self::VerifyReceipt => verify_receipt_usage(),
            Self::Benchmark => benchmark_usage(),
            Self::BenchmarkRun => benchmark_run_usage(),
            Self::BenchmarkScore => benchmark_score_usage(),
            Self::BenchmarkVerify => benchmark_verify_usage(),
            Self::Replay => replay_usage(),
            Self::ReplayRun => replay_run_usage(),
            Self::React => react_usage(),
            Self::ReactCompile => react_compile_usage(),
            Self::ReactBuild => react_build_usage(),
            Self::ReactContract => react_contract_usage(),
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReactArgs {
    Compile(ReactCompileArgs),
    Build(ReactBuildArgs),
    Contract(ReactContractArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReactCompileArgs {
    input: PathBuf,
    source_form: ReactSourceForm,
    runtime_mode: Option<ReactRuntimeMode>,
    out: Option<PathBuf>,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReactBuildArgs {
    entry: PathBuf,
    target: ReactBuildTarget,
    out: Option<PathBuf>,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReactContractArgs {
    out: Option<PathBuf>,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReactSourceForm {
    Jsx,
    Tsx,
    JsxFragment,
}

impl ReactSourceForm {
    fn as_str(self) -> &'static str {
        match self {
            Self::Jsx => "jsx",
            Self::Tsx => "tsx",
            Self::JsxFragment => "jsx-fragment",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReactRuntimeMode {
    Classic,
    Automatic,
}

impl ReactRuntimeMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::Automatic => "automatic",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReactBuildTarget {
    Ssr,
    Client,
    Hydration,
}

impl ReactBuildTarget {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ssr => "ssr",
            Self::Client => "client",
            Self::Hydration => "hydration",
        }
    }
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
    #[serde(default)]
    source_ingestion: SourceIngestionSummary,
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
    source_ingestion: SourceIngestionSummary,
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
    source_ingestion: SourceIngestionSummary,
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

#[derive(Debug, Clone, Deserialize)]
struct ReactCapabilityContract {
    schema_version: String,
    bead_id: String,
    product_surfaces: Vec<ReactProductSurface>,
    capability_rows: Vec<ReactCapabilityRow>,
}

#[derive(Debug, Clone, Deserialize)]
struct ReactProductSurface {
    surface_bead: String,
    name: String,
    ship_status: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ReactCapabilityRow {
    capability_id: String,
    source_form: String,
    runtime_mode: String,
    entry_surface: String,
    support_status: String,
    owning_implementation_bead: String,
    parity_gate_bead: String,
    product_surface_bead: String,
    verification_lane: String,
    required_artifacts: Vec<String>,
    user_visible_diagnostic: ReactUserVisibleDiagnostic,
    unsupported_surface_policy: ReactUnsupportedSurfacePolicy,
}

#[derive(Debug, Clone, Deserialize)]
struct ReactUserVisibleDiagnostic {
    error_code: String,
    diagnostic_surface: String,
    message_template: String,
    remediation_bead: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ReactUnsupportedSurfacePolicy {
    fallback_mode: String,
    waiver_required: bool,
    max_waiver_age_hours: u64,
    user_visible_diagnostics_required: bool,
    target_milestone: String,
    claim_language_state: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliContractOutput {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    capability_contract_schema_version: String,
    capability_contract_bead: String,
    commands: Vec<ReactCliCommandContract>,
    compile_capabilities: Vec<ReactCliCapabilitySummary>,
    build_capabilities: Vec<ReactCliCapabilitySummary>,
    product_surfaces: Vec<ReactCliProductSurface>,
    output: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliCommandContract {
    name: String,
    output_schema_version: String,
    behavior: String,
    usage: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliCapabilitySummary {
    capability_id: String,
    support_status: String,
    source_form: Option<String>,
    runtime_mode: Option<String>,
    build_target: Option<String>,
    error_code: String,
    diagnostic_surface: String,
    message_template: String,
    fallback_mode: String,
    claim_language_state: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliProductSurface {
    surface_bead: String,
    name: String,
    ship_status: String,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliReportOutput {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    command: String,
    support_status: String,
    shipped: bool,
    blocked: bool,
    capability_id: String,
    request: ReactCliRequest,
    diagnostic: ReactCliDiagnostic,
    required_artifacts: Vec<String>,
    output: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliRequest {
    input_path: String,
    source_form: Option<String>,
    runtime_mode: Option<String>,
    build_target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReactCliDiagnostic {
    error_code: String,
    diagnostic_surface: String,
    message: String,
    remediation_bead: String,
    fallback_mode: String,
    waiver_required: bool,
    max_waiver_age_hours: u64,
    user_visible_diagnostics_required: bool,
    target_milestone: String,
    claim_language_state: String,
    owning_implementation_bead: String,
    parity_gate_bead: String,
    product_surface_bead: String,
    verification_lane: String,
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
        CommandSpec::HelpTopic(topic) => {
            println!("{}", topic.render());
            Ok(0)
        }
        CommandSpec::Compile(args) => execute_compile(args),
        CommandSpec::Run(args) => execute_run(args),
        CommandSpec::Doctor(args) => execute_doctor(*args),
        CommandSpec::Verify(args) => execute_verify(args),
        CommandSpec::Benchmark(args) => execute_benchmark(args),
        CommandSpec::Replay(args) => execute_replay(args),
        CommandSpec::React(args) => execute_react(args),
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
        "compile" => parse_compile_command(&args[1..]),
        "run" => parse_run_command(&args[1..]),
        "doctor" => parse_doctor_command(&args[1..]),
        "verify" => parse_verify_command(&args[1..]),
        "benchmark" => parse_benchmark_command(&args[1..]),
        "replay" => parse_replay_command(&args[1..]),
        "react" => parse_react_command(&args[1..]),
        other => Err(format!("unknown command `{other}`\n\n{}", usage())),
    }
}

fn parse_compile_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Compile));
    }

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
            flag => return Err(format!("unknown compile flag `{flag}`")),
        }
        index += 1;
    }

    let input = input.ok_or_else(|| "compile requires --input <path>".to_string())?;
    let out = out.ok_or_else(|| "compile requires --out <path>".to_string())?;

    Ok(CommandSpec::Compile(CompileArgs {
        input,
        out,
        parse_goal: goal,
        trace_id,
        decision_id,
        policy_id,
    }))
}

fn parse_run_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Run));
    }

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

    Ok(CommandSpec::Run(RunArgs {
        input: input.ok_or_else(|| "run requires --input <path>".to_string())?,
        extension_id: extension_id.ok_or_else(|| "run requires --extension-id <id>".to_string())?,
        parse_goal: goal,
        out,
    }))
}

fn parse_doctor_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::Doctor));
    }

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

    Ok(CommandSpec::Doctor(Box::new(DoctorArgs {
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
    })))
}

fn parse_verify_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Err("verify requires a subcommand: compile-artifact | receipt".to_string());
    }
    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::HelpTopic(HelpTopic::Verify)),
        "compile-artifact" => parse_verify_compile_artifact_command(&args[1..]),
        "receipt" => parse_verify_receipt_command(&args[1..]),
        other => Err(format!(
            "unknown verify subcommand `{other}` (expected compile-artifact | receipt)"
        )),
    }
}

fn parse_verify_compile_artifact_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::VerifyCompileArtifact));
    }

    let mut input: Option<PathBuf> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            flag => return Err(format!("unknown verify compile-artifact flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::Verify(VerifyArgs::CompileArtifact {
        input: input.ok_or_else(|| {
            "verify compile-artifact requires --input <artifact.json>".to_string()
        })?,
    }))
}

fn parse_verify_receipt_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::VerifyReceipt));
    }

    let mut input: Option<PathBuf> = None;
    let mut receipt_id: Option<String> = None;
    let mut summary = false;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--receipt-id" => receipt_id = Some(next_arg(args, &mut index, "--receipt-id")?),
            "--summary" => summary = true,
            flag => return Err(format!("unknown verify receipt flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::Verify(VerifyArgs::Receipt {
        input: input.ok_or_else(|| "verify receipt requires --input <path>".to_string())?,
        receipt_id: receipt_id
            .ok_or_else(|| "verify receipt requires --receipt-id <id>".to_string())?,
        summary,
    }))
}

fn parse_benchmark_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Err("benchmark requires a subcommand: run | score | verify".to_string());
    }
    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::HelpTopic(HelpTopic::Benchmark)),
        "run" => parse_benchmark_run_command(&args[1..]),
        "score" => parse_benchmark_score_command(&args[1..]),
        "verify" => parse_benchmark_verify_command(&args[1..]),
        other => Err(format!(
            "unknown benchmark subcommand `{other}` (expected run | score | verify)"
        )),
    }
}

fn parse_benchmark_run_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::BenchmarkRun));
    }

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

    Ok(CommandSpec::Benchmark(BenchmarkArgs {
        mode: BenchmarkMode::Run(BenchmarkRunArgs {
            run_id,
            run_date,
            seed,
            out_dir,
            profiles,
            families,
        }),
    }))
}

fn parse_benchmark_score_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::BenchmarkScore));
    }

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

    Ok(CommandSpec::Benchmark(BenchmarkArgs {
        mode: BenchmarkMode::Score(BenchmarkScoreArgs {
            input: input.ok_or_else(|| "benchmark score requires --input <path>".to_string())?,
            trace_id,
            decision_id,
            policy_id,
            output,
        }),
    }))
}

fn parse_benchmark_verify_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::BenchmarkVerify));
    }

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

    Ok(CommandSpec::Benchmark(BenchmarkArgs {
        mode: BenchmarkMode::Verify(BenchmarkVerifyArgs {
            bundle: bundle.ok_or_else(|| "benchmark verify requires --bundle <dir>".to_string())?,
            output,
            summary,
        }),
    }))
}

fn parse_replay_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Err("replay requires subcommand `run`".to_string());
    }

    match args[0].as_str() {
        "help" | "--help" | "-h" => Ok(CommandSpec::HelpTopic(HelpTopic::Replay)),
        "run" => parse_replay_run_command(&args[1..]),
        other => Err(format!(
            "unknown replay subcommand `{other}` (expected run)"
        )),
    }
}

fn parse_replay_run_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::ReplayRun));
    }

    let mut trace: Option<PathBuf> = None;
    let mut mode = ReplayMode::Strict;
    let mut out: Option<PathBuf> = None;

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--trace" => trace = Some(PathBuf::from(next_arg(args, &mut index, "--trace")?)),
            "--mode" => mode = parse_replay_mode(&next_arg(args, &mut index, "--mode")?)?,
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            flag => return Err(format!("unknown replay run flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::Replay(ReplayArgs {
        trace: trace.ok_or_else(|| "replay run requires --trace <path>".to_string())?,
        mode,
        out,
    }))
}

fn parse_react_command(args: &[String]) -> Result<CommandSpec, String> {
    if args.is_empty() {
        return Ok(CommandSpec::HelpTopic(HelpTopic::React));
    }

    match args[0].as_str() {
        "help" | "--help" | "-h" => match args.get(1).map(String::as_str) {
            Some("compile") => Ok(CommandSpec::HelpTopic(HelpTopic::ReactCompile)),
            Some("build") => Ok(CommandSpec::HelpTopic(HelpTopic::ReactBuild)),
            Some("contract") => Ok(CommandSpec::HelpTopic(HelpTopic::ReactContract)),
            Some(other) => Err(format!(
                "unknown react help topic `{other}` (expected compile|build|contract)"
            )),
            None => Ok(CommandSpec::HelpTopic(HelpTopic::React)),
        },
        "compile" => parse_react_compile_command(&args[1..]),
        "build" => parse_react_build_command(&args[1..]),
        "contract" => parse_react_contract_command(&args[1..]),
        other => Err(format!(
            "unknown react subcommand `{other}` (expected compile|build|contract)"
        )),
    }
}

fn parse_react_compile_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::ReactCompile));
    }

    let mut input: Option<PathBuf> = None;
    let mut source_form: Option<ReactSourceForm> = None;
    let mut runtime_mode: Option<ReactRuntimeMode> = None;
    let mut out: Option<PathBuf> = None;
    let mut trace_id = "trace-frankenctl-react-compile".to_string();
    let mut decision_id = "decision-frankenctl-react-compile".to_string();
    let mut policy_id = "frankenctl.react.compile.v1".to_string();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--input" => input = Some(PathBuf::from(next_arg(args, &mut index, "--input")?)),
            "--source-form" => {
                source_form = Some(parse_react_source_form(&next_arg(
                    args,
                    &mut index,
                    "--source-form",
                )?)?)
            }
            "--runtime" => {
                runtime_mode = Some(parse_react_runtime_mode(&next_arg(
                    args,
                    &mut index,
                    "--runtime",
                )?)?)
            }
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--trace-id" => trace_id = next_arg(args, &mut index, "--trace-id")?,
            "--decision-id" => decision_id = next_arg(args, &mut index, "--decision-id")?,
            "--policy-id" => policy_id = next_arg(args, &mut index, "--policy-id")?,
            flag => return Err(format!("unknown react compile flag `{flag}`")),
        }
        index += 1;
    }

    let source_form = source_form
        .ok_or_else(|| "react compile requires --source-form <jsx|tsx|jsx-fragment>".to_string())?;
    if source_form != ReactSourceForm::JsxFragment && runtime_mode.is_none() {
        return Err("react compile requires --runtime <classic|automatic> unless --source-form jsx-fragment".to_string());
    }
    if source_form == ReactSourceForm::JsxFragment && runtime_mode.is_some() {
        return Err(
            "react compile does not accept --runtime when --source-form jsx-fragment".to_string(),
        );
    }

    Ok(CommandSpec::React(ReactArgs::Compile(ReactCompileArgs {
        input: input.ok_or_else(|| "react compile requires --input <path>".to_string())?,
        source_form,
        runtime_mode,
        out,
        trace_id,
        decision_id,
        policy_id,
    })))
}

fn parse_react_build_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::ReactBuild));
    }

    let mut entry: Option<PathBuf> = None;
    let mut target: Option<ReactBuildTarget> = None;
    let mut out: Option<PathBuf> = None;
    let mut trace_id = "trace-frankenctl-react-build".to_string();
    let mut decision_id = "decision-frankenctl-react-build".to_string();
    let mut policy_id = "frankenctl.react.build.v1".to_string();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--entry" => entry = Some(PathBuf::from(next_arg(args, &mut index, "--entry")?)),
            "--target" => {
                target = Some(parse_react_build_target(&next_arg(
                    args, &mut index, "--target",
                )?)?)
            }
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--trace-id" => trace_id = next_arg(args, &mut index, "--trace-id")?,
            "--decision-id" => decision_id = next_arg(args, &mut index, "--decision-id")?,
            "--policy-id" => policy_id = next_arg(args, &mut index, "--policy-id")?,
            flag => return Err(format!("unknown react build flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::React(ReactArgs::Build(ReactBuildArgs {
        entry: entry.ok_or_else(|| "react build requires --entry <path>".to_string())?,
        target: target
            .ok_or_else(|| "react build requires --target <ssr|client|hydration>".to_string())?,
        out,
        trace_id,
        decision_id,
        policy_id,
    })))
}

fn parse_react_contract_command(args: &[String]) -> Result<CommandSpec, String> {
    if has_help_flag(args) {
        return Ok(CommandSpec::HelpTopic(HelpTopic::ReactContract));
    }

    let mut out: Option<PathBuf> = None;
    let mut trace_id = "trace-frankenctl-react-contract".to_string();
    let mut decision_id = "decision-frankenctl-react-contract".to_string();
    let mut policy_id = "frankenctl.react.contract.v1".to_string();

    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--out" => out = Some(PathBuf::from(next_arg(args, &mut index, "--out")?)),
            "--trace-id" => trace_id = next_arg(args, &mut index, "--trace-id")?,
            "--decision-id" => decision_id = next_arg(args, &mut index, "--decision-id")?,
            "--policy-id" => policy_id = next_arg(args, &mut index, "--policy-id")?,
            flag => return Err(format!("unknown react contract flag `{flag}`")),
        }
        index += 1;
    }

    Ok(CommandSpec::React(ReactArgs::Contract(ReactContractArgs {
        out,
        trace_id,
        decision_id,
        policy_id,
    })))
}

fn has_help_flag(args: &[String]) -> bool {
    args.iter()
        .any(|value| matches!(value.as_str(), "--help" | "-h"))
}

fn execute_compile(args: CompileArgs) -> Result<i32, String> {
    let source = fs::read_to_string(&args.input)
        .map_err(|error| format!("failed to read source `{}`: {error}", args.input.display()))?;
    let source_label = args.input.display().to_string();
    let prepared = prepare_source_entry_for_public_entrypoints(
        source.as_str(),
        source_label.as_str(),
        args.trace_id.as_str(),
        args.decision_id.as_str(),
        args.policy_id.as_str(),
    )
    .map_err(|error| format!("source ingestion failed for `{source_label}`: {error}"))?;
    let parser_options = ParserOptions::default();
    let parser = CanonicalEs2020Parser;
    let (parse_result, parse_event_ir) = parser.parse_with_event_ir(
        prepared.prepared_source.as_str(),
        args.parse_goal,
        &parser_options,
    );
    let syntax_tree = parse_result.map_err(|error| format!("parse failed: {error}"))?;

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
        source_ingestion: prepared.source_ingestion.clone(),
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
        source_ingestion: artifact.source_ingestion.clone(),
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
    let source_label = args.input.display().to_string();
    let (source_trace_id, source_decision_id, source_policy_id) =
        cli_source_ingestion_ids("run", source.as_str());
    let prepared = prepare_source_entry_for_public_entrypoints(
        source.as_str(),
        source_label.as_str(),
        source_trace_id.as_str(),
        source_decision_id.as_str(),
        source_policy_id.as_str(),
    )
    .map_err(|error| format!("source ingestion failed for `{source_label}`: {error}"))?;
    let mut metadata = source_ingestion_metadata(&prepared.source_ingestion);

    let package = ExtensionPackage {
        extension_id: args.extension_id.clone(),
        source: prepared.prepared_source,
        source_file: None,
        capabilities: Vec::new(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        metadata: {
            metadata.insert("source_ingestion.source_path".to_string(), source_label);
            metadata
        },
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
        source_ingestion: prepared.source_ingestion,
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
    trace
        .validate_for_replay()
        .map_err(|error| format!("replay failed before sequence 0: {error}"))?;
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

fn execute_react(args: ReactArgs) -> Result<i32, String> {
    match args {
        ReactArgs::Compile(args) => execute_react_compile(args),
        ReactArgs::Build(args) => execute_react_build(args),
        ReactArgs::Contract(args) => execute_react_contract(args),
    }
}

fn execute_react_compile(args: ReactCompileArgs) -> Result<i32, String> {
    if !args.input.is_file() {
        return Err(format!(
            "react compile requires an existing --input <path> (missing `{}`)",
            args.input.display()
        ));
    }
    let contract = parse_react_capability_contract()?;
    let row = select_react_compile_row(&contract, args.source_form, args.runtime_mode)?;
    let output = build_react_cli_report(
        &args.trace_id,
        &args.decision_id,
        &args.policy_id,
        "react-compile",
        ReactCliRequest {
            input_path: args.input.display().to_string(),
            source_form: Some(args.source_form.as_str().to_string()),
            runtime_mode: args.runtime_mode.map(|mode| mode.as_str().to_string()),
            build_target: None,
        },
        row,
        args.out.as_ref(),
    );

    if let Some(path) = &args.out {
        write_json_file(path, &output)?;
    }
    print_json(&output)?;
    Ok(25)
}

fn execute_react_build(args: ReactBuildArgs) -> Result<i32, String> {
    if !args.entry.exists() {
        return Err(format!(
            "react build requires an existing --entry <path> (missing `{}`)",
            args.entry.display()
        ));
    }
    let contract = parse_react_capability_contract()?;
    let row = select_react_build_row(&contract, args.target)?;
    let output = build_react_cli_report(
        &args.trace_id,
        &args.decision_id,
        &args.policy_id,
        "react-build",
        ReactCliRequest {
            input_path: args.entry.display().to_string(),
            source_form: None,
            runtime_mode: None,
            build_target: Some(args.target.as_str().to_string()),
        },
        row,
        args.out.as_ref(),
    );

    if let Some(path) = &args.out {
        write_json_file(path, &output)?;
    }
    print_json(&output)?;
    Ok(25)
}

fn execute_react_contract(args: ReactContractArgs) -> Result<i32, String> {
    let contract = parse_react_capability_contract()?;
    let compile_capabilities = contract
        .capability_rows
        .iter()
        .filter(|row| row.entry_surface == "compile_contract")
        .map(|row| ReactCliCapabilitySummary {
            capability_id: row.capability_id.clone(),
            support_status: row.support_status.clone(),
            source_form: Some(row.source_form.clone()),
            runtime_mode: Some(row.runtime_mode.clone()),
            build_target: None,
            error_code: row.user_visible_diagnostic.error_code.clone(),
            diagnostic_surface: row.user_visible_diagnostic.diagnostic_surface.clone(),
            message_template: row.user_visible_diagnostic.message_template.clone(),
            fallback_mode: row.unsupported_surface_policy.fallback_mode.clone(),
            claim_language_state: row.unsupported_surface_policy.claim_language_state.clone(),
        })
        .collect();
    let build_capabilities = contract
        .capability_rows
        .iter()
        .filter_map(|row| {
            let build_target = match row.entry_surface.as_str() {
                "ssr_entry" => Some("ssr".to_string()),
                "client_entry_preparation" => Some("client".to_string()),
                "hydration_artifacts" => Some("hydration".to_string()),
                _ => None,
            }?;
            Some(ReactCliCapabilitySummary {
                capability_id: row.capability_id.clone(),
                support_status: row.support_status.clone(),
                source_form: None,
                runtime_mode: None,
                build_target: Some(build_target),
                error_code: row.user_visible_diagnostic.error_code.clone(),
                diagnostic_surface: row.user_visible_diagnostic.diagnostic_surface.clone(),
                message_template: row.user_visible_diagnostic.message_template.clone(),
                fallback_mode: row.unsupported_surface_policy.fallback_mode.clone(),
                claim_language_state: row.unsupported_surface_policy.claim_language_state.clone(),
            })
        })
        .collect();
    let output = ReactCliContractOutput {
        schema_version: REACT_CLI_CONTRACT_SCHEMA_VERSION.to_string(),
        trace_id: args.trace_id,
        decision_id: args.decision_id,
        policy_id: args.policy_id,
        capability_contract_schema_version: contract.schema_version,
        capability_contract_bead: contract.bead_id,
        commands: vec![
            ReactCliCommandContract {
                name: "react compile".to_string(),
                output_schema_version: REACT_CLI_REPORT_SCHEMA_VERSION.to_string(),
                behavior: "fail_closed_until_capability_row_is_shipped".to_string(),
                usage: "frankenctl react compile --input <path> --source-form <jsx|tsx|jsx-fragment> [--runtime <classic|automatic>] [--out <report.json>]".to_string(),
            },
            ReactCliCommandContract {
                name: "react build".to_string(),
                output_schema_version: REACT_CLI_REPORT_SCHEMA_VERSION.to_string(),
                behavior: "fail_closed_until_build_target_is_shipped".to_string(),
                usage: "frankenctl react build --entry <path> --target <ssr|client|hydration> [--out <report.json>]".to_string(),
            },
            ReactCliCommandContract {
                name: "react contract".to_string(),
                output_schema_version: REACT_CLI_CONTRACT_SCHEMA_VERSION.to_string(),
                behavior: "emit_machine_readable_contract".to_string(),
                usage: "frankenctl react contract [--out <react_cli_contract.json>]".to_string(),
            },
        ],
        compile_capabilities,
        build_capabilities,
        product_surfaces: contract
            .product_surfaces
            .into_iter()
            .map(|surface| ReactCliProductSurface {
                surface_bead: surface.surface_bead,
                name: surface.name,
                ship_status: surface.ship_status,
            })
            .collect(),
        output: args.out.as_ref().map(|path| path.display().to_string()),
    };

    if let Some(path) = &args.out {
        write_json_file(path, &output)?;
    }
    print_json(&output)?;
    Ok(0)
}

fn parse_react_capability_contract() -> Result<ReactCapabilityContract, String> {
    serde_json::from_str(REACT_CAPABILITY_CONTRACT_JSON)
        .map_err(|error| format!("failed to parse embedded React capability contract: {error}"))
}

fn select_react_compile_row(
    contract: &ReactCapabilityContract,
    source_form: ReactSourceForm,
    runtime_mode: Option<ReactRuntimeMode>,
) -> Result<&ReactCapabilityRow, String> {
    let capability_id = match (source_form, runtime_mode) {
        (ReactSourceForm::Jsx, Some(ReactRuntimeMode::Classic)) => "jsx-classic-runtime-compile",
        (ReactSourceForm::Tsx, Some(ReactRuntimeMode::Classic)) => "tsx-classic-runtime-compile",
        (ReactSourceForm::JsxFragment, None) => "fragment-lowering-contract",
        (ReactSourceForm::Jsx, Some(ReactRuntimeMode::Automatic)) => {
            "jsx-automatic-runtime-compile"
        }
        (ReactSourceForm::Tsx, Some(ReactRuntimeMode::Automatic)) => {
            "tsx-automatic-runtime-compile"
        }
        _ => {
            return Err(
                "react compile request did not map to a declared capability contract row"
                    .to_string(),
            );
        }
    };
    contract
        .capability_rows
        .iter()
        .find(|row| row.capability_id == capability_id)
        .ok_or_else(|| format!("missing React capability contract row `{capability_id}`"))
}

fn select_react_build_row(
    contract: &ReactCapabilityContract,
    target: ReactBuildTarget,
) -> Result<&ReactCapabilityRow, String> {
    let capability_id = match target {
        ReactBuildTarget::Ssr => "react-ssr-entrypoint",
        ReactBuildTarget::Client => "react-client-entry-preparation",
        ReactBuildTarget::Hydration => "react-hydration-handoff-artifacts",
    };
    contract
        .capability_rows
        .iter()
        .find(|row| row.capability_id == capability_id)
        .ok_or_else(|| format!("missing React capability contract row `{capability_id}`"))
}

fn build_react_cli_report(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    command: &str,
    request: ReactCliRequest,
    row: &ReactCapabilityRow,
    out: Option<&PathBuf>,
) -> ReactCliReportOutput {
    ReactCliReportOutput {
        schema_version: REACT_CLI_REPORT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        command: command.to_string(),
        support_status: row.support_status.clone(),
        shipped: row.support_status == "shipped",
        blocked: row.support_status != "shipped",
        capability_id: row.capability_id.clone(),
        request,
        diagnostic: ReactCliDiagnostic {
            error_code: row.user_visible_diagnostic.error_code.clone(),
            diagnostic_surface: row.user_visible_diagnostic.diagnostic_surface.clone(),
            message: row.user_visible_diagnostic.message_template.clone(),
            remediation_bead: row.user_visible_diagnostic.remediation_bead.clone(),
            fallback_mode: row.unsupported_surface_policy.fallback_mode.clone(),
            waiver_required: row.unsupported_surface_policy.waiver_required,
            max_waiver_age_hours: row.unsupported_surface_policy.max_waiver_age_hours,
            user_visible_diagnostics_required: row
                .unsupported_surface_policy
                .user_visible_diagnostics_required,
            target_milestone: row.unsupported_surface_policy.target_milestone.clone(),
            claim_language_state: row.unsupported_surface_policy.claim_language_state.clone(),
            owning_implementation_bead: row.owning_implementation_bead.clone(),
            parity_gate_bead: row.parity_gate_bead.clone(),
            product_surface_bead: row.product_surface_bead.clone(),
            verification_lane: row.verification_lane.clone(),
        },
        required_artifacts: row.required_artifacts.clone(),
        output: out.map(|path| path.display().to_string()),
    }
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

fn parse_react_source_form(value: &str) -> Result<ReactSourceForm, String> {
    match value {
        "jsx" => Ok(ReactSourceForm::Jsx),
        "tsx" => Ok(ReactSourceForm::Tsx),
        "jsx-fragment" => Ok(ReactSourceForm::JsxFragment),
        other => Err(format!(
            "invalid react source form `{other}` (expected jsx|tsx|jsx-fragment)"
        )),
    }
}

fn parse_react_runtime_mode(value: &str) -> Result<ReactRuntimeMode, String> {
    match value {
        "classic" => Ok(ReactRuntimeMode::Classic),
        "automatic" => Ok(ReactRuntimeMode::Automatic),
        other => Err(format!(
            "invalid react runtime `{other}` (expected classic|automatic)"
        )),
    }
}

fn parse_react_build_target(value: &str) -> Result<ReactBuildTarget, String> {
    match value {
        "ssr" => Ok(ReactBuildTarget::Ssr),
        "client" => Ok(ReactBuildTarget::Client),
        "hydration" => Ok(ReactBuildTarget::Hydration),
        other => Err(format!(
            "invalid react build target `{other}` (expected ssr|client|hydration)"
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

fn cli_source_ingestion_ids(command: &str, source: &str) -> (String, String, String) {
    let source_hash = ContentHash::compute(source.as_bytes()).to_hex();
    let trace_suffix = &source_hash[..16];
    (
        format!("frankenctl-{command}-source-{trace_suffix}"),
        format!("frankenctl-{command}-decision-{trace_suffix}"),
        format!("frankenctl-{command}.ts-ingestion.v1"),
    )
}

fn source_ingestion_metadata(
    source_ingestion: &SourceIngestionSummary,
) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "source_ingestion.source_language".to_string(),
        source_ingestion.source_language.as_str().to_string(),
    );
    metadata.insert(
        "source_ingestion.normalization_applied".to_string(),
        source_ingestion.normalization_applied.to_string(),
    );
    metadata.insert(
        "source_ingestion.original_source_hash".to_string(),
        source_ingestion.original_source_hash.clone(),
    );
    metadata.insert(
        "source_ingestion.normalized_source_hash".to_string(),
        source_ingestion.normalized_source_hash.clone(),
    );
    metadata.insert(
        "source_ingestion.ts_decision_count".to_string(),
        source_ingestion.ts_decision_count.to_string(),
    );
    metadata.insert(
        "source_ingestion.ts_capability_intent_count".to_string(),
        source_ingestion.ts_capability_intent_count.to_string(),
    );
    metadata
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
        CommandSpec::HelpTopic(_) => "help",
        CommandSpec::Compile(_) => "compile",
        CommandSpec::Run(_) => "run",
        CommandSpec::Doctor(_) => "doctor",
        CommandSpec::Verify(_) => "verify",
        CommandSpec::Benchmark(_) => "benchmark",
        CommandSpec::Replay(_) => "replay",
        CommandSpec::React(_) => "react",
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
        "react" => {
            "Inspect `frankenctl react contract` and rerun with a declared source-form/runtime/target combination."
        }
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

fn run_usage() -> String {
    [
        "run usage:",
        "  frankenctl run --input <source.js> --extension-id <id> [--goal script|module] [--out <report.json>]",
    ]
    .join("\n")
}

fn doctor_usage() -> String {
    [
        "doctor usage:",
        "  frankenctl doctor --input <runtime_input.json> [--summary] [--out-dir <path>]",
        "      [--workload-id <id>] [--package-name <name>] [--target-platform <value>]...",
        "      [--signals <signals.json>] [--advisories <signals_or_bundle.json>]",
        "      [--scenario-report <compatibility_scenario_report.json>] [--platform-signals <signals.json>]",
        "      [--extension-id <id>] [--trace-id <id>] [--start-ns <u64>] [--end-ns <u64>]",
        "      [--severity info|warning|critical] [--decision-type <snake_case_decision_type>]",
        "      [--redact-key <key_fragment>]...",
    ]
    .join("\n")
}

fn verify_usage() -> String {
    [
        "verify usage:",
        "  frankenctl verify compile-artifact --input <artifact.json>",
        "  frankenctl verify receipt --input <verifier_input.json> --receipt-id <id> [--summary]",
    ]
    .join("\n")
}

fn verify_compile_artifact_usage() -> String {
    [
        "verify compile-artifact usage:",
        "  frankenctl verify compile-artifact --input <artifact.json>",
    ]
    .join("\n")
}

fn verify_receipt_usage() -> String {
    [
        "verify receipt usage:",
        "  frankenctl verify receipt --input <verifier_input.json> --receipt-id <id> [--summary]",
    ]
    .join("\n")
}

fn benchmark_usage() -> String {
    [
        "benchmark usage:",
        "  frankenctl benchmark run [--seed <u64>] [--run-id <id>] [--run-date <YYYY-MM-DD>]",
        "      [--profile small|medium|large]... [--family <name>]... [--out-dir <path>]",
        "  frankenctl benchmark score --input <publication_gate_input.json>",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>] [--output <results.json>]",
        "  frankenctl benchmark verify --bundle <dir> [--summary] [--output <report.json>]",
    ]
    .join("\n")
}

fn benchmark_run_usage() -> String {
    [
        "benchmark run usage:",
        "  frankenctl benchmark run [--seed <u64>] [--run-id <id>] [--run-date <YYYY-MM-DD>]",
        "      [--profile small|medium|large]... [--family <name>]... [--out-dir <path>]",
    ]
    .join("\n")
}

fn benchmark_score_usage() -> String {
    [
        "benchmark score usage:",
        "  frankenctl benchmark score --input <publication_gate_input.json>",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>] [--output <results.json>]",
    ]
    .join("\n")
}

fn benchmark_verify_usage() -> String {
    [
        "benchmark verify usage:",
        "  frankenctl benchmark verify --bundle <dir> [--summary] [--output <report.json>]",
    ]
    .join("\n")
}

fn replay_usage() -> String {
    [
        "replay usage:",
        "  frankenctl replay run --trace <trace.json> [--mode strict|best-effort|validate] [--out <report.json>]",
    ]
    .join("\n")
}

fn replay_run_usage() -> String {
    [
        "replay run usage:",
        "  frankenctl replay run --trace <trace.json> [--mode strict|best-effort|validate] [--out <report.json>]",
    ]
    .join("\n")
}

fn react_usage() -> String {
    [
        "react usage:",
        "  frankenctl react compile --input <path> --source-form <jsx|tsx|jsx-fragment>",
        "      [--runtime <classic|automatic>] [--out <report.json>]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "  frankenctl react build --entry <path> --target <ssr|client|hydration>",
        "      [--out <report.json>] [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "  frankenctl react contract [--out <react_cli_contract.json>]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "",
        "notes:",
        "  react compile/build currently fail closed with deterministic unsupported-surface guidance",
        "  until the owning implementation and parity-gate beads are actually shipped.",
    ]
    .join("\n")
}

fn react_compile_usage() -> String {
    [
        "react compile usage:",
        "  frankenctl react compile --input <path> --source-form <jsx|tsx|jsx-fragment>",
        "      [--runtime <classic|automatic>] [--out <report.json>]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "",
        "behavior:",
        "  emits a deterministic react-cli report tied to the embedded React capability contract",
        "  and exits non-zero until the requested capability row is shipped.",
    ]
    .join("\n")
}

fn react_build_usage() -> String {
    [
        "react build usage:",
        "  frankenctl react build --entry <path> --target <ssr|client|hydration>",
        "      [--out <report.json>] [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "",
        "behavior:",
        "  emits a deterministic react-cli report tied to the embedded React capability contract",
        "  and exits non-zero until the requested build target is shipped.",
    ]
    .join("\n")
}

fn react_contract_usage() -> String {
    [
        "react contract usage:",
        "  frankenctl react contract [--out <react_cli_contract.json>]",
        "      [--trace-id <id>] [--decision-id <id>] [--policy-id <id>]",
        "",
        "behavior:",
        "  prints the machine-readable React compile/build CLI contract synthesized from",
        "  docs/rgc_react_capability_contract_v1.json.",
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
    fn parse_run_help_command() {
        let args = vec!["run".to_string(), "--help".to_string()];
        let parsed = parse_command(&args).expect("run --help should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::Run));
    }

    #[test]
    fn parse_verify_help_commands() {
        let top_level = vec!["verify".to_string(), "--help".to_string()];
        let parsed = parse_command(&top_level).expect("verify --help should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::Verify));

        let receipt = vec![
            "verify".to_string(),
            "receipt".to_string(),
            "--help".to_string(),
        ];
        let parsed = parse_command(&receipt).expect("verify receipt --help should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::VerifyReceipt));
    }

    #[test]
    fn parse_benchmark_and_replay_help_commands() {
        let benchmark = vec![
            "benchmark".to_string(),
            "run".to_string(),
            "--help".to_string(),
        ];
        let parsed = parse_command(&benchmark).expect("benchmark run --help should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::BenchmarkRun));

        let replay = vec![
            "replay".to_string(),
            "run".to_string(),
            "--help".to_string(),
        ];
        let parsed = parse_command(&replay).expect("replay run --help should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::ReplayRun));
    }

    #[test]
    fn parse_react_help_commands() {
        let top_level = vec!["react".to_string(), "--help".to_string()];
        let parsed = parse_command(&top_level).expect("react --help should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::React));

        let compile = vec![
            "react".to_string(),
            "help".to_string(),
            "compile".to_string(),
        ];
        let parsed = parse_command(&compile).expect("react help compile should parse");
        assert_eq!(parsed, CommandSpec::HelpTopic(HelpTopic::ReactCompile));
    }

    #[test]
    fn parse_react_compile_command() {
        let args = vec![
            "react".to_string(),
            "compile".to_string(),
            "--input".to_string(),
            "demo.tsx".to_string(),
            "--source-form".to_string(),
            "tsx".to_string(),
            "--runtime".to_string(),
            "automatic".to_string(),
            "--out".to_string(),
            "react-report.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("react compile should parse");
        match parsed {
            CommandSpec::React(ReactArgs::Compile(spec)) => {
                assert_eq!(spec.input, PathBuf::from("demo.tsx"));
                assert_eq!(spec.source_form, ReactSourceForm::Tsx);
                assert_eq!(spec.runtime_mode, Some(ReactRuntimeMode::Automatic));
                assert_eq!(spec.out, Some(PathBuf::from("react-report.json")));
            }
            other => panic!("expected react compile command, got {other:?}"),
        }
    }

    #[test]
    fn parse_react_build_command() {
        let args = vec![
            "react".to_string(),
            "build".to_string(),
            "--entry".to_string(),
            "app.jsx".to_string(),
            "--target".to_string(),
            "ssr".to_string(),
            "--out".to_string(),
            "build-report.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("react build should parse");
        match parsed {
            CommandSpec::React(ReactArgs::Build(spec)) => {
                assert_eq!(spec.entry, PathBuf::from("app.jsx"));
                assert_eq!(spec.target, ReactBuildTarget::Ssr);
                assert_eq!(spec.out, Some(PathBuf::from("build-report.json")));
            }
            other => panic!("expected react build command, got {other:?}"),
        }
    }

    #[test]
    fn parse_react_contract_command() {
        let args = vec![
            "react".to_string(),
            "contract".to_string(),
            "--out".to_string(),
            "react-cli-contract.json".to_string(),
        ];
        let parsed = parse_command(&args).expect("react contract should parse");
        match parsed {
            CommandSpec::React(ReactArgs::Contract(spec)) => {
                assert_eq!(spec.out, Some(PathBuf::from("react-cli-contract.json")));
            }
            other => panic!("expected react contract command, got {other:?}"),
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
