#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig, OrchestratorError,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};
use frankenengine_engine::rgc_test_harness::{
    DeterministicTestContext, EventInput, HarnessLane, HarnessRunManifest, write_artifact_triad,
};
use frankenengine_engine::ts_normalization::{
    SourceIngestionSummary, SourceLanguage, prepare_source_entry_for_public_entrypoints,
};
use serde::{Deserialize, Serialize};

const PARITY_SCHEMA_VERSION: &str = "franken-engine.shipped-path-parity.v1";
const PARITY_TRACE_IDS_SCHEMA_VERSION: &str = "franken-engine.shipped-path-parity.trace-ids.v1";
const PARITY_COMPONENT: &str = "shipped_path_parity";
const PARITY_SCENARIO_ID: &str = "rgc-204c-shipped-path-parity";
const PARITY_FIXTURE_ID: &str = "js-ts-library-frankenctl";
const DEFAULT_OUTPUT_ROOT: &str = "artifacts/franken_shipped_path_parity";
const DEFAULT_SEED: u64 = 204_053;
const MISMATCH_ERROR_CODE: &str = "FE-RGC-204C-PARITY-0001";

#[derive(Debug)]
struct CliArgs {
    frankenctl_bin: PathBuf,
    out_dir: PathBuf,
    fail_on_mismatch: bool,
    seed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParityCommandFamily {
    Compile,
    Run,
}

impl ParityCommandFamily {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Run => "run",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedOutcome {
    Success,
    Failure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ParityVerdict {
    Match,
    Mismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MismatchKind {
    ExitCode,
    FailureClass,
    ParseGoal,
    SourceIngestion,
    Hashes,
    LoweringCounts,
    ExecutionValue,
    Lane,
    ContainmentAction,
    ArtifactMissing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FailureClass {
    SourceIngestion,
    Parse,
    Lowering,
    Runtime,
    Io,
    Infrastructure,
    Unknown,
}

#[derive(Debug, Clone)]
struct ParitySpecimen {
    specimen_id: &'static str,
    description: &'static str,
    command_family: ParityCommandFamily,
    source_file_name: &'static str,
    source: &'static str,
    parse_goal: ParseGoal,
    expected_outcome: ExpectedOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ComparableCompileHashes {
    parse_event_ir: String,
    ir0: String,
    ir1: String,
    ir2: String,
    ir3: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CompileComparable {
    parse_goal: String,
    source_ingestion: SourceIngestionSummary,
    hashes: ComparableCompileHashes,
    lowering_event_count: u64,
    lowering_witness_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RunComparable {
    source_ingestion: SourceIngestionSummary,
    lane: String,
    lane_reason: String,
    containment_action: String,
    execution_value: String,
    expected_loss_millionths: i64,
    instructions_executed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct InvocationRecord {
    entrypoint: String,
    success: bool,
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_class: Option<FailureClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compile: Option<CompileComparable>,
    #[serde(skip_serializing_if = "Option::is_none")]
    run: Option<RunComparable>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_path: Option<String>,
}

impl InvocationRecord {
    fn success_compile(
        entrypoint: &str,
        compile: CompileComparable,
        artifact_path: Option<&Path>,
    ) -> Self {
        Self {
            entrypoint: entrypoint.to_string(),
            success: true,
            exit_code: 0,
            failure_class: None,
            error_detail: None,
            compile: Some(compile),
            run: None,
            artifact_path: artifact_path.map(|path| path.display().to_string()),
        }
    }

    fn success_run(entrypoint: &str, run: RunComparable, artifact_path: Option<&Path>) -> Self {
        Self {
            entrypoint: entrypoint.to_string(),
            success: true,
            exit_code: 0,
            failure_class: None,
            error_detail: None,
            compile: None,
            run: Some(run),
            artifact_path: artifact_path.map(|path| path.display().to_string()),
        }
    }

    fn failure(
        entrypoint: &str,
        exit_code: i32,
        failure_class: FailureClass,
        error_detail: impl Into<String>,
        artifact_path: Option<&Path>,
    ) -> Self {
        Self {
            entrypoint: entrypoint.to_string(),
            success: false,
            exit_code,
            failure_class: Some(failure_class),
            error_detail: Some(error_detail.into()),
            compile: None,
            run: None,
            artifact_path: artifact_path.map(|path| path.display().to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SpecimenParityRecord {
    specimen_id: String,
    description: String,
    command_family: String,
    source_language: SourceLanguage,
    expected_outcome: ExpectedOutcome,
    verdict: ParityVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    mismatch_kind: Option<MismatchKind>,
    library: InvocationRecord,
    cli: InvocationRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ParityReport {
    schema_version: String,
    component: String,
    scenario_id: String,
    fixture_id: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    specimen_count: u64,
    match_count: u64,
    mismatch_count: u64,
    js_specimen_count: u64,
    ts_specimen_count: u64,
    contract_satisfied: bool,
    specimens: Vec<SpecimenParityRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TraceIds {
    schema_version: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CliOutputSummary {
    schema_version: String,
    run_dir: String,
    parity_report_path: String,
    trace_ids_path: String,
    specimen_count: u64,
    match_count: u64,
    mismatch_count: u64,
    contract_satisfied: bool,
}

#[derive(Debug, Deserialize)]
struct CliCompileStdout {
    parse_goal: String,
    source_ingestion: SourceIngestionSummary,
    hashes: ComparableCompileHashes,
    lowering_event_count: u64,
    lowering_witness_count: u64,
}

#[derive(Debug, Deserialize)]
struct CliCompileArtifact {
    parse_goal: String,
    source_ingestion: SourceIngestionSummary,
    hashes: ComparableCompileHashes,
}

#[derive(Debug, Deserialize)]
struct CliRunOutput {
    source_ingestion: SourceIngestionSummary,
    lane: String,
    lane_reason: String,
    containment_action: String,
    execution_value: String,
    expected_loss_millionths: i64,
    instructions_executed: u64,
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32, String> {
    let args = parse_args(std::env::args().skip(1))?;
    let summary = execute_parity(&args)?;
    print_json(&summary)?;
    if args.fail_on_mismatch && !summary.contract_satisfied {
        Ok(2)
    } else {
        Ok(0)
    }
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<CliArgs, String> {
    let mut frankenctl_bin = default_frankenctl_bin()?;
    let mut out_dir = PathBuf::from(DEFAULT_OUTPUT_ROOT);
    let mut fail_on_mismatch = false;
    let mut seed = DEFAULT_SEED;

    let collected: Vec<String> = args.collect();
    let mut index = 0usize;
    while index < collected.len() {
        match collected[index].as_str() {
            "--frankenctl-bin" => {
                index += 1;
                let value = collected
                    .get(index)
                    .ok_or_else(|| "--frankenctl-bin requires a value".to_string())?;
                frankenctl_bin = PathBuf::from(value);
            }
            "--out-dir" => {
                index += 1;
                let value = collected
                    .get(index)
                    .ok_or_else(|| "--out-dir requires a value".to_string())?;
                out_dir = PathBuf::from(value);
            }
            "--seed" => {
                index += 1;
                let value = collected
                    .get(index)
                    .ok_or_else(|| "--seed requires a value".to_string())?;
                seed = value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --seed value `{value}`: {error}"))?;
            }
            "--fail-on-mismatch" => fail_on_mismatch = true,
            "--help" | "-h" => {
                return Err(
                    "usage: franken_shipped_path_parity [--frankenctl-bin <path>] [--out-dir <path>] [--seed <u64>] [--fail-on-mismatch]"
                        .to_string(),
                );
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
        index += 1;
    }

    Ok(CliArgs {
        frankenctl_bin,
        out_dir,
        fail_on_mismatch,
        seed,
    })
}

fn default_frankenctl_bin() -> Result<PathBuf, String> {
    let current_exe = std::env::current_exe()
        .map_err(|error| format!("failed to resolve current executable: {error}"))?;
    let bin_dir = current_exe
        .parent()
        .ok_or_else(|| "current executable has no parent directory".to_string())?;
    let frankenctl_name = format!("frankenctl{}", std::env::consts::EXE_SUFFIX);
    Ok(bin_dir.join(frankenctl_name))
}

fn execute_parity(args: &CliArgs) -> Result<CliOutputSummary, String> {
    let context = DeterministicTestContext::new(
        PARITY_SCENARIO_ID,
        PARITY_FIXTURE_ID,
        HarnessLane::E2e,
        args.seed,
    );
    let run_id = context.default_run_id();
    let run_dir = args.out_dir.join(&run_id);
    let specimen_root = run_dir.join("specimens");
    fs::create_dir_all(&specimen_root).map_err(|error| {
        format!(
            "failed to create specimen directory `{}`: {error}",
            specimen_root.display()
        )
    })?;

    let mut events = vec![context.event(EventInput {
        sequence: 1,
        component: PARITY_COMPONENT,
        event: "shipped_path_parity_started",
        outcome: "started",
        error_code: None,
        timing_us: 0,
        timestamp_unix_ms: current_unix_ms(),
    })];
    let mut commands = Vec::new();
    let mut specimens = Vec::new();

    for (index, specimen) in specimen_corpus().iter().enumerate() {
        let record = run_specimen(
            args,
            &context,
            &run_dir,
            &specimen_root,
            specimen,
            &mut commands,
        )?;
        let verdict_label = match record.verdict {
            ParityVerdict::Match => "match",
            ParityVerdict::Mismatch => "mismatch",
        };
        events.push(context.event(EventInput {
            sequence: (index as u64) + 2,
            component: PARITY_COMPONENT,
            event: "shipped_path_specimen_evaluated",
            outcome: verdict_label,
            error_code: if record.verdict == ParityVerdict::Mismatch {
                Some(MISMATCH_ERROR_CODE)
            } else {
                None
            },
            timing_us: 0,
            timestamp_unix_ms: current_unix_ms(),
        }));
        specimens.push(record);
    }

    let match_count = specimens
        .iter()
        .filter(|record| record.verdict == ParityVerdict::Match)
        .count() as u64;
    let mismatch_count = specimens.len() as u64 - match_count;
    let js_specimen_count = specimens
        .iter()
        .filter(|record| record.source_language == SourceLanguage::JavaScript)
        .count() as u64;
    let ts_specimen_count = specimens
        .iter()
        .filter(|record| record.source_language == SourceLanguage::TypeScript)
        .count() as u64;
    let contract_satisfied = mismatch_count == 0;

    events.push(context.event(EventInput {
        sequence: (specimens.len() as u64) + 2,
        component: PARITY_COMPONENT,
        event: "shipped_path_parity_completed",
        outcome: if contract_satisfied { "pass" } else { "fail" },
        error_code: if contract_satisfied {
            None
        } else {
            Some(MISMATCH_ERROR_CODE)
        },
        timing_us: 0,
        timestamp_unix_ms: current_unix_ms(),
    }));

    let report = ParityReport {
        schema_version: PARITY_SCHEMA_VERSION.to_string(),
        component: PARITY_COMPONENT.to_string(),
        scenario_id: context.scenario_id.clone(),
        fixture_id: context.fixture_id.clone(),
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        specimen_count: specimens.len() as u64,
        match_count,
        mismatch_count,
        js_specimen_count,
        ts_specimen_count,
        contract_satisfied,
        specimens,
    };

    let parity_report_path = run_dir.join("parity_report.json");
    write_json_file(&parity_report_path, &report)?;
    let trace_ids_path = run_dir.join("trace_ids.json");
    write_json_file(
        &trace_ids_path,
        &TraceIds {
            schema_version: PARITY_TRACE_IDS_SCHEMA_VERSION.to_string(),
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
        },
    )?;

    let manifest = HarnessRunManifest::from_context(
        &context,
        run_id.clone(),
        events.len(),
        commands.len(),
        "./scripts/e2e/franken_shipped_path_parity_replay.sh run",
        current_unix_ms(),
    );
    write_artifact_triad(&args.out_dir, &manifest, &events, &commands)
        .map_err(|error| format!("failed to write artifact triad: {error}"))?;

    Ok(CliOutputSummary {
        schema_version: PARITY_SCHEMA_VERSION.to_string(),
        run_dir: run_dir.display().to_string(),
        parity_report_path: parity_report_path.display().to_string(),
        trace_ids_path: trace_ids_path.display().to_string(),
        specimen_count: report.specimen_count,
        match_count: report.match_count,
        mismatch_count: report.mismatch_count,
        contract_satisfied: report.contract_satisfied,
    })
}

fn run_specimen(
    args: &CliArgs,
    context: &DeterministicTestContext,
    run_dir: &Path,
    specimen_root: &Path,
    specimen: &ParitySpecimen,
    commands: &mut Vec<String>,
) -> Result<SpecimenParityRecord, String> {
    let source_path = specimen_root.join(specimen.source_file_name);
    fs::write(&source_path, specimen.source).map_err(|error| {
        format!(
            "failed to write specimen source `{}`: {error}",
            source_path.display()
        )
    })?;

    let source_language = infer_source_language(specimen.source_file_name);
    let (library, cli) = match specimen.command_family {
        ParityCommandFamily::Compile => {
            let artifact_path =
                run_dir.join(format!("{}-compile-artifact.json", specimen.specimen_id));
            (
                run_library_compile(specimen, context),
                run_cli_compile(args, specimen, &source_path, &artifact_path, commands)?,
            )
        }
        ParityCommandFamily::Run => {
            let report_path = run_dir.join(format!("{}-run-report.json", specimen.specimen_id));
            (
                run_library_run(specimen, &source_path),
                run_cli_run(args, specimen, &source_path, &report_path, commands)?,
            )
        }
    };

    let (verdict, mismatch_kind) = compare_records(specimen.command_family, &library, &cli);
    Ok(SpecimenParityRecord {
        specimen_id: specimen.specimen_id.to_string(),
        description: specimen.description.to_string(),
        command_family: specimen.command_family.as_str().to_string(),
        source_language,
        expected_outcome: specimen.expected_outcome,
        verdict,
        mismatch_kind,
        library,
        cli,
    })
}

fn run_library_compile(
    specimen: &ParitySpecimen,
    context: &DeterministicTestContext,
) -> InvocationRecord {
    let prepared = match prepare_source_entry_for_public_entrypoints(
        specimen.source,
        specimen.source_file_name,
        context.trace_id.as_str(),
        context.decision_id.as_str(),
        context.policy_id.as_str(),
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            return InvocationRecord::failure(
                "library_compile",
                1,
                FailureClass::SourceIngestion,
                error.to_string(),
                None,
            );
        }
    };

    let parser = CanonicalEs2020Parser;
    let (parse_result, parse_event_ir) = parser.parse_with_event_ir(
        prepared.prepared_source.as_str(),
        specimen.parse_goal,
        &ParserOptions::default(),
    );
    let syntax_tree = match parse_result {
        Ok(tree) => tree,
        Err(error) => {
            return InvocationRecord::failure(
                "library_compile",
                1,
                FailureClass::Parse,
                error.to_string(),
                None,
            );
        }
    };

    let ir0 = Ir0Module::from_syntax_tree(syntax_tree, specimen.source_file_name);
    let lowering = match lower_ir0_to_ir3(
        &ir0,
        &LoweringContext::new(
            context.trace_id.clone(),
            context.decision_id.clone(),
            context.policy_id.clone(),
        ),
    ) {
        Ok(lowering) => lowering,
        Err(error) => {
            return InvocationRecord::failure(
                "library_compile",
                1,
                FailureClass::Lowering,
                error.to_string(),
                None,
            );
        }
    };

    InvocationRecord::success_compile(
        "library_compile",
        CompileComparable {
            parse_goal: specimen.parse_goal.as_str().to_string(),
            source_ingestion: prepared.source_ingestion,
            hashes: ComparableCompileHashes {
                parse_event_ir: parse_event_ir.canonical_hash(),
                ir0: ir0.content_hash().to_string(),
                ir1: lowering.ir1.content_hash().to_string(),
                ir2: lowering.ir2.content_hash().to_string(),
                ir3: lowering.ir3.content_hash().to_string(),
            },
            lowering_event_count: lowering.events.len() as u64,
            lowering_witness_count: lowering.witnesses.len() as u64,
        },
        None,
    )
}

fn run_library_run(specimen: &ParitySpecimen, source_path: &Path) -> InvocationRecord {
    let source = specimen.source;
    let source_label = source_path.display().to_string();
    let (trace_id, decision_id, policy_id) = source_ingestion_ids("run", source);
    let prepared = match prepare_source_entry_for_public_entrypoints(
        source,
        source_label.as_str(),
        trace_id.as_str(),
        decision_id.as_str(),
        policy_id.as_str(),
    ) {
        Ok(prepared) => prepared,
        Err(error) => {
            return InvocationRecord::failure(
                "library_run",
                1,
                FailureClass::SourceIngestion,
                error.to_string(),
                None,
            );
        }
    };

    let mut metadata = source_ingestion_metadata(&prepared.source_ingestion);
    metadata.insert("source_ingestion.source_path".to_string(), source_label);
    let package = ExtensionPackage {
        extension_id: format!("{}-library", specimen.specimen_id),
        source: prepared.prepared_source,
        source_file: None,
        capabilities: Vec::new(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        metadata,
    };
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig {
        parse_goal: specimen.parse_goal,
        ..OrchestratorConfig::default()
    });
    let result = match orchestrator.execute(&package) {
        Ok(result) => result,
        Err(error) => {
            return InvocationRecord::failure(
                "library_run",
                1,
                classify_orchestrator_error(&error),
                error.to_string(),
                None,
            );
        }
    };

    InvocationRecord::success_run(
        "library_run",
        RunComparable {
            source_ingestion: prepared.source_ingestion,
            lane: result.lane.to_string(),
            lane_reason: result.lane_reason.to_string(),
            containment_action: result.containment_action.to_string(),
            execution_value: result.execution_value,
            expected_loss_millionths: result.expected_loss_millionths,
            instructions_executed: result.instructions_executed,
        },
        None,
    )
}

fn run_cli_compile(
    args: &CliArgs,
    specimen: &ParitySpecimen,
    source_path: &Path,
    artifact_path: &Path,
    commands: &mut Vec<String>,
) -> Result<InvocationRecord, String> {
    let command = vec![
        args.frankenctl_bin.display().to_string(),
        "compile".to_string(),
        "--input".to_string(),
        source_path.display().to_string(),
        "--out".to_string(),
        artifact_path.display().to_string(),
        "--goal".to_string(),
        specimen.parse_goal.as_str().to_string(),
        "--trace-id".to_string(),
        format!("cli-{}-trace", specimen.specimen_id),
        "--decision-id".to_string(),
        format!("cli-{}-decision", specimen.specimen_id),
        "--policy-id".to_string(),
        format!("cli-{}-policy", specimen.specimen_id),
    ];
    commands.push(command.join(" "));
    let output = run_command(command.as_slice())?;

    if !output.status.success() {
        let detail = stderr_or_fallback(&output);
        return Ok(InvocationRecord::failure(
            "frankenctl_compile",
            output.status.code().unwrap_or(1),
            classify_failure_detail(&detail),
            detail,
            artifact_path.exists().then_some(artifact_path),
        ));
    }

    let stdout_json: CliCompileStdout =
        parse_json_bytes(&output.stdout, "frankenctl compile stdout")?;
    let artifact_json: CliCompileArtifact =
        parse_json_file(artifact_path, "frankenctl compile artifact")?;
    Ok(InvocationRecord::success_compile(
        "frankenctl_compile",
        CompileComparable {
            parse_goal: artifact_json.parse_goal,
            source_ingestion: artifact_json.source_ingestion,
            hashes: artifact_json.hashes,
            lowering_event_count: stdout_json.lowering_event_count,
            lowering_witness_count: stdout_json.lowering_witness_count,
        },
        Some(artifact_path),
    ))
}

fn run_cli_run(
    args: &CliArgs,
    specimen: &ParitySpecimen,
    source_path: &Path,
    report_path: &Path,
    commands: &mut Vec<String>,
) -> Result<InvocationRecord, String> {
    let command = vec![
        args.frankenctl_bin.display().to_string(),
        "run".to_string(),
        "--input".to_string(),
        source_path.display().to_string(),
        "--extension-id".to_string(),
        format!("{}-cli", specimen.specimen_id),
        "--out".to_string(),
        report_path.display().to_string(),
    ];
    commands.push(command.join(" "));
    let output = run_command(command.as_slice())?;

    if !output.status.success() {
        let detail = stderr_or_fallback(&output);
        return Ok(InvocationRecord::failure(
            "frankenctl_run",
            output.status.code().unwrap_or(1),
            classify_failure_detail(&detail),
            detail,
            report_path.exists().then_some(report_path),
        ));
    }

    let report_json: CliRunOutput = parse_json_file(report_path, "frankenctl run report")?;
    Ok(InvocationRecord::success_run(
        "frankenctl_run",
        RunComparable {
            source_ingestion: report_json.source_ingestion,
            lane: report_json.lane,
            lane_reason: report_json.lane_reason,
            containment_action: report_json.containment_action,
            execution_value: report_json.execution_value,
            expected_loss_millionths: report_json.expected_loss_millionths,
            instructions_executed: report_json.instructions_executed,
        },
        Some(report_path),
    ))
}

fn run_command(command: &[String]) -> Result<Output, String> {
    if command.is_empty() {
        return Err("empty command".to_string());
    }
    let mut process = Command::new(&command[0]);
    process.args(&command[1..]);
    process
        .output()
        .map_err(|error| format!("failed to execute `{}`: {error}", command.join(" ")))
}

fn compare_records(
    command_family: ParityCommandFamily,
    library: &InvocationRecord,
    cli: &InvocationRecord,
) -> (ParityVerdict, Option<MismatchKind>) {
    if library.exit_code != cli.exit_code {
        return (ParityVerdict::Mismatch, Some(MismatchKind::ExitCode));
    }
    if !library.success && !cli.success {
        if library.failure_class == cli.failure_class {
            return (ParityVerdict::Match, None);
        }
        return (ParityVerdict::Mismatch, Some(MismatchKind::FailureClass));
    }
    if library.success != cli.success {
        return (ParityVerdict::Mismatch, Some(MismatchKind::ExitCode));
    }

    match command_family {
        ParityCommandFamily::Compile => compare_compile_records(library, cli),
        ParityCommandFamily::Run => compare_run_records(library, cli),
    }
}

fn compare_compile_records(
    library: &InvocationRecord,
    cli: &InvocationRecord,
) -> (ParityVerdict, Option<MismatchKind>) {
    let Some(library_compile) = library.compile.as_ref() else {
        return (ParityVerdict::Mismatch, Some(MismatchKind::ArtifactMissing));
    };
    let Some(cli_compile) = cli.compile.as_ref() else {
        return (ParityVerdict::Mismatch, Some(MismatchKind::ArtifactMissing));
    };

    if library_compile.parse_goal != cli_compile.parse_goal {
        return (ParityVerdict::Mismatch, Some(MismatchKind::ParseGoal));
    }
    if library_compile.source_ingestion != cli_compile.source_ingestion {
        return (ParityVerdict::Mismatch, Some(MismatchKind::SourceIngestion));
    }
    if library_compile.hashes != cli_compile.hashes {
        return (ParityVerdict::Mismatch, Some(MismatchKind::Hashes));
    }
    if library_compile.lowering_event_count != cli_compile.lowering_event_count
        || library_compile.lowering_witness_count != cli_compile.lowering_witness_count
    {
        return (ParityVerdict::Mismatch, Some(MismatchKind::LoweringCounts));
    }
    (ParityVerdict::Match, None)
}

fn compare_run_records(
    library: &InvocationRecord,
    cli: &InvocationRecord,
) -> (ParityVerdict, Option<MismatchKind>) {
    let Some(library_run) = library.run.as_ref() else {
        return (ParityVerdict::Mismatch, Some(MismatchKind::ArtifactMissing));
    };
    let Some(cli_run) = cli.run.as_ref() else {
        return (ParityVerdict::Mismatch, Some(MismatchKind::ArtifactMissing));
    };

    if library_run.source_ingestion != cli_run.source_ingestion {
        return (ParityVerdict::Mismatch, Some(MismatchKind::SourceIngestion));
    }
    if library_run.lane != cli_run.lane || library_run.lane_reason != cli_run.lane_reason {
        return (ParityVerdict::Mismatch, Some(MismatchKind::Lane));
    }
    if library_run.containment_action != cli_run.containment_action {
        return (
            ParityVerdict::Mismatch,
            Some(MismatchKind::ContainmentAction),
        );
    }
    if library_run.execution_value != cli_run.execution_value
        || library_run.expected_loss_millionths != cli_run.expected_loss_millionths
        || library_run.instructions_executed != cli_run.instructions_executed
    {
        return (ParityVerdict::Mismatch, Some(MismatchKind::ExecutionValue));
    }
    (ParityVerdict::Match, None)
}

fn classify_orchestrator_error(error: &OrchestratorError) -> FailureClass {
    match error {
        OrchestratorError::Parse(_) | OrchestratorError::EmptySource => FailureClass::Parse,
        OrchestratorError::Lowering(_) => FailureClass::Lowering,
        OrchestratorError::TsNormalization(_) => FailureClass::SourceIngestion,
        OrchestratorError::Interpreter(_)
        | OrchestratorError::Ledger(_)
        | OrchestratorError::Saga(_)
        | OrchestratorError::Cell(_)
        | OrchestratorError::Containment(_)
        | OrchestratorError::IfcRuntimeGuardBlocked { .. }
        | OrchestratorError::EmptyExtensionId => FailureClass::Runtime,
    }
}

fn classify_failure_detail(detail: &str) -> FailureClass {
    if detail.contains("source ingestion failed") || detail.contains("ts normalization") {
        FailureClass::SourceIngestion
    } else if detail.contains("parse failed") || detail.contains("parse:") {
        FailureClass::Parse
    } else if detail.contains("lowering failed") || detail.contains("lowering:") {
        FailureClass::Lowering
    } else if detail.contains("failed to read source") {
        FailureClass::Io
    } else if detail.contains("run failed")
        || detail.contains("interpreter:")
        || detail.contains("containment:")
        || detail.contains("runtime:")
    {
        FailureClass::Runtime
    } else if detail.contains("failed to execute") || detail.contains("No such file") {
        FailureClass::Infrastructure
    } else {
        FailureClass::Unknown
    }
}

fn source_ingestion_ids(command: &str, source: &str) -> (String, String, String) {
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

fn specimen_corpus() -> Vec<ParitySpecimen> {
    vec![
        ParitySpecimen {
            specimen_id: "compile_js_success",
            description: "compile path preserves JavaScript ingestion metadata and hashes",
            command_family: ParityCommandFamily::Compile,
            source_file_name: "compile_js_success.js",
            source: "const answer = 40 + 2;\n",
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedOutcome::Success,
        },
        ParitySpecimen {
            specimen_id: "compile_ts_success",
            description: "compile path normalizes TypeScript consistently",
            command_family: ParityCommandFamily::Compile,
            source_file_name: "compile_ts_success.ts",
            source: "const answer: number = 40 + 2;\n",
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedOutcome::Success,
        },
        ParitySpecimen {
            specimen_id: "compile_parse_failure",
            description: "compile path classifies parse failures consistently",
            command_family: ParityCommandFamily::Compile,
            source_file_name: "compile_parse_failure.js",
            source: "const broken = ;\n",
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedOutcome::Failure,
        },
        ParitySpecimen {
            specimen_id: "run_js_success",
            description: "run path executes JavaScript consistently",
            command_family: ParityCommandFamily::Run,
            source_file_name: "run_js_success.js",
            source: "let value = 2 + 3;\n",
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedOutcome::Success,
        },
        ParitySpecimen {
            specimen_id: "run_ts_success",
            description: "run path normalizes TypeScript before execution",
            command_family: ParityCommandFamily::Run,
            source_file_name: "run_ts_success.ts",
            source: "const value: number = 2 + 3;\n",
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedOutcome::Success,
        },
        ParitySpecimen {
            specimen_id: "run_parse_failure",
            description: "run path classifies parse failures consistently",
            command_family: ParityCommandFamily::Run,
            source_file_name: "run_parse_failure.js",
            source: "let broken = ;\n",
            parse_goal: ParseGoal::Script,
            expected_outcome: ExpectedOutcome::Failure,
        },
    ]
}

fn infer_source_language(file_name: &str) -> SourceLanguage {
    if file_name.ends_with(".ts") || file_name.ends_with(".tsx") {
        SourceLanguage::TypeScript
    } else {
        SourceLanguage::JavaScript
    }
}

fn stderr_or_fallback(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        format!("command exited with status {:?}", output.status.code())
    } else {
        stderr
    }
}

fn parse_json_bytes<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("failed to parse {label}: {error}"))
}

fn parse_json_file<T: for<'de> Deserialize<'de>>(path: &Path, label: &str) -> Result<T, String> {
    let bytes = fs::read(path)
        .map_err(|error| format!("failed to read {label} `{}`: {error}", path.display()))?;
    parse_json_bytes(&bytes, label)
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            format!(
                "failed to create parent directory `{}`: {error}",
                parent.display()
            )
        })?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize `{}`: {error}", path.display()))?;
    fs::write(path, bytes).map_err(|error| format!("failed to write `{}`: {error}", path.display()))
}

fn print_json<T: Serialize>(value: &T) -> Result<(), String> {
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|error| format!("json render failed: {error}"))?;
    println!("{rendered}");
    Ok(())
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compile_record_with_hash(hash: &str) -> InvocationRecord {
        InvocationRecord::success_compile(
            "library_compile",
            CompileComparable {
                parse_goal: "script".to_string(),
                source_ingestion: SourceIngestionSummary::default(),
                hashes: ComparableCompileHashes {
                    parse_event_ir: hash.to_string(),
                    ir0: hash.to_string(),
                    ir1: hash.to_string(),
                    ir2: hash.to_string(),
                    ir3: hash.to_string(),
                },
                lowering_event_count: 1,
                lowering_witness_count: 1,
            },
            None,
        )
    }

    fn run_record_with_value(value: &str) -> InvocationRecord {
        InvocationRecord::success_run(
            "library_run",
            RunComparable {
                source_ingestion: SourceIngestionSummary::default(),
                lane: "baseline_deterministic_profile".to_string(),
                lane_reason: "default_deterministic_profile".to_string(),
                containment_action: "allow".to_string(),
                execution_value: value.to_string(),
                expected_loss_millionths: 0,
                instructions_executed: 1,
            },
            None,
        )
    }

    #[test]
    fn corpus_covers_js_and_ts_inputs() {
        let corpus = specimen_corpus();
        assert!(
            corpus
                .iter()
                .any(|specimen| infer_source_language(specimen.source_file_name)
                    == SourceLanguage::JavaScript)
        );
        assert!(
            corpus
                .iter()
                .any(|specimen| infer_source_language(specimen.source_file_name)
                    == SourceLanguage::TypeScript)
        );
    }

    #[test]
    fn failure_classification_maps_known_messages() {
        assert_eq!(
            classify_failure_detail("source ingestion failed for `demo.ts`: bad input"),
            FailureClass::SourceIngestion
        );
        assert_eq!(
            classify_failure_detail("parse failed: unexpected token"),
            FailureClass::Parse
        );
        assert_eq!(
            classify_failure_detail("lowering failed: unsupported syntax"),
            FailureClass::Lowering
        );
        assert_eq!(
            classify_failure_detail("failed to read source `/tmp/demo.js`: missing"),
            FailureClass::Io
        );
    }

    #[test]
    fn compile_comparison_detects_hash_mismatch() {
        let library = compile_record_with_hash("aaa");
        let cli = compile_record_with_hash("bbb");
        let comparison = compare_records(ParityCommandFamily::Compile, &library, &cli);
        assert_eq!(
            comparison,
            (ParityVerdict::Mismatch, Some(MismatchKind::Hashes))
        );
    }

    #[test]
    fn run_comparison_detects_execution_value_mismatch() {
        let library = run_record_with_value("5");
        let cli = run_record_with_value("6");
        let comparison = compare_records(ParityCommandFamily::Run, &library, &cli);
        assert_eq!(
            comparison,
            (ParityVerdict::Mismatch, Some(MismatchKind::ExecutionValue))
        );
    }
}
