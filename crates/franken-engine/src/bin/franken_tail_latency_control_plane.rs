#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::tail_latency_control_plane::{
    StressProfile, write_tail_latency_control_plane_bundle,
};
use serde::Serialize;

#[derive(Debug, Clone)]
enum CliAction {
    Help,
    Run {
        out_dir: PathBuf,
        profile: StressProfile,
        epoch: u64,
        emit_artifact_stream: bool,
    },
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    out_dir: String,
    profile: StressProfile,
    epoch: u64,
    latency_control_plane_report: String,
    trace_ids: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    step_logs_dir: String,
    summary_md: String,
    env_json: String,
    repro_lock: String,
    guardrail_state: String,
    fallback_activated: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    match parse_args(env::args().skip(1))? {
        CliAction::Help => {
            print_help();
            Ok(())
        }
        CliAction::Run {
            out_dir,
            profile,
            epoch,
            emit_artifact_stream: should_emit_artifacts,
        } => {
            let mut command = format!(
                "cargo run -p frankenengine-engine --bin franken_tail_latency_control_plane -- --out-dir {} --profile {} --epoch {}",
                out_dir.display(),
                profile,
                epoch
            );
            if should_emit_artifacts {
                command.push_str(" --emit-artifact-stream");
            }
            let artifacts =
                write_tail_latency_control_plane_bundle(&out_dir, profile, epoch, &[command])?;
            let output = CommandOutput {
                out_dir: out_dir.display().to_string(),
                profile,
                epoch,
                latency_control_plane_report: artifacts.report_path.display().to_string(),
                trace_ids: artifacts.trace_ids_path.display().to_string(),
                run_manifest: artifacts.run_manifest_path.display().to_string(),
                events_jsonl: artifacts.events_path.display().to_string(),
                commands_txt: artifacts.commands_path.display().to_string(),
                step_logs_dir: artifacts.step_logs_dir.display().to_string(),
                summary_md: artifacts.summary_path.display().to_string(),
                env_json: artifacts.env_path.display().to_string(),
                repro_lock: artifacts.repro_lock_path.display().to_string(),
                guardrail_state: artifacts.guardrail_state.to_string(),
                fallback_activated: artifacts.fallback_activated,
            };
            println!("{}", serde_json::to_string_pretty(&output)?);
            if should_emit_artifacts {
                emit_artifact_stream(&artifacts)?;
            }
            Ok(())
        }
    }
}

fn parse_args<I>(args: I) -> Result<CliAction, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut out_dir = None;
    let mut profile = StressProfile::SyntheticContention;
    let mut epoch = 42u64;
    let mut emit_artifact_stream = false;
    let mut iter = args.into_iter();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(CliAction::Help),
            "--emit-artifact-stream" => {
                emit_artifact_stream = true;
            }
            "--out-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --out-dir".to_string())?;
                out_dir = Some(PathBuf::from(value));
            }
            "--profile" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --profile".to_string())?;
                profile = value.parse::<StressProfile>()?;
            }
            "--epoch" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --epoch".to_string())?;
                epoch = value.parse::<u64>()?;
            }
            other => {
                return Err(format!("unsupported argument `{other}`").into());
            }
        }
    }

    let out_dir =
        out_dir.unwrap_or_else(|| PathBuf::from("artifacts/rgc_tail_latency_control_plane/latest"));
    Ok(CliAction::Run {
        out_dir,
        profile,
        epoch,
        emit_artifact_stream,
    })
}

fn emit_artifact_stream(
    artifacts: &frankenengine_engine::tail_latency_control_plane::TailLatencyControlPlaneArtifacts,
) -> Result<(), Box<dyn Error>> {
    const MARKER: &str = "__RGC_TAIL_LATENCY_CONTROL_PLANE_ARTIFACT__";

    let files = [
        ("run_manifest.json", artifacts.run_manifest_path.clone()),
        ("events.jsonl", artifacts.events_path.clone()),
        ("commands.txt", artifacts.commands_path.clone()),
        ("trace_ids.json", artifacts.trace_ids_path.clone()),
        (
            "latency_control_plane_report.json",
            artifacts.report_path.clone(),
        ),
        ("summary.md", artifacts.summary_path.clone()),
        ("env.json", artifacts.env_path.clone()),
        ("repro.lock", artifacts.repro_lock_path.clone()),
        (
            "step_logs/step_000.log",
            artifacts.step_logs_dir.join("step_000.log"),
        ),
    ];

    for (name, path) in files {
        let contents = fs::read_to_string(&path)?;
        println!("{MARKER}:BEGIN:{name}");
        print!("{contents}");
        if !contents.ends_with('\n') {
            println!();
        }
        println!("{MARKER}:END:{name}");
    }

    Ok(())
}

fn print_help() {
    println!(
        "\
franken_tail_latency_control_plane

Usage:
  cargo run -p frankenengine-engine --bin franken_tail_latency_control_plane -- \\
    --out-dir <dir> [--profile balanced|synthetic-contention] [--epoch <n>] \\
    [--emit-artifact-stream]

Description:
  Compose the stage-envelope, queueing-admission, and bounded-feedback subsystems
  into a deterministic RGC-611 artifact bundle.
"
    );
}
