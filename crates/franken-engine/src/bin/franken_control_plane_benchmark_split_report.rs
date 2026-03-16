#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;

use frankenengine_engine::control_plane_benchmark_split_gate::write_control_plane_benchmark_split_reports;
use serde::Serialize;

const OUTPUT_SCHEMA_VERSION: &str =
    "franken-engine.franken_control_plane_benchmark_split_report.v1";

enum CliAction {
    Help,
    Run { out_dir: PathBuf },
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    schema_version: String,
    out_dir: String,
    control_plane_real_context_overhead_report: String,
    benchmark_split_delta_report: String,
    decision_id: String,
    pass: bool,
    rollback_required: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let out_dir = match parse_args(&args[1..])? {
        CliAction::Help => {
            println!("{}", help_text());
            return Ok(());
        }
        CliAction::Run { out_dir } => out_dir,
    };

    let artifacts =
        write_control_plane_benchmark_split_reports(&out_dir).map_err(|error| error.to_string())?;
    let output = CommandOutput {
        schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
        out_dir: artifacts.out_dir.display().to_string(),
        control_plane_real_context_overhead_report: artifacts
            .control_plane_real_context_overhead_report_path
            .display()
            .to_string(),
        benchmark_split_delta_report: artifacts
            .benchmark_split_delta_report_path
            .display()
            .to_string(),
        decision_id: artifacts.decision_id,
        pass: artifacts.pass,
        rollback_required: artifacts.rollback_required,
    };
    let rendered = serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?;
    println!("{rendered}");
    Ok(())
}

fn parse_args(args: &[String]) -> Result<CliAction, String> {
    if args.is_empty() {
        return Err(help_text());
    }

    let mut out_dir: Option<PathBuf> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "-h" | "--help" => return Ok(CliAction::Help),
            "--out-dir" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("--out-dir requires a path".to_string());
                };
                out_dir = Some(PathBuf::from(value));
                index += 2;
            }
            other => {
                return Err(format!(
                    "unrecognized argument `{other}`\n\n{}",
                    help_text()
                ));
            }
        }
    }

    out_dir
        .map(|out_dir| CliAction::Run { out_dir })
        .ok_or_else(|| format!("missing required --out-dir\n\n{}", help_text()))
}

fn help_text() -> String {
    "Usage: franken_control_plane_benchmark_split_report --out-dir <DIR>".to_string()
}
