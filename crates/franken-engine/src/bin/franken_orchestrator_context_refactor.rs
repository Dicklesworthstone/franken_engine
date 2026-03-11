#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;

use frankenengine_engine::control_plane_mock_inventory::{
    OrchestratorContextRefactorReport, orchestrator_context_refactor_exit_code,
    write_orchestrator_context_refactor_bundle,
    write_orchestrator_context_refactor_bundle_in_root,
};
use serde::Serialize;

const OUTPUT_SCHEMA_VERSION: &str = "franken-engine.franken_orchestrator_context_refactor.v1";

enum CliAction {
    Help,
    Run {
        out_dir: PathBuf,
        workspace_root: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    schema_version: String,
    out_dir: String,
    production_context_path_contract: String,
    orchestrator_context_refactor_report: String,
    trace_ids: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    step_logs_dir: String,
    summary_md: String,
    env_json: String,
    repro_lock: String,
    contract_hash: String,
    report_hash: String,
    corrected_seam_count: usize,
    outcome: String,
}

fn main() {
    match run() {
        Ok(exit_code) => {
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = env::args().collect();
    let (out_dir, workspace_root) = match parse_args(&args[1..])? {
        CliAction::Help => {
            println!("{}", help_text());
            return Ok(0);
        }
        CliAction::Run {
            out_dir,
            workspace_root,
        } => (out_dir, workspace_root),
    };

    let artifacts = if let Some(workspace_root) = workspace_root {
        write_orchestrator_context_refactor_bundle_in_root(&workspace_root, &out_dir, &args)
            .map_err(|error| error.to_string())?
    } else {
        write_orchestrator_context_refactor_bundle(&out_dir, &args)
            .map_err(|error| error.to_string())?
    };

    let report: OrchestratorContextRefactorReport = serde_json::from_slice(
        &fs::read(&artifacts.report_path).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let output = CommandOutput {
        schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
        out_dir: artifacts.out_dir.display().to_string(),
        production_context_path_contract: artifacts.contract_path.display().to_string(),
        orchestrator_context_refactor_report: artifacts.report_path.display().to_string(),
        trace_ids: artifacts.trace_ids_path.display().to_string(),
        run_manifest: artifacts.run_manifest_path.display().to_string(),
        events_jsonl: artifacts.events_path.display().to_string(),
        commands_txt: artifacts.commands_path.display().to_string(),
        step_logs_dir: artifacts.step_logs_dir.display().to_string(),
        summary_md: artifacts.summary_path.display().to_string(),
        env_json: artifacts.env_path.display().to_string(),
        repro_lock: artifacts.repro_lock_path.display().to_string(),
        contract_hash: artifacts.contract_hash,
        report_hash: artifacts.report_hash,
        corrected_seam_count: artifacts.corrected_seam_count,
        outcome: report.outcome.as_str().to_string(),
    };
    let rendered = serde_json::to_string_pretty(&output).map_err(|error| error.to_string())?;
    println!("{rendered}");

    Ok(orchestrator_context_refactor_exit_code(&report))
}

fn parse_args(args: &[String]) -> Result<CliAction, String> {
    if args.is_empty() {
        return Err(help_text());
    }

    let mut out_dir: Option<PathBuf> = None;
    let mut workspace_root: Option<PathBuf> = None;
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
            "--workspace-root" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("--workspace-root requires a path".to_string());
                };
                workspace_root = Some(PathBuf::from(value));
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
        .map(|out_dir| CliAction::Run {
            out_dir,
            workspace_root,
        })
        .ok_or_else(|| format!("missing required --out-dir\n\n{}", help_text()))
}

fn help_text() -> String {
    "Usage: franken_orchestrator_context_refactor --out-dir <DIR> [--workspace-root <WORKSPACE_ROOT>]".to_string()
}
