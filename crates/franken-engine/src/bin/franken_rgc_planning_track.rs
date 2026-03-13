#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;

use frankenengine_engine::rgc_planning_track::write_rgc_planning_track_bundle;
use serde::Serialize;

const OUTPUT_SCHEMA_VERSION: &str = "franken-engine.franken_rgc_planning_track.v1";

enum CliAction {
    Help,
    Run { out_dir: PathBuf },
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    schema_version: String,
    out_dir: String,
    scope_contract_snapshot: String,
    milestone_gatebook: String,
    risk_acceptance_ledger: String,
    wave_handoff_matrix: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    summary_md: String,
    trace_ids: String,
    report_hash: String,
    expired_risk_count: usize,
    all_gate_commands_rch_backed: bool,
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
        write_rgc_planning_track_bundle(&out_dir, &args).map_err(|error| error.to_string())?;
    let output = CommandOutput {
        schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
        out_dir: artifacts.out_dir.display().to_string(),
        scope_contract_snapshot: artifacts.scope_contract_snapshot_path.display().to_string(),
        milestone_gatebook: artifacts.milestone_gatebook_path.display().to_string(),
        risk_acceptance_ledger: artifacts.risk_acceptance_ledger_path.display().to_string(),
        wave_handoff_matrix: artifacts.wave_handoff_matrix_path.display().to_string(),
        run_manifest: artifacts.run_manifest_path.display().to_string(),
        events_jsonl: artifacts.events_path.display().to_string(),
        commands_txt: artifacts.commands_path.display().to_string(),
        summary_md: artifacts.summary_path.display().to_string(),
        trace_ids: artifacts.trace_ids_path.display().to_string(),
        report_hash: artifacts.report_hash,
        expired_risk_count: artifacts.expired_risk_count,
        all_gate_commands_rch_backed: artifacts.all_gate_commands_rch_backed,
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
    "Usage: franken_rgc_planning_track --out-dir <DIR>".to_string()
}
