#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;

use frankenengine_engine::asupersync_contract_matrix::{
    default_asupersync_root, write_asupersync_contract_bundle,
};
use serde::Serialize;

const OUTPUT_SCHEMA_VERSION: &str = "franken-engine.franken_asupersync_contract_matrix.v1";

enum CliAction {
    Help,
    Run {
        out_dir: PathBuf,
        asupersync_root: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize)]
struct CommandOutput {
    schema_version: String,
    out_dir: String,
    asupersync_contract_compat_matrix: String,
    version_drift_failure_codes: String,
    run_manifest: String,
    events_jsonl: String,
    commands_txt: String,
    report_hash: String,
    compatible_surface_count: usize,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let (out_dir, asupersync_root) = match parse_args(&args[1..])? {
        CliAction::Help => {
            println!("{}", help_text());
            return Ok(());
        }
        CliAction::Run {
            out_dir,
            asupersync_root,
        } => (out_dir, asupersync_root),
    };

    let artifacts = write_asupersync_contract_bundle(&out_dir, &asupersync_root, &args)
        .map_err(|error| error.to_string())?;
    let output = CommandOutput {
        schema_version: OUTPUT_SCHEMA_VERSION.to_string(),
        out_dir: artifacts.out_dir.display().to_string(),
        asupersync_contract_compat_matrix: artifacts.compat_matrix_path.display().to_string(),
        version_drift_failure_codes: artifacts.failure_codes_path.display().to_string(),
        run_manifest: artifacts.run_manifest_path.display().to_string(),
        events_jsonl: artifacts.events_path.display().to_string(),
        commands_txt: artifacts.commands_path.display().to_string(),
        report_hash: artifacts.report_hash,
        compatible_surface_count: artifacts.compatible_surface_count,
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
    let mut asupersync_root = default_asupersync_root();
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
            "--asupersync-root" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("--asupersync-root requires a path".to_string());
                };
                asupersync_root = PathBuf::from(value);
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
            asupersync_root,
        })
        .ok_or_else(|| format!("missing required --out-dir\n\n{}", help_text()))
}

fn help_text() -> String {
    "Usage: franken_asupersync_contract_matrix --out-dir <DIR> [--asupersync-root <DIR>]"
        .to_string()
}
