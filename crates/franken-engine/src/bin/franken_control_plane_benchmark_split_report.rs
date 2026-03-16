#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;

use frankenengine_engine::control_plane_benchmark_split_gate::write_control_plane_benchmark_split_reports;
use serde::{Deserialize, Serialize};

const OUTPUT_SCHEMA_VERSION: &str =
    "franken-engine.franken_control_plane_benchmark_split_report.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliAction {
    Help,
    Run { out_dir: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    let args: Vec<String> = env::args().skip(1).collect();
    let rendered = run_with_args(&args)?;
    println!("{rendered}");
    Ok(())
}

fn run_with_args(args: &[String]) -> Result<String, String> {
    match parse_args(args)? {
        CliAction::Help => Ok(help_text()),
        CliAction::Run { out_dir } => {
            let output = build_command_output(&out_dir)?;
            serde_json::to_string_pretty(&output).map_err(|error| error.to_string())
        }
    }
}

fn build_command_output(out_dir: &std::path::Path) -> Result<CommandOutput, String> {
    let artifacts =
        write_control_plane_benchmark_split_reports(out_dir).map_err(|error| error.to_string())?;
    Ok(CommandOutput {
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
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use frankenengine_engine::control_plane_benchmark_split_gate::{
        BENCHMARK_SPLIT_DELTA_REPORT_FILE, CONTROL_PLANE_REAL_CONTEXT_OVERHEAD_REPORT_FILE,
    };

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "franken_engine_{prefix}_{}_{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir)
            .unwrap_or_else(|error| panic!("failed to create {}: {error}", dir.display()));
        dir
    }

    #[test]
    fn parse_args_accepts_out_dir() {
        let args = vec!["--out-dir".to_string(), "artifacts/example".to_string()];
        assert_eq!(
            parse_args(&args).expect("parse args"),
            CliAction::Run {
                out_dir: PathBuf::from("artifacts/example"),
            }
        );
    }

    #[test]
    fn parse_args_returns_help_for_help_flag() {
        let args = vec!["--help".to_string()];
        assert_eq!(parse_args(&args).expect("parse args"), CliAction::Help);
    }

    #[test]
    fn parse_args_requires_out_dir_value() {
        let args = vec!["--out-dir".to_string()];
        assert_eq!(
            parse_args(&args).expect_err("missing value should fail"),
            "--out-dir requires a path"
        );
    }

    #[test]
    fn parse_args_rejects_unknown_arguments() {
        let args = vec!["--bogus".to_string()];
        let error = parse_args(&args).expect_err("unknown flag should fail");
        assert!(
            error.contains("unrecognized argument `--bogus`"),
            "unexpected error: {error}"
        );
        assert!(error.contains("Usage:"));
    }

    #[test]
    fn run_with_args_emits_json_output_and_writes_reports() {
        let out_dir = unique_temp_dir("control_plane_benchmark_split_report_bin");
        let args = vec!["--out-dir".to_string(), out_dir.display().to_string()];
        let rendered = run_with_args(&args).expect("run with args");
        let output: CommandOutput =
            serde_json::from_str(&rendered).expect("rendered output should be valid JSON");

        assert_eq!(output.schema_version, OUTPUT_SCHEMA_VERSION);
        assert_eq!(PathBuf::from(&output.out_dir), out_dir);
        assert_eq!(
            PathBuf::from(&output.control_plane_real_context_overhead_report),
            out_dir.join(CONTROL_PLANE_REAL_CONTEXT_OVERHEAD_REPORT_FILE)
        );
        assert_eq!(
            PathBuf::from(&output.benchmark_split_delta_report),
            out_dir.join(BENCHMARK_SPLIT_DELTA_REPORT_FILE)
        );
        assert!(
            PathBuf::from(&output.control_plane_real_context_overhead_report).exists(),
            "overhead report should be written"
        );
        assert!(
            PathBuf::from(&output.benchmark_split_delta_report).exists(),
            "delta report should be written"
        );
        assert!(!output.pass);
        assert!(output.rollback_required);
        assert!(!output.decision_id.is_empty());
    }
}
