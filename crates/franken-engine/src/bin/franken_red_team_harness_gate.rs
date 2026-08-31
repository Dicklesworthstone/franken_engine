#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use frankenengine_engine::red_team_compromise_rate_metric_gate::{
    RedTeamCompromiseRateDecision, RedTeamCompromiseRateMetricReport,
    RedTeamHarnessMeasurementSummary, RedTeamHarnessOutput,
    evaluate_red_team_compromise_rate_metric, metric_input_from_harness_output,
    summarize_harness_output,
};
use serde::Serialize;

const OUTPUT_SCHEMA: &str = "franken-engine.red-team-harness-gate-output.v1";
const USAGE: &str = "usage: franken_red_team_harness_gate --input PATH|- [--output PATH] [--markdown PATH]";

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedArgs {
    Run(Args),
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    input: String,
    output: Option<PathBuf>,
    markdown: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct GateOutput {
    schema_version: &'static str,
    input: String,
    summary: RedTeamHarnessMeasurementSummary,
    report: RedTeamCompromiseRateMetricReport,
}

fn parse_args(arguments: impl IntoIterator<Item = String>) -> Result<ParsedArgs, String> {
    let mut input = None;
    let mut output = None;
    let mut markdown = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--input" => {
                input = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--input requires a value".to_string())?,
                );
            }
            "--output" => {
                output = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--output requires a value".to_string())?,
                ));
            }
            "--markdown" => {
                markdown = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--markdown requires a value".to_string())?,
                ));
            }
            "-h" | "--help" => return Ok(ParsedArgs::Help),
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    let input = input.ok_or_else(|| "--input is required".to_string())?;
    Ok(ParsedArgs::Run(Args {
        input,
        output,
        markdown,
    }))
}

fn read_input(input: &str) -> Result<Vec<u8>, String> {
    if input == "-" {
        let mut bytes = Vec::new();
        io::stdin()
            .read_to_end(&mut bytes)
            .map_err(|error| format!("failed to read harness JSON from stdin: {error}"))?;
        Ok(bytes)
    } else {
        fs::read(input).map_err(|error| format!("failed to read harness JSON from {input}: {error}"))
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        format!(
            "failed to create output directory {}: {error}",
            parent.display()
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("output path has no UTF-8 file name: {}", path.display()))?;
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    fs::write(&temporary, bytes)
        .map_err(|error| format!("failed to write {}: {error}", temporary.display()))?;
    if path.exists() {
        fs::remove_file(path)
            .map_err(|error| format!("failed to replace {}: {error}", path.display()))?;
    }
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        format!(
            "failed to publish {} as {}: {error}",
            temporary.display(),
            path.display()
        )
    })
}

fn evaluate(args: &Args) -> Result<GateOutput, String> {
    let bytes = read_input(&args.input)?;
    let harness: RedTeamHarnessOutput = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid RedTeamHarnessOutput JSON: {error}"))?;
    let summary = summarize_harness_output(&harness)
        .map_err(|error| format!("invalid repeated-trial harness output: {error}"))?;
    let metric_input = metric_input_from_harness_output(&harness)
        .map_err(|error| format!("harness-to-metric conversion failed: {error}"))?;
    let report = evaluate_red_team_compromise_rate_metric(&metric_input);
    Ok(GateOutput {
        schema_version: OUTPUT_SCHEMA,
        input: args.input.clone(),
        summary,
        report,
    })
}

fn run() -> Result<ExitCode, String> {
    let args = match parse_args(env::args().skip(1))? {
        ParsedArgs::Run(args) => args,
        ParsedArgs::Help => {
            println!("{USAGE}");
            return Ok(ExitCode::SUCCESS);
        }
    };
    let output = evaluate(&args)?;
    let mut json = serde_json::to_vec_pretty(&output)
        .map_err(|error| format!("failed to serialize gate output: {error}"))?;
    json.push(b'\n');
    if let Some(path) = &args.output {
        write_atomic(path, &json)?;
    } else {
        print!("{}", String::from_utf8_lossy(&json));
    }
    if let Some(path) = &args.markdown {
        let markdown = output.report.to_markdown();
        write_atomic(path, markdown.as_bytes())?;
    }
    Ok(match output.report.decision {
        RedTeamCompromiseRateDecision::Pass => ExitCode::SUCCESS,
        RedTeamCompromiseRateDecision::FailClosed => ExitCode::from(1),
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("franken_red_team_harness_gate: {error}");
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_requires_input() {
        assert_eq!(
            parse_args(Vec::<String>::new()),
            Err("--input is required".to_string())
        );
    }

    #[test]
    fn parser_accepts_all_outputs() {
        assert_eq!(
            parse_args([
                "--input".to_string(),
                "input.json".to_string(),
                "--output".to_string(),
                "report.json".to_string(),
                "--markdown".to_string(),
                "report.md".to_string(),
            ]),
            Ok(ParsedArgs::Run(Args {
                input: "input.json".to_string(),
                output: Some(PathBuf::from("report.json")),
                markdown: Some(PathBuf::from("report.md")),
            }))
        );
    }

    #[test]
    fn parser_help_is_success_path() {
        assert_eq!(parse_args(["--help".to_string()]), Ok(ParsedArgs::Help));
    }
}
