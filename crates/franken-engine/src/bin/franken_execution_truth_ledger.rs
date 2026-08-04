#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use chrono::{DateTime, Utc};
use frankenengine_engine::execution_truth_ledger::{
    ExecutionTruthLedger, ValidationContext, render_markdown, validate_ledger_file,
    write_events_jsonl,
};

const USAGE: &str = "\
usage:
  franken_execution_truth_ledger validate [--repo-root <path>] [--ledger <path>]
      [--events <path>] [--run-id <id>] [--trace-id <id>] [--scenario-id <id>]
      [--seed <u64>] [--attempt <u32>] [--as-of <RFC3339>]
  franken_execution_truth_ledger render [--repo-root <path>] [--ledger <path>]
";

#[derive(Debug)]
struct ValidateArgs {
    repo_root: PathBuf,
    ledger_path: PathBuf,
    events_path: Option<PathBuf>,
    run_id: String,
    trace_id: String,
    scenario_id: String,
    seed: u64,
    attempt: u32,
    as_of_utc: DateTime<Utc>,
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("validate") => match parse_validate_args(args.collect()) {
            Ok(config) => validate(config),
            Err(reason) => {
                eprintln!("{reason}\n{USAGE}");
                ExitCode::from(2)
            }
        },
        Some("render") => match parse_render_args(args.collect()) {
            Ok((repo_root, ledger_path)) => render(&repo_root, &ledger_path),
            Err(reason) => {
                eprintln!("{reason}\n{USAGE}");
                ExitCode::from(2)
            }
        },
        Some("-h" | "--help") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown command `{other}`\n{USAGE}");
            ExitCode::from(2)
        }
        None => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn parse_validate_args(raw: Vec<String>) -> Result<ValidateArgs, String> {
    let detected_repo_root = find_repo_root();
    let mut repo_root: Option<PathBuf> = None;
    let mut ledger_path: Option<PathBuf> = None;
    let mut events_path: Option<PathBuf> = None;
    let mut run_id = "run-execution-truth-ledger".to_string();
    let mut trace_id = "trace-execution-truth-ledger".to_string();
    let mut scenario_id = "canonical-validation".to_string();
    let mut seed = 0;
    let mut attempt = 1;
    let mut as_of_utc = Utc::now();
    let mut index = 0;
    while index < raw.len() {
        let flag = &raw[index];
        let value = raw
            .get(index + 1)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag.as_str() {
            "--repo-root" => repo_root = Some(PathBuf::from(value)),
            "--ledger" => ledger_path = Some(PathBuf::from(value)),
            "--events" => events_path = Some(PathBuf::from(value)),
            "--run-id" => run_id = nonempty(flag, value)?,
            "--trace-id" => trace_id = nonempty(flag, value)?,
            "--scenario-id" => scenario_id = nonempty(flag, value)?,
            "--seed" => {
                seed = value
                    .parse()
                    .map_err(|_| format!("--seed must be an unsigned integer: {value}"))?;
            }
            "--attempt" => {
                attempt = value
                    .parse()
                    .map_err(|_| format!("--attempt must be an unsigned integer: {value}"))?;
                if attempt == 0 {
                    return Err("--attempt must be at least 1".to_string());
                }
            }
            "--as-of" => {
                as_of_utc = DateTime::parse_from_rfc3339(value)
                    .map_err(|error| format!("--as-of must be RFC3339: {error}"))?
                    .with_timezone(&Utc);
            }
            unknown => return Err(format!("unknown validate option `{unknown}`")),
        }
        index += 2;
    }
    let repo_root = repo_root
        .or(detected_repo_root)
        .ok_or_else(|| "could not find repository root; pass --repo-root explicitly".to_string())?;
    let ledger_path =
        ledger_path.unwrap_or_else(|| PathBuf::from("docs/execution_truth_ledger_v1.json"));
    Ok(ValidateArgs {
        ledger_path: resolve_against(&repo_root, ledger_path),
        events_path: events_path.map(|path| resolve_against(&repo_root, path)),
        repo_root,
        run_id,
        trace_id,
        scenario_id,
        seed,
        attempt,
        as_of_utc,
    })
}

fn parse_render_args(raw: Vec<String>) -> Result<(PathBuf, PathBuf), String> {
    let detected_repo_root = find_repo_root();
    let mut repo_root: Option<PathBuf> = None;
    let mut ledger_path: Option<PathBuf> = None;
    let mut index = 0;
    while index < raw.len() {
        let flag = &raw[index];
        let value = raw
            .get(index + 1)
            .ok_or_else(|| format!("{flag} requires a value"))?;
        match flag.as_str() {
            "--repo-root" => repo_root = Some(PathBuf::from(value)),
            "--ledger" => ledger_path = Some(PathBuf::from(value)),
            unknown => return Err(format!("unknown render option `{unknown}`")),
        }
        index += 2;
    }
    let repo_root = repo_root
        .or(detected_repo_root)
        .ok_or_else(|| "could not find repository root; pass --repo-root explicitly".to_string())?;
    let ledger_path =
        ledger_path.unwrap_or_else(|| PathBuf::from("docs/execution_truth_ledger_v1.json"));
    Ok((repo_root.clone(), resolve_against(&repo_root, ledger_path)))
}

fn validate(config: ValidateArgs) -> ExitCode {
    let context = ValidationContext {
        run_id: config.run_id,
        trace_id: config.trace_id,
        scenario_id: config.scenario_id,
        seed: config.seed,
        attempt: config.attempt,
        as_of_utc: config.as_of_utc,
    };
    let output = validate_ledger_file(&config.repo_root, &config.ledger_path, &context);
    if let Some(events_path) = config.events_path.as_deref()
        && let Err(reason) = write_events_jsonl(events_path, &output.events)
    {
        eprintln!("failed to write validation events: {reason}");
        return ExitCode::from(2);
    }
    match serde_json::to_string_pretty(&output.report) {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("failed to serialize validation report: {error}");
            return ExitCode::from(2);
        }
    }
    if output.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn render(_repo_root: &Path, ledger_path: &Path) -> ExitCode {
    let bytes = match fs::read(ledger_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("failed to read {}: {error}", ledger_path.display());
            return ExitCode::from(2);
        }
    };
    let ledger: ExecutionTruthLedger = match serde_json::from_slice(&bytes) {
        Ok(ledger) => ledger,
        Err(error) => {
            eprintln!("failed to parse {}: {error}", ledger_path.display());
            return ExitCode::from(2);
        }
    };
    print!("{}", render_markdown(&ledger));
    ExitCode::SUCCESS
}

fn resolve_against(root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn nonempty(flag: &str, value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        Err(format!("{flag} must not be empty"))
    } else {
        Ok(value.to_string())
    }
}

fn find_repo_root() -> Option<PathBuf> {
    let mut current = env::current_dir().ok()?;
    loop {
        if current.join("docs/claim_to_proof_matrix_v1.json").is_file() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_attempt() {
        let error = parse_validate_args(vec!["--attempt".into(), "0".into()])
            .expect_err("zero attempt must fail");
        assert!(error.contains("at least 1"));
    }

    #[test]
    fn rejects_unknown_option() {
        let error = parse_validate_args(vec!["--mystery".into(), "value".into()])
            .expect_err("unknown option must fail");
        assert!(error.contains("unknown validate option"));
    }

    #[test]
    fn parses_deterministic_context() {
        let root = std::env::temp_dir().join("franken-execution-truth-ledger-context-root");
        let config = parse_validate_args(vec![
            "--repo-root".into(),
            root.to_string_lossy().into_owned(),
            "--seed".into(),
            "42".into(),
            "--attempt".into(),
            "2".into(),
            "--as-of".into(),
            "2026-07-24T00:00:00Z".into(),
        ])
        .expect("known options parse");
        assert_eq!(config.seed, 42);
        assert_eq!(config.attempt, 2);
        assert_eq!(config.as_of_utc.to_rfc3339(), "2026-07-24T00:00:00+00:00");
    }

    #[test]
    fn explicit_repo_root_rebinds_default_ledger() {
        let root = PathBuf::from("/tmp/franken-execution-truth-ledger-explicit-root");
        let config = parse_validate_args(vec![
            "--repo-root".into(),
            root.to_string_lossy().into_owned(),
        ])
        .expect("explicit root parses without requiring discovery");
        assert_eq!(config.repo_root, root);
        assert_eq!(
            config.ledger_path,
            config.repo_root.join("docs/execution_truth_ledger_v1.json")
        );

        let (render_root, render_ledger) = parse_render_args(vec![
            "--repo-root".into(),
            config.repo_root.to_string_lossy().into_owned(),
        ])
        .expect("render root parses without requiring discovery");
        assert_eq!(render_root, config.repo_root);
        assert_eq!(
            render_ledger,
            render_root.join("docs/execution_truth_ledger_v1.json")
        );
    }
}
