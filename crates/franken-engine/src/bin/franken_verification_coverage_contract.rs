#![forbid(unsafe_code)]

use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use frankenengine_engine::verification_coverage_contract::{
    BundleValidationReport, EventValidationReport, TierRProbeReport, ValidationContext,
    canonical_json_bytes, generate_contract, read_bounded_regular_file, render_markdown,
    validate_bundle, validate_contract_file, validate_event_stream, validate_tier_r_probe,
    write_artifact_manifest, write_bytes_no_replace,
};
use serde::Serialize;

const USAGE: &str = "\
usage:
  franken_verification_coverage_contract generate [--repo-root <path>] [--output <path>]
  franken_verification_coverage_contract render [--repo-root <path>] [--contract <path>] [--output <path>]
  franken_verification_coverage_contract validate [--repo-root <path>] [--contract <path>]
      [--output <path>] [--run-id <id>] [--trace-id <id>]
      [--test-id <id>] [--scenario-id <id>] [--seed <u64>] [--attempt <u32>]
      [--platform <id>] [--target <triple>] [--tier <id>] [--profile <id>]
  franken_verification_coverage_contract validate-events --events <path> [--report <path>]
  franken_verification_coverage_contract validate-tier-r --probe <path> [--report <path>]
  franken_verification_coverage_contract artifact-manifest --bundle <path>
  franken_verification_coverage_contract validate-bundle --bundle <path> [--report <path>]
";

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let command = args.next();
    let raw: Vec<String> = args.collect();
    match command.as_deref() {
        Some("generate") => command_generate(&raw),
        Some("render") => command_render(&raw),
        Some("validate") => command_validate(&raw),
        Some("validate-events") => command_validate_events(&raw),
        Some("validate-tier-r") => command_validate_tier_r(&raw),
        Some("artifact-manifest") => command_artifact_manifest(&raw),
        Some("validate-bundle") => command_validate_bundle(&raw),
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

fn command_generate(raw: &[String]) -> ExitCode {
    let options = match Options::parse(raw) {
        Ok(options) => options,
        Err(reason) => return usage_error(reason),
    };
    if let Err(reason) = options.reject_unknown(&["repo-root", "output"]) {
        return usage_error(reason);
    }
    let repo_root = match options.repo_root() {
        Ok(root) => root,
        Err(reason) => return usage_error(reason),
    };
    let contract = match generate_contract(&repo_root) {
        Ok(contract) => contract,
        Err(reason) => {
            eprintln!("{reason}");
            return ExitCode::FAILURE;
        }
    };
    let bytes = match canonical_json_bytes(&contract) {
        Ok(bytes) => bytes,
        Err(reason) => {
            eprintln!("{reason}");
            return ExitCode::from(2);
        }
    };
    emit_bytes(
        options
            .get("output")
            .map(PathBuf::from)
            .map(|path| resolve_against(&repo_root, path)),
        &bytes,
    )
}

fn command_render(raw: &[String]) -> ExitCode {
    let options = match Options::parse(raw) {
        Ok(options) => options,
        Err(reason) => return usage_error(reason),
    };
    if let Err(reason) = options.reject_unknown(&["repo-root", "contract", "output"]) {
        return usage_error(reason);
    }
    let repo_root = match options.repo_root() {
        Ok(root) => root,
        Err(reason) => return usage_error(reason),
    };
    let contract_path = options
        .get("contract")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root.join("docs/verification_coverage_contract_v1.json"));
    let contract_path = resolve_against(&repo_root, contract_path);
    let bytes = match read_bounded_regular_file(&contract_path, 32 * 1024 * 1024) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("read {}: {error}", contract_path.display());
            return ExitCode::from(2);
        }
    };
    let contract = match serde_json::from_slice(&bytes) {
        Ok(contract) => contract,
        Err(error) => {
            eprintln!("parse {}: {error}", contract_path.display());
            return ExitCode::from(2);
        }
    };
    emit_bytes(
        options
            .get("output")
            .map(PathBuf::from)
            .map(|path| resolve_against(&repo_root, path)),
        render_markdown(&contract).as_bytes(),
    )
}

fn command_validate(raw: &[String]) -> ExitCode {
    let options = match Options::parse(raw) {
        Ok(options) => options,
        Err(reason) => return usage_error(reason),
    };
    if let Err(reason) = options.reject_unknown(&[
        "repo-root",
        "contract",
        "output",
        "run-id",
        "trace-id",
        "test-id",
        "scenario-id",
        "seed",
        "attempt",
        "platform",
        "target",
        "tier",
        "profile",
    ]) {
        return usage_error(reason);
    }
    let repo_root = match options.repo_root() {
        Ok(root) => root,
        Err(reason) => return usage_error(reason),
    };
    let contract_path = resolve_against(
        &repo_root,
        options
            .get("contract")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("docs/verification_coverage_contract_v1.json")),
    );
    let context = match validation_context(&options) {
        Ok(context) => context,
        Err(reason) => return usage_error(reason),
    };
    let output = validate_contract_file(&repo_root, &contract_path, &context);
    let serialized_events = {
        let mut bytes = Vec::new();
        for event in &output.events {
            if let Err(error) = serde_json::to_writer(&mut bytes, event) {
                eprintln!("serialize generated event: {error}");
                return ExitCode::from(2);
            }
            bytes.push(b'\n');
        }
        bytes
    };
    let event_report = validate_event_stream(&serialized_events);
    if event_report.error_count != 0 {
        eprintln!(
            "refusing to publish validator output with invalid events: {:?}",
            event_report.findings
        );
        return ExitCode::FAILURE;
    }
    let mut envelope = match serde_json::to_vec_pretty(&output) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("serialize validation envelope: {error}");
            return ExitCode::from(2);
        }
    };
    envelope.push(b'\n');
    if let Some(path) = options.get("output") {
        let path = resolve_against(&repo_root, PathBuf::from(path));
        if let Err(reason) = write_bytes_no_replace(&path, &envelope) {
            eprintln!("{reason}");
            return ExitCode::from(2);
        }
    } else if let Err(error) = std::io::stdout().write_all(&envelope) {
        eprintln!("write validation envelope: {error}");
        return ExitCode::from(2);
    }
    if output.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn command_validate_events(raw: &[String]) -> ExitCode {
    let options = match Options::parse(raw) {
        Ok(options) => options,
        Err(reason) => return usage_error(reason),
    };
    if let Err(reason) = options.reject_unknown(&["events", "report"]) {
        return usage_error(reason);
    }
    let path = match options.required_path("events") {
        Ok(path) => path,
        Err(reason) => return usage_error(reason),
    };
    let report = match read_bounded_regular_file(&path, 16 * 1024 * 1024) {
        Ok(bytes) => validate_event_stream(&bytes),
        Err(error) => EventValidationReport {
            schema_version: "franken-engine.verification-event.validation-report.v1".to_string(),
            status: "fail".to_string(),
            event_count: 0,
            terminal_decision: None,
            first_failure: None,
            error_count: 1,
            findings: vec![
                frankenengine_engine::verification_coverage_contract::ValidationFinding {
                    error_code: "FE-VCC-1001".to_string(),
                    phase: "events.read".to_string(),
                    reason: format!("read {}: {error}", path.display()),
                    subject_id: None,
                    family_id: None,
                },
            ],
        },
    };
    emit_report(&options, &report, report.error_count == 0)
}

fn command_validate_tier_r(raw: &[String]) -> ExitCode {
    let options = match Options::parse(raw) {
        Ok(options) => options,
        Err(reason) => return usage_error(reason),
    };
    if let Err(reason) = options.reject_unknown(&["probe", "report"]) {
        return usage_error(reason);
    }
    let path = match options.required_path("probe") {
        Ok(path) => path,
        Err(reason) => return usage_error(reason),
    };
    let probe: TierRProbeReport = match read_json(&path) {
        Ok(probe) => probe,
        Err(reason) => {
            eprintln!("{reason}");
            return ExitCode::FAILURE;
        }
    };
    let findings = validate_tier_r_probe(&probe);
    let report = serde_json::json!({
        "schema_version": "franken-engine.provisional-tier-r-probe.validation-report.v1",
        "status": if findings.is_empty() { "pass" } else { "fail" },
        "scenario_count": probe.scenarios.len(),
        "error_count": findings.len(),
        "findings": findings,
    });
    emit_report(&options, &report, findings.is_empty())
}

fn command_artifact_manifest(raw: &[String]) -> ExitCode {
    let options = match Options::parse(raw) {
        Ok(options) => options,
        Err(reason) => return usage_error(reason),
    };
    if let Err(reason) = options.reject_unknown(&["bundle"]) {
        return usage_error(reason);
    }
    let bundle = match options.required_path("bundle") {
        Ok(path) => path,
        Err(reason) => return usage_error(reason),
    };
    match write_artifact_manifest(&bundle) {
        Ok(manifest) => match print_pretty_json(&manifest) {
            Ok(()) => ExitCode::SUCCESS,
            Err(reason) => {
                eprintln!("{reason}");
                ExitCode::from(2)
            }
        },
        Err(reason) => {
            eprintln!("{reason}");
            ExitCode::FAILURE
        }
    }
}

fn command_validate_bundle(raw: &[String]) -> ExitCode {
    let options = match Options::parse(raw) {
        Ok(options) => options,
        Err(reason) => return usage_error(reason),
    };
    if let Err(reason) = options.reject_unknown(&["bundle", "report"]) {
        return usage_error(reason);
    }
    let bundle = match options.required_path("bundle") {
        Ok(path) => path,
        Err(reason) => return usage_error(reason),
    };
    let report: BundleValidationReport = validate_bundle(&bundle);
    emit_report(&options, &report, report.error_count == 0)
}

fn validation_context(options: &Options) -> Result<ValidationContext, String> {
    let seed = options
        .get("seed")
        .unwrap_or("0")
        .parse()
        .map_err(|_| "--seed must be an unsigned integer".to_string())?;
    let attempt: u32 = options
        .get("attempt")
        .unwrap_or("1")
        .parse()
        .map_err(|_| "--attempt must be an unsigned integer".to_string())?;
    if attempt != 1 {
        return Err(
            "standalone validation must use --attempt 1; retries require a retained prior attempt_failed event in the scenario driver"
                .to_string(),
        );
    }
    let mut context = ValidationContext::certifying_now();
    if let Some(run_id) = options.get("run-id") {
        context.run_id = run_id.to_string();
    }
    if let Some(trace_id) = options.get("trace-id") {
        context.trace_id = trace_id.to_string();
    }
    context.test_id = options
        .get("test-id")
        .unwrap_or("verification-coverage-contract")
        .to_string();
    context.scenario_id = options
        .get("scenario-id")
        .unwrap_or("canonical-validation")
        .to_string();
    context.seed = seed;
    context.attempt = attempt;
    context.platform = options
        .get("platform")
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}-{}", env::consts::OS, env::consts::ARCH));
    if let Some(target) = options.get("target") {
        context.target = target.to_string();
    }
    context.tier = options
        .get("tier")
        .unwrap_or("verification-control-plane")
        .to_string();
    context.security_profile = options.get("profile").unwrap_or("evidence-on").to_string();
    for (field, value) in [
        ("run-id", context.run_id.as_str()),
        ("trace-id", context.trace_id.as_str()),
        ("test-id", context.test_id.as_str()),
        ("scenario-id", context.scenario_id.as_str()),
        ("platform", context.platform.as_str()),
        ("target", context.target.as_str()),
        ("tier", context.tier.as_str()),
        ("profile", context.security_profile.as_str()),
    ] {
        if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(format!(
                "--{field} must be nonblank, at most 256 bytes, and contain no control characters"
            ));
        }
    }
    Ok(context)
}

fn emit_report<T: Serialize>(options: &Options, report: &T, passed: bool) -> ExitCode {
    let result = match options.get("report") {
        Some(path) => write_pretty_json_new(Path::new(path), report),
        None => print_pretty_json(report),
    };
    if let Err(reason) = result {
        eprintln!("{reason}");
        ExitCode::from(2)
    } else if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn emit_bytes(path: Option<PathBuf>, bytes: &[u8]) -> ExitCode {
    match path {
        Some(path) => match write_bytes_no_replace(&path, bytes) {
            Ok(()) => ExitCode::SUCCESS,
            Err(reason) => {
                eprintln!("{reason}");
                ExitCode::from(2)
            }
        },
        None => {
            if let Err(error) = std::io::stdout().write_all(bytes) {
                eprintln!("write stdout: {error}");
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
    }
}

fn write_pretty_json_new<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| format!("serialize JSON: {error}"))?;
    bytes.push(b'\n');
    write_bytes_no_replace(path, &bytes)
}

fn print_pretty_json<T: Serialize>(value: &T) -> Result<(), String> {
    serde_json::to_writer_pretty(std::io::stdout(), value)
        .map_err(|error| format!("serialize JSON: {error}"))?;
    println!();
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = read_bounded_regular_file(path, 4 * 1024 * 1024)?;
    serde_json::from_slice(&bytes).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn usage_error(reason: String) -> ExitCode {
    eprintln!("{reason}\n{USAGE}");
    ExitCode::from(2)
}

fn resolve_against(root: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        root.join(path)
    }
}

fn find_repo_root() -> Option<PathBuf> {
    let mut current = env::current_dir().ok()?;
    loop {
        if current.join("docs/claim_to_proof_matrix_v1.json").is_file()
            && current.join(".beads/issues.jsonl").is_file()
        {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

#[derive(Debug, Default)]
struct Options {
    values: std::collections::BTreeMap<String, String>,
}

impl Options {
    fn parse(raw: &[String]) -> Result<Self, String> {
        let mut values = std::collections::BTreeMap::new();
        let mut index = 0;
        while index < raw.len() {
            let flag = raw[index]
                .strip_prefix("--")
                .ok_or_else(|| format!("expected --flag, got `{}`", raw[index]))?;
            let value = raw
                .get(index + 1)
                .ok_or_else(|| format!("--{flag} requires a value"))?;
            if values.insert(flag.to_string(), value.clone()).is_some() {
                return Err(format!("duplicate --{flag}"));
            }
            index += 2;
        }
        Ok(Self { values })
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    fn reject_unknown(&self, allowed: &[&str]) -> Result<(), String> {
        for key in self.values.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(format!("unknown option --{key}"));
            }
        }
        Ok(())
    }

    fn repo_root(&self) -> Result<PathBuf, String> {
        self.get("repo-root")
            .map(PathBuf::from)
            .or_else(find_repo_root)
            .ok_or_else(|| "could not find repository root; pass --repo-root".to_string())
    }

    fn required_path(&self, key: &str) -> Result<PathBuf, String> {
        self.get(key)
            .map(PathBuf::from)
            .ok_or_else(|| format!("--{key} is required"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_reject_duplicates() {
        let error = Options::parse(&[
            "--seed".to_string(),
            "1".to_string(),
            "--seed".to_string(),
            "2".to_string(),
        ])
        .expect_err("duplicate option must fail");
        assert!(error.contains("duplicate --seed"));
    }

    #[test]
    fn validation_context_rejects_non_initial_attempt() {
        let options =
            Options::parse(&["--attempt".to_string(), "0".to_string()]).expect("options parse");
        assert!(
            validation_context(&options)
                .expect_err("zero attempt fails")
                .contains("standalone validation must use --attempt 1")
        );
    }

    #[test]
    fn unknown_option_is_rejected() {
        let options = Options::parse(&["--mystery".to_string(), "x".to_string()]).expect("parse");
        assert!(options.reject_unknown(&["seed"]).is_err());
    }
}
