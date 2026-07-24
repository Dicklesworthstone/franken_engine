#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use frankenengine_engine::intl_surface_contract::{
    ContractEvent, ERROR_JSON, ERROR_MUTATION_SURVIVED, EVENT_SCHEMA_VERSION, EventContext,
    IntlSurfaceContract, ProbeRunConfig, canonical_json, generate_contract, parse_contract,
    render_markdown, run_mutation_suite, run_probes, seal_directory, validate_contract_file,
    validation_events, write_create_new, write_jsonl_create_new,
};

const USAGE: &str = "\
usage:
  franken_intl_surface_contract generate
      [--repo-root <path>] [--franken-node-root <path>]
      --output <new-json> --markdown <new-markdown>
  franken_intl_surface_contract validate
      [--repo-root <path>] [--franken-node-root <path>] --input <json>
      --report <new-json> --events <new-jsonl>
      [--run-id <id>] [--trace-id <id>] [--test-id <id>]
      [--scenario-id <id>] [--seed <u64>] [--attempt <u32>]
  franken_intl_surface_contract mutations
      --input <json> --report <new-json> --events <new-jsonl>
      [--run-id <id>] [--trace-id <id>] [--test-id <id>]
  franken_intl_surface_contract probe
      [--repo-root <path>] [--franken-node-root <path>] --input <json>
      --frankenctl <path> --franken-node <path>
      --output-dir <new-directory>
      [--run-id <id>] [--trace-id <id>] [--test-id <id>]
      [--seed <u64>] [--attempt <u32>]
  franken_intl_surface_contract render --input <json> --output <new-markdown>
  franken_intl_surface_contract seal
      --input <json> --bundle <directory> --decision <pass|fail>
      --reproduction-command <shell-safe-command>

Exit codes: 0 pass; 2 usage/io/parse; 3 validation/mutation failure; 4 probe failure.
All output paths are create-new and are never overwritten.
";

#[derive(Debug)]
struct ParsedOptions {
    values: BTreeMap<String, String>,
    seen: BTreeSet<String>,
}

impl ParsedOptions {
    fn parse(raw: Vec<String>) -> Result<Self, String> {
        let mut values = BTreeMap::new();
        let mut seen = BTreeSet::new();
        let mut index = 0usize;
        while index < raw.len() {
            let flag = &raw[index];
            if !flag.starts_with("--") {
                return Err(format!("expected an option, got `{flag}`"));
            }
            if !seen.insert(flag.clone()) {
                return Err(format!("duplicate option `{flag}`"));
            }
            let value = raw
                .get(index + 1)
                .ok_or_else(|| format!("{flag} requires a value"))?;
            if value.starts_with("--") {
                return Err(format!("{flag} requires a value, got option `{value}`"));
            }
            values.insert(flag.clone(), value.clone());
            index += 2;
        }
        Ok(Self { values, seen })
    }

    fn reject_unknown(&self, allowed: &[&str]) -> Result<(), String> {
        for flag in &self.seen {
            if !allowed.contains(&flag.as_str()) {
                return Err(format!("unknown option `{flag}`"));
            }
        }
        Ok(())
    }

    fn required(&self, flag: &str) -> Result<String, String> {
        self.values
            .get(flag)
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or_else(|| format!("{flag} is required"))
    }

    fn optional(&self, flag: &str) -> Option<String> {
        self.values.get(flag).cloned()
    }

    fn defaulted(&self, flag: &str, default: &str) -> String {
        self.values
            .get(flag)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    }
}

fn main() -> ExitCode {
    let mut raw = env::args().skip(1);
    let Some(command) = raw.next() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if matches!(command.as_str(), "-h" | "--help" | "help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let options = match ParsedOptions::parse(raw.collect()) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result = match command.as_str() {
        "generate" => generate(options),
        "validate" => validate(options),
        "mutations" => mutations(options),
        "probe" => probe(options),
        "render" => render(options),
        "seal" => seal(options),
        other => Err((2, format!("unknown command `{other}`"))),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, error)) => {
            eprintln!("{error}");
            ExitCode::from(code)
        }
    }
}

fn generate(options: ParsedOptions) -> Result<(), (u8, String)> {
    options
        .reject_unknown(&[
            "--repo-root",
            "--franken-node-root",
            "--output",
            "--markdown",
        ])
        .map_err(usage)?;
    let (repo_root, node_root) = roots(&options);
    let output = PathBuf::from(options.required("--output").map_err(usage)?);
    let markdown = PathBuf::from(options.required("--markdown").map_err(usage)?);
    let contract = generate_contract(&repo_root, &node_root).map_err(runtime)?;
    write_create_new(&output, &canonical_json(&contract).map_err(runtime)?).map_err(runtime)?;
    write_create_new(&markdown, render_markdown(&contract).as_bytes()).map_err(runtime)?;
    print!(
        "{}",
        String::from_utf8(canonical_json(&contract).map_err(runtime)?)
            .map_err(|error| runtime(format!("{ERROR_JSON}: {error}")))?,
    );
    Ok(())
}

fn validate(options: ParsedOptions) -> Result<(), (u8, String)> {
    options
        .reject_unknown(&[
            "--repo-root",
            "--franken-node-root",
            "--input",
            "--report",
            "--events",
            "--run-id",
            "--trace-id",
            "--test-id",
            "--scenario-id",
            "--seed",
            "--attempt",
        ])
        .map_err(usage)?;
    let (repo_root, node_root) = roots(&options);
    let input = PathBuf::from(options.required("--input").map_err(usage)?);
    let report_path = PathBuf::from(options.required("--report").map_err(usage)?);
    let events_path = PathBuf::from(options.required("--events").map_err(usage)?);
    let report = validate_contract_file(&repo_root, &node_root, &input);
    let events = validation_events(&report, &event_context(&options, "canonical-validation")?);
    write_create_new(&report_path, &canonical_json(&report).map_err(runtime)?).map_err(runtime)?;
    write_jsonl_create_new(&events_path, &events).map_err(runtime)?;
    print_json(&report)?;
    if report.passed() {
        Ok(())
    } else {
        Err((
            3,
            format!(
                "Intl surface contract validation failed with {} finding(s)",
                report.findings.len()
            ),
        ))
    }
}

fn mutations(options: ParsedOptions) -> Result<(), (u8, String)> {
    options
        .reject_unknown(&[
            "--input",
            "--report",
            "--events",
            "--run-id",
            "--trace-id",
            "--test-id",
            "--scenario-id",
            "--seed",
            "--attempt",
        ])
        .map_err(usage)?;
    let input = PathBuf::from(options.required("--input").map_err(usage)?);
    let report_path = PathBuf::from(options.required("--report").map_err(usage)?);
    let events_path = PathBuf::from(options.required("--events").map_err(usage)?);
    let contract = load_contract(&input).map_err(runtime)?;
    let report = run_mutation_suite(&contract);
    let context = event_context(&options, "seeded-mutation-suite")?;
    let events: Vec<ContractEvent> = report
        .results
        .iter()
        .enumerate()
        .map(|(index, result)| ContractEvent {
            schema_version: EVENT_SCHEMA_VERSION.to_string(),
            run_id: context.run_id.clone(),
            trace_id: context.trace_id.clone(),
            test_id: context.test_id.clone(),
            scenario_id: result.mutation_id.clone(),
            seed: context.seed,
            attempt: context.attempt,
            platform: context.platform.clone(),
            target: context.target.clone(),
            profile: "contract-freeze".to_string(),
            phase: "mutation.terminal".to_string(),
            sequence: index as u64,
            terminal: true,
            decision: result.decision.clone(),
            reason_code: if result.decision == "killed" {
                result.expected_reason_code.clone()
            } else {
                ERROR_MUTATION_SURVIVED.to_string()
            },
            reason: if result.decision == "killed" {
                "seeded defect reached and was rejected by the production validator".to_string()
            } else {
                "seeded defect survived the validator".to_string()
            },
            surface_id: None,
            owner: Some(contract.owning_bead.clone()),
            locale: None,
            timezone: None,
            provider: None,
            data_version: None,
            descriptor: None,
            input: Some(result.mutation_id.clone()),
            result: Some(format!("{:?}", result.observed_reason_codes)),
            error: None,
            fallback: Some("fail-closed validator rejection".to_string()),
            duration_us: 0,
            resource_delta_bytes: 0,
            artifact_sha256: None,
        })
        .collect();
    write_create_new(&report_path, &canonical_json(&report).map_err(runtime)?).map_err(runtime)?;
    write_jsonl_create_new(&events_path, &events).map_err(runtime)?;
    print_json(&report)?;
    if report.decision == "pass" {
        Ok(())
    } else {
        Err((3, "one or more seeded Intl mutations survived".to_string()))
    }
}

fn probe(options: ParsedOptions) -> Result<(), (u8, String)> {
    options
        .reject_unknown(&[
            "--repo-root",
            "--franken-node-root",
            "--input",
            "--frankenctl",
            "--franken-node",
            "--output-dir",
            "--run-id",
            "--trace-id",
            "--test-id",
            "--scenario-id",
            "--seed",
            "--attempt",
        ])
        .map_err(usage)?;
    let (repo_root, node_root) = roots(&options);
    let input = PathBuf::from(options.required("--input").map_err(usage)?);
    let frankenctl = PathBuf::from(options.required("--frankenctl").map_err(usage)?);
    let franken_node = PathBuf::from(options.required("--franken-node").map_err(usage)?);
    let output_dir = PathBuf::from(options.required("--output-dir").map_err(usage)?);
    let contract = load_contract(&input).map_err(runtime)?;
    let report = run_probes(ProbeRunConfig {
        repo_root: &repo_root,
        franken_node_root: &node_root,
        contract_path: &input,
        contract: &contract,
        frankenctl: &frankenctl,
        franken_node: &franken_node,
        output_dir: &output_dir,
        context: event_context(&options, "production-probes")?,
    })
    .map_err(runtime)?;
    print_json(&report)?;
    if report.decision == "pass" {
        Ok(())
    } else {
        Err((
            4,
            format!(
                "Intl production probes failed: {}",
                report.first_failure.as_deref().unwrap_or("unknown")
            ),
        ))
    }
}

fn render(options: ParsedOptions) -> Result<(), (u8, String)> {
    options
        .reject_unknown(&["--input", "--output"])
        .map_err(usage)?;
    let input = PathBuf::from(options.required("--input").map_err(usage)?);
    let output = PathBuf::from(options.required("--output").map_err(usage)?);
    let contract = load_contract(&input).map_err(runtime)?;
    write_create_new(&output, render_markdown(&contract).as_bytes()).map_err(runtime)
}

fn seal(options: ParsedOptions) -> Result<(), (u8, String)> {
    options
        .reject_unknown(&[
            "--input",
            "--bundle",
            "--decision",
            "--reproduction-command",
        ])
        .map_err(usage)?;
    let input = PathBuf::from(options.required("--input").map_err(usage)?);
    let bundle = PathBuf::from(options.required("--bundle").map_err(usage)?);
    let decision = options.required("--decision").map_err(usage)?;
    if !matches!(decision.as_str(), "pass" | "fail") {
        return Err(usage("--decision must be pass or fail".to_string()));
    }
    let reproduction = options.required("--reproduction-command").map_err(usage)?;
    let contract = load_contract(&input).map_err(runtime)?;
    let manifest = seal_directory(&bundle, &contract, &reproduction, &decision).map_err(runtime)?;
    print_json(&manifest)
}

fn roots(options: &ParsedOptions) -> (PathBuf, PathBuf) {
    let repo_root = PathBuf::from(options.defaulted("--repo-root", "."));
    let node_root = options
        .optional("--franken-node-root")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root.join("../franken_node"));
    (repo_root, node_root)
}

fn event_context(
    options: &ParsedOptions,
    default_scenario: &str,
) -> Result<EventContext, (u8, String)> {
    let seed = options
        .defaulted("--seed", "0")
        .parse::<u64>()
        .map_err(|_| usage("--seed must be an unsigned integer".to_string()))?;
    let attempt = options
        .defaulted("--attempt", "1")
        .parse::<u32>()
        .map_err(|_| usage("--attempt must be a positive integer".to_string()))?;
    if attempt == 0 {
        return Err(usage("--attempt must be at least 1".to_string()));
    }
    Ok(EventContext {
        run_id: options.defaulted("--run-id", "bridge-26-intl-contract"),
        trace_id: options.defaulted("--trace-id", "bridge-26-intl-contract-trace"),
        test_id: options.defaulted("--test-id", "bridge-26.1"),
        scenario_id: options.defaulted("--scenario-id", default_scenario),
        seed,
        attempt,
        platform: env::consts::OS.to_string(),
        target: env::consts::ARCH.to_string(),
    })
}

fn load_contract(path: &Path) -> Result<IntlSurfaceContract, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    parse_contract(&bytes)
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), (u8, String)> {
    let bytes = canonical_json(value).map_err(runtime)?;
    let text = String::from_utf8(bytes)
        .map_err(|error| runtime(format!("{ERROR_JSON}: output is not UTF-8: {error}")))?;
    print!("{text}");
    Ok(())
}

fn usage(error: String) -> (u8, String) {
    (2, format!("{error}\n{USAGE}"))
}

fn runtime(error: String) -> (u8, String) {
    (2, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_rejects_duplicate_options() {
        let error = ParsedOptions::parse(vec![
            "--input".to_string(),
            "a".to_string(),
            "--input".to_string(),
            "b".to_string(),
        ])
        .unwrap_err();
        assert!(error.contains("duplicate"));
    }

    #[test]
    fn parser_rejects_positional_values() {
        let error = ParsedOptions::parse(vec!["input".to_string()]).unwrap_err();
        assert!(error.contains("expected an option"));
    }

    #[test]
    fn parser_rejects_missing_value() {
        let error = ParsedOptions::parse(vec!["--input".to_string()]).unwrap_err();
        assert!(error.contains("requires a value"));
    }

    #[test]
    fn reject_unknown_is_fail_closed() {
        let options = ParsedOptions::parse(vec!["--mystery".to_string(), "x".to_string()]).unwrap();
        assert!(options.reject_unknown(&["--input"]).is_err());
    }

    #[test]
    fn context_rejects_zero_attempt() {
        let options = ParsedOptions::parse(vec!["--attempt".to_string(), "0".to_string()]).unwrap();
        assert!(event_context(&options, "test").is_err());
    }

    #[test]
    fn usage_names_all_public_commands() {
        for command in [
            "generate",
            "validate",
            "mutations",
            "probe",
            "render",
            "seal",
        ] {
            assert!(USAGE.contains(command));
        }
        assert!(USAGE.contains("create-new"));
    }

    #[test]
    fn contract_identity_is_stable() {
        assert_eq!(
            frankenengine_engine::intl_surface_contract::CONTRACT_ID,
            "franken-engine-intl-surface-v1"
        );
    }
}
