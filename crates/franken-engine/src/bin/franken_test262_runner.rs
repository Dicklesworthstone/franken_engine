use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::Utc;
use frankenengine_engine::test262_release_gate::{
    Test262EvidenceCollector, Test262GateRunner, Test262HighWaterMark, Test262ObservedResult,
    Test262PinSet, Test262Profile, Test262RunnerConfig, Test262WaiverSet, next_high_water_mark,
};
use frankenengine_engine::{
    HybridRouter, JsEngine, QuickJsInspiredNativeEngine, V8InspiredNativeEngine,
};
use serde::{Deserialize, Serialize};

const LIVE_HARNESS_VERSION: &str = "franken-engine.test262-live-harness.v1";
const FE_T262_EXPECTED_VALUE_MISMATCH: &str = "FE-T262-1011";
const FE_T262_UNEXPECTED_PASS: &str = "FE-T262-1012";
const FE_T262_CASE_VECTOR_INVALID: &str = "FE-T262-1013";

#[derive(Debug, Clone)]
struct CliArgs {
    pins_path: PathBuf,
    profile_path: PathBuf,
    waivers_path: PathBuf,
    case_vectors_path: PathBuf,
    observed_results_path: Option<PathBuf>,
    allow_precomputed_observed: bool,
    single_test_id: Option<String>,
    output_root: PathBuf,
    high_water_mark_path: Option<PathBuf>,
    run_date: String,
    worker_count: usize,
    trace_prefix: String,
    policy_id: String,
    acknowledge_pass_regression: bool,
}

fn default_pins_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test262_conformance_pins.toml")
}

fn default_profile_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test262_es2020_profile.toml")
}

fn default_waivers_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test262_conformance_waivers.toml")
}

fn default_case_vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test262_case_vectors.jsonl")
}

fn default_observed_results_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/test262_observed_results.jsonl")
}

fn default_output_root() -> PathBuf {
    PathBuf::from("artifacts/test262_es2020_gate")
}

fn usage() -> &'static str {
    "usage: franken_test262_runner [--pins <path>] [--profile <path>] [--waivers <path>] [--case-vectors <path>] [--single-test-id <id>] [--observed-results <path> --allow-precomputed-observed] [--output-root <path>] [--high-water-mark <path>] [--run-date <YYYY-MM-DD>] [--worker-count <n>] [--trace-prefix <prefix>] [--policy-id <id>] [--acknowledge-pass-regression]"
}

fn parse_args() -> Result<CliArgs, String> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from<I>(raw_args: I) -> Result<CliArgs, String>
where
    I: IntoIterator<Item = String>,
{
    let mut pins_path = default_pins_path();
    let mut profile_path = default_profile_path();
    let mut waivers_path = default_waivers_path();
    let mut case_vectors_path = default_case_vectors_path();
    let mut observed_results_path = None;
    let mut allow_precomputed_observed = false;
    let mut single_test_id = None;
    let mut output_root = default_output_root();
    let mut high_water_mark_path = None;
    let mut run_date = Utc::now().format("%Y-%m-%d").to_string();
    let mut worker_count = 8usize;
    let mut trace_prefix = "trace-test262".to_string();
    let mut policy_id = "policy-test262-es2020".to_string();
    let mut acknowledge_pass_regression = false;

    let mut args = raw_args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--pins" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--pins requires a value".to_string())?;
                pins_path = PathBuf::from(value);
            }
            "--profile" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--profile requires a value".to_string())?;
                profile_path = PathBuf::from(value);
            }
            "--waivers" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--waivers requires a value".to_string())?;
                waivers_path = PathBuf::from(value);
            }
            "--case-vectors" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--case-vectors requires a value".to_string())?;
                case_vectors_path = PathBuf::from(value);
            }
            "--single-test-id" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--single-test-id requires a value".to_string())?;
                single_test_id = Some(value);
            }
            "--observed-results" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--observed-results requires a value".to_string())?;
                observed_results_path = Some(PathBuf::from(value));
            }
            "--allow-precomputed-observed" => {
                allow_precomputed_observed = true;
            }
            "--output-root" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--output-root requires a value".to_string())?;
                output_root = PathBuf::from(value);
            }
            "--high-water-mark" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--high-water-mark requires a value".to_string())?;
                high_water_mark_path = Some(PathBuf::from(value));
            }
            "--run-date" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--run-date requires a value".to_string())?;
                run_date = value;
            }
            "--worker-count" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--worker-count requires a value".to_string())?;
                worker_count = value
                    .parse::<usize>()
                    .map_err(|_| "--worker-count must be a positive integer".to_string())?;
            }
            "--trace-prefix" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--trace-prefix requires a value".to_string())?;
                trace_prefix = value;
            }
            "--policy-id" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--policy-id requires a value".to_string())?;
                policy_id = value;
            }
            "--acknowledge-pass-regression" => {
                acknowledge_pass_regression = true;
            }
            "--help" | "-h" => {
                return Err(usage().to_string());
            }
            other => {
                return Err(format!(
                    "unknown argument: {other}. {usage}",
                    usage = usage()
                ));
            }
        }
    }

    if !allow_precomputed_observed && observed_results_path.is_some() {
        return Err(
            "--observed-results requires --allow-precomputed-observed (live case-vectors are the default gate authority)"
                .to_string(),
        );
    }

    if allow_precomputed_observed && observed_results_path.is_none() {
        observed_results_path = Some(default_observed_results_path());
    }

    if let Some(test_id) = single_test_id.as_ref()
        && test_id.trim().is_empty()
    {
        return Err("--single-test-id must not be empty".to_string());
    }

    Ok(CliArgs {
        pins_path,
        profile_path,
        waivers_path,
        case_vectors_path,
        observed_results_path,
        allow_precomputed_observed,
        single_test_id,
        output_root,
        high_water_mark_path,
        run_date,
        worker_count,
        trace_prefix,
        policy_id,
        acknowledge_pass_regression,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum RuntimeLane {
    QuickJs,
    V8,
    #[default]
    Hybrid,
}

impl RuntimeLane {
    fn as_str(self) -> &'static str {
        match self {
            Self::QuickJs => "quickjs",
            Self::V8 => "v8",
            Self::Hybrid => "hybrid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Test262CaseVector {
    test_id: String,
    es2020_clause: String,
    source: String,
    expected_value: String,
    #[serde(default)]
    runtime_lane: RuntimeLane,
    #[serde(default)]
    deterministic_seed: u64,
}

#[derive(Debug, Clone, Serialize)]
struct Test262CaseExecutionArtifact {
    test_id: String,
    es2020_clause: String,
    runtime_lane: String,
    deterministic_seed: u64,
    harness_version: String,
    outcome: String,
    duration_us: u64,
    observed_value: Option<String>,
    error_class: Option<String>,
    error_code: Option<String>,
    error_detail: Option<String>,
    rerun_command: String,
}

fn parse_observed_results(content: &str) -> io::Result<Vec<Test262ObservedResult>> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "observed results are empty",
        ));
    }

    if trimmed.starts_with('[') {
        let observed: Vec<Test262ObservedResult> = serde_json::from_str(trimmed)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        if observed.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "observed results must include at least one test",
            ));
        }
        return Ok(observed);
    }

    let mut observed = Vec::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let result: Test262ObservedResult = serde_json::from_str(line).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("observed results line {line_no} parse error: {err}"),
            )
        })?;
        observed.push(result);
    }

    if observed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "observed results must include at least one test",
        ));
    }

    Ok(observed)
}

fn load_observed_results(path: &Path) -> io::Result<Vec<Test262ObservedResult>> {
    let bytes = fs::read_to_string(path)?;
    parse_observed_results(&bytes)
}

fn parse_case_vectors(content: &str) -> io::Result<Vec<Test262CaseVector>> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "case vectors are empty",
        ));
    }

    if trimmed.starts_with('[') {
        let vectors: Vec<Test262CaseVector> = serde_json::from_str(trimmed)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        validate_case_vectors(vectors)
    } else {
        let mut vectors = Vec::new();
        for (idx, raw_line) in content.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let vector: Test262CaseVector = serde_json::from_str(line).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("case vectors line {line_no} parse error: {err}"),
                )
            })?;
            vectors.push(vector);
        }
        validate_case_vectors(vectors)
    }
}

fn validate_case_vectors(vectors: Vec<Test262CaseVector>) -> io::Result<Vec<Test262CaseVector>> {
    if vectors.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "case vectors must include at least one test",
        ));
    }

    let mut seen = BTreeSet::new();
    for vector in &vectors {
        if vector.test_id.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{FE_T262_CASE_VECTOR_INVALID}: case vector missing test_id"),
            ));
        }
        if vector.es2020_clause.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{FE_T262_CASE_VECTOR_INVALID}: case vector `{}` missing es2020_clause",
                    vector.test_id
                ),
            ));
        }
        if vector.source.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{FE_T262_CASE_VECTOR_INVALID}: case vector `{}` missing source",
                    vector.test_id
                ),
            ));
        }
        if vector.expected_value.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{FE_T262_CASE_VECTOR_INVALID}: case vector `{}` missing expected_value",
                    vector.test_id
                ),
            ));
        }
        if !seen.insert(vector.test_id.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{FE_T262_CASE_VECTOR_INVALID}: duplicate case vector test_id `{}`",
                    vector.test_id
                ),
            ));
        }
    }
    Ok(vectors)
}

fn load_case_vectors(path: &Path) -> io::Result<Vec<Test262CaseVector>> {
    let bytes = fs::read_to_string(path)?;
    parse_case_vectors(&bytes)
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | ':'))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

fn rerun_command_for_case(args: &CliArgs, test_id: &str) -> String {
    format!(
        "cargo run -p frankenengine-engine --bin franken_test262_runner -- --pins {} --profile {} --waivers {} --case-vectors {} --single-test-id {} --output-root {} --run-date {} --worker-count {} --trace-prefix {} --policy-id {}",
        shell_quote(&args.pins_path.display().to_string()),
        shell_quote(&args.profile_path.display().to_string()),
        shell_quote(&args.waivers_path.display().to_string()),
        shell_quote(&args.case_vectors_path.display().to_string()),
        shell_quote(test_id),
        shell_quote(&args.output_root.display().to_string()),
        shell_quote(&args.run_date),
        args.worker_count,
        shell_quote(&args.trace_prefix),
        shell_quote(&args.policy_id),
    )
}

fn evaluate_case_vector(
    case: &Test262CaseVector,
) -> Result<String, Box<frankenengine_engine::EvalError>> {
    match case.runtime_lane {
        RuntimeLane::Hybrid => {
            let mut router = HybridRouter::default();
            router
                .eval(case.source.as_str())
                .map(|outcome| outcome.value)
                .map_err(Box::new)
        }
        RuntimeLane::QuickJs => {
            let mut engine = QuickJsInspiredNativeEngine;
            engine
                .eval(case.source.as_str())
                .map(|outcome| outcome.value)
                .map_err(Box::new)
        }
        RuntimeLane::V8 => {
            let mut engine = V8InspiredNativeEngine;
            engine
                .eval(case.source.as_str())
                .map(|outcome| outcome.value)
                .map_err(Box::new)
        }
    }
}

fn execute_case_vector(
    case: &Test262CaseVector,
    rerun_command: String,
) -> (Test262ObservedResult, Test262CaseExecutionArtifact) {
    let start = Instant::now();
    let eval_result = evaluate_case_vector(case);
    let elapsed_us = start.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;

    let (outcome, observed_value, error_class, error_code, error_detail) = match eval_result {
        Ok(value) => {
            let trimmed_observed = value.trim().to_string();
            let expected = case.expected_value.trim();
            if trimmed_observed == expected {
                (
                    frankenengine_engine::test262_release_gate::Test262ObservedOutcome::Pass,
                    Some(trimmed_observed),
                    None,
                    None,
                    None,
                )
            } else {
                (
                    frankenengine_engine::test262_release_gate::Test262ObservedOutcome::Fail,
                    Some(trimmed_observed.clone()),
                    Some("assertion_mismatch".to_string()),
                    Some(FE_T262_EXPECTED_VALUE_MISMATCH.to_string()),
                    Some(format!(
                        "{FE_T262_UNEXPECTED_PASS}: expected `{expected}`, observed `{trimmed_observed}`",
                    )),
                )
            }
        }
        Err(err) => (
            frankenengine_engine::test262_release_gate::Test262ObservedOutcome::Fail,
            None,
            Some(err.class().stable_label().to_string()),
            Some(err.stable_namespace().to_string()),
            Some(err.diagnostic_summary()),
        ),
    };

    let observed = Test262ObservedResult {
        test_id: case.test_id.clone(),
        es2020_clause: case.es2020_clause.clone(),
        outcome,
        duration_us: elapsed_us,
        error_code: error_code.clone(),
        error_detail: error_detail.clone(),
    };

    let artifact = Test262CaseExecutionArtifact {
        test_id: case.test_id.clone(),
        es2020_clause: case.es2020_clause.clone(),
        runtime_lane: case.runtime_lane.as_str().to_string(),
        deterministic_seed: case.deterministic_seed,
        harness_version: LIVE_HARNESS_VERSION.to_string(),
        outcome: match observed.outcome {
            frankenengine_engine::test262_release_gate::Test262ObservedOutcome::Pass => "pass",
            frankenengine_engine::test262_release_gate::Test262ObservedOutcome::Fail => "fail",
            frankenengine_engine::test262_release_gate::Test262ObservedOutcome::Timeout => {
                "timeout"
            }
            frankenengine_engine::test262_release_gate::Test262ObservedOutcome::Crash => "crash",
        }
        .to_string(),
        duration_us: elapsed_us,
        observed_value,
        error_class,
        error_code,
        error_detail,
        rerun_command,
    };

    (observed, artifact)
}

fn execute_live_case_vectors(
    args: &CliArgs,
) -> io::Result<(
    Vec<Test262ObservedResult>,
    Vec<Test262CaseExecutionArtifact>,
)> {
    let all_vectors = load_case_vectors(&args.case_vectors_path)?;
    let selected: Vec<Test262CaseVector> = match args.single_test_id.as_ref() {
        Some(single) => all_vectors
            .into_iter()
            .filter(|vector| vector.test_id == *single)
            .collect(),
        None => all_vectors,
    };

    if selected.is_empty() {
        let selection = args
            .single_test_id
            .as_deref()
            .unwrap_or("<none>")
            .to_string();
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("no live test262 case vectors selected (single_test_id={selection})"),
        ));
    }

    let mut observed_results = Vec::with_capacity(selected.len());
    let mut case_artifacts = Vec::with_capacity(selected.len());
    for case in &selected {
        let rerun_command = rerun_command_for_case(args, case.test_id.as_str());
        let (observed, artifact) = execute_case_vector(case, rerun_command);
        observed_results.push(observed);
        case_artifacts.push(artifact);
    }

    Ok((observed_results, case_artifacts))
}

fn write_case_execution_artifacts(
    run_manifest_path: &Path,
    artifacts: &[Test262CaseExecutionArtifact],
) -> io::Result<Option<PathBuf>> {
    if artifacts.is_empty() {
        return Ok(None);
    }
    let run_root = run_manifest_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "run_manifest_path has no parent directory",
        )
    })?;
    let case_execution_path = run_root.join("test262_case_execution.jsonl");
    let mut lines = String::new();
    for artifact in artifacts {
        let line = serde_json::to_string(artifact)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        lines.push_str(&line);
        lines.push('\n');
    }
    fs::write(&case_execution_path, lines.as_bytes())?;
    Ok(Some(case_execution_path))
}

fn main() -> Result<(), Box<dyn Error>> {
    let args =
        parse_args().map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;

    let pins = Test262PinSet::load_toml(&args.pins_path)?;
    let profile = Test262Profile::load_toml(&args.profile_path)?;
    let waivers = Test262WaiverSet::load_toml(&args.waivers_path)?;
    let (observed, execution_mode, case_execution_artifacts) = if args.allow_precomputed_observed {
        let observed_path = args
            .observed_results_path
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing observed path"))?;
        (
            load_observed_results(observed_path)?,
            "precomputed_observed_results",
            Vec::new(),
        )
    } else {
        let (observed, case_artifacts) = execute_live_case_vectors(&args)?;
        (observed, "live_case_vectors", case_artifacts)
    };

    let previous_hwm = match args.high_water_mark_path.as_ref() {
        Some(path) => Test262HighWaterMark::load_json(path)?,
        None => None,
    };

    let runner = Test262GateRunner {
        config: Test262RunnerConfig {
            trace_prefix: args.trace_prefix,
            policy_id: args.policy_id,
            run_date: args.run_date,
            worker_count: args.worker_count,
            locale: "C".to_string(),
            timezone: "UTC".to_string(),
            gc_schedule: "deterministic".to_string(),
            acknowledge_pass_regression: args.acknowledge_pass_regression,
        },
    };

    let run = runner.run(&pins, &profile, &waivers, &observed, previous_hwm.as_ref())?;

    let next_hwm = next_high_water_mark(&run, previous_hwm.as_ref());
    let collector = Test262EvidenceCollector::new(&args.output_root)?;
    let artifacts = collector.collect(&run, &next_hwm)?;
    let case_execution_path =
        write_case_execution_artifacts(&artifacts.run_manifest_path, &case_execution_artifacts)?;

    if let Some(path) = args.high_water_mark_path.as_ref() {
        next_hwm.write_json(path)?;
        println!("test262 canonical_high_water_mark={}", path.display());
    }

    println!("test262 run_id={}", run.run_id);
    println!("test262 execution_mode={execution_mode}");
    println!(
        "test262 total_profile_tests={}",
        run.summary.total_profile_tests
    );
    println!("test262 passed={}", run.summary.passed);
    println!("test262 failed={}", run.summary.failed);
    println!("test262 waived={}", run.summary.waived);
    println!("test262 timed_out={}", run.summary.timed_out);
    println!("test262 crashed={}", run.summary.crashed);
    println!("test262 blocked_failures={}", run.summary.blocked_failures);
    println!("test262 blocked={}", run.blocked);
    println!("test262 profile_hash={}", run.summary.profile_hash);
    println!("test262 waiver_hash={}", run.summary.waiver_hash);
    println!("test262 pin_hash={}", run.summary.pin_hash);
    println!("test262 env_fingerprint={}", run.summary.env_fingerprint);
    println!(
        "test262 run_manifest={}",
        artifacts.run_manifest_path.display()
    );
    println!("test262 evidence={}", artifacts.evidence_path.display());
    println!(
        "test262 high_water_mark={}",
        artifacts.high_water_mark_path.display()
    );
    if let Some(path) = case_execution_path.as_ref() {
        println!("test262 case_execution={}", path.display());
    }

    if run.blocked {
        return Err(io::Error::other(format!(
            "FE-T262-1005: test262 release gate blocked with {} blocking outcome(s)",
            run.summary.blocked_failures
        ))
        .into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use frankenengine_engine::test262_release_gate::Test262ObservedOutcome;

    fn sample_line(test_id: &str, outcome: Test262ObservedOutcome) -> String {
        serde_json::json!({
            "test_id": test_id,
            "es2020_clause": "13.3.1",
            "outcome": outcome,
            "duration_us": 42,
            "error_code": null,
            "error_detail": null,
        })
        .to_string()
    }

    fn sample_case_line(test_id: &str, expected_value: &str) -> String {
        serde_json::json!({
            "test_id": test_id,
            "es2020_clause": "13.3.1",
            "source": "1 + 1;",
            "expected_value": expected_value,
            "runtime_lane": "hybrid",
            "deterministic_seed": 7
        })
        .to_string()
    }

    fn parse_cli_args(args: &[&str]) -> Result<CliArgs, String> {
        parse_args_from(args.iter().map(|arg| (*arg).to_string()))
    }

    #[test]
    fn parse_jsonl_observed_results() {
        let content = format!(
            "# test262 sample\n\n{}\n{}\n",
            sample_line(
                "language/expressions/optional-chaining/pass.js",
                Test262ObservedOutcome::Pass
            ),
            sample_line(
                "built-ins/Array/prototype/map/basic.js",
                Test262ObservedOutcome::Pass
            )
        );

        let observed = parse_observed_results(&content).expect("parse jsonl");
        assert_eq!(observed.len(), 2);
        assert_eq!(
            observed[0].test_id,
            "language/expressions/optional-chaining/pass.js"
        );
    }

    #[test]
    fn parse_json_array_observed_results() {
        let content = format!(
            "[{},{}]",
            sample_line("language/a.js", Test262ObservedOutcome::Pass),
            sample_line("language/b.js", Test262ObservedOutcome::Fail)
        );

        let observed = parse_observed_results(&content).expect("parse array");
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[1].test_id, "language/b.js");
    }

    #[test]
    fn parse_observed_results_rejects_empty_input() {
        let err = parse_observed_results("\n  \n").expect_err("empty must fail");
        assert!(err.to_string().contains("observed results are empty"));
    }

    #[test]
    fn parse_observed_results_reports_line_number() {
        let content = format!(
            "{}\nnot-json\n",
            sample_line("language/a.js", Test262ObservedOutcome::Pass)
        );
        let err = parse_observed_results(&content).expect_err("invalid line must fail");
        assert!(err.to_string().contains("line 2"));
    }

    #[test]
    fn parse_jsonl_case_vectors() {
        let content = format!(
            "# live vectors\n\n{}\n{}\n",
            sample_case_line("language/a.js", "2"),
            sample_case_line("built-ins/b.js", "2")
        );
        let vectors = parse_case_vectors(&content).expect("parse case vectors");
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0].test_id, "language/a.js");
        assert_eq!(vectors[0].runtime_lane, RuntimeLane::Hybrid);
    }

    #[test]
    fn parse_case_vectors_rejects_empty_input() {
        let err = parse_case_vectors("\n \n").expect_err("empty must fail");
        assert!(err.to_string().contains("case vectors are empty"));
    }

    #[test]
    fn parse_case_vectors_reports_line_number() {
        let content = format!("{}\nnot-json\n", sample_case_line("language/a.js", "2"));
        let err = parse_case_vectors(&content).expect_err("invalid line must fail");
        assert!(err.to_string().contains("line 2"));
    }

    #[test]
    fn parse_case_vectors_rejects_duplicate_test_ids() {
        let content = format!(
            "{}\n{}\n",
            sample_case_line("language/a.js", "2"),
            sample_case_line("language/a.js", "2")
        );
        let err = parse_case_vectors(&content).expect_err("duplicate test ids must fail");
        assert!(err.to_string().contains("duplicate case vector test_id"));
    }

    #[test]
    fn parse_case_vectors_rejects_missing_expected_value() {
        let content = serde_json::json!({
            "test_id": "language/a.js",
            "es2020_clause": "13.3.1",
            "source": "1 + 1;",
            "expected_value": "   ",
            "runtime_lane": "hybrid",
            "deterministic_seed": 7
        })
        .to_string();
        let err = parse_case_vectors(&content).expect_err("missing expected value must fail");
        assert!(err.to_string().contains("missing expected_value"));
    }

    #[test]
    fn parse_args_rejects_observed_without_allow_flag() {
        let err = parse_cli_args(&["--observed-results", "/tmp/observed.jsonl"])
            .expect_err("observed path without allow flag must fail");
        assert!(err.contains("--observed-results requires --allow-precomputed-observed"));
    }

    #[test]
    fn parse_args_defaults_observed_results_path_when_allowed() {
        let args = parse_cli_args(&["--allow-precomputed-observed"]).expect("args parse");
        assert!(args.allow_precomputed_observed);
        assert_eq!(
            args.observed_results_path,
            Some(default_observed_results_path())
        );
    }

    #[test]
    fn parse_args_rejects_empty_single_test_id() {
        let err = parse_cli_args(&["--single-test-id", "   "])
            .expect_err("empty single-test-id must fail");
        assert!(err.contains("--single-test-id must not be empty"));
    }

    #[test]
    fn rerun_command_quotes_single_test_id_with_apostrophe() {
        let args = parse_cli_args(&[]).expect("default args");
        let cmd = rerun_command_for_case(&args, "language/foo'bar.js");
        assert!(cmd.contains("--single-test-id 'language/foo'\"'\"'bar.js'"));
    }

    #[test]
    fn execute_case_vector_passes_when_expected_value_matches() {
        let case = Test262CaseVector {
            test_id: "language/pass.js".to_string(),
            es2020_clause: "13.1".to_string(),
            source: "1 + 1;".to_string(),
            expected_value: "2".to_string(),
            runtime_lane: RuntimeLane::Hybrid,
            deterministic_seed: 7,
        };
        let (observed, artifact) = execute_case_vector(&case, "rerun-cmd".to_string());
        assert_eq!(observed.outcome, Test262ObservedOutcome::Pass);
        assert_eq!(artifact.outcome, "pass");
        assert_eq!(artifact.rerun_command, "rerun-cmd");
    }

    #[test]
    fn execute_case_vector_fails_on_expected_value_mismatch() {
        let case = Test262CaseVector {
            test_id: "language/fail.js".to_string(),
            es2020_clause: "13.1".to_string(),
            source: "1 + 1;".to_string(),
            expected_value: "5".to_string(),
            runtime_lane: RuntimeLane::Hybrid,
            deterministic_seed: 7,
        };
        let (observed, artifact) = execute_case_vector(&case, "rerun-cmd".to_string());
        assert_eq!(observed.outcome, Test262ObservedOutcome::Fail);
        assert_eq!(
            observed.error_code.as_deref(),
            Some(FE_T262_EXPECTED_VALUE_MISMATCH)
        );
        assert_eq!(artifact.outcome, "fail");
    }
}
