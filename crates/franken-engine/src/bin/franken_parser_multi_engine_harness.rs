#![forbid(unsafe_code)]

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use frankenengine_engine::parser_multi_engine_harness::{
    DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH, HarnessEngineSpec, MultiEngineHarnessConfig,
    build_drift_governance_action_report, has_critical_drift, run_multi_engine_harness,
};
use serde::Deserialize;

#[derive(Debug)]
struct CliArgs {
    config: MultiEngineHarnessConfig,
    out_path: Option<PathBuf>,
    fail_on_divergence: bool,
    fail_on_critical_drift: bool,
    governance_actions_out: Option<PathBuf>,
    print_help: bool,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum EngineSpecFile {
    Array(Vec<HarnessEngineSpec>),
    Wrapped { engines: Vec<HarnessEngineSpec> },
}

fn main() {
    match run() {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<i32, Box<dyn Error>> {
    let args = parse_args(std::env::args().skip(1))?;
    if args.print_help {
        return Ok(0);
    }

    let report = run_multi_engine_harness(&args.config)?;
    let json = serde_json::to_string_pretty(&report)?;

    if let Some(out_path) = &args.out_path {
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out_path, json.as_bytes())?;
    }

    if let Some(out_path) = &args.governance_actions_out {
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let governance = build_drift_governance_action_report(&report);
        fs::write(out_path, serde_json::to_vec_pretty(&governance)?)?;
    }

    println!("{json}");

    if args.fail_on_critical_drift && has_critical_drift(&report) {
        return Ok(3);
    }
    if args.fail_on_divergence
        && (report.summary.divergent_fixtures > 0
            || report.summary.fixtures_with_nondeterminism > 0)
    {
        Ok(2)
    } else {
        Ok(0)
    }
}

fn parse_args<I>(args: I) -> Result<CliArgs, Box<dyn Error>>
where
    I: IntoIterator<Item = String>,
{
    let mut seed = 1_u64;
    let mut fixture_catalog = PathBuf::from(DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH);
    let mut fixture_limit = Some(8_usize);
    let mut fixture_id_filter = None::<String>;
    let mut trace_id = None::<String>;
    let mut decision_id = None::<String>;
    let mut policy_id = None::<String>;
    let mut locale = None::<String>;
    let mut timezone = None::<String>;
    let mut engine_specs = None::<Vec<HarnessEngineSpec>>;
    let mut out_path = None::<PathBuf>;
    let mut fail_on_divergence = false;
    let mut fail_on_critical_drift = false;
    let mut governance_actions_out = None::<PathBuf>;
    let mut print_help_flag = false;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--fixture-catalog" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --fixture-catalog".to_string())?;
                fixture_catalog = PathBuf::from(value);
            }
            "--fixture-limit" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --fixture-limit".to_string())?;
                fixture_limit = parse_fixture_limit(value.as_str())?;
            }
            "--fixture-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --fixture-id".to_string())?;
                fixture_id_filter = Some(value);
            }
            "--seed" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --seed".to_string())?;
                seed = value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid seed `{value}`: {error}"))?;
            }
            "--trace-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --trace-id".to_string())?;
                trace_id = Some(value);
            }
            "--decision-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --decision-id".to_string())?;
                decision_id = Some(value);
            }
            "--policy-id" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --policy-id".to_string())?;
                policy_id = Some(value);
            }
            "--locale" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --locale".to_string())?;
                locale = Some(value);
            }
            "--timezone" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --timezone".to_string())?;
                timezone = Some(value);
            }
            "--engine-specs" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --engine-specs".to_string())?;
                engine_specs = Some(load_engine_specs(Path::new(value.as_str()))?);
            }
            "--fail-on-divergence" => {
                fail_on_divergence = true;
            }
            "--fail-on-critical-drift" => {
                fail_on_critical_drift = true;
            }
            "--governance-actions-out" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --governance-actions-out".to_string())?;
                governance_actions_out = Some(PathBuf::from(value));
            }
            "--out" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value for --out".to_string())?;
                out_path = Some(PathBuf::from(value));
            }
            "--help" | "-h" => {
                print_help();
                print_help_flag = true;
            }
            other => {
                return Err(format!("unknown argument `{other}`").into());
            }
        }
    }

    let mut config = MultiEngineHarnessConfig::with_defaults(seed);
    config.fixture_catalog_path = fixture_catalog;
    config.fixture_limit = fixture_limit;
    config.fixture_id_filter = fixture_id_filter;
    if let Some(value) = trace_id {
        config.trace_id = value;
    }
    if let Some(value) = decision_id {
        config.decision_id = value;
    }
    if let Some(value) = policy_id {
        config.policy_id = value;
    }
    if let Some(value) = locale {
        config.locale = value;
    }
    if let Some(value) = timezone {
        config.timezone = value;
    }
    if let Some(specs) = engine_specs {
        config.engines = specs;
    }

    Ok(CliArgs {
        config,
        out_path,
        fail_on_divergence,
        fail_on_critical_drift,
        governance_actions_out,
        print_help: print_help_flag,
    })
}

fn parse_fixture_limit(value: &str) -> Result<Option<usize>, Box<dyn Error>> {
    if value.eq_ignore_ascii_case("none") {
        Ok(None)
    } else {
        value
            .parse::<usize>()
            .map(Some)
            .map_err(|error| format!("invalid fixture limit `{value}`: {error}").into())
    }
}

fn load_engine_specs(path: &Path) -> Result<Vec<HarnessEngineSpec>, Box<dyn Error>> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "failed to read engine spec file `{}`: {error}",
            path.display()
        )
    })?;
    let parsed = serde_json::from_slice::<EngineSpecFile>(&bytes).map_err(|error| {
        format!(
            "failed to parse engine spec file `{}`: {error}",
            path.display()
        )
    })?;
    let specs = match parsed {
        EngineSpecFile::Array(specs) => specs,
        EngineSpecFile::Wrapped { engines } => engines,
    };
    if specs.is_empty() {
        return Err(format!("engine spec file `{}` must not be empty", path.display()).into());
    }
    Ok(specs)
}

fn print_help() {
    println!("franken_parser_multi_engine_harness");
    println!("  --fixture-catalog <path>");
    println!("  --fixture-limit <usize|none>");
    println!("  --fixture-id <fixture-id>");
    println!("  --seed <u64>");
    println!("  --trace-id <id>");
    println!("  --decision-id <id>");
    println!("  --policy-id <id>");
    println!("  --locale <locale>");
    println!("  --timezone <timezone>");
    println!("  --engine-specs <path>");
    println!("  --fail-on-divergence");
    println!("  --fail-on-critical-drift");
    println!("  --governance-actions-out <path>");
    println!("  --out <path>");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_accepts_critical_drift_and_governance_output_flags() {
        let args = vec![
            "--seed".to_string(),
            "11".to_string(),
            "--fail-on-critical-drift".to_string(),
            "--governance-actions-out".to_string(),
            "artifacts/parser_multi_engine_harness/actions.json".to_string(),
        ];

        let parsed = parse_args(args).expect("args should parse");
        assert_eq!(parsed.config.seed, 11);
        assert!(parsed.fail_on_critical_drift);
        assert_eq!(
            parsed.governance_actions_out,
            Some(PathBuf::from(
                "artifacts/parser_multi_engine_harness/actions.json"
            ))
        );
    }

    #[test]
    fn parse_args_requires_governance_output_value() {
        let err = parse_args(vec!["--governance-actions-out".to_string()])
            .expect_err("missing path should fail");
        assert!(
            err.to_string()
                .contains("missing value for --governance-actions-out"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_args_handles_empty_args() {
        let parsed = parse_args(vec![]).expect("empty args should parse with defaults");
        assert!(!parsed.print_help);
        assert!(!parsed.fail_on_divergence);
        assert!(!parsed.fail_on_critical_drift);
        assert!(parsed.out_path.is_none());
        assert!(parsed.governance_actions_out.is_none());
    }

    #[test]
    fn parse_args_handles_help_flags() {
        assert!(parse_args(vec!["--help".to_string()]).unwrap().print_help);
        assert!(parse_args(vec!["-h".to_string()]).unwrap().print_help);
    }

    #[test]
    fn parse_args_handles_seed_argument() {
        let parsed = parse_args(vec!["--seed".to_string(), "42".to_string()])
            .expect("seed arg should parse");
        assert_eq!(parsed.config.seed, 42);
    }

    #[test]
    fn parse_args_handles_invalid_seed() {
        let err = parse_args(vec!["--seed".to_string(), "invalid".to_string()])
            .expect_err("invalid seed should fail");
        assert!(err.to_string().contains("invalid seed"));
    }

    #[test]
    fn parse_args_handles_missing_seed_value() {
        let err =
            parse_args(vec!["--seed".to_string()]).expect_err("missing seed value should fail");
        assert!(err.to_string().contains("missing value for --seed"));
    }

    #[test]
    fn parse_args_handles_out_path() {
        let parsed = parse_args(vec!["--out".to_string(), "output.json".to_string()])
            .expect("out path should parse");
        assert_eq!(parsed.out_path, Some(PathBuf::from("output.json")));
    }

    #[test]
    fn parse_args_handles_missing_out_value() {
        let err = parse_args(vec!["--out".to_string()]).expect_err("missing out value should fail");
        assert!(err.to_string().contains("missing value for --out"));
    }

    #[test]
    fn parse_args_handles_engine_specs() {
        use std::env;
        let engines_path = env::temp_dir().join("parse_args_engine_specs_test.json");
        fs::write(
            &engines_path,
            r#"[{"engine_id":"test_engine","display_name":"Test Engine","kind":"external_command","version_pin":"test@1","command":"node","args":["--check"]}]"#,
        )
        .expect("should write engine specs");

        let parsed = parse_args(vec![
            "--engine-specs".to_string(),
            engines_path.display().to_string(),
        ])
        .expect("engines spec should parse");
        assert_eq!(parsed.config.engines[0].engine_id, "test_engine");

        let _ = fs::remove_file(&engines_path);
    }

    #[test]
    fn parse_args_handles_fixture_limit() {
        let parsed = parse_args(vec!["--fixture-limit".to_string(), "100".to_string()])
            .expect("fixture limit should parse");
        assert_eq!(parsed.config.fixture_limit, Some(100));
    }

    #[test]
    fn parse_args_handles_invalid_fixture_limit() {
        let err = parse_args(vec!["--fixture-limit".to_string(), "invalid".to_string()])
            .expect_err("invalid fixture limit should fail");
        assert!(err.to_string().contains("invalid fixture limit"));
    }

    #[test]
    fn parse_args_handles_fixture_limit_none() {
        let parsed = parse_args(vec!["--fixture-limit".to_string(), "none".to_string()])
            .expect("fixture limit none should parse");
        assert_eq!(parsed.config.fixture_limit, None);
    }

    #[test]
    fn parse_args_handles_fail_on_divergence_flag() {
        let parsed = parse_args(vec!["--fail-on-divergence".to_string()])
            .expect("fail on divergence flag should parse");
        assert!(parsed.fail_on_divergence);
    }

    #[test]
    fn parse_args_handles_fail_on_critical_drift_flag() {
        let parsed = parse_args(vec!["--fail-on-critical-drift".to_string()])
            .expect("fail on critical drift flag should parse");
        assert!(parsed.fail_on_critical_drift);
    }

    #[test]
    fn parse_args_handles_multiple_flags_combined() {
        let parsed = parse_args(vec![
            "--seed".to_string(),
            "123".to_string(),
            "--out".to_string(),
            "report.json".to_string(),
            "--fixture-catalog".to_string(),
            "fixtures.json".to_string(),
            "--fixture-limit".to_string(),
            "50".to_string(),
            "--fail-on-divergence".to_string(),
            "--fail-on-critical-drift".to_string(),
            "--governance-actions-out".to_string(),
            "actions.json".to_string(),
        ])
        .expect("multiple flags should parse");

        assert_eq!(parsed.config.seed, 123);
        assert_eq!(parsed.out_path, Some(PathBuf::from("report.json")));
        assert_eq!(
            parsed.config.fixture_catalog_path,
            PathBuf::from("fixtures.json")
        );
        assert_eq!(parsed.config.fixture_limit, Some(50));
        assert!(parsed.fail_on_divergence);
        assert!(parsed.fail_on_critical_drift);
        assert_eq!(
            parsed.governance_actions_out,
            Some(PathBuf::from("actions.json"))
        );
    }

    #[test]
    fn parse_args_handles_unknown_argument() {
        let err =
            parse_args(vec!["--unknown".to_string()]).expect_err("unknown argument should fail");
        assert!(err.to_string().contains("unknown argument"));
    }

    #[test]
    fn parse_fixture_limit_handles_valid_numbers() {
        assert_eq!(parse_fixture_limit("0").unwrap(), Some(0));
        assert_eq!(parse_fixture_limit("1").unwrap(), Some(1));
        assert_eq!(parse_fixture_limit("1000").unwrap(), Some(1000));
    }

    #[test]
    fn parse_fixture_limit_handles_none_keyword() {
        assert_eq!(parse_fixture_limit("none").unwrap(), None);
        assert_eq!(parse_fixture_limit("None").unwrap(), None);
        assert_eq!(parse_fixture_limit("NONE").unwrap(), None);
    }

    #[test]
    fn parse_fixture_limit_handles_invalid_input() {
        assert!(parse_fixture_limit("invalid").is_err());
        assert!(parse_fixture_limit("").is_err());
        assert!(parse_fixture_limit("-1").is_err());
        assert!(parse_fixture_limit("1.5").is_err());
    }

    #[test]
    fn load_engine_specs_handles_missing_file() {
        use std::env;
        let temp_dir = env::temp_dir();
        let nonexistent_path = temp_dir.join("nonexistent_engines.json");

        let result = load_engine_specs(&nonexistent_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No such file"));
    }

    #[test]
    fn load_engine_specs_handles_array_format() {
        use std::env;
        let temp_dir = env::temp_dir();
        let engines_path = temp_dir.join("engines_array_test.json");

        let engines_json = r#"[
            {
                "engine_id": "test_engine",
                "display_name": "Test Engine",
                "kind": "external_command",
                "version_pin": "test@1",
                "command": "node",
                "args": ["--check"]
            }
        ]"#;

        fs::write(&engines_path, engines_json).expect("should write test file");

        let result = load_engine_specs(&engines_path);
        assert!(result.is_ok());
        let engines = result.unwrap();
        assert_eq!(engines.len(), 1);
        assert_eq!(engines[0].engine_id, "test_engine");

        let _ = fs::remove_file(&engines_path);
    }

    #[test]
    fn load_engine_specs_handles_wrapped_format() {
        use std::env;
        let temp_dir = env::temp_dir();
        let engines_path = temp_dir.join("engines_wrapped_test.json");

        let engines_json = r#"{
            "engines": [
                {
                    "engine_id": "wrapped_engine",
                    "display_name": "Wrapped Engine",
                    "kind": "external_command",
                    "version_pin": "wrapped@1",
                    "command": "node",
                    "args": ["--check"]
                },
                {
                    "engine_id": "second_engine",
                    "display_name": "Second Engine",
                    "kind": "external_command",
                    "version_pin": "second@1",
                    "command": "node",
                    "args": ["--check"]
                }
            ]
        }"#;

        fs::write(&engines_path, engines_json).expect("should write test file");

        let result = load_engine_specs(&engines_path);
        assert!(result.is_ok());
        let engines = result.unwrap();
        assert_eq!(engines.len(), 2);
        assert_eq!(engines[0].engine_id, "wrapped_engine");
        assert_eq!(engines[1].engine_id, "second_engine");

        let _ = fs::remove_file(&engines_path);
    }

    #[test]
    fn load_engine_specs_handles_invalid_json() {
        use std::env;
        let temp_dir = env::temp_dir();
        let engines_path = temp_dir.join("engines_invalid_test.json");

        let invalid_json = r#"{ invalid json content"#;

        fs::write(&engines_path, invalid_json).expect("should write test file");

        let result = load_engine_specs(&engines_path);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("failed to parse engine spec file")
        );

        let _ = fs::remove_file(&engines_path);
    }

    #[test]
    fn load_engine_specs_handles_empty_file() {
        use std::env;
        let temp_dir = env::temp_dir();
        let engines_path = temp_dir.join("engines_empty_test.json");

        fs::write(&engines_path, "").expect("should write empty test file");

        let result = load_engine_specs(&engines_path);
        assert!(result.is_err());

        let _ = fs::remove_file(&engines_path);
    }

    #[test]
    fn cli_args_debug_formatting() {
        let mut config = MultiEngineHarnessConfig::with_defaults(42);
        config.fixture_limit = Some(100);

        let args = CliArgs {
            config,
            out_path: Some(PathBuf::from("output.json")),
            fail_on_divergence: true,
            fail_on_critical_drift: false,
            governance_actions_out: None,
            print_help: false,
        };

        let debug_str = format!("{:?}", args);
        assert!(debug_str.contains("CliArgs"));
        assert!(debug_str.contains("seed: 42"));
        assert!(debug_str.contains("fail_on_divergence: true"));
    }

    #[test]
    fn engine_spec_file_deserialization() {
        // Test Array variant
        let array_json = r#"[{"engine_id":"test","display_name":"Test","kind":"external_command","version_pin":"test@1","command":"node","args":["--check"]}]"#;
        let array_result: EngineSpecFile =
            serde_json::from_str(array_json).expect("array format should deserialize");
        match array_result {
            EngineSpecFile::Array(engines) => {
                assert_eq!(engines.len(), 1);
                assert_eq!(engines[0].engine_id, "test");
            }
            _ => panic!("Expected Array variant"),
        }

        // Test Wrapped variant
        let wrapped_json = r#"{"engines":[{"engine_id":"test","display_name":"Test","kind":"external_command","version_pin":"test@1","command":"node","args":["--check"]}]}"#;
        let wrapped_result: EngineSpecFile =
            serde_json::from_str(wrapped_json).expect("wrapped format should deserialize");
        match wrapped_result {
            EngineSpecFile::Wrapped { engines } => {
                assert_eq!(engines.len(), 1);
                assert_eq!(engines[0].engine_id, "test");
            }
            _ => panic!("Expected Wrapped variant"),
        }
    }

    #[test]
    fn print_help_displays_usage_information() {
        // This test captures stdout to verify help content is printed
        // In a real scenario you might use a more sophisticated approach
        // For now we just verify the function doesn't panic
        print_help();
    }

    #[test]
    fn default_config_values() {
        let mut config = MultiEngineHarnessConfig::with_defaults(0);
        config.fixture_limit = None;

        assert_eq!(config.seed, 0);
        assert!(config.fixture_limit.is_none());
        assert_eq!(
            config.fixture_catalog_path,
            PathBuf::from(DEFAULT_MULTI_ENGINE_FIXTURE_CATALOG_PATH)
        );
    }

    #[test]
    fn path_handling_edge_cases() {
        // Test with relative paths
        let parsed = parse_args(vec![
            "--out".to_string(),
            "relative/path.json".to_string(),
            "--fixture-catalog".to_string(),
            "./fixtures.json".to_string(),
        ])
        .expect("relative paths should parse");

        assert_eq!(parsed.out_path, Some(PathBuf::from("relative/path.json")));
        assert_eq!(
            parsed.config.fixture_catalog_path,
            PathBuf::from("./fixtures.json")
        );

        // Test with absolute paths
        let parsed = parse_args(vec!["--out".to_string(), "/absolute/path.json".to_string()])
            .expect("absolute paths should parse");

        assert_eq!(parsed.out_path, Some(PathBuf::from("/absolute/path.json")));
    }

    #[test]
    fn argument_order_independence() {
        let args1 = vec![
            "--seed".to_string(),
            "123".to_string(),
            "--out".to_string(),
            "output.json".to_string(),
        ];

        let args2 = vec![
            "--out".to_string(),
            "output.json".to_string(),
            "--seed".to_string(),
            "123".to_string(),
        ];

        let parsed1 = parse_args(args1).expect("first order should parse");
        let parsed2 = parse_args(args2).expect("second order should parse");

        assert_eq!(parsed1.config.seed, parsed2.config.seed);
        assert_eq!(parsed1.out_path, parsed2.out_path);
    }

    #[test]
    fn duplicate_arguments_use_last_value() {
        let args = vec![
            "--seed".to_string(),
            "100".to_string(),
            "--seed".to_string(),
            "200".to_string(),
        ];

        let parsed = parse_args(args).expect("duplicate args should parse");
        assert_eq!(parsed.config.seed, 200); // Last value should win
    }
}
