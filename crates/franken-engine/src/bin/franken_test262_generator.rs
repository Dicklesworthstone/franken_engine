//! Test262 Case Vector Generator
//!
//! BD-24POU: Generates real Test262 case vectors from the official tc39/test262 suite.
//!
//! This tool replaces the fake test262_case_vectors.jsonl with vectors generated from
//! actual Test262 tests, enabling real conformance testing instead of fixture-only assertions.
//!
//! Usage:
//!   cargo run --bin franken_test262_generator -- --test262-repo /path/to/test262 --pins pins.toml --profile profile.toml --output case_vectors.jsonl
//!
//! Workflow:
//! 1. Downloads/verifies Test262 suite at pinned commit
//! 2. Parses .js test files and extracts metadata
//! 3. Filters tests based on ES2020 profile patterns
//! 4. Converts to case vectors for franken_test262_runner
//! 5. Writes JSONL output compatible with existing Test262 infrastructure

use std::path::{Component, Path, PathBuf};
use std::process;

use frankenengine_engine::test262_harness::{Test262Harness, Test262HarnessError};
use frankenengine_engine::test262_release_gate::{Test262PinSet, Test262Profile};

#[derive(Debug)]
struct CliArgs {
    test262_repo_path: PathBuf,
    pins_path: PathBuf,
    profile_path: PathBuf,
    output_path: PathBuf,
    sample_only: bool,
    sample_count: usize,
}

const CANONICAL_CASE_VECTORS_RELATIVE: &str = "tests/test262_case_vectors.jsonl";
const SAMPLE_ONLY_CANONICAL_ERROR: &str = "sample-only Test262 generation cannot write the canonical test262_case_vectors.jsonl; pass --test262-repo for real vectors or choose a scratch --output path";

fn main() {
    let args = parse_args().unwrap_or_else(|err| {
        eprintln!("Error: {}", err);
        eprintln!();
        eprintln!("{}", usage());
        process::exit(1);
    });

    if let Err(err) = run(args) {
        eprintln!("Error: {}", err);
        process::exit(1);
    }
}

fn usage() -> &'static str {
    "Usage: franken_test262_generator [options]

Options:
  --test262-repo <path>     Path to Test262 repository (will be cloned if missing)
  --pins <path>             Path to Test262 pins configuration (default: tests/test262_conformance_pins.toml)
  --profile <path>          Path to Test262 profile configuration (default: tests/test262_es2020_profile.toml)
  --output <path>           Output path for case vectors JSONL (default: crates/franken-engine/tests/test262_case_vectors.jsonl)
  --sample-only             Generate only a sample from a real Test262 checkout for faster development
  --sample-count <count>    Number of tests in sample (default: 50)
  --help                    Show this help

Example:
  cargo run -p frankenengine-engine --bin franken_test262_generator -- --test262-repo ./test262 --output ./real_test262_vectors.jsonl
  cargo run -p frankenengine-engine --bin franken_test262_generator -- --test262-repo ./test262 --sample-only --sample-count 10 --output ./scratch_test262_vectors.jsonl"
}

fn parse_args() -> Result<CliArgs, String> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from<I>(raw_args: I) -> Result<CliArgs, String>
where
    I: IntoIterator<Item = String>,
{
    let mut test262_repo_path = PathBuf::from("./test262");
    let mut pins_path = PathBuf::from("tests/test262_conformance_pins.toml");
    let mut profile_path = PathBuf::from("tests/test262_es2020_profile.toml");
    let mut output_path = default_case_vectors_path();
    let mut sample_only = false;
    let mut sample_count = 50;

    let mut args = raw_args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--test262-repo" => {
                let value = args.next().ok_or("--test262-repo requires a value")?;
                test262_repo_path = PathBuf::from(value);
            }
            "--pins" => {
                let value = args.next().ok_or("--pins requires a value")?;
                pins_path = PathBuf::from(value);
            }
            "--profile" => {
                let value = args.next().ok_or("--profile requires a value")?;
                profile_path = PathBuf::from(value);
            }
            "--output" => {
                let value = args.next().ok_or("--output requires a value")?;
                output_path = PathBuf::from(value);
            }
            "--sample-only" => {
                sample_only = true;
            }
            "--sample-count" => {
                let value = args.next().ok_or("--sample-count requires a value")?;
                sample_count = value
                    .parse()
                    .map_err(|_| format!("--sample-count must be a number, got '{}'", value))?;
            }
            "--help" => {
                println!("{}", usage());
                process::exit(0);
            }
            _ => {
                return Err(format!("Unknown argument: {}", arg));
            }
        }
    }

    Ok(CliArgs {
        test262_repo_path,
        pins_path,
        profile_path,
        output_path,
        sample_only,
        sample_count,
    })
}

fn run(args: CliArgs) -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Test262 Case Vector Generator");
    println!("BD-24POU: Real Test262 conformance harness integration");
    println!();

    if args.sample_only && output_path_is_canonical_case_vectors(&args.output_path) {
        return Err(SAMPLE_ONLY_CANONICAL_ERROR.into());
    }

    // Load configuration
    println!("📋 Loading configuration...");
    let pins = load_pins(&args.pins_path)?;
    let profile = load_profile(&args.profile_path)?;

    println!(
        "  Pins: {} (commit: {})",
        pins.source_repo, pins.test262_commit
    );
    println!(
        "  Profile: {} ({})",
        profile.profile_name, profile.es_profile
    );

    // Create harness
    let harness = Test262Harness::new(args.test262_repo_path.clone(), pins, profile);

    // Ensure Test262 suite is available
    println!("🔄 Ensuring Test262 suite availability...");
    println!("  Target path: {}", args.test262_repo_path.display());

    match harness.ensure_test262_suite() {
        Ok(()) => println!("  ✅ Test262 suite ready"),
        Err(Test262HarnessError::GitError(msg)) => {
            return Err(format!(
                "Test262 suite unavailable: {msg}. Refusing to synthesize sample vectors; use a valid --test262-repo checkout or --sample-only with a real checkout and scratch --output."
            )
            .into());
        }
        Err(err) => return Err(err.into()),
    }

    // Extract test cases
    println!("🔍 Extracting Test262 test cases...");
    let mut test_cases = harness.extract_test_cases()?;
    println!("  Found {} tests matching profile", test_cases.len());

    // Sample subset if requested
    if args.sample_only {
        test_cases.truncate(args.sample_count);
        println!(
            "  📝 Using sample of {} tests for development",
            test_cases.len()
        );
    }

    // Generate case vectors
    println!("⚙️  Generating case vectors...");
    let case_vectors = harness.generate_case_vectors(&test_cases);
    println!("  Generated {} case vectors", case_vectors.len());

    // Write output
    println!(
        "💾 Writing case vectors to {}...",
        args.output_path.display()
    );
    harness.write_case_vectors(&case_vectors, &args.output_path)?;

    println!();
    println!("✅ Test262 case vector generation complete!");
    println!("📊 Summary:");
    println!("  • Input: {} test cases", test_cases.len());
    println!("  • Output: {} case vectors", case_vectors.len());
    println!("  • File: {}", args.output_path.display());
    println!();
    println!("🚀 Next steps:");
    println!(
        "  1. Run: franken_test262_runner --case-vectors {}",
        args.output_path.display()
    );
    println!("  2. View: Test262 gate results with real conformance data");
    println!("  3. Update: High-water marks based on actual Test262 results");

    Ok(())
}

fn load_pins(path: &std::path::Path) -> Result<Test262PinSet, Box<dyn std::error::Error>> {
    if !path.exists() {
        // Generate a working pins file with a recent Test262 commit
        println!("  📝 Generating pins configuration at {}", path.display());
        generate_sample_pins(path)?;
    }

    Test262PinSet::load_toml(path)
        .map_err(|e| format!("Failed to load pins from {}: {}", path.display(), e).into())
}

fn load_profile(path: &std::path::Path) -> Result<Test262Profile, Box<dyn std::error::Error>> {
    Test262Profile::load_toml(path)
        .map_err(|e| format!("Failed to load profile from {}: {}", path.display(), e).into())
}

fn default_case_vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(CANONICAL_CASE_VECTORS_RELATIVE)
}

fn output_path_is_canonical_case_vectors(path: &Path) -> bool {
    path == Path::new(CANONICAL_CASE_VECTORS_RELATIVE)
        || normalize_path_for_compare(path)
            == normalize_path_for_compare(&default_case_vectors_path())
}

fn normalize_path_for_compare(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };

    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn generate_sample_pins(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let pins_content = r#"schema_version = "franken-engine.test262-pin.v1"
source_repo = "tc39/test262"
es_profile = "ES2020"
# Official tc39/test262 commit pinned for reproducible case-vector generation.
test262_commit = "d0c1b4555b03dd404873fd6422a4b5da00136500"
"#;

    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(path, pins_content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_cli_args(args: &[&str]) -> Result<CliArgs, String> {
        parse_args_from(args.iter().map(|arg| (*arg).to_string()))
    }

    #[test]
    fn parse_args_defaults_output_to_crate_case_vectors() {
        let args = parse_cli_args(&[]).expect("default args parse");
        assert_eq!(args.output_path, default_case_vectors_path());
    }

    #[test]
    fn canonical_case_vector_detection_catches_default_and_relative_paths() {
        assert!(output_path_is_canonical_case_vectors(
            default_case_vectors_path().as_path()
        ));
        assert!(output_path_is_canonical_case_vectors(Path::new(
            CANONICAL_CASE_VECTORS_RELATIVE
        )));
        assert!(!output_path_is_canonical_case_vectors(Path::new(
            "artifacts/test262/scratch_vectors.jsonl"
        )));
    }

    #[test]
    fn sample_only_rejects_canonical_output_before_network_work() {
        let args = parse_cli_args(&["--sample-only"]).expect("sample args parse");
        let err = run(args).expect_err("sample-only canonical output must fail");
        assert!(err.to_string().contains(SAMPLE_ONLY_CANONICAL_ERROR));
    }
}
