#!/usr/bin/env cargo
//! Benchmark-gating behavior-equivalence runner against external baselines.
//!
//! This binary reads reference baseline results from a JSON manifest and gates
//! a benchmark run against equivalence thresholds to ensure behavior consistency
//! before treating performance numbers as meaningful.

#![forbid(unsafe_code)]

use clap::{Arg, Command};
use serde::{Deserialize, Serialize};
// bd-pvr9h: BTreeMap, not HashMap — README.md L921 + AGENTS.md mission
// language require deterministic iteration order anywhere a content
// hash or a serde output can observe it. `BenchmarkResult.metadata` is
// serde-derived and the lookup map below is read in baseline order, so
// switching to BTreeMap also keeps comparison-order deterministic.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

/// Benchmark result entry containing test name and measured value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub test_name: String,
    pub value: f64,
    pub unit: String,
    pub metadata: Option<BTreeMap<String, serde_json::Value>>,
}

/// Collection of benchmark results from a test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkManifest {
    pub timestamp: Option<String>,
    pub engine: Option<String>,
    pub results: Vec<BenchmarkResult>,
}

/// Equivalence comparison result for a single benchmark test.
#[derive(Debug, Clone)]
pub struct EquivalenceResult {
    pub test_name: String,
    pub baseline_value: f64,
    pub run_value: f64,
    pub relative_diff: f64,
    pub within_threshold: bool,
}

/// Overall gating verdict with detailed breakdown.
#[derive(Debug, Clone)]
pub struct GatingResult {
    pub passed: bool,
    pub threshold: f64,
    pub total_tests: usize,
    pub passing_tests: usize,
    pub equivalence_results: Vec<EquivalenceResult>,
}

impl GatingResult {
    /// Print a human-readable summary of the gating results.
    pub fn print_summary(&self) {
        println!("Benchmark Equivalence Gate Results:");
        println!("  Threshold: {:.4}", self.threshold);
        println!("  Total tests: {}", self.total_tests);
        println!("  Passing tests: {}", self.passing_tests);
        println!("  Failed tests: {}", self.total_tests - self.passing_tests);
        println!(
            "  Overall verdict: {}",
            if self.passed { "PASS" } else { "FAIL" }
        );
        println!();

        if !self.passed {
            println!("Failed tests:");
            for result in &self.equivalence_results {
                if !result.within_threshold {
                    println!(
                        "  {} - baseline: {:.6}, run: {:.6}, diff: {:.4}%",
                        result.test_name,
                        result.baseline_value,
                        result.run_value,
                        result.relative_diff * 100.0
                    );
                }
            }
        }
    }
}

/// Load and parse a benchmark manifest from a JSON file.
fn load_benchmark_manifest(path: &Path) -> Result<BenchmarkManifest, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read manifest file '{}': {}", path.display(), e))?;

    let manifest: BenchmarkManifest = serde_json::from_str(&content)
        .map_err(|e| format!("Failed to parse JSON manifest '{}': {}", path.display(), e))?;

    Ok(manifest)
}

/// Compare two benchmark manifests and gate against equivalence threshold.
fn gate_benchmark_equivalence(
    baseline: &BenchmarkManifest,
    run: &BenchmarkManifest,
    threshold: f64,
) -> GatingResult {
    let mut equivalence_results = Vec::new();
    let mut passing_tests = 0;

    // Create lookup map for run results
    let run_map: BTreeMap<&String, &BenchmarkResult> =
        run.results.iter().map(|r| (&r.test_name, r)).collect();

    // Compare each baseline result against corresponding run result
    for baseline_result in &baseline.results {
        if let Some(run_result) = run_map.get(&baseline_result.test_name) {
            // Calculate relative difference: |run - baseline| / baseline
            let relative_diff = if baseline_result.value == 0.0 {
                if run_result.value == 0.0 {
                    0.0
                } else {
                    f64::INFINITY
                }
            } else {
                (run_result.value - baseline_result.value).abs() / baseline_result.value
            };

            let within_threshold = relative_diff <= threshold;
            if within_threshold {
                passing_tests += 1;
            }

            equivalence_results.push(EquivalenceResult {
                test_name: baseline_result.test_name.clone(),
                baseline_value: baseline_result.value,
                run_value: run_result.value,
                relative_diff,
                within_threshold,
            });
        } else {
            // Missing test in run results - treat as failure
            equivalence_results.push(EquivalenceResult {
                test_name: baseline_result.test_name.clone(),
                baseline_value: baseline_result.value,
                run_value: f64::NAN,
                relative_diff: f64::INFINITY,
                within_threshold: false,
            });
        }
    }

    let total_tests = equivalence_results.len();
    let passed = passing_tests == total_tests && total_tests > 0;

    GatingResult {
        passed,
        threshold,
        total_tests,
        passing_tests,
        equivalence_results,
    }
}

fn main() {
    let matches = Command::new("franken_benchmark_gate")
        .about("Benchmark-gating behavior-equivalence runner against external baselines")
        .version("1.0.0")
        .arg(
            Arg::new("baseline")
                .long("baseline")
                .value_name("PATH")
                .help("Path to baseline benchmark results JSON manifest")
                .required(true),
        )
        .arg(
            Arg::new("run")
                .long("run")
                .value_name("PATH")
                .help("Path to current run benchmark results JSON manifest")
                .required(true),
        )
        .arg(
            Arg::new("threshold")
                .long("threshold")
                .value_name("FLOAT")
                .help("Equivalence threshold as relative difference (e.g., 0.05 for 5%)")
                .default_value("0.05"),
        )
        .get_matches();

    let baseline_path = PathBuf::from(
        matches
            .get_one::<String>("baseline")
            .expect("serde deserialization should succeed"),
    );
    let run_path = PathBuf::from(
        matches
            .get_one::<String>("run")
            .expect("serde deserialization should succeed"),
    );
    let threshold: f64 = matches
        .get_one::<String>("threshold")
        .expect("serde deserialization should succeed")
        .parse()
        .unwrap_or_else(|e| {
            eprintln!("Error: Invalid threshold value: {}", e);
            process::exit(1);
        });

    // Validate threshold range
    if !(0.0..=1.0).contains(&threshold) {
        eprintln!(
            "Error: Threshold must be between 0.0 and 1.0, got {}",
            threshold
        );
        process::exit(1);
    }

    // Load baseline manifest
    let baseline_manifest = match load_benchmark_manifest(&baseline_path) {
        Ok(manifest) => manifest,
        Err(e) => {
            eprintln!("Error loading baseline manifest: {}", e);
            process::exit(1);
        }
    };

    // Load run manifest
    let run_manifest = match load_benchmark_manifest(&run_path) {
        Ok(manifest) => manifest,
        Err(e) => {
            eprintln!("Error loading run manifest: {}", e);
            process::exit(1);
        }
    };

    // Perform equivalence gating
    let gating_result = gate_benchmark_equivalence(&baseline_manifest, &run_manifest, threshold);

    // Print results
    gating_result.print_summary();

    // Exit with appropriate code
    process::exit(if gating_result.passed { 0 } else { 1 });
}
