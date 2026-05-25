#!/usr/bin/env rust
//! Runtime Lockstep Oracle Orchestrator
//!
//! Command-line tool for integrating Node.js and Bun benchmark results with
//! the lockstep oracle for differential checking against FrankenEngine.
//!
//! This tool coordinates the execution of comparative benchmarks and feeds
//! the results into the lockstep oracle for automated differential analysis.

#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use clap::{Args, Parser, Subcommand};

use frankenengine_engine::runtime_lockstep_helpers::{
    RuntimeId, RuntimeLockstepConfig, generate_trace_session_id,
    run_comprehensive_lockstep_analysis, verify_trace_completeness,
};

#[derive(Parser)]
#[command(name = "runtime-lockstep-orchestrator")]
#[command(about = "Orchestrate runtime comparison benchmarks with lockstep oracle analysis")]
#[command(version = "1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run Node.js vs FrankenEngine comparative benchmarks with lockstep analysis
    Node {
        /// Base directory for storing trace files
        #[arg(long, default_value = "/tmp/franken_engine_lockstep")]
        traces_dir: PathBuf,

        /// Specific workload to benchmark (if not provided, runs all)
        #[arg(long)]
        workload: Option<String>,

        /// Skip lockstep oracle analysis, just generate traces
        #[arg(long)]
        traces_only: bool,

        /// Keep trace files after analysis
        #[arg(long)]
        keep_traces: bool,

        /// Output directory for lockstep reports
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },

    /// Run Bun vs FrankenEngine comparative benchmarks with lockstep analysis
    Bun {
        /// Base directory for storing trace files
        #[arg(long, default_value = "/tmp/franken_engine_lockstep")]
        traces_dir: PathBuf,

        /// Specific workload to benchmark (if not provided, runs all)
        #[arg(long)]
        workload: Option<String>,

        /// Skip lockstep oracle analysis, just generate traces
        #[arg(long)]
        traces_only: bool,

        /// Keep trace files after analysis
        #[arg(long)]
        keep_traces: bool,

        /// Output directory for lockstep reports
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },

    /// Run comprehensive analysis (both Node and Bun vs FrankenEngine)
    All {
        /// Base directory for storing trace files
        #[arg(long, default_value = "/tmp/franken_engine_lockstep")]
        traces_dir: PathBuf,

        /// Specific workload to benchmark (if not provided, runs all)
        #[arg(long)]
        workload: Option<String>,

        /// Skip lockstep oracle analysis, just generate traces
        #[arg(long)]
        traces_only: bool,

        /// Keep trace files after analysis
        #[arg(long)]
        keep_traces: bool,

        /// Output directory for lockstep reports
        #[arg(long)]
        output_dir: Option<PathBuf>,
    },

    /// Analyze existing trace files with lockstep oracle
    Analyze {
        /// Directory containing trace files
        #[arg(long)]
        traces_dir: PathBuf,

        /// Output directory for reports
        #[arg(long)]
        output_dir: Option<PathBuf>,

        /// Runtime to analyze (node, bun, or all)
        #[arg(long, default_value = "all")]
        runtime: String,
    },

    /// Verify trace completeness for expected workloads
    Verify {
        /// Directory containing trace files
        #[arg(long)]
        traces_dir: PathBuf,

        /// Expected workloads (comma-separated)
        #[arg(long)]
        workloads: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Node {
            traces_dir,
            workload,
            traces_only,
            keep_traces,
            output_dir,
        } => run_runtime_benchmarks(
            RuntimeId::NodeJs,
            traces_dir,
            workload,
            traces_only,
            keep_traces,
            output_dir,
        ),
        Commands::Bun {
            traces_dir,
            workload,
            traces_only,
            keep_traces,
            output_dir,
        } => run_runtime_benchmarks(
            RuntimeId::Bun,
            traces_dir,
            workload,
            traces_only,
            keep_traces,
            output_dir,
        ),
        Commands::All {
            traces_dir,
            workload,
            traces_only,
            keep_traces,
            output_dir,
        } => run_all_benchmarks(traces_dir, workload, traces_only, keep_traces, output_dir),
        Commands::Analyze {
            traces_dir,
            output_dir,
            runtime,
        } => analyze_traces(traces_dir, output_dir, runtime),
        Commands::Verify {
            traces_dir,
            workloads,
        } => verify_traces(traces_dir, workloads),
    }
}

fn run_runtime_benchmarks(
    runtime: RuntimeId,
    traces_dir: PathBuf,
    workload: Option<String>,
    traces_only: bool,
    keep_traces: bool,
    output_dir: Option<PathBuf>,
) -> ExitCode {
    println!(
        "Running {} vs FrankenEngine comparative benchmarks...",
        runtime.as_str()
    );

    let config = RuntimeLockstepConfig {
        traces_base_dir: traces_dir,
        run_oracle: !traces_only,
        cleanup_traces: !keep_traces,
    };

    // Run the appropriate benchmark
    let benchmark_name = match runtime {
        RuntimeId::NodeJs => "comparative_node",
        RuntimeId::Bun => "comparative_bun",
        RuntimeId::FrankenEngine => unreachable!("Cannot run FrankenEngine-only benchmark"),
    };

    let mut benchmark_cmd = Command::new("cargo");
    benchmark_cmd
        .args([
            "bench",
            "-p",
            "frankenengine-engine",
            "--bench",
            benchmark_name,
        ])
        .env("RUNTIME_LOCKSTEP_ENABLED", "1")
        .env("RUNTIME_LOCKSTEP_TRACES_DIR", &config.traces_base_dir);

    if let Some(ref workload_filter) = workload {
        benchmark_cmd.env("RUNTIME_LOCKSTEP_WORKLOAD_FILTER", workload_filter);
    }

    println!("Executing: {benchmark_cmd:?}");

    match benchmark_cmd.status() {
        Ok(status) if status.success() => {
            println!("Benchmark completed successfully");
        }
        Ok(status) => {
            eprintln!("Benchmark failed with exit code: {:?}", status.code());
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("Failed to execute benchmark: {e}");
            return ExitCode::FAILURE;
        }
    }

    if !traces_only {
        match run_comprehensive_lockstep_analysis(&config) {
            Ok(result) => {
                println!("Lockstep analysis completed:");
                println!("  Trace files generated: {}", result.trace_files_generated);

                if let Some(ref output_path) = output_dir {
                    save_reports(&result, output_path, runtime);
                } else {
                    print_reports(&result, runtime);
                }

                if result.cleanup_successful {
                    println!("Trace files cleaned up successfully");
                }
            }
            Err(e) => {
                eprintln!("Lockstep analysis failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}

fn run_all_benchmarks(
    traces_dir: PathBuf,
    workload: Option<String>,
    traces_only: bool,
    keep_traces: bool,
    output_dir: Option<PathBuf>,
) -> ExitCode {
    println!("Running comprehensive runtime comparison analysis...");

    // Run Node benchmarks
    let node_result = run_runtime_benchmarks(
        RuntimeId::NodeJs,
        traces_dir.clone(),
        workload.clone(),
        true, // traces_only for individual runs
        true, // keep_traces for individual runs
        None,
    );

    if node_result != ExitCode::SUCCESS {
        eprintln!("Node.js benchmarks failed");
        return node_result;
    }

    // Run Bun benchmarks
    let bun_result = run_runtime_benchmarks(
        RuntimeId::Bun,
        traces_dir.clone(),
        workload,
        true, // traces_only for individual runs
        true, // keep_traces for individual runs
        None,
    );

    if bun_result != ExitCode::SUCCESS {
        eprintln!("Bun benchmarks failed");
        return bun_result;
    }

    // Run comprehensive analysis if requested
    if !traces_only {
        let config = RuntimeLockstepConfig {
            traces_base_dir: traces_dir,
            run_oracle: true,
            cleanup_traces: !keep_traces,
        };

        match run_comprehensive_lockstep_analysis(&config) {
            Ok(result) => {
                println!("Comprehensive lockstep analysis completed:");
                println!("  Total trace files: {}", result.trace_files_generated);

                if let Some(ref output_path) = output_dir {
                    save_comprehensive_reports(&result, output_path);
                } else {
                    print_comprehensive_reports(&result);
                }
            }
            Err(e) => {
                eprintln!("Comprehensive analysis failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}

fn analyze_traces(traces_dir: PathBuf, output_dir: Option<PathBuf>, runtime: String) -> ExitCode {
    println!("Analyzing traces in: {}", traces_dir.display());

    let config = RuntimeLockstepConfig {
        traces_base_dir: traces_dir,
        run_oracle: true,
        cleanup_traces: false,
    };

    match run_comprehensive_lockstep_analysis(&config) {
        Ok(result) => {
            println!(
                "Analysis completed for {} trace files",
                result.trace_files_generated
            );

            match runtime.as_str() {
                "node" => {
                    if let Some(ref report) = result.node_vs_franken_report {
                        if let Some(ref output_path) = output_dir {
                            save_single_report(report, output_path, "node_vs_franken_report.json");
                        } else {
                            println!("Node vs FrankenEngine Report:\n{report}");
                        }
                    }
                }
                "bun" => {
                    if let Some(ref report) = result.bun_vs_franken_report {
                        if let Some(ref output_path) = output_dir {
                            save_single_report(report, output_path, "bun_vs_franken_report.json");
                        } else {
                            println!("Bun vs FrankenEngine Report:\n{report}");
                        }
                    }
                }
                "all" => {
                    if let Some(ref output_path) = output_dir {
                        save_comprehensive_reports(&result, output_path);
                    } else {
                        print_comprehensive_reports(&result);
                    }
                }
                _ => {
                    eprintln!("Invalid runtime: {runtime}. Use 'node', 'bun', or 'all'");
                    return ExitCode::FAILURE;
                }
            }

            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Analysis failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn verify_traces(traces_dir: PathBuf, workloads: Option<String>) -> ExitCode {
    let expected_workloads = workloads
        .map(|w| {
            w.split(',')
                .map(str::trim)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            vec![
                "numeric_loop".to_string(),
                "basic_arithmetic".to_string(),
                "json_roundtrip".to_string(),
                "array_indexing".to_string(),
            ]
        });

    let config = RuntimeLockstepConfig {
        traces_base_dir: traces_dir,
        run_oracle: false,
        cleanup_traces: false,
    };

    let workload_refs: Vec<&str> = expected_workloads.iter().map(|s| s.as_str()).collect();

    match verify_trace_completeness(&config, &workload_refs) {
        Ok((present, missing)) => {
            println!("Trace verification results:");
            println!("  Present workloads ({}): {:?}", present.len(), present);
            println!("  Missing workloads ({}): {:?}", missing.len(), missing);

            if missing.is_empty() {
                println!("✓ All expected traces are present");
                ExitCode::SUCCESS
            } else {
                println!("✗ {} workloads missing traces", missing.len());
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("Verification failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn save_reports(
    result: &frankenengine_engine::runtime_lockstep_helpers::RuntimeLockstepResult,
    output_dir: &PathBuf,
    runtime: RuntimeId,
) {
    let _ = fs::create_dir_all(output_dir);
    let session_id = generate_trace_session_id();

    match runtime {
        RuntimeId::NodeJs => {
            if let Some(ref report) = result.node_vs_franken_report {
                let filename = format!("node_vs_franken_report_{session_id}.json");
                save_single_report(report, output_dir, &filename);
            }
        }
        RuntimeId::Bun => {
            if let Some(ref report) = result.bun_vs_franken_report {
                let filename = format!("bun_vs_franken_report_{session_id}.json");
                save_single_report(report, output_dir, &filename);
            }
        }
        RuntimeId::FrankenEngine => unreachable!(),
    }
}

fn save_comprehensive_reports(
    result: &frankenengine_engine::runtime_lockstep_helpers::RuntimeLockstepResult,
    output_dir: &PathBuf,
) {
    let _ = fs::create_dir_all(output_dir);
    let session_id = generate_trace_session_id();

    if let Some(ref report) = result.node_vs_franken_report {
        let filename = format!("node_vs_franken_report_{session_id}.json");
        save_single_report(report, output_dir, &filename);
    }

    if let Some(ref report) = result.bun_vs_franken_report {
        let filename = format!("bun_vs_franken_report_{session_id}.json");
        save_single_report(report, output_dir, &filename);
    }
}

fn save_single_report(report: &str, output_dir: &PathBuf, filename: &str) {
    let path = output_dir.join(filename);
    match fs::write(&path, report) {
        Ok(()) => println!("Report saved to: {}", path.display()),
        Err(e) => eprintln!("Failed to save report to {}: {e}", path.display()),
    }
}

fn print_reports(
    result: &frankenengine_engine::runtime_lockstep_helpers::RuntimeLockstepResult,
    runtime: RuntimeId,
) {
    match runtime {
        RuntimeId::NodeJs => {
            if let Some(ref report) = result.node_vs_franken_report {
                println!("\n=== Node.js vs FrankenEngine Lockstep Report ===");
                println!("{report}");
            }
        }
        RuntimeId::Bun => {
            if let Some(ref report) = result.bun_vs_franken_report {
                println!("\n=== Bun vs FrankenEngine Lockstep Report ===");
                println!("{report}");
            }
        }
        RuntimeId::FrankenEngine => unreachable!(),
    }
}

fn print_comprehensive_reports(
    result: &frankenengine_engine::runtime_lockstep_helpers::RuntimeLockstepResult,
) {
    if let Some(ref report) = result.node_vs_franken_report {
        println!("\n=== Node.js vs FrankenEngine Lockstep Report ===");
        println!("{report}");
    }

    if let Some(ref report) = result.bun_vs_franken_report {
        println!("\n=== Bun vs FrankenEngine Lockstep Report ===");
        println!("{report}");
    }
}
