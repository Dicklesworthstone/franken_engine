//! Helper functions for integrating runtime comparison benchmarks with lockstep oracle.
//!
//! This module provides utilities to generate trace files from benchmark execution
//! results and coordinate lockstep oracle runs with Node.js and Bun comparisons.

#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{SecondsFormat, Utc};

use crate::frx_lockstep_oracle::{
    FrxLockstepRunContext, RuntimeBenchmarkResult, create_runtime_benchmark_trace,
    run_bun_lockstep_oracle, run_node_lockstep_oracle,
};

/// Configuration for runtime lockstep integration.
#[derive(Debug, Clone)]
pub struct RuntimeLockstepConfig {
    /// Base directory for storing trace files
    pub traces_base_dir: PathBuf,
    /// Whether to run lockstep oracle after generating traces
    pub run_oracle: bool,
    /// Whether to clean up trace files after oracle run
    pub cleanup_traces: bool,
}

impl Default for RuntimeLockstepConfig {
    fn default() -> Self {
        Self {
            traces_base_dir: std::env::temp_dir().join("franken_engine_lockstep_traces"),
            run_oracle: true,
            cleanup_traces: true,
        }
    }
}

/// Runtime identifier for trace generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeId {
    NodeJs,
    Bun,
    FrankenEngine,
}

impl RuntimeId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NodeJs => "Node.js",
            Self::Bun => "Bun",
            Self::FrankenEngine => "FrankenEngine",
        }
    }

    pub fn trace_dir_name(self) -> &'static str {
        match self {
            Self::NodeJs => "node_traces",
            Self::Bun => "bun_traces",
            Self::FrankenEngine => "franken_traces",
        }
    }
}

/// Result from a runtime lockstep session.
#[derive(Debug)]
pub struct RuntimeLockstepResult {
    pub node_vs_franken_report: Option<String>,
    pub bun_vs_franken_report: Option<String>,
    pub trace_files_generated: usize,
    pub cleanup_successful: bool,
}

/// Generate trace file from benchmark output and timing information.
pub fn create_benchmark_trace_from_output(
    workload_id: &str,
    runtime: RuntimeId,
    output: &Output,
    wall_time: Duration,
    peak_rss_bytes: Option<u64>,
    config: &RuntimeLockstepConfig,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let result = RuntimeBenchmarkResult {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        wall_time_ns: wall_time.as_nanos().min(u128::from(u64::MAX)) as u64,
        peak_rss_bytes: peak_rss_bytes.unwrap_or(0),
        exit_success: output.status.success(),
        exit_code: output.status.code(),
    };

    let runtime_dir = config.traces_base_dir.join(runtime.trace_dir_name());
    fs::create_dir_all(&runtime_dir)?;

    let trace_path = runtime_dir.join(format!("{workload_id}.trace.json"));
    create_runtime_benchmark_trace(workload_id, runtime.as_str(), result, &trace_path)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    Ok(trace_path)
}

/// Run comprehensive lockstep oracle analysis comparing all runtime traces.
pub fn run_comprehensive_lockstep_analysis(
    config: &RuntimeLockstepConfig,
) -> Result<RuntimeLockstepResult, Box<dyn std::error::Error>> {
    let node_dir = config
        .traces_base_dir
        .join(RuntimeId::NodeJs.trace_dir_name());
    let bun_dir = config.traces_base_dir.join(RuntimeId::Bun.trace_dir_name());
    let franken_dir = config
        .traces_base_dir
        .join(RuntimeId::FrankenEngine.trace_dir_name());

    let mut result = RuntimeLockstepResult {
        node_vs_franken_report: None,
        bun_vs_franken_report: None,
        trace_files_generated: count_trace_files(&config.traces_base_dir)?,
        cleanup_successful: false,
    };

    if !config.run_oracle {
        return Ok(result);
    }

    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();

    // Run Node vs FrankenEngine comparison if both directories exist
    if node_dir.exists() && franken_dir.exists() {
        let context = FrxLockstepRunContext::deterministic(
            &format!("trace-node-lockstep-{timestamp}"),
            &format!("decision-node-lockstep-{timestamp}"),
            "policy-runtime-comparison-node-v1",
        );

        match run_node_lockstep_oracle(&node_dir, &franken_dir, context, None) {
            Ok(report) => {
                result.node_vs_franken_report = Some(serde_json::to_string_pretty(&report)?);
            }
            Err(e) => {
                eprintln!("Warning: Node vs FrankenEngine lockstep oracle failed: {e}");
            }
        }
    }

    // Run Bun vs FrankenEngine comparison if both directories exist
    if bun_dir.exists() && franken_dir.exists() {
        let context = FrxLockstepRunContext::deterministic(
            &format!("trace-bun-lockstep-{timestamp}"),
            &format!("decision-bun-lockstep-{timestamp}"),
            "policy-runtime-comparison-bun-v1",
        );

        match run_bun_lockstep_oracle(&bun_dir, &franken_dir, context, None) {
            Ok(report) => {
                result.bun_vs_franken_report = Some(serde_json::to_string_pretty(&report)?);
            }
            Err(e) => {
                eprintln!("Warning: Bun vs FrankenEngine lockstep oracle failed: {e}");
            }
        }
    }

    // Clean up trace files if requested
    if config.cleanup_traces {
        result.cleanup_successful = cleanup_trace_directories(&config.traces_base_dir).is_ok();
    } else {
        result.cleanup_successful = true;
    }

    Ok(result)
}

/// Count the total number of trace files in the base directory.
fn count_trace_files(base_dir: &Path) -> Result<usize, std::io::Error> {
    let mut count = 0;

    if !base_dir.exists() {
        return Ok(0);
    }

    for runtime in [RuntimeId::NodeJs, RuntimeId::Bun, RuntimeId::FrankenEngine] {
        let runtime_dir = base_dir.join(runtime.trace_dir_name());
        if runtime_dir.exists() {
            let entries = fs::read_dir(&runtime_dir)?;
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if path.is_file()
                    && path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map_or(false, |name| name.ends_with(".trace.json"))
                {
                    count += 1;
                }
            }
        }
    }

    Ok(count)
}

/// Clean up trace directories.
fn cleanup_trace_directories(base_dir: &Path) -> Result<(), std::io::Error> {
    if base_dir.exists() {
        fs::remove_dir_all(base_dir)?;
    }
    Ok(())
}

/// Generate a unique trace session identifier based on current timestamp.
pub fn generate_trace_session_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("runtime-lockstep-{timestamp}")
}

/// Verify that all required runtime traces are present for lockstep analysis.
pub fn verify_trace_completeness(
    config: &RuntimeLockstepConfig,
    expected_workloads: &[&str],
) -> Result<(Vec<String>, Vec<String>), Box<dyn std::error::Error>> {
    let mut present_workloads = Vec::new();
    let mut missing_workloads = Vec::new();

    for workload in expected_workloads {
        let node_trace = config
            .traces_base_dir
            .join(RuntimeId::NodeJs.trace_dir_name())
            .join(format!("{workload}.trace.json"));
        let bun_trace = config
            .traces_base_dir
            .join(RuntimeId::Bun.trace_dir_name())
            .join(format!("{workload}.trace.json"));
        let franken_trace = config
            .traces_base_dir
            .join(RuntimeId::FrankenEngine.trace_dir_name())
            .join(format!("{workload}.trace.json"));

        let has_all_traces = node_trace.exists() && bun_trace.exists() && franken_trace.exists();

        if has_all_traces {
            present_workloads.push(workload.to_string());
        } else {
            missing_workloads.push(workload.to_string());
        }
    }

    Ok((present_workloads, missing_workloads))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn runtime_id_string_conversion() {
        assert_eq!(RuntimeId::NodeJs.as_str(), "Node.js");
        assert_eq!(RuntimeId::Bun.as_str(), "Bun");
        assert_eq!(RuntimeId::FrankenEngine.as_str(), "FrankenEngine");
    }

    #[test]
    fn runtime_id_trace_dir_names() {
        assert_eq!(RuntimeId::NodeJs.trace_dir_name(), "node_traces");
        assert_eq!(RuntimeId::Bun.trace_dir_name(), "bun_traces");
        assert_eq!(RuntimeId::FrankenEngine.trace_dir_name(), "franken_traces");
    }

    #[test]
    fn runtime_lockstep_config_default() {
        let config = RuntimeLockstepConfig::default();
        assert!(
            config
                .traces_base_dir
                .ends_with("franken_engine_lockstep_traces")
        );
        assert!(config.run_oracle);
        assert!(config.cleanup_traces);
    }

    #[test]
    fn generate_trace_session_id_format() {
        let session_id = generate_trace_session_id();
        assert!(session_id.starts_with("runtime-lockstep-"));
        assert!(session_id.len() > "runtime-lockstep-".len());
    }

    #[test]
    fn count_trace_files_empty_directory() {
        let temp_dir = std::env::temp_dir().join("trace_count_test_empty");
        let _ = fs::remove_dir_all(&temp_dir); // Ensure it doesn't exist

        let count = count_trace_files(&temp_dir).expect("should handle non-existent directory");
        assert_eq!(count, 0);
    }

    #[test]
    fn create_benchmark_trace_from_output_success() {
        let temp_dir = std::env::temp_dir().join("benchmark_trace_test");
        let config = RuntimeLockstepConfig {
            traces_base_dir: temp_dir.clone(),
            run_oracle: false,
            cleanup_traces: false,
        };

        let output = Output {
            status: std::process::ExitStatus::from_raw(0),
            stdout: b"42".to_vec(),
            stderr: b"".to_vec(),
        };

        let result = create_benchmark_trace_from_output(
            "test_workload",
            RuntimeId::NodeJs,
            &output,
            Duration::from_millis(1500),
            Some(4096),
            &config,
        );

        assert!(result.is_ok());
        let trace_path = result.unwrap();
        assert!(trace_path.exists());
        assert!(trace_path.ends_with("test_workload.trace.json"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn verify_trace_completeness_missing_traces() {
        let temp_dir = std::env::temp_dir().join("trace_completeness_test");
        let config = RuntimeLockstepConfig {
            traces_base_dir: temp_dir.clone(),
            run_oracle: false,
            cleanup_traces: false,
        };

        let workloads = ["workload1", "workload2"];
        let result = verify_trace_completeness(&config, &workloads);

        assert!(result.is_ok());
        let (present, missing) = result.unwrap();
        assert_eq!(present.len(), 0);
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"workload1".to_string()));
        assert!(missing.contains(&"workload2".to_string()));

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
