//! Differential oracle driver for comparing JavaScript runtime outputs.
//!
//! The driver records a receipt for every requested backend. Missing external
//! runtimes are represented as degraded receipts instead of failing the whole
//! run, which keeps corpus sweeps reproducible on machines without Node or Bun.

use std::env;
use std::fs;
use std::io::{self, Read};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wait_timeout::ChildExt;

use crate::{HybridRouter, JsEngine, QuickJsInspiredNativeEngine};

pub const DIFFERENTIAL_ORACLE_SCHEMA_VERSION: &str = "franken-engine.differential-oracle.v1";

const DEFAULT_TIMEOUT_MS: u64 = 2_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalRuntimeSpec {
    pub runtime_id: DifferentialBackend,
    pub program: String,
    pub version_args: Vec<String>,
    pub eval_args: Vec<String>,
}

impl ExternalRuntimeSpec {
    pub fn node_default() -> Self {
        Self {
            runtime_id: DifferentialBackend::NodeLts,
            program: "node".to_string(),
            version_args: vec!["--version".to_string()],
            eval_args: vec!["-e".to_string()],
        }
    }

    pub fn bun_default() -> Self {
        Self {
            runtime_id: DifferentialBackend::BunStable,
            program: "bun".to_string(),
            version_args: vec!["--version".to_string()],
            eval_args: vec!["-e".to_string()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialOracleInput {
    pub case_id: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    pub timeout_ms: u64,
    pub node: ExternalRuntimeSpec,
    pub bun: ExternalRuntimeSpec,
}

impl DifferentialOracleInput {
    pub fn new(case_id: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            case_id: case_id.into(),
            source: source.into(),
            source_path: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            node: ExternalRuntimeSpec::node_default(),
            bun: ExternalRuntimeSpec::bun_default(),
        }
    }

    pub fn with_source_path(mut self, source_path: impl Into<String>) -> Self {
        self.source_path = Some(source_path.into());
        self
    }

    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms.max(1);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferentialBackend {
    NodeLts,
    BunStable,
    FrankenEngine,
    FrankenCore,
}

impl DifferentialBackend {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::NodeLts => "node_lts",
            Self::BunStable => "bun_stable",
            Self::FrankenEngine => "franken_engine",
            Self::FrankenCore => "franken_core",
        }
    }
}

impl std::fmt::Display for DifferentialBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.stable_label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferentialBackendStatus {
    Completed,
    Failed,
    Unavailable,
    Timeout,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialHostFacts {
    pub os: String,
    pub arch: String,
    pub kernel: String,
    pub cpu_model: String,
    pub cpu_cores_logical: usize,
    pub franken_engine_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialBackendReceipt {
    pub backend: DifferentialBackend,
    pub status: DifferentialBackendStatus,
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub duration_micros: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialOracleReport {
    pub schema_version: String,
    pub generated_unix_ns: u128,
    pub case_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    pub source_sha256: String,
    pub host: DifferentialHostFacts,
    pub backends: Vec<DifferentialBackendReceipt>,
}

pub fn run_differential_oracle(input: &DifferentialOracleInput) -> DifferentialOracleReport {
    let timeout = Duration::from_millis(input.timeout_ms.max(1));
    let backends = vec![
        run_external_backend(&input.node, input.source.as_str(), timeout),
        run_external_backend(&input.bun, input.source.as_str(), timeout),
        run_franken_engine_backend(input.source.as_str()),
        run_franken_core_backend(input.source.as_str()),
    ];

    DifferentialOracleReport {
        schema_version: DIFFERENTIAL_ORACLE_SCHEMA_VERSION.to_string(),
        generated_unix_ns: current_unix_ns(),
        case_id: input.case_id.clone(),
        source_path: input.source_path.clone(),
        source_sha256: sha256_hex(input.source.as_bytes()),
        host: capture_host_facts(),
        backends,
    }
}

fn run_external_backend(
    spec: &ExternalRuntimeSpec,
    source: &str,
    timeout: Duration,
) -> DifferentialBackendReceipt {
    let version = match capture_external_version(spec, timeout) {
        VersionProbe::Available(version) => Some(version),
        VersionProbe::Unavailable(message) => {
            return DifferentialBackendReceipt {
                backend: spec.runtime_id,
                status: DifferentialBackendStatus::Unavailable,
                command: external_eval_command(spec),
                version: None,
                exit_code: None,
                duration_micros: 0,
                value: None,
                stdout: String::new(),
                stderr: String::new(),
                stdout_sha256: sha256_hex(b""),
                stderr_sha256: sha256_hex(b""),
                diagnostics: vec![message],
            };
        }
    };

    let command = external_eval_command(spec);
    let timed = run_command_with_timeout(
        spec.program.as_str(),
        spec.eval_args.iter().map(String::as_str).chain([source]),
        timeout,
    );

    match timed {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let status = if output.timed_out {
                DifferentialBackendStatus::Timeout
            } else if output.status.success() {
                DifferentialBackendStatus::Completed
            } else {
                DifferentialBackendStatus::Failed
            };
            let mut diagnostics = Vec::new();
            if output.timed_out {
                diagnostics.push(format!(
                    "{} exceeded {}ms timeout and was killed",
                    spec.runtime_id,
                    timeout.as_millis()
                ));
            }
            DifferentialBackendReceipt {
                backend: spec.runtime_id,
                status,
                command,
                version,
                exit_code: output.status.code(),
                duration_micros: output.duration_micros,
                value: None,
                stdout,
                stderr,
                stdout_sha256: sha256_hex(&output.stdout),
                stderr_sha256: sha256_hex(&output.stderr),
                diagnostics,
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => DifferentialBackendReceipt {
            backend: spec.runtime_id,
            status: DifferentialBackendStatus::Unavailable,
            command,
            version,
            exit_code: None,
            duration_micros: 0,
            value: None,
            stdout: String::new(),
            stderr: String::new(),
            stdout_sha256: sha256_hex(b""),
            stderr_sha256: sha256_hex(b""),
            diagnostics: vec![format!(
                "{} executable `{}` was not found",
                spec.runtime_id, spec.program
            )],
        },
        Err(error) => DifferentialBackendReceipt {
            backend: spec.runtime_id,
            status: DifferentialBackendStatus::Failed,
            command,
            version,
            exit_code: None,
            duration_micros: 0,
            value: None,
            stdout: String::new(),
            stderr: error.to_string(),
            stdout_sha256: sha256_hex(b""),
            stderr_sha256: sha256_hex(error.to_string().as_bytes()),
            diagnostics: vec![format!("failed to run {}: {error}", spec.runtime_id)],
        },
    }
}

fn run_franken_engine_backend(source: &str) -> DifferentialBackendReceipt {
    let started = Instant::now();
    let mut router = HybridRouter::default();
    match router.eval(source) {
        Ok(outcome) => {
            let stdout = outcome.value.clone();
            DifferentialBackendReceipt {
                backend: DifferentialBackend::FrankenEngine,
                status: DifferentialBackendStatus::Completed,
                command: vec!["franken-engine::HybridRouter::eval".to_string()],
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                exit_code: Some(0),
                duration_micros: started.elapsed().as_micros(),
                value: Some(outcome.value),
                stdout_sha256: sha256_hex(stdout.as_bytes()),
                stderr_sha256: sha256_hex(b""),
                stdout,
                stderr: String::new(),
                diagnostics: vec![format!("route_reason={}", outcome.route_reason)],
            }
        }
        Err(error) => {
            let stderr = error.to_string();
            DifferentialBackendReceipt {
                backend: DifferentialBackend::FrankenEngine,
                status: DifferentialBackendStatus::Failed,
                command: vec!["franken-engine::HybridRouter::eval".to_string()],
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                exit_code: Some(1),
                duration_micros: started.elapsed().as_micros(),
                value: None,
                stdout: String::new(),
                stderr,
                stdout_sha256: sha256_hex(b""),
                stderr_sha256: sha256_hex(error.to_string().as_bytes()),
                diagnostics: vec![error.stable_namespace().to_string()],
            }
        }
    }
}

fn run_franken_core_backend(source: &str) -> DifferentialBackendReceipt {
    let started = Instant::now();
    let mut engine = QuickJsInspiredNativeEngine;
    match engine.eval(source) {
        Ok(outcome) => {
            let stdout = outcome.value.clone();
            DifferentialBackendReceipt {
                backend: DifferentialBackend::FrankenCore,
                status: DifferentialBackendStatus::Completed,
                command: vec![
                    "franken-engine::QuickJsInspiredNativeEngine::eval".to_string(),
                    "franken-core-compatible-baseline-lane".to_string(),
                ],
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                exit_code: Some(0),
                duration_micros: started.elapsed().as_micros(),
                value: Some(outcome.value),
                stdout_sha256: sha256_hex(stdout.as_bytes()),
                stderr_sha256: sha256_hex(b""),
                stdout,
                stderr: String::new(),
                diagnostics: vec![
                    "frankenengine-core crate is not linked by frankenengine-engine; receipt uses the in-crate baseline interpreter compatibility lane".to_string(),
                ],
            }
        }
        Err(error) => {
            let stderr = error.to_string();
            DifferentialBackendReceipt {
                backend: DifferentialBackend::FrankenCore,
                status: DifferentialBackendStatus::Failed,
                command: vec![
                    "franken-engine::QuickJsInspiredNativeEngine::eval".to_string(),
                    "franken-core-compatible-baseline-lane".to_string(),
                ],
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                exit_code: Some(1),
                duration_micros: started.elapsed().as_micros(),
                value: None,
                stdout: String::new(),
                stderr,
                stdout_sha256: sha256_hex(b""),
                stderr_sha256: sha256_hex(error.to_string().as_bytes()),
                diagnostics: vec![
                    error.stable_namespace().to_string(),
                    "frankenengine-core crate is not linked by frankenengine-engine; receipt uses the in-crate baseline interpreter compatibility lane".to_string(),
                ],
            }
        }
    }
}

enum VersionProbe {
    Available(String),
    Unavailable(String),
}

fn capture_external_version(spec: &ExternalRuntimeSpec, timeout: Duration) -> VersionProbe {
    match run_command_with_timeout(
        spec.program.as_str(),
        spec.version_args.iter().map(String::as_str),
        timeout,
    ) {
        Ok(output) if output.status.success() && !output.timed_out => {
            let rendered = if output.stdout.is_empty() {
                String::from_utf8_lossy(&output.stderr).trim().to_string()
            } else {
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            };
            VersionProbe::Available(rendered)
        }
        Ok(output) if output.timed_out => VersionProbe::Unavailable(format!(
            "{} version probe exceeded {}ms timeout",
            spec.runtime_id,
            timeout.as_millis()
        )),
        Ok(output) => VersionProbe::Unavailable(format!(
            "{} version probe failed with exit code {:?}",
            spec.runtime_id,
            output.status.code()
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            VersionProbe::Unavailable(format!(
                "{} executable `{}` was not found",
                spec.runtime_id, spec.program
            ))
        }
        Err(error) => {
            VersionProbe::Unavailable(format!("{} version probe failed: {error}", spec.runtime_id))
        }
    }
}

struct TimedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    duration_micros: u128,
    timed_out: bool,
}

fn run_command_with_timeout<'a>(
    program: &str,
    args: impl IntoIterator<Item = &'a str>,
    timeout: Duration,
) -> io::Result<TimedCommandOutput> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout_reader = child.stdout.take().map(spawn_reader);
    let stderr_reader = child.stderr.take().map(spawn_reader);
    let started = Instant::now();

    let (status, timed_out) = match child.wait_timeout(timeout)? {
        Some(status) => (status, false),
        None => {
            let _ = child.kill();
            (child.wait()?, true)
        }
    };

    let stdout = join_reader(stdout_reader)?;
    let stderr = join_reader(stderr_reader)?;
    Ok(TimedCommandOutput {
        status,
        stdout,
        stderr,
        duration_micros: started.elapsed().as_micros(),
        timed_out,
    })
}

fn spawn_reader<R>(mut reader: R) -> thread::JoinHandle<io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

fn join_reader(reader: Option<thread::JoinHandle<io::Result<Vec<u8>>>>) -> io::Result<Vec<u8>> {
    match reader {
        Some(handle) => match handle.join() {
            Ok(result) => result,
            Err(_) => Err(io::Error::other("reader thread panicked")),
        },
        None => Ok(Vec::new()),
    }
}

fn external_eval_command(spec: &ExternalRuntimeSpec) -> Vec<String> {
    let mut command = Vec::with_capacity(spec.eval_args.len() + 2);
    command.push(spec.program.clone());
    command.extend(spec.eval_args.clone());
    command.push("<source>".to_string());
    command
}

fn capture_host_facts() -> DifferentialHostFacts {
    DifferentialHostFacts {
        os: env::consts::OS.to_string(),
        arch: env::consts::ARCH.to_string(),
        kernel: uname_kernel(),
        cpu_model: linux_cpu_model().unwrap_or_else(|| "unknown".to_string()),
        cpu_cores_logical: thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(0),
        franken_engine_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

fn uname_kernel() -> String {
    Command::new("uname")
        .arg("-sr")
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn linux_cpu_model() -> Option<String> {
    fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|cpuinfo| {
            cpuinfo.lines().find_map(|line| {
                line.strip_prefix("model name").and_then(|rest| {
                    rest.split_once(':')
                        .map(|(_, model)| model.trim().to_string())
                })
            })
        })
        .filter(|model| !model.is_empty())
}

fn current_unix_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_always_records_four_backend_receipts() {
        let mut input = DifferentialOracleInput::new("basic-arithmetic", "1 + 1;");
        input.node.program = "frankenengine-missing-node-runtime".to_string();
        input.bun.program = "frankenengine-missing-bun-runtime".to_string();

        let report = run_differential_oracle(&input);

        assert_eq!(report.schema_version, DIFFERENTIAL_ORACLE_SCHEMA_VERSION);
        assert_eq!(report.backends.len(), 4);
        assert_eq!(report.backends[0].backend, DifferentialBackend::NodeLts);
        assert_eq!(
            report.backends[0].status,
            DifferentialBackendStatus::Unavailable
        );
        assert_eq!(report.backends[1].backend, DifferentialBackend::BunStable);
        assert_eq!(
            report.backends[1].status,
            DifferentialBackendStatus::Unavailable
        );
        assert_eq!(
            report.backends[2].backend,
            DifferentialBackend::FrankenEngine
        );
        assert_eq!(
            report.backends[2].status,
            DifferentialBackendStatus::Completed
        );
        assert_eq!(report.backends[2].value.as_deref(), Some("2"));
        assert_eq!(report.backends[3].backend, DifferentialBackend::FrankenCore);
        assert_eq!(
            report.backends[3].status,
            DifferentialBackendStatus::Completed
        );
        assert_eq!(report.backends[3].value.as_deref(), Some("2"));
    }

    #[test]
    fn configured_external_runtime_records_raw_output() {
        let runtime = ExternalRuntimeSpec {
            runtime_id: DifferentialBackend::NodeLts,
            program: "sh".to_string(),
            version_args: vec!["-c".to_string(), "printf shell-version".to_string()],
            eval_args: vec!["-c".to_string(), "printf oracle-output".to_string()],
        };

        let receipt = run_external_backend(&runtime, "ignored-source", Duration::from_secs(1));

        assert_eq!(receipt.status, DifferentialBackendStatus::Completed);
        assert_eq!(receipt.version.as_deref(), Some("shell-version"));
        assert_eq!(receipt.stdout, "oracle-output");
        assert_eq!(receipt.stdout_sha256, sha256_hex(b"oracle-output"));
    }
}
