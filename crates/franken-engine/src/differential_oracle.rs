//! Differential oracle driver for comparing JavaScript runtime outputs.
//!
//! The driver records a receipt for every requested backend. Missing external
//! runtimes are represented as degraded receipts instead of failing the whole
//! run, which keeps corpus sweeps reproducible on machines without Node or Bun.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wait_timeout::ChildExt;

use frankenengine_core::baseline_interpreter::{
    InterpreterConfig as CoreInterpreterConfig, QuickJsLane as CoreQuickJsLane,
};
use frankenengine_core::capability::RuntimeCapability as CoreRuntimeCapability;
use frankenengine_core::ir_contract::{
    Ir0Module as CoreIr0Module, Ir3Instruction as CoreIr3Instruction, Ir3Module as CoreIr3Module,
};
use frankenengine_core::lowering_pipeline::{
    LoweringContext as CoreLoweringContext, lower_ir0_to_ir3 as core_lower_ir0_to_ir3,
};
use frankenengine_core::parser::{
    CanonicalEs2020Parser as CoreParser, ParseGoal as CoreParseGoal,
    ParserOptions as CoreParserOptions,
};

use crate::{HybridRouter, RouteReason};

pub const DIFFERENTIAL_ORACLE_SCHEMA_VERSION: &str = "franken-engine.differential-oracle.v1";
pub const DIFFERENTIAL_ORACLE_CANONICALIZATION_SCHEMA_VERSION: &str =
    "franken-engine.differential-oracle.canonicalization.v1";
pub const DIFFERENTIAL_ORACLE_DIVERGENCE_TAXONOMY_SCHEMA_VERSION: &str =
    "franken-engine.differential-oracle.divergence-taxonomy.v1";

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
    /// Override for the engine lane's interpreter instruction budget. The
    /// containment default cannot execute large benchmark workloads; corpus
    /// sweeps set this so the engine lane measures throughput rather than the
    /// budget ceiling. Recorded in the backend receipt's diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_instruction_budget: Option<u64>,
    pub node: ExternalRuntimeSpec,
    pub bun: ExternalRuntimeSpec,
    /// Backends to execute and compare. Defaults to all four lanes. The
    /// user-facing `frankenctl oracle run --engines ...` flag narrows this set;
    /// unselected lanes are neither executed nor included in the canonical
    /// comparison so the semantic verdict reflects exactly the requested lanes.
    #[serde(default = "default_backend_selection")]
    pub selected_backends: Vec<DifferentialBackend>,
}

/// The canonical, fully-populated backend selection (node, bun, franken-engine,
/// franken-core). Used as the serde default so historical inputs without the
/// field deserialize to the prior all-lanes behavior.
pub fn default_backend_selection() -> Vec<DifferentialBackend> {
    vec![
        DifferentialBackend::NodeLts,
        DifferentialBackend::BunStable,
        DifferentialBackend::FrankenEngine,
        DifferentialBackend::FrankenCore,
    ]
}

impl DifferentialOracleInput {
    pub fn new(case_id: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            case_id: case_id.into(),
            source: source.into(),
            source_path: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            engine_instruction_budget: None,
            node: ExternalRuntimeSpec::node_default(),
            bun: ExternalRuntimeSpec::bun_default(),
            selected_backends: default_backend_selection(),
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

    pub fn with_engine_instruction_budget(mut self, instruction_budget: u64) -> Self {
        self.engine_instruction_budget = Some(instruction_budget);
        self
    }

    /// Restrict execution/comparison to the given backends. An empty selection
    /// is normalized to the full set so the driver never produces an empty,
    /// uncomparable report; ordering and duplicates in `backends` are ignored
    /// because [`run_differential_oracle`] always emits the canonical order.
    pub fn with_selected_backends(
        mut self,
        backends: impl IntoIterator<Item = DifferentialBackend>,
    ) -> Self {
        let mut selected: Vec<DifferentialBackend> = backends.into_iter().collect();
        selected.sort_unstable();
        selected.dedup();
        if selected.is_empty() {
            selected = default_backend_selection();
        }
        self.selected_backends = selected;
        self
    }

    fn backend_selected(&self, backend: DifferentialBackend) -> bool {
        self.selected_backends.contains(&backend)
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

impl DifferentialBackendStatus {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::Degraded => "degraded",
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferentialComparisonMode {
    StructuredValue,
    ExactStdout,
    ExactStderr,
    ExceptionClass,
    TimingEnvelope,
}

impl DifferentialComparisonMode {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::StructuredValue => "structured_value",
            Self::ExactStdout => "exact_stdout",
            Self::ExactStderr => "exact_stderr",
            Self::ExceptionClass => "exception_class",
            Self::TimingEnvelope => "timing_envelope",
        }
    }

    const fn contributes_to_semantic_verdict(self) -> bool {
        match self {
            Self::StructuredValue | Self::ExceptionClass => true,
            Self::ExactStdout | Self::ExactStderr | Self::TimingEnvelope => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferentialComparisonVerdict {
    Consensus,
    Divergence,
    InsufficientData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialTimingEnvelope {
    pub duration_micros: u128,
    pub tolerance_micros: u128,
    pub lower_micros: u128,
    pub upper_micros: u128,
    pub bucket: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialCanonicalObservation {
    pub backend: DifferentialBackend,
    pub status: DifferentialBackendStatus,
    pub canonical_stdout: String,
    pub canonical_stderr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception_message_class: Option<String>,
    pub timing_envelope: DifferentialTimingEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialCanonicalGroup {
    pub canonical_key_sha256: String,
    pub sample: String,
    pub backends: Vec<DifferentialBackend>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialModeComparison {
    pub mode: DifferentialComparisonMode,
    pub verdict: DifferentialComparisonVerdict,
    pub applicable_backends: Vec<DifferentialBackend>,
    pub ignored_backends: Vec<DifferentialBackend>,
    pub groups: Vec<DifferentialCanonicalGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialCanonicalizationReport {
    pub schema_version: String,
    pub semantic_verdict: DifferentialComparisonVerdict,
    pub observations: Vec<DifferentialCanonicalObservation>,
    pub comparisons: Vec<DifferentialModeComparison>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferentialDivergenceClass {
    Parser,
    Lowering,
    Runtime,
    ModuleResolution,
    HostcallPolicy,
    IntentionalSecurityDivergence,
    ReferenceRuntimeBug,
}

impl DifferentialDivergenceClass {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Parser => "parser",
            Self::Lowering => "lowering",
            Self::Runtime => "runtime",
            Self::ModuleResolution => "module_resolution",
            Self::HostcallPolicy => "hostcall_policy",
            Self::IntentionalSecurityDivergence => "intentional_security_divergence",
            Self::ReferenceRuntimeBug => "reference_runtime_bug",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialDivergenceFinding {
    pub class: DifferentialDivergenceClass,
    pub comparison_mode: DifferentialComparisonMode,
    pub message: String,
    pub affected_backends: Vec<DifferentialBackend>,
    pub reference_backends: Vec<DifferentialBackend>,
    pub evidence_group_hashes: Vec<String>,
    pub remediation_hint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiver_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialDivergenceTaxonomyReport {
    pub schema_version: String,
    pub verdict: DifferentialComparisonVerdict,
    pub findings: Vec<DifferentialDivergenceFinding>,
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
    pub canonicalization: DifferentialCanonicalizationReport,
    pub divergence_taxonomy: DifferentialDivergenceTaxonomyReport,
}

pub fn run_differential_oracle(input: &DifferentialOracleInput) -> DifferentialOracleReport {
    let timeout = Duration::from_millis(input.timeout_ms.max(1));
    // Emit lanes in canonical order regardless of the order the caller requested
    // them, so the report is stable across invocations. Unselected lanes are not
    // executed (no external process is spawned, no interpreter is invoked).
    let mut backends = Vec::with_capacity(input.selected_backends.len());
    if input.backend_selected(DifferentialBackend::NodeLts) {
        backends.push(run_external_backend(
            &input.node,
            input.source.as_str(),
            timeout,
        ));
    }
    if input.backend_selected(DifferentialBackend::BunStable) {
        backends.push(run_external_backend(
            &input.bun,
            input.source.as_str(),
            timeout,
        ));
    }
    if input.backend_selected(DifferentialBackend::FrankenEngine) {
        backends.push(run_franken_engine_backend(
            input.source.as_str(),
            input.engine_instruction_budget,
        ));
    }
    if input.backend_selected(DifferentialBackend::FrankenCore) {
        backends.push(run_franken_core_backend(input.source.as_str()));
    }

    let canonicalization = canonicalize_backend_receipts(&backends);
    let divergence_taxonomy = classify_differential_divergences(&backends, &canonicalization);

    DifferentialOracleReport {
        schema_version: DIFFERENTIAL_ORACLE_SCHEMA_VERSION.to_string(),
        generated_unix_ns: current_unix_ns(),
        case_id: input.case_id.clone(),
        source_path: input.source_path.clone(),
        source_sha256: sha256_hex(input.source.as_bytes()),
        host: capture_host_facts(),
        canonicalization,
        divergence_taxonomy,
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

/// Renders captured `console.*` output the way `node -e` / `bun -e` surface it:
/// `log`/`info` entries flow to stdout and `warn`/`error` entries to stderr,
/// each terminated by a newline. This lets the in-process engine backend be
/// compared against the subprocess runtimes on the same observable (their
/// console stream) rather than on the engine's internal completion value.
fn render_console_streams(
    entries: &[crate::baseline_interpreter::ConsoleEntry],
) -> (String, String) {
    use crate::baseline_interpreter::ConsoleLevel;
    let mut stdout = String::new();
    let mut stderr = String::new();
    for entry in entries {
        let target = match entry.level {
            ConsoleLevel::Log | ConsoleLevel::Info => &mut stdout,
            ConsoleLevel::Warn | ConsoleLevel::Error => &mut stderr,
        };
        target.push_str(&entry.message);
        target.push('\n');
    }
    (stdout, stderr)
}

fn run_franken_engine_backend(
    source: &str,
    instruction_budget: Option<u64>,
) -> DifferentialBackendReceipt {
    let started = Instant::now();
    let mut router = HybridRouter::default();
    let evaluated = match instruction_budget {
        Some(budget) => router.eval_with_instruction_budget(source, budget),
        None => router.eval(source),
    };
    let budget_diagnostic =
        instruction_budget.map(|budget| format!("instruction_budget_override={budget}"));
    match evaluated {
        Ok(outcome) => {
            // The external backends are `node -e` / `bun -e` subprocesses whose
            // only observable is their console stream. Surface the in-process
            // engine's captured `console.*` output the same way so the
            // structured-value comparison is apples-to-apples; the completion
            // `value` is retained as supplementary detail.
            let (stdout, stderr) = render_console_streams(&outcome.console_output);
            let mut diagnostics = vec![format!("route_reason={}", outcome.route_reason)];
            diagnostics.extend(budget_diagnostic.clone());
            DifferentialBackendReceipt {
                backend: DifferentialBackend::FrankenEngine,
                status: DifferentialBackendStatus::Completed,
                command: vec!["franken-engine::HybridRouter::eval".to_string()],
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                exit_code: Some(0),
                duration_micros: started.elapsed().as_micros(),
                value: Some(outcome.value),
                stdout_sha256: sha256_hex(stdout.as_bytes()),
                stderr_sha256: sha256_hex(stderr.as_bytes()),
                stdout,
                stderr,
                diagnostics,
            }
        }
        Err(error) => {
            let stderr = error.to_string();
            let mut diagnostics = vec![error.stable_namespace().to_string()];
            diagnostics.extend(budget_diagnostic);
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
                diagnostics,
            }
        }
    }
}

fn run_franken_core_backend(source: &str) -> DifferentialBackendReceipt {
    let started = Instant::now();
    match eval_with_franken_core(source) {
        Ok(value) => {
            let stdout = value.clone();
            DifferentialBackendReceipt {
                backend: DifferentialBackend::FrankenCore,
                status: DifferentialBackendStatus::Completed,
                command: vec![
                    "frankenengine_core::parser::CanonicalEs2020Parser::parse_with_options"
                        .to_string(),
                    "frankenengine_core::lowering_pipeline::lower_ir0_to_ir3".to_string(),
                    "frankenengine_core::baseline_interpreter::QuickJsLane::execute".to_string(),
                ],
                version: Some(format!(
                    "frankenengine-core path dependency; frankenengine-engine {}",
                    env!("CARGO_PKG_VERSION")
                )),
                exit_code: Some(0),
                duration_micros: started.elapsed().as_micros(),
                value: Some(value),
                stdout_sha256: sha256_hex(stdout.as_bytes()),
                stderr_sha256: sha256_hex(b""),
                stdout,
                stderr: String::new(),
                diagnostics: vec![
                    "frankenengine-core path dependency executed in-process through parser/lowering/QuickJsLane".to_string(),
                ],
            }
        }
        Err(error) => {
            let stderr = format!("{}: {}", error.stage, error.message);
            DifferentialBackendReceipt {
                backend: DifferentialBackend::FrankenCore,
                status: DifferentialBackendStatus::Failed,
                command: vec![
                    "frankenengine_core::parser::CanonicalEs2020Parser::parse_with_options"
                        .to_string(),
                    "frankenengine_core::lowering_pipeline::lower_ir0_to_ir3".to_string(),
                    "frankenengine_core::baseline_interpreter::QuickJsLane::execute".to_string(),
                ],
                version: Some(format!(
                    "frankenengine-core path dependency; frankenengine-engine {}",
                    env!("CARGO_PKG_VERSION")
                )),
                exit_code: Some(1),
                duration_micros: started.elapsed().as_micros(),
                value: None,
                stdout: String::new(),
                stderr,
                stdout_sha256: sha256_hex(b""),
                stderr_sha256: sha256_hex(format!("{}: {}", error.stage, error.message).as_bytes()),
                diagnostics: vec![
                    format!("frankenengine-core backend failed during {}", error.stage),
                    "frankenengine-core path dependency is linked; no fallback lane was used"
                        .to_string(),
                ],
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrankenCoreBackendError {
    stage: &'static str,
    message: String,
}

impl FrankenCoreBackendError {
    fn new(stage: &'static str, error: impl std::fmt::Display) -> Self {
        Self {
            stage,
            message: error.to_string(),
        }
    }
}

fn eval_with_franken_core(source: &str) -> Result<String, FrankenCoreBackendError> {
    let normalized = source.trim();
    if normalized.is_empty() {
        return Err(FrankenCoreBackendError {
            stage: "parse",
            message: "empty source".to_string(),
        });
    }

    let parser = CoreParser;
    let syntax_tree = parser
        .parse_with_options(
            normalized,
            core_parse_goal(normalized),
            &CoreParserOptions::default(),
        )
        .map_err(|error| FrankenCoreBackendError::new("parse", error))?;
    let ir0 = CoreIr0Module::from_syntax_tree(syntax_tree, "<differential-oracle>");
    let lowering_context = CoreLoweringContext::new(
        "trace-differential-franken-core",
        "decision-differential-franken-core",
        "policy-differential-franken-core",
    );
    let mut lowering_output = core_lower_ir0_to_ir3(&ir0, &lowering_context)
        .map_err(|error| FrankenCoreBackendError::new("lower", error))?;
    patch_core_eval_completion_value(&mut lowering_output.ir3);
    // The franken-core lane is capability-gated and `QuickJsLane::new()`
    // grants nothing, so it denied `VmDispatch` on every program — the
    // backend could not execute even `1 + 1`. Grant the deterministic
    // execution baseline (VM dispatch + heap allocation), matching
    // franken-core's own `test_quickjs_config`, so the differential
    // comparison actually exercises franken-core rather than always failing.
    let mut config = CoreInterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(CoreRuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(CoreRuntimeCapability::HeapAllocate);
    let result = CoreQuickJsLane::with_config(config)
        .execute(&lowering_output.ir3, "trace-differential-franken-core")
        .map_err(|error| FrankenCoreBackendError::new("execute", error))?;
    Ok(result.value.to_string())
}

fn core_parse_goal(source: &str) -> CoreParseGoal {
    match HybridRouter::classify_source_route(source) {
        RouteReason::ContainsImportKeyword | RouteReason::ContainsAwaitKeyword => {
            CoreParseGoal::Module
        }
        RouteReason::DirectEngineInvocation | RouteReason::DefaultQuickJsPath => {
            CoreParseGoal::Script
        }
    }
}

fn patch_core_eval_completion_value(ir3: &mut CoreIr3Module) {
    let Some(main) = ir3.function_table.first() else {
        return;
    };
    let Ok(main_start) = usize::try_from(main.entry) else {
        return;
    };
    if main_start >= ir3.instructions.len() {
        return;
    }
    let main_end = ir3
        .function_table
        .iter()
        .skip(1)
        .filter_map(|function| usize::try_from(function.entry).ok())
        .filter(|entry| *entry > main_start)
        .min()
        .unwrap_or(ir3.instructions.len())
        .min(ir3.instructions.len());
    let instructions = &mut ir3.instructions[main_start..main_end];

    let mut completion_reg = None;
    for instr in instructions.iter().rev() {
        match instr {
            CoreIr3Instruction::Move { dst, src } if dst == src => continue,
            CoreIr3Instruction::Halt | CoreIr3Instruction::Throw { .. } => continue,
            CoreIr3Instruction::Return { .. } => continue,
            _ => {
                completion_reg = core_ir3_destination_register(instr);
                break;
            }
        }
    }

    if let Some(src) = completion_reg
        && src != 0
    {
        for instr in instructions.iter_mut() {
            if let CoreIr3Instruction::Return { value } = instr {
                *value = src;
            }
        }
    }
}

fn core_ir3_destination_register(instr: &CoreIr3Instruction) -> Option<u32> {
    match instr {
        CoreIr3Instruction::LoadInt { dst, .. }
        | CoreIr3Instruction::LoadFloat { dst, .. }
        | CoreIr3Instruction::LoadStr { dst, .. }
        | CoreIr3Instruction::LoadBool { dst, .. }
        | CoreIr3Instruction::LoadNull { dst }
        | CoreIr3Instruction::LoadUndefined { dst }
        | CoreIr3Instruction::Add { dst, .. }
        | CoreIr3Instruction::Sub { dst, .. }
        | CoreIr3Instruction::Mul { dst, .. }
        | CoreIr3Instruction::Div { dst, .. }
        | CoreIr3Instruction::Mod { dst, .. }
        | CoreIr3Instruction::Exp { dst, .. }
        | CoreIr3Instruction::UnaryNeg { dst, .. }
        | CoreIr3Instruction::UnaryPlus { dst, .. }
        | CoreIr3Instruction::LogicalNot { dst, .. }
        | CoreIr3Instruction::BitNot { dst, .. }
        | CoreIr3Instruction::TypeOf { dst, .. }
        | CoreIr3Instruction::Void { dst, .. }
        | CoreIr3Instruction::Lt { dst, .. }
        | CoreIr3Instruction::Lte { dst, .. }
        | CoreIr3Instruction::Gt { dst, .. }
        | CoreIr3Instruction::Gte { dst, .. }
        | CoreIr3Instruction::Eq { dst, .. }
        | CoreIr3Instruction::StrictEq { dst, .. }
        | CoreIr3Instruction::NotEq { dst, .. }
        | CoreIr3Instruction::StrictNotEq { dst, .. }
        | CoreIr3Instruction::BitAnd { dst, .. }
        | CoreIr3Instruction::BitOr { dst, .. }
        | CoreIr3Instruction::BitXor { dst, .. }
        | CoreIr3Instruction::Shl { dst, .. }
        | CoreIr3Instruction::Shr { dst, .. }
        | CoreIr3Instruction::Ushr { dst, .. }
        | CoreIr3Instruction::InstanceOf { dst, .. }
        | CoreIr3Instruction::InOp { dst, .. }
        | CoreIr3Instruction::Construct { dst, .. }
        | CoreIr3Instruction::ForInInit { dst, .. }
        | CoreIr3Instruction::ForInNext { value_dst: dst, .. }
        | CoreIr3Instruction::ForOfInit { dst, .. }
        | CoreIr3Instruction::ForOfNext { value_dst: dst, .. }
        | CoreIr3Instruction::Move { dst, .. }
        | CoreIr3Instruction::Call { dst, .. }
        | CoreIr3Instruction::CallMethod { dst, .. }
        | CoreIr3Instruction::HostCall { dst, .. }
        | CoreIr3Instruction::GetProperty { dst, .. }
        | CoreIr3Instruction::DeleteProperty { dst, .. }
        | CoreIr3Instruction::NewObject { dst }
        | CoreIr3Instruction::NewArray { dst }
        | CoreIr3Instruction::ArraySlice { dst, .. }
        | CoreIr3Instruction::TemplateLiteral { dst, .. }
        | CoreIr3Instruction::LoadThis { dst }
        | CoreIr3Instruction::LoadNewTarget { dst }
        | CoreIr3Instruction::LoadSuper { dst }
        | CoreIr3Instruction::EnterCatch { dst }
        | CoreIr3Instruction::CreateClosure { dst, .. }
        | CoreIr3Instruction::ImportModule { dst, .. }
        | CoreIr3Instruction::CreateGenerator { dst, .. }
        | CoreIr3Instruction::CreateAsyncFunction { dst, .. }
        | CoreIr3Instruction::CreateAsyncGenerator { dst, .. } => Some(*dst),
        _ => None,
    }
}

pub fn canonicalize_backend_receipts(
    receipts: &[DifferentialBackendReceipt],
) -> DifferentialCanonicalizationReport {
    let observations = receipts
        .iter()
        .map(canonicalize_backend_receipt)
        .collect::<Vec<_>>();
    let comparisons = [
        DifferentialComparisonMode::StructuredValue,
        DifferentialComparisonMode::ExactStdout,
        DifferentialComparisonMode::ExactStderr,
        DifferentialComparisonMode::ExceptionClass,
        DifferentialComparisonMode::TimingEnvelope,
    ]
    .into_iter()
    .map(|mode| build_mode_comparison(mode, &observations))
    .collect::<Vec<_>>();
    let semantic_verdict = summarize_semantic_verdict(&comparisons);
    let diagnostics = observations
        .iter()
        .filter(|observation| {
            matches!(
                observation.status,
                DifferentialBackendStatus::Unavailable
                    | DifferentialBackendStatus::Timeout
                    | DifferentialBackendStatus::Degraded
            )
        })
        .map(|observation| {
            format!(
                "{} is {} and was excluded from semantic consensus",
                observation.backend,
                observation.status.stable_label()
            )
        })
        .collect::<Vec<_>>();

    DifferentialCanonicalizationReport {
        schema_version: DIFFERENTIAL_ORACLE_CANONICALIZATION_SCHEMA_VERSION.to_string(),
        semantic_verdict,
        observations,
        comparisons,
        diagnostics,
    }
}

pub fn classify_differential_divergences(
    receipts: &[DifferentialBackendReceipt],
    canonicalization: &DifferentialCanonicalizationReport,
) -> DifferentialDivergenceTaxonomyReport {
    let findings = canonicalization
        .comparisons
        .iter()
        .filter(|comparison| comparison.verdict == DifferentialComparisonVerdict::Divergence)
        .map(|comparison| classify_mode_divergence(receipts, comparison))
        .collect::<Vec<_>>();
    let verdict = if findings.is_empty() {
        canonicalization.semantic_verdict
    } else if findings.iter().any(|finding| {
        finding.comparison_mode.contributes_to_semantic_verdict()
            && finding.class != DifferentialDivergenceClass::IntentionalSecurityDivergence
    }) {
        DifferentialComparisonVerdict::Divergence
    } else {
        canonicalization.semantic_verdict
    };
    let diagnostics = if findings.is_empty() {
        Vec::new()
    } else {
        findings
            .iter()
            .filter(|finding| finding.waiver_id.is_some())
            .map(|finding| {
                format!(
                    "{} requires waiver `{}`",
                    finding.class.stable_label(),
                    finding.waiver_id.as_deref().unwrap_or_default()
                )
            })
            .collect()
    };

    DifferentialDivergenceTaxonomyReport {
        schema_version: DIFFERENTIAL_ORACLE_DIVERGENCE_TAXONOMY_SCHEMA_VERSION.to_string(),
        verdict,
        findings,
        diagnostics,
    }
}

fn classify_mode_divergence(
    receipts: &[DifferentialBackendReceipt],
    comparison: &DifferentialModeComparison,
) -> DifferentialDivergenceFinding {
    let evidence = divergence_evidence_text(receipts, comparison);
    let class = classify_divergence_evidence(evidence.as_str(), comparison);
    let evidence_group_hashes = comparison
        .groups
        .iter()
        .map(|group| group.canonical_key_sha256.clone())
        .collect::<Vec<_>>();
    let waiver_id = if class == DifferentialDivergenceClass::IntentionalSecurityDivergence {
        Some(stable_waiver_id(comparison, &evidence_group_hashes))
    } else {
        None
    };

    DifferentialDivergenceFinding {
        class,
        comparison_mode: comparison.mode,
        message: divergence_message(comparison),
        affected_backends: comparison.applicable_backends.clone(),
        reference_backends: comparison
            .applicable_backends
            .iter()
            .copied()
            .filter(is_reference_backend)
            .collect(),
        evidence_group_hashes,
        remediation_hint: remediation_hint(class).to_string(),
        waiver_id,
    }
}

fn divergence_message(comparison: &DifferentialModeComparison) -> String {
    let groups = comparison
        .groups
        .iter()
        .map(|group| {
            format!(
                "{}=[{}]",
                abbreviate(group.sample.as_str()),
                group
                    .backends
                    .iter()
                    .map(|backend| backend.stable_label())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "{} divergence across {} backend group(s): {}",
        comparison.mode.stable_label(),
        comparison.groups.len(),
        groups
    )
}

fn divergence_evidence_text(
    receipts: &[DifferentialBackendReceipt],
    comparison: &DifferentialModeComparison,
) -> String {
    let mut evidence = String::new();
    evidence.push_str(comparison.mode.stable_label());
    for group in &comparison.groups {
        evidence.push(' ');
        evidence.push_str(group.sample.as_str());
        evidence.push(' ');
        evidence.push_str(group.canonical_key_sha256.as_str());
    }
    for receipt in receipts {
        if !comparison.applicable_backends.contains(&receipt.backend) {
            continue;
        }
        evidence.push(' ');
        evidence.push_str(receipt.backend.stable_label());
        evidence.push(' ');
        evidence.push_str(receipt.status.stable_label());
        evidence.push(' ');
        evidence.push_str(receipt.stderr.as_str());
        evidence.push(' ');
        evidence.push_str(receipt.stdout.as_str());
        evidence.push(' ');
        evidence.push_str(receipt.diagnostics.join(" ").as_str());
    }
    evidence.to_ascii_lowercase()
}

fn classify_divergence_evidence(
    evidence: &str,
    comparison: &DifferentialModeComparison,
) -> DifferentialDivergenceClass {
    if contains_any(
        evidence,
        &[
            "intentional-security",
            "intentional_security",
            "security divergence",
            "security-divergence",
        ],
    ) {
        return DifferentialDivergenceClass::IntentionalSecurityDivergence;
    }
    if contains_any(
        evidence,
        &[
            "hostcall",
            "host call",
            "capability",
            "policy",
            "permission",
            "denied",
            "egress",
            "filesystem",
            "processspawn",
            "cross_zone",
        ],
    ) {
        return DifferentialDivergenceClass::HostcallPolicy;
    }
    if contains_any(
        evidence,
        &[
            "module",
            "import",
            "require",
            "resolution",
            "resolve",
            "not found",
        ],
    ) {
        return DifferentialDivergenceClass::ModuleResolution;
    }
    if contains_any(
        evidence,
        &[
            "parse",
            "parser",
            "syntax",
            "unexpected token",
            "unterminated",
        ],
    ) {
        return DifferentialDivergenceClass::Parser;
    }
    if contains_any(
        evidence,
        &["lower", "lowering", "ir2", "ir3", "ir contract"],
    ) {
        return DifferentialDivergenceClass::Lowering;
    }
    if reference_runtimes_disagree_while_franken_agrees(comparison) {
        return DifferentialDivergenceClass::ReferenceRuntimeBug;
    }
    DifferentialDivergenceClass::Runtime
}

fn reference_runtimes_disagree_while_franken_agrees(
    comparison: &DifferentialModeComparison,
) -> bool {
    let franken_group = comparison.groups.iter().find(|group| {
        group.backends.contains(&DifferentialBackend::FrankenEngine)
            && group.backends.contains(&DifferentialBackend::FrankenCore)
    });
    let Some(franken_group) = franken_group else {
        return false;
    };
    let reference_group_count = comparison
        .groups
        .iter()
        .filter(|group| group.backends.iter().any(is_reference_backend))
        .count();
    reference_group_count > 1
        && comparison
            .groups
            .iter()
            .any(|group| group.canonical_key_sha256 != franken_group.canonical_key_sha256)
}

fn is_reference_backend(backend: &DifferentialBackend) -> bool {
    matches!(
        backend,
        DifferentialBackend::NodeLts | DifferentialBackend::BunStable
    )
}

fn stable_waiver_id(
    comparison: &DifferentialModeComparison,
    evidence_group_hashes: &[String],
) -> String {
    let joined_hashes = evidence_group_hashes.join(":");
    let digest =
        sha256_hex(format!("{}:{joined_hashes}", comparison.mode.stable_label()).as_bytes());
    format!("differential-oracle-waiver-{}", &digest[..16])
}

fn remediation_hint(class: DifferentialDivergenceClass) -> &'static str {
    match class {
        DifferentialDivergenceClass::Parser => {
            "Minimize the source and compare parser diagnostics and source spans before runtime triage."
        }
        DifferentialDivergenceClass::Lowering => {
            "Inspect lowering_pipeline and ir_contract output for a semantic translation mismatch."
        }
        DifferentialDivergenceClass::Runtime => {
            "Minimize the case and compare evaluator/runtime instruction handling against the canonical observations."
        }
        DifferentialDivergenceClass::ModuleResolution => {
            "Check module loader and resolution policy before classifying the runtime as semantically wrong."
        }
        DifferentialDivergenceClass::HostcallPolicy => {
            "Inspect hostcall, capability, and IFC policy receipts; add an explicit waiver only for intended denials."
        }
        DifferentialDivergenceClass::IntentionalSecurityDivergence => {
            "Verify the waiver id, document the intentional security divergence, and keep it out of bug counts."
        }
        DifferentialDivergenceClass::ReferenceRuntimeBug => {
            "Confirm reference runtime versions and isolate the denominator behavior before opening an engine defect."
        }
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn canonicalize_backend_receipt(
    receipt: &DifferentialBackendReceipt,
) -> DifferentialCanonicalObservation {
    let canonical_stdout = canonicalize_stream(receipt.stdout.as_str());
    let canonical_stderr = canonicalize_stream(receipt.stderr.as_str());
    let structured_value = canonical_structured_value(receipt, canonical_stdout.as_str());
    let (exception_kind, exception_message_class) = canonical_exception(receipt);

    DifferentialCanonicalObservation {
        backend: receipt.backend,
        status: receipt.status,
        canonical_stdout,
        canonical_stderr,
        structured_value,
        exception_kind,
        exception_message_class,
        timing_envelope: timing_envelope(receipt.duration_micros),
    }
}

fn build_mode_comparison(
    mode: DifferentialComparisonMode,
    observations: &[DifferentialCanonicalObservation],
) -> DifferentialModeComparison {
    let mut applicable_backends = Vec::new();
    let mut ignored_backends = Vec::new();
    let mut groups: BTreeMap<String, (String, Vec<DifferentialBackend>)> = BTreeMap::new();

    for observation in observations {
        match comparison_entry(mode, observation) {
            Some((key, sample)) => {
                applicable_backends.push(observation.backend);
                groups
                    .entry(key)
                    .or_insert_with(|| (sample, Vec::new()))
                    .1
                    .push(observation.backend);
            }
            None => ignored_backends.push(observation.backend),
        }
    }

    let groups = groups
        .into_iter()
        .map(|(key, (sample, backends))| DifferentialCanonicalGroup {
            canonical_key_sha256: sha256_hex(key.as_bytes()),
            sample,
            backends,
        })
        .collect::<Vec<_>>();
    let verdict = if applicable_backends.len() < 2 {
        DifferentialComparisonVerdict::InsufficientData
    } else if groups.len() == 1 {
        DifferentialComparisonVerdict::Consensus
    } else {
        DifferentialComparisonVerdict::Divergence
    };

    DifferentialModeComparison {
        mode,
        verdict,
        applicable_backends,
        ignored_backends,
        groups,
    }
}

fn comparison_entry(
    mode: DifferentialComparisonMode,
    observation: &DifferentialCanonicalObservation,
) -> Option<(String, String)> {
    match mode {
        DifferentialComparisonMode::StructuredValue => {
            observation.structured_value.as_ref().map(|value| {
                let sample = abbreviate(value);
                (format!("structured_value:{value}"), sample)
            })
        }
        DifferentialComparisonMode::ExactStdout => {
            if observation.status == DifferentialBackendStatus::Completed {
                Some((
                    format!("stdout:{}", observation.canonical_stdout),
                    abbreviate(observation.canonical_stdout.as_str()),
                ))
            } else {
                None
            }
        }
        DifferentialComparisonMode::ExactStderr => {
            if observation.canonical_stderr.is_empty() {
                None
            } else {
                Some((
                    format!("stderr:{}", observation.canonical_stderr),
                    abbreviate(observation.canonical_stderr.as_str()),
                ))
            }
        }
        DifferentialComparisonMode::ExceptionClass => {
            if observation.status == DifferentialBackendStatus::Failed {
                let kind = observation
                    .exception_kind
                    .as_deref()
                    .unwrap_or("unknown_exception");
                let message_class = observation
                    .exception_message_class
                    .as_deref()
                    .unwrap_or("unknown_message");
                Some((
                    format!("exception:{kind}:{message_class}"),
                    format!("{kind}:{message_class}"),
                ))
            } else {
                None
            }
        }
        DifferentialComparisonMode::TimingEnvelope => {
            if matches!(
                observation.status,
                DifferentialBackendStatus::Completed | DifferentialBackendStatus::Failed
            ) && observation.timing_envelope.duration_micros > 0
            {
                Some((
                    format!("timing:{}", observation.timing_envelope.bucket),
                    observation.timing_envelope.bucket.clone(),
                ))
            } else {
                None
            }
        }
    }
}

fn summarize_semantic_verdict(
    comparisons: &[DifferentialModeComparison],
) -> DifferentialComparisonVerdict {
    let semantic = comparisons
        .iter()
        .filter(|comparison| comparison.mode.contributes_to_semantic_verdict())
        .filter(|comparison| comparison.verdict != DifferentialComparisonVerdict::InsufficientData)
        .collect::<Vec<_>>();

    if semantic
        .iter()
        .any(|comparison| comparison.verdict == DifferentialComparisonVerdict::Divergence)
    {
        DifferentialComparisonVerdict::Divergence
    } else if semantic
        .iter()
        .any(|comparison| comparison.verdict == DifferentialComparisonVerdict::Consensus)
    {
        DifferentialComparisonVerdict::Consensus
    } else {
        DifferentialComparisonVerdict::InsufficientData
    }
}

fn canonical_structured_value(
    receipt: &DifferentialBackendReceipt,
    canonical_stdout: &str,
) -> Option<String> {
    if receipt.status != DifferentialBackendStatus::Completed {
        return None;
    }
    // Prefer the program's observable console output (matching the `node -e` /
    // `bun -e` subprocess model the external backends use); fall back to an
    // explicit completion value only when nothing was printed (e.g. a bare
    // expression that the in-process lanes can still report a value for).
    infer_single_stdout_value(canonical_stdout)
        .or(receipt.value.as_deref())
        .map(canonicalize_js_value)
}

fn infer_single_stdout_value(canonical_stdout: &str) -> Option<&str> {
    let mut non_empty_lines = canonical_stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let first = non_empty_lines.next()?;
    if non_empty_lines.next().is_some() {
        None
    } else {
        Some(first)
    }
}

fn canonical_exception(receipt: &DifferentialBackendReceipt) -> (Option<String>, Option<String>) {
    if receipt.status != DifferentialBackendStatus::Failed {
        return (None, None);
    }

    if let Some(namespace) = receipt
        .diagnostics
        .iter()
        .find(|entry| entry.starts_with("eval."))
    {
        return (Some(namespace.to_string()), Some(namespace.to_string()));
    }

    let first_line = receipt
        .stderr
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !is_stack_trace_line(line))
        .unwrap_or_else(|| receipt.stderr.trim());
    if first_line.is_empty() {
        return (
            Some("process_failure".to_string()),
            Some("empty_stderr".to_string()),
        );
    }

    let (kind, message) = first_line
        .split_once(':')
        .map(|(kind, message)| (kind.trim(), message.trim()))
        .unwrap_or(("process_failure", first_line));
    (
        Some(canonicalize_exception_kind(kind)),
        Some(canonicalize_message_class(message)),
    )
}

fn canonicalize_stream(value: &str) -> String {
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    normalized.trim_end_matches(['\n', '\t', ' ']).to_string()
}

fn canonicalize_js_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "empty".to_string();
    }

    let lowercase = trimmed.to_ascii_lowercase();
    match lowercase.as_str() {
        "undefined" | "null" | "true" | "false" | "nan" | "infinity" | "-infinity" => {
            return lowercase;
        }
        _ => {}
    }

    if let Ok(number) = trimmed.parse::<f64>()
        && number.is_finite()
    {
        if number.fract() == 0.0 {
            return format!("{number:.0}");
        }
        return number.to_string();
    }

    strip_matching_quotes(trimmed)
        .map(str::to_string)
        .unwrap_or_else(|| trimmed.to_string())
}

fn strip_matching_quotes(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"'))
    {
        value.get(1..value.len() - 1)
    } else {
        None
    }
}

fn canonicalize_exception_kind(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "process_failure".to_string();
    }
    let mut normalized = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
        } else if !normalized.ends_with('_') {
            normalized.push('_');
        }
    }
    normalized.trim_matches('_').to_string()
}

fn canonicalize_message_class(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut previous_was_separator = false;
    let mut in_quote = false;
    let mut quote_char = '\0';
    for ch in value.trim().chars() {
        if in_quote {
            if ch == quote_char {
                in_quote = false;
            }
            if !previous_was_separator {
                normalized.push('_');
                previous_was_separator = true;
            }
            continue;
        }
        if ch == '\'' || ch == '"' || ch == '`' {
            in_quote = true;
            quote_char = ch;
            if !previous_was_separator {
                normalized.push('_');
                previous_was_separator = true;
            }
            continue;
        }
        if ch.is_ascii_digit() {
            if !previous_was_separator {
                normalized.push('#');
                previous_was_separator = true;
            }
            continue;
        }
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            previous_was_separator = false;
        } else if !previous_was_separator {
            normalized.push('_');
            previous_was_separator = true;
        }
    }
    let normalized = normalized.trim_matches('_');
    if normalized.is_empty() {
        "empty_message".to_string()
    } else {
        normalized.to_string()
    }
}

fn is_stack_trace_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("at ")
        || trimmed.starts_with("at:")
        || trimmed.starts_with("node:")
        || trimmed.contains(".js:")
}

fn timing_envelope(duration_micros: u128) -> DifferentialTimingEnvelope {
    let tolerance_micros = (duration_micros / 10).max(1_000);
    DifferentialTimingEnvelope {
        duration_micros,
        tolerance_micros,
        lower_micros: duration_micros.saturating_sub(tolerance_micros),
        upper_micros: duration_micros.saturating_add(tolerance_micros),
        bucket: timing_bucket(duration_micros).to_string(),
    }
}

fn timing_bucket(duration_micros: u128) -> &'static str {
    match duration_micros {
        0..=999 => "lt_1ms",
        1_000..=4_999 => "1ms_to_5ms",
        5_000..=24_999 => "5ms_to_25ms",
        25_000..=99_999 => "25ms_to_100ms",
        100_000..=999_999 => "100ms_to_1s",
        _ => "gte_1s",
    }
}

fn abbreviate(value: &str) -> String {
    const MAX_CHARS: usize = 160;
    let mut chars = value.chars();
    let prefix = chars.by_ref().take(MAX_CHARS).collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}...")
    } else {
        prefix
    }
}

pub(crate) enum VersionProbe {
    Available(String),
    Unavailable(String),
}

pub(crate) fn capture_external_version(
    spec: &ExternalRuntimeSpec,
    timeout: Duration,
) -> VersionProbe {
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

pub(crate) struct TimedCommandOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) duration_micros: u128,
    pub(crate) timed_out: bool,
}

pub(crate) fn run_command_with_timeout<'a>(
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

pub(crate) fn capture_host_facts() -> DifferentialHostFacts {
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

pub(crate) fn current_unix_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
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
    fn franken_engine_backend_surfaces_console_output_as_stdout() {
        // Regression (bd-fqlfw.2.4): a program whose only observable is
        // `console.log` must report that console output as stdout — matching the
        // `node -e` / `bun -e` subprocess backends — rather than its `undefined`
        // completion value, otherwise the cross-runtime structured-value
        // comparison can never reach consensus and no case enters the denominator.
        let engine = run_franken_engine_backend("console.log(1 + 1);", Some(2_000_000_000));
        assert_eq!(engine.status, DifferentialBackendStatus::Completed);
        assert_eq!(engine.stdout, "2\n");
        assert_eq!(engine.stdout_sha256, sha256_hex(b"2\n"));

        // The engine now shares a structured-value group with a node-style
        // stdout-only receipt for the same printed value.
        let report = canonicalize_backend_receipts(&[
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Completed,
                None,
                "2\n",
                "",
                &[],
            ),
            engine,
        ]);
        let structured = comparison(&report, DifferentialComparisonMode::StructuredValue);
        assert_eq!(structured.verdict, DifferentialComparisonVerdict::Consensus);
        assert_eq!(structured.groups.len(), 1);
        assert!(
            structured.groups[0]
                .backends
                .contains(&DifferentialBackend::FrankenEngine)
        );
        assert!(
            structured.groups[0]
                .backends
                .contains(&DifferentialBackend::NodeLts)
        );
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

    #[test]
    fn canonicalization_matches_cosmetic_stdout_and_value_differences() {
        let report = canonicalize_backend_receipts(&[
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Completed,
                None,
                "2\r\n",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenEngine,
                DifferentialBackendStatus::Completed,
                Some("2.0"),
                "2",
                "",
                &[],
            ),
        ]);

        assert_eq!(
            report.semantic_verdict,
            DifferentialComparisonVerdict::Consensus
        );
        let structured = comparison(&report, DifferentialComparisonMode::StructuredValue);
        assert_eq!(structured.verdict, DifferentialComparisonVerdict::Consensus);
        assert_eq!(structured.groups.len(), 1);
        assert_eq!(
            structured.groups[0].backends,
            vec![
                DifferentialBackend::NodeLts,
                DifferentialBackend::FrankenEngine
            ]
        );
    }

    #[test]
    fn canonicalization_detects_real_structured_value_divergence() {
        let report = canonicalize_backend_receipts(&[
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Completed,
                None,
                "2\n",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenEngine,
                DifferentialBackendStatus::Completed,
                Some("3"),
                "3",
                "",
                &[],
            ),
        ]);

        assert_eq!(
            report.semantic_verdict,
            DifferentialComparisonVerdict::Divergence
        );
        let structured = comparison(&report, DifferentialComparisonMode::StructuredValue);
        assert_eq!(
            structured.verdict,
            DifferentialComparisonVerdict::Divergence
        );
        assert_eq!(structured.groups.len(), 2);
    }

    #[test]
    fn canonicalization_matches_equivalent_exception_shapes() {
        let report = canonicalize_backend_receipts(&[
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Failed,
                None,
                "",
                "TypeError: Cannot read property 'x' of undefined\n    at fixture.js:1:7\n",
                &[],
            ),
            receipt(
                DifferentialBackend::BunStable,
                DifferentialBackendStatus::Failed,
                None,
                "",
                "TypeError: Cannot read property \"y\" of undefined\n    at bun:internal\n",
                &[],
            ),
        ]);

        assert_eq!(
            report.semantic_verdict,
            DifferentialComparisonVerdict::Consensus
        );
        let exceptions = comparison(&report, DifferentialComparisonMode::ExceptionClass);
        assert_eq!(exceptions.verdict, DifferentialComparisonVerdict::Consensus);
        assert_eq!(exceptions.groups.len(), 1);
    }

    #[test]
    fn canonicalization_detects_exception_kind_divergence() {
        let report = canonicalize_backend_receipts(&[
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Failed,
                None,
                "",
                "TypeError: Cannot read property 'x' of undefined\n",
                &[],
            ),
            receipt(
                DifferentialBackend::BunStable,
                DifferentialBackendStatus::Failed,
                None,
                "",
                "ReferenceError: x is not defined\n",
                &[],
            ),
        ]);

        assert_eq!(
            report.semantic_verdict,
            DifferentialComparisonVerdict::Divergence
        );
        let exceptions = comparison(&report, DifferentialComparisonMode::ExceptionClass);
        assert_eq!(
            exceptions.verdict,
            DifferentialComparisonVerdict::Divergence
        );
        assert_eq!(exceptions.groups.len(), 2);
    }

    #[test]
    fn taxonomy_classifies_structured_value_divergence_as_runtime() {
        let receipts = vec![
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Completed,
                Some("2"),
                "2",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenEngine,
                DifferentialBackendStatus::Completed,
                Some("3"),
                "3",
                "",
                &[],
            ),
        ];
        let canonicalization = canonicalize_backend_receipts(&receipts);
        let taxonomy = classify_differential_divergences(&receipts, &canonicalization);

        assert_eq!(
            taxonomy.schema_version,
            DIFFERENTIAL_ORACLE_DIVERGENCE_TAXONOMY_SCHEMA_VERSION
        );
        assert_eq!(taxonomy.verdict, DifferentialComparisonVerdict::Divergence);
        let finding = taxonomy
            .findings
            .iter()
            .find(|finding| finding.comparison_mode == DifferentialComparisonMode::StructuredValue)
            .expect("structured value divergence should be classified");
        assert_eq!(finding.class, DifferentialDivergenceClass::Runtime);
        assert_eq!(
            finding.affected_backends,
            vec![
                DifferentialBackend::NodeLts,
                DifferentialBackend::FrankenEngine
            ]
        );
        assert!(finding.waiver_id.is_none());
    }

    #[test]
    fn taxonomy_marks_intentional_security_divergence_with_waiver() {
        let receipts = vec![
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Failed,
                None,
                "",
                "TypeError: network is not defined\n",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenEngine,
                DifferentialBackendStatus::Failed,
                None,
                "",
                "PolicyError: intentional-security-divergence hostcall capability denied\n",
                &["intentional-security-divergence.hostcall_policy_denied"],
            ),
        ];
        let canonicalization = canonicalize_backend_receipts(&receipts);
        let taxonomy = classify_differential_divergences(&receipts, &canonicalization);

        let finding = taxonomy
            .findings
            .iter()
            .find(|finding| finding.comparison_mode == DifferentialComparisonMode::ExceptionClass)
            .expect("exception class divergence should be classified");
        assert_eq!(
            finding.class,
            DifferentialDivergenceClass::IntentionalSecurityDivergence
        );
        assert_eq!(
            finding.reference_backends,
            vec![DifferentialBackend::NodeLts]
        );
        assert!(
            finding
                .waiver_id
                .as_deref()
                .is_some_and(|waiver| waiver.starts_with("differential-oracle-waiver-"))
        );
        assert!(finding.remediation_hint.contains("waiver id"));
        assert!(
            taxonomy
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("intentional_security_divergence"))
        );
    }

    #[test]
    fn taxonomy_classifies_reference_runtime_split_when_franken_backends_agree() {
        let receipts = vec![
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Completed,
                Some("2"),
                "2",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::BunStable,
                DifferentialBackendStatus::Completed,
                Some("3"),
                "3",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenEngine,
                DifferentialBackendStatus::Completed,
                Some("2"),
                "2",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenCore,
                DifferentialBackendStatus::Completed,
                Some("2"),
                "2",
                "",
                &[],
            ),
        ];
        let canonicalization = canonicalize_backend_receipts(&receipts);
        let taxonomy = classify_differential_divergences(&receipts, &canonicalization);

        let finding = taxonomy
            .findings
            .iter()
            .find(|finding| finding.comparison_mode == DifferentialComparisonMode::StructuredValue)
            .expect("structured value divergence should be classified");
        assert_eq!(
            finding.class,
            DifferentialDivergenceClass::ReferenceRuntimeBug
        );
        assert_eq!(
            finding.reference_backends,
            vec![DifferentialBackend::NodeLts, DifferentialBackend::BunStable]
        );
    }

    fn receipt(
        backend: DifferentialBackend,
        status: DifferentialBackendStatus,
        value: Option<&str>,
        stdout: &str,
        stderr: &str,
        diagnostics: &[&str],
    ) -> DifferentialBackendReceipt {
        DifferentialBackendReceipt {
            backend,
            status,
            command: vec![backend.stable_label().to_string()],
            version: Some("test-runtime".to_string()),
            exit_code: Some(if status == DifferentialBackendStatus::Completed {
                0
            } else {
                1
            }),
            duration_micros: 2_500,
            value: value.map(str::to_string),
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            stdout_sha256: sha256_hex(stdout.as_bytes()),
            stderr_sha256: sha256_hex(stderr.as_bytes()),
            diagnostics: diagnostics.iter().map(|entry| entry.to_string()).collect(),
        }
    }

    fn comparison(
        report: &DifferentialCanonicalizationReport,
        mode: DifferentialComparisonMode,
    ) -> &DifferentialModeComparison {
        report
            .comparisons
            .iter()
            .find(|comparison| comparison.mode == mode)
            .unwrap_or_else(|| panic!("missing {mode:?} comparison"))
    }
}
