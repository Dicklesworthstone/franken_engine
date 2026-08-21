//! Differential oracle driver for comparing JavaScript runtime outputs.
//!
//! The driver records a receipt for every requested backend. Missing external
//! runtimes are represented as degraded receipts instead of failing the whole
//! run, which keeps corpus sweeps reproducible on machines without Node or Bun.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::{fd::AsFd, unix::process::CommandExt};
use std::process::{Command, ExitStatus, Stdio};
#[cfg(unix)]
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wait_timeout::ChildExt;

use frankenengine_core::baseline_interpreter::{
    ConsoleEntry as CoreConsoleEntry, ConsoleLevel as CoreConsoleLevel,
    InterpreterConfig as CoreInterpreterConfig, InterpreterError as CoreInterpreterError,
    QuickJsLane as CoreQuickJsLane, Value as CoreValue,
};
use frankenengine_core::capability::RuntimeCapability as CoreRuntimeCapability;
use frankenengine_core::ifc_artifacts::Label as CoreIfcLabel;
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

use crate::{EngineMemoryBudget, EvalErrorCode, HybridRouter, RouteReason};

pub const DIFFERENTIAL_ORACLE_SCHEMA_VERSION: &str = "franken-engine.differential-oracle.v1";
pub const DIFFERENTIAL_ORACLE_CANONICALIZATION_SCHEMA_VERSION: &str =
    "franken-engine.differential-oracle.canonicalization.v2";
const DIFFERENTIAL_ORACLE_CANONICALIZATION_SCHEMA_VERSION_V1: &str =
    "franken-engine.differential-oracle.canonicalization.v1";
pub const DIFFERENTIAL_ORACLE_DIVERGENCE_TAXONOMY_SCHEMA_VERSION: &str =
    "franken-engine.differential-oracle.divergence-taxonomy.v2";

const DEFAULT_TIMEOUT_MS: u64 = 2_000;
const MAX_CAPTURED_STREAM_BYTES: u64 = 4 * 1024 * 1024;
#[cfg(unix)]
const OUTPUT_DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(2);
#[cfg(unix)]
const OUTPUT_DRAIN_EXIT_GRACE: Duration = Duration::from_millis(50);
#[cfg(unix)]
const OUTPUT_DRAIN_TEARDOWN_GRACE: Duration = Duration::from_millis(250);

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
    /// Override for the engine lane's heap-object budget (max live heap
    /// objects). The deterministic containment default (100k) trips on
    /// object-allocating benchmark loops because the interpreter heap is
    /// append-only (no live-object reclamation), so the count is total
    /// allocations. Corpus sweeps raise this so memory-heavy workloads measure
    /// throughput rather than the containment ceiling. The byte ceiling is
    /// derived proportionally (see [`engine_memory_budget_from_heap_objects`]).
    /// Recorded in the backend receipt's diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_memory_budget: Option<u64>,
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
            engine_memory_budget: None,
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

    pub fn with_engine_memory_budget(mut self, max_heap_objects: u64) -> Self {
        self.engine_memory_budget = Some(max_heap_objects);
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

fn is_reference_backend(backend: &DifferentialBackend) -> bool {
    matches!(
        backend,
        DifferentialBackend::NodeLts | DifferentialBackend::BunStable
    )
}

fn is_franken_backend(backend: &DifferentialBackend) -> bool {
    matches!(
        backend,
        DifferentialBackend::FrankenEngine | DifferentialBackend::FrankenCore
    )
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

/// Trusted base classes produced only by the in-process backend runners.
///
/// This deliberately excludes `IntentionalSecurityDivergence` (which requires
/// separate operator authority) and `ReferenceRuntimeBug` (which requires
/// external attribution authority; guest-visible group structure is evidence,
/// not proof that a reference runtime is at fault).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustedBaseClass {
    Parser,
    Lowering,
    Runtime,
    ModuleResolution,
    HostcallPolicy,
}

impl TrustedBaseClass {
    const fn divergence_class(self) -> DifferentialDivergenceClass {
        match self {
            Self::Parser => DifferentialDivergenceClass::Parser,
            Self::Lowering => DifferentialDivergenceClass::Lowering,
            Self::Runtime => DifferentialDivergenceClass::Runtime,
            Self::ModuleResolution => DifferentialDivergenceClass::ModuleResolution,
            Self::HostcallPolicy => DifferentialDivergenceClass::HostcallPolicy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrankenCoreFailureStage {
    Parse,
    Lower,
    Execute,
}

impl FrankenCoreFailureStage {
    const fn stable_label(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Lower => "lower",
            Self::Execute => "execute",
        }
    }
}

impl std::fmt::Display for FrankenCoreFailureStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.stable_label())
    }
}

/// Non-serialized provenance that exists only between a local backend runner
/// and the immediate taxonomy pass. Guest-visible receipt fields must never be
/// promoted into this signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrustedTaxonomySignal {
    FrankenEngine(EvalErrorCode),
    FrankenCore {
        stage: FrankenCoreFailureStage,
        class: TrustedBaseClass,
    },
}

impl TrustedTaxonomySignal {
    const fn matches_backend(self, backend: DifferentialBackend) -> bool {
        matches!(
            (self, backend),
            (Self::FrankenEngine(_), DifferentialBackend::FrankenEngine)
                | (Self::FrankenCore { .. }, DifferentialBackend::FrankenCore)
        )
    }

    const fn base_class(self) -> TrustedBaseClass {
        match self {
            Self::FrankenEngine(code) => match code {
                EvalErrorCode::EmptySource | EvalErrorCode::ParseFailure => {
                    TrustedBaseClass::Parser
                }
                EvalErrorCode::ResolutionFailure => TrustedBaseClass::ModuleResolution,
                EvalErrorCode::PolicyDenied
                | EvalErrorCode::CapabilityDenied
                | EvalErrorCode::HostcallFault => TrustedBaseClass::HostcallPolicy,
                EvalErrorCode::RuntimeFault | EvalErrorCode::InvariantViolation => {
                    TrustedBaseClass::Runtime
                }
            },
            Self::FrankenCore { stage, class } => match stage {
                FrankenCoreFailureStage::Parse => TrustedBaseClass::Parser,
                FrankenCoreFailureStage::Lower => TrustedBaseClass::Lowering,
                FrankenCoreFailureStage::Execute => class,
            },
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
    /// IFC provenance of the completion value when an in-process backend
    /// exposes it. Historical receipts and external runtimes omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_label: Option<CoreIfcLabel>,
    /// Exact UTF-16 code units of the completion value, present iff it is a
    /// string containing lone surrogates (bd-2vzgi). `value` then carries the
    /// lossy U+FFFD projection, which collapses distinct lone surrogates (and
    /// a lone surrogate vs a literal U+FFFD) into identical strings; the
    /// canonical comparison keys on the (projection, units) pair so those
    /// stay distinct. Absent for every well-formed observable, keeping the
    /// serialized receipt byte-identical for them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_wtf16: Option<Vec<u16>>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

/// A receipt paired with local-only taxonomy provenance. The sidecar is never
/// serialized, so deserializing or mutating a report cannot forge it.
#[derive(Debug, Clone)]
struct BackendExecution {
    receipt: DifferentialBackendReceipt,
    trusted_signal: Option<TrustedTaxonomySignal>,
}

impl BackendExecution {
    fn untrusted(receipt: DifferentialBackendReceipt) -> Self {
        Self {
            receipt,
            trusted_signal: None,
        }
    }

    fn trusted(receipt: DifferentialBackendReceipt, trusted_signal: TrustedTaxonomySignal) -> Self {
        Self {
            receipt,
            trusted_signal: Some(trusted_signal),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferentialComparisonMode {
    StructuredValue,
    ExactStdout,
    ExactStderr,
    ExceptionClass,
    TimingEnvelope,
    /// Top-level completion-provenance agreement between the in-process lanes
    /// (bd-5ilh1). Only backends that report a completion label participate
    /// (engine + core); `node -e`/`bun -e` subprocesses never do. Advisory:
    /// engine and core label inference may legitimately differ in precision,
    /// so this mode reports divergence without deciding the semantic verdict.
    CompletionLabel,
}

impl DifferentialComparisonMode {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::StructuredValue => "structured_value",
            Self::ExactStdout => "exact_stdout",
            Self::ExactStderr => "exact_stderr",
            Self::ExceptionClass => "exception_class",
            Self::TimingEnvelope => "timing_envelope",
            Self::CompletionLabel => "completion_label",
        }
    }

    const fn contributes_to_semantic_verdict(self) -> bool {
        match self {
            Self::StructuredValue | Self::ExceptionClass => true,
            Self::ExactStdout
            | Self::ExactStderr
            | Self::TimingEnvelope
            | Self::CompletionLabel => false,
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
    /// Exact UTF-16 code units backing `structured_value` when the structured
    /// value is the completion value and that value contains lone surrogates
    /// (bd-2vzgi). Participates in the `StructuredValue` comparison key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_value_wtf16: Option<Vec<u16>>,
    /// Completion-provenance label reported by an in-process backend for a
    /// completed run (bd-5ilh1). Participates in the `CompletionLabel`
    /// comparison; external subprocess lanes never populate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_label: Option<CoreIfcLabel>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct DifferentialCanonicalGroupScope {
    canonical_key_sha256: String,
    backends: Vec<DifferentialBackend>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DifferentialDivergenceKey {
    comparison_mode: DifferentialComparisonMode,
    base_class: DifferentialDivergenceClass,
    groups: Vec<DifferentialCanonicalGroupScope>,
    ignored_backends: Vec<DifferentialBackend>,
}

impl DifferentialDivergenceKey {
    fn from_live_comparison(
        finding: &DifferentialDivergenceFinding,
        comparison: &DifferentialModeComparison,
    ) -> Option<Self> {
        if comparison.verdict != DifferentialComparisonVerdict::Divergence
            || comparison.mode != finding.comparison_mode
            || comparison.mode == DifferentialComparisonMode::TimingEnvelope
            || matches!(
                finding.class,
                DifferentialDivergenceClass::IntentionalSecurityDivergence
                    | DifferentialDivergenceClass::ReferenceRuntimeBug
            )
        {
            return None;
        }

        let mut affected_backends = comparison.applicable_backends.clone();
        affected_backends.sort_unstable();
        affected_backends.dedup();
        let mut finding_backends = finding.affected_backends.clone();
        finding_backends.sort_unstable();
        finding_backends.dedup();
        if affected_backends != finding_backends
            || !affected_backends.iter().any(is_reference_backend)
            || !affected_backends.iter().any(is_franken_backend)
        {
            return None;
        }

        let reference_backends = affected_backends
            .iter()
            .copied()
            .filter(is_reference_backend)
            .collect::<Vec<_>>();
        let mut finding_reference_backends = finding.reference_backends.clone();
        finding_reference_backends.sort_unstable();
        finding_reference_backends.dedup();
        if reference_backends != finding_reference_backends {
            return None;
        }

        let mut groups = comparison
            .groups
            .iter()
            .map(|group| {
                let mut backends = group.backends.clone();
                backends.sort_unstable();
                backends.dedup();
                DifferentialCanonicalGroupScope {
                    canonical_key_sha256: group.canonical_key_sha256.clone(),
                    backends,
                }
            })
            .collect::<Vec<_>>();
        groups.sort_by(|left, right| {
            left.canonical_key_sha256
                .cmp(&right.canonical_key_sha256)
                .then_with(|| left.backends.cmp(&right.backends))
        });
        if groups.len() < 2
            || groups.iter().any(|group| {
                normalize_sha256(group.canonical_key_sha256.as_str()).is_none()
                    || group.backends.is_empty()
            })
        {
            return None;
        }

        let mut grouped_backends = groups
            .iter()
            .flat_map(|group| group.backends.iter().copied())
            .collect::<Vec<_>>();
        grouped_backends.sort_unstable();
        grouped_backends.dedup();
        let mut evidence_group_hashes = groups
            .iter()
            .map(|group| group.canonical_key_sha256.clone())
            .collect::<Vec<_>>();
        evidence_group_hashes.sort_unstable();
        let mut finding_evidence_group_hashes = finding.evidence_group_hashes.clone();
        finding_evidence_group_hashes.sort_unstable();
        if grouped_backends != affected_backends
            || evidence_group_hashes != finding_evidence_group_hashes
        {
            return None;
        }

        let mut ignored_backends = comparison.ignored_backends.clone();
        ignored_backends.sort_unstable();
        ignored_backends.dedup();
        Some(Self {
            comparison_mode: finding.comparison_mode,
            base_class: finding.class,
            groups,
            ignored_backends,
        })
    }
}

/// Opaque approval candidate emitted only by a live oracle execution.
///
/// Its private scope binds the actual source bytes, typed base classification,
/// and exact canonical hash-to-backend group topology. It is deliberately not
/// serializable or constructible from a stored report.
#[derive(Debug, Clone)]
pub struct DifferentialWaiverCandidate {
    source_sha256: String,
    key: DifferentialDivergenceKey,
    finding: DifferentialDivergenceFinding,
}

impl DifferentialWaiverCandidate {
    pub fn source_sha256(&self) -> &str {
        self.source_sha256.as_str()
    }

    pub fn finding(&self) -> &DifferentialDivergenceFinding {
        &self.finding
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DifferentialSecurityWaiver {
    waiver_id: String,
    source_sha256: String,
    key: DifferentialDivergenceKey,
    reason: String,
    approved_by: String,
    tracking_bead: String,
}

/// In-memory authority for explicitly approved intentional security
/// divergences.
///
/// This trust root is intentionally neither serializable nor deserializable.
/// Output hashes bind an approval's scope, but never create an approval.
#[derive(Debug, Default)]
pub struct DifferentialWaiverAuthority {
    waivers: Vec<DifferentialSecurityWaiver>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DifferentialWaiverAuthorityError {
    EmptyField(&'static str),
    InvalidSourceSha256,
    ConflictingWaiver,
}

impl std::fmt::Display for DifferentialWaiverAuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "waiver authority field `{field}` is empty"),
            Self::InvalidSourceSha256 => {
                f.write_str("waiver authority source_sha256 is not a 64-digit hexadecimal hash")
            }
            Self::ConflictingWaiver => {
                f.write_str("waiver id or divergence scope conflicts with an existing approval")
            }
        }
    }
}

impl std::error::Error for DifferentialWaiverAuthorityError {}

impl DifferentialWaiverAuthority {
    pub fn new() -> Self {
        Self::default()
    }

    /// Explicitly authorize one live, already-classified divergence as intentional.
    ///
    /// The opaque candidate binds the exact source bytes, typed base class,
    /// comparison mode, and canonical hash-to-backend group topology. It cannot
    /// be reconstructed from serialized output or follow a modified source.
    pub fn approve_intentional_security(
        &mut self,
        candidate: &DifferentialWaiverCandidate,
        waiver_id: impl Into<String>,
        reason: impl Into<String>,
        approved_by: impl Into<String>,
        tracking_bead: impl Into<String>,
    ) -> Result<(), DifferentialWaiverAuthorityError> {
        let waiver_id = require_authority_field("waiver_id", waiver_id.into())?;
        let source_sha256 = normalize_sha256(candidate.source_sha256.as_str())
            .ok_or(DifferentialWaiverAuthorityError::InvalidSourceSha256)?;
        let reason = require_authority_field("reason", reason.into())?;
        let approved_by = require_authority_field("approved_by", approved_by.into())?;
        let tracking_bead = require_authority_field("tracking_bead", tracking_bead.into())?;

        let key = candidate.key.clone();
        if let Some(existing) = self.waivers.iter().find(|existing| {
            existing.waiver_id == waiver_id
                || (existing.source_sha256 == source_sha256 && existing.key == key)
        }) {
            return if existing.waiver_id == waiver_id
                && existing.source_sha256 == source_sha256
                && existing.key == key
                && existing.reason == reason
                && existing.approved_by == approved_by
                && existing.tracking_bead == tracking_bead
            {
                Ok(())
            } else {
                Err(DifferentialWaiverAuthorityError::ConflictingWaiver)
            };
        }

        self.waivers.push(DifferentialSecurityWaiver {
            waiver_id,
            source_sha256,
            key,
            reason,
            approved_by,
            tracking_bead,
        });
        Ok(())
    }

    fn waiver_id_for(&self, candidate: &DifferentialWaiverCandidate) -> Option<&str> {
        let source_sha256 = normalize_sha256(candidate.source_sha256.as_str())?;
        self.waivers
            .iter()
            .find(|waiver| waiver.source_sha256 == source_sha256 && waiver.key == candidate.key)
            .map(|waiver| waiver.waiver_id.as_str())
    }
}

fn require_authority_field(
    field: &'static str,
    value: String,
) -> Result<String, DifferentialWaiverAuthorityError> {
    let value = value.trim();
    if value.is_empty() {
        Err(DifferentialWaiverAuthorityError::EmptyField(field))
    } else {
        Ok(value.to_string())
    }
}

fn normalize_sha256(value: &str) -> Option<String> {
    let value = value.trim();
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn is_canonical_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Deserialize)]
struct DifferentialOracleReportWire {
    schema_version: String,
    generated_unix_ns: u128,
    case_id: String,
    #[serde(default)]
    source_path: Option<String>,
    source_sha256: String,
    host: DifferentialHostFacts,
    backends: Vec<DifferentialBackendReceipt>,
    #[serde(rename = "canonicalization")]
    stored_canonicalization: DifferentialCanonicalizationReport,
    #[serde(rename = "divergence_taxonomy")]
    stored_divergence_taxonomy: DifferentialDivergenceTaxonomyReport,
}

impl<'de> Deserialize<'de> for DifferentialOracleReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DifferentialOracleReportWire::deserialize(deserializer)?;
        if wire.schema_version != DIFFERENTIAL_ORACLE_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(format!(
                "unsupported differential-oracle schema `{}`",
                wire.schema_version
            )));
        }
        if !is_canonical_sha256_hex(&wire.source_sha256) {
            return Err(serde::de::Error::custom(
                "differential-oracle source_sha256 is not canonical lowercase sha256 hex",
            ));
        }
        if wire.backends.is_empty()
            || wire
                .backends
                .windows(2)
                .any(|pair| pair[0].backend >= pair[1].backend)
        {
            return Err(serde::de::Error::custom(
                "differential-oracle backends are empty, duplicated, or not in canonical order",
            ));
        }
        let canonicalization_schema = wire.stored_canonicalization.schema_version.as_str();
        if canonicalization_schema != DIFFERENTIAL_ORACLE_CANONICALIZATION_SCHEMA_VERSION
            && canonicalization_schema != DIFFERENTIAL_ORACLE_CANONICALIZATION_SCHEMA_VERSION_V1
        {
            return Err(serde::de::Error::custom(format!(
                "unsupported differential-oracle canonicalization schema `{}`",
                wire.stored_canonicalization.schema_version
            )));
        }
        let taxonomy_schema = wire.stored_divergence_taxonomy.schema_version.as_str();
        if taxonomy_schema != DIFFERENTIAL_ORACLE_DIVERGENCE_TAXONOMY_SCHEMA_VERSION
            && taxonomy_schema != "franken-engine.differential-oracle.divergence-taxonomy.v1"
        {
            return Err(serde::de::Error::custom(format!(
                "unsupported differential-oracle taxonomy schema `{taxonomy_schema}`"
            )));
        }

        let canonicalization = canonicalize_backend_receipts(&wire.backends);
        let expected_stored_canonicalization =
            if canonicalization_schema == DIFFERENTIAL_ORACLE_CANONICALIZATION_SCHEMA_VERSION_V1 {
                canonicalize_backend_receipts_v1(&wire.backends)
            } else {
                canonicalization.clone()
            };
        if expected_stored_canonicalization != wire.stored_canonicalization {
            return Err(serde::de::Error::custom(
                "stored canonicalization does not match recomputation from backend receipts",
            ));
        }
        // Serialized taxonomy is audit evidence, not live provenance. Rebuild
        // the effective taxonomy conservatively; typed sidecars and waiver
        // candidates intentionally cannot survive serialization.
        let divergence_taxonomy =
            classify_differential_divergences(&wire.backends, &canonicalization);
        Ok(Self {
            schema_version: wire.schema_version,
            generated_unix_ns: wire.generated_unix_ns,
            case_id: wire.case_id,
            source_path: wire.source_path,
            source_sha256: wire.source_sha256,
            host: wire.host,
            backends: wire.backends,
            canonicalization,
            divergence_taxonomy,
        })
    }
}

/// One live oracle execution plus the opaque, typed waiver candidates it
/// produced. Stored reports cannot recreate these candidates.
#[derive(Debug, Clone)]
pub struct DifferentialOracleExecution {
    report: DifferentialOracleReport,
    waiver_candidates: Vec<DifferentialWaiverCandidate>,
}

impl DifferentialOracleExecution {
    pub fn report(&self) -> &DifferentialOracleReport {
        &self.report
    }

    pub fn waiver_candidates(&self) -> &[DifferentialWaiverCandidate] {
        self.waiver_candidates.as_slice()
    }

    pub fn into_report(self) -> DifferentialOracleReport {
        self.report
    }

    pub fn into_report_with_authority(
        mut self,
        authority: &DifferentialWaiverAuthority,
    ) -> DifferentialOracleReport {
        for candidate in &self.waiver_candidates {
            let Some(waiver_id) = authority.waiver_id_for(candidate) else {
                continue;
            };
            let Some(finding) =
                self.report
                    .divergence_taxonomy
                    .findings
                    .iter_mut()
                    .find(|finding| {
                        finding.comparison_mode == candidate.finding.comparison_mode
                            && finding.class == candidate.finding.class
                            && finding.affected_backends == candidate.finding.affected_backends
                            && finding.evidence_group_hashes
                                == candidate.finding.evidence_group_hashes
                    })
            else {
                continue;
            };
            finding.class = DifferentialDivergenceClass::IntentionalSecurityDivergence;
            finding.remediation_hint = remediation_hint(finding.class).to_string();
            finding.waiver_id = Some(waiver_id.to_string());
        }
        self.report.divergence_taxonomy.verdict = taxonomy_verdict(
            &self.report.canonicalization,
            &self.report.divergence_taxonomy.findings,
        );
        self.report.divergence_taxonomy.diagnostics =
            taxonomy_diagnostics(&self.report.divergence_taxonomy.findings);
        self.report
    }
}

/// Execute the oracle and retain opaque candidates for a separate explicit
/// waiver-approval step.
pub fn review_differential_oracle(input: &DifferentialOracleInput) -> DifferentialOracleExecution {
    let timeout = Duration::from_millis(input.timeout_ms.max(1));
    // Emit lanes in canonical order regardless of the order the caller requested
    // them, so the report is stable across invocations. Unselected lanes are not
    // executed (no external process is spawned, no interpreter is invoked).
    let mut executions = Vec::with_capacity(input.selected_backends.len());
    if input.backend_selected(DifferentialBackend::NodeLts) {
        executions.push(run_external_backend(
            &input.node,
            input.source.as_str(),
            timeout,
        ));
    }
    if input.backend_selected(DifferentialBackend::BunStable) {
        executions.push(run_external_backend(
            &input.bun,
            input.source.as_str(),
            timeout,
        ));
    }
    if input.backend_selected(DifferentialBackend::FrankenEngine) {
        executions.push(run_franken_engine_backend(
            input.source.as_str(),
            input.engine_instruction_budget,
            input.engine_memory_budget,
        ));
    }
    if input.backend_selected(DifferentialBackend::FrankenCore) {
        executions.push(run_franken_core_backend(
            input.source.as_str(),
            input.engine_instruction_budget,
            input.engine_memory_budget,
        ));
    }

    let backends = executions
        .iter()
        .map(|execution| execution.receipt.clone())
        .collect::<Vec<_>>();
    let canonicalization = canonicalize_backend_receipts(&backends);
    let divergence_taxonomy = classify_differential_divergences_with_trusted_context(
        &backends,
        &canonicalization,
        &executions,
    );
    let source_sha256 = sha256_hex(input.source.as_bytes());
    let waiver_candidates = build_live_waiver_candidates(
        source_sha256.as_str(),
        &divergence_taxonomy,
        &canonicalization,
        &executions,
    );

    DifferentialOracleExecution {
        report: DifferentialOracleReport {
            schema_version: DIFFERENTIAL_ORACLE_SCHEMA_VERSION.to_string(),
            generated_unix_ns: current_unix_ns(),
            case_id: input.case_id.clone(),
            source_path: input.source_path.clone(),
            source_sha256,
            host: capture_host_facts(),
            canonicalization,
            divergence_taxonomy,
            backends,
        },
        waiver_candidates,
    }
}

pub fn run_differential_oracle(input: &DifferentialOracleInput) -> DifferentialOracleReport {
    review_differential_oracle(input).into_report()
}

pub fn run_differential_oracle_with_authority(
    input: &DifferentialOracleInput,
    authority: &DifferentialWaiverAuthority,
) -> DifferentialOracleReport {
    review_differential_oracle(input).into_report_with_authority(authority)
}

fn run_external_backend(
    spec: &ExternalRuntimeSpec,
    source: &str,
    timeout: Duration,
) -> BackendExecution {
    let version = match capture_external_version(spec, timeout) {
        VersionProbe::Available(version) => Some(version),
        VersionProbe::Unavailable(message) => {
            return BackendExecution::untrusted(DifferentialBackendReceipt {
                backend: spec.runtime_id,
                status: DifferentialBackendStatus::Unavailable,
                command: external_eval_command(spec),
                version: None,
                exit_code: None,
                duration_micros: 0,
                value: None,
                completion_label: None,
                value_wtf16: None,
                stdout: String::new(),
                stderr: String::new(),
                stdout_sha256: sha256_hex(b""),
                stderr_sha256: sha256_hex(b""),
                diagnostics: vec![message],
            });
        }
    };

    let command = external_eval_command(spec);
    let timed = run_command_with_timeout(
        spec.program.as_str(),
        spec.eval_args.iter().map(String::as_str).chain([source]),
        timeout,
    );

    BackendExecution::untrusted(match timed {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let status = if output.timed_out {
                DifferentialBackendStatus::Timeout
            } else if output.stdout_truncated || output.stderr_truncated {
                DifferentialBackendStatus::Degraded
            } else if output.status.success() {
                DifferentialBackendStatus::Completed
            } else if output.status.code() == Some(1)
                && canonical_js_exception_line(&stderr).is_some()
            {
                DifferentialBackendStatus::Failed
            } else {
                DifferentialBackendStatus::Degraded
            };
            let mut diagnostics = Vec::new();
            if output.timed_out {
                diagnostics.push(format!(
                    "{} exceeded {}ms timeout and was killed",
                    spec.runtime_id,
                    timeout.as_millis()
                ));
            }
            if output.stdout_truncated {
                diagnostics.push(format!(
                    "{} stdout exceeded the {}-byte capture limit",
                    spec.runtime_id, MAX_CAPTURED_STREAM_BYTES
                ));
            }
            if output.stderr_truncated {
                diagnostics.push(format!(
                    "{} stderr exceeded the {}-byte capture limit",
                    spec.runtime_id, MAX_CAPTURED_STREAM_BYTES
                ));
            }
            if status == DifferentialBackendStatus::Degraded
                && !output.stdout_truncated
                && !output.stderr_truncated
            {
                diagnostics.push(if output.status.code().is_none() {
                    format!(
                        "{} terminated without a comparable runtime exit code",
                        spec.runtime_id
                    )
                } else {
                    format!(
                        "{} exited without a recognized JavaScript exception",
                        spec.runtime_id
                    )
                });
            }
            DifferentialBackendReceipt {
                backend: spec.runtime_id,
                status,
                command,
                version,
                exit_code: output.status.code(),
                duration_micros: output.duration_micros,
                value: None,
                completion_label: None,
                value_wtf16: None,
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
            completion_label: None,
            value_wtf16: None,
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
            // A post-version-probe launch/I/O failure is an infrastructure
            // fault, not a JavaScript exception that can participate in the
            // ExceptionClass semantic domain.
            status: DifferentialBackendStatus::Degraded,
            command,
            version,
            exit_code: None,
            duration_micros: 0,
            value: None,
            completion_label: None,
            value_wtf16: None,
            stdout: String::new(),
            stderr: error.to_string(),
            stdout_sha256: sha256_hex(b""),
            stderr_sha256: sha256_hex(error.to_string().as_bytes()),
            diagnostics: vec![format!("failed to run {}: {error}", spec.runtime_id)],
        },
    })
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

/// Core-lane twin of [`render_console_streams`]: franken-core's console types
/// are a distinct mirror of the engine's, so the same routing is spelled out
/// against the core enums to keep both in-process lanes' observable streams
/// apples-to-apples with the `node -e` / `bun -e` subprocess lanes.
fn render_core_console_streams(entries: &[CoreConsoleEntry]) -> (String, String) {
    let mut stdout = String::new();
    let mut stderr = String::new();
    for entry in entries {
        let target = match entry.level {
            CoreConsoleLevel::Log | CoreConsoleLevel::Info => &mut stdout,
            CoreConsoleLevel::Warn | CoreConsoleLevel::Error => &mut stderr,
        };
        target.push_str(&entry.message);
        target.push('\n');
    }
    (stdout, stderr)
}

/// Bytes of headroom granted per heap object when an operator raises the engine
/// heap-object budget via `--engine-memory-budget`. The interpreter's per-object
/// base footprint estimate is 64 bytes; 1 KiB/object covers objects carrying
/// several string/array properties so the byte ceiling does not silently become
/// the new bottleneck once the count ceiling is raised.
const ENGINE_MEMORY_BUDGET_BYTES_PER_OBJECT: u64 = 1024;
/// Floor for the derived byte ceiling: never drop below the deterministic
/// profile's 64 MiB containment default (`DEFAULT_QUICKJS_MAX_TOTAL_MEMORY_BYTES`).
const ENGINE_MEMORY_BUDGET_MIN_BYTES: u64 = 64 * 1024 * 1024;

/// Derive a full [`EngineMemoryBudget`] from the single operator-facing
/// heap-object ceiling. The byte ceiling is scaled proportionally (and floored
/// at the containment default) so the `--engine-memory-budget` flag is a single,
/// self-consistent lever rather than two coupled numbers the operator must keep
/// in sync.
fn engine_memory_budget_from_heap_objects(max_heap_objects: u64) -> EngineMemoryBudget {
    EngineMemoryBudget {
        max_heap_objects: u32::try_from(max_heap_objects).unwrap_or(u32::MAX),
        max_total_memory_bytes: max_heap_objects
            .saturating_mul(ENGINE_MEMORY_BUDGET_BYTES_PER_OBJECT)
            .max(ENGINE_MEMORY_BUDGET_MIN_BYTES),
    }
}

fn run_franken_engine_backend(
    source: &str,
    instruction_budget: Option<u64>,
    memory_budget: Option<u64>,
) -> BackendExecution {
    let started = Instant::now();
    let mut router = HybridRouter::default();
    let memory_budget_override = memory_budget.map(engine_memory_budget_from_heap_objects);
    let evaluated = router.eval_with_budgets(source, instruction_budget, memory_budget_override);
    let mut budget_diagnostics: Vec<String> = Vec::new();
    if let Some(budget) = instruction_budget {
        budget_diagnostics.push(format!("instruction_budget_override={budget}"));
    }
    if let (Some(objects), Some(budget)) = (memory_budget, memory_budget_override) {
        budget_diagnostics.push(format!(
            "memory_budget_override={objects} heap_objects / {} bytes",
            budget.max_total_memory_bytes
        ));
    }
    match evaluated {
        Ok(outcome) => {
            // The external backends are `node -e` / `bun -e` subprocesses whose
            // only observable is their console stream. Surface the in-process
            // engine's captured `console.*` output the same way so the
            // structured-value comparison is apples-to-apples; the completion
            // `value` is retained as supplementary detail.
            let (stdout, stderr) = render_console_streams(&outcome.console_output);
            let mut diagnostics = vec![format!("route_reason={}", outcome.route_reason)];
            diagnostics.extend(budget_diagnostics.clone());
            BackendExecution::untrusted(DifferentialBackendReceipt {
                backend: DifferentialBackend::FrankenEngine,
                status: DifferentialBackendStatus::Completed,
                command: vec!["franken-engine::HybridRouter::eval".to_string()],
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
                exit_code: Some(0),
                duration_micros: started.elapsed().as_micros(),
                value: Some(outcome.value),
                completion_label: outcome.completion_label.map(core_label_from_engine),
                value_wtf16: outcome.value_wtf16,
                stdout_sha256: sha256_hex(stdout.as_bytes()),
                stderr_sha256: sha256_hex(stderr.as_bytes()),
                stdout,
                stderr,
                diagnostics,
            })
        }
        Err(error) => {
            let stderr = error.to_string();
            let mut diagnostics = vec![error.stable_namespace().to_string()];
            diagnostics.extend(budget_diagnostics);
            let trusted_signal = TrustedTaxonomySignal::FrankenEngine(error.code);
            BackendExecution::trusted(
                DifferentialBackendReceipt {
                    backend: DifferentialBackend::FrankenEngine,
                    status: DifferentialBackendStatus::Failed,
                    command: vec!["franken-engine::HybridRouter::eval".to_string()],
                    version: Some(env!("CARGO_PKG_VERSION").to_string()),
                    exit_code: Some(1),
                    duration_micros: started.elapsed().as_micros(),
                    value: None,
                    completion_label: None,
                    value_wtf16: None,
                    stdout: String::new(),
                    stderr,
                    stdout_sha256: sha256_hex(b""),
                    stderr_sha256: sha256_hex(error.to_string().as_bytes()),
                    diagnostics,
                },
                trusted_signal,
            )
        }
    }
}

/// Project the engine's IFC label onto the core's structurally identical
/// label lattice so both in-process lanes report completion provenance in one
/// vocabulary (bd-5ilh1).
fn core_label_from_engine(label: crate::ifc_artifacts::Label) -> CoreIfcLabel {
    match label {
        crate::ifc_artifacts::Label::Public => CoreIfcLabel::Public,
        crate::ifc_artifacts::Label::Internal => CoreIfcLabel::Internal,
        crate::ifc_artifacts::Label::Confidential => CoreIfcLabel::Confidential,
        crate::ifc_artifacts::Label::Secret => CoreIfcLabel::Secret,
        crate::ifc_artifacts::Label::TopSecret => CoreIfcLabel::TopSecret,
        crate::ifc_artifacts::Label::Custom { name, level } => CoreIfcLabel::Custom { name, level },
    }
}

fn run_franken_core_backend(
    source: &str,
    instruction_budget: Option<u64>,
    memory_budget: Option<u64>,
) -> BackendExecution {
    let started = Instant::now();
    // Mirror the franken-engine lane: surface whichever budget levers were
    // threaded so the receipt records that the secondary core lane honoured the
    // same `--engine-budget` / `--engine-memory-budget` flags (bd-v4oaz).
    let memory_budget_override = memory_budget.map(engine_memory_budget_from_heap_objects);
    let mut budget_diagnostics: Vec<String> = Vec::new();
    if let Some(budget) = instruction_budget {
        budget_diagnostics.push(format!("instruction_budget_override={budget}"));
    }
    if let (Some(objects), Some(budget)) = (memory_budget, memory_budget_override) {
        budget_diagnostics.push(format!(
            "memory_budget_override={objects} heap_objects / {} bytes",
            budget.max_total_memory_bytes
        ));
    }
    match eval_with_franken_core(source, instruction_budget, memory_budget_override) {
        Ok((value, value_wtf16, completion_label, console_output)) => {
            // Mirror the franken-engine lane: the observable stream is what
            // the program printed through `console.*`, exactly like the
            // `node -e` / `bun -e` subprocess lanes. The prior synthesis of
            // stdout from the completion value made `exact_stdout` report a
            // false divergence for every console-free source with a non-empty
            // completion value (bd-n8eta.4.5); the completion `value` is
            // retained as supplementary detail.
            let (stdout, stderr) = render_core_console_streams(&console_output);
            let mut diagnostics = vec![
                "frankenengine-core path dependency executed in-process through parser/lowering/QuickJsLane".to_string(),
            ];
            diagnostics.extend(budget_diagnostics);
            BackendExecution::untrusted(DifferentialBackendReceipt {
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
                completion_label: Some(completion_label),
                value_wtf16,
                stdout_sha256: sha256_hex(stdout.as_bytes()),
                stderr_sha256: sha256_hex(stderr.as_bytes()),
                stdout,
                stderr,
                diagnostics,
            })
        }
        Err(error) => {
            let stderr = format!("{}: {}", error.stage, error.message);
            let mut diagnostics = vec![
                error.semantic_exception_namespace().to_string(),
                format!("frankenengine-core backend failed during {}", error.stage),
                "frankenengine-core path dependency is linked; no fallback lane was used"
                    .to_string(),
            ];
            diagnostics.extend(budget_diagnostics);
            let trusted_signal = TrustedTaxonomySignal::FrankenCore {
                stage: error.stage,
                class: error.class,
            };
            BackendExecution::trusted(
                DifferentialBackendReceipt {
                    backend: DifferentialBackend::FrankenCore,
                    status: DifferentialBackendStatus::Failed,
                    command: vec![
                        "frankenengine_core::parser::CanonicalEs2020Parser::parse_with_options"
                            .to_string(),
                        "frankenengine_core::lowering_pipeline::lower_ir0_to_ir3".to_string(),
                        "frankenengine_core::baseline_interpreter::QuickJsLane::execute"
                            .to_string(),
                    ],
                    version: Some(format!(
                        "frankenengine-core path dependency; frankenengine-engine {}",
                        env!("CARGO_PKG_VERSION")
                    )),
                    exit_code: Some(1),
                    duration_micros: started.elapsed().as_micros(),
                    value: None,
                    completion_label: None,
                    value_wtf16: None,
                    stdout: String::new(),
                    stderr,
                    stdout_sha256: sha256_hex(b""),
                    stderr_sha256: sha256_hex(
                        format!("{}: {}", error.stage, error.message).as_bytes(),
                    ),
                    diagnostics,
                },
                trusted_signal,
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrankenCoreBackendError {
    stage: FrankenCoreFailureStage,
    class: TrustedBaseClass,
    message: String,
}

impl FrankenCoreBackendError {
    fn new(
        stage: FrankenCoreFailureStage,
        class: TrustedBaseClass,
        error: impl std::fmt::Display,
    ) -> Self {
        Self {
            stage,
            class,
            message: error.to_string(),
        }
    }

    fn from_interpreter(error: CoreInterpreterError) -> Self {
        let class = match &error {
            CoreInterpreterError::ModuleResolutionFailed { .. }
            | CoreInterpreterError::ModuleReadFailed { .. } => TrustedBaseClass::ModuleResolution,
            CoreInterpreterError::ModuleParseFailed { .. } => TrustedBaseClass::Parser,
            CoreInterpreterError::ModuleLoweringFailed { .. } => TrustedBaseClass::Lowering,
            CoreInterpreterError::CapabilityDenied { .. }
            | CoreInterpreterError::ContainmentActionRequested { .. }
            | CoreInterpreterError::Terminated { .. } => TrustedBaseClass::HostcallPolicy,
            _ => TrustedBaseClass::Runtime,
        };
        Self::new(FrankenCoreFailureStage::Execute, class, error)
    }

    const fn semantic_exception_namespace(&self) -> &'static str {
        match (self.stage, self.class) {
            (FrankenCoreFailureStage::Parse, _) | (_, TrustedBaseClass::Parser) => {
                "eval.parse.failure"
            }
            (FrankenCoreFailureStage::Lower, _) | (_, TrustedBaseClass::Lowering) => {
                "eval.lowering.failure"
            }
            (_, TrustedBaseClass::ModuleResolution) => "eval.resolution.failure",
            (_, TrustedBaseClass::HostcallPolicy) => "eval.policy.denied",
            (_, TrustedBaseClass::Runtime) => "eval.runtime.fault",
        }
    }
}

/// Evaluate `source` on the franken-core lane, returning the rendered
/// completion value, exact UTF-16 code units when (and only when) the value is
/// a lone-surrogate string that the rendered projection cannot represent, and
/// the completion's IFC label (bd-2vzgi, bd-ur3tk.17).
/// Successful franken-core evaluation: rendered completion value, exact
/// UTF-16 units when the value is a lone-surrogate string, the completion's
/// IFC label, and the captured console transcript.
type FrankenCoreEvaluation = (
    String,
    Option<Vec<u16>>,
    CoreIfcLabel,
    Vec<CoreConsoleEntry>,
);

fn eval_with_franken_core(
    source: &str,
    instruction_budget: Option<u64>,
    memory_budget_override: Option<EngineMemoryBudget>,
) -> Result<FrankenCoreEvaluation, FrankenCoreBackendError> {
    let normalized = source.trim();
    if normalized.is_empty() {
        return Err(FrankenCoreBackendError {
            stage: FrankenCoreFailureStage::Parse,
            class: TrustedBaseClass::Parser,
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
        .map_err(|error| {
            FrankenCoreBackendError::new(
                FrankenCoreFailureStage::Parse,
                TrustedBaseClass::Parser,
                error,
            )
        })?;
    let ir0 = CoreIr0Module::from_syntax_tree(syntax_tree, "<differential-oracle>");
    let lowering_context = CoreLoweringContext::new(
        "trace-differential-franken-core",
        "decision-differential-franken-core",
        "policy-differential-franken-core",
    );
    let mut lowering_output = core_lower_ir0_to_ir3(&ir0, &lowering_context).map_err(|error| {
        FrankenCoreBackendError::new(
            FrankenCoreFailureStage::Lower,
            TrustedBaseClass::Lowering,
            error,
        )
    })?;
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
    // Thread the operator-facing budget levers into the core lane's config so a
    // heavy benchmark program does not trip the 100k QuickJS instruction floor
    // (or the heap-object/byte ceiling) on the secondary lane while the engine
    // lane runs to completion. The heap-object ceiling and its proportional byte
    // ceiling are derived by the same helper the engine lane uses, keeping the
    // single `--engine-memory-budget` lever self-consistent across both lanes
    // (bd-v4oaz).
    if let Some(budget) = instruction_budget {
        config.instruction_budget = budget;
    }
    if let Some(budget) = memory_budget_override {
        config.max_heap_objects = budget.max_heap_objects;
        config.max_total_memory_bytes = budget.max_total_memory_bytes;
    }
    let result = CoreQuickJsLane::with_config(config)
        .execute(&lowering_output.ir3, "trace-differential-franken-core")
        .map_err(FrankenCoreBackendError::from_interpreter)?;
    let value_wtf16 = match &result.value {
        CoreValue::Str(s) if !s.is_well_formed() => Some(s.code_units_vec()),
        _ => None,
    };
    Ok((
        result.value.to_string(),
        value_wtf16,
        result.completion_label,
        result.console_output,
    ))
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
        | CoreIr3Instruction::ConstructWithNewTarget { dst, .. }
        | CoreIr3Instruction::ConstructSuper { dst, .. }
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
    canonicalize_backend_receipts_with_policy(
        receipts,
        DIFFERENTIAL_ORACLE_CANONICALIZATION_SCHEMA_VERSION,
        true,
    )
}

fn canonicalize_backend_receipts_v1(
    receipts: &[DifferentialBackendReceipt],
) -> DifferentialCanonicalizationReport {
    canonicalize_backend_receipts_with_policy(
        receipts,
        DIFFERENTIAL_ORACLE_CANONICALIZATION_SCHEMA_VERSION_V1,
        false,
    )
}

fn canonicalize_backend_receipts_with_policy(
    receipts: &[DifferentialBackendReceipt],
    schema_version: &str,
    require_full_semantic_coverage: bool,
) -> DifferentialCanonicalizationReport {
    let observations = receipts
        .iter()
        .map(|receipt| canonicalize_backend_receipt(receipt, require_full_semantic_coverage))
        .collect::<Vec<_>>();
    let mut distinct_backends = observations
        .iter()
        .map(|observation| observation.backend)
        .collect::<Vec<_>>();
    distinct_backends.sort_unstable();
    distinct_backends.dedup();
    let selected_cohort_is_valid =
        !observations.is_empty() && distinct_backends.len() == observations.len();
    let comparisons = [
        DifferentialComparisonMode::StructuredValue,
        DifferentialComparisonMode::ExactStdout,
        DifferentialComparisonMode::ExactStderr,
        DifferentialComparisonMode::ExceptionClass,
        DifferentialComparisonMode::TimingEnvelope,
        DifferentialComparisonMode::CompletionLabel,
    ]
    .into_iter()
    .map(|mode| {
        build_mode_comparison(
            mode,
            &observations,
            require_full_semantic_coverage,
            selected_cohort_is_valid,
        )
    })
    .collect::<Vec<_>>();
    let semantic_verdict = summarize_semantic_verdict(&comparisons);
    let mut diagnostics = observations
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
    if require_full_semantic_coverage
        && semantic_verdict == DifferentialComparisonVerdict::InsufficientData
    {
        let status_domain = if !selected_cohort_is_valid {
            None
        } else if observations
            .iter()
            .all(|observation| observation.status == DifferentialBackendStatus::Completed)
        {
            Some(DifferentialComparisonMode::StructuredValue)
        } else if observations
            .iter()
            .all(|observation| observation.status == DifferentialBackendStatus::Failed)
        {
            Some(DifferentialComparisonMode::ExceptionClass)
        } else {
            None
        };
        diagnostics.push(match (selected_cohort_is_valid, status_domain) {
            (false, _) => "selected backend cohort is empty or contains duplicate backend identities; semantic verdict is insufficient_data"
                .to_string(),
            (true, Some(mode)) => format!(
                "{} comparison did not cover at least two and every selected backend; semantic verdict is insufficient_data",
                mode.stable_label()
            ),
            (true, None) => "selected backends do not share one comparable semantic status domain; semantic verdict is insufficient_data"
                .to_string(),
        });
    }

    DifferentialCanonicalizationReport {
        schema_version: schema_version.to_string(),
        semantic_verdict,
        observations,
        comparisons,
        diagnostics,
    }
}

pub fn classify_differential_divergences(
    receipts: &[DifferentialBackendReceipt],
    _canonicalization: &DifferentialCanonicalizationReport,
) -> DifferentialDivergenceTaxonomyReport {
    // The public receipt classifier is an untrusted-input boundary. Recompute
    // canonicalization so a caller cannot supply forged groups or verdicts.
    let canonicalization = canonicalize_backend_receipts(receipts);
    classify_differential_divergences_with_trusted_context(receipts, &canonicalization, &[])
}

fn classify_differential_divergences_with_trusted_context(
    _receipts: &[DifferentialBackendReceipt],
    canonicalization: &DifferentialCanonicalizationReport,
    executions: &[BackendExecution],
) -> DifferentialDivergenceTaxonomyReport {
    let findings = canonicalization
        .comparisons
        .iter()
        .filter(|comparison| comparison.verdict == DifferentialComparisonVerdict::Divergence)
        .map(|comparison| classify_mode_divergence(comparison, executions))
        .collect::<Vec<_>>();
    taxonomy_report(canonicalization, findings)
}

fn taxonomy_report(
    canonicalization: &DifferentialCanonicalizationReport,
    findings: Vec<DifferentialDivergenceFinding>,
) -> DifferentialDivergenceTaxonomyReport {
    let verdict = taxonomy_verdict(canonicalization, &findings);
    let diagnostics = taxonomy_diagnostics(&findings);

    DifferentialDivergenceTaxonomyReport {
        schema_version: DIFFERENTIAL_ORACLE_DIVERGENCE_TAXONOMY_SCHEMA_VERSION.to_string(),
        verdict,
        findings,
        diagnostics,
    }
}

fn taxonomy_verdict(
    canonicalization: &DifferentialCanonicalizationReport,
    findings: &[DifferentialDivergenceFinding],
) -> DifferentialComparisonVerdict {
    if canonicalization.semantic_verdict == DifferentialComparisonVerdict::InsufficientData {
        DifferentialComparisonVerdict::InsufficientData
    } else if findings.is_empty() {
        canonicalization.semantic_verdict
    } else if findings.iter().any(|finding| {
        finding.comparison_mode.contributes_to_semantic_verdict()
            && finding.class != DifferentialDivergenceClass::IntentionalSecurityDivergence
    }) {
        DifferentialComparisonVerdict::Divergence
    } else {
        canonicalization.semantic_verdict
    }
}

fn taxonomy_diagnostics(findings: &[DifferentialDivergenceFinding]) -> Vec<String> {
    findings
        .iter()
        .filter_map(|finding| {
            finding.waiver_id.as_deref().map(|waiver_id| {
                format!(
                    "{} authorized by waiver `{waiver_id}`",
                    finding.class.stable_label()
                )
            })
        })
        .collect()
}

fn build_live_waiver_candidates(
    source_sha256: &str,
    taxonomy: &DifferentialDivergenceTaxonomyReport,
    canonicalization: &DifferentialCanonicalizationReport,
    executions: &[BackendExecution],
) -> Vec<DifferentialWaiverCandidate> {
    if taxonomy.verdict != DifferentialComparisonVerdict::Divergence {
        return Vec::new();
    }
    taxonomy
        .findings
        .iter()
        .filter_map(|finding| {
            let comparison = canonicalization
                .comparisons
                .iter()
                .find(|comparison| comparison.mode == finding.comparison_mode)?;
            let trusted_class = trusted_base_class_for_divergence(executions, comparison)?;
            if trusted_class.divergence_class() != finding.class {
                return None;
            }
            let key = DifferentialDivergenceKey::from_live_comparison(finding, comparison)?;
            Some(DifferentialWaiverCandidate {
                source_sha256: source_sha256.to_string(),
                key,
                finding: finding.clone(),
            })
        })
        .collect()
}

fn classify_mode_divergence(
    comparison: &DifferentialModeComparison,
    executions: &[BackendExecution],
) -> DifferentialDivergenceFinding {
    let class = classify_trusted_divergence(executions, comparison);
    let evidence_group_hashes = comparison
        .groups
        .iter()
        .map(|group| group.canonical_key_sha256.clone())
        .collect::<Vec<_>>();

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
        waiver_id: None,
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

fn classify_trusted_divergence(
    executions: &[BackendExecution],
    comparison: &DifferentialModeComparison,
) -> DifferentialDivergenceClass {
    trusted_base_class_for_divergence(executions, comparison)
        .map(TrustedBaseClass::divergence_class)
        .unwrap_or(DifferentialDivergenceClass::Runtime)
}

fn trusted_base_class_for_divergence(
    executions: &[BackendExecution],
    comparison: &DifferentialModeComparison,
) -> Option<TrustedBaseClass> {
    let trusted_classes = executions
        .iter()
        .filter(|execution| {
            execution.receipt.status == DifferentialBackendStatus::Failed
                && comparison
                    .applicable_backends
                    .contains(&execution.receipt.backend)
        })
        .filter_map(|execution| {
            execution
                .trusted_signal
                .filter(|signal| signal.matches_backend(execution.receipt.backend))
                .map(TrustedTaxonomySignal::base_class)
        })
        .collect::<Vec<_>>();

    // Preserve the old specialized-class precedence, but only over typed,
    // private runner signals. Observable text and serialized diagnostics never
    // enter this selection.
    [
        TrustedBaseClass::HostcallPolicy,
        TrustedBaseClass::ModuleResolution,
        TrustedBaseClass::Parser,
        TrustedBaseClass::Lowering,
        TrustedBaseClass::Runtime,
    ]
    .into_iter()
    .find(|class| trusted_classes.contains(class))
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

fn canonicalize_backend_receipt(
    receipt: &DifferentialBackendReceipt,
    normalize_infrastructure_failures: bool,
) -> DifferentialCanonicalObservation {
    // Canonicalization v1 treated every serialized `Failed` receipt as a
    // comparable JavaScript exception. V2 requires the conventional JS error
    // exit plus a typed internal diagnostic or recognized exception line;
    // old post-probe I/O errors, crashes, empty exits, and generic failures
    // cannot safely enter the ExceptionClass domain.
    let v2_exception = normalize_infrastructure_failures
        .then(|| canonical_exception_v2(receipt, DifferentialBackendStatus::Failed));
    let status = if normalize_infrastructure_failures
        && receipt.status == DifferentialBackendStatus::Failed
        && (receipt.exit_code != Some(1)
            || v2_exception
                .as_ref()
                .is_some_and(|(kind, _)| kind.is_none()))
    {
        DifferentialBackendStatus::Degraded
    } else {
        receipt.status
    };
    let canonical_stdout = canonicalize_stream(receipt.stdout.as_str());
    let canonical_stderr = canonicalize_stream(receipt.stderr.as_str());
    let (structured_value, structured_value_wtf16) =
        canonical_structured_value(receipt, canonical_stdout.as_str());
    let (exception_kind, exception_message_class) = if normalize_infrastructure_failures {
        if status == DifferentialBackendStatus::Failed {
            v2_exception.unwrap_or((None, None))
        } else {
            (None, None)
        }
    } else {
        canonical_exception_v1(receipt, status)
    };

    DifferentialCanonicalObservation {
        backend: receipt.backend,
        status,
        canonical_stdout,
        canonical_stderr,
        structured_value,
        structured_value_wtf16,
        completion_label: if status == DifferentialBackendStatus::Completed {
            receipt.completion_label.clone()
        } else {
            None
        },
        exception_kind,
        exception_message_class,
        timing_envelope: timing_envelope(receipt.duration_micros),
    }
}

fn build_mode_comparison(
    mode: DifferentialComparisonMode,
    observations: &[DifferentialCanonicalObservation],
    require_full_semantic_coverage: bool,
    selected_cohort_is_valid: bool,
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
    let has_full_semantic_coverage = if require_full_semantic_coverage {
        if !selected_cohort_is_valid {
            false
        } else {
            match mode {
                DifferentialComparisonMode::StructuredValue => {
                    applicable_backends.len() == observations.len()
                        && observations.iter().all(|observation| {
                            observation.status == DifferentialBackendStatus::Completed
                        })
                }
                DifferentialComparisonMode::ExceptionClass => {
                    applicable_backends.len() == observations.len()
                        && observations.iter().all(|observation| {
                            observation.status == DifferentialBackendStatus::Failed
                        })
                }
                DifferentialComparisonMode::ExactStdout
                | DifferentialComparisonMode::ExactStderr
                | DifferentialComparisonMode::TimingEnvelope
                | DifferentialComparisonMode::CompletionLabel => true,
            }
        }
    } else {
        true
    };
    let verdict = if !has_full_semantic_coverage || applicable_backends.len() < 2 {
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
                // The comparison key is the (projection, exact-units) pair:
                // the projection alone would collapse distinct lone
                // surrogates — and a lone surrogate vs a literal U+FFFD —
                // into false consensus (bd-2vzgi).
                let key = match &observation.structured_value_wtf16 {
                    Some(units) => format!("structured_value:{value}|wtf16:{units:?}"),
                    None => format!("structured_value:{value}"),
                };
                (key, sample)
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
        DifferentialComparisonMode::CompletionLabel => observation
            .completion_label
            .as_ref()
            .map(|label| (format!("completion_label:{label:?}"), format!("{label:?}"))),
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
) -> (Option<String>, Option<Vec<u16>>) {
    if receipt.status != DifferentialBackendStatus::Completed {
        return (None, None);
    }
    // Prefer the program's observable console output (matching the `node -e` /
    // `bun -e` subprocess model the external backends use); fall back to an
    // explicit completion value only when nothing was printed (e.g. a bare
    // expression that the in-process lanes can still report a value for).
    let Some(source) = infer_single_stdout_value(canonical_stdout).or(receipt.value.as_deref())
    else {
        return (None, None);
    };
    // Exact code units ride along only when the structured value IS the
    // completion value — taken directly (both in-process lanes fall back to
    // it for console-free sources), or via a stdout line that mirrors it —
    // never attached to unrelated console output (bd-2vzgi).
    let wtf16 = match (&receipt.value_wtf16, &receipt.value) {
        (Some(units), Some(value)) if source == value => Some(units.clone()),
        _ => None,
    };
    (Some(canonicalize_js_value(source)), wtf16)
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

fn canonical_exception_v2(
    receipt: &DifferentialBackendReceipt,
    status: DifferentialBackendStatus,
) -> (Option<String>, Option<String>) {
    if status != DifferentialBackendStatus::Failed {
        return (None, None);
    }

    if is_franken_backend(&receipt.backend)
        && let Some(namespace) = receipt
            .diagnostics
            .iter()
            .find(|entry| entry.starts_with("eval."))
    {
        return (Some(namespace.to_string()), Some(namespace.to_string()));
    }

    let Some((kind, message)) = canonical_js_exception_line(&receipt.stderr) else {
        return (None, None);
    };
    (
        Some(canonicalize_exception_kind(kind)),
        Some(canonicalize_message_class(message)),
    )
}

fn canonical_js_exception_line(stderr: &str) -> Option<(&str, &str)> {
    const JS_EXCEPTION_KINDS: &[&str] = &[
        "AggregateError",
        "CompileError",
        "DOMException",
        "Error",
        "EvalError",
        "InternalError",
        "LinkError",
        "RangeError",
        "ReferenceError",
        "RuntimeError",
        "SyntaxError",
        "TypeError",
        "URIError",
        "WebAssembly.CompileError",
        "WebAssembly.LinkError",
        "WebAssembly.RuntimeError",
    ];
    stderr.lines().find_map(|line| {
        let line = line.trim();
        let line = line.strip_prefix("Uncaught ").unwrap_or(line);
        let (kind, message) = line.split_once(':')?;
        let kind = kind.trim();
        JS_EXCEPTION_KINDS
            .contains(&kind)
            .then_some((kind, message.trim()))
    })
}

fn canonical_exception_v1(
    receipt: &DifferentialBackendReceipt,
    status: DifferentialBackendStatus,
) -> (Option<String>, Option<String>) {
    if status != DifferentialBackendStatus::Failed {
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

    // An opaque heap/table identity handle (`[object#6]`, `[function#3]`, ...) is
    // normalized to its kind-only form so the interpreter-internal index — which
    // is not comparable across two independent lanes — does not read as a value
    // divergence (bd-rkmpj). The kind is preserved, so a genuine kind mismatch
    // still surfaces.
    if let Some(normalized) = normalize_heap_identity_handle(trimmed) {
        return normalized;
    }

    strip_matching_quotes(trimmed)
        .map(str::to_string)
        .unwrap_or_else(|| trimmed.to_string())
}

/// Normalize an opaque heap/table identity handle of the form `[<kind>#<index>]`
/// (e.g. `[object#6]`, `[function#3]`, `[generator#12]`) to its kind-only form
/// `[<kind>]`, or return `None` for any string that is not such a handle.
///
/// The `#<index>` suffix is the interpreter-internal heap/table position of the
/// value. It is *not* comparable across two independent interpreters: the
/// franken-engine lane preallocates its runtime-global objects (argv, env,
/// process, console, ...) before user code runs, so a user array/object lands at
/// a higher index, while the franken-core lane starts from an empty heap and
/// assigns index 0. Comparing those indices produced spurious `structured_value`
/// divergences for bare array/object completion values (`[1,2,3];`,
/// `({a:1,b:2});`) even though both lanes agree structurally — the residual
/// defects tracked by bd-rkmpj.
///
/// The *kind* token (`object`, `function`, `promise`, ...) is comparable and is
/// preserved, so a genuine kind divergence (e.g. one lane returns an object, the
/// other a function) still surfaces. Handles that carry a semantic name rather
/// than an index (`[builtin:Array]`, `[accessor]`) have no `#<digits>` suffix and
/// are deliberately left untouched.
fn normalize_heap_identity_handle(value: &str) -> Option<String> {
    let inner = value.strip_prefix('[')?.strip_suffix(']')?;
    let (kind, index) = inner.split_once('#')?;
    let kind_ok = !kind.is_empty() && kind.bytes().all(|b| b.is_ascii_lowercase());
    let index_ok = !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit());
    (kind_ok && index_ok).then(|| format!("[{kind}]"))
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
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
    pub(crate) duration_micros: u128,
    pub(crate) timed_out: bool,
}

#[cfg(unix)]
pub(crate) fn run_command_with_timeout<'a>(
    program: &str,
    args: impl IntoIterator<Item = &'a str>,
    timeout: Duration,
) -> io::Result<TimedCommandOutput> {
    let started = Instant::now();
    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Every external runtime owns a fresh process group. A timeout therefore
    // has a stable containment target that includes ordinary descendants,
    // instead of only the direct child represented by `std::process::Child`.
    command.process_group(0);
    let mut child = command.spawn()?;
    let process_group = rustix::process::Pid::from_child(&child);

    let stdout_reader = match child.stdout.take() {
        Some(stdout) => match spawn_output_drain(stdout, "stdout") {
            Ok(reader) => Some(reader),
            Err(error) => {
                terminate_and_reap_after_setup_failure(&mut child, process_group);
                return Err(error);
            }
        },
        None => None,
    };
    let stderr_reader = match child.stderr.take() {
        Some(stderr) => match spawn_output_drain(stderr, "stderr") {
            Ok(reader) => Some(reader),
            Err(error) => {
                terminate_and_reap_after_setup_failure(&mut child, process_group);
                cancel_and_join_output_drain(stdout_reader);
                return Err(error);
            }
        },
        None => None,
    };

    let remaining = timeout.saturating_sub(started.elapsed());
    let wait_result = child.wait_timeout(remaining);
    let (status, timed_out, termination_error) = match wait_result {
        Ok(Some(status)) => (status, false, None),
        Ok(None) => {
            let group_result = terminate_process_group(process_group);
            // Keep a direct-child fallback so the child is always reaped even
            // if the platform reports a process-group signalling failure. We
            // still surface that failure after cleanup: killing only the child
            // would not satisfy the descendant-tree timeout contract.
            let direct_result = child.kill();
            let status = child.wait();
            let termination_error = match group_result {
                Ok(()) => None,
                Err(group_error) => Some(match direct_result {
                    Ok(()) => group_error,
                    Err(direct_error) => io::Error::new(
                        group_error.kind(),
                        format!(
                            "failed to terminate runtime process group: {group_error}; \
                             direct-child fallback also failed: {direct_error}"
                        ),
                    ),
                }),
            };
            match status {
                Ok(status) => (status, true, termination_error),
                Err(error) => {
                    cancel_and_join_output_drain(stdout_reader);
                    cancel_and_join_output_drain(stderr_reader);
                    return Err(error);
                }
            }
        }
        Err(error) => {
            terminate_and_reap_after_setup_failure(&mut child, process_group);
            cancel_and_join_output_drain(stdout_reader);
            cancel_and_join_output_drain(stderr_reader);
            return Err(error);
        }
    };

    let captures = collect_output_drains(process_group, stdout_reader, stderr_reader);
    if let Some(error) = termination_error {
        // `collect_output_drains` has already cancelled and joined both reader
        // threads, so returning here cannot strand a process or thread.
        let _ = captures;
        return Err(error);
    }
    let (stdout, stderr) = captures?;
    Ok(TimedCommandOutput {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        stdout_truncated: stdout.truncated,
        stderr_truncated: stderr.truncated,
        duration_micros: started.elapsed().as_micros(),
        timed_out,
    })
}

#[cfg(not(unix))]
pub(crate) fn run_command_with_timeout<'a>(
    _program: &str,
    _args: impl IntoIterator<Item = &'a str>,
    _timeout: Duration,
) -> io::Result<TimedCommandOutput> {
    // A direct-child kill is not a wall-clock bound when descendants inherit
    // the capture handles. Fail closed until this target has a native job or
    // process-tree containment backend.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "external runtime execution requires native process-tree containment",
    ))
}

#[cfg(unix)]
#[derive(Debug)]
struct CapturedCommandStream {
    bytes: Vec<u8>,
    truncated: bool,
}

#[cfg(unix)]
#[derive(Debug)]
struct CommandOutputDrain {
    cancel: Arc<AtomicBool>,
    thread: thread::JoinHandle<io::Result<CapturedCommandStream>>,
}

#[cfg(unix)]
fn spawn_output_drain<R>(reader: R, stream: &'static str) -> io::Result<CommandOutputDrain>
where
    R: AsFd + Read + Send + 'static,
{
    let flags = rustix::fs::fcntl_getfl(reader.as_fd()).map_err(io::Error::from)?;
    rustix::fs::fcntl_setfl(reader.as_fd(), flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(io::Error::from)?;
    let cancel = Arc::new(AtomicBool::new(false));
    let reader_cancel = Arc::clone(&cancel);
    let thread = thread::Builder::new()
        .name(format!("franken-oracle-{stream}"))
        .spawn(move || read_bounded_output(reader, &reader_cancel))?;
    Ok(CommandOutputDrain { cancel, thread })
}

#[cfg(unix)]
fn read_bounded_output(
    mut reader: impl Read,
    cancel: &AtomicBool,
) -> io::Result<CapturedCommandStream> {
    let capacity = usize::try_from(MAX_CAPTURED_STREAM_BYTES.min(64 * 1024)).unwrap_or(64 * 1024);
    let mut bytes = Vec::with_capacity(capacity);
    let mut truncated = false;
    let mut chunk = [0_u8; 8192];
    loop {
        if cancel.load(Ordering::Acquire) {
            break;
        }
        let read = match reader.read(&mut chunk) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(OUTPUT_DRAIN_POLL_INTERVAL);
                continue;
            }
            Err(error) => return Err(error),
        };
        if read == 0 {
            break;
        }
        let remaining = MAX_CAPTURED_STREAM_BYTES
            .saturating_sub(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let retain = usize::try_from(remaining).unwrap_or(usize::MAX).min(read);
        bytes.extend_from_slice(&chunk[..retain]);
        truncated |= retain < read;
    }
    Ok(CapturedCommandStream { bytes, truncated })
}

#[cfg(unix)]
fn output_drains_finished(
    stdout: &Option<CommandOutputDrain>,
    stderr: &Option<CommandOutputDrain>,
) -> bool {
    stdout
        .as_ref()
        .is_none_or(|reader| reader.thread.is_finished())
        && stderr
            .as_ref()
            .is_none_or(|reader| reader.thread.is_finished())
}

#[cfg(unix)]
fn wait_for_output_drains(
    stdout: &Option<CommandOutputDrain>,
    stderr: &Option<CommandOutputDrain>,
    timeout: Duration,
) {
    let started = Instant::now();
    while !output_drains_finished(stdout, stderr) && started.elapsed() < timeout {
        thread::sleep(OUTPUT_DRAIN_POLL_INTERVAL);
    }
}

#[cfg(unix)]
fn collect_output_drains(
    process_group: rustix::process::Pid,
    stdout: Option<CommandOutputDrain>,
    stderr: Option<CommandOutputDrain>,
) -> io::Result<(CapturedCommandStream, CapturedCommandStream)> {
    // A runtime may exit after spawning a descendant that inherited its pipes.
    // Give ordinary buffered output a short grace period, then terminate the
    // private group before joining. Nonblocking readers have an independent
    // cancellation bound even if a descendant escaped that group.
    wait_for_output_drains(&stdout, &stderr, OUTPUT_DRAIN_EXIT_GRACE);
    let group_teardown = if output_drains_finished(&stdout, &stderr) {
        Ok(())
    } else {
        let result = terminate_process_group(process_group);
        wait_for_output_drains(&stdout, &stderr, OUTPUT_DRAIN_TEARDOWN_GRACE);
        result
    };

    let stdout_result = join_output_drain(stdout, "stdout");
    let stderr_result = join_output_drain(stderr, "stderr");
    group_teardown?;
    let (stdout, stdout_forced_cancel) = stdout_result?;
    let (stderr, stderr_forced_cancel) = stderr_result?;
    if stdout_forced_cancel || stderr_forced_cancel {
        return Err(io::Error::other(
            "runtime output remained open after process-group teardown; \
             a descendant escaped containment",
        ));
    }
    Ok((stdout, stderr))
}

#[cfg(unix)]
fn join_output_drain(
    reader: Option<CommandOutputDrain>,
    stream: &str,
) -> io::Result<(CapturedCommandStream, bool)> {
    let Some(reader) = reader else {
        return Ok((
            CapturedCommandStream {
                bytes: Vec::new(),
                truncated: false,
            },
            false,
        ));
    };
    let forced_cancel = !reader.thread.is_finished();
    if forced_cancel {
        reader.cancel.store(true, Ordering::Release);
    }
    let captured = reader
        .thread
        .join()
        .map_err(|_| io::Error::other(format!("{stream} reader thread panicked")))??;
    Ok((captured, forced_cancel))
}

#[cfg(unix)]
fn cancel_and_join_output_drain(reader: Option<CommandOutputDrain>) {
    if let Some(reader) = reader {
        reader.cancel.store(true, Ordering::Release);
        let _ = reader.thread.join();
    }
}

#[cfg(unix)]
fn terminate_process_group(process_group: rustix::process::Pid) -> io::Result<()> {
    match rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(io::Error::from(error)),
    }
}

#[cfg(unix)]
fn terminate_and_reap_after_setup_failure(
    child: &mut std::process::Child,
    process_group: rustix::process::Pid,
) {
    let _ = terminate_process_group(process_group);
    let _ = child.kill();
    let _ = child.wait();
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

// ============================================================================
// E2.T5 — Divergence-preserving case minimization (bd-fqlfw.2.5)
// ============================================================================
//
// The minimizer delta-debugs a failing program down to a minimal source that
// PRESERVES its specific classified divergence, so the artifact an operator or
// agent receives is gold (the smallest program that still reproduces the bug)
// rather than noise.
//
// The "property under test" is a program's [`DivergenceSignature`]: the taxonomy
// verdict plus the sorted multiset of `(comparison_mode, divergence_class)`
// labels emitted by [`classify_differential_divergences`] (E2.T3). A reduction
// is accepted ONLY when the candidate's signature is identical to the original's,
// which means the minimizer can never
//   * collapse a real divergence into consensus,
//   * swap one divergence class for another, or
//   * minimize away an `IntentionalSecurityDivergence` (intentional-vs-bug is
//     part of the class, hence part of the signature).
//
// Only findings whose comparison mode *contributes to the semantic verdict*
// (structured value, exception class) enter the signature. Stdout/stderr exact
// matches and — critically — the wall-clock `TimingEnvelope` are excluded,
// because timing is non-deterministic and would make the minimizer's fixed point
// unstable across re-runs. This keeps the signature a stable function of the
// program's *correctness* behavior, which is exactly the property worth
// preserving.

pub const DIFFERENTIAL_ORACLE_MINIMIZATION_SCHEMA_VERSION: &str =
    "franken-engine.differential-oracle.minimization.v1";

/// Default oracle-invocation budget for [`minimize_oracle_divergence`]. Each
/// invocation re-runs the selected lanes once; the budget bounds the cost of
/// minimizing pathological inputs while still being generous enough for the
/// line counts a real corpus case carries.
pub const DIFFERENTIAL_ORACLE_MINIMIZATION_DEFAULT_BUDGET: usize = 512;

/// One classified finding reduced to its stable, comparable labels.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DivergenceSignatureEntry {
    pub comparison_mode: String,
    pub class: String,
}

/// A stable, order-independent fingerprint of a program's *classified* divergence.
///
/// Two programs share a signature iff they reach the same taxonomy `verdict` and
/// emit the same multiset of semantic `(comparison_mode, class)` findings. The
/// signature deliberately ignores volatile detail (human messages, evidence
/// hashes, affected-backend ordering, timing) so that two source variants which
/// reproduce the *same* divergence compare equal even though their reports differ
/// in incidental fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceSignature {
    pub verdict: DifferentialComparisonVerdict,
    pub findings: Vec<DivergenceSignatureEntry>,
}

impl DivergenceSignature {
    /// Build a signature from taxonomy produced inside the current live run.
    /// This remains private because a standalone serialized taxonomy carries no
    /// runner or waiver provenance.
    fn from_live_taxonomy(report: &DifferentialDivergenceTaxonomyReport) -> Self {
        let mut findings = report
            .findings
            .iter()
            .filter(|finding| finding.comparison_mode.contributes_to_semantic_verdict())
            .map(|finding| DivergenceSignatureEntry {
                comparison_mode: finding.comparison_mode.stable_label().to_string(),
                class: finding.class.stable_label().to_string(),
            })
            .collect::<Vec<_>>();
        findings.sort();
        Self {
            verdict: report.verdict,
            findings,
        }
    }

    /// Derive a conservative signature from an arbitrary report.
    ///
    /// Stored taxonomy is never trusted: canonical observations and taxonomy
    /// are recomputed from receipts without typed sidecars or waiver authority.
    pub fn from_report(report: &DifferentialOracleReport) -> Self {
        let canonicalization = canonicalize_backend_receipts(&report.backends);
        let taxonomy = classify_differential_divergences(&report.backends, &canonicalization);
        Self::from_live_taxonomy(&taxonomy)
    }

    fn from_live_report(report: &DifferentialOracleReport) -> Self {
        Self::from_live_taxonomy(&report.divergence_taxonomy)
    }

    /// A signature represents a real, minimizable divergence when at least one
    /// semantic finding survived the filter. A program with no semantic findings
    /// (consensus, insufficient data, or a timing-only difference) is not a
    /// classified divergence and cannot be minimized.
    pub fn has_classified_divergence(&self) -> bool {
        self.verdict == DifferentialComparisonVerdict::Divergence && !self.findings.is_empty()
    }
}

/// Why a minimization request could not produce a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DifferentialMinimizationError {
    /// The original source does not exhibit a classified divergence, so there is
    /// nothing to minimize. The minimizer refuses to manufacture one.
    NoDivergenceInOriginal,
}

impl std::fmt::Display for DifferentialMinimizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDivergenceInOriginal => f.write_str(
                "original source exhibits no classified divergence; nothing to minimize",
            ),
        }
    }
}

impl std::error::Error for DifferentialMinimizationError {}

/// The result of minimizing a diverging program.
///
/// On success the `minimized_source` reproduces the original's classified
/// divergence (`classification_preserved` is always `true`) under the same lane
/// selection. `reached_fixed_point` is `false` only when the oracle-invocation
/// budget was exhausted before the minimizer could prove 1-minimality; the
/// reported source is still a valid (signature-preserving) reduction, just not
/// necessarily the smallest one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialMinimizationOutcome {
    pub schema_version: String,
    pub original_source: String,
    pub minimized_source: String,
    /// The divergence signature shared by the original and minimized sources.
    pub signature: DivergenceSignature,
    pub original_line_count: usize,
    pub minimized_line_count: usize,
    pub original_len_bytes: usize,
    pub minimized_len_bytes: usize,
    pub accepted_reductions: usize,
    pub oracle_invocations: usize,
    pub reached_fixed_point: bool,
    pub classification_preserved: bool,
}

fn render_lines(lines: &[&str], indices: &[usize]) -> String {
    indices
        .iter()
        .map(|&i| lines[i])
        .collect::<Vec<_>>()
        .join("\n")
}

/// Delta-debug `source` (line granularity) down to a minimal program that
/// preserves its classified divergence, using `classify` as the divergence
/// oracle.
///
/// `classify` maps a candidate source to its [`DivergenceSignature`]; the
/// production wiring is [`minimize_oracle_divergence`], which runs the real
/// differential oracle, but the algorithm is generic so it can be exercised
/// deterministically. The original source is classified once up front; if it has
/// no classified divergence the call fails with
/// [`DifferentialMinimizationError::NoDivergenceInOriginal`].
///
/// The reduction is a complement-based `ddmin`: it removes ever-finer chunks of
/// lines and keeps a removal only when the candidate's signature still equals the
/// original's, escalating granularity down to single lines so the result is
/// 1-minimal (no single remaining line can be dropped without changing the
/// classification). `max_oracle_invocations` bounds the number of `classify`
/// calls; if the budget is hit the best signature-preserving reduction found so
/// far is returned with `reached_fixed_point == false`.
pub fn minimize_divergence_source<F>(
    source: &str,
    mut classify: F,
    max_oracle_invocations: usize,
) -> Result<DifferentialMinimizationOutcome, DifferentialMinimizationError>
where
    F: FnMut(&str) -> DivergenceSignature,
{
    let original_lines: Vec<&str> = source.lines().collect();
    let mut invocations: usize = 0;

    // Classify the original program (counts against the budget).
    let target = classify(source);
    invocations += 1;
    if !target.has_classified_divergence() {
        return Err(DifferentialMinimizationError::NoDivergenceInOriginal);
    }

    let mut kept: Vec<usize> = (0..original_lines.len()).collect();
    let mut accepted: usize = 0;
    let mut reached_fixed_point = true;

    // Complement-based delta debugging. `n` is the current chunk count; each pass
    // tries removing one chunk at a time, escalating to finer chunks when a pass
    // makes no progress, until single-line removals are exhausted (1-minimal).
    // Any accepted removal restarts the outer loop, so reaching the end of an
    // inner pass means nothing at this granularity could be dropped.
    let mut n = 2usize;
    'outer: while kept.len() >= 2 {
        let chunk_count = n.min(kept.len());
        let chunk_size = kept.len().div_ceil(chunk_count);
        let mut start = 0usize;
        while start < kept.len() {
            let end = (start + chunk_size).min(kept.len());
            // Candidate = kept with the chunk [start, end) removed.
            let candidate: Vec<usize> = kept[..start]
                .iter()
                .chain(kept[end..].iter())
                .copied()
                .collect();
            if candidate.is_empty() {
                start = end;
                continue;
            }
            if invocations >= max_oracle_invocations {
                reached_fixed_point = false;
                break 'outer;
            }
            let candidate_source = render_lines(&original_lines, &candidate);
            let signature = classify(&candidate_source);
            invocations += 1;
            if signature == target {
                kept = candidate;
                accepted += 1;
                // Shrink granularity and restart the pass on the smaller set.
                n = n.saturating_sub(1).max(2);
                continue 'outer;
            }
            start = end;
        }
        // Inner pass removed nothing at this granularity.
        if n >= kept.len() {
            // Every single-line removal was rejected: 1-minimal.
            break;
        }
        n = (n * 2).min(kept.len());
    }

    let minimized_source = render_lines(&original_lines, &kept);
    let minimized_len_bytes = minimized_source.len();
    Ok(DifferentialMinimizationOutcome {
        schema_version: DIFFERENTIAL_ORACLE_MINIMIZATION_SCHEMA_VERSION.to_string(),
        original_source: source.to_string(),
        minimized_source,
        signature: target,
        original_line_count: original_lines.len(),
        minimized_line_count: kept.len(),
        original_len_bytes: source.len(),
        minimized_len_bytes,
        accepted_reductions: accepted,
        oracle_invocations: invocations,
        reached_fixed_point,
        classification_preserved: true,
    })
}

/// Minimize a diverging case using the real differential oracle as the
/// divergence predicate.
///
/// Each candidate is re-run through [`run_differential_oracle`] with the same
/// lane selection, budgets, and runtime specs as `input`, swapping only the
/// source and a per-step case id so reports stay distinguishable. For a hermetic,
/// fully in-process run, restrict `input.selected_backends` to
/// `[FrankenEngine, FrankenCore]` (the internal twin): no external process is
/// spawned and the result is deterministic.
pub fn minimize_oracle_divergence(
    input: &DifferentialOracleInput,
    max_oracle_invocations: usize,
) -> Result<DifferentialMinimizationOutcome, DifferentialMinimizationError> {
    let mut step: u64 = 0;
    minimize_divergence_source(
        input.source.as_str(),
        |candidate| {
            step += 1;
            let mut probe = input.clone();
            probe.source = candidate.to_string();
            probe.case_id = format!("{}::min{step}", input.case_id);
            DivergenceSignature::from_live_report(&run_differential_oracle(&probe))
        },
        max_oracle_invocations,
    )
}

// ============================================================================
// E2.T3a — engine <-> franken-core internal differential oracle (bd-fqlfw.2.3.1)
// ============================================================================
//
// The two in-tree interpreters (franken-engine and franken-core) MUST agree on
// every corpus item. Differentially fuzzing that equivalence is a free, powerful
// internal bug-finder: it surfaces interpreter defects with no need for an
// external node/bun denominator (both lanes run in-process). Each divergence is
// reported as a defect carrying a minimized reproducer (via the E2.T5 minimizer),
// so the artifact is agent-ready rather than noise.
//
// Comparability note: a case where only one lane completes (e.g. the core lane
// faults on a builtin the engine lane supports) is reported as `Inconclusive`,
// not a defect — with only two lanes the canonical comparison has fewer than two
// applicable observations and cannot classify a divergence. Such cases are
// surfaced (counted, not silently dropped) so a corpus author can tell "the twins
// disagree" apart from "one lane could not run this".

pub const ENGINE_CORE_DIFFERENTIAL_HARNESS_SCHEMA_VERSION: &str =
    "franken-engine.engine-core-differential-harness.v1";

/// Engine-lane instruction budget used by the internal twin harness. The
/// deterministic containment default (100k) trips on modest loops; the harness
/// raises it so a divergence reflects semantics rather than one lane hitting the
/// budget ceiling first. Both lanes receive the same budget.
pub const ENGINE_CORE_DIFFERENTIAL_HARNESS_INSTRUCTION_BUDGET: u64 = 64_000_000;

/// One corpus item: a named JavaScript program to run through both lanes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineCoreCorpusCase {
    pub case_id: String,
    pub source: String,
}

impl EngineCoreCorpusCase {
    pub fn new(case_id: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            case_id: case_id.into(),
            source: source.into(),
        }
    }
}

/// Per-case classification of the engine <-> core comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineCoreCaseStatus {
    /// Both lanes produced comparable observations and agreed.
    Agreement,
    /// A classified divergence: reported as a defect with a minimized repro.
    Defect,
    /// Fewer than two comparable observations (e.g. one lane faulted), so the
    /// comparison could not classify a divergence either way.
    Inconclusive,
}

/// A reported engine <-> core defect with a minimized reproducer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineCoreDefect {
    pub case_id: String,
    pub original_source: String,
    pub minimized_source: String,
    pub signature: DivergenceSignature,
    pub original_line_count: usize,
    pub minimized_line_count: usize,
    pub minimization_reached_fixed_point: bool,
    pub oracle_invocations: usize,
}

/// Aggregate report of running a corpus through the internal twin oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineCoreDifferentialReport {
    pub schema_version: String,
    pub cases_checked: usize,
    pub agreements: usize,
    pub inconclusive: usize,
    pub defects: Vec<EngineCoreDefect>,
}

impl EngineCoreDifferentialReport {
    pub fn has_defects(&self) -> bool {
        !self.defects.is_empty()
    }

    /// Invariant the caller can assert: every case lands in exactly one bucket.
    pub fn accounting_is_consistent(&self) -> bool {
        self.agreements + self.inconclusive + self.defects.len() == self.cases_checked
    }
}

/// Build an oracle input restricted to the internal franken-engine <-> franken-core
/// twin (no external process is spawned).
fn engine_core_oracle_input(case_id: &str, source: &str) -> DifferentialOracleInput {
    DifferentialOracleInput::new(case_id, source)
        .with_selected_backends([
            DifferentialBackend::FrankenEngine,
            DifferentialBackend::FrankenCore,
        ])
        .with_engine_instruction_budget(ENGINE_CORE_DIFFERENTIAL_HARNESS_INSTRUCTION_BUDGET)
}

/// Run a corpus through the engine <-> core internal differential oracle, reporting
/// every classified divergence as a defect with a minimized reproducer.
///
/// `minimization_budget` bounds the oracle invocations spent minimizing each
/// defect (see [`minimize_oracle_divergence`]). The comparison is fully in-process
/// and deterministic.
pub fn run_engine_core_differential_oracle(
    corpus: &[EngineCoreCorpusCase],
    minimization_budget: usize,
) -> EngineCoreDifferentialReport {
    let mut report = EngineCoreDifferentialReport {
        schema_version: ENGINE_CORE_DIFFERENTIAL_HARNESS_SCHEMA_VERSION.to_string(),
        cases_checked: corpus.len(),
        agreements: 0,
        inconclusive: 0,
        defects: Vec::new(),
    };

    for case in corpus {
        let input = engine_core_oracle_input(&case.case_id, &case.source);
        let signature = DivergenceSignature::from_live_report(&run_differential_oracle(&input));
        if signature.has_classified_divergence() {
            // A classified divergence: minimize it to an agent-ready repro. The
            // original already classified as a divergence, so the minimizer cannot
            // return `NoDivergenceInOriginal`; if it ever did we still record the
            // defect with the original source as its (un-minimized) reproducer.
            let defect = match minimize_oracle_divergence(&input, minimization_budget) {
                Ok(outcome) => EngineCoreDefect {
                    case_id: case.case_id.clone(),
                    original_source: outcome.original_source,
                    minimized_source: outcome.minimized_source,
                    signature: outcome.signature,
                    original_line_count: outcome.original_line_count,
                    minimized_line_count: outcome.minimized_line_count,
                    minimization_reached_fixed_point: outcome.reached_fixed_point,
                    oracle_invocations: outcome.oracle_invocations,
                },
                Err(_) => EngineCoreDefect {
                    case_id: case.case_id.clone(),
                    original_source: case.source.clone(),
                    minimized_source: case.source.clone(),
                    signature,
                    original_line_count: case.source.lines().count(),
                    minimized_line_count: case.source.lines().count(),
                    minimization_reached_fixed_point: false,
                    oracle_invocations: 0,
                },
            };
            report.defects.push(defect);
        } else if signature.verdict == DifferentialComparisonVerdict::Divergence {
            // Defensive: a Divergence verdict with no retained semantic finding is
            // not a minimizable classified divergence; treat it as inconclusive.
            report.inconclusive += 1;
        } else if signature.verdict == DifferentialComparisonVerdict::Consensus {
            report.agreements += 1;
        } else {
            report.inconclusive += 1;
        }
    }

    report
}

/// A curated seed corpus for the internal twin oracle, spanning constructs both
/// lanes execute (arithmetic, comparison, control flow, functions/closures,
/// arrays/objects). It is a starting point that callers extend with
/// metamorphic-relation and fuzz-generated cases; the harness reports any
/// divergence among whatever corpus it is given.
pub fn default_engine_core_corpus() -> Vec<EngineCoreCorpusCase> {
    [
        ("arith_precedence", "1 + 2 * 3;"),
        ("arith_parens", "(1 + 2) * 3;"),
        ("arith_mod", "17 % 5;"),
        ("string_concat", "\"a\" + \"b\" + \"c\";"),
        ("comparison_lt", "1 < 2;"),
        ("ternary", "true ? 10 : 20;"),
        ("var_then_use", "var x = 5; x + 1;"),
        ("let_block", "let y = 10; y * 2;"),
        (
            "function_two_params",
            "(function (a, b) { return a + b; })(3, 4);",
        ),
        (
            "nested_function",
            "(function () { function f(n) { return n * n; } return f(5); })();",
        ),
        (
            "loop_accumulate",
            "(function () { var s = 0; for (var i = 0; i < 5; i++) { s += i; } return s; })();",
        ),
        (
            "for_of_custom_break_closes_iterator",
            r#"let n=0,c=0; let it={next:function(){n=n+1;return n===1?{value:7,done:false}:{done:true};},return:function(){c=c+1;return {};}}; let xs={[Symbol.iterator]:function(){return it;}}; let v=0; for(const x of xs){v=x;break;} v*10+c;"#,
        ),
        (
            "for_of_object_method_shorthand",
            r#"let it={n:0,next(){this.n=this.n+1;return {value:this.n,done:false};},return(){return {};}};let xs={[Symbol.iterator](){return it;}};let v=0;for(const x of xs){v=x;break;}v;"#,
        ),
        (
            "for_of_body_throw_keeps_original_completion",
            r#"let c=0; let it={next:function(){return {value:1,done:false};},return:function(){c=c+1;throw "close";}}; let xs={[Symbol.iterator]:function(){return it;}}; let caught=""; try{for(const x of xs){throw "body";}}catch(e){caught=e;} caught+":"+c;"#,
        ),
        (
            "for_of_nested_labelled_break_close_order",
            r#"let log=""; let oi={next:function(){return {value:1,done:false};},return:function(){log=log+"o";return {};}}; let ii={next:function(){return {value:1,done:false};},return:function(){log=log+"i";return {};}}; let os={[Symbol.iterator]:function(){return oi;}}; let is={[Symbol.iterator]:function(){return ii;}}; outer:for(const x of os){for(const y of is){break outer;}} log;"#,
        ),
        (
            "for_of_nested_labelled_continue_close_order",
            r#"let n=0,log=""; let oi={next:function(){n=n+1;return n<3?{value:n,done:false}:{done:true};},return:function(){log=log+"o";return {};}}; let ii={next:function(){return {value:1,done:false};},return:function(){log=log+"i";return {};}}; let os={[Symbol.iterator]:function(){return oi;}}; let is={[Symbol.iterator]:function(){return ii;}}; outer:for(const x of os){for(const y of is){continue outer;}} log;"#,
        ),
        (
            "for_of_return_close_primitive_replaces_return",
            r#"let it={next:function(){return {value:1,done:false};},return:function(){return 0;}}; let xs={[Symbol.iterator]:function(){return it;}}; function f(){try{for(const x of xs){return "old";}}catch(e){return e.name;}} f();"#,
        ),
        (
            "for_of_return_closes_and_preserves_value",
            r#"let c=0; let it={next:function(){return {value:7,done:false};},return:function(){c=c+1;return {};}}; let xs={[Symbol.iterator]:function(){return it;}}; function f(){for(const x of xs){return x;}return 0;} f()+":"+c;"#,
        ),
        (
            "for_of_break_close_throw_replaces_break",
            r#"let it={next:function(){return {value:1,done:false};},return:function(){throw "close";}}; let xs={[Symbol.iterator]:function(){return it;}}; let caught=""; try{for(const x of xs){break;}}catch(e){caught=e;} caught;"#,
        ),
        (
            "for_of_source_finally_precedes_iterator_close",
            r#"let log=""; let it={next:function(){return {value:1,done:false};},return:function(){log=log+"r";return {};}}; let xs={[Symbol.iterator]:function(){return it;}}; for(const x of xs){try{break;}finally{log=log+"f";}} log;"#,
        ),
        (
            "for_of_caught_close_failure_inside_finally_preserves_return",
            r#"let c=0; let it={next:function(){return {value:1,done:false};},return:function(){c=c+1;throw "close";}}; let xs={[Symbol.iterator]:function(){return it;}}; function f(){try{return "old";}finally{try{for(const x of xs){break;}}catch(e){e;}}} f()+":"+c;"#,
        ),
        (
            "for_of_uncaught_close_failure_inside_finally_replaces_return",
            r#"let c=0; let it={next:function(){return {value:1,done:false};},return:function(){c=c+1;throw "close";}}; let xs={[Symbol.iterator]:function(){return it;}}; function f(){try{return "old";}finally{for(const x of xs){break;}}} let caught="";try{f();}catch(e){caught=e;}caught+":"+c;"#,
        ),
        ("array_literal", "[1, 2, 3];"),
        ("object_literal", "({a: 1, b: 2});"),
        (
            "array_index",
            "(function () { var a = [10, 20, 30]; return a[1]; })();",
        ),
        // Lone-surrogate string semantics (bd-2vzgi): both lanes carry exact
        // UTF-16 code units through `value_wtf16`, so a surrogate half is
        // compared exactly rather than through its lossy U+FFFD projection.
        ("string_length_utf16", "\"a\u{1F600}b\".length;"),
        (
            "string_char_at_surrogate_half",
            "\"a\u{1F600}b\".charAt(1);",
        ),
        (
            "string_char_at_healing",
            "\"a\u{1F600}b\".charAt(1) + \"a\u{1F600}b\".charAt(2);",
        ),
        (
            "string_char_code_at_exact_unit",
            "\"a\u{1F600}b\".charCodeAt(1);",
        ),
        ("string_from_char_code_lone", "String.fromCharCode(55357);"),
        (
            "string_from_char_code_healing",
            "String.fromCharCode(55357, 56832);",
        ),
        (
            "string_distinct_lone_surrogates_not_equal",
            "String.fromCharCode(55296) === String.fromCharCode(55297);",
        ),
        // codePointAt is UTF-16 code-unit indexed in both lanes (bd-rdnhc):
        // index 1 lands on the high surrogate and combines the pair; index 2
        // lands on the unpaired view of the low surrogate.
        (
            "string_code_point_at_pair_combines",
            "\"a\u{1F600}b\".codePointAt(1);",
        ),
        (
            "string_code_point_at_low_unit",
            "\"a\u{1F600}b\".codePointAt(2);",
        ),
        // bd-7zwar: core string-surface residual upgrades, kept in lockstep
        // with the engine — String.fromCodePoint, ES2024 well-formedness
        // probes, code-unit relational order, and code-point-grain for..of.
        (
            "string_from_code_point_lone",
            "String.fromCodePoint(55296);",
        ),
        (
            "string_from_code_point_supplementary",
            "String.fromCodePoint(128512);",
        ),
        (
            "string_is_well_formed_lone",
            "String.fromCharCode(55296).isWellFormed();",
        ),
        (
            "string_to_well_formed_projection",
            "String.fromCharCode(55296).toWellFormed();",
        ),
        (
            "string_relational_code_unit_order",
            "String.fromCharCode(55296) < String.fromCharCode(57344);",
        ),
        (
            "string_for_of_code_point_count",
            "var n = 0; for (var c of \"a\u{1F600}b\") { n = n + 1; } n;",
        ),
        // Function-body twin: core's function-body lowering used to drop
        // iterator ops to nops and spin to budget exhaustion (bd-ddloz).
        (
            "string_for_of_in_function_body",
            "(function () { var n = 0; for (var c of \"a\u{1F600}b\") { n = n + 1; } return n; })();",
        ),
        ("string_unknown_property_undefined", "\"abc\".nope;"),
    ]
    .into_iter()
    .map(|(case_id, source)| EngineCoreCorpusCase::new(case_id, source))
    .collect()
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
    fn bd_5ilh1_in_process_lanes_agree_on_completion_label() {
        let mut input = DifferentialOracleInput::new("completion-label-agreement", "1 + 1;");
        input.node.program = "frankenengine-missing-node-runtime".to_string();
        input.bun.program = "frankenengine-missing-bun-runtime".to_string();

        let report = run_differential_oracle(&input);
        // Both in-process lanes now report completion provenance.
        assert_eq!(
            report.backends[2].completion_label,
            Some(CoreIfcLabel::Public),
            "engine lane must report a completion label"
        );
        assert_eq!(
            report.backends[3].completion_label,
            Some(CoreIfcLabel::Public),
            "core lane must report a completion label"
        );

        let comparison = report
            .canonicalization
            .comparisons
            .iter()
            .find(|comparison| comparison.mode == DifferentialComparisonMode::CompletionLabel)
            .expect("completion-label comparison mode must be present");
        // Only the in-process lanes participate: subprocess runtimes cannot
        // report completion provenance and must not poison the comparison.
        assert_eq!(
            comparison.applicable_backends,
            vec![
                DifferentialBackend::FrankenEngine,
                DifferentialBackend::FrankenCore,
            ]
        );
        assert_eq!(comparison.verdict, DifferentialComparisonVerdict::Consensus);
    }

    #[test]
    fn bd_5ilh1_legacy_report_without_completion_label_mode_remains_readable() {
        // A serialized observation predating the field deserializes with None
        // and the receipt-level legacy path is unchanged.
        let receipt = run_franken_engine_backend("1 + 1;", None, None).receipt;
        assert_eq!(receipt.completion_label, Some(CoreIfcLabel::Public));
        let mut wire = serde_json::to_value(receipt).expect("receipt should serialize");
        wire.as_object_mut()
            .expect("receipt wire should be an object")
            .remove("completion_label");
        let restored: DifferentialBackendReceipt =
            serde_json::from_value(wire).expect("legacy receipt should deserialize");
        assert_eq!(restored.completion_label, None);
    }

    #[test]
    fn franken_engine_backend_surfaces_console_output_as_stdout() {
        // Regression (bd-fqlfw.2.4): a program whose only observable is
        // `console.log` must report that console output as stdout — matching the
        // `node -e` / `bun -e` subprocess backends — rather than its `undefined`
        // completion value, otherwise the cross-runtime structured-value
        // comparison can never reach consensus and no case enters the denominator.
        let engine =
            run_franken_engine_backend("console.log(1 + 1);", Some(2_000_000_000), None).receipt;
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

    // --- bd-2vzgi: lone-surrogate observables compare exactly ----------------

    #[test]
    fn franken_core_backend_reports_exact_units_for_lone_surrogate_value() {
        let receipt = run_franken_core_backend("\"a\u{1F600}b\".charAt(1);", None, None).receipt;
        assert_eq!(receipt.status, DifferentialBackendStatus::Completed);
        // The String channel carries the lossy projection; the exact code
        // units ride alongside.
        assert_eq!(receipt.value.as_deref(), Some("\u{FFFD}"));
        assert_eq!(receipt.completion_label, Some(CoreIfcLabel::Public));
        assert_eq!(receipt.value_wtf16, Some(vec![0xD83D]));
    }

    #[test]
    fn legacy_backend_receipt_without_completion_label_remains_readable_bd_ur3tk_17() {
        let receipt = run_franken_core_backend("1 + 1;", None, None).receipt;
        assert_eq!(receipt.completion_label, Some(CoreIfcLabel::Public));

        let mut wire = serde_json::to_value(receipt).expect("receipt should serialize");
        wire.as_object_mut()
            .expect("receipt wire should be an object")
            .remove("completion_label");
        let restored: DifferentialBackendReceipt =
            serde_json::from_value(wire).expect("legacy receipt should deserialize");
        assert_eq!(restored.completion_label, None);
    }

    #[test]
    fn franken_engine_backend_reports_exact_units_for_lone_surrogate_value() {
        let receipt = run_franken_engine_backend("\"a\u{1F600}b\".charAt(1);", None, None).receipt;
        assert_eq!(receipt.status, DifferentialBackendStatus::Completed);
        assert_eq!(receipt.value.as_deref(), Some("\u{FFFD}"));
        assert_eq!(receipt.value_wtf16, Some(vec![0xD83D]));
    }

    #[test]
    fn healed_surrogate_concat_has_no_wtf16_channel() {
        // A healed pair is well-formed, so the exact-units channel must stay
        // absent and the wire format unchanged.
        let receipt = run_franken_core_backend(
            "\"a\u{1F600}b\".charAt(1) + \"a\u{1F600}b\".charAt(2);",
            None,
            None,
        )
        .receipt;
        assert_eq!(receipt.status, DifferentialBackendStatus::Completed);
        assert_eq!(receipt.value.as_deref(), Some("\u{1F600}"));
        assert_eq!(receipt.value_wtf16, None);
    }

    #[test]
    fn lone_surrogate_vs_literal_replacement_char_diverges_not_consensus() {
        // Same U+FFFD projection, but one lane's value is a real lone
        // surrogate: the (projection, units) comparison key must classify a
        // divergence rather than declare false consensus.
        let mut lone = receipt(
            DifferentialBackend::FrankenEngine,
            DifferentialBackendStatus::Completed,
            Some("\u{FFFD}"),
            "\u{FFFD}",
            "",
            &[],
        );
        lone.value_wtf16 = Some(vec![0xD800]);
        let literal = receipt(
            DifferentialBackend::FrankenCore,
            DifferentialBackendStatus::Completed,
            Some("\u{FFFD}"),
            "\u{FFFD}",
            "",
            &[],
        );
        let report = canonicalize_backend_receipts(&[lone, literal]);
        let structured = comparison(&report, DifferentialComparisonMode::StructuredValue);
        assert_eq!(
            structured.verdict,
            DifferentialComparisonVerdict::Divergence
        );
        assert_eq!(structured.groups.len(), 2);
    }

    #[test]
    fn distinct_lone_surrogates_diverge_while_equal_units_reach_consensus() {
        let mut d800 = receipt(
            DifferentialBackend::FrankenEngine,
            DifferentialBackendStatus::Completed,
            Some("\u{FFFD}"),
            "\u{FFFD}",
            "",
            &[],
        );
        d800.value_wtf16 = Some(vec![0xD800]);
        let mut d801 = receipt(
            DifferentialBackend::FrankenCore,
            DifferentialBackendStatus::Completed,
            Some("\u{FFFD}"),
            "\u{FFFD}",
            "",
            &[],
        );
        d801.value_wtf16 = Some(vec![0xD801]);
        let report = canonicalize_backend_receipts(&[d800.clone(), d801]);
        let structured = comparison(&report, DifferentialComparisonMode::StructuredValue);
        assert_eq!(
            structured.verdict,
            DifferentialComparisonVerdict::Divergence
        );

        let mut d800_twin = d800.clone();
        d800_twin.backend = DifferentialBackend::FrankenCore;
        let report = canonicalize_backend_receipts(&[d800, d800_twin]);
        let structured = comparison(&report, DifferentialComparisonMode::StructuredValue);
        assert_eq!(structured.verdict, DifferentialComparisonVerdict::Consensus);
    }

    #[test]
    fn engine_core_surrogate_corpus_reaches_consensus() {
        // The bd-2vzgi acceptance criterion: the lone-surrogate seed corpus
        // cases agree between the two in-process lanes (no external runtime).
        let corpus: Vec<EngineCoreCorpusCase> = default_engine_core_corpus()
            .into_iter()
            .filter(|case| {
                matches!(
                    case.case_id.as_str(),
                    "string_length_utf16"
                        | "string_char_at_surrogate_half"
                        | "string_char_at_healing"
                        | "string_char_code_at_exact_unit"
                        | "string_from_char_code_lone"
                        | "string_from_char_code_healing"
                        | "string_distinct_lone_surrogates_not_equal"
                        | "string_code_point_at_pair_combines"
                        | "string_code_point_at_low_unit"
                        | "string_from_code_point_lone"
                        | "string_from_code_point_supplementary"
                        | "string_is_well_formed_lone"
                        | "string_to_well_formed_projection"
                        | "string_relational_code_unit_order"
                        | "string_for_of_code_point_count"
                        | "string_for_of_in_function_body"
                )
            })
            .collect();
        assert_eq!(corpus.len(), 16, "all surrogate corpus cases present");
        let report = run_engine_core_differential_oracle(&corpus, 8);
        assert!(
            report.defects.is_empty(),
            "surrogate corpus defects: {:?}",
            report.defects
        );
        assert_eq!(report.agreements, corpus.len());
        assert!(report.accounting_is_consistent());
    }

    #[test]
    fn engine_memory_budget_derivation_scales_bytes_and_floors_at_default() {
        // Small override: byte ceiling is floored at the 64 MiB containment
        // default rather than collapsing to objects * 1 KiB.
        let small = engine_memory_budget_from_heap_objects(1_000);
        assert_eq!(small.max_heap_objects, 1_000);
        assert_eq!(small.max_total_memory_bytes, ENGINE_MEMORY_BUDGET_MIN_BYTES);

        // Large override: byte ceiling scales 1 KiB/object once that exceeds the
        // floor, so the byte cap does not become the new bottleneck.
        let large = engine_memory_budget_from_heap_objects(1_000_000);
        assert_eq!(large.max_heap_objects, 1_000_000);
        assert_eq!(
            large.max_total_memory_bytes,
            1_000_000 * ENGINE_MEMORY_BUDGET_BYTES_PER_OBJECT
        );

        // A count beyond u32 saturates rather than wrapping.
        let saturated = engine_memory_budget_from_heap_objects(u64::from(u32::MAX) + 10);
        assert_eq!(saturated.max_heap_objects, u32::MAX);
    }

    #[test]
    fn franken_engine_backend_memory_budget_lets_object_loop_complete() {
        // bd-fqlfw.2.11.3: the same corpus-shaped object loop fails closed on
        // the containment default but completes once the heap-object budget is
        // raised, and the override is recorded in the receipt diagnostics.
        const OBJECT_LOOP: &str = "var n=0; var i=0; \
             while(i<110000){ var obj={a:i,b:i+1}; n=n+1; i=i+1; } \
             console.log(n);";

        let without = run_franken_engine_backend(OBJECT_LOOP, Some(2_000_000_000), None).receipt;
        assert_eq!(without.status, DifferentialBackendStatus::Failed);
        assert!(
            without.stderr.to_lowercase().contains("memory budget"),
            "expected a memory-budget fault, got: {}",
            without.stderr
        );

        let with =
            run_franken_engine_backend(OBJECT_LOOP, Some(2_000_000_000), Some(1_000_000)).receipt;
        assert_eq!(with.status, DifferentialBackendStatus::Completed);
        assert_eq!(with.stdout, "110000\n");
        assert!(
            with.diagnostics
                .iter()
                .any(|line| line.starts_with("memory_budget_override=1000000 heap_objects")),
            "memory-budget override must be recorded in diagnostics: {:?}",
            with.diagnostics
        );
    }

    #[test]
    fn franken_core_backend_instruction_budget_lets_long_loop_complete() {
        // bd-v4oaz: the secondary franken-core lane must honour the same
        // `--engine-budget` instruction lever as the primary engine lane. A loop
        // that needs more than the core QuickJS 100k instruction floor fails
        // closed on the default budget but completes once the budget is threaded
        // through eval_with_franken_core, and the override is recorded in the
        // receipt diagnostics.
        const LONG_LOOP: &str =
            "var i = 0; var n = 0; while (i < 60000) { n = n + 1; i = i + 1; } n + 0;";

        let without = run_franken_core_backend(LONG_LOOP, None, None).receipt;
        assert_eq!(without.status, DifferentialBackendStatus::Failed);
        assert!(
            without.stderr.contains("instruction budget exhausted"),
            "expected an instruction-budget fault on the default core budget, got: {}",
            without.stderr
        );

        let with = run_franken_core_backend(LONG_LOOP, Some(2_000_000_000), None).receipt;
        assert_eq!(
            with.status,
            DifferentialBackendStatus::Completed,
            "raised instruction budget should let the core-lane loop complete: {}",
            with.stderr
        );
        assert_eq!(with.value.as_deref(), Some("60000"));
        assert!(
            with.diagnostics
                .iter()
                .any(|line| line.starts_with("instruction_budget_override=2000000000")),
            "instruction-budget override must be recorded in diagnostics: {:?}",
            with.diagnostics
        );
    }

    #[test]
    fn franken_core_backend_memory_budget_lever_reaches_config() {
        // bd-v4oaz: the `--engine-memory-budget` heap-object ceiling must reach
        // the franken-core lane's interpreter config too. An object-allocating
        // program completes on the default 100k heap-object ceiling but fails
        // closed once the ceiling is lowered below what it needs, and the
        // override is recorded in the receipt diagnostics. (Threading is proven
        // via a tiny ceiling rather than a 100k+ object loop, so the proof does
        // not depend on the core lane's heap-retention behaviour over huge
        // loops.)
        const OBJECT_PROG: &str = "var a={}; var b={}; var c={}; var d={}; var e={}; var f={}; var g={}; var h={}; 0 + 0;";

        let without = run_franken_core_backend(OBJECT_PROG, None, None).receipt;
        assert_eq!(
            without.status,
            DifferentialBackendStatus::Completed,
            "object program should complete on the default heap-object ceiling: {}",
            without.stderr
        );
        assert_eq!(without.value.as_deref(), Some("0"));

        let with = run_franken_core_backend(OBJECT_PROG, None, Some(2)).receipt;
        assert_eq!(with.status, DifferentialBackendStatus::Failed);
        assert!(
            with.stderr.to_lowercase().contains("memory budget"),
            "expected a memory-budget fault once the ceiling is lowered, got: {}",
            with.stderr
        );
        assert!(
            with.diagnostics
                .iter()
                .any(|line| line.starts_with("memory_budget_override=2 heap_objects")),
            "memory-budget override must be recorded in diagnostics: {:?}",
            with.diagnostics
        );
        let canonical = canonicalize_backend_receipts(std::slice::from_ref(&with));
        assert_eq!(
            canonical.observations[0].status,
            DifferentialBackendStatus::Failed,
            "the core runner's typed semantic namespace must keep its live failure in the exception domain"
        );
        assert!(
            canonical.observations[0]
                .exception_kind
                .as_deref()
                .is_some_and(|kind| kind.starts_with("eval."))
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

        let receipt =
            run_external_backend(&runtime, "ignored-source", Duration::from_secs(1)).receipt;

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

    // ---- bd-rkmpj: heap-identity handle normalization -------------------
    //
    // A bare array/object completion value renders as an opaque `[object#N]`
    // handle in both lanes; the `#N` heap index differs only because the engine
    // lane preallocates runtime globals before user code. Normalizing the index
    // (while preserving the kind) removes the spurious divergence.

    #[test]
    fn heap_identity_handle_normalization_strips_index_preserves_kind() {
        // Index-bearing handles collapse to their kind.
        assert_eq!(
            normalize_heap_identity_handle("[object#6]").as_deref(),
            Some("[object]")
        );
        assert_eq!(
            normalize_heap_identity_handle("[object#0]").as_deref(),
            Some("[object]")
        );
        assert_eq!(
            normalize_heap_identity_handle("[function#3]").as_deref(),
            Some("[function]")
        );
        assert_eq!(
            normalize_heap_identity_handle("[generatorfunction#12]").as_deref(),
            Some("[generatorfunction]")
        );

        // Non-handles and name-carrying handles are left alone.
        assert_eq!(normalize_heap_identity_handle("[builtin:Array]"), None);
        assert_eq!(normalize_heap_identity_handle("[accessor]"), None);
        assert_eq!(normalize_heap_identity_handle("42"), None);
        assert_eq!(normalize_heap_identity_handle("hello"), None);
        assert_eq!(normalize_heap_identity_handle("[object#]"), None); // empty index
        assert_eq!(normalize_heap_identity_handle("[#6]"), None); // empty kind
        assert_eq!(normalize_heap_identity_handle("[Object#6]"), None); // Display is lowercase
        assert_eq!(normalize_heap_identity_handle("[object#6"), None); // unterminated
    }

    #[test]
    fn canonicalization_matches_heap_object_completion_identity() {
        // The two in-process lanes complete `[1,2,3];` / `({a:1,b:2});` with an
        // object whose only rendered difference is the heap index — engine
        // preallocates 6 runtime globals (index 6), core starts empty (index 0).
        // After normalization these must be consensus, not a divergence.
        let report = canonicalize_backend_receipts(&[
            receipt(
                DifferentialBackend::FrankenEngine,
                DifferentialBackendStatus::Completed,
                Some("[object#6]"),
                "",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenCore,
                DifferentialBackendStatus::Completed,
                Some("[object#0]"),
                "",
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
    }

    #[test]
    fn canonicalization_detects_heap_object_vs_function_kind_divergence() {
        // Normalization preserves the KIND, so a genuine kind mismatch (object in
        // one lane, function in the other) still surfaces as a divergence.
        let report = canonicalize_backend_receipts(&[
            receipt(
                DifferentialBackend::FrankenEngine,
                DifferentialBackendStatus::Completed,
                Some("[object#6]"),
                "",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenCore,
                DifferentialBackendStatus::Completed,
                Some("[function#0]"),
                "",
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
    fn default_engine_core_corpus_has_no_residual_defects() {
        // bd-rkmpj closes the last two residual defects (array_literal,
        // object_literal) of the internal engine<->core differential oracle. The
        // default corpus must now be at full parity: every case agrees, zero
        // defects. This is the standing regression guard for the closure.
        let corpus = default_engine_core_corpus();
        let report = run_engine_core_differential_oracle(&corpus, 256);
        assert!(
            !report.has_defects(),
            "default engine<->core corpus must be at full parity: {:?}",
            report.defects
        );
        assert_eq!(
            report.agreements,
            corpus.len(),
            "every default-corpus case must agree"
        );
        assert!(report.accounting_is_consistent());
    }

    #[test]
    fn object_method_shorthand_agrees_between_engine_and_core_bd_vjmy7() {
        let corpus = vec![EngineCoreCorpusCase::new(
            "for_of_object_method_shorthand",
            r#"let it={n:0,next(){this.n=this.n+1;return {value:this.n,done:false};},return(){return {};}};let xs={[Symbol.iterator](){return it;}};let v=0;for(const x of xs){v=x;break;}v;"#,
        )];
        let report = run_engine_core_differential_oracle(&corpus, 64);
        assert!(!report.has_defects(), "{:?}", report.defects);
        assert_eq!(report.agreements, 1);
        assert_eq!(report.inconclusive, 0);
        assert!(report.accounting_is_consistent());
    }

    #[test]
    fn concise_method_identity_and_home_object_agree_between_twins_bd_gqaa4() {
        let corpus = vec![
            EngineCoreCorpusCase::new(
                "concise_method_inferred_names",
                r#"let key="computed";let o={plain(){},[key](){}};o.plain.name+"|"+o[key].name;"#,
            ),
            EngineCoreCorpusCase::new(
                "concise_method_without_prototype",
                r#"let o={plain(){}};typeof o.plain.prototype;"#,
            ),
            EngineCoreCorpusCase::new(
                "concise_method_home_object_and_dynamic_this",
                r#"let key="computed";let base={value(){return 40;}};let owner={plain(){return super.value()+this.delta;},[key](){return super.value()+this.delta+1;}};owner.__proto__=base;let alien={delta:2};alien.plain=owner.plain;alien.computed=owner[key];alien.plain()*100+alien.computed();"#,
            ),
        ];
        // Nonconstructability is pinned directly in both interpreter suites.
        // The twin oracle intentionally classifies a backend exception as
        // inconclusive, so this corpus compares the complementary successful
        // observation (`prototype` is absent) instead of disguising that
        // harness limitation with a try/catch wrapper.
        for case in &corpus {
            let case_report = run_engine_core_differential_oracle(std::slice::from_ref(case), 64);
            assert!(
                !case_report.has_defects(),
                "{}: {:?}",
                case.case_id,
                case_report.defects
            );
            assert_eq!(
                case_report.agreements, 1,
                "{} was inconclusive",
                case.case_id
            );
            assert_eq!(case_report.inconclusive, 0, "{}", case.case_id);
            assert!(case_report.accounting_is_consistent(), "{}", case.case_id);
        }
        let report = run_engine_core_differential_oracle(&corpus, 64);
        assert!(!report.has_defects(), "{:?}", report.defects);
        assert_eq!(report.agreements, corpus.len());
        assert_eq!(report.inconclusive, 0);
        assert!(report.accounting_is_consistent());
    }

    #[test]
    fn consumed_postfix_update_now_agrees_after_bd_xi3bk() {
        // bd-xi3bk regression guard at the oracle level. A consumed postfix update
        // `var x = i++` must yield i's PRIOR value (5) in BOTH lanes: franken-core
        // now lowers it through a faithful `Update` node (ToNumber + prior/new
        // result value) rather than desugaring to `i += 1` (which yielded the
        // incremented value). The internal twin must therefore AGREE. If this ever
        // regresses to a divergence, bd-xi3bk has broken.
        let input = DifferentialOracleInput::new(
            "consumed_postfix",
            "(function () { var i = 5; var x = i++; return x; })();",
        )
        .with_selected_backends([
            DifferentialBackend::FrankenEngine,
            DifferentialBackend::FrankenCore,
        ]);
        let report = run_differential_oracle(&input);
        let signature = DivergenceSignature::from_live_report(&report);
        assert!(
            !signature.has_classified_divergence(),
            "consumed-postfix update must agree across the twin after bd-xi3bk: {report:?}"
        );
    }

    #[test]
    fn canonicalizer_surfaces_a_genuine_engine_core_divergence() {
        // Honesty guard: the canonicalizer must SURFACE a real structured-value
        // difference, not smooth it away. `typeof console` is a stable
        // architectural divergence — franken-core intentionally injects no runtime
        // globals (so `typeof console` is "undefined") while the engine injects
        // them (so it is "object"). This is the load-bearing genuine divergence for
        // the surfacing / minimizer / clustering tests now that the array/object
        // (bd-rkmpj) and consumed-postfix (bd-xi3bk) cases have reached parity.
        let input = DifferentialOracleInput::new("typeof_console", "typeof console;")
            .with_selected_backends([
                DifferentialBackend::FrankenEngine,
                DifferentialBackend::FrankenCore,
            ]);
        let report = run_differential_oracle(&input);
        let signature = DivergenceSignature::from_live_report(&report);
        assert!(
            signature.has_classified_divergence(),
            "a genuine engine<->core divergence must be surfaced: {report:?}"
        );
        assert_eq!(signature.verdict, DifferentialComparisonVerdict::Divergence);
    }

    #[test]
    fn canonicalization_matches_equivalent_exception_shapes() {
        // A homogeneous all-failed cohort is a real semantic outcome domain:
        // equivalent canonical exception classes are consensus, not degraded.
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
    fn canonicalization_requires_one_full_selected_status_domain() {
        let mixed = vec![
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Completed,
                Some("1"),
                "1",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::BunStable,
                DifferentialBackendStatus::Completed,
                Some("1"),
                "1",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenEngine,
                DifferentialBackendStatus::Completed,
                Some("1"),
                "1",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenCore,
                DifferentialBackendStatus::Failed,
                None,
                "",
                "TypeError: expected object, got undefined",
                &[],
            ),
        ];
        let report = canonicalize_backend_receipts(&mixed);
        assert_eq!(
            report.semantic_verdict,
            DifferentialComparisonVerdict::InsufficientData
        );
        for mode in [
            DifferentialComparisonMode::StructuredValue,
            DifferentialComparisonMode::ExceptionClass,
        ] {
            assert_eq!(
                comparison(&report, mode).verdict,
                DifferentialComparisonVerdict::InsufficientData,
                "a semantic mode must not classify a selected status subgroup"
            );
        }
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.contains("do not share one comparable semantic status domain")
        }));

        let taxonomy = classify_differential_divergences(&mixed, &report);
        assert_eq!(
            taxonomy.verdict,
            DifferentialComparisonVerdict::InsufficientData
        );
        assert!(
            taxonomy
                .findings
                .iter()
                .all(|finding| !finding.comparison_mode.contributes_to_semantic_verdict()),
            "an incomplete status cohort must not mint a semantic finding"
        );
    }

    #[test]
    fn noncomparable_statuses_make_the_selected_cohort_insufficient() {
        for status in [
            DifferentialBackendStatus::Unavailable,
            DifferentialBackendStatus::Timeout,
            DifferentialBackendStatus::Degraded,
        ] {
            let report = canonicalize_backend_receipts(&[
                receipt(
                    DifferentialBackend::NodeLts,
                    DifferentialBackendStatus::Completed,
                    Some("1"),
                    "1",
                    "",
                    &[],
                ),
                receipt(
                    DifferentialBackend::FrankenEngine,
                    DifferentialBackendStatus::Completed,
                    Some("1"),
                    "1",
                    "",
                    &[],
                ),
                receipt(DifferentialBackend::FrankenCore, status, None, "", "", &[]),
            ]);
            assert_eq!(
                report.semantic_verdict,
                DifferentialComparisonVerdict::InsufficientData,
                "{status:?} must prevent selected-cohort consensus"
            );
        }
    }

    #[test]
    fn generic_or_no_exit_failures_are_infrastructure_degraded_in_v2() {
        let first = receipt(
            DifferentialBackend::NodeLts,
            DifferentialBackendStatus::Failed,
            None,
            "",
            "generic process failure",
            &["failed to run node_lts"],
        );
        let mut second = first.clone();
        second.backend = DifferentialBackend::BunStable;

        let current = canonicalize_backend_receipts(&[first.clone(), second.clone()]);
        assert_eq!(
            current.semantic_verdict,
            DifferentialComparisonVerdict::InsufficientData
        );
        assert!(current.observations.iter().all(|observation| {
            observation.status == DifferentialBackendStatus::Degraded
                && observation.exception_kind.is_none()
        }));

        let forged_external = receipt(
            DifferentialBackend::NodeLts,
            DifferentialBackendStatus::Failed,
            None,
            "",
            "generic process failure",
            &["eval.runtime.fault"],
        );
        let mut forged_external_peer = forged_external.clone();
        forged_external_peer.backend = DifferentialBackend::BunStable;
        let current = canonicalize_backend_receipts(&[forged_external, forged_external_peer]);
        assert!(current.observations.iter().all(|observation| {
            observation.status == DifferentialBackendStatus::Degraded
                && observation.exception_kind.is_none()
        }));

        let legacy = canonicalize_backend_receipts_v1(&[first, second]);
        assert_eq!(
            legacy.semantic_verdict,
            DifferentialComparisonVerdict::Consensus,
            "the v1 reconstruction must preserve its old evidence semantics before migration"
        );

        let mut no_exit = receipt(
            DifferentialBackend::NodeLts,
            DifferentialBackendStatus::Failed,
            None,
            "",
            "TypeError: recognizable text is insufficient without an exit code",
            &[],
        );
        no_exit.exit_code = None;
        let mut no_exit_peer = no_exit.clone();
        no_exit_peer.backend = DifferentialBackend::BunStable;
        let current = canonicalize_backend_receipts(&[no_exit, no_exit_peer]);
        assert!(current.observations.iter().all(|observation| {
            observation.status == DifferentialBackendStatus::Degraded
                && observation.exception_kind.is_none()
        }));
    }

    #[test]
    fn duplicate_backend_identities_never_form_a_semantic_cohort() {
        let node = receipt(
            DifferentialBackend::NodeLts,
            DifferentialBackendStatus::Completed,
            Some("1"),
            "1",
            "",
            &[],
        );
        let receipts = vec![node.clone(), node];
        let report = canonicalize_backend_receipts(&receipts);
        assert_eq!(
            report.semantic_verdict,
            DifferentialComparisonVerdict::InsufficientData
        );
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.contains("empty or contains duplicate backend identities")
        }));
        let taxonomy = classify_differential_divergences(&receipts, &report);
        assert_eq!(
            taxonomy.verdict,
            DifferentialComparisonVerdict::InsufficientData
        );
    }

    #[test]
    fn completed_lanes_without_full_structured_coverage_are_insufficient() {
        let report = canonicalize_backend_receipts(&[
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Completed,
                None,
                "1",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::BunStable,
                DifferentialBackendStatus::Completed,
                None,
                "",
                "",
                &[],
            ),
        ]);
        assert_eq!(
            report.semantic_verdict,
            DifferentialComparisonVerdict::InsufficientData
        );
        assert_eq!(
            comparison(&report, DifferentialComparisonMode::StructuredValue).verdict,
            DifferentialComparisonVerdict::InsufficientData
        );
    }

    #[test]
    fn status_disagreement_cannot_be_minimized_into_a_subset_divergence() {
        let completed = [
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Completed,
                Some("1"),
                "1",
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
        ];
        let mut mixed = completed.to_vec();
        mixed.push(receipt(
            DifferentialBackend::FrankenCore,
            DifferentialBackendStatus::Failed,
            None,
            "",
            "TypeError: expected object",
            &[],
        ));

        let mixed_canonicalization = canonicalize_backend_receipts(&mixed);
        let mixed_taxonomy = classify_differential_divergences(&mixed, &mixed_canonicalization);
        let mixed_signature = DivergenceSignature::from_live_taxonomy(&mixed_taxonomy);
        assert_eq!(
            mixed_signature.verdict,
            DifferentialComparisonVerdict::InsufficientData
        );
        assert!(!mixed_signature.has_classified_divergence());

        let subset_canonicalization = canonicalize_backend_receipts(&completed);
        let subset_taxonomy =
            classify_differential_divergences(&completed, &subset_canonicalization);
        let subset_signature = DivergenceSignature::from_live_taxonomy(&subset_taxonomy);
        assert!(subset_signature.has_classified_divergence());
        assert_ne!(mixed_signature, subset_signature);
    }

    const RESERVED_TAXONOMY_NEEDLES: &[&str] = &[
        "intentional-security",
        "intentional_security",
        "security divergence",
        "security-divergence",
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
        "module",
        "import",
        "require",
        "resolution",
        "resolve",
        "not found",
        "parse",
        "parser",
        "syntax",
        "unexpected token",
        "unterminated",
        "lower",
        "lowering",
        "ir2",
        "ir3",
        "ir contract",
    ];

    fn taxonomy_for_receipts(
        receipts: &[DifferentialBackendReceipt],
    ) -> DifferentialDivergenceTaxonomyReport {
        let canonicalization = canonicalize_backend_receipts(receipts);
        classify_differential_divergences(receipts, &canonicalization)
    }

    fn assert_runtime_without_waiver(
        taxonomy: &DifferentialDivergenceTaxonomyReport,
        needle: &str,
        channel: &str,
    ) {
        assert!(
            !taxonomy.findings.is_empty(),
            "{channel} injection did not produce a finding for {needle:?}"
        );
        for finding in &taxonomy.findings {
            assert_eq!(
                finding.class,
                DifferentialDivergenceClass::Runtime,
                "{channel} injection controlled taxonomy for {needle:?} in {:?}",
                finding.comparison_mode
            );
            assert_eq!(
                finding.waiver_id, None,
                "{channel} injection minted a waiver for {needle:?}"
            );
        }
        assert!(
            taxonomy.diagnostics.is_empty(),
            "{channel} injection emitted waiver diagnostics for {needle:?}: {:?}",
            taxonomy.diagnostics
        );
    }

    fn serde_roundtrip_receipts(
        receipts: &[DifferentialBackendReceipt],
    ) -> Vec<DifferentialBackendReceipt> {
        let encoded = serde_json::to_vec(receipts).expect("receipt vector should serialize");
        serde_json::from_slice(&encoded).expect("receipt vector should deserialize")
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
    fn public_classifier_recomputes_canonicalization_from_receipts() {
        let receipts = vec![
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Completed,
                Some("one"),
                "",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenEngine,
                DifferentialBackendStatus::Completed,
                Some("two"),
                "",
                "",
                &[],
            ),
        ];
        let mut forged = canonicalize_backend_receipts(&receipts);
        forged.semantic_verdict = DifferentialComparisonVerdict::Consensus;
        forged.comparisons.clear();
        let taxonomy = classify_differential_divergences(&receipts, &forged);
        assert_eq!(taxonomy.verdict, DifferentialComparisonVerdict::Divergence);
        assert_eq!(
            taxonomy_finding(&taxonomy, DifferentialComparisonMode::StructuredValue).class,
            DifferentialDivergenceClass::Runtime
        );
    }

    #[test]
    fn observable_taxonomy_needles_are_evidence_only_and_never_mint_waivers() {
        assert_eq!(RESERVED_TAXONOMY_NEEDLES.len(), 30);
        for needle in RESERVED_TAXONOMY_NEEDLES {
            let value_receipts = serde_roundtrip_receipts(&[
                receipt(
                    DifferentialBackend::NodeLts,
                    DifferentialBackendStatus::Completed,
                    Some(needle),
                    "",
                    "",
                    &[],
                ),
                receipt(
                    DifferentialBackend::FrankenEngine,
                    DifferentialBackendStatus::Completed,
                    Some("benign-value"),
                    "",
                    "",
                    &[],
                ),
            ]);
            assert_runtime_without_waiver(&taxonomy_for_receipts(&value_receipts), needle, "value");

            let stdout_receipts = serde_roundtrip_receipts(&[
                receipt(
                    DifferentialBackend::NodeLts,
                    DifferentialBackendStatus::Completed,
                    None,
                    needle,
                    "",
                    &[],
                ),
                receipt(
                    DifferentialBackend::FrankenEngine,
                    DifferentialBackendStatus::Completed,
                    None,
                    "benign-stdout",
                    "",
                    &[],
                ),
            ]);
            assert_runtime_without_waiver(
                &taxonomy_for_receipts(&stdout_receipts),
                needle,
                "stdout",
            );

            let stderr_receipts = serde_roundtrip_receipts(&[
                receipt(
                    DifferentialBackend::NodeLts,
                    DifferentialBackendStatus::Completed,
                    Some("same-value"),
                    "",
                    needle,
                    &[],
                ),
                receipt(
                    DifferentialBackend::FrankenEngine,
                    DifferentialBackendStatus::Completed,
                    Some("same-value"),
                    "",
                    "benign-stderr",
                    &[],
                ),
            ]);
            assert_runtime_without_waiver(
                &taxonomy_for_receipts(&stderr_receipts),
                needle,
                "stderr",
            );

            let failed_message = format!("TypeError: {needle}");
            let failed_stderr_receipts = serde_roundtrip_receipts(&[
                receipt(
                    DifferentialBackend::NodeLts,
                    DifferentialBackendStatus::Failed,
                    None,
                    "",
                    &failed_message,
                    &[],
                ),
                receipt(
                    DifferentialBackend::FrankenEngine,
                    DifferentialBackendStatus::Failed,
                    None,
                    "",
                    "ReferenceError: benign-failure",
                    &[],
                ),
            ]);
            assert_runtime_without_waiver(
                &taxonomy_for_receipts(&failed_stderr_receipts),
                needle,
                "failed_stderr",
            );
        }
    }

    #[test]
    fn runtime_dependent_reference_split_does_not_assign_bug_ownership() {
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
        assert_eq!(finding.class, DifferentialDivergenceClass::Runtime);
        assert_eq!(
            finding.reference_backends,
            vec![DifferentialBackend::NodeLts, DifferentialBackend::BunStable]
        );
    }

    #[test]
    fn classifier_ignores_completed_lane_bookkeeping_diagnostics() {
        // bd-fqlfw.2.3.2: a pure value divergence between two COMPLETED lanes
        // must classify as Runtime even though the franken-core lane's stock
        // path-dependency diagnostic mentions "parser"/"lowering". Bookkeeping
        // diagnostics on a completed lane must not leak into classification.
        let receipts = vec![
            receipt(
                DifferentialBackend::FrankenEngine,
                DifferentialBackendStatus::Completed,
                Some("[1, 2, 3]"),
                "[1, 2, 3]",
                "",
                &["route_reason=default_quickjs_path"],
            ),
            receipt(
                DifferentialBackend::FrankenCore,
                DifferentialBackendStatus::Completed,
                Some("1,2,3"),
                "1,2,3",
                "",
                &[
                    "frankenengine-core path dependency executed in-process through \
                     parser/lowering/QuickJsLane",
                ],
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
            DifferentialDivergenceClass::Runtime,
            "completed-lane bookkeeping must not classify a value divergence as Parser"
        );
    }

    #[test]
    fn trusted_engine_error_codes_select_base_class_without_observable_text() {
        let cases = [
            (
                EvalErrorCode::EmptySource,
                DifferentialDivergenceClass::Parser,
            ),
            (
                EvalErrorCode::ParseFailure,
                DifferentialDivergenceClass::Parser,
            ),
            (
                EvalErrorCode::ResolutionFailure,
                DifferentialDivergenceClass::ModuleResolution,
            ),
            (
                EvalErrorCode::PolicyDenied,
                DifferentialDivergenceClass::HostcallPolicy,
            ),
            (
                EvalErrorCode::CapabilityDenied,
                DifferentialDivergenceClass::HostcallPolicy,
            ),
            (
                EvalErrorCode::HostcallFault,
                DifferentialDivergenceClass::HostcallPolicy,
            ),
            (
                EvalErrorCode::RuntimeFault,
                DifferentialDivergenceClass::Runtime,
            ),
            (
                EvalErrorCode::InvariantViolation,
                DifferentialDivergenceClass::Runtime,
            ),
        ];

        for (code, expected) in cases {
            let (receipts, canonicalization) = divergent_failed_receipts(
                DifferentialBackend::FrankenEngine,
                "untrusted intentional-security parser module hostcall text",
            );
            let executions = [BackendExecution::trusted(
                receipts[1].clone(),
                TrustedTaxonomySignal::FrankenEngine(code),
            )];
            let taxonomy = classify_differential_divergences_with_trusted_context(
                &receipts,
                &canonicalization,
                &executions,
            );
            let finding = taxonomy_finding(&taxonomy, DifferentialComparisonMode::ExceptionClass);
            assert_eq!(finding.class, expected, "wrong mapping for {code:?}");
            assert!(finding.waiver_id.is_none());
        }
    }

    #[test]
    fn trusted_core_stages_and_interpreter_errors_select_exact_base_classes() {
        let stage_cases = [
            (
                FrankenCoreFailureStage::Parse,
                TrustedBaseClass::Parser,
                DifferentialDivergenceClass::Parser,
            ),
            (
                FrankenCoreFailureStage::Lower,
                TrustedBaseClass::Lowering,
                DifferentialDivergenceClass::Lowering,
            ),
            (
                FrankenCoreFailureStage::Execute,
                TrustedBaseClass::Runtime,
                DifferentialDivergenceClass::Runtime,
            ),
        ];
        for (stage, class, expected) in stage_cases {
            let (receipts, canonicalization) = divergent_failed_receipts(
                DifferentialBackend::FrankenCore,
                "untrusted intentional-security parser module hostcall text",
            );
            let executions = [BackendExecution::trusted(
                receipts[1].clone(),
                TrustedTaxonomySignal::FrankenCore { stage, class },
            )];
            let taxonomy = classify_differential_divergences_with_trusted_context(
                &receipts,
                &canonicalization,
                &executions,
            );
            assert_eq!(
                taxonomy_finding(&taxonomy, DifferentialComparisonMode::ExceptionClass).class,
                expected
            );
        }

        let interpreter_cases = [
            (
                CoreInterpreterError::ModuleResolutionFailed {
                    specifier: "x".to_string(),
                    reason: "missing".to_string(),
                },
                TrustedBaseClass::ModuleResolution,
            ),
            (
                CoreInterpreterError::ModuleParseFailed {
                    specifier: "x".to_string(),
                    error: "parse".to_string(),
                },
                TrustedBaseClass::Parser,
            ),
            (
                CoreInterpreterError::ModuleLoweringFailed {
                    specifier: "x".to_string(),
                    error: "lower".to_string(),
                },
                TrustedBaseClass::Lowering,
            ),
            (
                CoreInterpreterError::CapabilityDenied {
                    capability: "network".to_string(),
                },
                TrustedBaseClass::HostcallPolicy,
            ),
            (
                CoreInterpreterError::TypeError {
                    expected: "number".to_string(),
                    got: "object".to_string(),
                },
                TrustedBaseClass::Runtime,
            ),
        ];
        for (error, expected) in interpreter_cases {
            assert_eq!(
                FrankenCoreBackendError::from_interpreter(error).class,
                expected
            );
        }
    }

    #[test]
    fn completed_or_origin_mismatched_sidecars_cannot_control_taxonomy() {
        let receipts = vec![
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Completed,
                Some("one"),
                "",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenEngine,
                DifferentialBackendStatus::Completed,
                Some("two"),
                "",
                "",
                &[],
            ),
        ];
        let canonicalization = canonicalize_backend_receipts(&receipts);
        let completed_signal = [BackendExecution::trusted(
            receipts[1].clone(),
            TrustedTaxonomySignal::FrankenEngine(EvalErrorCode::PolicyDenied),
        )];
        let taxonomy = classify_differential_divergences_with_trusted_context(
            &receipts,
            &canonicalization,
            &completed_signal,
        );
        assert_eq!(
            taxonomy_finding(&taxonomy, DifferentialComparisonMode::StructuredValue).class,
            DifferentialDivergenceClass::Runtime
        );

        let (failed_receipts, failed_canonicalization) =
            divergent_failed_receipts(DifferentialBackend::FrankenEngine, "untrusted policy text");
        let wrong_origin = [BackendExecution::trusted(
            failed_receipts[1].clone(),
            TrustedTaxonomySignal::FrankenCore {
                stage: FrankenCoreFailureStage::Parse,
                class: TrustedBaseClass::Parser,
            },
        )];
        let taxonomy = classify_differential_divergences_with_trusted_context(
            &failed_receipts,
            &failed_canonicalization,
            &wrong_origin,
        );
        assert_eq!(
            taxonomy_finding(&taxonomy, DifferentialComparisonMode::ExceptionClass).class,
            DifferentialDivergenceClass::Runtime
        );
    }

    #[test]
    fn intentional_security_requires_an_exact_opaque_live_candidate() {
        let execution = trusted_policy_execution(b"trusted intentional-security case", false);
        let candidate =
            waiver_candidate(&execution, DifferentialComparisonMode::ExceptionClass).clone();
        assert_eq!(
            candidate.finding().class,
            DifferentialDivergenceClass::HostcallPolicy
        );
        let mut authority = DifferentialWaiverAuthority::new();
        authority
            .approve_intentional_security(
                &candidate,
                "SEC-2026-0001",
                "documented capability denial",
                "security-review-board",
                "bd-9p7z8",
            )
            .expect("exact authority should be accepted");
        let authorized = execution.clone().into_report_with_authority(&authority);
        let authorized_finding = taxonomy_finding(
            &authorized.divergence_taxonomy,
            DifferentialComparisonMode::ExceptionClass,
        );
        assert_eq!(
            authorized_finding.class,
            DifferentialDivergenceClass::IntentionalSecurityDivergence
        );
        assert_eq!(
            authorized_finding.waiver_id.as_deref(),
            Some("SEC-2026-0001")
        );
        assert!(
            authorized
                .divergence_taxonomy
                .diagnostics
                .iter()
                .any(|diagnostic| {
                    diagnostic.contains("intentional_security_divergence")
                        && diagnostic.contains("SEC-2026-0001")
                })
        );

        let wrong_source = trusted_policy_execution(b"different source", false)
            .into_report_with_authority(&authority);
        assert_eq!(
            taxonomy_finding(
                &wrong_source.divergence_taxonomy,
                DifferentialComparisonMode::ExceptionClass,
            )
            .class,
            DifferentialDivergenceClass::HostcallPolicy
        );

        // The same hash set with backend membership swapped is a different
        // scope and cannot replay the approval.
        let swapped = trusted_policy_execution(b"trusted intentional-security case", true)
            .into_report_with_authority(&authority);
        assert_eq!(
            taxonomy_finding(
                &swapped.divergence_taxonomy,
                DifferentialComparisonMode::ExceptionClass,
            )
            .class,
            DifferentialDivergenceClass::HostcallPolicy
        );

        let mut conflicting = DifferentialWaiverAuthority::new();
        conflicting
            .approve_intentional_security(&candidate, "SEC-ONE", "first", "reviewer", "bd-9p7z8")
            .expect("first exact waiver should be accepted");
        assert_eq!(
            conflicting.approve_intentional_security(
                &candidate, "SEC-TWO", "second", "reviewer", "bd-9p7z8",
            ),
            Err(DifferentialWaiverAuthorityError::ConflictingWaiver)
        );
        let other_candidate = waiver_candidate(
            &trusted_policy_execution(b"other source", false),
            DifferentialComparisonMode::ExceptionClass,
        )
        .clone();
        assert_eq!(
            conflicting.approve_intentional_security(
                &other_candidate,
                "SEC-ONE",
                "first",
                "reviewer",
                "bd-9p7z8",
            ),
            Err(DifferentialWaiverAuthorityError::ConflictingWaiver)
        );
        let mut invalid_authority = DifferentialWaiverAuthority::new();
        assert_eq!(
            invalid_authority
                .approve_intentional_security(&candidate, "", "reason", "reviewer", "bd-9p7z8",),
            Err(DifferentialWaiverAuthorityError::EmptyField("waiver_id"))
        );
    }

    #[test]
    fn untrusted_runtime_findings_never_become_waiver_candidates() {
        let (receipts, canonicalization) = divergent_failed_receipts(
            DifferentialBackend::FrankenEngine,
            "guest policy and intentional-security words",
        );
        let base = classify_differential_divergences_with_trusted_context(
            &receipts,
            &canonicalization,
            &[],
        );
        assert!(
            build_live_waiver_candidates(
                sha256_hex(b"guest-controlled case").as_str(),
                &base,
                &canonicalization,
                &[],
            )
            .is_empty()
        );
    }

    #[test]
    fn deserialized_reports_recompute_taxonomy_and_drop_waiver_authority() {
        let execution = trusted_policy_execution(b"archived policy case", false);
        let candidate =
            waiver_candidate(&execution, DifferentialComparisonMode::ExceptionClass).clone();
        let mut authority = DifferentialWaiverAuthority::new();
        authority
            .approve_intentional_security(
                &candidate,
                "SEC-ARCHIVE-1",
                "live approval only",
                "reviewer",
                "bd-9p7z8",
            )
            .expect("live candidate should be approvable");
        let authorized = execution.into_report_with_authority(&authority);
        assert_eq!(
            taxonomy_finding(
                &authorized.divergence_taxonomy,
                DifferentialComparisonMode::ExceptionClass,
            )
            .class,
            DifferentialDivergenceClass::IntentionalSecurityDivergence
        );

        let archived: DifferentialOracleReport = serde_json::from_value(
            serde_json::to_value(&authorized).expect("report should serialize"),
        )
        .expect("current report should deserialize conservatively");
        let archived_finding = taxonomy_finding(
            &archived.divergence_taxonomy,
            DifferentialComparisonMode::ExceptionClass,
        );
        assert_eq!(archived_finding.class, DifferentialDivergenceClass::Runtime);
        assert!(archived_finding.waiver_id.is_none());

        let mut legacy = serde_json::to_value(&authorized).expect("report should serialize");
        legacy["divergence_taxonomy"]["schema_version"] = serde_json::Value::String(
            "franken-engine.differential-oracle.divergence-taxonomy.v1".to_string(),
        );
        let legacy: DifferentialOracleReport =
            serde_json::from_value(legacy).expect("legacy v1 taxonomy should remain readable");
        let legacy_finding = taxonomy_finding(
            &legacy.divergence_taxonomy,
            DifferentialComparisonMode::ExceptionClass,
        );
        assert_eq!(legacy_finding.class, DifferentialDivergenceClass::Runtime);
        assert!(legacy_finding.waiver_id.is_none());
    }

    #[test]
    fn legacy_v1_canonicalization_is_validated_then_migrated_fail_closed() {
        let receipts = vec![
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Completed,
                Some("1"),
                "1",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenEngine,
                DifferentialBackendStatus::Completed,
                Some("1"),
                "1",
                "",
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenCore,
                DifferentialBackendStatus::Failed,
                None,
                "",
                "TypeError: expected object",
                &[],
            ),
        ];
        let canonicalization = canonicalize_backend_receipts(&receipts);
        let divergence_taxonomy = classify_differential_divergences(&receipts, &canonicalization);
        let report = DifferentialOracleReport {
            schema_version: DIFFERENTIAL_ORACLE_SCHEMA_VERSION.to_string(),
            generated_unix_ns: 1,
            case_id: "legacy-status-mismatch".to_string(),
            source_path: None,
            source_sha256: sha256_hex(b"legacy status mismatch"),
            host: capture_host_facts(),
            backends: receipts.clone(),
            canonicalization,
            divergence_taxonomy,
        };

        let mut archived = serde_json::to_value(&report).expect("report should serialize");
        archived["canonicalization"] =
            serde_json::to_value(canonicalize_backend_receipts_v1(&receipts))
                .expect("legacy canonicalization should serialize");
        let migrated: DifferentialOracleReport = serde_json::from_value(archived.clone())
            .expect("valid legacy v1 canonicalization should remain readable");
        assert_eq!(
            migrated.canonicalization.schema_version,
            DIFFERENTIAL_ORACLE_CANONICALIZATION_SCHEMA_VERSION
        );
        assert_eq!(
            migrated.canonicalization.semantic_verdict,
            DifferentialComparisonVerdict::InsufficientData,
            "the old subgroup consensus must be downgraded under v2"
        );

        archived["canonicalization"]["semantic_verdict"] =
            serde_json::Value::String("divergence".to_string());
        assert!(
            serde_json::from_value::<DifferentialOracleReport>(archived).is_err(),
            "legacy evidence must still match an exact v1 recomputation before migration"
        );
    }

    #[test]
    fn deserialized_reports_reject_forged_canonicalization_and_unknown_schemas() {
        let report = trusted_policy_execution(b"archive validation", false).into_report();
        let mut forged = serde_json::to_value(&report).expect("report should serialize");
        forged["canonicalization"]["semantic_verdict"] =
            serde_json::Value::String("consensus".to_string());
        assert!(serde_json::from_value::<DifferentialOracleReport>(forged).is_err());

        let mut unknown = serde_json::to_value(&report).expect("report should serialize");
        unknown["divergence_taxonomy"]["schema_version"] =
            serde_json::Value::String("attacker.taxonomy.v999".to_string());
        assert!(serde_json::from_value::<DifferentialOracleReport>(unknown).is_err());

        let mut unknown_canonicalization =
            serde_json::to_value(&report).expect("report should serialize");
        unknown_canonicalization["canonicalization"]["schema_version"] =
            serde_json::Value::String("attacker.canonicalization.v999".to_string());
        assert!(
            serde_json::from_value::<DifferentialOracleReport>(unknown_canonicalization).is_err()
        );

        let mut duplicate_backends =
            serde_json::to_value(&report).expect("report should serialize");
        let duplicate_receipt = duplicate_backends["backends"][0].clone();
        duplicate_backends["backends"][1] = duplicate_receipt;
        let duplicate_receipts: Vec<DifferentialBackendReceipt> =
            serde_json::from_value(duplicate_backends["backends"].clone())
                .expect("duplicate receipt fixture should decode");
        duplicate_backends["canonicalization"] =
            serde_json::to_value(canonicalize_backend_receipts(&duplicate_receipts))
                .expect("duplicate canonicalization should serialize");
        assert!(
            serde_json::from_value::<DifferentialOracleReport>(duplicate_backends).is_err(),
            "standalone reports must reject duplicate backend identities even when their stored canonicalization is self-consistent"
        );

        for malformed in ["garbage".to_string(), "A".repeat(64)] {
            let mut malformed_source =
                serde_json::to_value(&report).expect("report should serialize");
            malformed_source["source_sha256"] = serde_json::Value::String(malformed);
            assert!(serde_json::from_value::<DifferentialOracleReport>(malformed_source).is_err());
        }
    }

    fn trusted_policy_execution(
        source: &[u8],
        swap_group_membership: bool,
    ) -> DifferentialOracleExecution {
        let reference_error = "TypeError: reference failure";
        // Use two recognized semantic exception shapes for the evidence
        // topology. The private typed signal below, never this observable text,
        // is what assigns HostcallPolicy.
        let policy_error = "ReferenceError: capability denied";
        let (node_error, engine_error) = if swap_group_membership {
            (policy_error, reference_error)
        } else {
            (reference_error, policy_error)
        };
        let receipts = vec![
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Failed,
                None,
                "",
                node_error,
                &[],
            ),
            receipt(
                DifferentialBackend::FrankenEngine,
                DifferentialBackendStatus::Failed,
                None,
                "",
                engine_error,
                &[],
            ),
        ];
        let executions = vec![
            BackendExecution::untrusted(receipts[0].clone()),
            BackendExecution::trusted(
                receipts[1].clone(),
                TrustedTaxonomySignal::FrankenEngine(EvalErrorCode::PolicyDenied),
            ),
        ];
        let canonicalization = canonicalize_backend_receipts(&receipts);
        let divergence_taxonomy = classify_differential_divergences_with_trusted_context(
            &receipts,
            &canonicalization,
            &executions,
        );
        let source_sha256 = sha256_hex(source);
        let waiver_candidates = build_live_waiver_candidates(
            source_sha256.as_str(),
            &divergence_taxonomy,
            &canonicalization,
            &executions,
        );
        DifferentialOracleExecution {
            report: DifferentialOracleReport {
                schema_version: DIFFERENTIAL_ORACLE_SCHEMA_VERSION.to_string(),
                generated_unix_ns: 1,
                case_id: "trusted-policy-fixture".to_string(),
                source_path: None,
                source_sha256,
                host: capture_host_facts(),
                backends: receipts,
                canonicalization,
                divergence_taxonomy,
            },
            waiver_candidates,
        }
    }

    fn waiver_candidate(
        execution: &DifferentialOracleExecution,
        mode: DifferentialComparisonMode,
    ) -> &DifferentialWaiverCandidate {
        execution
            .waiver_candidates()
            .iter()
            .find(|candidate| candidate.finding().comparison_mode == mode)
            .unwrap_or_else(|| panic!("missing {mode:?} waiver candidate"))
    }

    fn divergent_failed_receipts(
        internal_backend: DifferentialBackend,
        internal_stderr: &str,
    ) -> (
        Vec<DifferentialBackendReceipt>,
        DifferentialCanonicalizationReport,
    ) {
        let internal_stderr = format!("ReferenceError: internal baseline\n{internal_stderr}");
        let receipts = vec![
            receipt(
                DifferentialBackend::NodeLts,
                DifferentialBackendStatus::Failed,
                None,
                "",
                "TypeError: reference failure",
                &[],
            ),
            receipt(
                internal_backend,
                DifferentialBackendStatus::Failed,
                None,
                "",
                &internal_stderr,
                &[],
            ),
        ];
        let canonicalization = canonicalize_backend_receipts(&receipts);
        (receipts, canonicalization)
    }

    fn taxonomy_finding(
        taxonomy: &DifferentialDivergenceTaxonomyReport,
        mode: DifferentialComparisonMode,
    ) -> &DifferentialDivergenceFinding {
        taxonomy
            .findings
            .iter()
            .find(|finding| finding.comparison_mode == mode)
            .unwrap_or_else(|| panic!("missing {mode:?} taxonomy finding"))
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
            completion_label: None,
            value_wtf16: None,
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

    // ---- E2.T5 divergence-preserving minimizer (bd-fqlfw.2.5) -----------
    //
    // These tests exercise the `ddmin` algorithm directly through a synthetic,
    // deterministic divergence predicate so the reduction logic is covered
    // exhaustively and without a heavy build. The real-oracle wiring
    // (`minimize_oracle_divergence`) is exercised end-to-end in
    // `tests/differential_oracle_minimization_bd_fqlfw_2_5.rs`.

    fn synth_sig(
        verdict: DifferentialComparisonVerdict,
        entries: &[(&str, &str)],
    ) -> DivergenceSignature {
        let mut findings = entries
            .iter()
            .map(|(mode, class)| DivergenceSignatureEntry {
                comparison_mode: (*mode).to_string(),
                class: (*class).to_string(),
            })
            .collect::<Vec<_>>();
        findings.sort();
        DivergenceSignature { verdict, findings }
    }

    fn consensus_sig() -> DivergenceSignature {
        DivergenceSignature {
            verdict: DifferentialComparisonVerdict::Consensus,
            findings: Vec::new(),
        }
    }

    fn runtime_div_sig() -> DivergenceSignature {
        synth_sig(
            DifferentialComparisonVerdict::Divergence,
            &[("structured_value", "runtime")],
        )
    }

    fn has_line(source: &str, marker: &str) -> bool {
        source.lines().any(|line| line.trim() == marker)
    }

    fn synth_finding(
        class: DifferentialDivergenceClass,
        mode: DifferentialComparisonMode,
    ) -> DifferentialDivergenceFinding {
        DifferentialDivergenceFinding {
            class,
            comparison_mode: mode,
            message: String::new(),
            affected_backends: Vec::new(),
            reference_backends: Vec::new(),
            evidence_group_hashes: Vec::new(),
            remediation_hint: String::new(),
            waiver_id: None,
        }
    }

    fn synth_taxonomy(
        verdict: DifferentialComparisonVerdict,
        findings: Vec<DifferentialDivergenceFinding>,
    ) -> DifferentialDivergenceTaxonomyReport {
        DifferentialDivergenceTaxonomyReport {
            schema_version: DIFFERENTIAL_ORACLE_DIVERGENCE_TAXONOMY_SCHEMA_VERSION.to_string(),
            verdict,
            findings,
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn minimizer_strips_filler_to_the_single_required_line() {
        let source = "// filler a\n// filler b\nBUG\n// filler c\n// filler d";
        let outcome = minimize_divergence_source(
            source,
            |candidate| {
                if has_line(candidate, "BUG") {
                    runtime_div_sig()
                } else {
                    consensus_sig()
                }
            },
            512,
        )
        .expect("source diverges, so minimization must succeed");

        assert_eq!(outcome.minimized_source, "BUG");
        assert_eq!(outcome.minimized_line_count, 1);
        assert_eq!(outcome.original_line_count, 5);
        assert!(outcome.classification_preserved);
        assert!(outcome.reached_fixed_point);
        assert!(outcome.signature.has_classified_divergence());
        assert!(outcome.minimized_len_bytes < outcome.original_len_bytes);
        assert!(outcome.accepted_reductions >= 1);
    }

    #[test]
    fn minimizer_keeps_every_line_required_for_the_classification() {
        // The divergence requires BOTH marker lines; the result must be exactly
        // those two (1-minimal), in original order, with all filler removed.
        let source = "x\nAAA\ny\nz\nBBB\nw";
        let outcome = minimize_divergence_source(
            source,
            |candidate| {
                if has_line(candidate, "AAA") && has_line(candidate, "BBB") {
                    runtime_div_sig()
                } else {
                    consensus_sig()
                }
            },
            512,
        )
        .expect("source diverges");

        let lines: Vec<&str> = outcome.minimized_source.lines().collect();
        assert_eq!(lines, vec!["AAA", "BBB"]);
        assert_eq!(outcome.minimized_line_count, 2);
        assert!(outcome.reached_fixed_point);
        assert!(outcome.classification_preserved);
    }

    #[test]
    fn minimizer_refuses_a_non_diverging_original() {
        let err = minimize_divergence_source("a\nb\nc", |_| consensus_sig(), 512)
            .expect_err("a consensus program is not minimizable");
        assert_eq!(err, DifferentialMinimizationError::NoDivergenceInOriginal);
    }

    #[test]
    fn minimizer_is_idempotent_on_an_already_minimal_case() {
        let outcome = minimize_divergence_source(
            "BUG",
            |candidate| {
                if has_line(candidate, "BUG") {
                    runtime_div_sig()
                } else {
                    consensus_sig()
                }
            },
            512,
        )
        .expect("source diverges");

        assert_eq!(outcome.minimized_source, "BUG");
        assert_eq!(outcome.accepted_reductions, 0);
        assert!(outcome.reached_fixed_point);
        // Only the original classification call was needed.
        assert_eq!(outcome.oracle_invocations, 1);
    }

    #[test]
    fn minimizer_never_drops_a_distinct_divergence_class() {
        // The original reproduces two distinct classes. Dropping either marker
        // would change the signature (e.g. to runtime-only), so a faithful
        // minimizer must keep both — it can never minimize away the intentional
        // security divergence to leave a plain runtime bug, or vice versa.
        let classify = |candidate: &str| {
            let mut entries: Vec<(&str, &str)> = Vec::new();
            if has_line(candidate, "SEC") {
                entries.push(("structured_value", "intentional_security_divergence"));
            }
            if has_line(candidate, "RUN") {
                entries.push(("structured_value", "runtime"));
            }
            if entries.is_empty() {
                consensus_sig()
            } else {
                synth_sig(DifferentialComparisonVerdict::Divergence, &entries)
            }
        };

        let source = "f1\nSEC\nf2\nRUN\nf3";
        let outcome = minimize_divergence_source(source, classify, 512).expect("source diverges");

        let lines: Vec<&str> = outcome.minimized_source.lines().collect();
        assert_eq!(lines, vec!["SEC", "RUN"]);
        assert_eq!(outcome.signature.findings.len(), 2);
        let classes: Vec<&str> = outcome
            .signature
            .findings
            .iter()
            .map(|finding| finding.class.as_str())
            .collect();
        assert!(classes.contains(&"intentional_security_divergence"));
        assert!(classes.contains(&"runtime"));
    }

    #[test]
    fn minimizer_respects_the_oracle_invocation_budget() {
        let source = (0..50)
            .map(|i| {
                if i == 25 {
                    "BUG".to_string()
                } else {
                    format!("// filler {i}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let outcome = minimize_divergence_source(
            &source,
            |candidate| {
                if has_line(candidate, "BUG") {
                    runtime_div_sig()
                } else {
                    consensus_sig()
                }
            },
            3,
        )
        .expect("source diverges");

        assert!(!outcome.reached_fixed_point);
        assert!(outcome.oracle_invocations <= 3);
        assert!(outcome.classification_preserved);
        // Even a budget-truncated reduction still reproduces the divergence.
        assert!(has_line(&outcome.minimized_source, "BUG"));
    }

    #[test]
    fn signature_is_order_independent_and_excludes_non_semantic_modes() {
        let forward = synth_taxonomy(
            DifferentialComparisonVerdict::Divergence,
            vec![
                synth_finding(
                    DifferentialDivergenceClass::Parser,
                    DifferentialComparisonMode::StructuredValue,
                ),
                synth_finding(
                    DifferentialDivergenceClass::Runtime,
                    DifferentialComparisonMode::ExceptionClass,
                ),
            ],
        );
        let reversed = synth_taxonomy(
            DifferentialComparisonVerdict::Divergence,
            vec![
                synth_finding(
                    DifferentialDivergenceClass::Runtime,
                    DifferentialComparisonMode::ExceptionClass,
                ),
                synth_finding(
                    DifferentialDivergenceClass::Parser,
                    DifferentialComparisonMode::StructuredValue,
                ),
            ],
        );
        assert_eq!(
            DivergenceSignature::from_live_taxonomy(&forward),
            DivergenceSignature::from_live_taxonomy(&reversed),
        );

        // A timing-envelope finding is non-deterministic and must be excluded so
        // the minimizer's fixed point stays stable across re-runs.
        let with_timing = synth_taxonomy(
            DifferentialComparisonVerdict::Divergence,
            vec![
                synth_finding(
                    DifferentialDivergenceClass::Runtime,
                    DifferentialComparisonMode::StructuredValue,
                ),
                synth_finding(
                    DifferentialDivergenceClass::Runtime,
                    DifferentialComparisonMode::TimingEnvelope,
                ),
            ],
        );
        let signature = DivergenceSignature::from_live_taxonomy(&with_timing);
        assert_eq!(signature.findings.len(), 1);
        assert_eq!(signature.findings[0].comparison_mode, "structured_value");
        assert!(signature.has_classified_divergence());
    }

    #[test]
    fn inconsistent_consensus_signature_is_not_a_classified_divergence() {
        let taxonomy = synth_taxonomy(
            DifferentialComparisonVerdict::Consensus,
            vec![synth_finding(
                DifferentialDivergenceClass::IntentionalSecurityDivergence,
                DifferentialComparisonMode::StructuredValue,
            )],
        );
        let signature = DivergenceSignature::from_live_taxonomy(&taxonomy);
        assert!(!signature.has_classified_divergence());
    }

    // ---- E2.T3a engine<->core internal oracle (bd-fqlfw.2.3.1) ----------
    //
    // These tests drive the REAL in-process engine and franken-core lanes (no
    // mocks, no external runtime). They cover the harness contract: every
    // classified divergence is reported as a defect carrying a minimized repro
    // that independently reproduces the same classification.

    #[test]
    fn engine_core_harness_reports_divergence_with_minimized_repro() {
        // A consensus case, a multi-line divergent case wrapped in inert filler,
        // and another consensus case. The divergent case is `typeof console`: a
        // stable architectural divergence — franken-core injects no runtime globals
        // ("undefined") while the engine injects them ("object"). (The consumed
        // postfix `i++` and array-literal cases that previously seeded this test
        // agree now — bd-xi3bk and bd-rkmpj respectively.)
        let corpus = vec![
            EngineCoreCorpusCase::new("ok_add", "1 + 1;"),
            EngineCoreCorpusCase::new(
                "divergent_typeof_global",
                "var a = 1;\nvar b = 2;\ntypeof console;",
            ),
            EngineCoreCorpusCase::new("ok_mul", "2 * 3;"),
        ];

        let report = run_engine_core_differential_oracle(&corpus, 256);

        assert_eq!(report.cases_checked, 3);
        assert!(report.accounting_is_consistent());
        assert_eq!(report.agreements, 2);
        assert_eq!(report.defects.len(), 1);

        let defect = &report.defects[0];
        assert_eq!(defect.case_id, "divergent_typeof_global");
        assert!(defect.signature.has_classified_divergence());
        // The inert `var` filler is stripped down toward the divergent expression.
        assert!(
            defect.minimized_line_count < defect.original_line_count,
            "expected reduction: {} -> {} lines",
            defect.original_line_count,
            defect.minimized_line_count
        );

        // ACCEPTANCE: the minimized repro independently reproduces the same
        // classification (recompute the signature from scratch via the real
        // oracle, do not trust the defect's own bookkeeping).
        let reverify = DivergenceSignature::from_live_report(&run_differential_oracle(
            &engine_core_oracle_input("reverify", &defect.minimized_source),
        ));
        assert_eq!(reverify, defect.signature);
    }

    #[test]
    fn engine_core_harness_is_clean_on_a_consensus_only_corpus() {
        let corpus = vec![
            EngineCoreCorpusCase::new("a", "1 + 1;"),
            EngineCoreCorpusCase::new("b", "2 * 3;"),
            EngineCoreCorpusCase::new("c", "10 - 4;"),
        ];

        let report = run_engine_core_differential_oracle(&corpus, 256);

        assert!(!report.has_defects());
        assert_eq!(report.agreements, 3);
        assert!(report.accounting_is_consistent());
    }

    #[test]
    fn default_engine_core_corpus_runs_with_consistent_accounting() {
        let corpus = default_engine_core_corpus();
        let started = Instant::now();
        let report = run_engine_core_differential_oracle(&corpus, 256);
        eprintln!(
            "[bd-fqlfw.2.3.1] default corpus: {} cases in {}ms -> {} agreements, \
             {} inconclusive, {} defects",
            report.cases_checked,
            started.elapsed().as_millis(),
            report.agreements,
            report.inconclusive,
            report.defects.len(),
        );

        assert_eq!(report.cases_checked, corpus.len());
        assert!(report.accounting_is_consistent());
        // Every reported defect must carry a reproducer that reproduces it.
        for defect in &report.defects {
            let classes: Vec<&str> = defect
                .signature
                .findings
                .iter()
                .map(|finding| finding.class.as_str())
                .collect();
            eprintln!(
                "[bd-fqlfw.2.3.1] defect {}: {:?} -> minimized {:?} (classes {:?})",
                defect.case_id, defect.original_source, defect.minimized_source, classes,
            );
            let reverify = DivergenceSignature::from_live_report(&run_differential_oracle(
                &engine_core_oracle_input(&defect.case_id, &defect.minimized_source),
            ));
            assert_eq!(reverify, defect.signature, "defect {}", defect.case_id);
        }
    }
}
