use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const FRX_LOCKSTEP_TRACE_SCHEMA_VERSION: &str = "frx.react.observable.trace.v1";
pub const FRX_LOCKSTEP_REPORT_SCHEMA_VERSION: &str = "frx.react.lockstep.oracle.report.v1";
pub const FRX_LOCKSTEP_COMPONENT: &str = "frx_react_lockstep_oracle";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrxObservableTrace {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub scenario_id: String,
    pub fixture_ref: String,
    pub seed: u64,
    pub events: Vec<FrxTraceEvent>,
    pub outcome: String,
    #[serde(default)]
    pub error_code: Option<String>,
}

impl FrxObservableTrace {
    fn normalize(&mut self) {
        self.schema_version = self.schema_version.trim().to_string();
        self.trace_id = self.trace_id.trim().to_string();
        self.decision_id = self.decision_id.trim().to_string();
        self.policy_id = self.policy_id.trim().to_string();
        self.component = self.component.trim().to_string();
        self.scenario_id = self.scenario_id.trim().to_string();
        self.fixture_ref = self.fixture_ref.trim().to_string();
        self.outcome = self.outcome.trim().to_string();
        self.error_code = self
            .error_code
            .take()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        for event in &mut self.events {
            event.normalize();
        }
    }

    fn validate(&self, label: &str) -> Result<(), FrxLockstepOracleError> {
        if self.schema_version != FRX_LOCKSTEP_TRACE_SCHEMA_VERSION {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.schema_version `{}` != expected `{}`",
                self.schema_version, FRX_LOCKSTEP_TRACE_SCHEMA_VERSION
            )));
        }
        if self.trace_id.is_empty() {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.trace_id must not be empty"
            )));
        }
        if self.decision_id.is_empty() {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.decision_id must not be empty"
            )));
        }
        if self.policy_id.is_empty() {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.policy_id must not be empty"
            )));
        }
        if self.component.is_empty() {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.component must not be empty"
            )));
        }
        if self.scenario_id.is_empty() {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.scenario_id must not be empty"
            )));
        }
        if self.fixture_ref.is_empty() {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.fixture_ref must not be empty"
            )));
        }
        if self.events.is_empty() {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.events must not be empty"
            )));
        }
        ensure_monotonic_events(&self.events, label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrxTraceEvent {
    pub seq: u64,
    pub phase: String,
    pub actor: String,
    pub event: String,
    pub decision_path: String,
    pub timing_us: u64,
    pub outcome: String,
}

impl FrxTraceEvent {
    fn normalize(&mut self) {
        self.phase = self.phase.trim().to_string();
        self.actor = self.actor.trim().to_string();
        self.event = self.event.trim().to_string();
        self.decision_path = self.decision_path.trim().to_string();
        self.outcome = self.outcome.trim().to_string();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrxLockstepCaseInput {
    pub fixture_ref: String,
    pub scenario_id: String,
    pub react_trace: FrxObservableTrace,
    pub franken_trace: FrxObservableTrace,
    pub react_trace_path: Option<PathBuf>,
    pub franken_trace_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrxDivergenceClass {
    DomMutationTrace,
    EffectInvocationOrder,
    StateTransition,
    HydrationOutcome,
    EventSequence,
    SchemaViolation,
}

impl FrxDivergenceClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DomMutationTrace => "dom_mutation_trace",
            Self::EffectInvocationOrder => "effect_invocation_order",
            Self::StateTransition => "state_transition",
            Self::HydrationOutcome => "hydration_outcome",
            Self::EventSequence => "event_sequence",
            Self::SchemaViolation => "schema_violation",
        }
    }
}

impl fmt::Display for FrxDivergenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed evidence atoms for divergence classification (bd-cixqu.9.2).
///
/// Each lockstep oracle divergence is classified into one of these categories
/// for systematic triage and evidence ledger integration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceEvidenceAtom {
    /// Genuine FrankenEngine bug - behavior differs from reference implementation incorrectly
    EngineBug {
        divergence_class: FrxDivergenceClass,
        severity: BugSeverity,
        reproducer: String,
        expected_behavior: String,
        actual_behavior: String,
    },
    /// Intentional improvement - FrankenEngine deliberately improves on reference behavior
    IntentionalImprovement {
        divergence_class: FrxDivergenceClass,
        improvement_type: ImprovementType,
        rationale: String,
        compatibility_impact: CompatibilityImpact,
    },
    /// Compatibility debt - Known deviation that needs addressing for ecosystem compatibility
    CompatibilityDebt {
        divergence_class: FrxDivergenceClass,
        debt_priority: DebtPriority,
        ecosystem_impact: Vec<String>,
        mitigation_strategy: Option<String>,
    },
    /// Ecosystem ambiguity - Reference implementations disagree or behavior is underspecified
    EcosystemAmbiguity {
        divergence_class: FrxDivergenceClass,
        ambiguity_type: AmbiguityType,
        reference_behaviors: Vec<ReferenceRuntimeBehavior>,
        franken_behavior: String,
        specification_gap: Option<String>,
    },
}

/// Bug severity levels for EngineBug atoms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BugSeverity {
    /// Causes incorrect program termination or data corruption
    Critical,
    /// Causes incorrect program behavior but no corruption
    Major,
    /// Minor behavioral deviation with minimal impact
    Minor,
    /// Cosmetic differences (e.g., error message formatting)
    Cosmetic,
}

/// Types of intentional improvements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementType {
    /// Better performance characteristics
    Performance,
    /// Enhanced security properties
    Security,
    /// Improved error diagnostics
    Diagnostics,
    /// Better memory efficiency
    MemoryEfficiency,
    /// Enhanced determinism properties
    Determinism,
}

/// Compatibility impact assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityImpact {
    /// No impact on existing code
    None,
    /// May affect edge cases in unusual code patterns
    Minimal,
    /// Could affect some real-world code
    Moderate,
    /// Likely to affect significant amount of real-world code
    Significant,
}

/// Compatibility debt priority levels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebtPriority {
    /// Must be fixed before v1.0 release
    Blocker,
    /// Should be fixed for ecosystem compatibility
    High,
    /// Nice to have for broader compatibility
    Medium,
    /// Low impact, can be deferred
    Low,
}

/// Types of ecosystem ambiguity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguityType {
    /// ECMAScript specification is unclear or incomplete
    SpecificationGap,
    /// Reference implementations disagree on behavior
    ImplementationDivergence,
    /// Historical evolution led to multiple valid behaviors
    LegacyVariation,
    /// Platform-specific behavior that varies by environment
    PlatformSpecific,
}

/// Behavior observed in a reference runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceRuntimeBehavior {
    pub runtime_name: String,
    pub runtime_version: String,
    pub observed_behavior: String,
    pub context_notes: Option<String>,
}

/// Signed evidence atom for divergence classification (bd-cixqu.9.2).
///
/// Each divergence produces a signed evidence atom that chains into the evidence ledger
/// for auditable triage and classification decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDivergenceEvidence {
    pub schema_version: String,
    pub evidence_id: String,
    pub generated_at_utc: String,
    pub lockstep_case_id: String,
    pub classification: DivergenceEvidenceAtom,
    pub original_divergence: FrxDivergenceDetail,
    pub classification_confidence: ClassificationConfidence,
    pub evidence_sources: Vec<EvidenceSource>,
    pub signature: Option<String>,
}

/// Classification confidence levels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationConfidence {
    /// Automated classification with high confidence
    Automated,
    /// Human-reviewed and confirmed
    HumanConfirmed,
    /// Requires further investigation
    Tentative,
    /// Disputed classification requiring resolution
    Disputed,
}

/// Sources of evidence used for classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSource {
    pub source_type: EvidenceSourceType,
    pub identifier: String,
    pub description: String,
}

/// Types of evidence sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceType {
    /// ECMAScript specification section
    Specification,
    /// Reference implementation behavior
    ReferenceImplementation,
    /// Test262 test suite results
    Test262,
    /// Community discussions or issues
    Community,
    /// Historical behavior analysis
    Historical,
    /// Manual investigation results
    Manual,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrxTraceEventSignature {
    pub seq: u64,
    pub phase: String,
    pub event: String,
    pub decision_path: String,
    pub outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrxDivergenceDetail {
    pub class: FrxDivergenceClass,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_index: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub react_signature: Option<FrxTraceEventSignature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub franken_signature: Option<FrxTraceEventSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrxLockstepCaseResult {
    pub fixture_ref: String,
    pub scenario_id: String,
    pub react_trace_id: String,
    pub franken_trace_id: String,
    pub pass: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divergence: Option<FrxDivergenceDetail>,
    pub replay_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrxLockstepSummary {
    pub total_cases: u64,
    pub pass_cases: u64,
    pub failed_cases: u64,
    pub divergence_counts_by_class: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrxLockstepReport {
    pub schema_version: String,
    pub generated_at_utc: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub react_traces_dir: String,
    pub franken_traces_dir: String,
    pub summary: FrxLockstepSummary,
    pub case_results: Vec<FrxLockstepCaseResult>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrxLockstepRunContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl FrxLockstepRunContext {
    pub fn with_defaults() -> Self {
        let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        Self {
            trace_id: format!("trace-frx-lockstep-oracle-{timestamp}"),
            decision_id: format!("decision-frx-lockstep-oracle-{timestamp}"),
            policy_id: "policy-frx-lockstep-oracle-v1".to_string(),
        }
    }

    pub fn deterministic(trace_id: &str, decision_id: &str, policy_id: &str) -> Self {
        Self {
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: policy_id.to_string(),
        }
    }
}

#[derive(Debug, Error)]
pub enum FrxLockstepOracleError {
    #[error("invalid lockstep input: {0}")]
    InvalidInput(String),
    #[error("failed to read `{path}`: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse trace JSON `{path}`: {source}")]
    ParseTrace {
        path: String,
        source: serde_json::Error,
    },
}

pub fn load_trace_file(path: &Path) -> Result<FrxObservableTrace, FrxLockstepOracleError> {
    let raw = fs::read_to_string(path).map_err(|source| FrxLockstepOracleError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;
    let mut trace = serde_json::from_str::<FrxObservableTrace>(&raw).map_err(|source| {
        FrxLockstepOracleError::ParseTrace {
            path: path.display().to_string(),
            source,
        }
    })?;
    trace.normalize();
    Ok(trace)
}

pub fn evaluate_case(
    mut input: FrxLockstepCaseInput,
) -> Result<FrxLockstepCaseResult, FrxLockstepOracleError> {
    input.fixture_ref = input.fixture_ref.trim().to_string();
    input.scenario_id = input.scenario_id.trim().to_string();
    input.react_trace.normalize();
    input.franken_trace.normalize();

    if input.fixture_ref.is_empty() {
        return Err(FrxLockstepOracleError::InvalidInput(
            "fixture_ref must not be empty".to_string(),
        ));
    }
    if input.scenario_id.is_empty() {
        return Err(FrxLockstepOracleError::InvalidInput(
            "scenario_id must not be empty".to_string(),
        ));
    }

    input.react_trace.validate("react_trace")?;
    input.franken_trace.validate("franken_trace")?;

    if input.react_trace.fixture_ref != input.fixture_ref {
        return Err(FrxLockstepOracleError::InvalidInput(format!(
            "react trace fixture_ref `{}` != case fixture_ref `{}`",
            input.react_trace.fixture_ref, input.fixture_ref
        )));
    }
    if input.franken_trace.fixture_ref != input.fixture_ref {
        return Err(FrxLockstepOracleError::InvalidInput(format!(
            "franken trace fixture_ref `{}` != case fixture_ref `{}`",
            input.franken_trace.fixture_ref, input.fixture_ref
        )));
    }
    if input.react_trace.scenario_id != input.scenario_id {
        return Err(FrxLockstepOracleError::InvalidInput(format!(
            "react trace scenario_id `{}` != case scenario_id `{}`",
            input.react_trace.scenario_id, input.scenario_id
        )));
    }
    if input.franken_trace.scenario_id != input.scenario_id {
        return Err(FrxLockstepOracleError::InvalidInput(format!(
            "franken trace scenario_id `{}` != case scenario_id `{}`",
            input.franken_trace.scenario_id, input.scenario_id
        )));
    }

    let replay_command = build_replay_command(&input);
    let divergence = compare_traces(&input.react_trace, &input.franken_trace);

    Ok(FrxLockstepCaseResult {
        fixture_ref: input.fixture_ref,
        scenario_id: input.scenario_id,
        react_trace_id: input.react_trace.trace_id,
        franken_trace_id: input.franken_trace.trace_id,
        pass: divergence.is_none(),
        divergence,
        replay_command,
    })
}

pub fn run_lockstep_oracle(
    react_traces_dir: &Path,
    franken_traces_dir: &Path,
    context: FrxLockstepRunContext,
    fixture_ref_filter: Option<&str>,
) -> Result<FrxLockstepReport, FrxLockstepOracleError> {
    if context.trace_id.trim().is_empty() {
        return Err(FrxLockstepOracleError::InvalidInput(
            "run context trace_id must not be empty".to_string(),
        ));
    }
    if context.decision_id.trim().is_empty() {
        return Err(FrxLockstepOracleError::InvalidInput(
            "run context decision_id must not be empty".to_string(),
        ));
    }
    if context.policy_id.trim().is_empty() {
        return Err(FrxLockstepOracleError::InvalidInput(
            "run context policy_id must not be empty".to_string(),
        ));
    }

    let filter = fixture_ref_filter
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let baseline_files = list_trace_files(react_traces_dir)?;
    if baseline_files.is_empty() {
        return Err(FrxLockstepOracleError::InvalidInput(format!(
            "no .trace.json files found in `{}`",
            react_traces_dir.display()
        )));
    }

    let mut case_results = Vec::new();
    for react_path in baseline_files {
        let fixture_ref = fixture_ref_from_trace_filename(react_path.as_path())?;
        if let Some(target_fixture_ref) = filter
            && fixture_ref != target_fixture_ref
        {
            continue;
        }

        let react_trace = load_trace_file(react_path.as_path())?;
        let franken_path = franken_traces_dir.join(react_path.file_name().ok_or_else(|| {
            FrxLockstepOracleError::InvalidInput(format!(
                "trace path `{}` missing filename",
                react_path.display()
            ))
        })?);

        if !franken_path.exists() {
            case_results.push(missing_trace_result(
                fixture_ref,
                react_trace,
                react_path,
                franken_path,
            ));
            continue;
        }

        let franken_trace = load_trace_file(franken_path.as_path())?;
        let scenario_id = react_trace.scenario_id.clone();

        let case_input = FrxLockstepCaseInput {
            fixture_ref,
            scenario_id,
            react_trace,
            franken_trace,
            react_trace_path: Some(react_path),
            franken_trace_path: Some(franken_path),
        };
        let invalid_case_context = FrxInvalidCaseContext::from_input(&case_input);

        match evaluate_case(case_input) {
            Ok(result) => case_results.push(result),
            Err(err) => {
                case_results.push(invalid_case_result(invalid_case_context, err));
            }
        }
    }

    if case_results.is_empty() {
        return Err(FrxLockstepOracleError::InvalidInput(
            "fixture_ref filter excluded all traces".to_string(),
        ));
    }

    let summary = summarize(&case_results);

    Ok(FrxLockstepReport {
        schema_version: FRX_LOCKSTEP_REPORT_SCHEMA_VERSION.to_string(),
        generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        trace_id: context.trace_id,
        decision_id: context.decision_id,
        policy_id: context.policy_id,
        component: FRX_LOCKSTEP_COMPONENT.to_string(),
        react_traces_dir: react_traces_dir.display().to_string(),
        franken_traces_dir: franken_traces_dir.display().to_string(),
        summary,
        case_results,
    })
}

fn summarize(case_results: &[FrxLockstepCaseResult]) -> FrxLockstepSummary {
    let mut pass_cases = 0_u64;
    let mut failed_cases = 0_u64;
    let mut divergence_counts_by_class = BTreeMap::new();

    for result in case_results {
        if result.pass {
            pass_cases += 1;
            continue;
        }
        failed_cases += 1;
        if let Some(divergence) = &result.divergence {
            let key = divergence.class.as_str().to_string();
            *divergence_counts_by_class.entry(key).or_insert(0) += 1;
        }
    }

    FrxLockstepSummary {
        total_cases: case_results.len() as u64,
        pass_cases,
        failed_cases,
        divergence_counts_by_class,
    }
}

fn list_trace_files(dir: &Path) -> Result<Vec<PathBuf>, FrxLockstepOracleError> {
    let mut files = Vec::new();
    let iter = fs::read_dir(dir).map_err(|source| FrxLockstepOracleError::ReadFile {
        path: dir.display().to_string(),
        source,
    })?;

    for entry in iter {
        let entry = entry.map_err(|source| FrxLockstepOracleError::ReadFile {
            path: dir.display().to_string(),
            source,
        })?;
        let path = entry.path();
        let is_trace = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".trace.json"));
        if is_trace {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn fixture_ref_from_trace_filename(path: &Path) -> Result<String, FrxLockstepOracleError> {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            FrxLockstepOracleError::InvalidInput(format!(
                "trace path `{}` has invalid filename",
                path.display()
            ))
        })?;

    let Some(fixture_ref) = filename.strip_suffix(".trace.json") else {
        return Err(FrxLockstepOracleError::InvalidInput(format!(
            "trace filename `{filename}` does not end with `.trace.json`"
        )));
    };

    Ok(fixture_ref.to_string())
}

fn build_replay_command(input: &FrxLockstepCaseInput) -> String {
    match (&input.react_trace_path, &input.franken_trace_path) {
        (Some(react_path), Some(franken_path)) => build_replay_run_command(
            react_path.parent().unwrap_or_else(|| Path::new(".")),
            franken_path.parent().unwrap_or_else(|| Path::new(".")),
            input.fixture_ref.as_str(),
        ),
        _ => default_replay_test_command(),
    }
}

fn build_replay_run_command(
    react_traces_dir: &Path,
    franken_traces_dir: &Path,
    fixture_ref: &str,
) -> String {
    format!(
        "rch cargo run -p frankenengine-engine --bin frx_lockstep_oracle -- --react-traces-dir {} --franken-traces-dir {} --fixture-ref {} --fail-on-divergence",
        shell_escape_path(react_traces_dir),
        shell_escape_path(franken_traces_dir),
        shell_escape_argument(fixture_ref),
    )
}

fn default_replay_test_command() -> String {
    "rch cargo test -p frankenengine-engine --test frx_lockstep_oracle -- --nocapture".to_string()
}

fn shell_escape_path(path: &Path) -> String {
    shell_escape_argument(&path.display().to_string())
}

fn shell_escape_argument(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value.bytes().all(|byte| {
        matches!(
            byte,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'@'
                | b'%'
                | b'_'
                | b'+'
                | b'='
                | b':'
                | b','
                | b'.'
                | b'/'
                | b'-'
        )
    }) {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn missing_trace_result(
    fixture_ref: String,
    react_trace: FrxObservableTrace,
    react_path: PathBuf,
    franken_path: PathBuf,
) -> FrxLockstepCaseResult {
    let replay_command = build_replay_run_command(
        react_path.parent().unwrap_or_else(|| Path::new(".")),
        franken_path.parent().unwrap_or_else(|| Path::new(".")),
        fixture_ref.as_str(),
    );
    FrxLockstepCaseResult {
        fixture_ref,
        scenario_id: react_trace.scenario_id,
        react_trace_id: react_trace.trace_id,
        franken_trace_id: "missing".to_string(),
        pass: false,
        divergence: Some(FrxDivergenceDetail {
            class: FrxDivergenceClass::SchemaViolation,
            message: format!(
                "missing FrankenReact trace file `{}` for baseline `{}`",
                franken_path.display(),
                react_path.display()
            ),
            event_index: None,
            react_signature: None,
            franken_signature: None,
        }),
        replay_command,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FrxInvalidCaseContext {
    fixture_ref: String,
    scenario_id: String,
    react_trace_id: String,
    franken_trace_id: String,
    replay_command: String,
}

impl FrxInvalidCaseContext {
    fn from_input(input: &FrxLockstepCaseInput) -> Self {
        let fixture_ref = invalid_case_identity(input.fixture_ref.as_str(), "invalid-fixture-ref");
        let replay_command = match (&input.react_trace_path, &input.franken_trace_path) {
            (Some(react_path), Some(franken_path)) => build_replay_run_command(
                react_path.parent().unwrap_or_else(|| Path::new(".")),
                franken_path.parent().unwrap_or_else(|| Path::new(".")),
                fixture_ref.as_str(),
            ),
            _ => default_replay_test_command(),
        };
        Self {
            fixture_ref,
            scenario_id: invalid_case_identity(input.scenario_id.as_str(), "invalid-scenario-id"),
            react_trace_id: invalid_case_identity(
                input.react_trace.trace_id.as_str(),
                "invalid-react-trace",
            ),
            franken_trace_id: invalid_case_identity(
                input.franken_trace.trace_id.as_str(),
                "invalid-franken-trace",
            ),
            replay_command,
        }
    }
}

fn invalid_case_identity(value: &str, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.to_string()
    }
}

fn invalid_case_result(
    context: FrxInvalidCaseContext,
    err: FrxLockstepOracleError,
) -> FrxLockstepCaseResult {
    FrxLockstepCaseResult {
        fixture_ref: context.fixture_ref,
        scenario_id: context.scenario_id,
        react_trace_id: context.react_trace_id,
        franken_trace_id: context.franken_trace_id,
        pass: false,
        divergence: Some(FrxDivergenceDetail {
            class: FrxDivergenceClass::SchemaViolation,
            message: err.to_string(),
            event_index: None,
            react_signature: None,
            franken_signature: None,
        }),
        replay_command: context.replay_command,
    }
}

fn compare_traces(
    react_trace: &FrxObservableTrace,
    franken_trace: &FrxObservableTrace,
) -> Option<FrxDivergenceDetail> {
    if react_trace.events.len() != franken_trace.events.len() {
        return Some(FrxDivergenceDetail {
            class: FrxDivergenceClass::EventSequence,
            message: format!(
                "event count mismatch: react={} franken={}",
                react_trace.events.len(),
                franken_trace.events.len()
            ),
            event_index: None,
            react_signature: None,
            franken_signature: None,
        });
    }

    for (idx, (react_event, franken_event)) in react_trace
        .events
        .iter()
        .zip(franken_trace.events.iter())
        .enumerate()
    {
        let react_sig = canonical_event_signature(react_event);
        let franken_sig = canonical_event_signature(franken_event);
        if react_sig != franken_sig {
            let class = classify_mismatch(react_event, franken_event);
            return Some(FrxDivergenceDetail {
                class,
                message: format!(
                    "event mismatch at index {idx}: react=`{}|{}|{}|{}` franken=`{}|{}|{}|{}`",
                    react_sig.phase,
                    react_sig.event,
                    react_sig.decision_path,
                    react_sig.outcome,
                    franken_sig.phase,
                    franken_sig.event,
                    franken_sig.decision_path,
                    franken_sig.outcome
                ),
                event_index: Some(idx),
                react_signature: Some(react_sig),
                franken_signature: Some(franken_sig),
            });
        }
    }

    if canonicalize_token(react_trace.outcome.as_str())
        != canonicalize_token(franken_trace.outcome.as_str())
    {
        return Some(FrxDivergenceDetail {
            class: FrxDivergenceClass::EventSequence,
            message: format!(
                "trace outcome mismatch: react=`{}` franken=`{}`",
                react_trace.outcome, franken_trace.outcome
            ),
            event_index: None,
            react_signature: None,
            franken_signature: None,
        });
    }

    if react_trace.error_code != franken_trace.error_code {
        return Some(FrxDivergenceDetail {
            class: FrxDivergenceClass::SchemaViolation,
            message: format!(
                "error_code mismatch: react={:?} franken={:?}",
                react_trace.error_code, franken_trace.error_code
            ),
            event_index: None,
            react_signature: None,
            franken_signature: None,
        });
    }

    None
}

fn canonical_event_signature(event: &FrxTraceEvent) -> FrxTraceEventSignature {
    FrxTraceEventSignature {
        seq: event.seq,
        phase: canonicalize_token(event.phase.as_str()),
        event: canonicalize_token(event.event.as_str()),
        decision_path: canonicalize_token(event.decision_path.as_str()),
        outcome: canonicalize_token(event.outcome.as_str()),
    }
}

fn canonicalize_token(value: &str) -> String {
    let trimmed = value.trim().to_ascii_lowercase();
    let first_segment = trimmed
        .split(':')
        .next()
        .expect("operation should succeed for valid inputs");

    let mut normalized = String::with_capacity(first_segment.len());
    let mut previous_underscore = false;
    for byte in first_segment.bytes() {
        let next = if byte.is_ascii_alphanumeric() || byte == b'-' {
            byte as char
        } else {
            '_'
        };
        if next == '_' && previous_underscore {
            continue;
        }
        previous_underscore = next == '_';
        normalized.push(next);
    }
    normalized.trim_matches('_').to_string()
}

fn classify_mismatch(
    react_event: &FrxTraceEvent,
    franken_event: &FrxTraceEvent,
) -> FrxDivergenceClass {
    let combined = format!(
        "{} {} {} {} {} {}",
        react_event.phase,
        react_event.event,
        react_event.decision_path,
        franken_event.phase,
        franken_event.event,
        franken_event.decision_path,
    )
    .to_ascii_lowercase();

    if contains_any(
        combined.as_str(),
        &["hydrate", "hydration", "mismatch", "server", "client"],
    ) {
        return FrxDivergenceClass::HydrationOutcome;
    }
    if contains_any(
        combined.as_str(),
        &[
            "effect",
            "cleanup",
            "layout",
            "passive",
            "insertion",
            "hook",
        ],
    ) {
        return FrxDivergenceClass::EffectInvocationOrder;
    }
    if contains_any(
        combined.as_str(),
        &[
            "state",
            "dispatch",
            "transition",
            "reducer",
            "context",
            "batch",
        ],
    ) {
        return FrxDivergenceClass::StateTransition;
    }
    if contains_any(
        combined.as_str(),
        &["dom", "render", "portal", "patch", "commit"],
    ) {
        return FrxDivergenceClass::DomMutationTrace;
    }
    FrxDivergenceClass::EventSequence
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn ensure_monotonic_events(
    events: &[FrxTraceEvent],
    label: &str,
) -> Result<(), FrxLockstepOracleError> {
    let mut previous_seq = 0_u64;
    let mut previous_timing = 0_u64;
    for event in events {
        if event.phase.is_empty() {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.events[].phase must not be empty"
            )));
        }
        if event.actor.is_empty() {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.events[].actor must not be empty"
            )));
        }
        if event.event.is_empty() {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.events[].event must not be empty"
            )));
        }
        if event.decision_path.is_empty() {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.events[].decision_path must not be empty"
            )));
        }
        if event.outcome.is_empty() {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.events[].outcome must not be empty"
            )));
        }
        if event.seq <= previous_seq {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.events[].seq must be strictly increasing"
            )));
        }
        if event.timing_us < previous_timing {
            return Err(FrxLockstepOracleError::InvalidInput(format!(
                "{label}.events[].timing_us must be monotonic"
            )));
        }
        previous_seq = event.seq;
        previous_timing = event.timing_us;
    }
    Ok(())
}

/// Run lockstep oracle comparing Node.js execution traces against FrankenEngine traces.
///
/// This function works similarly to `run_lockstep_oracle` but compares Node.js traces
/// (as the baseline) against FrankenEngine traces for differential checking.
pub fn run_node_lockstep_oracle(
    node_traces_dir: &Path,
    franken_traces_dir: &Path,
    context: FrxLockstepRunContext,
    fixture_ref_filter: Option<&str>,
) -> Result<FrxLockstepReport, FrxLockstepOracleError> {
    run_runtime_lockstep_oracle(
        node_traces_dir,
        franken_traces_dir,
        context,
        fixture_ref_filter,
        "Node.js",
    )
}

/// Run lockstep oracle comparing Bun execution traces against FrankenEngine traces.
///
/// This function works similarly to `run_lockstep_oracle` but compares Bun traces
/// (as the baseline) against FrankenEngine traces for differential checking.
pub fn run_bun_lockstep_oracle(
    bun_traces_dir: &Path,
    franken_traces_dir: &Path,
    context: FrxLockstepRunContext,
    fixture_ref_filter: Option<&str>,
) -> Result<FrxLockstepReport, FrxLockstepOracleError> {
    run_runtime_lockstep_oracle(
        bun_traces_dir,
        franken_traces_dir,
        context,
        fixture_ref_filter,
        "Bun",
    )
}

/// Internal implementation for runtime-specific lockstep oracle operations.
///
/// This generalizes the comparison logic to work with any two trace directories,
/// where the first directory contains baseline runtime traces and the second
/// contains FrankenEngine traces for comparison.
fn run_runtime_lockstep_oracle(
    baseline_traces_dir: &Path,
    franken_traces_dir: &Path,
    context: FrxLockstepRunContext,
    fixture_ref_filter: Option<&str>,
    runtime_name: &str,
) -> Result<FrxLockstepReport, FrxLockstepOracleError> {
    if context.trace_id.trim().is_empty() {
        return Err(FrxLockstepOracleError::InvalidInput(
            "run context trace_id must not be empty".to_string(),
        ));
    }
    if context.decision_id.trim().is_empty() {
        return Err(FrxLockstepOracleError::InvalidInput(
            "run context decision_id must not be empty".to_string(),
        ));
    }
    if context.policy_id.trim().is_empty() {
        return Err(FrxLockstepOracleError::InvalidInput(
            "run context policy_id must not be empty".to_string(),
        ));
    }

    let filter = fixture_ref_filter
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let baseline_files = list_trace_files(baseline_traces_dir)?;
    if baseline_files.is_empty() {
        return Err(FrxLockstepOracleError::InvalidInput(format!(
            "no .trace.json files found in `{}`",
            baseline_traces_dir.display()
        )));
    }

    let mut case_results = Vec::new();
    for baseline_path in baseline_files {
        let fixture_ref = fixture_ref_from_trace_filename(baseline_path.as_path())?;
        if let Some(target_fixture_ref) = filter
            && fixture_ref != target_fixture_ref
        {
            continue;
        }

        let baseline_trace = load_trace_file(baseline_path.as_path())?;
        let franken_path = franken_traces_dir.join(baseline_path.file_name().ok_or_else(|| {
            FrxLockstepOracleError::InvalidInput(format!(
                "trace path `{}` missing filename",
                baseline_path.display()
            ))
        })?);

        if !franken_path.exists() {
            case_results.push(missing_runtime_trace_result(
                fixture_ref,
                baseline_trace,
                baseline_path,
                franken_path,
                runtime_name,
            ));
            continue;
        }

        let franken_trace = load_trace_file(franken_path.as_path())?;
        let scenario_id = baseline_trace.scenario_id.clone();

        // Create case input with runtime trace as baseline and franken trace as comparison
        let case_input = FrxLockstepCaseInput {
            fixture_ref,
            scenario_id,
            react_trace: baseline_trace, // Using baseline trace in the react_trace field
            franken_trace,
            react_trace_path: Some(baseline_path),
            franken_trace_path: Some(franken_path),
        };
        let invalid_case_context = FrxInvalidCaseContext::from_input(&case_input);

        match evaluate_case(case_input) {
            Ok(result) => case_results.push(result),
            Err(err) => {
                case_results.push(invalid_case_result(invalid_case_context, err));
            }
        }
    }

    if case_results.is_empty() {
        return Err(FrxLockstepOracleError::InvalidInput(
            "fixture_ref filter excluded all traces".to_string(),
        ));
    }

    let summary = summarize(&case_results);

    Ok(FrxLockstepReport {
        schema_version: FRX_LOCKSTEP_REPORT_SCHEMA_VERSION.to_string(),
        generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        trace_id: context.trace_id,
        decision_id: context.decision_id,
        policy_id: context.policy_id,
        component: FRX_LOCKSTEP_COMPONENT.to_string(),
        react_traces_dir: baseline_traces_dir.display().to_string(),
        franken_traces_dir: franken_traces_dir.display().to_string(),
        summary,
        case_results,
    })
}

/// Create trace files in FrxObservableTrace format for runtime comparison benchmarks.
///
/// This function generates trace files suitable for lockstep oracle comparison from
/// benchmark execution results. Each workload execution is captured as a trace with
/// events for execution phases (start, console output, completion).
pub fn create_runtime_benchmark_trace(
    workload_id: &str,
    runtime_name: &str,
    execution_result: RuntimeBenchmarkResult,
    output_path: &Path,
) -> Result<(), FrxLockstepOracleError> {
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let trace_id = format!("trace-{runtime_name}-{workload_id}-{timestamp}");
    let decision_id = format!("decision-{runtime_name}-{workload_id}-{timestamp}");

    let mut events = Vec::new();
    let mut seq = 1_u64;

    // Execution start event
    events.push(FrxTraceEvent {
        seq,
        phase: "execution".to_string(),
        actor: runtime_name.to_string(),
        event: "start".to_string(),
        decision_path: format!("benchmark/{workload_id}"),
        timing_us: 0, // Relative timing from execution start
        outcome: "ok".to_string(),
    });
    seq += 1;

    // Console output event (if present)
    if !execution_result.stdout.trim().is_empty() {
        events.push(FrxTraceEvent {
            seq,
            phase: "execution".to_string(),
            actor: runtime_name.to_string(),
            event: format!("console_output:{}", execution_result.stdout.trim()),
            decision_path: format!("benchmark/{workload_id}"),
            timing_us: execution_result.wall_time_ns / 1000, // Convert to microseconds
            outcome: "ok".to_string(),
        });
        seq += 1;
    }

    // Execution completion event
    let completion_outcome = if execution_result.exit_success {
        "ok"
    } else {
        "error"
    };
    events.push(FrxTraceEvent {
        seq,
        phase: "execution".to_string(),
        actor: runtime_name.to_string(),
        event: "completion".to_string(),
        decision_path: format!("benchmark/{workload_id}"),
        timing_us: execution_result.wall_time_ns / 1000, // Convert to microseconds
        outcome: completion_outcome.to_string(),
    });

    let trace = FrxObservableTrace {
        schema_version: FRX_LOCKSTEP_TRACE_SCHEMA_VERSION.to_string(),
        trace_id,
        decision_id,
        policy_id: format!("policy-runtime-comparison-{runtime_name}-v1"),
        component: "runtime_comparison_benchmark".to_string(),
        scenario_id: format!("benchmark-{workload_id}"),
        fixture_ref: workload_id.to_string(),
        seed: 42, // Fixed seed for deterministic comparison
        events,
        outcome: completion_outcome.to_string(),
        error_code: if execution_result.exit_success {
            None
        } else {
            Some(format!(
                "exit_code_{}",
                execution_result.exit_code.unwrap_or(-1)
            ))
        },
    };

    let json = serde_json::to_string_pretty(&trace).map_err(|err| {
        FrxLockstepOracleError::InvalidInput(format!("failed to serialize trace: {err}"))
    })?;

    fs::write(output_path, json).map_err(|source| FrxLockstepOracleError::ReadFile {
        path: output_path.display().to_string(),
        source,
    })?;

    Ok(())
}

/// Runtime benchmark execution result for trace generation.
#[derive(Debug, Clone)]
pub struct RuntimeBenchmarkResult {
    pub stdout: String,
    pub stderr: String,
    pub wall_time_ns: u64,
    pub peak_rss_bytes: u64,
    pub exit_success: bool,
    pub exit_code: Option<i32>,
}

fn missing_runtime_trace_result(
    fixture_ref: String,
    baseline_trace: FrxObservableTrace,
    baseline_path: PathBuf,
    franken_path: PathBuf,
    runtime_name: &str,
) -> FrxLockstepCaseResult {
    let replay_command = build_replay_run_command(
        baseline_path.parent().unwrap_or_else(|| Path::new(".")),
        franken_path.parent().unwrap_or_else(|| Path::new(".")),
        fixture_ref.as_str(),
    );
    FrxLockstepCaseResult {
        fixture_ref,
        scenario_id: baseline_trace.scenario_id,
        react_trace_id: baseline_trace.trace_id,
        franken_trace_id: "missing".to_string(),
        pass: false,
        divergence: Some(FrxDivergenceDetail {
            class: FrxDivergenceClass::SchemaViolation,
            message: format!(
                "missing FrankenEngine trace file `{}` for {runtime_name} baseline `{}`",
                franken_path.display(),
                baseline_path.display()
            ),
            event_index: None,
            react_signature: None,
            franken_signature: None,
        }),
        replay_command,
    }
}

// ── Divergence Classification Functions (bd-cixqu.9.2) ─────────────────────

/// Schema version for signed divergence evidence.
pub const DIVERGENCE_EVIDENCE_SCHEMA_VERSION: &str = "franken-engine.divergence-evidence.v1";

/// Create signed evidence atom from a divergence with automatic classification.
///
/// This function applies the divergence taxonomy to classify a lockstep oracle
/// divergence into typed evidence atoms for evidence ledger integration.
pub fn create_divergence_evidence(
    divergence: &FrxDivergenceDetail,
    case_id: &str,
    confidence: ClassificationConfidence,
) -> SignedDivergenceEvidence {
    let evidence_id = format!("divergence-evidence-{}", uuid_v4_like());
    let classification = classify_divergence(divergence);

    SignedDivergenceEvidence {
        schema_version: DIVERGENCE_EVIDENCE_SCHEMA_VERSION.to_string(),
        evidence_id,
        generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        lockstep_case_id: case_id.to_string(),
        classification,
        original_divergence: divergence.clone(),
        classification_confidence: confidence,
        evidence_sources: vec![EvidenceSource {
            source_type: EvidenceSourceType::ReferenceImplementation,
            identifier: "lockstep-oracle-differential-analysis".to_string(),
            description: "Automated lockstep oracle divergence detection".to_string(),
        }],
        signature: None, // TODO: Implement evidence signing
    }
}

/// Classify a divergence into the appropriate evidence atom category.
///
/// Applies classification rules from the divergence taxonomy to determine
/// the most appropriate category for a given divergence.
pub fn classify_divergence(divergence: &FrxDivergenceDetail) -> DivergenceEvidenceAtom {
    // Apply classification heuristics based on divergence patterns
    match &divergence.class {
        FrxDivergenceClass::SchemaViolation => {
            // Schema violations are typically engine bugs
            DivergenceEvidenceAtom::EngineBug {
                divergence_class: divergence.class.clone(),
                severity: classify_bug_severity(&divergence.message),
                reproducer: format!("Lockstep oracle case: {}", divergence.message),
                expected_behavior: extract_expected_behavior(divergence),
                actual_behavior: extract_actual_behavior(divergence),
            }
        }
        FrxDivergenceClass::EventSequence => {
            // Event sequence differences may indicate timing or execution order issues
            if is_performance_related(&divergence.message) {
                DivergenceEvidenceAtom::IntentionalImprovement {
                    divergence_class: divergence.class.clone(),
                    improvement_type: ImprovementType::Performance,
                    rationale: "Optimized execution ordering".to_string(),
                    compatibility_impact: CompatibilityImpact::Minimal,
                }
            } else if is_console_output_difference(divergence) {
                classify_console_output_divergence(divergence)
            } else {
                DivergenceEvidenceAtom::CompatibilityDebt {
                    divergence_class: divergence.class.clone(),
                    debt_priority: DebtPriority::Medium,
                    ecosystem_impact: vec!["Runtime execution order compatibility".to_string()],
                    mitigation_strategy: Some(
                        "Align execution ordering with reference implementations".to_string(),
                    ),
                }
            }
        }
        FrxDivergenceClass::StateTransition => {
            // State transitions may indicate deeper semantic differences
            DivergenceEvidenceAtom::EcosystemAmbiguity {
                divergence_class: divergence.class.clone(),
                ambiguity_type: AmbiguityType::ImplementationDivergence,
                reference_behaviors: extract_reference_behaviors(divergence),
                franken_behavior: extract_franken_behavior(divergence),
                specification_gap: Some("State transition semantics underspecified".to_string()),
            }
        }
        _ => {
            // Default classification for other divergence types
            DivergenceEvidenceAtom::CompatibilityDebt {
                divergence_class: divergence.class.clone(),
                debt_priority: DebtPriority::Medium,
                ecosystem_impact: vec!["General runtime compatibility".to_string()],
                mitigation_strategy: None,
            }
        }
    }
}

/// Generate batch signed evidence for multiple divergences.
pub fn create_batch_divergence_evidence(
    divergences: &[(FrxDivergenceDetail, String)], // (divergence, case_id)
    confidence: ClassificationConfidence,
) -> Vec<SignedDivergenceEvidence> {
    divergences
        .iter()
        .map(|(div, case_id)| create_divergence_evidence(div, case_id, confidence.clone()))
        .collect()
}

/// Apply triage rules from the taxonomy to determine priority and assignment.
pub fn apply_triage_rules(evidence: &SignedDivergenceEvidence) -> TriageResult {
    match &evidence.classification {
        DivergenceEvidenceAtom::EngineBug { severity, .. } => {
            match severity {
                BugSeverity::Critical => TriageResult {
                    priority: TrPriority::P0,
                    assignment: TriageAssignment::EngineTeam,
                    sla_hours: Some(24),
                    escalation_required: true,
                },
                BugSeverity::Major => TriageResult {
                    priority: TrPriority::P1,
                    assignment: TriageAssignment::EngineTeam,
                    sla_hours: Some(72),
                    escalation_required: false,
                },
                BugSeverity::Minor => TriageResult {
                    priority: TrPriority::P2,
                    assignment: TriageAssignment::EngineTeam,
                    sla_hours: Some(168), // 1 week
                    escalation_required: false,
                },
                BugSeverity::Cosmetic => TriageResult {
                    priority: TrPriority::P3,
                    assignment: TriageAssignment::Backlog,
                    sla_hours: None,
                    escalation_required: false,
                },
            }
        }
        DivergenceEvidenceAtom::CompatibilityDebt { debt_priority, .. } => {
            match debt_priority {
                DebtPriority::Blocker => TriageResult {
                    priority: TrPriority::P0,
                    assignment: TriageAssignment::CompatibilityTeam,
                    sla_hours: Some(48),
                    escalation_required: true,
                },
                DebtPriority::High => TriageResult {
                    priority: TrPriority::P1,
                    assignment: TriageAssignment::CompatibilityTeam,
                    sla_hours: Some(120), // 5 days
                    escalation_required: false,
                },
                DebtPriority::Medium => TriageResult {
                    priority: TrPriority::P2,
                    assignment: TriageAssignment::CompatibilityTeam,
                    sla_hours: Some(336), // 2 weeks
                    escalation_required: false,
                },
                DebtPriority::Low => TriageResult {
                    priority: TrPriority::P3,
                    assignment: TriageAssignment::Backlog,
                    sla_hours: None,
                    escalation_required: false,
                },
            }
        }
        DivergenceEvidenceAtom::IntentionalImprovement {
            compatibility_impact,
            ..
        } => match compatibility_impact {
            CompatibilityImpact::Significant => TriageResult {
                priority: TrPriority::P1,
                assignment: TriageAssignment::ArchitectureTeam,
                sla_hours: Some(72),
                escalation_required: false,
            },
            _ => TriageResult {
                priority: TrPriority::P2,
                assignment: TriageAssignment::DocumentationTeam,
                sla_hours: Some(168),
                escalation_required: false,
            },
        },
        DivergenceEvidenceAtom::EcosystemAmbiguity { .. } => TriageResult {
            priority: TrPriority::P2,
            assignment: TriageAssignment::StandardsTeam,
            sla_hours: Some(240), // 10 days
            escalation_required: false,
        },
    }
}

/// Result of applying triage rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageResult {
    pub priority: TrPriority,
    pub assignment: TriageAssignment,
    pub sla_hours: Option<u64>,
    pub escalation_required: bool,
}

/// Triage priority levels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrPriority {
    P0, // Critical
    P1, // High
    P2, // Medium
    P3, // Low
}

/// Triage assignment targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriageAssignment {
    EngineTeam,
    CompatibilityTeam,
    ArchitectureTeam,
    StandardsTeam,
    DocumentationTeam,
    Backlog,
}

// ── Classification Helper Functions ─────────────────────────────────────────

fn uuid_v4_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:016x}", timestamp)
}

fn classify_bug_severity(message: &str) -> BugSeverity {
    let lower_message = message.to_lowercase();
    if lower_message.contains("crash")
        || lower_message.contains("segfault")
        || lower_message.contains("panic")
    {
        BugSeverity::Critical
    } else if lower_message.contains("incorrect") || lower_message.contains("wrong") {
        BugSeverity::Major
    } else if lower_message.contains("format") || lower_message.contains("display") {
        BugSeverity::Cosmetic
    } else {
        BugSeverity::Minor
    }
}

fn is_performance_related(message: &str) -> bool {
    let lower_message = message.to_lowercase();
    lower_message.contains("timing")
        || lower_message.contains("performance")
        || lower_message.contains("speed")
}

fn is_console_output_difference(divergence: &FrxDivergenceDetail) -> bool {
    divergence.message.contains("console_output")
        || divergence
            .react_signature
            .as_ref()
            .map_or(false, |sig| sig.event.contains("console_output"))
        || divergence
            .franken_signature
            .as_ref()
            .map_or(false, |sig| sig.event.contains("console_output"))
}

fn classify_console_output_divergence(divergence: &FrxDivergenceDetail) -> DivergenceEvidenceAtom {
    // Console output differences are often engine bugs unless they're clearly improvements
    if divergence.message.contains("more precise") || divergence.message.contains("better") {
        DivergenceEvidenceAtom::IntentionalImprovement {
            divergence_class: divergence.class.clone(),
            improvement_type: ImprovementType::Diagnostics,
            rationale: "Improved console output precision".to_string(),
            compatibility_impact: CompatibilityImpact::Minimal,
        }
    } else {
        DivergenceEvidenceAtom::EngineBug {
            divergence_class: divergence.class.clone(),
            severity: BugSeverity::Minor,
            reproducer: format!("Console output mismatch: {}", divergence.message),
            expected_behavior: extract_expected_behavior(divergence),
            actual_behavior: extract_actual_behavior(divergence),
        }
    }
}

fn extract_expected_behavior(divergence: &FrxDivergenceDetail) -> String {
    divergence
        .react_signature
        .as_ref()
        .map(|sig| format!("{}: {}", sig.phase, sig.event))
        .unwrap_or_else(|| "Reference implementation behavior".to_string())
}

fn extract_actual_behavior(divergence: &FrxDivergenceDetail) -> String {
    divergence
        .franken_signature
        .as_ref()
        .map(|sig| format!("{}: {}", sig.phase, sig.event))
        .unwrap_or_else(|| "FrankenEngine behavior".to_string())
}

fn extract_reference_behaviors(divergence: &FrxDivergenceDetail) -> Vec<ReferenceRuntimeBehavior> {
    if let Some(react_sig) = &divergence.react_signature {
        vec![ReferenceRuntimeBehavior {
            runtime_name: "Reference".to_string(),
            runtime_version: "unknown".to_string(),
            observed_behavior: format!("{}: {}", react_sig.phase, react_sig.event),
            context_notes: Some(react_sig.outcome.clone()),
        }]
    } else {
        vec![]
    }
}

fn extract_franken_behavior(divergence: &FrxDivergenceDetail) -> String {
    divergence
        .franken_signature
        .as_ref()
        .map(|sig| format!("{}: {} (outcome: {})", sig.phase, sig.event, sig.outcome))
        .unwrap_or_else(|| "FrankenEngine behavior not captured".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_event(seq: u64, timing_us: u64) -> FrxTraceEvent {
        FrxTraceEvent {
            seq,
            phase: "render".to_string(),
            actor: "Component".to_string(),
            event: "mount".to_string(),
            decision_path: "root/child".to_string(),
            timing_us,
            outcome: "ok".to_string(),
        }
    }

    fn mk_trace(events: Vec<FrxTraceEvent>) -> FrxObservableTrace {
        FrxObservableTrace {
            schema_version: FRX_LOCKSTEP_TRACE_SCHEMA_VERSION.to_string(),
            trace_id: "trace-1".to_string(),
            decision_id: "dec-1".to_string(),
            policy_id: "pol-1".to_string(),
            component: "TestComponent".to_string(),
            scenario_id: "scenario-a".to_string(),
            fixture_ref: "fixture-a".to_string(),
            seed: 42,
            events,
            outcome: "pass".to_string(),
            error_code: None,
        }
    }

    fn mk_case_input() -> FrxLockstepCaseInput {
        let events = vec![mk_event(1, 100)];
        FrxLockstepCaseInput {
            fixture_ref: "fixture-a".to_string(),
            scenario_id: "scenario-a".to_string(),
            react_trace: mk_trace(events.clone()),
            franken_trace: mk_trace(events),
            react_trace_path: None,
            franken_trace_path: None,
        }
    }

    // ====================================================================
    // canonicalize_token
    // ====================================================================

    #[test]
    fn canonicalize_token_strips_suffix_after_colon() {
        assert_eq!(
            canonicalize_token("Mismatch_Detected:text"),
            "mismatch_detected"
        );
    }

    #[test]
    fn canonicalize_token_empty() {
        assert_eq!(canonicalize_token(""), "");
    }

    #[test]
    fn canonicalize_token_collapses_underscores() {
        assert_eq!(canonicalize_token("a__b___c"), "a_b_c");
    }

    #[test]
    fn canonicalize_token_special_chars_become_underscores() {
        assert_eq!(canonicalize_token("hello world!"), "hello_world");
    }

    #[test]
    fn canonicalize_token_trims_leading_trailing_underscores() {
        assert_eq!(canonicalize_token(" _test_ "), "test");
    }

    #[test]
    fn canonicalize_token_preserves_hyphens() {
        assert_eq!(canonicalize_token("my-event"), "my-event");
    }

    // ====================================================================
    // classify_mismatch
    // ====================================================================

    #[test]
    fn classify_mismatch_prefers_hydration_bucket() {
        let left = FrxTraceEvent {
            seq: 1,
            phase: "hydrate".to_string(),
            actor: "Hydrator".to_string(),
            event: "mismatch_detected:text".to_string(),
            decision_path: "hydrate_path".to_string(),
            timing_us: 1,
            outcome: "warn".to_string(),
        };
        let mut right = left.clone();
        right.event = "recover_client_render".to_string();
        assert_eq!(
            classify_mismatch(&left, &right),
            FrxDivergenceClass::HydrationOutcome
        );
    }

    #[test]
    fn classify_mismatch_effect_bucket() {
        let left = FrxTraceEvent {
            seq: 1,
            phase: "passive_effect".to_string(),
            actor: "Scheduler".to_string(),
            event: "cleanup".to_string(),
            decision_path: "root".to_string(),
            timing_us: 1,
            outcome: "ok".to_string(),
        };
        let right = FrxTraceEvent {
            seq: 1,
            phase: "layout_effect".to_string(),
            actor: "Scheduler".to_string(),
            event: "insertion".to_string(),
            decision_path: "root".to_string(),
            timing_us: 1,
            outcome: "ok".to_string(),
        };
        assert_eq!(
            classify_mismatch(&left, &right),
            FrxDivergenceClass::EffectInvocationOrder
        );
    }

    #[test]
    fn classify_mismatch_state_transition_bucket() {
        let left = FrxTraceEvent {
            seq: 1,
            phase: "dispatch".to_string(),
            actor: "Reducer".to_string(),
            event: "state_update".to_string(),
            decision_path: "root".to_string(),
            timing_us: 1,
            outcome: "ok".to_string(),
        };
        let mut right = left.clone();
        right.event = "batch_update".to_string();
        assert_eq!(
            classify_mismatch(&left, &right),
            FrxDivergenceClass::StateTransition
        );
    }

    #[test]
    fn classify_mismatch_dom_mutation_bucket() {
        let left = FrxTraceEvent {
            seq: 1,
            phase: "commit".to_string(),
            actor: "Renderer".to_string(),
            event: "dom_patch".to_string(),
            decision_path: "root".to_string(),
            timing_us: 1,
            outcome: "ok".to_string(),
        };
        let mut right = left.clone();
        right.event = "portal_render".to_string();
        assert_eq!(
            classify_mismatch(&left, &right),
            FrxDivergenceClass::DomMutationTrace
        );
    }

    #[test]
    fn classify_mismatch_fallback_event_sequence() {
        let left = FrxTraceEvent {
            seq: 1,
            phase: "unknown".to_string(),
            actor: "X".to_string(),
            event: "something".to_string(),
            decision_path: "root".to_string(),
            timing_us: 1,
            outcome: "ok".to_string(),
        };
        let mut right = left.clone();
        right.event = "other".to_string();
        assert_eq!(
            classify_mismatch(&left, &right),
            FrxDivergenceClass::EventSequence
        );
    }

    // ====================================================================
    // FrxDivergenceClass
    // ====================================================================

    #[test]
    fn divergence_class_as_str_all_variants() {
        let variants = [
            (FrxDivergenceClass::DomMutationTrace, "dom_mutation_trace"),
            (
                FrxDivergenceClass::EffectInvocationOrder,
                "effect_invocation_order",
            ),
            (FrxDivergenceClass::StateTransition, "state_transition"),
            (FrxDivergenceClass::HydrationOutcome, "hydration_outcome"),
            (FrxDivergenceClass::EventSequence, "event_sequence"),
            (FrxDivergenceClass::SchemaViolation, "schema_violation"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (variant, expected) in &variants {
            assert_eq!(variant.as_str(), *expected);
            assert_eq!(format!("{variant}"), *expected);
            seen.insert(*expected);
        }
        assert_eq!(seen.len(), 6);
    }

    #[test]
    fn divergence_class_serde_roundtrip() {
        let variants = [
            FrxDivergenceClass::DomMutationTrace,
            FrxDivergenceClass::EffectInvocationOrder,
            FrxDivergenceClass::StateTransition,
            FrxDivergenceClass::HydrationOutcome,
            FrxDivergenceClass::EventSequence,
            FrxDivergenceClass::SchemaViolation,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).expect("serialize derived Serialize");
            let back: FrxDivergenceClass =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*variant, back);
        }
    }

    // ====================================================================
    // FrxTraceEvent::normalize
    // ====================================================================

    #[test]
    fn trace_event_normalize_trims() {
        let mut event = FrxTraceEvent {
            seq: 1,
            phase: "  render  ".to_string(),
            actor: " A ".to_string(),
            event: " mount ".to_string(),
            decision_path: "  root  ".to_string(),
            timing_us: 0,
            outcome: " ok ".to_string(),
        };
        event.normalize();
        assert_eq!(event.phase, "render");
        assert_eq!(event.actor, "A");
        assert_eq!(event.event, "mount");
        assert_eq!(event.decision_path, "root");
        assert_eq!(event.outcome, "ok");
    }

    // ====================================================================
    // FrxObservableTrace::normalize
    // ====================================================================

    #[test]
    fn observable_trace_normalize_trims_fields() {
        let mut trace = mk_trace(vec![mk_event(1, 0)]);
        trace.trace_id = "  trace-1  ".to_string();
        trace.error_code = Some("  ".to_string());
        trace.normalize();
        assert_eq!(trace.trace_id, "trace-1");
        assert!(trace.error_code.is_none()); // empty after trim => filtered
    }

    #[test]
    fn observable_trace_normalize_preserves_nonempty_error_code() {
        let mut trace = mk_trace(vec![mk_event(1, 0)]);
        trace.error_code = Some(" ERR-01 ".to_string());
        trace.normalize();
        assert_eq!(trace.error_code.as_deref(), Some("ERR-01"));
    }

    // ====================================================================
    // FrxObservableTrace::validate
    // ====================================================================

    #[test]
    fn validate_trace_wrong_schema_version() {
        let mut trace = mk_trace(vec![mk_event(1, 0)]);
        trace.schema_version = "wrong".to_string();
        let err = trace.validate("test").unwrap_err();
        assert!(err.to_string().contains("schema_version"));
    }

    #[test]
    fn validate_trace_empty_trace_id() {
        let mut trace = mk_trace(vec![mk_event(1, 0)]);
        trace.trace_id = String::new();
        let err = trace.validate("test").unwrap_err();
        assert!(err.to_string().contains("trace_id"));
    }

    #[test]
    fn validate_trace_empty_decision_id() {
        let mut trace = mk_trace(vec![mk_event(1, 0)]);
        trace.decision_id = String::new();
        let err = trace.validate("test").unwrap_err();
        assert!(err.to_string().contains("decision_id"));
    }

    #[test]
    fn validate_trace_empty_policy_id() {
        let mut trace = mk_trace(vec![mk_event(1, 0)]);
        trace.policy_id = String::new();
        let err = trace.validate("test").unwrap_err();
        assert!(err.to_string().contains("policy_id"));
    }

    #[test]
    fn validate_trace_empty_component() {
        let mut trace = mk_trace(vec![mk_event(1, 0)]);
        trace.component = String::new();
        let err = trace.validate("test").unwrap_err();
        assert!(err.to_string().contains("component"));
    }

    #[test]
    fn validate_trace_empty_scenario_id() {
        let mut trace = mk_trace(vec![mk_event(1, 0)]);
        trace.scenario_id = String::new();
        let err = trace.validate("test").unwrap_err();
        assert!(err.to_string().contains("scenario_id"));
    }

    #[test]
    fn validate_trace_empty_fixture_ref() {
        let mut trace = mk_trace(vec![mk_event(1, 0)]);
        trace.fixture_ref = String::new();
        let err = trace.validate("test").unwrap_err();
        assert!(err.to_string().contains("fixture_ref"));
    }

    #[test]
    fn validate_trace_empty_events() {
        let trace = mk_trace(vec![]);
        let err = trace.validate("test").unwrap_err();
        assert!(err.to_string().contains("events must not be empty"));
    }

    #[test]
    fn validate_trace_success() {
        let trace = mk_trace(vec![mk_event(1, 0), mk_event(2, 100)]);
        assert!(trace.validate("test").is_ok());
    }

    // ====================================================================
    // ensure_monotonic_events
    // ====================================================================

    #[test]
    fn monotonic_events_empty_phase() {
        let mut event = mk_event(1, 0);
        event.phase = String::new();
        let err = ensure_monotonic_events(&[event], "test").unwrap_err();
        assert!(err.to_string().contains("phase"));
    }

    #[test]
    fn monotonic_events_empty_actor() {
        let mut event = mk_event(1, 0);
        event.actor = String::new();
        let err = ensure_monotonic_events(&[event], "test").unwrap_err();
        assert!(err.to_string().contains("actor"));
    }

    #[test]
    fn monotonic_events_empty_event() {
        let mut event = mk_event(1, 0);
        event.event = String::new();
        let err = ensure_monotonic_events(&[event], "test").unwrap_err();
        assert!(err.to_string().contains("event"));
    }

    #[test]
    fn monotonic_events_empty_decision_path() {
        let mut event = mk_event(1, 0);
        event.decision_path = String::new();
        let err = ensure_monotonic_events(&[event], "test").unwrap_err();
        assert!(err.to_string().contains("decision_path"));
    }

    #[test]
    fn monotonic_events_empty_outcome() {
        let mut event = mk_event(1, 0);
        event.outcome = String::new();
        let err = ensure_monotonic_events(&[event], "test").unwrap_err();
        assert!(err.to_string().contains("outcome"));
    }

    #[test]
    fn monotonic_events_non_increasing_seq() {
        let events = vec![mk_event(2, 0), mk_event(1, 100)];
        let err = ensure_monotonic_events(&events, "test").unwrap_err();
        assert!(err.to_string().contains("strictly increasing"));
    }

    #[test]
    fn monotonic_events_equal_seq() {
        let events = vec![mk_event(1, 0), mk_event(1, 100)];
        let err = ensure_monotonic_events(&events, "test").unwrap_err();
        assert!(err.to_string().contains("strictly increasing"));
    }

    #[test]
    fn monotonic_events_non_monotonic_timing() {
        let events = vec![mk_event(1, 200), mk_event(2, 100)];
        let err = ensure_monotonic_events(&events, "test").unwrap_err();
        assert!(err.to_string().contains("monotonic"));
    }

    #[test]
    fn monotonic_events_valid() {
        let events = vec![mk_event(1, 0), mk_event(2, 0), mk_event(3, 100)];
        assert!(ensure_monotonic_events(&events, "test").is_ok());
    }

    // ====================================================================
    // compare_traces
    // ====================================================================

    #[test]
    fn compare_traces_identical_returns_none() {
        let events = vec![mk_event(1, 100)];
        let trace = mk_trace(events);
        assert!(compare_traces(&trace, &trace).is_none());
    }

    #[test]
    fn compare_traces_event_count_mismatch() {
        let react = mk_trace(vec![mk_event(1, 100)]);
        let franken = mk_trace(vec![mk_event(1, 100), mk_event(2, 200)]);
        let div =
            compare_traces(&react, &franken).expect("operation should succeed for valid inputs");
        assert_eq!(div.class, FrxDivergenceClass::EventSequence);
        assert!(div.message.contains("event count mismatch"));
    }

    #[test]
    fn compare_traces_event_content_mismatch() {
        let react = mk_trace(vec![mk_event(1, 100)]);
        let mut franken_events = vec![mk_event(1, 100)];
        franken_events[0].outcome = "fail".to_string();
        let franken = mk_trace(franken_events);
        let div =
            compare_traces(&react, &franken).expect("operation should succeed for valid inputs");
        assert!(div.event_index.is_some());
        assert_eq!(div.event_index, Some(0));
        assert!(div.react_signature.is_some());
        assert!(div.franken_signature.is_some());
    }

    #[test]
    fn compare_traces_outcome_mismatch() {
        let events = vec![mk_event(1, 100)];
        let mut react = mk_trace(events.clone());
        let mut franken = mk_trace(events);
        react.outcome = "pass".to_string();
        franken.outcome = "fail".to_string();
        let div =
            compare_traces(&react, &franken).expect("operation should succeed for valid inputs");
        assert_eq!(div.class, FrxDivergenceClass::EventSequence);
        assert!(div.message.contains("outcome mismatch"));
    }

    #[test]
    fn compare_traces_error_code_mismatch() {
        let events = vec![mk_event(1, 100)];
        let mut react = mk_trace(events.clone());
        let mut franken = mk_trace(events);
        react.error_code = Some("ERR-01".to_string());
        franken.error_code = None;
        let div =
            compare_traces(&react, &franken).expect("operation should succeed for valid inputs");
        assert_eq!(div.class, FrxDivergenceClass::SchemaViolation);
        assert!(div.message.contains("error_code mismatch"));
    }

    // ====================================================================
    // evaluate_case
    // ====================================================================

    #[test]
    fn evaluate_case_pass() {
        let input = mk_case_input();
        let result = evaluate_case(input).expect("operation should succeed for valid inputs");
        assert!(result.pass);
        assert!(result.divergence.is_none());
        assert_eq!(result.fixture_ref, "fixture-a");
        assert_eq!(result.scenario_id, "scenario-a");
    }

    #[test]
    fn evaluate_case_empty_fixture_ref() {
        let mut input = mk_case_input();
        input.fixture_ref = String::new();
        let err = evaluate_case(input).unwrap_err();
        assert!(err.to_string().contains("fixture_ref"));
    }

    #[test]
    fn evaluate_case_empty_scenario_id() {
        let mut input = mk_case_input();
        input.scenario_id = String::new();
        let err = evaluate_case(input).unwrap_err();
        assert!(err.to_string().contains("scenario_id"));
    }

    #[test]
    fn evaluate_case_fixture_ref_mismatch_react() {
        let mut input = mk_case_input();
        input.react_trace.fixture_ref = "other".to_string();
        let err = evaluate_case(input).unwrap_err();
        assert!(err.to_string().contains("react trace fixture_ref"));
    }

    #[test]
    fn evaluate_case_fixture_ref_mismatch_franken() {
        let mut input = mk_case_input();
        input.franken_trace.fixture_ref = "other".to_string();
        let err = evaluate_case(input).unwrap_err();
        assert!(err.to_string().contains("franken trace fixture_ref"));
    }

    #[test]
    fn evaluate_case_scenario_id_mismatch_react() {
        let mut input = mk_case_input();
        input.react_trace.scenario_id = "other".to_string();
        let err = evaluate_case(input).unwrap_err();
        assert!(err.to_string().contains("react trace scenario_id"));
    }

    #[test]
    fn evaluate_case_scenario_id_mismatch_franken() {
        let mut input = mk_case_input();
        input.franken_trace.scenario_id = "other".to_string();
        let err = evaluate_case(input).unwrap_err();
        assert!(err.to_string().contains("franken trace scenario_id"));
    }

    #[test]
    fn evaluate_case_with_divergence() {
        let mut input = mk_case_input();
        input.franken_trace.events[0].outcome = "fail".to_string();
        let result = evaluate_case(input).expect("operation should succeed for valid inputs");
        assert!(!result.pass);
        assert!(result.divergence.is_some());
    }

    #[test]
    fn evaluate_case_trims_fixture_ref() {
        let mut input = mk_case_input();
        input.fixture_ref = "  fixture-a  ".to_string();
        let result = evaluate_case(input).expect("operation should succeed for valid inputs");
        assert_eq!(result.fixture_ref, "fixture-a");
    }

    // ====================================================================
    // summarize
    // ====================================================================

    #[test]
    fn summarize_all_pass() {
        let results = vec![
            FrxLockstepCaseResult {
                fixture_ref: "a".into(),
                scenario_id: "s".into(),
                react_trace_id: "r".into(),
                franken_trace_id: "f".into(),
                pass: true,
                divergence: None,
                replay_command: String::new(),
            },
            FrxLockstepCaseResult {
                fixture_ref: "b".into(),
                scenario_id: "s".into(),
                react_trace_id: "r".into(),
                franken_trace_id: "f".into(),
                pass: true,
                divergence: None,
                replay_command: String::new(),
            },
        ];
        let summary = summarize(&results);
        assert_eq!(summary.total_cases, 2);
        assert_eq!(summary.pass_cases, 2);
        assert_eq!(summary.failed_cases, 0);
        assert!(summary.divergence_counts_by_class.is_empty());
    }

    #[test]
    fn summarize_with_failures() {
        let results = vec![
            FrxLockstepCaseResult {
                fixture_ref: "a".into(),
                scenario_id: "s".into(),
                react_trace_id: "r".into(),
                franken_trace_id: "f".into(),
                pass: true,
                divergence: None,
                replay_command: String::new(),
            },
            FrxLockstepCaseResult {
                fixture_ref: "b".into(),
                scenario_id: "s".into(),
                react_trace_id: "r".into(),
                franken_trace_id: "f".into(),
                pass: false,
                divergence: Some(FrxDivergenceDetail {
                    class: FrxDivergenceClass::EventSequence,
                    message: "mismatch".into(),
                    event_index: None,
                    react_signature: None,
                    franken_signature: None,
                }),
                replay_command: String::new(),
            },
            FrxLockstepCaseResult {
                fixture_ref: "c".into(),
                scenario_id: "s".into(),
                react_trace_id: "r".into(),
                franken_trace_id: "f".into(),
                pass: false,
                divergence: Some(FrxDivergenceDetail {
                    class: FrxDivergenceClass::EventSequence,
                    message: "another".into(),
                    event_index: None,
                    react_signature: None,
                    franken_signature: None,
                }),
                replay_command: String::new(),
            },
        ];
        let summary = summarize(&results);
        assert_eq!(summary.total_cases, 3);
        assert_eq!(summary.pass_cases, 1);
        assert_eq!(summary.failed_cases, 2);
        assert_eq!(
            summary.divergence_counts_by_class.get("event_sequence"),
            Some(&2)
        );
    }

    #[test]
    fn summarize_failed_without_divergence() {
        let results = vec![FrxLockstepCaseResult {
            fixture_ref: "a".into(),
            scenario_id: "s".into(),
            react_trace_id: "r".into(),
            franken_trace_id: "f".into(),
            pass: false,
            divergence: None,
            replay_command: String::new(),
        }];
        let summary = summarize(&results);
        assert_eq!(summary.failed_cases, 1);
        assert!(summary.divergence_counts_by_class.is_empty());
    }

    // ====================================================================
    // build_replay_command
    // ====================================================================

    #[test]
    fn build_replay_command_without_paths() {
        let input = mk_case_input();
        let cmd = build_replay_command(&input);
        assert_eq!(
            cmd,
            "rch cargo test -p frankenengine-engine --test frx_lockstep_oracle -- --nocapture"
        );
    }

    #[test]
    fn build_replay_command_with_paths() {
        let mut input = mk_case_input();
        input.react_trace_path = Some(PathBuf::from("/traces/react/test.trace.json"));
        input.franken_trace_path = Some(PathBuf::from("/traces/franken/test.trace.json"));
        let cmd = build_replay_command(&input);
        assert!(cmd.starts_with("rch cargo run -p frankenengine-engine --bin frx_lockstep_oracle"));
        assert!(cmd.contains("--react-traces-dir"));
        assert!(cmd.contains("/traces/react"));
        assert!(cmd.contains("--franken-traces-dir"));
        assert!(cmd.contains("/traces/franken"));
        assert!(cmd.contains("--fixture-ref fixture-a"));
    }

    #[test]
    fn build_replay_command_shell_escapes_fixture_ref() {
        let mut input = mk_case_input();
        input.fixture_ref = "fixture with 'quote'".to_string();
        input.react_trace.fixture_ref = "fixture with 'quote'".to_string();
        input.franken_trace.fixture_ref = "fixture with 'quote'".to_string();
        input.react_trace_path = Some(PathBuf::from("/tmp/react traces/test.trace.json"));
        input.franken_trace_path = Some(PathBuf::from("/tmp/franken traces/test.trace.json"));
        let cmd = build_replay_command(&input);
        assert!(cmd.contains("--react-traces-dir '/tmp/react traces'"));
        assert!(cmd.contains("--franken-traces-dir '/tmp/franken traces'"));
        assert!(cmd.contains("--fixture-ref 'fixture with '\"'\"'quote'\"'\"''"));
    }

    // ====================================================================
    // shell_escape_argument / shell_escape_path
    // ====================================================================

    #[test]
    fn shell_escape_path_no_spaces() {
        assert_eq!(shell_escape_path(Path::new("/foo/bar")), "/foo/bar");
    }

    #[test]
    fn shell_escape_path_with_spaces() {
        let escaped = shell_escape_path(Path::new("/foo bar/baz"));
        assert_eq!(escaped, "'/foo bar/baz'");
    }

    #[test]
    fn shell_escape_argument_with_single_quote() {
        let escaped = shell_escape_argument("a'b");
        assert_eq!(escaped, "'a'\"'\"'b'");
    }

    // ====================================================================
    // invalid_case_result
    // ====================================================================

    #[test]
    fn invalid_case_result_sets_schema_violation() {
        let context = FrxInvalidCaseContext {
            fixture_ref: "fixture-a".into(),
            scenario_id: "scenario-a".into(),
            react_trace_id: "react-trace".into(),
            franken_trace_id: "franken-trace".into(),
            replay_command: "rch cargo run -p frankenengine-engine --bin frx_lockstep_oracle -- --fixture-ref fixture-a".into(),
        };
        let err = FrxLockstepOracleError::InvalidInput("bad".into());
        let result = invalid_case_result(context, err);
        assert!(!result.pass);
        assert_eq!(result.fixture_ref, "fixture-a");
        assert_eq!(result.scenario_id, "scenario-a");
        assert_eq!(result.react_trace_id, "react-trace");
        assert_eq!(result.franken_trace_id, "franken-trace");
        assert!(result.replay_command.contains("rch cargo run"));
        let div = result
            .divergence
            .expect("operation should succeed for valid inputs");
        assert_eq!(div.class, FrxDivergenceClass::SchemaViolation);
        assert!(div.message.contains("bad"));
    }

    // ====================================================================
    // missing_trace_result
    // ====================================================================

    #[test]
    fn missing_trace_result_constructs_failure() {
        let trace = mk_trace(vec![mk_event(1, 0)]);
        let result = missing_trace_result(
            "fix-a".into(),
            trace,
            PathBuf::from("/react/fix-a.trace.json"),
            PathBuf::from("/franken/fix-a.trace.json"),
        );
        assert!(!result.pass);
        assert_eq!(result.franken_trace_id, "missing");
        let div = result
            .divergence
            .expect("operation should succeed for valid inputs");
        assert_eq!(div.class, FrxDivergenceClass::SchemaViolation);
        assert!(div.message.contains("missing FrankenReact trace file"));
    }

    #[test]
    fn missing_trace_result_replay_command_preserves_fixture_ref_and_shell_escapes_paths() {
        let trace = mk_trace(vec![mk_event(1, 0)]);
        let result = missing_trace_result(
            "fixture with 'quote'".into(),
            trace,
            PathBuf::from("/react traces/fix-a.trace.json"),
            PathBuf::from("/franken traces/fix-a.trace.json"),
        );
        assert!(
            result
                .replay_command
                .starts_with("rch cargo run -p frankenengine-engine --bin frx_lockstep_oracle")
        );
        assert!(
            result
                .replay_command
                .contains("--react-traces-dir '/react traces'")
        );
        assert!(
            result
                .replay_command
                .contains("--franken-traces-dir '/franken traces'")
        );
        assert!(
            result
                .replay_command
                .contains("--fixture-ref 'fixture with '\"'\"'quote'\"'\"''")
        );
    }

    // ====================================================================
    // fixture_ref_from_trace_filename
    // ====================================================================

    #[test]
    fn fixture_ref_from_valid_filename() {
        let path = PathBuf::from("/traces/my-fixture.trace.json");
        let fixture = fixture_ref_from_trace_filename(&path)
            .expect("operation should succeed for valid inputs");
        assert_eq!(fixture, "my-fixture");
    }

    #[test]
    fn fixture_ref_from_invalid_suffix() {
        let path = PathBuf::from("/traces/my-fixture.json");
        let err = fixture_ref_from_trace_filename(&path).unwrap_err();
        assert!(err.to_string().contains(".trace.json"));
    }

    // ====================================================================
    // FrxLockstepRunContext
    // ====================================================================

    #[test]
    fn run_context_deterministic() {
        let ctx = FrxLockstepRunContext::deterministic("t1", "d1", "p1");
        assert_eq!(ctx.trace_id, "t1");
        assert_eq!(ctx.decision_id, "d1");
        assert_eq!(ctx.policy_id, "p1");
    }

    #[test]
    fn run_context_with_defaults_nonempty() {
        let ctx = FrxLockstepRunContext::with_defaults();
        assert!(!ctx.trace_id.is_empty());
        assert!(!ctx.decision_id.is_empty());
        assert!(ctx.policy_id.contains("v1"));
    }

    // ====================================================================
    // canonical_event_signature
    // ====================================================================

    #[test]
    fn canonical_event_signature_preserves_seq() {
        let event = mk_event(42, 0);
        let sig = canonical_event_signature(&event);
        assert_eq!(sig.seq, 42);
    }

    #[test]
    fn canonical_event_signature_lowercases() {
        let mut event = mk_event(1, 0);
        event.phase = "Render:extra".to_string();
        event.outcome = "OK".to_string();
        let sig = canonical_event_signature(&event);
        assert_eq!(sig.phase, "render");
        assert_eq!(sig.outcome, "ok");
    }

    // ====================================================================
    // Serde roundtrips
    // ====================================================================

    #[test]
    fn serde_roundtrip_observable_trace() {
        let trace = mk_trace(vec![mk_event(1, 100)]);
        let json = serde_json::to_string(&trace).expect("serialize derived Serialize");
        let back: FrxObservableTrace =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(trace, back);
    }

    #[test]
    fn serde_roundtrip_trace_event() {
        let event = mk_event(5, 500);
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let back: FrxTraceEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, back);
    }

    #[test]
    fn serde_roundtrip_case_result() {
        let result =
            evaluate_case(mk_case_input()).expect("operation should succeed for valid inputs");
        let json = serde_json::to_string(&result).expect("serialize derived Serialize");
        let back: FrxLockstepCaseResult =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(result, back);
    }

    #[test]
    fn serde_roundtrip_summary() {
        let results = vec![
            evaluate_case(mk_case_input()).expect("operation should succeed for valid inputs"),
        ];
        let summary = summarize(&results);
        let json = serde_json::to_string(&summary).expect("serialize derived Serialize");
        let back: FrxLockstepSummary =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(summary, back);
    }

    #[test]
    fn serde_roundtrip_divergence_detail() {
        let detail = FrxDivergenceDetail {
            class: FrxDivergenceClass::HydrationOutcome,
            message: "test divergence".into(),
            event_index: Some(3),
            react_signature: Some(FrxTraceEventSignature {
                seq: 1,
                phase: "render".into(),
                event: "mount".into(),
                decision_path: "root".into(),
                outcome: "ok".into(),
            }),
            franken_signature: None,
        };
        let json = serde_json::to_string(&detail).expect("serialize derived Serialize");
        let back: FrxDivergenceDetail =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(detail, back);
    }

    #[test]
    fn serde_roundtrip_report() {
        let results = vec![
            evaluate_case(mk_case_input()).expect("operation should succeed for valid inputs"),
        ];
        let summary = summarize(&results);
        let report = FrxLockstepReport {
            schema_version: FRX_LOCKSTEP_REPORT_SCHEMA_VERSION.to_string(),
            generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            trace_id: "t1".into(),
            decision_id: "d1".into(),
            policy_id: "p1".into(),
            component: FRX_LOCKSTEP_COMPONENT.to_string(),
            react_traces_dir: "/react".into(),
            franken_traces_dir: "/franken".into(),
            summary,
            case_results: results,
        };
        let json = serde_json::to_string(&report).expect("serialize derived Serialize");
        let back: FrxLockstepReport =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(report, back);
    }

    // ====================================================================
    // load_trace_file with tempdir
    // ====================================================================

    #[test]
    fn load_trace_file_valid() {
        let trace = mk_trace(vec![mk_event(1, 0)]);
        let json = serde_json::to_string(&trace).expect("serialize derived Serialize");
        let dir = std::env::temp_dir().join("frx_lockstep_test_load");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test.trace.json");
        fs::write(&path, &json).expect("operation should succeed for valid inputs");
        let loaded = load_trace_file(&path).expect("operation should succeed for valid inputs");
        assert_eq!(loaded.trace_id, "trace-1");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_trace_file_missing() {
        let path = PathBuf::from("/nonexistent/trace.json");
        let err = load_trace_file(&path).unwrap_err();
        assert!(err.to_string().contains("failed to read"));
    }

    #[test]
    fn load_trace_file_invalid_json() {
        let dir = std::env::temp_dir().join("frx_lockstep_test_badjson");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("bad.trace.json");
        fs::write(&path, "not json").expect("operation should succeed for valid inputs");
        let err = load_trace_file(&path).unwrap_err();
        assert!(err.to_string().contains("failed to parse"));
        let _ = fs::remove_dir_all(&dir);
    }

    // ====================================================================
    // Error Display
    // ====================================================================

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<FrxLockstepOracleError> = vec![
            FrxLockstepOracleError::InvalidInput("test".into()),
            FrxLockstepOracleError::ReadFile {
                path: "/x".into(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
            },
            FrxLockstepOracleError::ParseTrace {
                path: "/y".into(),
                source: serde_json::from_str::<String>("bad").unwrap_err(),
            },
        ];
        let mut msgs = std::collections::BTreeSet::new();
        for err in &errors {
            let msg = format!("{err}");
            assert!(!msg.is_empty());
            msgs.insert(msg);
        }
        assert_eq!(msgs.len(), 3);
    }

    // ====================================================================
    // Constants
    // ====================================================================

    #[test]
    fn schema_version_constants_nonempty() {
        assert!(!FRX_LOCKSTEP_TRACE_SCHEMA_VERSION.is_empty());
        assert!(!FRX_LOCKSTEP_REPORT_SCHEMA_VERSION.is_empty());
        assert!(!FRX_LOCKSTEP_COMPONENT.is_empty());
    }

    // -- Enrichment: serde roundtrip for untested type (PearlTower 2026-02-26) --

    #[test]
    fn trace_event_signature_serde_roundtrip() {
        let sig = FrxTraceEventSignature {
            seq: 42,
            phase: "render".into(),
            event: "commit".into(),
            decision_path: "fast-path".into(),
            outcome: "success".into(),
        };
        let json = serde_json::to_string(&sig).expect("serialize derived Serialize");
        let back: FrxTraceEventSignature =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(sig, back);
    }

    // ====================================================================
    // Runtime lockstep oracle tests (PearlTower bd-cixqu.9.1)
    // ====================================================================

    #[test]
    fn runtime_benchmark_result_basic_construction() {
        let result = RuntimeBenchmarkResult {
            stdout: "Hello, World!".to_string(),
            stderr: "".to_string(),
            wall_time_ns: 1_000_000,
            peak_rss_bytes: 4096,
            exit_success: true,
            exit_code: Some(0),
        };

        assert_eq!(result.stdout, "Hello, World!");
        assert_eq!(result.wall_time_ns, 1_000_000);
        assert!(result.exit_success);
        assert_eq!(result.exit_code, Some(0));
    }

    #[test]
    fn create_runtime_benchmark_trace_successful_execution() {
        let result = RuntimeBenchmarkResult {
            stdout: "42".to_string(),
            stderr: "".to_string(),
            wall_time_ns: 500_000,
            peak_rss_bytes: 2048,
            exit_success: true,
            exit_code: Some(0),
        };

        let temp_dir = std::env::temp_dir().join("frx_runtime_trace_test");
        let _ = fs::create_dir_all(&temp_dir);
        let trace_path = temp_dir.join("test_workload.trace.json");

        let create_result =
            create_runtime_benchmark_trace("test_workload", "Node.js", result, &trace_path);

        assert!(create_result.is_ok(), "trace creation should succeed");
        assert!(trace_path.exists(), "trace file should be created");

        // Verify the trace file can be loaded and has correct structure
        let loaded_trace = load_trace_file(&trace_path).expect("should load created trace");
        assert_eq!(loaded_trace.fixture_ref, "test_workload");
        assert_eq!(loaded_trace.component, "runtime_comparison_benchmark");
        assert_eq!(loaded_trace.outcome, "ok");
        assert!(
            loaded_trace.events.len() >= 2,
            "should have start and completion events"
        );

        // Check that console output is captured as an event
        let console_event = loaded_trace
            .events
            .iter()
            .find(|e| e.event.starts_with("console_output:"));
        assert!(console_event.is_some(), "should have console output event");
        assert!(console_event.unwrap().event.contains("42"));

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn create_runtime_benchmark_trace_failed_execution() {
        let result = RuntimeBenchmarkResult {
            stdout: "".to_string(),
            stderr: "Error: something went wrong".to_string(),
            wall_time_ns: 100_000,
            peak_rss_bytes: 1024,
            exit_success: false,
            exit_code: Some(1),
        };

        let temp_dir = std::env::temp_dir().join("frx_runtime_trace_test_fail");
        let _ = fs::create_dir_all(&temp_dir);
        let trace_path = temp_dir.join("failed_workload.trace.json");

        let create_result =
            create_runtime_benchmark_trace("failed_workload", "Bun", result, &trace_path);

        assert!(
            create_result.is_ok(),
            "trace creation should succeed even for failed execution"
        );

        let loaded_trace = load_trace_file(&trace_path).expect("should load created trace");
        assert_eq!(loaded_trace.outcome, "error");
        assert!(loaded_trace.error_code.is_some(), "should have error code");
        assert!(loaded_trace.error_code.unwrap().contains("exit_code_1"));

        // Check completion event has error outcome
        let completion_event = loaded_trace.events.iter().find(|e| e.event == "completion");
        assert!(completion_event.is_some(), "should have completion event");
        assert_eq!(completion_event.unwrap().outcome, "error");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn run_node_lockstep_oracle_empty_directory() {
        let temp_dir = std::env::temp_dir().join("frx_node_oracle_empty_test");
        let node_dir = temp_dir.join("node_traces");
        let franken_dir = temp_dir.join("franken_traces");

        let _ = fs::create_dir_all(&node_dir);
        let _ = fs::create_dir_all(&franken_dir);

        let context =
            FrxLockstepRunContext::deterministic("test-trace", "test-decision", "test-policy");

        let result = run_node_lockstep_oracle(&node_dir, &franken_dir, context, None);
        assert!(
            result.is_err(),
            "should fail with empty node traces directory"
        );

        let err = result.unwrap_err();
        match err {
            FrxLockstepOracleError::InvalidInput(msg) => {
                assert!(msg.contains("no .trace.json files found"));
            }
            _ => panic!("expected InvalidInput error for empty directory"),
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn run_bun_lockstep_oracle_empty_directory() {
        let temp_dir = std::env::temp_dir().join("frx_bun_oracle_empty_test");
        let bun_dir = temp_dir.join("bun_traces");
        let franken_dir = temp_dir.join("franken_traces");

        let _ = fs::create_dir_all(&bun_dir);
        let _ = fs::create_dir_all(&franken_dir);

        let context =
            FrxLockstepRunContext::deterministic("test-trace", "test-decision", "test-policy");

        let result = run_bun_lockstep_oracle(&bun_dir, &franken_dir, context, None);
        assert!(
            result.is_err(),
            "should fail with empty bun traces directory"
        );

        let _ = fs::remove_dir_all(&temp_dir);
    }

    // ====================================================================
    // Divergence Classification Tests (bd-cixqu.9.2)
    // ====================================================================

    #[test]
    fn divergence_evidence_atom_serde_roundtrip() {
        let atom = DivergenceEvidenceAtom::EngineBug {
            divergence_class: FrxDivergenceClass::EventSequence,
            severity: BugSeverity::Major,
            reproducer: "Test reproducer".to_string(),
            expected_behavior: "Expected output".to_string(),
            actual_behavior: "Actual output".to_string(),
        };

        let json = serde_json::to_string(&atom).expect("should serialize");
        let back: DivergenceEvidenceAtom = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(atom, back);
    }

    #[test]
    fn signed_divergence_evidence_serde_roundtrip() {
        let divergence = FrxDivergenceDetail {
            class: FrxDivergenceClass::SchemaViolation,
            message: "Test divergence message".to_string(),
            event_index: Some(1),
            react_signature: None,
            franken_signature: None,
        };

        let evidence = SignedDivergenceEvidence {
            schema_version: DIVERGENCE_EVIDENCE_SCHEMA_VERSION.to_string(),
            evidence_id: "test-evidence-123".to_string(),
            generated_at_utc: "2026-05-21T19:53:00Z".to_string(),
            lockstep_case_id: "test-case-456".to_string(),
            classification: DivergenceEvidenceAtom::EngineBug {
                divergence_class: FrxDivergenceClass::SchemaViolation,
                severity: BugSeverity::Critical,
                reproducer: "Test bug reproducer".to_string(),
                expected_behavior: "Expected behavior".to_string(),
                actual_behavior: "Actual behavior".to_string(),
            },
            original_divergence: divergence,
            classification_confidence: ClassificationConfidence::Automated,
            evidence_sources: vec![EvidenceSource {
                source_type: EvidenceSourceType::ReferenceImplementation,
                identifier: "node-22.13.1".to_string(),
                description: "Node.js reference execution".to_string(),
            }],
            signature: Some("mock-signature".to_string()),
        };

        let json = serde_json::to_string(&evidence).expect("should serialize");
        let back: SignedDivergenceEvidence =
            serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(evidence, back);
    }

    #[test]
    fn classify_divergence_schema_violation_as_engine_bug() {
        let divergence = FrxDivergenceDetail {
            class: FrxDivergenceClass::SchemaViolation,
            message: "Invalid schema format detected".to_string(),
            event_index: None,
            react_signature: None,
            franken_signature: None,
        };

        let classification = classify_divergence(&divergence);
        match classification {
            DivergenceEvidenceAtom::EngineBug {
                divergence_class,
                severity,
                ..
            } => {
                assert_eq!(divergence_class, FrxDivergenceClass::SchemaViolation);
                assert_eq!(severity, BugSeverity::Minor);
            }
            _ => panic!("Expected EngineBug classification for schema violation"),
        }
    }

    #[test]
    fn classify_divergence_performance_improvement() {
        let divergence = FrxDivergenceDetail {
            class: FrxDivergenceClass::EventSequence,
            message: "Timing optimization detected in execution order".to_string(),
            event_index: Some(2),
            react_signature: None,
            franken_signature: None,
        };

        let classification = classify_divergence(&divergence);
        match classification {
            DivergenceEvidenceAtom::IntentionalImprovement {
                improvement_type,
                compatibility_impact,
                ..
            } => {
                assert_eq!(improvement_type, ImprovementType::Performance);
                assert_eq!(compatibility_impact, CompatibilityImpact::Minimal);
            }
            _ => panic!(
                "Expected IntentionalImprovement classification for performance optimization"
            ),
        }
    }

    #[test]
    fn classify_divergence_console_output_difference() {
        let divergence = FrxDivergenceDetail {
            class: FrxDivergenceClass::EventSequence,
            message: "Console output differs".to_string(),
            event_index: Some(2),
            react_signature: Some(FrxTraceEventSignature {
                seq: 2,
                phase: "execution".to_string(),
                event: "console_output:42".to_string(),
                decision_path: "test".to_string(),
                outcome: "ok".to_string(),
            }),
            franken_signature: Some(FrxTraceEventSignature {
                seq: 2,
                phase: "execution".to_string(),
                event: "console_output:43".to_string(),
                decision_path: "test".to_string(),
                outcome: "ok".to_string(),
            }),
        };

        let classification = classify_divergence(&divergence);
        match classification {
            DivergenceEvidenceAtom::EngineBug {
                severity,
                reproducer,
                expected_behavior,
                actual_behavior,
                ..
            } => {
                assert_eq!(severity, BugSeverity::Minor);
                assert!(reproducer.contains("Console output mismatch"));
                assert!(expected_behavior.contains("console_output:42"));
                assert!(actual_behavior.contains("console_output:43"));
            }
            _ => panic!("Expected EngineBug classification for console output difference"),
        }
    }

    #[test]
    fn classify_divergence_state_transition_as_ambiguity() {
        let divergence = FrxDivergenceDetail {
            class: FrxDivergenceClass::StateTransition,
            message: "Different state handling observed".to_string(),
            event_index: Some(1),
            react_signature: Some(FrxTraceEventSignature {
                seq: 1,
                phase: "state".to_string(),
                event: "transition".to_string(),
                decision_path: "test".to_string(),
                outcome: "ok".to_string(),
            }),
            franken_signature: None,
        };

        let classification = classify_divergence(&divergence);
        match classification {
            DivergenceEvidenceAtom::EcosystemAmbiguity {
                ambiguity_type,
                reference_behaviors,
                franken_behavior,
                ..
            } => {
                assert_eq!(ambiguity_type, AmbiguityType::ImplementationDivergence);
                assert_eq!(reference_behaviors.len(), 1);
                assert_eq!(reference_behaviors[0].runtime_name, "Reference");
                assert!(franken_behavior.contains("state: transition"));
            }
            _ => panic!("Expected EcosystemAmbiguity classification for state transition"),
        }
    }

    #[test]
    fn create_divergence_evidence_generates_valid_structure() {
        let divergence = FrxDivergenceDetail {
            class: FrxDivergenceClass::SchemaViolation,
            message: "Test divergence".to_string(),
            event_index: None,
            react_signature: None,
            franken_signature: None,
        };

        let evidence = create_divergence_evidence(
            &divergence,
            "test-case-123",
            ClassificationConfidence::Automated,
        );

        assert_eq!(evidence.schema_version, DIVERGENCE_EVIDENCE_SCHEMA_VERSION);
        assert!(!evidence.evidence_id.is_empty());
        assert_eq!(evidence.lockstep_case_id, "test-case-123");
        assert_eq!(
            evidence.classification_confidence,
            ClassificationConfidence::Automated
        );
        assert_eq!(evidence.original_divergence, divergence);
        assert_eq!(evidence.evidence_sources.len(), 1);
        assert_eq!(
            evidence.evidence_sources[0].source_type,
            EvidenceSourceType::ReferenceImplementation
        );
        assert!(evidence.signature.is_none()); // Not implemented yet
    }

    #[test]
    fn test_create_batch_divergence_evidence() {
        let divergences = vec![
            (
                FrxDivergenceDetail {
                    class: FrxDivergenceClass::SchemaViolation,
                    message: "First divergence".to_string(),
                    event_index: None,
                    react_signature: None,
                    franken_signature: None,
                },
                "case-1".to_string(),
            ),
            (
                FrxDivergenceDetail {
                    class: FrxDivergenceClass::EventSequence,
                    message: "Second divergence".to_string(),
                    event_index: Some(1),
                    react_signature: None,
                    franken_signature: None,
                },
                "case-2".to_string(),
            ),
        ];

        let evidence_batch = create_batch_divergence_evidence(
            &divergences,
            ClassificationConfidence::HumanConfirmed,
        );

        assert_eq!(evidence_batch.len(), 2);
        assert_eq!(evidence_batch[0].lockstep_case_id, "case-1");
        assert_eq!(evidence_batch[1].lockstep_case_id, "case-2");
        assert_eq!(
            evidence_batch[0].classification_confidence,
            ClassificationConfidence::HumanConfirmed
        );
        assert_eq!(
            evidence_batch[1].classification_confidence,
            ClassificationConfidence::HumanConfirmed
        );
    }

    #[test]
    fn apply_triage_rules_critical_bug() {
        let evidence = SignedDivergenceEvidence {
            schema_version: DIVERGENCE_EVIDENCE_SCHEMA_VERSION.to_string(),
            evidence_id: "test-123".to_string(),
            generated_at_utc: "2026-05-21T19:53:00Z".to_string(),
            lockstep_case_id: "case-123".to_string(),
            classification: DivergenceEvidenceAtom::EngineBug {
                divergence_class: FrxDivergenceClass::SchemaViolation,
                severity: BugSeverity::Critical,
                reproducer: "Crash on startup".to_string(),
                expected_behavior: "Normal execution".to_string(),
                actual_behavior: "Segmentation fault".to_string(),
            },
            original_divergence: FrxDivergenceDetail {
                class: FrxDivergenceClass::SchemaViolation,
                message: "Crash".to_string(),
                event_index: None,
                react_signature: None,
                franken_signature: None,
            },
            classification_confidence: ClassificationConfidence::Automated,
            evidence_sources: vec![],
            signature: None,
        };

        let triage = apply_triage_rules(&evidence);
        assert_eq!(triage.priority, TrPriority::P0);
        assert_eq!(triage.assignment, TriageAssignment::EngineTeam);
        assert_eq!(triage.sla_hours, Some(24));
        assert!(triage.escalation_required);
    }

    #[test]
    fn apply_triage_rules_compatibility_debt() {
        let evidence = SignedDivergenceEvidence {
            schema_version: DIVERGENCE_EVIDENCE_SCHEMA_VERSION.to_string(),
            evidence_id: "test-456".to_string(),
            generated_at_utc: "2026-05-21T19:53:00Z".to_string(),
            lockstep_case_id: "case-456".to_string(),
            classification: DivergenceEvidenceAtom::CompatibilityDebt {
                divergence_class: FrxDivergenceClass::StateTransition,
                debt_priority: DebtPriority::High,
                ecosystem_impact: vec!["Framework X".to_string(), "Library Y".to_string()],
                mitigation_strategy: Some("Add compatibility mode".to_string()),
            },
            original_divergence: FrxDivergenceDetail {
                class: FrxDivergenceClass::StateTransition,
                message: "State mismatch".to_string(),
                event_index: None,
                react_signature: None,
                franken_signature: None,
            },
            classification_confidence: ClassificationConfidence::HumanConfirmed,
            evidence_sources: vec![],
            signature: None,
        };

        let triage = apply_triage_rules(&evidence);
        assert_eq!(triage.priority, TrPriority::P1);
        assert_eq!(triage.assignment, TriageAssignment::CompatibilityTeam);
        assert_eq!(triage.sla_hours, Some(120));
        assert!(!triage.escalation_required);
    }

    #[test]
    fn apply_triage_rules_ecosystem_ambiguity() {
        let evidence = SignedDivergenceEvidence {
            schema_version: DIVERGENCE_EVIDENCE_SCHEMA_VERSION.to_string(),
            evidence_id: "test-789".to_string(),
            generated_at_utc: "2026-05-21T19:53:00Z".to_string(),
            lockstep_case_id: "case-789".to_string(),
            classification: DivergenceEvidenceAtom::EcosystemAmbiguity {
                divergence_class: FrxDivergenceClass::HydrationOutcome,
                ambiguity_type: AmbiguityType::SpecificationGap,
                reference_behaviors: vec![],
                franken_behavior: "FrankenEngine choice".to_string(),
                specification_gap: Some("ECMAScript unclear".to_string()),
            },
            original_divergence: FrxDivergenceDetail {
                class: FrxDivergenceClass::HydrationOutcome,
                message: "Ambiguous behavior".to_string(),
                event_index: None,
                react_signature: None,
                franken_signature: None,
            },
            classification_confidence: ClassificationConfidence::Tentative,
            evidence_sources: vec![],
            signature: None,
        };

        let triage = apply_triage_rules(&evidence);
        assert_eq!(triage.priority, TrPriority::P2);
        assert_eq!(triage.assignment, TriageAssignment::StandardsTeam);
        assert_eq!(triage.sla_hours, Some(240));
        assert!(!triage.escalation_required);
    }

    #[test]
    fn bug_severity_classification_from_message() {
        assert_eq!(
            classify_bug_severity("System crash detected"),
            BugSeverity::Critical
        );
        assert_eq!(
            classify_bug_severity("Panic in runtime"),
            BugSeverity::Critical
        );
        assert_eq!(
            classify_bug_severity("Incorrect calculation result"),
            BugSeverity::Major
        );
        assert_eq!(
            classify_bug_severity("Wrong output value"),
            BugSeverity::Major
        );
        assert_eq!(
            classify_bug_severity("Error message format differs"),
            BugSeverity::Cosmetic
        );
        assert_eq!(
            classify_bug_severity("Display formatting issue"),
            BugSeverity::Cosmetic
        );
        assert_eq!(
            classify_bug_severity("Other minor issue"),
            BugSeverity::Minor
        );
    }

    #[test]
    fn is_performance_related_detection() {
        assert!(is_performance_related("Timing optimization detected"));
        assert!(is_performance_related(
            "Performance improvement in execution"
        ));
        assert!(is_performance_related("Speed enhancement"));
        assert!(!is_performance_related("Console output differs"));
        assert!(!is_performance_related("Schema validation failed"));
    }

    #[test]
    fn is_console_output_difference_detection() {
        let divergence_with_console = FrxDivergenceDetail {
            class: FrxDivergenceClass::EventSequence,
            message: "Console output differs between runtimes".to_string(),
            event_index: Some(1),
            react_signature: Some(FrxTraceEventSignature {
                seq: 1,
                phase: "execution".to_string(),
                event: "console_output:42".to_string(),
                decision_path: "test".to_string(),
                outcome: "ok".to_string(),
            }),
            franken_signature: None,
        };

        let divergence_without_console = FrxDivergenceDetail {
            class: FrxDivergenceClass::StateTransition,
            message: "State mismatch detected".to_string(),
            event_index: None,
            react_signature: None,
            franken_signature: None,
        };

        assert!(is_console_output_difference(&divergence_with_console));
        assert!(!is_console_output_difference(&divergence_without_console));
    }

    #[test]
    fn extract_behaviors_from_signatures() {
        let divergence = FrxDivergenceDetail {
            class: FrxDivergenceClass::EventSequence,
            message: "Different behaviors observed".to_string(),
            event_index: Some(1),
            react_signature: Some(FrxTraceEventSignature {
                seq: 1,
                phase: "render".to_string(),
                event: "component_mount".to_string(),
                decision_path: "root/child".to_string(),
                outcome: "success".to_string(),
            }),
            franken_signature: Some(FrxTraceEventSignature {
                seq: 1,
                phase: "execution".to_string(),
                event: "component_init".to_string(),
                decision_path: "root/child".to_string(),
                outcome: "ok".to_string(),
            }),
        };

        let expected = extract_expected_behavior(&divergence);
        let actual = extract_actual_behavior(&divergence);
        let franken = extract_franken_behavior(&divergence);
        let ref_behaviors = extract_reference_behaviors(&divergence);

        assert_eq!(expected, "render: component_mount");
        assert_eq!(actual, "execution: component_init");
        assert_eq!(franken, "execution: component_init (outcome: ok)");
        assert_eq!(ref_behaviors.len(), 1);
        assert_eq!(ref_behaviors[0].runtime_name, "Reference");
        assert_eq!(
            ref_behaviors[0].observed_behavior,
            "render: component_mount"
        );
        assert_eq!(ref_behaviors[0].context_notes, Some("success".to_string()));
    }
}
