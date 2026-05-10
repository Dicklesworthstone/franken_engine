//! RCH validation telemetry ledger.
//!
//! This module records remote validation attempts without invoking cargo or RCH.
//! It gives agents a shared schema for classifying timeouts, compiler
//! diagnostics, worker infrastructure failures, and the next validation action
//! that should be attempted.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hash_tiers::ContentHash;
use serde::{Deserialize, Serialize};

pub const RCH_VALIDATION_TELEMETRY_SCHEMA_VERSION: &str =
    "franken-engine.rch-validation-telemetry.v1";
pub const RCH_VALIDATION_TELEMETRY_TRACE_IDS_SCHEMA_VERSION: &str =
    "franken-engine.rch-validation-telemetry.trace-ids.v1";
pub const RCH_VALIDATION_TELEMETRY_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.rch-validation-telemetry.run-manifest.v1";
pub const RCH_VALIDATION_TELEMETRY_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.rch-validation-telemetry.event.v1";
pub const RCH_VALIDATION_TELEMETRY_COMPONENT: &str = "rch_validation_telemetry";
pub const RCH_VALIDATION_TELEMETRY_POLICY_ID: &str =
    "franken-engine.rch-validation-telemetry.policy.v1";
pub const RCH_VALIDATION_TELEMETRY_BEAD_ID: &str = "bd-7r53m.1";

const TRANSCRIPT_EXCERPT_LIMIT: usize = 4096;

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchValidationCommandClass {
    SourceOnly,
    FocusedLibTest,
    FocusedIntegrationTest,
    PackageAllTargetsCheck,
    ClippyAllTargets,
    TestSuite,
    ReleaseGate,
    Unknown,
}

impl RchValidationCommandClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceOnly => "source_only",
            Self::FocusedLibTest => "focused_lib_test",
            Self::FocusedIntegrationTest => "focused_integration_test",
            Self::PackageAllTargetsCheck => "package_all_targets_check",
            Self::ClippyAllTargets => "clippy_all_targets",
            Self::TestSuite => "test_suite",
            Self::ReleaseGate => "release_gate",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchCompileStage {
    NotStarted,
    SyncingProject,
    ResolvingDependencies,
    CompilingDependencies,
    CompilingTargetCrate,
    TestHarness,
    Completed,
    Unknown,
}

impl RchCompileStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::SyncingProject => "syncing_project",
            Self::ResolvingDependencies => "resolving_dependencies",
            Self::CompilingDependencies => "compiling_dependencies",
            Self::CompilingTargetCrate => "compiling_target_crate",
            Self::TestHarness => "test_harness",
            Self::Completed => "completed",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchValidationOutcome {
    Success,
    CompilerDiagnostic,
    InfrastructureTimeout,
    WorkerDiskFull,
    Cancelled,
    InfrastructureFailure,
    UnknownFailure,
}

impl RchValidationOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::CompilerDiagnostic => "compiler_diagnostic",
            Self::InfrastructureTimeout => "infrastructure_timeout",
            Self::WorkerDiskFull => "worker_disk_full",
            Self::Cancelled => "cancelled",
            Self::InfrastructureFailure => "infrastructure_failure",
            Self::UnknownFailure => "unknown_failure",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RchValidationNextAction {
    NoAction,
    FixCompilerDiagnostic,
    RetryFocusedWithWarmTarget,
    UseSourceOnlyProof,
    WaitForExistingAllTargets,
    QuarantineWorker,
    EscalateInfrastructure,
}

impl RchValidationNextAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoAction => "no_action",
            Self::FixCompilerDiagnostic => "fix_compiler_diagnostic",
            Self::RetryFocusedWithWarmTarget => "retry_focused_with_warm_target",
            Self::UseSourceOnlyProof => "use_source_only_proof",
            Self::WaitForExistingAllTargets => "wait_for_existing_all_targets",
            Self::QuarantineWorker => "quarantine_worker",
            Self::EscalateInfrastructure => "escalate_infrastructure",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchValidationClassifierInput {
    pub bead_id: String,
    pub command: String,
    pub transcript: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_target_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_duration_seconds: Option<u64>,
    pub elapsed_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

impl RchValidationClassifierInput {
    pub fn new(
        bead_id: impl Into<String>,
        command: impl Into<String>,
        transcript: impl Into<String>,
        elapsed_seconds: u64,
    ) -> Self {
        Self {
            bead_id: bead_id.into(),
            command: command.into(),
            transcript: transcript.into(),
            worker_id: None,
            selected_target_dir: None,
            sync_duration_seconds: None,
            elapsed_seconds,
            exit_code: None,
        }
    }

    pub fn worker_id(mut self, worker_id: impl Into<String>) -> Self {
        self.worker_id = Some(worker_id.into());
        self
    }

    pub fn selected_target_dir(mut self, selected_target_dir: impl Into<String>) -> Self {
        self.selected_target_dir = Some(selected_target_dir.into());
        self
    }

    pub fn sync_duration_seconds(mut self, sync_duration_seconds: u64) -> Self {
        self.sync_duration_seconds = Some(sync_duration_seconds);
        self
    }

    pub fn exit_code(mut self, exit_code: i32) -> Self {
        self.exit_code = Some(exit_code);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchValidationTelemetryRecord {
    pub schema_version: String,
    pub bead_id: String,
    pub command: String,
    pub command_class: RchValidationCommandClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_target_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_duration_seconds: Option<u64>,
    pub compile_stage_reached: RchCompileStage,
    pub elapsed_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rch_error_code: Option<String>,
    pub compiler_diagnostic_surfaced: bool,
    pub outcome: RchValidationOutcome,
    pub recommended_next_action: RchValidationNextAction,
    pub transcript_excerpt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchValidationOutcomeSummary {
    pub outcome: RchValidationOutcome,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchValidationTelemetryLedger {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub record_count: u64,
    pub outcome_summaries: Vec<RchValidationOutcomeSummary>,
    pub records: Vec<RchValidationTelemetryRecord>,
}

impl RchValidationTelemetryLedger {
    pub fn from_records(records: Vec<RchValidationTelemetryRecord>) -> Self {
        Self {
            schema_version: RCH_VALIDATION_TELEMETRY_SCHEMA_VERSION.to_string(),
            component: RCH_VALIDATION_TELEMETRY_COMPONENT.to_string(),
            policy_id: RCH_VALIDATION_TELEMETRY_POLICY_ID.to_string(),
            record_count: records.len() as u64,
            outcome_summaries: outcome_summaries(&records),
            records,
        }
    }

    pub fn timeout_count(&self) -> u64 {
        self.records
            .iter()
            .filter(|record| record.outcome == RchValidationOutcome::InfrastructureTimeout)
            .count() as u64
    }

    pub fn compiler_diagnostic_count(&self) -> u64 {
        self.records
            .iter()
            .filter(|record| record.compiler_diagnostic_surfaced)
            .count() as u64
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchValidationTelemetryArtifactPaths {
    pub ledger: String,
    pub trace_ids: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchValidationTelemetryTraceIds {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub ledger_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchValidationTelemetryRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub owner_bead_id: String,
    pub ledger_hash: String,
    pub record_count: u64,
    pub timeout_count: u64,
    pub compiler_diagnostic_count: u64,
    pub artifact_paths: RchValidationTelemetryArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RchValidationTelemetryEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bead_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_class: Option<RchValidationCommandClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rch_error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RchValidationTelemetryArtifacts {
    pub out_dir: PathBuf,
    pub ledger_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub ledger_hash: String,
    pub record_count: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum RchValidationTelemetryWriteError {
    #[error("failed to serialize `{path}`: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to write `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("bundle output directory is already locked by another writer: `{path}`")]
    Busy { path: String },
}

pub fn classify_rch_validation_attempt(
    input: RchValidationClassifierInput,
) -> RchValidationTelemetryRecord {
    let command_class = classify_command(&input.command);
    let compile_stage_reached = classify_compile_stage(&input.transcript, input.exit_code);
    let rch_error_code = extract_rch_error_code(&input.transcript);
    let compiler_diagnostic_surfaced = has_compiler_diagnostic(&input.transcript);
    let outcome = classify_outcome(
        &input.transcript,
        input.exit_code,
        rch_error_code.as_deref(),
        compiler_diagnostic_surfaced,
    );
    let recommended_next_action = recommend_next_action(outcome, command_class);

    RchValidationTelemetryRecord {
        schema_version: RCH_VALIDATION_TELEMETRY_SCHEMA_VERSION.to_string(),
        bead_id: input.bead_id,
        command: input.command,
        command_class,
        worker_id: input.worker_id,
        selected_target_dir: input.selected_target_dir,
        sync_duration_seconds: input.sync_duration_seconds,
        compile_stage_reached,
        elapsed_seconds: input.elapsed_seconds,
        exit_code: input.exit_code,
        rch_error_code,
        compiler_diagnostic_surfaced,
        outcome,
        recommended_next_action,
        transcript_excerpt: bounded_transcript_excerpt(&input.transcript),
    }
}

pub fn write_rch_validation_telemetry_bundle(
    out_dir: impl AsRef<Path>,
    records: &[RchValidationTelemetryRecord],
    command_lines: &[String],
) -> Result<RchValidationTelemetryArtifacts, RchValidationTelemetryWriteError> {
    let out_dir = out_dir.as_ref().to_path_buf();
    fs::create_dir_all(&out_dir).map_err(|source| RchValidationTelemetryWriteError::Io {
        path: out_dir.display().to_string(),
        source,
    })?;

    let ledger = RchValidationTelemetryLedger::from_records(records.to_vec());
    let ledger_path = out_dir.join("rch_validation_telemetry_ledger.json");
    let trace_ids_path = out_dir.join("trace_ids.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");

    let ledger_bytes = canonical_json_bytes(&ledger, &ledger_path)?;
    let ledger_hash = sha256_hex(&ledger_bytes);
    let short_hash = ledger_hash.chars().take(16).collect::<String>();
    let trace_id = format!("trace-rch-validation-{short_hash}");
    let decision_id = format!("decision-rch-validation-{short_hash}");

    let trace_ids = RchValidationTelemetryTraceIds {
        schema_version: RCH_VALIDATION_TELEMETRY_TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: RCH_VALIDATION_TELEMETRY_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: RCH_VALIDATION_TELEMETRY_POLICY_ID.to_string(),
        ledger_hash: ledger_hash.clone(),
    };
    let trace_ids_bytes = canonical_json_bytes(&trace_ids, &trace_ids_path)?;

    let manifest = RchValidationTelemetryRunManifest {
        schema_version: RCH_VALIDATION_TELEMETRY_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: RCH_VALIDATION_TELEMETRY_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: RCH_VALIDATION_TELEMETRY_POLICY_ID.to_string(),
        owner_bead_id: RCH_VALIDATION_TELEMETRY_BEAD_ID.to_string(),
        ledger_hash: ledger_hash.clone(),
        record_count: ledger.record_count,
        timeout_count: ledger.timeout_count(),
        compiler_diagnostic_count: ledger.compiler_diagnostic_count(),
        artifact_paths: RchValidationTelemetryArtifactPaths {
            ledger: "rch_validation_telemetry_ledger.json".to_string(),
            trace_ids: "trace_ids.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        },
    };
    let manifest_bytes = canonical_json_bytes(&manifest, &run_manifest_path)?;

    let events = build_validation_events(&ledger, &trace_id, &decision_id);
    let mut events_jsonl = String::new();
    for event in &events {
        let line = serde_json::to_string(event).map_err(|source| {
            RchValidationTelemetryWriteError::Json {
                path: events_path.display().to_string(),
                source,
            }
        })?;
        events_jsonl.push_str(&line);
        events_jsonl.push('\n');
    }

    let mut commands_buf = String::new();
    for command in command_lines {
        commands_buf.push_str(command);
        commands_buf.push('\n');
    }

    let _bundle_lock = acquire_bundle_write_lock(&out_dir)?;
    remove_commit_marker(&run_manifest_path)?;
    write_atomic(&ledger_path, &ledger_bytes)?;
    write_atomic(&trace_ids_path, &trace_ids_bytes)?;
    write_atomic(&events_path, events_jsonl.as_bytes())?;
    write_atomic(&commands_path, commands_buf.as_bytes())?;
    write_atomic(&run_manifest_path, &manifest_bytes)?;

    Ok(RchValidationTelemetryArtifacts {
        out_dir,
        ledger_path,
        trace_ids_path,
        run_manifest_path,
        events_path,
        commands_path,
        ledger_hash,
        record_count: ledger.record_count as usize,
    })
}

pub fn classify_command(command: &str) -> RchValidationCommandClass {
    let normalized = normalize_text(command);
    if normalized.contains("cargo fmt")
        || normalized.contains("rustfmt")
        || normalized.contains("git diff --check")
    {
        return RchValidationCommandClass::SourceOnly;
    }
    if normalized.contains("cargo clippy") && normalized.contains("--all-targets") {
        return RchValidationCommandClass::ClippyAllTargets;
    }
    if normalized.contains("cargo check") && normalized.contains("--all-targets") {
        return RchValidationCommandClass::PackageAllTargetsCheck;
    }
    if normalized.contains("cargo test") && normalized.contains("--lib") {
        return RchValidationCommandClass::FocusedLibTest;
    }
    if normalized.contains("cargo test") && normalized.contains("--test") {
        return RchValidationCommandClass::FocusedIntegrationTest;
    }
    if normalized.contains("scripts/reproduce.sh") || normalized.contains("cargo publish") {
        return RchValidationCommandClass::ReleaseGate;
    }
    if normalized.contains("cargo test") {
        return RchValidationCommandClass::TestSuite;
    }
    RchValidationCommandClass::Unknown
}

pub fn classify_compile_stage(transcript: &str, exit_code: Option<i32>) -> RchCompileStage {
    let normalized = normalize_text(transcript);
    if exit_code == Some(0)
        || normalized.contains("test result: ok")
        || normalized.contains("finished `test`")
        || normalized.contains("finished `dev`")
    {
        return RchCompileStage::Completed;
    }
    if normalized.contains("running unittests")
        || normalized.contains("running tests")
        || normalized.contains("executable unittests")
        || normalized.contains("test harness")
    {
        return RchCompileStage::TestHarness;
    }
    if normalized.contains("compiling frankenengine-engine")
        || normalized.contains("checking frankenengine-engine")
        || normalized.contains("compiling frankenengine_extension_host")
        || normalized.contains("checking frankenengine_extension_host")
        || normalized.contains("frankenengine_engine/test")
    {
        return RchCompileStage::CompilingTargetCrate;
    }
    if normalized.contains("compiling ") || normalized.contains("checking ") {
        return RchCompileStage::CompilingDependencies;
    }
    if normalized.contains("updating crates.io index")
        || normalized.contains("downloading crates")
        || normalized.contains("resolving dependencies")
        || normalized.contains("locking ")
    {
        return RchCompileStage::ResolvingDependencies;
    }
    if normalized.contains("syncing")
        || normalized.contains("rsync")
        || normalized.contains("selected target")
    {
        return RchCompileStage::SyncingProject;
    }
    if transcript.trim().is_empty() {
        RchCompileStage::NotStarted
    } else {
        RchCompileStage::Unknown
    }
}

pub fn extract_rch_error_code(transcript: &str) -> Option<String> {
    let marker = "RCH-E";
    let start = transcript.find(marker)?;
    let tail = &transcript[start..];
    let code = tail
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .collect::<String>();
    if code == marker || code.is_empty() {
        None
    } else {
        Some(code)
    }
}

pub fn has_compiler_diagnostic(transcript: &str) -> bool {
    let normalized = normalize_text(transcript);
    transcript.contains("error[E")
        || normalized.contains("\nerror[")
        || normalized.contains("error: aborting")
        || normalized.contains("error: could not compile")
        || (normalized.contains("\nerror: ") && normalized.contains("\n  --> "))
}

fn classify_outcome(
    transcript: &str,
    exit_code: Option<i32>,
    rch_error_code: Option<&str>,
    compiler_diagnostic_surfaced: bool,
) -> RchValidationOutcome {
    let normalized = normalize_text(transcript);
    if exit_code == Some(0) {
        return RchValidationOutcome::Success;
    }
    if compiler_diagnostic_surfaced {
        return RchValidationOutcome::CompilerDiagnostic;
    }
    if normalized.contains("no space left on device") || normalized.contains("enospc") {
        return RchValidationOutcome::WorkerDiskFull;
    }
    if rch_error_code == Some("RCH-E104")
        || normalized.contains("timed out")
        || normalized.contains("timeout")
    {
        return RchValidationOutcome::InfrastructureTimeout;
    }
    if normalized.contains("cancelled") || normalized.contains("canceled") {
        return RchValidationOutcome::Cancelled;
    }
    if normalized.contains("ssh")
        || normalized.contains("connection refused")
        || normalized.contains("connection reset")
        || rch_error_code.is_some()
    {
        return RchValidationOutcome::InfrastructureFailure;
    }
    RchValidationOutcome::UnknownFailure
}

fn recommend_next_action(
    outcome: RchValidationOutcome,
    command_class: RchValidationCommandClass,
) -> RchValidationNextAction {
    match outcome {
        RchValidationOutcome::Success => RchValidationNextAction::NoAction,
        RchValidationOutcome::CompilerDiagnostic => RchValidationNextAction::FixCompilerDiagnostic,
        RchValidationOutcome::WorkerDiskFull => RchValidationNextAction::QuarantineWorker,
        RchValidationOutcome::InfrastructureFailure | RchValidationOutcome::Cancelled => {
            RchValidationNextAction::EscalateInfrastructure
        }
        RchValidationOutcome::InfrastructureTimeout => match command_class {
            RchValidationCommandClass::PackageAllTargetsCheck
            | RchValidationCommandClass::ClippyAllTargets
            | RchValidationCommandClass::TestSuite
            | RchValidationCommandClass::ReleaseGate => {
                RchValidationNextAction::WaitForExistingAllTargets
            }
            RchValidationCommandClass::SourceOnly => RchValidationNextAction::UseSourceOnlyProof,
            RchValidationCommandClass::FocusedLibTest
            | RchValidationCommandClass::FocusedIntegrationTest
            | RchValidationCommandClass::Unknown => {
                RchValidationNextAction::RetryFocusedWithWarmTarget
            }
        },
        RchValidationOutcome::UnknownFailure => RchValidationNextAction::EscalateInfrastructure,
    }
}

fn outcome_summaries(records: &[RchValidationTelemetryRecord]) -> Vec<RchValidationOutcomeSummary> {
    let outcomes = [
        RchValidationOutcome::Success,
        RchValidationOutcome::CompilerDiagnostic,
        RchValidationOutcome::InfrastructureTimeout,
        RchValidationOutcome::WorkerDiskFull,
        RchValidationOutcome::Cancelled,
        RchValidationOutcome::InfrastructureFailure,
        RchValidationOutcome::UnknownFailure,
    ];
    outcomes
        .iter()
        .filter_map(|outcome| {
            let count = records
                .iter()
                .filter(|record| record.outcome == *outcome)
                .count() as u64;
            (count > 0).then_some(RchValidationOutcomeSummary {
                outcome: *outcome,
                count,
            })
        })
        .collect()
}

fn build_validation_events(
    ledger: &RchValidationTelemetryLedger,
    trace_id: &str,
    decision_id: &str,
) -> Vec<RchValidationTelemetryEvent> {
    let mut events = Vec::with_capacity(ledger.records.len() + 2);
    events.push(RchValidationTelemetryEvent {
        schema_version: RCH_VALIDATION_TELEMETRY_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: RCH_VALIDATION_TELEMETRY_POLICY_ID.to_string(),
        component: RCH_VALIDATION_TELEMETRY_COMPONENT.to_string(),
        event: "ledger_started".to_string(),
        outcome: "started".to_string(),
        bead_id: Some(RCH_VALIDATION_TELEMETRY_BEAD_ID.to_string()),
        command_class: None,
        worker_id: None,
        rch_error_code: None,
        detail: Some(format!("{} validation records", ledger.record_count)),
    });

    events.extend(
        ledger
            .records
            .iter()
            .map(|record| RchValidationTelemetryEvent {
                schema_version: RCH_VALIDATION_TELEMETRY_EVENT_SCHEMA_VERSION.to_string(),
                trace_id: trace_id.to_string(),
                decision_id: decision_id.to_string(),
                policy_id: RCH_VALIDATION_TELEMETRY_POLICY_ID.to_string(),
                component: RCH_VALIDATION_TELEMETRY_COMPONENT.to_string(),
                event: "validation_recorded".to_string(),
                outcome: record.outcome.as_str().to_string(),
                bead_id: Some(record.bead_id.clone()),
                command_class: Some(record.command_class),
                worker_id: record.worker_id.clone(),
                rch_error_code: record.rch_error_code.clone(),
                detail: Some(format!(
                    "stage={}; action={}; elapsed_seconds={}",
                    record.compile_stage_reached.as_str(),
                    record.recommended_next_action.as_str(),
                    record.elapsed_seconds
                )),
            }),
    );

    events.push(RchValidationTelemetryEvent {
        schema_version: RCH_VALIDATION_TELEMETRY_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: RCH_VALIDATION_TELEMETRY_POLICY_ID.to_string(),
        component: RCH_VALIDATION_TELEMETRY_COMPONENT.to_string(),
        event: "ledger_completed".to_string(),
        outcome: "completed".to_string(),
        bead_id: Some(RCH_VALIDATION_TELEMETRY_BEAD_ID.to_string()),
        command_class: None,
        worker_id: None,
        rch_error_code: None,
        detail: Some(format!(
            "{} records ({} timeouts, {} compiler diagnostics)",
            ledger.record_count,
            ledger.timeout_count(),
            ledger.compiler_diagnostic_count()
        )),
    });

    events
}

fn bounded_transcript_excerpt(transcript: &str) -> String {
    let trimmed = transcript.trim();
    if trimmed.len() <= TRANSCRIPT_EXCERPT_LIMIT {
        return trimmed.to_string();
    }

    let mut excerpt = String::new();
    for ch in trimmed.chars() {
        if excerpt.len() + ch.len_utf8() > TRANSCRIPT_EXCERPT_LIMIT {
            break;
        }
        excerpt.push(ch);
    }
    excerpt.push_str("\n[truncated]");
    excerpt
}

fn normalize_text(text: &str) -> String {
    text.to_ascii_lowercase()
}

fn canonical_json_bytes<T: Serialize>(
    value: &T,
    path: &Path,
) -> Result<Vec<u8>, RchValidationTelemetryWriteError> {
    serde_json::to_vec(value).map_err(|source| RchValidationTelemetryWriteError::Json {
        path: path.display().to_string(),
        source,
    })
}

fn acquire_bundle_write_lock(
    out_dir: &Path,
) -> Result<BundleWriteLock, RchValidationTelemetryWriteError> {
    let lock_path = out_dir.join(".rch_validation_telemetry.lock");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_) => Ok(BundleWriteLock { path: lock_path }),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => {
            Err(RchValidationTelemetryWriteError::Busy {
                path: lock_path.display().to_string(),
            })
        }
        Err(source) => Err(RchValidationTelemetryWriteError::Io {
            path: lock_path.display().to_string(),
            source,
        }),
    }
}

fn remove_commit_marker(path: &Path) -> Result<(), RchValidationTelemetryWriteError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(RchValidationTelemetryWriteError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), RchValidationTelemetryWriteError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| RchValidationTelemetryWriteError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let temp_path = unique_temp_path(path);
    fs::write(&temp_path, bytes).map_err(|source| RchValidationTelemetryWriteError::Io {
        path: temp_path.display().to_string(),
        source,
    })?;
    if let Err(source) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(RchValidationTelemetryWriteError::Io {
            path: path.display().to_string(),
            source,
        });
    }
    Ok(())
}

fn unique_temp_path(path: &Path) -> PathBuf {
    let sequence = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let mut temp_name = OsString::from(".");
    match path.file_name() {
        Some(file_name) => temp_name.push(file_name),
        None => temp_name.push("artifact"),
    }
    temp_name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(temp_name)
}

fn sha256_hex(bytes: &[u8]) -> String {
    ContentHash::compute(bytes).to_hex()
}

struct BundleWriteLock {
    path: PathBuf,
}

impl Drop for BundleWriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rch_e104_timeout_without_diagnostic_gets_retryable_action() {
        let transcript = "\
[RCH] selected worker vmi1153651
[RCH] selected target dir /tmp/rch-target-franken-engine-bd-7eefz-async-gen
   Compiling frankenengine-engine v0.1.0 (/work/crates/franken-engine)
[RCH] remote vmi1153651 failed [RCH-E104] SSH command timed out (no local fallback)
";
        let record = classify_rch_validation_attempt(
            RchValidationClassifierInput::new(
                "bd-7eefz",
                "rch exec -- cargo test -p frankenengine-engine --lib async_generator_next_fails_closed_for_suspended_body -- --nocapture",
                transcript,
                3600,
            )
            .worker_id("vmi1153651")
            .selected_target_dir("/tmp/rch-target-franken-engine-bd-7eefz-async-gen"),
        );

        assert_eq!(
            record.command_class,
            RchValidationCommandClass::FocusedLibTest
        );
        assert_eq!(
            record.compile_stage_reached,
            RchCompileStage::CompilingTargetCrate
        );
        assert_eq!(record.rch_error_code.as_deref(), Some("RCH-E104"));
        assert!(!record.compiler_diagnostic_surfaced);
        assert_eq!(record.outcome, RchValidationOutcome::InfrastructureTimeout);
        assert_eq!(
            record.recommended_next_action,
            RchValidationNextAction::RetryFocusedWithWarmTarget
        );
    }

    #[test]
    fn compiler_diagnostic_takes_precedence_over_infrastructure_text() {
        let transcript = "\
error[E0308]: mismatched types
  --> crates/franken-engine/src/lib.rs:10:5
   |
10 |     1
   |     ^ expected `String`, found integer
error: could not compile `frankenengine-engine` due to previous error
";
        let record = classify_rch_validation_attempt(
            RchValidationClassifierInput::new(
                "bd-diagnostic",
                "rch exec -- cargo check --all-targets",
                transcript,
                42,
            )
            .exit_code(101),
        );

        assert_eq!(
            record.command_class,
            RchValidationCommandClass::PackageAllTargetsCheck
        );
        assert!(record.compiler_diagnostic_surfaced);
        assert_eq!(record.outcome, RchValidationOutcome::CompilerDiagnostic);
        assert_eq!(
            record.recommended_next_action,
            RchValidationNextAction::FixCompilerDiagnostic
        );
    }

    #[test]
    fn worker_disk_full_quarantines_worker() {
        let record = classify_rch_validation_attempt(
            RchValidationClassifierInput::new(
                "bd-disk",
                "rch exec -- cargo clippy --all-targets -- -D warnings",
                "failed to write target object: No space left on device (os error 28)",
                7,
            )
            .worker_id("vmi-diskfull")
            .exit_code(1),
        );

        assert_eq!(
            record.command_class,
            RchValidationCommandClass::ClippyAllTargets
        );
        assert_eq!(record.outcome, RchValidationOutcome::WorkerDiskFull);
        assert_eq!(
            record.recommended_next_action,
            RchValidationNextAction::QuarantineWorker
        );
    }

    #[test]
    fn successful_source_only_validation_records_no_action() {
        let record = classify_rch_validation_attempt(
            RchValidationClassifierInput::new(
                "bd-source",
                "rustfmt --edition 2024 --check crates/franken-engine/src/rch_validation_telemetry.rs",
                "",
                1,
            )
            .exit_code(0),
        );

        assert_eq!(record.command_class, RchValidationCommandClass::SourceOnly);
        assert_eq!(record.compile_stage_reached, RchCompileStage::Completed);
        assert_eq!(record.outcome, RchValidationOutcome::Success);
        assert_eq!(
            record.recommended_next_action,
            RchValidationNextAction::NoAction
        );
    }

    #[test]
    fn write_bundle_emits_ledger_manifest_events_and_commands() {
        let timeout = classify_rch_validation_attempt(RchValidationClassifierInput::new(
            "bd-timeout",
            "rch exec -- cargo check --all-targets",
            "[RCH-E104] SSH command timed out",
            3600,
        ));
        let success = classify_rch_validation_attempt(
            RchValidationClassifierInput::new(
                "bd-source",
                "git diff --check -- crates/franken-engine/src/rch_validation_telemetry.rs",
                "",
                1,
            )
            .exit_code(0),
        );
        let records = vec![timeout, success];
        let out_dir = unique_temp_dir("rch-validation-telemetry");
        let commands = vec![
            "rch_validation_telemetry --out-dir".to_string(),
            out_dir.display().to_string(),
        ];

        let artifacts = write_rch_validation_telemetry_bundle(&out_dir, &records, &commands)
            .expect("write rch validation telemetry bundle");
        assert!(artifacts.ledger_path.exists());
        assert!(artifacts.trace_ids_path.exists());
        assert!(artifacts.run_manifest_path.exists());
        assert!(artifacts.events_path.exists());
        assert!(artifacts.commands_path.exists());
        assert_eq!(artifacts.record_count, 2);

        let ledger: RchValidationTelemetryLedger =
            serde_json::from_slice(&fs::read(&artifacts.ledger_path).expect("read ledger"))
                .expect("ledger json");
        assert_eq!(ledger.record_count, 2);
        assert_eq!(ledger.timeout_count(), 1);

        let manifest: RchValidationTelemetryRunManifest =
            serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read manifest"))
                .expect("manifest json");
        assert_eq!(manifest.ledger_hash, artifacts.ledger_hash);
        assert_eq!(manifest.timeout_count, 1);
        assert_eq!(manifest.compiler_diagnostic_count, 0);

        let events = fs::read_to_string(&artifacts.events_path).expect("read events");
        assert_eq!(events.lines().count(), 4);
        assert!(events.contains("infrastructure_timeout"));

        let commands_txt = fs::read_to_string(&artifacts.commands_path).expect("read commands");
        assert!(commands_txt.contains("rch_validation_telemetry --out-dir"));
        assert!(!out_dir.join(".rch_validation_telemetry.lock").exists());
    }

    #[test]
    fn transcript_excerpt_is_bounded_at_utf8_boundary() {
        let transcript = format!("{}{}", "a".repeat(TRANSCRIPT_EXCERPT_LIMIT + 10), "end");
        let record = classify_rch_validation_attempt(RchValidationClassifierInput::new(
            "bd-long",
            "rch exec -- cargo test",
            transcript,
            2,
        ));
        assert!(record.transcript_excerpt.len() <= TRANSCRIPT_EXCERPT_LIMIT + 12);
        assert!(record.transcript_excerpt.ends_with("[truncated]"));
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let sequence = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), sequence))
    }
}
