//! Replay runner for SWARM-CTRL-XII execution queue inputs.
//!
//! This module loads the normalized input emitted by
//! `scripts/swarm_execution_queue_input_normalizer.sh`, converts the task rows
//! into `SwarmControlLoop` nodes, runs `SwarmControlLoop::recompute`, and writes
//! replayable advisory artifacts. It does not mutate live bead, reservation,
//! Agent Mail, or worker state.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::swarm_control_loop::{
    ControlLoopConfig, ControlLoopError, CrossCuttingSignals, QueueArtifact, SwarmControlLoop,
    SwarmRiskBudget, TaskNode,
};

const MILLION: i64 = 1_000_000;
const MAX_QUEUE_DEPTH: usize = 64;

/// Schema version for runner manifests.
pub const SWARM_EXECUTION_QUEUE_RUNNER_SCHEMA_VERSION: &str =
    "franken-engine.swarm-execution-queue-runner.v1";

/// Schema version for the artifact envelope written by this runner.
pub const SWARM_EXECUTION_QUEUE_ARTIFACT_SCHEMA_VERSION: &str =
    "franken-engine.swarm-execution-queue-artifact.v1";

/// Schema version for risk-budget receipts written by this runner.
pub const SWARM_EXECUTION_RISK_BUDGET_RECEIPT_SCHEMA_VERSION: &str =
    "franken-engine.swarm-execution-risk-budget-receipt.v1";

/// Schema version for bottleneck reports written by this runner.
pub const SWARM_EXECUTION_BOTTLENECK_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.swarm-execution-bottleneck-report.v1";

/// Expected normalized input schema version.
pub const SWARM_EXECUTION_QUEUE_INPUT_SCHEMA_VERSION: &str =
    "franken-engine.swarm-execution-queue-input.v1";

/// Runner options supplied by the CLI or tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionQueueRunOptions {
    /// Maximum number of queue entries to emit.
    pub queue_depth: usize,
    /// Include gated tasks in the queue.
    pub include_gated_in_queue: bool,
    /// Security epoch for the emitted artifact.
    pub epoch: u64,
    /// Deterministic timestamp for the emitted artifact.
    pub timestamp_ns: u64,
    /// Optional command-line transcript to place in `commands.txt`.
    pub command_line: Vec<String>,
}

impl Default for ExecutionQueueRunOptions {
    fn default() -> Self {
        Self {
            queue_depth: 10,
            include_gated_in_queue: false,
            epoch: 0,
            timestamp_ns: 0,
            command_line: Vec::new(),
        }
    }
}

/// Paths written by a successful run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionQueueRunOutput {
    /// Run manifest path.
    pub run_manifest_json: PathBuf,
    /// Event stream path.
    pub events_jsonl: PathBuf,
    /// Command transcript path.
    pub commands_txt: PathBuf,
    /// Queue artifact path.
    pub execution_queue_artifact_json: PathBuf,
    /// Risk-budget receipt path.
    pub risk_budget_receipt_json: PathBuf,
    /// Bottleneck report path.
    pub bottleneck_report_json: PathBuf,
    /// Operator-facing summary path.
    pub operator_summary_md: PathBuf,
    /// Deterministic artifact hash from `SwarmControlLoop`.
    pub artifact_hash_hex: String,
}

/// Errors from the replay runner.
#[derive(Debug)]
pub enum ExecutionQueueRunnerError {
    /// Filesystem error.
    Io {
        /// Path involved in the failed operation.
        path: PathBuf,
        /// Stable diagnostic.
        detail: String,
    },
    /// JSON parse or serialization error.
    Json {
        /// Stable diagnostic.
        detail: String,
    },
    /// Input failed runner validation.
    InvalidInput {
        /// Stable diagnostic.
        detail: String,
    },
    /// Underlying control-loop validation or recompute failed.
    ControlLoop(ControlLoopError),
}

impl ExecutionQueueRunnerError {
    /// Shell exit code for the CLI wrapper.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Io { .. } | Self::Json { .. } => 64,
            Self::InvalidInput { .. } | Self::ControlLoop(_) => 42,
        }
    }
}

impl fmt::Display for ExecutionQueueRunnerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, detail } => {
                write!(f, "I/O error at {}: {detail}", path.display())
            }
            Self::Json { detail } => write!(f, "JSON error: {detail}"),
            Self::InvalidInput { detail } => write!(f, "invalid execution queue input: {detail}"),
            Self::ControlLoop(err) => write!(f, "swarm control loop rejected input: {err}"),
        }
    }
}

impl std::error::Error for ExecutionQueueRunnerError {}

impl From<ControlLoopError> for ExecutionQueueRunnerError {
    fn from(value: ControlLoopError) -> Self {
        Self::ControlLoop(value)
    }
}

/// Run `SwarmControlLoop` against a normalized input file and write artifacts.
pub fn run_normalized_input_file(
    normalized_input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    options: ExecutionQueueRunOptions,
) -> Result<ExecutionQueueRunOutput, ExecutionQueueRunnerError> {
    let normalized_input_path = normalized_input_path.as_ref();
    let raw = fs::read(normalized_input_path).map_err(|err| ExecutionQueueRunnerError::Io {
        path: normalized_input_path.to_path_buf(),
        detail: err.to_string(),
    })?;
    let input: NormalizedExecutionQueueInput =
        serde_json::from_slice(&raw).map_err(|err| ExecutionQueueRunnerError::Json {
            detail: err.to_string(),
        })?;
    run_normalized_input_bytes(&raw, input, normalized_input_path, output_dir, options)
}

fn run_normalized_input_bytes(
    raw_input: &[u8],
    input: NormalizedExecutionQueueInput,
    normalized_input_path: &Path,
    output_dir: impl AsRef<Path>,
    options: ExecutionQueueRunOptions,
) -> Result<ExecutionQueueRunOutput, ExecutionQueueRunnerError> {
    validate_options(&options)?;
    validate_input(&input)?;

    let output_dir = output_dir.as_ref();
    fs::create_dir_all(output_dir).map_err(|err| ExecutionQueueRunnerError::Io {
        path: output_dir.to_path_buf(),
        detail: err.to_string(),
    })?;

    let events_path = output_dir.join("events.jsonl");
    let commands_path = output_dir.join("commands.txt");
    let run_manifest_path = output_dir.join("run_manifest.json");
    let queue_artifact_path = output_dir.join("execution_queue_artifact.json");
    let risk_budget_path = output_dir.join("risk_budget_receipt.json");
    let bottleneck_report_path = output_dir.join("bottleneck_report.json");
    let operator_summary_path = output_dir.join("operator_summary.md");

    write_commands(&commands_path, normalized_input_path, output_dir, &options)?;
    write_event(
        &events_path,
        "runner.started",
        "loaded normalized execution queue input",
        input.source_revision.as_deref().unwrap_or("unknown"),
    )?;

    let mut control_loop = SwarmControlLoop::new(ControlLoopConfig {
        queue_depth: options.queue_depth,
        conservative_threshold_millionths: input.risk_budget.conservative_threshold_millionths,
        include_gated_in_queue: options.include_gated_in_queue,
        ..ControlLoopConfig::default()
    })?;
    control_loop.risk_budget = input.risk_budget.to_swarm_budget()?;

    for task in &input.tasks {
        control_loop.add_task(task.to_task_node()?)?;
    }

    let artifact = control_loop.recompute(
        SecurityEpoch::from_raw(options.epoch),
        options.timestamp_ns,
        input.cross_cutting_signals.clone(),
        input.evidence_ids(),
    )?;

    let input_hash = ContentHash::compute(raw_input).to_hex();
    let artifact_hash_hex = artifact.artifact_hash.to_hex();

    let queue_doc = ExecutionQueueArtifactDocument {
        schema_version: SWARM_EXECUTION_QUEUE_ARTIFACT_SCHEMA_VERSION,
        runner_schema_version: SWARM_EXECUTION_QUEUE_RUNNER_SCHEMA_VERSION,
        source_revision: input.source_revision.as_deref().unwrap_or("unknown"),
        normalized_input_hash_hex: &input_hash,
        artifact_hash_hex: &artifact_hash_hex,
        queue_artifact: &artifact,
    };
    write_json(&queue_artifact_path, &queue_doc)?;

    let risk_doc = RiskBudgetReceiptDocument {
        schema_version: SWARM_EXECUTION_RISK_BUDGET_RECEIPT_SCHEMA_VERSION,
        runner_schema_version: SWARM_EXECUTION_QUEUE_RUNNER_SCHEMA_VERSION,
        source_revision: input.source_revision.as_deref().unwrap_or("unknown"),
        normalized_input_hash_hex: &input_hash,
        decision: input.decision.as_deref().unwrap_or("unknown"),
        risk_budget: &artifact.risk_budget,
        conservative_mode: artifact.risk_budget.conservative_mode,
        queue_depth: artifact.queue.len() as u64,
    };
    write_json(&risk_budget_path, &risk_doc)?;

    let bottleneck_doc = BottleneckReportDocument {
        schema_version: SWARM_EXECUTION_BOTTLENECK_REPORT_SCHEMA_VERSION,
        runner_schema_version: SWARM_EXECUTION_QUEUE_RUNNER_SCHEMA_VERSION,
        source_revision: input.source_revision.as_deref().unwrap_or("unknown"),
        normalized_input_hash_hex: &input_hash,
        bottleneck_count: artifact.bottlenecks.len() as u64,
        critical_bottleneck_count: artifact.critical_bottleneck_count() as u64,
        bottlenecks: &artifact.bottlenecks,
    };
    write_json(&bottleneck_report_path, &bottleneck_doc)?;

    write_operator_summary(
        &operator_summary_path,
        &artifact,
        &input,
        &artifact_hash_hex,
    )?;

    let output = ExecutionQueueRunOutput {
        run_manifest_json: run_manifest_path.clone(),
        events_jsonl: events_path.clone(),
        commands_txt: commands_path.clone(),
        execution_queue_artifact_json: queue_artifact_path.clone(),
        risk_budget_receipt_json: risk_budget_path.clone(),
        bottleneck_report_json: bottleneck_report_path.clone(),
        operator_summary_md: operator_summary_path.clone(),
        artifact_hash_hex: artifact_hash_hex.clone(),
    };

    let manifest_doc = RunManifestDocument {
        schema_version: SWARM_EXECUTION_QUEUE_RUNNER_SCHEMA_VERSION,
        source_revision: input.source_revision.as_deref().unwrap_or("unknown"),
        normalized_input_path: &normalized_input_path.display().to_string(),
        normalized_input_hash_hex: &input_hash,
        decision: input.decision.as_deref().unwrap_or("unknown"),
        task_count: input.tasks.len() as u64,
        queue_depth: artifact.queue.len() as u64,
        artifact_hash_hex: &artifact_hash_hex,
        artifact_paths: &output,
    };
    write_json(&run_manifest_path, &manifest_doc)?;

    write_event(
        &events_path,
        "runner.completed",
        &format!(
            "queue_entries={} conservative={}",
            artifact.queue.len(),
            artifact.risk_budget.conservative_mode
        ),
        input.source_revision.as_deref().unwrap_or("unknown"),
    )?;

    Ok(output)
}

fn validate_options(options: &ExecutionQueueRunOptions) -> Result<(), ExecutionQueueRunnerError> {
    if options.queue_depth == 0 || options.queue_depth > MAX_QUEUE_DEPTH {
        return Err(ExecutionQueueRunnerError::InvalidInput {
            detail: format!(
                "queue_depth {} must be in 1..={MAX_QUEUE_DEPTH}",
                options.queue_depth
            ),
        });
    }
    Ok(())
}

fn validate_input(input: &NormalizedExecutionQueueInput) -> Result<(), ExecutionQueueRunnerError> {
    if input.schema_version != SWARM_EXECUTION_QUEUE_INPUT_SCHEMA_VERSION {
        return Err(ExecutionQueueRunnerError::InvalidInput {
            detail: format!(
                "schema_version must be {SWARM_EXECUTION_QUEUE_INPUT_SCHEMA_VERSION}, got {}",
                input.schema_version
            ),
        });
    }
    if input.tasks.is_empty() {
        return Err(ExecutionQueueRunnerError::InvalidInput {
            detail: "empty task graph".to_string(),
        });
    }
    if !input.fail_closed_reasons.is_empty() {
        return Err(ExecutionQueueRunnerError::InvalidInput {
            detail: "input already contains fail_closed_reasons".to_string(),
        });
    }
    if input.decision.as_deref() == Some("fail_closed") {
        return Err(ExecutionQueueRunnerError::InvalidInput {
            detail: "input decision is fail_closed".to_string(),
        });
    }
    for degraded in &input.degraded_inputs {
        if !degraded.is_recognized() {
            return Err(ExecutionQueueRunnerError::InvalidInput {
                detail: format!("unrecognized degraded evidence: {}", degraded.label()),
            });
        }
    }
    for task in &input.tasks {
        task.validate()?;
    }
    Ok(())
}

fn write_commands(
    path: &Path,
    normalized_input_path: &Path,
    output_dir: &Path,
    options: &ExecutionQueueRunOptions,
) -> Result<(), ExecutionQueueRunnerError> {
    let line = if options.command_line.is_empty() {
        format!(
            "franken_swarm_execution_queue --normalized-input-json {} --output-dir {}",
            normalized_input_path.display(),
            output_dir.display()
        )
    } else {
        options.command_line.join(" ")
    };
    fs::write(path, format!("{line}\n")).map_err(|err| ExecutionQueueRunnerError::Io {
        path: path.to_path_buf(),
        detail: err.to_string(),
    })
}

fn write_event(
    path: &Path,
    event_name: &str,
    detail: &str,
    source_revision: &str,
) -> Result<(), ExecutionQueueRunnerError> {
    let mut existing = if path.exists() {
        fs::read_to_string(path).map_err(|err| ExecutionQueueRunnerError::Io {
            path: path.to_path_buf(),
            detail: err.to_string(),
        })?
    } else {
        String::new()
    };
    let event = json!({
        "schema_version": "franken-engine.swarm-execution-queue-runner.event.v1",
        "event_name": event_name,
        "detail": detail,
        "source_revision": source_revision,
    });
    existing.push_str(&serde_json::to_string(&event).map_err(|err| {
        ExecutionQueueRunnerError::Json {
            detail: err.to_string(),
        }
    })?);
    existing.push('\n');
    fs::write(path, existing).map_err(|err| ExecutionQueueRunnerError::Io {
        path: path.to_path_buf(),
        detail: err.to_string(),
    })
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), ExecutionQueueRunnerError> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|err| ExecutionQueueRunnerError::Json {
            detail: err.to_string(),
        })?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(|err| ExecutionQueueRunnerError::Io {
        path: path.to_path_buf(),
        detail: err.to_string(),
    })
}

fn write_operator_summary(
    path: &Path,
    artifact: &QueueArtifact,
    input: &NormalizedExecutionQueueInput,
    artifact_hash_hex: &str,
) -> Result<(), ExecutionQueueRunnerError> {
    let mut summary = String::new();
    summary.push_str("# Swarm Execution Queue\n\n");
    summary.push_str(&format!(
        "- Decision: `{}`\n",
        input.decision.as_deref().unwrap_or("unknown")
    ));
    summary.push_str(&format!("- Queue entries: `{}`\n", artifact.queue.len()));
    summary.push_str(&format!(
        "- Conservative mode: `{}`\n",
        artifact.risk_budget.conservative_mode
    ));
    summary.push_str(&format!(
        "- Bottlenecks: `{}`\n",
        artifact.bottlenecks.len()
    ));
    summary.push_str(&format!("- Artifact hash: `{artifact_hash_hex}`\n\n"));
    summary.push_str("## First Actions\n");
    for entry in &artifact.queue {
        summary.push_str(&format!(
            "- `#{}` `{}` `{}`: {}\n",
            entry.rank, entry.task_id, entry.wave, entry.first_action
        ));
    }
    fs::write(path, summary).map_err(|err| ExecutionQueueRunnerError::Io {
        path: path.to_path_buf(),
        detail: err.to_string(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NormalizedExecutionQueueInput {
    schema_version: String,
    #[serde(default)]
    source_revision: Option<String>,
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    cross_cutting_signals: CrossCuttingSignals,
    #[serde(default)]
    risk_budget: NormalizedRiskBudget,
    #[serde(default)]
    accepted_inputs: Vec<NormalizedEvidence>,
    #[serde(default)]
    degraded_inputs: Vec<NormalizedEvidence>,
    #[serde(default)]
    fail_closed_reasons: Vec<NormalizedEvidence>,
    tasks: Vec<NormalizedTask>,
}

impl NormalizedExecutionQueueInput {
    fn evidence_ids(&self) -> Vec<String> {
        self.accepted_inputs
            .iter()
            .filter_map(|evidence| evidence.input.clone().or_else(|| evidence.source.clone()))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NormalizedRiskBudget {
    #[serde(default = "default_remaining_millionths")]
    remaining_millionths: i64,
    #[serde(default)]
    consumed_millionths: i64,
    #[serde(default = "default_conservative_threshold_millionths")]
    conservative_threshold_millionths: i64,
    #[serde(default)]
    conservative_mode: bool,
}

impl Default for NormalizedRiskBudget {
    fn default() -> Self {
        Self {
            remaining_millionths: MILLION,
            consumed_millionths: 0,
            conservative_threshold_millionths: 200_000,
            conservative_mode: false,
        }
    }
}

impl NormalizedRiskBudget {
    fn to_swarm_budget(&self) -> Result<SwarmRiskBudget, ExecutionQueueRunnerError> {
        validate_millionths(
            self.remaining_millionths,
            "risk_budget.remaining_millionths",
        )?;
        validate_millionths(self.consumed_millionths, "risk_budget.consumed_millionths")?;
        validate_millionths(
            self.conservative_threshold_millionths,
            "risk_budget.conservative_threshold_millionths",
        )?;
        Ok(SwarmRiskBudget {
            remaining_millionths: self.remaining_millionths,
            consumed_millionths: self.consumed_millionths,
            conservative_mode: self.conservative_mode
                || self.remaining_millionths <= self.conservative_threshold_millionths,
            conservative_threshold_millionths: self.conservative_threshold_millionths,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NormalizedTask {
    task_id: String,
    title: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    priority: u64,
    #[serde(default)]
    assignee: String,
    #[serde(default)]
    depends_on: Vec<String>,
    #[serde(default)]
    dependents: Vec<String>,
    #[serde(default)]
    completed: bool,
    #[serde(default)]
    scores: NormalizedScores,
    #[serde(default)]
    proof_transport: NormalizedProofTransport,
    #[serde(default)]
    fallback_trigger: String,
    first_action: String,
}

impl NormalizedTask {
    fn validate(&self) -> Result<(), ExecutionQueueRunnerError> {
        if self.task_id.trim().is_empty() {
            return Err(ExecutionQueueRunnerError::InvalidInput {
                detail: "task_id cannot be empty".to_string(),
            });
        }
        if self.first_action.trim().is_empty() {
            return Err(ExecutionQueueRunnerError::InvalidInput {
                detail: format!("task {} has empty first_action", self.task_id),
            });
        }
        if self.priority > 4 {
            return Err(ExecutionQueueRunnerError::InvalidInput {
                detail: format!("task {} priority {} exceeds 4", self.task_id, self.priority),
            });
        }
        if self.proof_transport.local_fallback_detected {
            return Err(ExecutionQueueRunnerError::InvalidInput {
                detail: format!(
                    "task {} promotes local-rch fallback as proof health",
                    self.task_id
                ),
            });
        }
        if self.proof_transport.state.contains("local_fallback") {
            return Err(ExecutionQueueRunnerError::InvalidInput {
                detail: format!(
                    "task {} encodes local-rch fallback as proof transport state",
                    self.task_id
                ),
            });
        }
        self.scores.validate(&self.task_id)
    }

    fn to_task_node(&self) -> Result<TaskNode, ExecutionQueueRunnerError> {
        Ok(TaskNode {
            task_id: self.task_id.clone(),
            title: self.title.clone(),
            depends_on: self.depends_on.iter().cloned().collect::<BTreeSet<_>>(),
            dependents: self.dependents.iter().cloned().collect::<BTreeSet<_>>(),
            completed: self.completed || self.status == "closed",
            impact_millionths: self.scores.impact_millionths,
            confidence_millionths: self.scores.confidence_millionths,
            reuse_millionths: self.scores.reuse_millionths,
            effort_millionths: self.scores.effort_millionths,
            friction_millionths: self.scores.friction_millionths,
            primary_risk: if self.fallback_trigger.is_empty() || self.fallback_trigger == "none" {
                "none".to_string()
            } else {
                self.fallback_trigger.clone()
            },
            countermeasure: self.first_action.clone(),
            fallback_trigger: if self.fallback_trigger.is_empty() {
                "none".to_string()
            } else {
                self.fallback_trigger.clone()
            },
            first_action: self.first_action.clone(),
            assignee: self.assignee.clone(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NormalizedScores {
    #[serde(default = "default_score")]
    impact_millionths: i64,
    #[serde(default = "default_score")]
    confidence_millionths: i64,
    #[serde(default)]
    reuse_millionths: i64,
    #[serde(default = "default_effort")]
    effort_millionths: i64,
    #[serde(default)]
    friction_millionths: i64,
}

impl Default for NormalizedScores {
    fn default() -> Self {
        Self {
            impact_millionths: 500_000,
            confidence_millionths: 500_000,
            reuse_millionths: 0,
            effort_millionths: 300_000,
            friction_millionths: 0,
        }
    }
}

impl NormalizedScores {
    fn validate(&self, task_id: &str) -> Result<(), ExecutionQueueRunnerError> {
        validate_millionths(
            self.impact_millionths,
            &format!("task {task_id} scores.impact_millionths"),
        )?;
        validate_millionths(
            self.confidence_millionths,
            &format!("task {task_id} scores.confidence_millionths"),
        )?;
        validate_millionths(
            self.reuse_millionths,
            &format!("task {task_id} scores.reuse_millionths"),
        )?;
        validate_millionths(
            self.effort_millionths,
            &format!("task {task_id} scores.effort_millionths"),
        )?;
        validate_millionths(
            self.friction_millionths,
            &format!("task {task_id} scores.friction_millionths"),
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct NormalizedProofTransport {
    #[serde(default)]
    state: String,
    #[serde(default)]
    local_fallback_detected: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct NormalizedEvidence {
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    input: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    label: Option<String>,
}

impl NormalizedEvidence {
    fn is_recognized(&self) -> bool {
        const KINDS: &[&str] = &[
            "stale_owner",
            "reservation_contention",
            "proof_transport_degraded",
        ];
        const INPUTS: &[&str] = &[
            "agent_mail_activity_json",
            "file_reservations_json",
            "stale_lock_recommendations_json",
            "proof_transport_health_json",
        ];
        self.kind
            .as_deref()
            .is_some_and(|kind| KINDS.contains(&kind))
            || self
                .input
                .as_deref()
                .is_some_and(|input| INPUTS.contains(&input))
    }

    fn label(&self) -> String {
        self.kind
            .clone()
            .or_else(|| self.input.clone())
            .or_else(|| self.source.clone())
            .or_else(|| self.label.clone())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

#[derive(Debug, Serialize)]
struct ExecutionQueueArtifactDocument<'a> {
    schema_version: &'static str,
    runner_schema_version: &'static str,
    source_revision: &'a str,
    normalized_input_hash_hex: &'a str,
    artifact_hash_hex: &'a str,
    queue_artifact: &'a QueueArtifact,
}

#[derive(Debug, Serialize)]
struct RiskBudgetReceiptDocument<'a> {
    schema_version: &'static str,
    runner_schema_version: &'static str,
    source_revision: &'a str,
    normalized_input_hash_hex: &'a str,
    decision: &'a str,
    risk_budget: &'a SwarmRiskBudget,
    conservative_mode: bool,
    queue_depth: u64,
}

#[derive(Debug, Serialize)]
struct BottleneckReportDocument<'a> {
    schema_version: &'static str,
    runner_schema_version: &'static str,
    source_revision: &'a str,
    normalized_input_hash_hex: &'a str,
    bottleneck_count: u64,
    critical_bottleneck_count: u64,
    bottlenecks: &'a [crate::swarm_control_loop::Bottleneck],
}

#[derive(Debug, Serialize)]
struct RunManifestDocument<'a> {
    schema_version: &'static str,
    source_revision: &'a str,
    normalized_input_path: &'a str,
    normalized_input_hash_hex: &'a str,
    decision: &'a str,
    task_count: u64,
    queue_depth: u64,
    artifact_hash_hex: &'a str,
    artifact_paths: &'a ExecutionQueueRunOutput,
}

fn validate_millionths(value: i64, label: &str) -> Result<(), ExecutionQueueRunnerError> {
    if !(0..=MILLION).contains(&value) {
        return Err(ExecutionQueueRunnerError::InvalidInput {
            detail: format!("{label} must be in 0..={MILLION}, got {value}"),
        });
    }
    Ok(())
}

fn default_remaining_millionths() -> i64 {
    MILLION
}

fn default_conservative_threshold_millionths() -> i64 {
    200_000
}

fn default_score() -> i64 {
    500_000
}

fn default_effort() -> i64 {
    300_000
}
