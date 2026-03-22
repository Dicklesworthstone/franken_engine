#![forbid(unsafe_code)]

//! Parent integration/report surface for the compositional tail-latency control
//! plane.
//!
//! Bead: bd-1lsy.7.11 [RGC-611]
//!
//! This module composes the existing stage-envelope, queueing-admission, and
//! bounded-feedback subsystems into a parent control-plane artifact. The goal
//! is not a new hot-path runtime primitive; the goal is an operator-grade,
//! deterministic bundle that explains:
//! - per-stage envelope compliance
//! - queue-model calibration
//! - end-to-end p99/p999 bounds
//! - explicit queue/service/synchronization/GC decomposition
//! - fail-closed fallback activation when tail guardrails are breached

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::bounded_feedback_controller::{
    ActuatorKind, ControllerConfig, ControllerDecision, ControllerMode, CoordinatorHealthSummary,
    FeedbackCoordinator, FeedbackEvidenceManifest, FeedbackPolicy, LatencyObservation,
    LatencyTarget, PolicyValidationError,
};
use crate::queueing_admission_control::{
    AdmissionControlManifest, AdmissionControlPolicy, AdmissionController, AdmissionPriority,
    AdmissionReceipt, SizingInput, WorkerPoolSizing, compute_worker_pool_sizing,
};
use crate::security_epoch::SecurityEpoch;
use crate::stage_envelope_certificate::{
    EnvelopeBundle, EnvelopeVerdict, ExecutionStage, LatencyPercentile, StageLatencyEnvelope,
    StageLatencyObservation, ViolationReport, build_envelope_bundle, generate_violation_report,
};

pub const TAIL_LATENCY_CONTROL_PLANE_SCHEMA_VERSION: &str =
    "franken-engine.tail-latency-control-plane.v1";
pub const TAIL_LATENCY_CONTROL_PLANE_BEAD_ID: &str = "bd-1lsy.7.11";
pub const TAIL_LATENCY_CONTROL_PLANE_POLICY_ID: &str = "RGC-611";
pub const TAIL_LATENCY_CONTROL_PLANE_COMPONENT: &str = "tail_latency_control_plane";
pub const TAIL_LATENCY_CONTROL_PLANE_TRACE_IDS_SCHEMA_VERSION: &str =
    "franken-engine.tail-latency-control-plane.trace-ids.v1";
pub const TAIL_LATENCY_CONTROL_PLANE_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.tail-latency-control-plane.run-manifest.v1";
pub const TAIL_LATENCY_CONTROL_PLANE_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.tail-latency-control-plane.events.v1";
pub const TAIL_LATENCY_CONTROL_PLANE_REPORT_FILE: &str = "latency_control_plane_report.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StressProfile {
    Balanced,
    SyntheticContention,
}

impl StressProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Balanced => "balanced",
            Self::SyntheticContention => "synthetic-contention",
        }
    }
}

impl fmt::Display for StressProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for StressProfile {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "balanced" => Ok(Self::Balanced),
            "synthetic-contention" | "synthetic_contention" => Ok(Self::SyntheticContention),
            other => Err(format!(
                "unsupported stress profile `{other}`; expected `balanced` or `synthetic-contention`"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageQueueCalibration {
    pub stage: ExecutionStage,
    pub target_percentile: LatencyPercentile,
    pub target_latency_ns: u64,
    pub arrival_rate_millionths: u64,
    pub mean_service_ns: u64,
    pub sizing: WorkerPoolSizing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndToEndLatencyBounds {
    pub composition_model: String,
    pub stage_count: u64,
    pub budget_p50_ns: u64,
    pub budget_p95_ns: u64,
    pub budget_p99_ns: u64,
    pub budget_p999_ns: u64,
    pub observed_p50_ns: u64,
    pub observed_p95_ns: u64,
    pub observed_p99_ns: u64,
    pub observed_p999_ns: u64,
    pub queue_adjusted_p99_ns: u64,
    pub queue_adjusted_p999_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyDecomposition {
    pub queue_p99_ns: u64,
    pub queue_p999_ns: u64,
    pub service_p99_ns: u64,
    pub service_p999_ns: u64,
    pub synchronization_p99_ns: u64,
    pub synchronization_p999_ns: u64,
    pub gc_p99_ns: u64,
    pub gc_p999_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardrailState {
    Nominal,
    NearLimit,
    FallbackEngaged,
}

impl fmt::Display for GuardrailState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Nominal => "nominal",
            Self::NearLimit => "near_limit",
            Self::FallbackEngaged => "fallback_engaged",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeGuardrailStatus {
    pub state: GuardrailState,
    pub fallback_activated: bool,
    pub reason_codes: Vec<String>,
    pub controller_modes_after_guardrail: BTreeMap<String, ControllerMode>,
    pub shed_count: u64,
    pub violated_stage_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyControlPlaneReport {
    pub schema_version: String,
    pub bead_id: String,
    pub policy_id: String,
    pub component: String,
    pub profile: StressProfile,
    pub bundle_epoch: u64,
    pub envelope_bundle: EnvelopeBundle,
    pub violation_reports: Vec<ViolationReport>,
    pub stage_calibrations: Vec<StageQueueCalibration>,
    pub admission_manifest: AdmissionControlManifest,
    pub admission_receipts: Vec<AdmissionReceipt>,
    pub feedback_manifest: FeedbackEvidenceManifest,
    pub feedback_health: CoordinatorHealthSummary,
    pub controller_decisions: Vec<ControllerDecision>,
    pub end_to_end_bounds: EndToEndLatencyBounds,
    pub decomposition: TailLatencyDecomposition,
    pub guardrails: RuntimeGuardrailStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyControlPlaneArtifactPaths {
    pub latency_control_plane_report: String,
    pub trace_ids: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
    pub step_logs_dir: String,
    pub summary_md: String,
    pub env_json: String,
    pub repro_lock: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyControlPlaneRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub report_hash: String,
    pub profile: StressProfile,
    pub guardrail_state: GuardrailState,
    pub fallback_activated: bool,
    pub stage_count: u64,
    pub violated_stage_count: u64,
    pub shed_count: u64,
    pub artifact_paths: TailLatencyControlPlaneArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyControlPlaneTraceIds {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub report_hash: String,
    pub profile: StressProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailLatencyControlPlaneEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailLatencyControlPlaneArtifacts {
    pub out_dir: PathBuf,
    pub report_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub step_logs_dir: PathBuf,
    pub summary_path: PathBuf,
    pub env_path: PathBuf,
    pub repro_lock_path: PathBuf,
    pub guardrail_state: GuardrailState,
    pub fallback_activated: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum TailLatencyControlPlaneWriteError {
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
    #[error("feedback policy validation failed: {detail}")]
    PolicyValidation { detail: String },
}

#[derive(Debug, Clone)]
struct StageScenario {
    stage: ExecutionStage,
    arrival_rate_millionths: u64,
    mean_service_ns: u64,
    observation: StageLatencyObservation,
}

#[derive(Debug, Clone)]
struct AdmissionInvocation {
    stage: ExecutionStage,
    priority: AdmissionPriority,
    count: u64,
}

#[derive(Debug, Clone)]
struct WorkloadScenario {
    profile: StressProfile,
    utilization_millionths: u64,
    stages: Vec<StageScenario>,
    admission_plan: Vec<AdmissionInvocation>,
}

pub fn default_stage_envelopes() -> Vec<StageLatencyEnvelope> {
    vec![
        StageLatencyEnvelope::default_for_stage(ExecutionStage::Parse),
        StageLatencyEnvelope::default_for_stage(ExecutionStage::Lower),
        StageLatencyEnvelope::default_for_stage(ExecutionStage::CompileOptimized),
        StageLatencyEnvelope::default_for_stage(ExecutionStage::ModuleLoad),
        StageLatencyEnvelope::default_for_stage(ExecutionStage::GcPause),
        StageLatencyEnvelope::default_for_stage(ExecutionStage::SandboxInit),
        StageLatencyEnvelope::default_for_stage(ExecutionStage::ExecutionQuantum),
    ]
}

pub fn build_tail_latency_control_plane_report(
    profile: StressProfile,
    epoch: u64,
) -> Result<TailLatencyControlPlaneReport, TailLatencyControlPlaneWriteError> {
    let scenario = workload_scenario(profile, epoch);
    let envelopes = default_stage_envelopes();
    let envelope_map: BTreeMap<ExecutionStage, StageLatencyEnvelope> = envelopes
        .iter()
        .cloned()
        .map(|envelope| (envelope.stage, envelope))
        .collect();
    let observations: Vec<StageLatencyObservation> = scenario
        .stages
        .iter()
        .map(|stage| stage.observation.clone())
        .collect();
    let envelope_bundle = build_envelope_bundle(&envelopes, &observations, epoch);
    let violation_reports = envelope_bundle
        .certificates
        .iter()
        .enumerate()
        .filter_map(|(idx, certificate)| {
            generate_violation_report(certificate, &format!("tail-latency-violation-{idx}"))
        })
        .collect::<Vec<_>>();

    let stage_calibrations = scenario
        .stages
        .iter()
        .filter_map(|stage| {
            envelope_map.get(&stage.stage).map(|envelope| {
                let sizing = compute_worker_pool_sizing(&SizingInput {
                    arrival_rate_millionths: stage.arrival_rate_millionths,
                    mean_service_ns: stage.mean_service_ns,
                    target_p99_ns: envelope.p99_budget_ns,
                    target_utilization_millionths: 800_000,
                    max_workers: 32,
                });
                StageQueueCalibration {
                    stage: stage.stage,
                    target_percentile: LatencyPercentile::P99,
                    target_latency_ns: envelope.p99_budget_ns,
                    arrival_rate_millionths: stage.arrival_rate_millionths,
                    mean_service_ns: stage.mean_service_ns,
                    sizing,
                }
            })
        })
        .collect::<Vec<_>>();

    let mut admission_controller = build_admission_controller(&scenario);
    let should_complete_immediately = matches!(profile, StressProfile::Balanced);
    let mut admission_receipts = Vec::new();
    for invocation in &scenario.admission_plan {
        for _ in 0..invocation.count {
            let receipt =
                admission_controller.check_admission(invocation.stage, invocation.priority);
            let admitted = matches!(
                receipt.decision,
                crate::queueing_admission_control::AdmissionDecision::Admit
                    | crate::queueing_admission_control::AdmissionDecision::Queue { .. }
            );
            admission_receipts.push(receipt);
            if should_complete_immediately && admitted {
                admission_controller.record_completion(invocation.stage);
            }
        }
    }

    let primary_sizing = stage_calibrations
        .iter()
        .find(|calibration| calibration.stage == ExecutionStage::ExecutionQuantum)
        .map(|calibration| calibration.sizing.clone())
        .or_else(|| {
            stage_calibrations
                .first()
                .map(|calibration| calibration.sizing.clone())
        });
    let mut admission_manifest = AdmissionControlManifest::from_controller(&admission_controller);
    if let Some(sizing) = primary_sizing {
        admission_manifest = admission_manifest.with_sizing(sizing);
    }

    let execution_envelope = envelope_map
        .get(&ExecutionStage::ExecutionQuantum)
        .expect("execution quantum envelope must exist");
    let feedback_policy = default_feedback_policy(execution_envelope);
    feedback_policy
        .validate()
        .map_err(map_policy_validation_error)?;
    let mut coordinator = FeedbackCoordinator::new(feedback_policy, SecurityEpoch::from_raw(epoch));
    let feedback_observations = feedback_observations(&scenario);
    let mut controller_decisions = coordinator.tick_all(&feedback_observations);
    let decomposition = derive_tail_latency_decomposition(&stage_calibrations, &observations);
    let mut end_to_end_bounds = compose_end_to_end_bounds(&envelopes, &observations);
    end_to_end_bounds.queue_adjusted_p99_ns = end_to_end_bounds
        .observed_p99_ns
        .saturating_add(decomposition.queue_p99_ns);
    end_to_end_bounds.queue_adjusted_p999_ns = end_to_end_bounds
        .observed_p999_ns
        .saturating_add(decomposition.queue_p999_ns);

    let guardrails = apply_runtime_guardrails(
        &mut coordinator,
        &envelope_bundle,
        &admission_manifest,
        &end_to_end_bounds,
    );
    if guardrails.fallback_activated {
        controller_decisions.extend(coordinator.tick_all(&feedback_observations));
    }

    let feedback_health = coordinator.health_summary();
    let feedback_manifest = FeedbackEvidenceManifest::from_coordinator(&coordinator);

    Ok(TailLatencyControlPlaneReport {
        schema_version: TAIL_LATENCY_CONTROL_PLANE_SCHEMA_VERSION.to_string(),
        bead_id: TAIL_LATENCY_CONTROL_PLANE_BEAD_ID.to_string(),
        policy_id: TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.to_string(),
        component: TAIL_LATENCY_CONTROL_PLANE_COMPONENT.to_string(),
        profile: scenario.profile,
        bundle_epoch: epoch,
        envelope_bundle,
        violation_reports,
        stage_calibrations,
        admission_manifest,
        admission_receipts,
        feedback_manifest,
        feedback_health,
        controller_decisions,
        end_to_end_bounds,
        decomposition,
        guardrails,
    })
}

pub fn write_tail_latency_control_plane_bundle(
    out_dir: impl AsRef<Path>,
    profile: StressProfile,
    epoch: u64,
    command_lines: &[String],
) -> Result<TailLatencyControlPlaneArtifacts, TailLatencyControlPlaneWriteError> {
    let out_dir = out_dir.as_ref().to_path_buf();
    fs::create_dir_all(&out_dir).map_err(|source| TailLatencyControlPlaneWriteError::Io {
        path: out_dir.display().to_string(),
        source,
    })?;

    let report = build_tail_latency_control_plane_report(profile, epoch)?;
    let report_path = out_dir.join(TAIL_LATENCY_CONTROL_PLANE_REPORT_FILE);
    let trace_ids_path = out_dir.join("trace_ids.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");
    let step_logs_dir = out_dir.join("step_logs");
    let summary_path = out_dir.join("summary.md");
    let env_path = out_dir.join("env.json");
    let repro_lock_path = out_dir.join("repro.lock");

    let report_bytes = canonical_json_bytes(&report, &report_path)?;
    let report_hash = sha256_hex(&report_bytes);
    let short_hash = report_hash.chars().take(16).collect::<String>();
    let trace_id = format!("trace-tail-latency-control-plane-{short_hash}");
    let decision_id = format!("decision-tail-latency-control-plane-{short_hash}");

    let trace_ids = TailLatencyControlPlaneTraceIds {
        schema_version: TAIL_LATENCY_CONTROL_PLANE_TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: TAIL_LATENCY_CONTROL_PLANE_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.to_string(),
        report_hash: report_hash.clone(),
        profile,
    };
    let trace_ids_bytes = canonical_json_bytes(&trace_ids, &trace_ids_path)?;

    let run_manifest = TailLatencyControlPlaneRunManifest {
        schema_version: TAIL_LATENCY_CONTROL_PLANE_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: TAIL_LATENCY_CONTROL_PLANE_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.to_string(),
        report_hash: report_hash.clone(),
        profile,
        guardrail_state: report.guardrails.state,
        fallback_activated: report.guardrails.fallback_activated,
        stage_count: report.envelope_bundle.stage_count as u64,
        violated_stage_count: report.envelope_bundle.violated_count as u64,
        shed_count: report.admission_manifest.summary.total_shed,
        artifact_paths: TailLatencyControlPlaneArtifactPaths {
            latency_control_plane_report: TAIL_LATENCY_CONTROL_PLANE_REPORT_FILE.to_string(),
            trace_ids: "trace_ids.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
            step_logs_dir: "step_logs".to_string(),
            summary_md: "summary.md".to_string(),
            env_json: "env.json".to_string(),
            repro_lock: "repro.lock".to_string(),
        },
    };
    let run_manifest_bytes = canonical_json_bytes(&run_manifest, &run_manifest_path)?;

    let events = build_control_plane_events(&report, &trace_id, &decision_id);
    let mut events_jsonl = String::new();
    for event in &events {
        let line = serde_json::to_string(event).map_err(|source| {
            TailLatencyControlPlaneWriteError::Json {
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

    let summary_md = render_control_plane_summary(&report, &trace_id, &decision_id);
    let env_bytes = canonical_json_bytes(
        &json!({
            "schema_version": "franken-engine.tail-latency-control-plane.env.v1",
            "component": TAIL_LATENCY_CONTROL_PLANE_COMPONENT,
            "policy_id": TAIL_LATENCY_CONTROL_PLANE_POLICY_ID,
            "profile": profile,
            "epoch": epoch,
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "toolchain": std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "unknown".to_string()),
        }),
        &env_path,
    )?;
    let repro_lock_bytes = canonical_json_bytes(
        &json!({
            "schema_version": "franken-engine.repro-lock.v1",
            "component": TAIL_LATENCY_CONTROL_PLANE_COMPONENT,
            "policy_id": TAIL_LATENCY_CONTROL_PLANE_POLICY_ID,
            "profile": profile,
            "epoch": epoch,
            "report_hash": report_hash,
            "replay_command": format!(
                "cargo run -p frankenengine-engine --bin franken_tail_latency_control_plane -- --out-dir <DIR> --profile {profile} --epoch {epoch}"
            ),
        }),
        &repro_lock_path,
    )?;
    let step_log = render_step_log(&report, &trace_id, &decision_id);

    let _bundle_lock = acquire_bundle_write_lock(&out_dir)?;
    remove_commit_marker(&run_manifest_path)?;
    write_atomic(&report_path, &report_bytes)?;
    write_atomic(&trace_ids_path, &trace_ids_bytes)?;
    write_atomic(&events_path, events_jsonl.as_bytes())?;
    write_atomic(&commands_path, commands_buf.as_bytes())?;
    fs::create_dir_all(&step_logs_dir).map_err(|source| TailLatencyControlPlaneWriteError::Io {
        path: step_logs_dir.display().to_string(),
        source,
    })?;
    write_atomic(&step_logs_dir.join("step_000.log"), step_log.as_bytes())?;
    write_atomic(&summary_path, summary_md.as_bytes())?;
    write_atomic(&env_path, &env_bytes)?;
    write_atomic(&repro_lock_path, &repro_lock_bytes)?;
    write_atomic(&run_manifest_path, &run_manifest_bytes)?;

    Ok(TailLatencyControlPlaneArtifacts {
        out_dir,
        report_path,
        trace_ids_path,
        run_manifest_path,
        events_path,
        commands_path,
        step_logs_dir,
        summary_path,
        env_path,
        repro_lock_path,
        guardrail_state: report.guardrails.state,
        fallback_activated: report.guardrails.fallback_activated,
    })
}

fn workload_scenario(profile: StressProfile, epoch: u64) -> WorkloadScenario {
    let observation = |stage: ExecutionStage,
                       p50_ns: u64,
                       p95_ns: u64,
                       p99_ns: u64,
                       p999_ns: u64,
                       observation_count: u64| StageLatencyObservation {
        stage,
        stage_label: None,
        observation_count,
        p50_ns,
        p95_ns,
        p99_ns,
        p999_ns,
        observed_epoch: epoch,
    };

    match profile {
        StressProfile::Balanced => WorkloadScenario {
            profile,
            utilization_millionths: 640_000,
            stages: vec![
                StageScenario {
                    stage: ExecutionStage::Parse,
                    arrival_rate_millionths: 240_000,
                    mean_service_ns: 1_700_000,
                    observation: observation(
                        ExecutionStage::Parse,
                        220_000,
                        1_100_000,
                        4_100_000,
                        12_000_000,
                        128,
                    ),
                },
                StageScenario {
                    stage: ExecutionStage::Lower,
                    arrival_rate_millionths: 220_000,
                    mean_service_ns: 900_000,
                    observation: observation(
                        ExecutionStage::Lower,
                        140_000,
                        600_000,
                        2_400_000,
                        8_000_000,
                        128,
                    ),
                },
                StageScenario {
                    stage: ExecutionStage::CompileOptimized,
                    arrival_rate_millionths: 160_000,
                    mean_service_ns: 5_200_000,
                    observation: observation(
                        ExecutionStage::CompileOptimized,
                        700_000,
                        3_000_000,
                        12_800_000,
                        41_000_000,
                        96,
                    ),
                },
                StageScenario {
                    stage: ExecutionStage::ModuleLoad,
                    arrival_rate_millionths: 200_000,
                    mean_service_ns: 700_000,
                    observation: observation(
                        ExecutionStage::ModuleLoad,
                        70_000,
                        310_000,
                        1_600_000,
                        6_000_000,
                        128,
                    ),
                },
                StageScenario {
                    stage: ExecutionStage::GcPause,
                    arrival_rate_millionths: 90_000,
                    mean_service_ns: 3_600_000,
                    observation: observation(
                        ExecutionStage::GcPause,
                        420_000,
                        1_600_000,
                        8_600_000,
                        25_000_000,
                        96,
                    ),
                },
                StageScenario {
                    stage: ExecutionStage::SandboxInit,
                    arrival_rate_millionths: 120_000,
                    mean_service_ns: 800_000,
                    observation: observation(
                        ExecutionStage::SandboxInit,
                        150_000,
                        700_000,
                        2_600_000,
                        9_000_000,
                        96,
                    ),
                },
                StageScenario {
                    stage: ExecutionStage::ExecutionQuantum,
                    arrival_rate_millionths: 420_000,
                    mean_service_ns: 350_000,
                    observation: observation(
                        ExecutionStage::ExecutionQuantum,
                        80_000,
                        260_000,
                        900_000,
                        4_200_000,
                        256,
                    ),
                },
            ],
            admission_plan: vec![
                AdmissionInvocation {
                    stage: ExecutionStage::Parse,
                    priority: AdmissionPriority::Normal,
                    count: 3,
                },
                AdmissionInvocation {
                    stage: ExecutionStage::ExecutionQuantum,
                    priority: AdmissionPriority::High,
                    count: 4,
                },
                AdmissionInvocation {
                    stage: ExecutionStage::ModuleLoad,
                    priority: AdmissionPriority::Normal,
                    count: 2,
                },
            ],
        },
        StressProfile::SyntheticContention => WorkloadScenario {
            profile,
            utilization_millionths: 930_000,
            stages: vec![
                StageScenario {
                    stage: ExecutionStage::Parse,
                    arrival_rate_millionths: 820_000,
                    mean_service_ns: 4_100_000,
                    observation: observation(
                        ExecutionStage::Parse,
                        520_000,
                        2_200_000,
                        5_600_000,
                        16_000_000,
                        160,
                    ),
                },
                StageScenario {
                    stage: ExecutionStage::Lower,
                    arrival_rate_millionths: 760_000,
                    mean_service_ns: 1_100_000,
                    observation: observation(
                        ExecutionStage::Lower,
                        210_000,
                        1_100_000,
                        3_400_000,
                        10_800_000,
                        160,
                    ),
                },
                StageScenario {
                    stage: ExecutionStage::CompileOptimized,
                    arrival_rate_millionths: 540_000,
                    mean_service_ns: 6_800_000,
                    observation: observation(
                        ExecutionStage::CompileOptimized,
                        1_200_000,
                        5_400_000,
                        16_100_000,
                        52_000_000,
                        128,
                    ),
                },
                StageScenario {
                    stage: ExecutionStage::ModuleLoad,
                    arrival_rate_millionths: 690_000,
                    mean_service_ns: 1_200_000,
                    observation: observation(
                        ExecutionStage::ModuleLoad,
                        120_000,
                        700_000,
                        2_300_000,
                        8_400_000,
                        160,
                    ),
                },
                StageScenario {
                    stage: ExecutionStage::GcPause,
                    arrival_rate_millionths: 180_000,
                    mean_service_ns: 5_100_000,
                    observation: observation(
                        ExecutionStage::GcPause,
                        650_000,
                        2_400_000,
                        12_200_000,
                        34_000_000,
                        128,
                    ),
                },
                StageScenario {
                    stage: ExecutionStage::SandboxInit,
                    arrival_rate_millionths: 250_000,
                    mean_service_ns: 1_500_000,
                    observation: observation(
                        ExecutionStage::SandboxInit,
                        260_000,
                        1_200_000,
                        3_500_000,
                        11_000_000,
                        128,
                    ),
                },
                StageScenario {
                    stage: ExecutionStage::ExecutionQuantum,
                    arrival_rate_millionths: 950_000,
                    mean_service_ns: 700_000,
                    observation: observation(
                        ExecutionStage::ExecutionQuantum,
                        160_000,
                        700_000,
                        1_400_000,
                        6_000_000,
                        320,
                    ),
                },
            ],
            admission_plan: vec![
                AdmissionInvocation {
                    stage: ExecutionStage::ExecutionQuantum,
                    priority: AdmissionPriority::Normal,
                    count: 3,
                },
                AdmissionInvocation {
                    stage: ExecutionStage::Parse,
                    priority: AdmissionPriority::Normal,
                    count: 3,
                },
                AdmissionInvocation {
                    stage: ExecutionStage::CompileOptimized,
                    priority: AdmissionPriority::Low,
                    count: 4,
                },
                AdmissionInvocation {
                    stage: ExecutionStage::ModuleLoad,
                    priority: AdmissionPriority::BestEffort,
                    count: 4,
                },
            ],
        },
    }
}

fn build_admission_controller(scenario: &WorkloadScenario) -> AdmissionController {
    let mut stage_max_depths = BTreeMap::new();
    for stage in &scenario.stages {
        let max_depth = match scenario.profile {
            StressProfile::Balanced => 8,
            StressProfile::SyntheticContention => 2,
        };
        stage_max_depths.insert(stage.stage, max_depth);
    }

    let policy = match scenario.profile {
        StressProfile::Balanced => AdmissionControlPolicy {
            max_queue_depth: 16,
            stage_max_depths: stage_max_depths.clone(),
            target_utilization_millionths: 750_000,
            shed_threshold_millionths: 900_000,
            emergency_threshold_millionths: 970_000,
            token_capacity: 32,
            token_refill_rate: 16,
            tokens_per_admission: 1,
            slo_percentile: LatencyPercentile::P99,
            slo_target_ns: 8_000_000,
            max_receipts: 128,
        },
        StressProfile::SyntheticContention => AdmissionControlPolicy {
            max_queue_depth: 4,
            stage_max_depths: stage_max_depths.clone(),
            target_utilization_millionths: 800_000,
            shed_threshold_millionths: 900_000,
            emergency_threshold_millionths: 950_000,
            token_capacity: 6,
            token_refill_rate: 1,
            tokens_per_admission: 1,
            slo_percentile: LatencyPercentile::P99,
            slo_target_ns: 5_000_000,
            max_receipts: 128,
        },
    };

    let mut controller = AdmissionController::new(policy);
    for (stage, max_depth) in stage_max_depths {
        controller.init_partition(stage, max_depth);
    }
    controller.update_utilization(scenario.utilization_millionths);
    controller
}

fn default_feedback_policy(execution_envelope: &StageLatencyEnvelope) -> FeedbackPolicy {
    let mut controllers = BTreeMap::new();
    controllers.insert(
        "admission_rate".to_string(),
        ControllerConfig {
            actuator: ActuatorKind::AdmissionRate,
            warmup_epochs: 0,
            ..Default::default()
        },
    );
    controllers.insert(
        "worker_concurrency".to_string(),
        ControllerConfig {
            actuator: ActuatorKind::WorkerConcurrency,
            kp_millionths: 400_000,
            ki_millionths: 50_000,
            warmup_epochs: 0,
            ..Default::default()
        },
    );

    FeedbackPolicy {
        schema_version: crate::bounded_feedback_controller::FEEDBACK_SCHEMA_VERSION.to_string(),
        policy_id: TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.to_string(),
        controllers,
        targets: vec![LatencyTarget::new(
            ExecutionStage::ExecutionQuantum,
            LatencyPercentile::P99,
            execution_envelope.p99_budget_ns,
            200_000,
            execution_envelope.p999_budget_ns,
        )],
        enabled: true,
        emergency_multiplier_millionths: 3_000_000,
    }
}

fn feedback_observations(scenario: &WorkloadScenario) -> Vec<LatencyObservation> {
    scenario
        .stages
        .iter()
        .filter(|stage| stage.stage == ExecutionStage::ExecutionQuantum)
        .map(|stage| LatencyObservation {
            stage: stage.stage,
            percentile: LatencyPercentile::P99,
            observed_ns: stage.observation.p99_ns,
            sample_count: stage.observation.observation_count,
            epoch: SecurityEpoch::from_raw(stage.observation.observed_epoch),
        })
        .collect()
}

fn derive_tail_latency_decomposition(
    stage_calibrations: &[StageQueueCalibration],
    observations: &[StageLatencyObservation],
) -> TailLatencyDecomposition {
    let queue_p99_ns = stage_calibrations
        .iter()
        .map(|calibration| calibration.sizing.estimated_p99_wait_ns)
        .sum::<u64>();
    let queue_p999_ns = stage_calibrations
        .iter()
        .map(|calibration| {
            calibration
                .sizing
                .estimated_p99_wait_ns
                .saturating_mul(3)
                .checked_div(2)
                .unwrap_or(calibration.sizing.estimated_p99_wait_ns)
        })
        .sum::<u64>();

    let mut service_p99_ns = 0u64;
    let mut service_p999_ns = 0u64;
    let mut synchronization_p99_ns = 0u64;
    let mut synchronization_p999_ns = 0u64;
    let mut gc_p99_ns = 0u64;
    let mut gc_p999_ns = 0u64;

    for observation in observations {
        match observation.stage {
            ExecutionStage::GcPause => {
                gc_p99_ns = gc_p99_ns.saturating_add(observation.p99_ns);
                gc_p999_ns = gc_p999_ns.saturating_add(observation.p999_ns);
            }
            ExecutionStage::SandboxInit => {
                synchronization_p99_ns = synchronization_p99_ns.saturating_add(observation.p99_ns);
                synchronization_p999_ns =
                    synchronization_p999_ns.saturating_add(observation.p999_ns);
            }
            _ => {
                service_p99_ns = service_p99_ns.saturating_add(observation.p99_ns);
                service_p999_ns = service_p999_ns.saturating_add(observation.p999_ns);
            }
        }
    }

    TailLatencyDecomposition {
        queue_p99_ns,
        queue_p999_ns,
        service_p99_ns,
        service_p999_ns,
        synchronization_p99_ns,
        synchronization_p999_ns,
        gc_p99_ns,
        gc_p999_ns,
    }
}

fn compose_end_to_end_bounds(
    envelopes: &[StageLatencyEnvelope],
    observations: &[StageLatencyObservation],
) -> EndToEndLatencyBounds {
    let budget_p50_ns = envelopes
        .iter()
        .map(|envelope| envelope.p50_budget_ns)
        .sum();
    let budget_p95_ns = envelopes
        .iter()
        .map(|envelope| envelope.p95_budget_ns)
        .sum();
    let budget_p99_ns = envelopes
        .iter()
        .map(|envelope| envelope.p99_budget_ns)
        .sum();
    let budget_p999_ns = envelopes
        .iter()
        .map(|envelope| envelope.p999_budget_ns)
        .sum();
    let observed_p50_ns = observations
        .iter()
        .map(|observation| observation.p50_ns)
        .sum();
    let observed_p95_ns = observations
        .iter()
        .map(|observation| observation.p95_ns)
        .sum();
    let observed_p99_ns = observations
        .iter()
        .map(|observation| observation.p99_ns)
        .sum();
    let observed_p999_ns = observations
        .iter()
        .map(|observation| observation.p999_ns)
        .sum();

    EndToEndLatencyBounds {
        composition_model: "serial_min_plus_sum".to_string(),
        stage_count: observations.len() as u64,
        budget_p50_ns,
        budget_p95_ns,
        budget_p99_ns,
        budget_p999_ns,
        observed_p50_ns,
        observed_p95_ns,
        observed_p99_ns,
        observed_p999_ns,
        queue_adjusted_p99_ns: observed_p99_ns,
        queue_adjusted_p999_ns: observed_p999_ns,
    }
}

fn apply_runtime_guardrails(
    coordinator: &mut FeedbackCoordinator,
    envelope_bundle: &EnvelopeBundle,
    admission_manifest: &AdmissionControlManifest,
    end_to_end_bounds: &EndToEndLatencyBounds,
) -> RuntimeGuardrailStatus {
    let pre_guardrail_health = coordinator.health_summary();
    let mut reason_codes = Vec::new();

    if envelope_bundle.overall_verdict == EnvelopeVerdict::Violated {
        reason_codes.push("stage_envelope_violation".to_string());
    }
    if admission_manifest.summary.total_shed > 0 {
        reason_codes.push("queue_shed".to_string());
    }
    if pre_guardrail_health.controllers_in_emergency > 0 {
        reason_codes.push("feedback_emergency".to_string());
    }
    if end_to_end_bounds.observed_p999_ns > end_to_end_bounds.budget_p999_ns {
        reason_codes.push("end_to_end_p999_budget_breach".to_string());
    }

    let fallback_activated = !reason_codes.is_empty();
    if fallback_activated {
        for controller in coordinator.controllers.values_mut() {
            controller.config.mode = ControllerMode::Fallback;
        }
    }

    let state = if fallback_activated {
        GuardrailState::FallbackEngaged
    } else if envelope_bundle.overall_verdict == EnvelopeVerdict::NearLimit
        || admission_manifest.summary.total_queued > 0
        || end_to_end_bounds.observed_p99_ns > end_to_end_bounds.budget_p99_ns
    {
        GuardrailState::NearLimit
    } else {
        GuardrailState::Nominal
    };

    let controller_modes_after_guardrail = coordinator
        .controllers
        .iter()
        .map(|(key, controller)| (key.clone(), controller.config.mode))
        .collect::<BTreeMap<_, _>>();

    RuntimeGuardrailStatus {
        state,
        fallback_activated,
        reason_codes,
        controller_modes_after_guardrail,
        shed_count: admission_manifest.summary.total_shed,
        violated_stage_count: envelope_bundle.violated_count,
    }
}

fn build_control_plane_events(
    report: &TailLatencyControlPlaneReport,
    trace_id: &str,
    decision_id: &str,
) -> Vec<TailLatencyControlPlaneEvent> {
    let mut events = vec![TailLatencyControlPlaneEvent {
        schema_version: TAIL_LATENCY_CONTROL_PLANE_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.to_string(),
        component: TAIL_LATENCY_CONTROL_PLANE_COMPONENT.to_string(),
        event: "control_plane_started".to_string(),
        outcome: "started".to_string(),
        stage: None,
        detail: Some(format!(
            "profile={} epoch={}",
            report.profile, report.bundle_epoch
        )),
    }];

    for certificate in &report.envelope_bundle.certificates {
        events.push(TailLatencyControlPlaneEvent {
            schema_version: TAIL_LATENCY_CONTROL_PLANE_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.to_string(),
            component: TAIL_LATENCY_CONTROL_PLANE_COMPONENT.to_string(),
            event: "stage_certificate_issued".to_string(),
            outcome: certificate.verdict.to_string(),
            stage: Some(certificate.stage.to_string()),
            detail: Some(format!(
                "p99={}ns p999={}ns",
                certificate.observation.p99_ns, certificate.observation.p999_ns
            )),
        });
    }

    for calibration in &report.stage_calibrations {
        events.push(TailLatencyControlPlaneEvent {
            schema_version: TAIL_LATENCY_CONTROL_PLANE_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.to_string(),
            component: TAIL_LATENCY_CONTROL_PLANE_COMPONENT.to_string(),
            event: "queue_model_calibrated".to_string(),
            outcome: "calibrated".to_string(),
            stage: Some(calibration.stage.to_string()),
            detail: Some(format!(
                "workers={} estimated_p99_wait_ns={}",
                calibration.sizing.recommended_workers, calibration.sizing.estimated_p99_wait_ns
            )),
        });
    }

    for decision in report.controller_decisions.iter().take(4) {
        events.push(TailLatencyControlPlaneEvent {
            schema_version: TAIL_LATENCY_CONTROL_PLANE_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.to_string(),
            component: TAIL_LATENCY_CONTROL_PLANE_COMPONENT.to_string(),
            event: "feedback_decision_recorded".to_string(),
            outcome: format!("{}", decision.action),
            stage: None,
            detail: Some(format!(
                "actuator={} observed_ns={} target_ns={}",
                decision.actuator, decision.observed_ns, decision.target_ns
            )),
        });
    }

    events.push(TailLatencyControlPlaneEvent {
        schema_version: TAIL_LATENCY_CONTROL_PLANE_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.to_string(),
        component: TAIL_LATENCY_CONTROL_PLANE_COMPONENT.to_string(),
        event: "guardrail_evaluated".to_string(),
        outcome: report.guardrails.state.to_string(),
        stage: None,
        detail: Some(report.guardrails.reason_codes.join(",")),
    });
    events.push(TailLatencyControlPlaneEvent {
        schema_version: TAIL_LATENCY_CONTROL_PLANE_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.to_string(),
        component: TAIL_LATENCY_CONTROL_PLANE_COMPONENT.to_string(),
        event: "control_plane_completed".to_string(),
        outcome: "completed".to_string(),
        stage: None,
        detail: Some(format!(
            "violations={} shed_count={} fallback={}",
            report.violation_reports.len(),
            report.admission_manifest.summary.total_shed,
            report.guardrails.fallback_activated
        )),
    });

    events
}

fn render_control_plane_summary(
    report: &TailLatencyControlPlaneReport,
    trace_id: &str,
    decision_id: &str,
) -> String {
    [
        "# Tail Latency Control Plane".to_string(),
        String::new(),
        format!("- profile: {}", report.profile),
        format!("- trace_id: {trace_id}"),
        format!("- decision_id: {decision_id}"),
        format!("- stage verdict: {}", report.envelope_bundle.overall_verdict),
        format!("- guardrail state: {}", report.guardrails.state),
        format!("- fallback activated: {}", report.guardrails.fallback_activated),
        format!(
            "- p99 budget/observed: {}/{} ns",
            report.end_to_end_bounds.budget_p99_ns, report.end_to_end_bounds.observed_p99_ns
        ),
        format!(
            "- p999 budget/observed: {}/{} ns",
            report.end_to_end_bounds.budget_p999_ns, report.end_to_end_bounds.observed_p999_ns
        ),
        format!(
            "- queue adjusted p999: {} ns",
            report.end_to_end_bounds.queue_adjusted_p999_ns
        ),
        String::new(),
        "## Decomposition".to_string(),
        format!(
            "- queue p99/p999: {}/{} ns",
            report.decomposition.queue_p99_ns, report.decomposition.queue_p999_ns
        ),
        format!(
            "- service p99/p999: {}/{} ns",
            report.decomposition.service_p99_ns, report.decomposition.service_p999_ns
        ),
        format!(
            "- synchronization p99/p999: {}/{} ns",
            report.decomposition.synchronization_p99_ns, report.decomposition.synchronization_p999_ns
        ),
        format!(
            "- gc p99/p999: {}/{} ns",
            report.decomposition.gc_p99_ns, report.decomposition.gc_p999_ns
        ),
        String::new(),
        "## Replay".to_string(),
        "- inspect run_manifest.json, events.jsonl, commands.txt, and latency_control_plane_report.json".to_string(),
    ]
    .join("\n")
}

fn render_step_log(
    report: &TailLatencyControlPlaneReport,
    trace_id: &str,
    decision_id: &str,
) -> String {
    let mut lines = vec![
        format!("trace_id={trace_id}"),
        format!("decision_id={decision_id}"),
        format!("profile={}", report.profile),
        format!("guardrail_state={}", report.guardrails.state),
        format!(
            "fallback_activated={}",
            report.guardrails.fallback_activated
        ),
    ];

    for certificate in &report.envelope_bundle.certificates {
        lines.push(format!(
            "stage={} verdict={} observed_p99_ns={} budget_p99_ns={}",
            certificate.stage,
            certificate.verdict,
            certificate.observation.p99_ns,
            certificate.envelope.p99_budget_ns
        ));
    }
    for calibration in &report.stage_calibrations {
        lines.push(format!(
            "queue_calibration stage={} workers={} estimated_p99_wait_ns={}",
            calibration.stage,
            calibration.sizing.recommended_workers,
            calibration.sizing.estimated_p99_wait_ns
        ));
    }

    lines.join("\n")
}

fn map_policy_validation_error(error: PolicyValidationError) -> TailLatencyControlPlaneWriteError {
    TailLatencyControlPlaneWriteError::PolicyValidation {
        detail: error.to_string(),
    }
}

fn canonical_json_bytes<T: Serialize>(
    value: &T,
    path: &Path,
) -> Result<Vec<u8>, TailLatencyControlPlaneWriteError> {
    serde_json::to_vec_pretty(value).map_err(|source| TailLatencyControlPlaneWriteError::Json {
        path: path.display().to_string(),
        source,
    })
}

fn acquire_bundle_write_lock(
    out_dir: &Path,
) -> Result<BundleWriteLock, TailLatencyControlPlaneWriteError> {
    let lock_path = out_dir.join(".tail_latency_control_plane.lock");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_) => Ok(BundleWriteLock { path: lock_path }),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => {
            Err(TailLatencyControlPlaneWriteError::Busy {
                path: lock_path.display().to_string(),
            })
        }
        Err(source) => Err(TailLatencyControlPlaneWriteError::Io {
            path: lock_path.display().to_string(),
            source,
        }),
    }
}

fn remove_commit_marker(path: &Path) -> Result<(), TailLatencyControlPlaneWriteError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TailLatencyControlPlaneWriteError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), TailLatencyControlPlaneWriteError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| TailLatencyControlPlaneWriteError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let mut digest = Sha256::new();
    digest.update(path.display().to_string().as_bytes());
    digest.update(bytes.len().to_le_bytes());
    let tmp_name = format!(".{}.tmp", hex::encode(digest.finalize()));
    let tmp_path = path.with_file_name(tmp_name);

    fs::write(&tmp_path, bytes).map_err(|source| TailLatencyControlPlaneWriteError::Io {
        path: tmp_path.display().to_string(),
        source,
    })?;
    fs::rename(&tmp_path, path).map_err(|source| TailLatencyControlPlaneWriteError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
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
    fn end_to_end_bounds_sum_stage_budgets_and_observations() {
        let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 7).unwrap();
        assert_eq!(report.end_to_end_bounds.stage_count, 7);
        assert!(report.end_to_end_bounds.budget_p99_ns > 0);
        assert!(report.end_to_end_bounds.observed_p99_ns > 0);
        assert!(report.end_to_end_bounds.budget_p999_ns > report.end_to_end_bounds.budget_p99_ns);
    }

    #[test]
    fn queue_model_calibration_is_explicit_per_stage() {
        let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 9).unwrap();
        assert_eq!(report.stage_calibrations.len(), 7);
        assert!(
            report
                .stage_calibrations
                .iter()
                .all(|calibration| calibration.sizing.recommended_workers >= 1)
        );
        assert!(
            report
                .stage_calibrations
                .iter()
                .any(|calibration| calibration.sizing.estimated_p99_wait_ns > 0)
        );
    }

    #[test]
    fn synthetic_contention_engages_fallback_guardrail() {
        let report =
            build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 42)
                .unwrap();
        assert!(report.guardrails.fallback_activated);
        assert_eq!(report.guardrails.state, GuardrailState::FallbackEngaged);
        assert!(
            report
                .guardrails
                .controller_modes_after_guardrail
                .values()
                .all(|mode| *mode == ControllerMode::Fallback)
        );
        assert!(report.controller_decisions.iter().any(|decision| matches!(
            decision.action,
            crate::bounded_feedback_controller::ControlAction::Bypassed {
                mode: ControllerMode::Fallback
            }
        )));
    }

    #[test]
    fn balanced_profile_stays_out_of_fallback() {
        let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 21).unwrap();
        assert!(!report.guardrails.fallback_activated);
        assert_ne!(report.guardrails.state, GuardrailState::FallbackEngaged);
        assert_eq!(report.admission_manifest.summary.total_shed, 0);
    }

    #[test]
    fn decomposition_keeps_queue_service_sync_and_gc_separate() {
        let report =
            build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 77)
                .unwrap();
        assert!(report.decomposition.queue_p99_ns > 0);
        assert!(report.decomposition.service_p99_ns > 0);
        assert!(report.decomposition.synchronization_p99_ns > 0);
        assert!(report.decomposition.gc_p99_ns > 0);
    }

    // --- Constant validation ---

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn constants_are_non_empty_and_well_formed() {
        assert!(!TAIL_LATENCY_CONTROL_PLANE_SCHEMA_VERSION.is_empty());
        assert!(!TAIL_LATENCY_CONTROL_PLANE_BEAD_ID.is_empty());
        assert!(!TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.is_empty());
        assert!(!TAIL_LATENCY_CONTROL_PLANE_COMPONENT.is_empty());
        assert!(!TAIL_LATENCY_CONTROL_PLANE_TRACE_IDS_SCHEMA_VERSION.is_empty());
        assert!(!TAIL_LATENCY_CONTROL_PLANE_RUN_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!TAIL_LATENCY_CONTROL_PLANE_EVENT_SCHEMA_VERSION.is_empty());
        assert!(!TAIL_LATENCY_CONTROL_PLANE_REPORT_FILE.is_empty());
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn schema_version_constants_contain_version_tag() {
        assert!(TAIL_LATENCY_CONTROL_PLANE_SCHEMA_VERSION.contains(".v1"));
        assert!(TAIL_LATENCY_CONTROL_PLANE_TRACE_IDS_SCHEMA_VERSION.contains(".v1"));
        assert!(TAIL_LATENCY_CONTROL_PLANE_RUN_MANIFEST_SCHEMA_VERSION.contains(".v1"));
        assert!(TAIL_LATENCY_CONTROL_PLANE_EVENT_SCHEMA_VERSION.contains(".v1"));
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn report_file_constant_ends_with_json() {
        assert!(TAIL_LATENCY_CONTROL_PLANE_REPORT_FILE.ends_with(".json"));
    }

    // --- StressProfile Display / as_str / FromStr ---

    #[test]
    fn stress_profile_display_balanced() {
        assert_eq!(StressProfile::Balanced.to_string(), "balanced");
    }

    #[test]
    fn stress_profile_display_synthetic_contention() {
        assert_eq!(
            StressProfile::SyntheticContention.to_string(),
            "synthetic-contention"
        );
    }

    #[test]
    fn stress_profile_as_str_matches_display() {
        for profile in [StressProfile::Balanced, StressProfile::SyntheticContention] {
            assert_eq!(profile.as_str(), profile.to_string());
        }
    }

    #[test]
    fn stress_profile_from_str_roundtrip() {
        for profile in [StressProfile::Balanced, StressProfile::SyntheticContention] {
            let parsed: StressProfile = profile.as_str().parse().unwrap();
            assert_eq!(parsed, profile);
        }
    }

    #[test]
    fn stress_profile_from_str_accepts_underscore_variant() {
        let parsed: StressProfile = "synthetic_contention".parse().unwrap();
        assert_eq!(parsed, StressProfile::SyntheticContention);
    }

    #[test]
    fn stress_profile_from_str_rejects_unknown() {
        let result = "unknown_profile".parse::<StressProfile>();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("unsupported stress profile"));
    }

    // --- GuardrailState Display ---

    #[test]
    fn guardrail_state_display_nominal() {
        assert_eq!(GuardrailState::Nominal.to_string(), "nominal");
    }

    #[test]
    fn guardrail_state_display_near_limit() {
        assert_eq!(GuardrailState::NearLimit.to_string(), "near_limit");
    }

    #[test]
    fn guardrail_state_display_fallback_engaged() {
        assert_eq!(
            GuardrailState::FallbackEngaged.to_string(),
            "fallback_engaged"
        );
    }

    // --- Serde roundtrips ---

    #[test]
    fn serde_roundtrip_stress_profile() {
        for profile in [StressProfile::Balanced, StressProfile::SyntheticContention] {
            let json = serde_json::to_string(&profile).unwrap();
            let deserialized: StressProfile = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, profile);
        }
    }

    #[test]
    fn serde_stress_profile_uses_kebab_case() {
        let json = serde_json::to_string(&StressProfile::SyntheticContention).unwrap();
        assert_eq!(json, "\"synthetic-contention\"");
        let json_balanced = serde_json::to_string(&StressProfile::Balanced).unwrap();
        assert_eq!(json_balanced, "\"balanced\"");
    }

    #[test]
    fn serde_roundtrip_guardrail_state() {
        for state in [
            GuardrailState::Nominal,
            GuardrailState::NearLimit,
            GuardrailState::FallbackEngaged,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let deserialized: GuardrailState = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, state);
        }
    }

    #[test]
    fn serde_guardrail_state_uses_snake_case() {
        let json = serde_json::to_string(&GuardrailState::NearLimit).unwrap();
        assert_eq!(json, "\"near_limit\"");
        let json_fallback = serde_json::to_string(&GuardrailState::FallbackEngaged).unwrap();
        assert_eq!(json_fallback, "\"fallback_engaged\"");
    }

    #[test]
    fn serde_roundtrip_end_to_end_latency_bounds() {
        let bounds = EndToEndLatencyBounds {
            composition_model: "serial_min_plus_sum".to_string(),
            stage_count: 4,
            budget_p50_ns: 100,
            budget_p95_ns: 200,
            budget_p99_ns: 300,
            budget_p999_ns: 400,
            observed_p50_ns: 90,
            observed_p95_ns: 180,
            observed_p99_ns: 270,
            observed_p999_ns: 360,
            queue_adjusted_p99_ns: 350,
            queue_adjusted_p999_ns: 450,
        };
        let json = serde_json::to_string(&bounds).unwrap();
        let deserialized: EndToEndLatencyBounds = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, bounds);
    }

    #[test]
    fn serde_roundtrip_tail_latency_decomposition() {
        let decomposition = TailLatencyDecomposition {
            queue_p99_ns: 1000,
            queue_p999_ns: 1500,
            service_p99_ns: 2000,
            service_p999_ns: 3000,
            synchronization_p99_ns: 500,
            synchronization_p999_ns: 750,
            gc_p99_ns: 800,
            gc_p999_ns: 1200,
        };
        let json = serde_json::to_string(&decomposition).unwrap();
        let deserialized: TailLatencyDecomposition = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, decomposition);
    }

    #[test]
    fn serde_roundtrip_runtime_guardrail_status() {
        let mut modes = BTreeMap::new();
        modes.insert("admission_rate".to_string(), ControllerMode::Active);
        modes.insert("worker_concurrency".to_string(), ControllerMode::Fallback);
        let status = RuntimeGuardrailStatus {
            state: GuardrailState::FallbackEngaged,
            fallback_activated: true,
            reason_codes: vec![
                "stage_envelope_violation".to_string(),
                "queue_shed".to_string(),
            ],
            controller_modes_after_guardrail: modes,
            shed_count: 5,
            violated_stage_count: 2,
        };
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: RuntimeGuardrailStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, status);
    }

    #[test]
    fn serde_roundtrip_artifact_paths() {
        let paths = TailLatencyControlPlaneArtifactPaths {
            latency_control_plane_report: "report.json".to_string(),
            trace_ids: "trace_ids.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
            step_logs_dir: "step_logs".to_string(),
            summary_md: "summary.md".to_string(),
            env_json: "env.json".to_string(),
            repro_lock: "repro.lock".to_string(),
        };
        let json = serde_json::to_string(&paths).unwrap();
        let deserialized: TailLatencyControlPlaneArtifactPaths =
            serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, paths);
    }

    #[test]
    fn serde_roundtrip_trace_ids() {
        let trace_ids = TailLatencyControlPlaneTraceIds {
            schema_version: TAIL_LATENCY_CONTROL_PLANE_TRACE_IDS_SCHEMA_VERSION.to_string(),
            component: TAIL_LATENCY_CONTROL_PLANE_COMPONENT.to_string(),
            trace_id: "trace-123".to_string(),
            decision_id: "decision-456".to_string(),
            policy_id: TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.to_string(),
            report_hash: "abcdef0123456789".to_string(),
            profile: StressProfile::Balanced,
        };
        let json = serde_json::to_string(&trace_ids).unwrap();
        let deserialized: TailLatencyControlPlaneTraceIds = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, trace_ids);
    }

    #[test]
    fn serde_roundtrip_event_with_optional_fields() {
        let event_full = TailLatencyControlPlaneEvent {
            schema_version: TAIL_LATENCY_CONTROL_PLANE_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: "trace-1".to_string(),
            decision_id: "decision-1".to_string(),
            policy_id: TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.to_string(),
            component: TAIL_LATENCY_CONTROL_PLANE_COMPONENT.to_string(),
            event: "stage_certificate_issued".to_string(),
            outcome: "pass".to_string(),
            stage: Some("parse".to_string()),
            detail: Some("p99=100ns".to_string()),
        };
        let json = serde_json::to_string(&event_full).unwrap();
        let deserialized: TailLatencyControlPlaneEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, event_full);
    }

    #[test]
    fn serde_event_omits_none_optional_fields() {
        let event = TailLatencyControlPlaneEvent {
            schema_version: TAIL_LATENCY_CONTROL_PLANE_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: "trace-2".to_string(),
            decision_id: "decision-2".to_string(),
            policy_id: TAIL_LATENCY_CONTROL_PLANE_POLICY_ID.to_string(),
            component: TAIL_LATENCY_CONTROL_PLANE_COMPONENT.to_string(),
            event: "control_plane_started".to_string(),
            outcome: "started".to_string(),
            stage: None,
            detail: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("stage"));
        assert!(!json.contains("detail"));
        // Roundtrip still works
        let deserialized: TailLatencyControlPlaneEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, event);
    }

    // --- default_stage_envelopes ---

    #[test]
    fn default_stage_envelopes_returns_seven_stages() {
        let envelopes = default_stage_envelopes();
        assert_eq!(envelopes.len(), 7);
    }

    #[test]
    fn default_stage_envelopes_covers_all_expected_stages() {
        let envelopes = default_stage_envelopes();
        let stages: Vec<ExecutionStage> = envelopes.iter().map(|e| e.stage).collect();
        assert!(stages.contains(&ExecutionStage::Parse));
        assert!(stages.contains(&ExecutionStage::Lower));
        assert!(stages.contains(&ExecutionStage::CompileOptimized));
        assert!(stages.contains(&ExecutionStage::ModuleLoad));
        assert!(stages.contains(&ExecutionStage::GcPause));
        assert!(stages.contains(&ExecutionStage::SandboxInit));
        assert!(stages.contains(&ExecutionStage::ExecutionQuantum));
    }

    #[test]
    fn default_stage_envelopes_have_positive_budgets() {
        let envelopes = default_stage_envelopes();
        for envelope in &envelopes {
            assert!(
                envelope.p50_budget_ns > 0,
                "stage {:?} p50 must be > 0",
                envelope.stage
            );
            assert!(
                envelope.p99_budget_ns > 0,
                "stage {:?} p99 must be > 0",
                envelope.stage
            );
            assert!(
                envelope.p999_budget_ns > 0,
                "stage {:?} p999 must be > 0",
                envelope.stage
            );
        }
    }

    // --- Report structure: balanced ---

    #[test]
    fn balanced_report_has_correct_schema_fields() {
        let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
        assert_eq!(
            report.schema_version,
            TAIL_LATENCY_CONTROL_PLANE_SCHEMA_VERSION
        );
        assert_eq!(report.bead_id, TAIL_LATENCY_CONTROL_PLANE_BEAD_ID);
        assert_eq!(report.policy_id, TAIL_LATENCY_CONTROL_PLANE_POLICY_ID);
        assert_eq!(report.component, TAIL_LATENCY_CONTROL_PLANE_COMPONENT);
        assert_eq!(report.profile, StressProfile::Balanced);
        assert_eq!(report.bundle_epoch, 1);
    }

    #[test]
    fn balanced_report_has_admission_receipts() {
        let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 3).unwrap();
        // Balanced plan: 3 + 4 + 2 = 9 admission invocations
        assert_eq!(report.admission_receipts.len(), 9);
    }

    #[test]
    fn balanced_report_has_feedback_decisions() {
        let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 5).unwrap();
        // At least one decision per controller for the tick
        assert!(!report.controller_decisions.is_empty());
    }

    // --- Report structure: synthetic contention ---

    #[test]
    fn synthetic_contention_report_has_admission_receipts() {
        let report =
            build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 10)
                .unwrap();
        // SyntheticContention plan: 3 + 3 + 4 + 4 = 14 admission invocations
        assert_eq!(report.admission_receipts.len(), 14);
    }

    #[test]
    fn synthetic_contention_has_shed_count_from_tight_policy() {
        let report =
            build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 10)
                .unwrap();
        // With tight queue depths (2) and many admissions, shedding should occur
        assert!(
            report.guardrails.shed_count > 0
                || report.admission_manifest.summary.total_shed > 0
                || report.guardrails.fallback_activated
        );
    }

    #[test]
    fn synthetic_contention_reason_codes_non_empty() {
        let report =
            build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 50)
                .unwrap();
        assert!(!report.guardrails.reason_codes.is_empty());
    }

    // --- Decomposition edge cases ---

    #[test]
    fn decomposition_p999_exceeds_p99_for_queue() {
        let report =
            build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 77)
                .unwrap();
        // queue_p999 = sum of (p99_wait * 3/2), so it should be >= queue_p99
        assert!(report.decomposition.queue_p999_ns >= report.decomposition.queue_p99_ns);
    }

    #[test]
    fn decomposition_gc_comes_only_from_gc_pause_stage() {
        let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
        // GC p99 should equal the GcPause observation p99_ns
        // From the balanced scenario: GcPause p99_ns = 8_600_000
        assert_eq!(report.decomposition.gc_p99_ns, 8_600_000);
        assert_eq!(report.decomposition.gc_p999_ns, 25_000_000);
    }

    #[test]
    fn decomposition_synchronization_comes_from_sandbox_init() {
        let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
        // From the balanced scenario: SandboxInit p99_ns = 2_600_000, p999_ns = 9_000_000
        assert_eq!(report.decomposition.synchronization_p99_ns, 2_600_000);
        assert_eq!(report.decomposition.synchronization_p999_ns, 9_000_000);
    }

    // --- End-to-end bounds ---

    #[test]
    fn end_to_end_bounds_queue_adjusted_exceeds_observed() {
        let report =
            build_tail_latency_control_plane_report(StressProfile::SyntheticContention, 42)
                .unwrap();
        assert!(
            report.end_to_end_bounds.queue_adjusted_p99_ns
                >= report.end_to_end_bounds.observed_p99_ns
        );
        assert!(
            report.end_to_end_bounds.queue_adjusted_p999_ns
                >= report.end_to_end_bounds.observed_p999_ns
        );
    }

    #[test]
    fn end_to_end_bounds_composition_model_is_serial() {
        let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
        assert_eq!(
            report.end_to_end_bounds.composition_model,
            "serial_min_plus_sum"
        );
    }

    #[test]
    fn end_to_end_bounds_budget_ordering_p50_le_p95_le_p99_le_p999() {
        let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
        let b = &report.end_to_end_bounds;
        assert!(b.budget_p50_ns <= b.budget_p95_ns);
        assert!(b.budget_p95_ns <= b.budget_p99_ns);
        assert!(b.budget_p99_ns <= b.budget_p999_ns);
    }

    // --- Serde roundtrip of full report ---

    #[test]
    fn serde_roundtrip_full_report() {
        let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
        let json = serde_json::to_string_pretty(&report).unwrap();
        let deserialized: TailLatencyControlPlaneReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.schema_version, report.schema_version);
        assert_eq!(deserialized.profile, report.profile);
        assert_eq!(deserialized.bundle_epoch, report.bundle_epoch);
        assert_eq!(deserialized.guardrails.state, report.guardrails.state);
        assert_eq!(deserialized.decomposition, report.decomposition);
        assert_eq!(deserialized.end_to_end_bounds, report.end_to_end_bounds);
    }

    // --- StageQueueCalibration serde roundtrip ---

    #[test]
    fn serde_roundtrip_stage_queue_calibration() {
        let report = build_tail_latency_control_plane_report(StressProfile::Balanced, 1).unwrap();
        let calibration = &report.stage_calibrations[0];
        let json = serde_json::to_string(calibration).unwrap();
        let deserialized: StageQueueCalibration = serde_json::from_str(&json).unwrap();
        assert_eq!(&deserialized, calibration);
    }

    // --- WriteError Display ---

    #[test]
    fn write_error_display_json_variant() {
        let err = TailLatencyControlPlaneWriteError::PolicyValidation {
            detail: "no targets defined".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("no targets defined"));
        assert!(msg.contains("feedback policy validation failed"));
    }

    #[test]
    fn write_error_display_busy_variant() {
        let err = TailLatencyControlPlaneWriteError::Busy {
            path: "/tmp/test.lock".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("/tmp/test.lock"));
        assert!(msg.contains("locked"));
    }

    // --- Determinism: same inputs produce same output ---

    #[test]
    fn report_is_deterministic_for_same_inputs() {
        let report_a =
            build_tail_latency_control_plane_report(StressProfile::Balanced, 99).unwrap();
        let report_b =
            build_tail_latency_control_plane_report(StressProfile::Balanced, 99).unwrap();
        let json_a = serde_json::to_string(&report_a).unwrap();
        let json_b = serde_json::to_string(&report_b).unwrap();
        assert_eq!(json_a, json_b);
    }

    // --- Clone / Debug impls ---

    #[test]
    fn stress_profile_clone_and_debug() {
        let profile = StressProfile::Balanced;
        let cloned = profile;
        assert_eq!(profile, cloned);
        let debug = format!("{:?}", profile);
        assert!(debug.contains("Balanced"));
    }

    #[test]
    fn guardrail_state_clone_and_debug() {
        let state = GuardrailState::NearLimit;
        let cloned = state;
        assert_eq!(state, cloned);
        let debug = format!("{:?}", state);
        assert!(debug.contains("NearLimit"));
    }
}
