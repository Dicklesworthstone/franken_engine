use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use frankenengine_engine::seqlock_candidate_inventory::{
    CandidateDisposition, CandidateInventoryEntry, default_candidate_inventory,
};
use frankenengine_engine::seqlock_fastpath::{
    FastPathFallbackReason, FastPathReadSource, FastPathTelemetry, RetryBudgetPolicy,
    SnapshotFastPath,
};

pub const BEAD_ID: &str = "bd-1lsy.7.21.3";
pub const PREDECESSOR_BEAD_ID: &str = "bd-1lsy.7.21.2";
pub const COMPONENT: &str = "seqlock_rollout_guard";
pub const SAFETY_CASE_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-safety-case.v1";
pub const STARVATION_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-seqlock-starvation-microbench.v1";
pub const LOOM_COVERAGE_SCHEMA_VERSION: &str =
    "franken-engine.rgc-seqlock-loom-schedule-coverage.v1";
pub const ROLLOUT_GUARD_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-rollout-guard.v1";
pub const TRACE_IDS_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-rollout-trace-ids.v1";
pub const RUN_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-rollout-run-manifest.v1";
pub const DOCS_CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-rollout-guard-docs.v1";

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardEvidenceVerdict {
    Pass,
    Missing,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRolloutInput {
    pub candidate_id: String,
    pub surface_name: String,
    pub module_path: String,
    pub incumbent_baseline: String,
    pub disposition: CandidateDisposition,
    pub retry_budget_policy: RetryBudgetPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarvationBurstObservation {
    pub burst_index: u32,
    pub committed_value: u64,
    pub during_write_source: FastPathReadSource,
    pub during_write_fallback_reason: Option<FastPathFallbackReason>,
    pub during_write_writer_pressure_observations: u32,
    pub post_publish_source: FastPathReadSource,
    pub post_publish_value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarvationMicrobenchRow {
    pub candidate_id: String,
    pub retry_budget_policy: RetryBudgetPolicy,
    pub burst_writes: u32,
    pub observations: Vec<StarvationBurstObservation>,
    pub telemetry: FastPathTelemetry,
    pub verdict: GuardEvidenceVerdict,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarvationMicrobenchReportArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub predecessor_bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub report_hash: String,
    pub rows: Vec<StarvationMicrobenchRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoomScheduleCoverageRow {
    pub candidate_id: String,
    pub manual_schedule_cases: Vec<String>,
    pub loom_schedule_count: u32,
    pub verdict: GuardEvidenceVerdict,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoomScheduleCoverageReportArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub predecessor_bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub report_hash: String,
    pub rows: Vec<LoomScheduleCoverageRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqlockSafetyCaseRow {
    pub candidate_id: String,
    pub surface_name: String,
    pub inventory_disposition: CandidateDisposition,
    pub starvation_verdict: GuardEvidenceVerdict,
    pub model_check_verdict: GuardEvidenceVerdict,
    pub rollout_allowed: bool,
    pub disable_reasons: Vec<String>,
    pub incumbent_baseline: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqlockSafetyCaseArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub predecessor_bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub safety_case_hash: String,
    pub rows: Vec<SeqlockSafetyCaseRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqlockRolloutGuardRow {
    pub candidate_id: String,
    pub enabled: bool,
    pub fallback_target: String,
    pub required_artifacts: Vec<String>,
    pub disable_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeqlockRolloutGuardArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub predecessor_bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub guard_hash: String,
    pub all_candidates_disabled: bool,
    pub rows: Vec<SeqlockRolloutGuardRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceIdsArtifact {
    pub schema_version: String,
    pub trace_ids: Vec<String>,
    pub decision_id: String,
    pub policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub candidate_id: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactContext {
    pub artifact_dir: PathBuf,
    pub run_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub generated_at_utc: String,
    pub source_commit: String,
    pub toolchain: String,
    pub command_invocation: String,
}

impl ArtifactContext {
    pub fn new(artifact_dir: impl Into<PathBuf>) -> Self {
        Self {
            artifact_dir: artifact_dir.into(),
            run_id: format!("run-{}-{}", COMPONENT, Utc::now().format("%Y%m%dT%H%M%SZ")),
            trace_id: "trace.rgc.621c".to_string(),
            decision_id: "decision.rgc.621c".to_string(),
            policy_id: "policy.rgc.621c".to_string(),
            generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            source_commit: "unknown".to_string(),
            toolchain: std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "nightly".to_string()),
            command_invocation: "cargo run -p frankenengine-engine --bin franken_seqlock_rollout_guard -- --artifact-dir <path>".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArtifactReference {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleWriteReport {
    pub artifact_dir: PathBuf,
    pub safety_case: SeqlockSafetyCaseArtifact,
    pub starvation_report: StarvationMicrobenchReportArtifact,
    pub loom_coverage: LoomScheduleCoverageReportArtifact,
    pub rollout_guard: SeqlockRolloutGuardArtifact,
    pub trace_ids_path: PathBuf,
    pub written_files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsContractFixture {
    pub schema_version: String,
    pub bead_id: String,
    pub default_disabled_candidates: Vec<String>,
    pub required_artifacts: Vec<String>,
}

#[derive(Debug, Clone)]
struct EvaluatedArtifacts {
    safety_case: SeqlockSafetyCaseArtifact,
    starvation_report: StarvationMicrobenchReportArtifact,
    loom_coverage: LoomScheduleCoverageReportArtifact,
    rollout_guard: SeqlockRolloutGuardArtifact,
    trace_ids: TraceIdsArtifact,
    logs: Vec<StructuredLogEvent>,
}

#[derive(Debug, Clone)]
struct FileArtifact {
    path: String,
    contents: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RunManifest {
    schema_version: String,
    bead_id: String,
    component: String,
    run_id: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    generated_at_utc: String,
    safety_case_hash: String,
    starvation_report_hash: String,
    loom_schedule_coverage_hash: String,
    rollout_guard_hash: String,
    artifact_hashes: BTreeMap<String, String>,
}

pub fn emit_default_rollout_bundle(context: &ArtifactContext) -> io::Result<BundleWriteReport> {
    let evaluated = evaluate_default_artifacts(context)?;
    write_bundle(context, &evaluated)
}

pub fn build_docs_contract_fixture() -> DocsContractFixture {
    let mut disabled_candidates = accepted_candidates("2026-03-06T00:00:00Z")
        .expect("accepted candidates must build")
        .into_iter()
        .map(|candidate| candidate.candidate_id)
        .collect::<Vec<_>>();
    disabled_candidates.sort();
    DocsContractFixture {
        schema_version: DOCS_CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        default_disabled_candidates: disabled_candidates,
        required_artifacts: required_artifact_names(),
    }
}

pub fn render_summary(
    safety_case: &SeqlockSafetyCaseArtifact,
    rollout_guard: &SeqlockRolloutGuardArtifact,
) -> String {
    let enabled = rollout_guard
        .rows
        .iter()
        .filter(|row| row.enabled)
        .map(|row| row.candidate_id.as_str())
        .collect::<Vec<_>>();
    let disabled = rollout_guard
        .rows
        .iter()
        .filter(|row| !row.enabled)
        .map(|row| row.candidate_id.as_str())
        .collect::<Vec<_>>();

    [
        "# Seqlock Rollout Guard Summary".to_string(),
        String::new(),
        format!("- bead_id: `{}`", BEAD_ID),
        format!("- component: `{}`", COMPONENT),
        format!("- generated_at_utc: `{}`", safety_case.generated_at_utc),
        format!("- safety_case_hash: `{}`", safety_case.safety_case_hash),
        format!("- guard_hash: `{}`", rollout_guard.guard_hash),
        format!(
            "- all_candidates_disabled: `{}`",
            rollout_guard.all_candidates_disabled
        ),
        String::new(),
        "## Enabled".to_string(),
        if enabled.is_empty() {
            "- none (fail-closed until model-check evidence is positive)".to_string()
        } else {
            enabled
                .iter()
                .map(|candidate| format!("- `{candidate}`"))
                .collect::<Vec<_>>()
                .join("\n")
        },
        String::new(),
        "## Disabled".to_string(),
        disabled
            .iter()
            .map(|candidate| {
                let reasons = safety_case
                    .rows
                    .iter()
                    .find(|row| row.candidate_id == *candidate)
                    .map(|row| row.disable_reasons.join(", "))
                    .unwrap_or_else(|| "unknown".to_string());
                format!("- `{candidate}`: {reasons}")
            })
            .collect::<Vec<_>>()
            .join("\n"),
    ]
    .join("\n")
}

fn evaluate_default_artifacts(context: &ArtifactContext) -> io::Result<EvaluatedArtifacts> {
    let accepted = accepted_candidates(context.generated_at_utc.clone())?;
    let starvation_rows = accepted
        .iter()
        .map(run_starvation_microbench)
        .collect::<Vec<_>>();
    let starvation_report = StarvationMicrobenchReportArtifact {
        schema_version: STARVATION_REPORT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        report_hash: digest_json(&serde_json::json!({ "rows": &starvation_rows })),
        rows: starvation_rows.clone(),
    };

    let loom_rows = accepted
        .iter()
        .map(build_missing_model_check_row)
        .collect::<Vec<_>>();
    let loom_coverage = LoomScheduleCoverageReportArtifact {
        schema_version: LOOM_COVERAGE_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        report_hash: digest_json(&serde_json::json!({ "rows": &loom_rows })),
        rows: loom_rows.clone(),
    };

    let safety_rows = accepted
        .iter()
        .map(|candidate| {
            let starvation = starvation_rows
                .iter()
                .find(|row| row.candidate_id == candidate.candidate_id)
                .expect("starvation row must exist");
            let model_check = loom_rows
                .iter()
                .find(|row| row.candidate_id == candidate.candidate_id)
                .expect("model-check row must exist");
            build_safety_case_row(candidate, starvation, model_check)
        })
        .collect::<Vec<_>>();
    let safety_case = SeqlockSafetyCaseArtifact {
        schema_version: SAFETY_CASE_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        safety_case_hash: digest_json(&serde_json::json!({ "rows": &safety_rows })),
        rows: safety_rows.clone(),
    };

    let rollout_rows = accepted
        .iter()
        .map(|candidate| {
            let safety = safety_rows
                .iter()
                .find(|row| row.candidate_id == candidate.candidate_id)
                .expect("safety row must exist");
            SeqlockRolloutGuardRow {
                candidate_id: candidate.candidate_id.clone(),
                enabled: safety.rollout_allowed,
                fallback_target: candidate.incumbent_baseline.clone(),
                required_artifacts: vec![
                    "seqlock_safety_case.json".to_string(),
                    "starvation_microbench_report.json".to_string(),
                    "loom_schedule_coverage_report.json".to_string(),
                ],
                disable_reasons: safety.disable_reasons.clone(),
            }
        })
        .collect::<Vec<_>>();
    let rollout_guard = SeqlockRolloutGuardArtifact {
        schema_version: ROLLOUT_GUARD_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        predecessor_bead_id: PREDECESSOR_BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        guard_hash: digest_json(&serde_json::json!({ "rows": &rollout_rows })),
        all_candidates_disabled: rollout_rows.iter().all(|row| !row.enabled),
        rows: rollout_rows.clone(),
    };

    let trace_ids = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec![context.trace_id.clone()],
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
    };

    let mut logs = Vec::new();
    for row in &starvation_rows {
        logs.push(StructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: "starvation_microbench_evaluated".to_string(),
            outcome: verdict_label(row.verdict).to_string(),
            error_code: None,
            candidate_id: Some(row.candidate_id.clone()),
            detail: format!(
                "burst_writes={} fallback_reads={} fast_path_reads={} writer_pressure_fallbacks={}",
                row.burst_writes,
                row.telemetry.fallback_reads,
                row.telemetry.fast_path_reads,
                row.telemetry.writer_pressure_fallbacks,
            ),
        });
    }
    for row in &loom_rows {
        logs.push(StructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: "model_check_evidence_evaluated".to_string(),
            outcome: verdict_label(row.verdict).to_string(),
            error_code: if matches!(row.verdict, GuardEvidenceVerdict::Missing) {
                Some("FE-SEQLOCK-ROLL-0001".to_string())
            } else {
                None
            },
            candidate_id: Some(row.candidate_id.clone()),
            detail: row.notes.join("; "),
        });
    }
    for row in &rollout_rows {
        logs.push(StructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: "rollout_guard_evaluated".to_string(),
            outcome: if row.enabled { "enabled" } else { "disabled" }.to_string(),
            error_code: if row.enabled {
                None
            } else {
                Some("FE-SEQLOCK-ROLL-0002".to_string())
            },
            candidate_id: Some(row.candidate_id.clone()),
            detail: row.disable_reasons.join("; "),
        });
    }
    logs.push(StructuredLogEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: "gate_completed".to_string(),
        outcome: if rollout_guard.all_candidates_disabled {
            "disabled_pending_model_check"
        } else {
            "ready"
        }
        .to_string(),
        error_code: None,
        candidate_id: None,
        detail: format!(
            "candidate_count={} all_candidates_disabled={}",
            rollout_guard.rows.len(),
            rollout_guard.all_candidates_disabled
        ),
    });
    logs.sort_by(|left, right| {
        left.event
            .cmp(&right.event)
            .then(left.candidate_id.cmp(&right.candidate_id))
    });

    Ok(EvaluatedArtifacts {
        safety_case,
        starvation_report,
        loom_coverage,
        rollout_guard,
        trace_ids,
        logs,
    })
}

fn write_bundle(
    context: &ArtifactContext,
    evaluated: &EvaluatedArtifacts,
) -> io::Result<BundleWriteReport> {
    fs::create_dir_all(&context.artifact_dir)?;

    let summary_md = render_summary(&evaluated.safety_case, &evaluated.rollout_guard);
    let artifact_dir_display = context.artifact_dir.display().to_string();
    let commands = vec![
        context.command_invocation.clone(),
        format!(
            "jq '.rows' {}/seqlock_rollout_guard.json",
            artifact_dir_display
        ),
        format!("cat {}/run_manifest.json", artifact_dir_display),
    ];

    let env_json = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": "franken-engine.env.v1",
        "captured_at_utc": &context.generated_at_utc,
        "project": {
            "name": "franken_engine",
            "repo_url": "https://github.com/Dicklesworthstone/franken_engine",
            "commit": &context.source_commit,
            "bead_id": BEAD_ID,
        },
        "host": {
            "toolchain": &context.toolchain,
            "trace_id": &context.trace_id,
        },
    }))
    .expect("env.json must serialize");

    let trace_ids_json =
        serde_json::to_string_pretty(&evaluated.trace_ids).expect("trace_ids.json must serialize");
    let events_jsonl = evaluated
        .logs
        .iter()
        .map(|event| serde_json::to_string(event).expect("event log must serialize"))
        .collect::<Vec<_>>()
        .join("\n");

    let mut artifact_hashes = BTreeMap::new();
    let mut primary_files = vec![
        FileArtifact::json("seqlock_safety_case.json", &evaluated.safety_case),
        FileArtifact::json(
            "starvation_microbench_report.json",
            &evaluated.starvation_report,
        ),
        FileArtifact::json(
            "loom_schedule_coverage_report.json",
            &evaluated.loom_coverage,
        ),
        FileArtifact::json("seqlock_rollout_guard.json", &evaluated.rollout_guard),
        FileArtifact::text("summary.md", &summary_md),
        FileArtifact::text("commands.txt", &commands.join("\n")),
        FileArtifact::text("env.json", &env_json),
        FileArtifact::text("trace_ids.json", &trace_ids_json),
        FileArtifact::text("events.jsonl", &events_jsonl),
    ];
    for artifact in &primary_files {
        artifact_hashes.insert(
            artifact.path.clone(),
            format!("sha256:{}", sha256_hex(&artifact.contents)),
        );
    }

    let repro_lock_json = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": "franken-engine.repro-lock.v1",
        "bead_id": BEAD_ID,
        "commands": &commands,
    }))
    .expect("repro.lock must serialize");
    let repro_lock_artifact = FileArtifact::text("repro.lock", &repro_lock_json);
    artifact_hashes.insert(
        repro_lock_artifact.path.clone(),
        format!("sha256:{}", sha256_hex(&repro_lock_artifact.contents)),
    );
    primary_files.push(repro_lock_artifact);

    let run_manifest = RunManifest {
        schema_version: RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        run_id: context.run_id.clone(),
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        generated_at_utc: context.generated_at_utc.clone(),
        safety_case_hash: evaluated.safety_case.safety_case_hash.clone(),
        starvation_report_hash: evaluated.starvation_report.report_hash.clone(),
        loom_schedule_coverage_hash: evaluated.loom_coverage.report_hash.clone(),
        rollout_guard_hash: evaluated.rollout_guard.guard_hash.clone(),
        artifact_hashes: artifact_hashes.clone(),
    };
    let run_manifest_artifact = FileArtifact::json("run_manifest.json", &run_manifest);
    artifact_hashes.insert(
        run_manifest_artifact.path.clone(),
        format!("sha256:{}", sha256_hex(&run_manifest_artifact.contents)),
    );
    primary_files.push(run_manifest_artifact);

    let manifest_artifacts = artifact_hashes
        .iter()
        .map(|(path, sha256)| ManifestArtifactReference {
            path: path.clone(),
            sha256: sha256.clone(),
        })
        .collect::<Vec<_>>();
    let manifest_json = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": "franken-engine.manifest.v1",
        "bead_id": BEAD_ID,
        "component": COMPONENT,
        "generated_at_utc": &context.generated_at_utc,
        "claim": {
            "statement": "Gate seqlock rollout on safety-case, starvation, and model-check evidence with fail-closed disablement.",
            "status": if evaluated.rollout_guard.all_candidates_disabled { "fail_closed" } else { "guarded_enablement" },
            "bundle_root": &artifact_dir_display,
        },
        "source_revision": {
            "repo": "franken_engine",
            "branch": "main",
            "commit": &context.source_commit,
        },
        "provenance": {
            "trace_id": &context.trace_id,
            "decision_id": &context.decision_id,
            "policy_id": &context.policy_id,
            "replay_pointer": format!("file://{artifact_dir_display}/commands.txt"),
            "evidence_pointer": format!("file://{artifact_dir_display}/seqlock_rollout_guard.json"),
        },
        "artifacts": &manifest_artifacts,
    }))
    .expect("manifest.json must serialize");
    let manifest_artifact = FileArtifact::text("manifest.json", &manifest_json);

    let _bundle_lock = acquire_bundle_write_lock(&context.artifact_dir)?;
    remove_commit_marker(&context.artifact_dir.join(&manifest_artifact.path))?;
    let mut written_files = BTreeMap::new();
    for artifact in primary_files {
        let full_path = context.artifact_dir.join(&artifact.path);
        write_atomic(&full_path, &artifact.contents)?;
        written_files.insert(
            artifact.path,
            format!("sha256:{}", sha256_hex(&artifact.contents)),
        );
    }
    let manifest_path = context.artifact_dir.join(&manifest_artifact.path);
    write_atomic(&manifest_path, &manifest_artifact.contents)?;
    written_files.insert(
        manifest_artifact.path,
        format!("sha256:{}", sha256_hex(&manifest_artifact.contents)),
    );

    Ok(BundleWriteReport {
        artifact_dir: context.artifact_dir.clone(),
        safety_case: evaluated.safety_case.clone(),
        starvation_report: evaluated.starvation_report.clone(),
        loom_coverage: evaluated.loom_coverage.clone(),
        rollout_guard: evaluated.rollout_guard.clone(),
        trace_ids_path: context.artifact_dir.join("trace_ids.json"),
        written_files,
    })
}

fn accepted_candidates(
    generated_at_utc: impl Into<String>,
) -> io::Result<Vec<CandidateRolloutInput>> {
    let inventory = default_candidate_inventory(generated_at_utc);
    let mut rows = inventory
        .candidates
        .into_iter()
        .filter(|candidate| candidate.disposition == CandidateDisposition::Accept)
        .map(candidate_rollout_input)
        .collect::<io::Result<Vec<_>>>()?;
    rows.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    Ok(rows)
}

fn candidate_rollout_input(
    candidate: CandidateInventoryEntry,
) -> io::Result<CandidateRolloutInput> {
    Ok(CandidateRolloutInput {
        candidate_id: candidate.candidate_id.clone(),
        surface_name: candidate.surface_name.clone(),
        module_path: candidate.module_path.clone(),
        incumbent_baseline: candidate.incumbent_baseline.clone(),
        disposition: candidate.disposition,
        retry_budget_policy: policy_for_candidate(&candidate.candidate_id)?,
    })
}

fn policy_for_candidate(candidate_id: &str) -> io::Result<RetryBudgetPolicy> {
    match candidate_id {
        "governance-ledger-head-view" => Ok(RetryBudgetPolicy::new(4, 1)),
        "guardplane-calibration-snapshot" => Ok(RetryBudgetPolicy::new(3, 1)),
        "module-cache-snapshot" => Ok(RetryBudgetPolicy::new(2, 2)),
        other => Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("unexpected accepted seqlock candidate `{other}`"),
        )),
    }
}

fn run_starvation_microbench(candidate: &CandidateRolloutInput) -> StarvationMicrobenchRow {
    let burst_writes = 3u32;
    let fast_path = SnapshotFastPath::new(candidate.retry_budget_policy);
    let _ = fast_path.seed_if_uninitialized(1_u64);
    let mut observations = Vec::new();
    let mut committed_value = 1_u64;

    for burst_index in 0..burst_writes {
        let next_value = committed_value + 1;
        let previous_value = committed_value;
        let during_write = RefCell::new(None);
        fast_path.publish_with_hook(next_value, || {
            let result = fast_path.read_clone_or_else(|| previous_value);
            *during_write.borrow_mut() = Some(result);
        });
        let during_write = during_write
            .into_inner()
            .expect("during-write probe must complete deterministically");
        let post_publish = fast_path.read_clone_or_else(|| 0_u64);
        observations.push(StarvationBurstObservation {
            burst_index,
            committed_value: next_value,
            during_write_source: during_write.source,
            during_write_fallback_reason: during_write.fallback_reason,
            during_write_writer_pressure_observations: during_write.writer_pressure_observations,
            post_publish_source: post_publish.source,
            post_publish_value: post_publish.value,
        });
        committed_value = next_value;
    }

    let telemetry = fast_path.telemetry();
    let verdict = if observations.iter().all(|observation| {
        observation.during_write_source == FastPathReadSource::Fallback
            && observation.during_write_fallback_reason
                == Some(FastPathFallbackReason::WriterPressure)
            && observation.post_publish_source == FastPathReadSource::FastPath
            && observation.post_publish_value == observation.committed_value
    }) && telemetry.writer_pressure_fallbacks == burst_writes as u64
        && telemetry.fast_path_reads == burst_writes as u64
        && telemetry.fallback_reads == burst_writes as u64
        && telemetry.writes == burst_writes as u64
    {
        GuardEvidenceVerdict::Pass
    } else {
        GuardEvidenceVerdict::Fail
    };

    let notes = vec![
        "Each burst performs a read inside the writer critical section and requires deterministic fallback instead of unbounded spinning.".to_string(),
        "A second read runs after publication and must observe the committed snapshot through the optimistic fast path.".to_string(),
    ];

    StarvationMicrobenchRow {
        candidate_id: candidate.candidate_id.clone(),
        retry_budget_policy: candidate.retry_budget_policy,
        burst_writes,
        observations,
        telemetry,
        verdict,
        notes,
    }
}

fn build_missing_model_check_row(candidate: &CandidateRolloutInput) -> LoomScheduleCoverageRow {
    LoomScheduleCoverageRow {
        candidate_id: candidate.candidate_id.clone(),
        manual_schedule_cases: vec![
            "writer_pressure_fallback".to_string(),
            "post_publish_visibility".to_string(),
            "seeded_cold_start_read".to_string(),
        ],
        loom_schedule_count: 0,
        verdict: GuardEvidenceVerdict::Missing,
        notes: vec![
            "Manual deterministic schedule drills exist, but no loom-backed schedule exploration is wired for this lane yet.".to_string(),
            "Rollout stays fail-closed until positive model-check evidence replaces this missing verdict.".to_string(),
        ],
    }
}

fn build_safety_case_row(
    candidate: &CandidateRolloutInput,
    starvation: &StarvationMicrobenchRow,
    model_check: &LoomScheduleCoverageRow,
) -> SeqlockSafetyCaseRow {
    let mut disable_reasons = Vec::new();
    if candidate.disposition != CandidateDisposition::Accept {
        disable_reasons.push("candidate_not_accepted_for_seqlock".to_string());
    }
    if !matches!(starvation.verdict, GuardEvidenceVerdict::Pass) {
        disable_reasons.push("starvation_microbench_failed".to_string());
    }
    if !matches!(model_check.verdict, GuardEvidenceVerdict::Pass) {
        disable_reasons.push("model_check_evidence_missing".to_string());
    }

    SeqlockSafetyCaseRow {
        candidate_id: candidate.candidate_id.clone(),
        surface_name: candidate.surface_name.clone(),
        inventory_disposition: candidate.disposition,
        starvation_verdict: starvation.verdict,
        model_check_verdict: model_check.verdict,
        rollout_allowed: disable_reasons.is_empty(),
        disable_reasons,
        incumbent_baseline: candidate.incumbent_baseline.clone(),
    }
}

fn verdict_label(verdict: GuardEvidenceVerdict) -> &'static str {
    match verdict {
        GuardEvidenceVerdict::Pass => "pass",
        GuardEvidenceVerdict::Missing => "missing",
        GuardEvidenceVerdict::Fail => "fail",
    }
}

pub fn required_artifact_names() -> Vec<String> {
    vec![
        "commands.txt".to_string(),
        "env.json".to_string(),
        "events.jsonl".to_string(),
        "loom_schedule_coverage_report.json".to_string(),
        "manifest.json".to_string(),
        "repro.lock".to_string(),
        "run_manifest.json".to_string(),
        "seqlock_rollout_guard.json".to_string(),
        "seqlock_safety_case.json".to_string(),
        "starvation_microbench_report.json".to_string(),
        "summary.md".to_string(),
        "trace_ids.json".to_string(),
    ]
}

fn acquire_bundle_write_lock(artifact_dir: &Path) -> io::Result<BundleWriteLock> {
    let lock_path = artifact_dir.join(".seqlock_rollout_guard.lock");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_) => Ok(BundleWriteLock { path: lock_path }),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => Err(io::Error::new(
            ErrorKind::AlreadyExists,
            format!("bundle already being written: {}", lock_path.display()),
        )),
        Err(source) => Err(io::Error::new(
            source.kind(),
            format!(
                "failed to acquire bundle write lock {}: {source}",
                lock_path.display()
            ),
        )),
    }
}

fn remove_commit_marker(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(source),
    }
}

fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = unique_temp_path(path);
    fs::write(&temp_path, contents)?;
    if let Err(source) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(source);
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
        .unwrap_or_else(|| Path::new("."))
        .join(temp_name)
}

#[derive(Debug)]
struct BundleWriteLock {
    path: PathBuf,
}

impl Drop for BundleWriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn digest_json(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).expect("digest input must serialize");
    sha256_hex(&bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

impl FileArtifact {
    fn json<T: Serialize>(path: &str, value: &T) -> Self {
        Self {
            path: path.to_string(),
            contents: serde_json::to_vec_pretty(value).expect("json artifact must serialize"),
        }
    }

    fn text(path: &str, value: &str) -> Self {
        Self {
            path: path.to_string(),
            contents: value.as_bytes().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactContext, DOCS_CONTRACT_SCHEMA_VERSION, FastPathFallbackReason, FastPathReadSource,
        GuardEvidenceVerdict, accepted_candidates, build_docs_contract_fixture,
        build_missing_model_check_row, build_safety_case_row, emit_default_rollout_bundle,
        render_summary, run_starvation_microbench,
    };

    use std::fs;
    use std::path::PathBuf;

    fn temp_dir(label: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        path.push(format!(
            "franken-engine-seqlock-rollout-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn starvation_microbench_trips_writer_pressure_guard_and_recovers_post_publish() {
        let candidate = accepted_candidates("2026-03-06T00:00:00Z")
            .expect("candidates should build")
            .into_iter()
            .find(|candidate| candidate.candidate_id == "module-cache-snapshot")
            .expect("module cache candidate");

        let report = run_starvation_microbench(&candidate);

        assert_eq!(report.verdict, GuardEvidenceVerdict::Pass);
        assert_eq!(report.telemetry.writer_pressure_fallbacks, 3);
        assert_eq!(report.telemetry.fast_path_reads, 3);
        assert_eq!(report.telemetry.fallback_reads, 3);
        assert!(
            report.observations.iter().all(|observation| {
                observation.during_write_source == FastPathReadSource::Fallback
                    && observation.during_write_fallback_reason
                        == Some(FastPathFallbackReason::WriterPressure)
                    && observation.post_publish_source == FastPathReadSource::FastPath
                    && observation.post_publish_value == observation.committed_value
            }),
            "every burst must fallback under writer pressure and recover on the next stable read"
        );
    }

    #[test]
    fn missing_model_check_evidence_disables_rollout_even_when_starvation_is_green() {
        let candidate = accepted_candidates("2026-03-06T00:00:00Z")
            .expect("candidates should build")
            .into_iter()
            .find(|candidate| candidate.candidate_id == "governance-ledger-head-view")
            .expect("governance candidate");

        let starvation = run_starvation_microbench(&candidate);
        let model_check = build_missing_model_check_row(&candidate);
        let safety = build_safety_case_row(&candidate, &starvation, &model_check);

        assert_eq!(starvation.verdict, GuardEvidenceVerdict::Pass);
        assert_eq!(model_check.verdict, GuardEvidenceVerdict::Missing);
        assert!(!safety.rollout_allowed);
        assert!(
            safety
                .disable_reasons
                .contains(&"model_check_evidence_missing".to_string())
        );
    }

    #[test]
    fn summary_mentions_fail_closed_state() {
        let artifact_dir = temp_dir("summary");
        let mut context = ArtifactContext::new(&artifact_dir);
        context.generated_at_utc = "2026-03-06T00:00:00Z".to_string();
        context.command_invocation = format!(
            "cargo run -p frankenengine-engine --bin franken_seqlock_rollout_guard -- --artifact-dir {}",
            artifact_dir.display()
        );

        let bundle = emit_default_rollout_bundle(&context).expect("bundle should emit");
        let summary = render_summary(&bundle.safety_case, &bundle.rollout_guard);

        assert!(summary.contains("fail-closed until model-check evidence is positive"));
        let _ = fs::remove_dir_all(&artifact_dir);
    }

    #[test]
    fn docs_contract_fixture_has_expected_schema_version() {
        let fixture = build_docs_contract_fixture();
        assert_eq!(fixture.schema_version, DOCS_CONTRACT_SCHEMA_VERSION);
        assert!(
            fixture
                .default_disabled_candidates
                .contains(&"module-cache-snapshot".to_string())
        );
    }

    // ── schema constants ────────────────────────────────────────────

    #[test]
    fn schema_constants_start_with_franken_engine() {
        assert!(super::SAFETY_CASE_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(super::STARVATION_REPORT_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(super::LOOM_COVERAGE_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(super::ROLLOUT_GUARD_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(super::TRACE_IDS_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(super::RUN_MANIFEST_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(DOCS_CONTRACT_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn bead_and_predecessor_are_distinct() {
        assert_ne!(super::BEAD_ID, super::PREDECESSOR_BEAD_ID);
        assert!(!super::BEAD_ID.is_empty());
        assert!(!super::PREDECESSOR_BEAD_ID.is_empty());
    }

    // ── enum serde round-trips ──────────────────────────────────────

    #[test]
    fn guard_evidence_verdict_serde_round_trip() {
        for v in [
            GuardEvidenceVerdict::Pass,
            GuardEvidenceVerdict::Missing,
            GuardEvidenceVerdict::Fail,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: GuardEvidenceVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // ── accepted_candidates ─────────────────────────────────────────

    #[test]
    fn accepted_candidates_returns_three() {
        let candidates = accepted_candidates("2026-03-06T00:00:00Z").unwrap();
        assert_eq!(candidates.len(), 3);
    }

    #[test]
    fn accepted_candidates_are_sorted_by_id() {
        let candidates = accepted_candidates("2026-03-06T00:00:00Z").unwrap();
        let ids: Vec<_> = candidates.iter().map(|c| c.candidate_id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn all_accepted_candidates_have_accept_disposition() {
        let candidates = accepted_candidates("2026-03-06T00:00:00Z").unwrap();
        for candidate in &candidates {
            assert_eq!(
                candidate.disposition,
                frankenengine_engine::seqlock_candidate_inventory::CandidateDisposition::Accept,
                "candidate {} should be accepted",
                candidate.candidate_id
            );
        }
    }

    // ── starvation microbench ───────────────────────────────────────

    #[test]
    fn all_candidates_pass_starvation_microbench() {
        let candidates = accepted_candidates("2026-03-06T00:00:00Z").unwrap();
        for candidate in &candidates {
            let report = run_starvation_microbench(candidate);
            assert_eq!(
                report.verdict,
                GuardEvidenceVerdict::Pass,
                "starvation failed for {}",
                candidate.candidate_id
            );
            assert_eq!(report.observations.len(), 3);
        }
    }

    #[test]
    fn starvation_microbench_fallback_reads_match_burst_writes() {
        let candidate = accepted_candidates("2026-03-06T00:00:00Z")
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let report = run_starvation_microbench(&candidate);
        assert_eq!(report.telemetry.fallback_reads, report.burst_writes as u64);
        assert_eq!(report.telemetry.fast_path_reads, report.burst_writes as u64);
    }

    // ── model check missing ─────────────────────────────────────────

    #[test]
    fn model_check_missing_for_all_candidates() {
        let candidates = accepted_candidates("2026-03-06T00:00:00Z").unwrap();
        for candidate in &candidates {
            let row = build_missing_model_check_row(candidate);
            assert_eq!(row.verdict, GuardEvidenceVerdict::Missing);
            assert_eq!(row.loom_schedule_count, 0);
            assert!(!row.manual_schedule_cases.is_empty());
        }
    }

    // ── safety case logic ───────────────────────────────────────────

    #[test]
    fn safety_case_disallows_rollout_when_model_check_missing() {
        let candidates = accepted_candidates("2026-03-06T00:00:00Z").unwrap();
        for candidate in &candidates {
            let starvation = run_starvation_microbench(candidate);
            let model_check = build_missing_model_check_row(candidate);
            let safety = build_safety_case_row(candidate, &starvation, &model_check);
            assert!(!safety.rollout_allowed);
            assert!(
                safety
                    .disable_reasons
                    .contains(&"model_check_evidence_missing".to_string())
            );
        }
    }

    // ── required_artifact_names ─────────────────────────────────────

    #[test]
    fn required_artifact_names_are_unique_and_sorted() {
        let names = super::required_artifact_names();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        let deduped: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(deduped.len(), names.len());
    }

    #[test]
    fn required_artifact_names_include_core_files() {
        let names = super::required_artifact_names();
        assert!(names.contains(&"seqlock_safety_case.json".to_string()));
        assert!(names.contains(&"seqlock_rollout_guard.json".to_string()));
        assert!(names.contains(&"starvation_microbench_report.json".to_string()));
        assert!(names.contains(&"manifest.json".to_string()));
    }

    // ── render_summary ──────────────────────────────────────────────

    #[test]
    fn render_summary_contains_header_and_sections() {
        let artifact_dir = temp_dir("summary-sections");
        let mut context = ArtifactContext::new(&artifact_dir);
        context.generated_at_utc = "2026-03-06T00:00:00Z".to_string();
        context.command_invocation = "test".to_string();
        let bundle = emit_default_rollout_bundle(&context).expect("bundle");
        let summary = render_summary(&bundle.safety_case, &bundle.rollout_guard);
        assert!(summary.contains("# Seqlock Rollout Guard Summary"));
        assert!(summary.contains("## Enabled"));
        assert!(summary.contains("## Disabled"));
        let _ = std::fs::remove_dir_all(&artifact_dir);
    }

    // ── docs fixture properties ─────────────────────────────────────

    #[test]
    fn docs_fixture_disabled_candidates_are_sorted() {
        let fixture = build_docs_contract_fixture();
        let mut sorted = fixture.default_disabled_candidates.clone();
        sorted.sort();
        assert_eq!(fixture.default_disabled_candidates, sorted);
    }

    #[test]
    fn docs_fixture_required_artifacts_are_non_empty() {
        let fixture = build_docs_contract_fixture();
        assert!(!fixture.required_artifacts.is_empty());
    }

    // ── serde round-trips ───────────────────────────────────────────

    #[test]
    fn candidate_rollout_input_serde_round_trip() {
        let input = super::CandidateRolloutInput {
            candidate_id: "test".to_string(),
            surface_name: "surface".to_string(),
            module_path: "crate::test".to_string(),
            incumbent_baseline: "rwlock".to_string(),
            disposition:
                frankenengine_engine::seqlock_candidate_inventory::CandidateDisposition::Accept,
            retry_budget_policy: frankenengine_engine::seqlock_fastpath::RetryBudgetPolicy::new(
                3, 1,
            ),
        };
        let json = serde_json::to_string(&input).unwrap();
        let back: super::CandidateRolloutInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, back);
    }

    #[test]
    fn artifact_context_defaults_are_reasonable() {
        let ctx = ArtifactContext::new("/tmp/test-rollout");
        assert!(ctx.run_id.starts_with("run-seqlock_rollout_guard-"));
        assert!(!ctx.trace_id.is_empty());
        assert!(!ctx.decision_id.is_empty());
        assert!(!ctx.policy_id.is_empty());
    }
}
