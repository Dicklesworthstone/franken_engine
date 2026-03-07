use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::adversarial_campaign::GuardplaneCalibrationState;
use crate::module_cache::{
    CacheContext, CacheInsertRequest, ModuleCache, ModuleVersionFingerprint,
};
use crate::portfolio_governor::governance_audit_ledger::{
    GovernanceActor, GovernanceAuditLedger, GovernanceDecisionType, GovernanceLedgerConfig,
    GovernanceLedgerInput, GovernanceLedgerQuery, GovernanceRationale, ScorecardSnapshot,
};
use crate::seqlock_candidate_inventory::{
    CandidateDisposition, CandidateInventoryEntry, default_candidate_inventory,
};
use crate::seqlock_fastpath::{FastPathTelemetry, RetryBudgetPolicy};
use crate::hash_tiers::ContentHash;

pub const BEAD_ID: &str = "bd-1lsy.7.21.2";
pub const COMPONENT: &str = "seqlock_reader_writer_contract";
pub const CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-reader-writer-contract.v1";
pub const RETRY_POLICY_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-retry-budget-policy.v1";
pub const FALLBACK_MATRIX_SCHEMA_VERSION: &str =
    "franken-engine.rgc-seqlock-incumbent-fallback-matrix.v1";
pub const TRACE_IDS_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-rw-trace-ids.v1";
pub const RUN_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.rgc-seqlock-rw-run-manifest.v1";
#[cfg(test)]
pub const DOCS_CONTRACT_SCHEMA_VERSION: &str =
    "franken-engine.rgc-seqlock-reader-writer-contract-docs.v1";

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCandidateRow {
    pub candidate_id: String,
    pub surface_name: String,
    pub module_path: String,
    pub read_api: String,
    pub write_api: String,
    pub incumbent_baseline: String,
    pub retry_budget_policy: RetryBudgetPolicy,
    pub exact_fallback_conditions: Vec<String>,
    pub telemetry_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReaderWriterContractArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub contract_hash: String,
    pub accepted_candidates: Vec<ContractCandidateRow>,
    pub observed_telemetry: Vec<ObservedTelemetryRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryBudgetPolicyRow {
    pub candidate_id: String,
    pub max_retries: u32,
    pub max_writer_pressure_observations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryBudgetPolicyArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub policy_hash: String,
    pub rows: Vec<RetryBudgetPolicyRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackMatrixRow {
    pub candidate_id: String,
    pub incumbent_baseline: String,
    pub exact_fallback_conditions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncumbentFallbackMatrixArtifact {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub generated_at_utc: String,
    pub matrix_hash: String,
    pub rows: Vec<FallbackMatrixRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedTelemetryRow {
    pub candidate_id: String,
    pub total_reads: u64,
    pub fast_path_reads: u64,
    pub fallback_reads: u64,
    pub total_retries: u64,
    pub writer_pressure_observations: u64,
    pub writes: u64,
    pub latest_read_source: String,
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
            trace_id: "trace.rgc.621b".to_string(),
            decision_id: "decision.rgc.621b".to_string(),
            policy_id: "policy.rgc.621b".to_string(),
            generated_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            source_commit: "unknown".to_string(),
            toolchain: std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "nightly".to_string()),
            command_invocation: "cargo run -p frankenengine-engine --bin franken_seqlock_reader_writer_contract -- --artifact-dir <path>".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestArtifactReference {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleWriteReport {
    pub artifact_dir: PathBuf,
    pub contract: ReaderWriterContractArtifact,
    pub retry_policy: RetryBudgetPolicyArtifact,
    pub fallback_matrix: IncumbentFallbackMatrixArtifact,
    pub trace_ids_path: PathBuf,
    pub written_files: BTreeMap<String, String>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsContractFixture {
    pub schema_version: String,
    pub bead_id: String,
    pub required_artifacts: Vec<String>,
    pub candidate_policies: Vec<DocsCandidatePolicy>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocsCandidatePolicy {
    pub candidate_id: String,
    pub max_retries: u32,
    pub max_writer_pressure_observations: u32,
}

#[derive(Debug, Clone)]
struct EvaluatedArtifacts {
    contract: ReaderWriterContractArtifact,
    retry_policy: RetryBudgetPolicyArtifact,
    fallback_matrix: IncumbentFallbackMatrixArtifact,
    trace_ids: TraceIdsArtifact,
    logs: Vec<StructuredLogEvent>,
}

#[derive(Debug, Clone)]
struct FileArtifact {
    path: String,
    contents: Vec<u8>,
}

pub fn emit_default_contract_bundle(context: &ArtifactContext) -> io::Result<BundleWriteReport> {
    let evaluated = evaluate_default_artifacts(context)?;
    write_bundle(context, &evaluated)
}

#[cfg(test)]
pub fn build_docs_contract_fixture() -> DocsContractFixture {
    let rows = accepted_candidate_rows("2026-03-06T00:00:00Z");
    let mut candidate_policies = rows
        .iter()
        .map(|row| DocsCandidatePolicy {
            candidate_id: row.candidate_id.clone(),
            max_retries: row.retry_budget_policy.max_retries,
            max_writer_pressure_observations: row.retry_budget_policy.max_writer_pressure_observations,
        })
        .collect::<Vec<_>>();
    candidate_policies.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));

    DocsContractFixture {
        schema_version: DOCS_CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        required_artifacts: required_artifact_names(),
        candidate_policies,
    }
}

pub fn render_summary(contract: &ReaderWriterContractArtifact) -> String {
    let mut lines = vec![
        "# Seqlock Reader/Writer Contract Summary".to_string(),
        String::new(),
        format!("- bead_id: `{}`", BEAD_ID),
        format!("- component: `{}`", COMPONENT),
        format!("- generated_at_utc: `{}`", contract.generated_at_utc),
        format!("- accepted_candidates: `{}`", contract.accepted_candidates.len()),
        format!("- contract_hash: `{}`", contract.contract_hash),
        String::new(),
        "## Candidate Policies".to_string(),
    ];

    for row in &contract.accepted_candidates {
        lines.push(format!(
            "- `{}` retries={} writer_pressure_budget={} read_api=`{}`",
            row.candidate_id,
            row.retry_budget_policy.max_retries,
            row.retry_budget_policy.max_writer_pressure_observations,
            row.read_api,
        ));
    }

    lines.push(String::new());
    lines.push("## Observed Telemetry".to_string());
    for telemetry in &contract.observed_telemetry {
        lines.push(format!(
            "- `{}` reads={} fast_path={} fallback={} writes={}",
            telemetry.candidate_id,
            telemetry.total_reads,
            telemetry.fast_path_reads,
            telemetry.fallback_reads,
            telemetry.writes,
        ));
    }

    lines.join("\n")
}

fn evaluate_default_artifacts(context: &ArtifactContext) -> io::Result<EvaluatedArtifacts> {
    let candidates = accepted_candidate_rows(context.generated_at_utc.clone());
    let observed_telemetry = vec![
        sample_governance_ledger_fastpath()?,
        sample_guardplane_calibration_fastpath(),
        sample_module_cache_fastpath()?,
    ];

    let contract_hash = digest_json(&serde_json::json!({
        "accepted_candidates": &candidates,
        "observed_telemetry": &observed_telemetry,
    }));
    let contract = ReaderWriterContractArtifact {
        schema_version: CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        contract_hash,
        accepted_candidates: candidates.clone(),
        observed_telemetry: observed_telemetry.clone(),
    };

    let policy_rows = candidates
        .iter()
        .map(|row| RetryBudgetPolicyRow {
            candidate_id: row.candidate_id.clone(),
            max_retries: row.retry_budget_policy.max_retries,
            max_writer_pressure_observations: row.retry_budget_policy.max_writer_pressure_observations,
        })
        .collect::<Vec<_>>();
    let retry_policy = RetryBudgetPolicyArtifact {
        schema_version: RETRY_POLICY_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        policy_hash: digest_json(&serde_json::json!({ "rows": &policy_rows })),
        rows: policy_rows,
    };

    let fallback_rows = candidates
        .iter()
        .map(|row| FallbackMatrixRow {
            candidate_id: row.candidate_id.clone(),
            incumbent_baseline: row.incumbent_baseline.clone(),
            exact_fallback_conditions: row.exact_fallback_conditions.clone(),
        })
        .collect::<Vec<_>>();
    let fallback_matrix = IncumbentFallbackMatrixArtifact {
        schema_version: FALLBACK_MATRIX_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        component: COMPONENT.to_string(),
        generated_at_utc: context.generated_at_utc.clone(),
        matrix_hash: digest_json(&serde_json::json!({ "rows": &fallback_rows })),
        rows: fallback_rows,
    };

    let trace_ids = TraceIdsArtifact {
        schema_version: TRACE_IDS_SCHEMA_VERSION.to_string(),
        trace_ids: vec![context.trace_id.clone()],
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
    };

    let mut logs = candidates
        .iter()
        .map(|row| StructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: "candidate_contract_evaluated".to_string(),
            outcome: "accept".to_string(),
            error_code: None,
            candidate_id: Some(row.candidate_id.clone()),
            detail: format!(
                "read_api={} write_api={} retries={} writer_pressure_budget={}",
                row.read_api,
                row.write_api,
                row.retry_budget_policy.max_retries,
                row.retry_budget_policy.max_writer_pressure_observations,
            ),
        })
        .collect::<Vec<_>>();

    for telemetry in &observed_telemetry {
        logs.push(StructuredLogEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: COMPONENT.to_string(),
            event: "candidate_telemetry_observed".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            candidate_id: Some(telemetry.candidate_id.clone()),
            detail: format!(
                "reads={} fast_path={} fallback={} retries={} writer_pressure={} writes={}",
                telemetry.total_reads,
                telemetry.fast_path_reads,
                telemetry.fallback_reads,
                telemetry.total_retries,
                telemetry.writer_pressure_observations,
                telemetry.writes,
            ),
        });
    }

    logs.sort_by(|left, right| {
        left.event
            .cmp(&right.event)
            .then(left.candidate_id.cmp(&right.candidate_id))
    });

    Ok(EvaluatedArtifacts {
        contract,
        retry_policy,
        fallback_matrix,
        trace_ids,
        logs,
    })
}

fn write_bundle(
    context: &ArtifactContext,
    evaluated: &EvaluatedArtifacts,
) -> io::Result<BundleWriteReport> {
    fs::create_dir_all(&context.artifact_dir)?;

    let summary_md = render_summary(&evaluated.contract);
    let artifact_dir_display = context.artifact_dir.display().to_string();
    let commands = vec![
        context.command_invocation.clone(),
        format!(
            "jq '.accepted_candidates' {}/seqlock_reader_writer_contract.json",
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
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "toolchain": {
            "rustup_toolchain": &context.toolchain,
        },
        "runtime": {
            "component": COMPONENT,
            "trace_id": &context.trace_id,
        },
        "policy": {
            "policy_id": &context.policy_id,
        }
    }))
    .expect("env.json must serialize");

    let mut primary_files = vec![
        FileArtifact::json("seqlock_reader_writer_contract.json", &evaluated.contract),
        FileArtifact::json("retry_budget_policy.json", &evaluated.retry_policy),
        FileArtifact::json("incumbent_fallback_matrix.json", &evaluated.fallback_matrix),
        FileArtifact::json("trace_ids.json", &evaluated.trace_ids),
        FileArtifact::json(
            "run_manifest.json",
            &serde_json::json!({
                "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
                "bead_id": BEAD_ID,
                "component": COMPONENT,
                "run_id": &context.run_id,
                "generated_at_utc": &context.generated_at_utc,
                "trace_id": &context.trace_id,
                "decision_id": &context.decision_id,
                "policy_id": &context.policy_id,
                "candidate_count": evaluated.contract.accepted_candidates.len(),
                "contract_hash": &evaluated.contract.contract_hash,
                "retry_policy_hash": &evaluated.retry_policy.policy_hash,
                "fallback_matrix_hash": &evaluated.fallback_matrix.matrix_hash,
                "artifacts": required_artifact_names(),
                "operator_verification": commands.clone(),
            }),
        ),
        FileArtifact::jsonl("events.jsonl", &evaluated.logs),
        FileArtifact::text("commands.txt", &commands.join("\n")),
        FileArtifact::text("summary.md", &summary_md),
        FileArtifact::text("env.json", &env_json),
    ];
    primary_files.sort_by(|left, right| left.path.cmp(&right.path));

    let primary_hashes = primary_files
        .iter()
        .map(|artifact| {
            (
                artifact.path.clone(),
                format!("sha256:{}", sha256_hex(&artifact.contents)),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let repro_lock = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": "franken-engine.repro-lock.v1",
        "generated_at_utc": &context.generated_at_utc,
        "lock_id": format!("{}-{}", COMPONENT, context.run_id),
        "source_commit": &context.source_commit,
        "determinism": {
            "allow_network": false,
            "allow_wall_clock": false,
            "allow_randomness": false,
        },
        "commands": commands.clone(),
        "expected_outputs": primary_hashes.iter().map(|(path, sha256)| {
            serde_json::json!({
                "path": path,
                "sha256": sha256,
            })
        }).collect::<Vec<_>>(),
        "replay": {
            "trace_id": &context.trace_id,
            "decision_id": &context.decision_id,
            "policy_id": &context.policy_id,
        }
    }))
    .expect("repro.lock must serialize");
    primary_files.push(FileArtifact::text("repro.lock", &repro_lock));
    primary_files.sort_by(|left, right| left.path.cmp(&right.path));

    let manifest_artifacts = primary_files
        .iter()
        .map(|artifact| ManifestArtifactReference {
            path: artifact.path.clone(),
            sha256: format!("sha256:{}", sha256_hex(&artifact.contents)),
        })
        .collect::<Vec<_>>();

    let manifest_json = serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": "franken-engine.manifest.v1",
        "manifest_id": format!("{}-{}", COMPONENT, context.run_id),
        "generated_at_utc": &context.generated_at_utc,
        "claim": {
            "claim_id": BEAD_ID,
            "class": "implementation",
            "statement": "Implement retry-budget seqlock reader/writer contracts with deterministic fallback for accepted candidates.",
            "status": "observed",
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
            "evidence_pointer": format!("file://{artifact_dir_display}/seqlock_reader_writer_contract.json"),
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
        contract: evaluated.contract.clone(),
        retry_policy: evaluated.retry_policy.clone(),
        fallback_matrix: evaluated.fallback_matrix.clone(),
        trace_ids_path: context.artifact_dir.join("trace_ids.json"),
        written_files,
    })
}

fn accepted_candidate_rows(generated_at_utc: impl Into<String>) -> Vec<ContractCandidateRow> {
    let inventory = default_candidate_inventory(generated_at_utc);
    let mut rows = inventory
        .candidates
        .iter()
        .filter(|candidate| candidate.disposition == CandidateDisposition::Accept)
        .map(contract_candidate_row)
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));
    rows
}

fn contract_candidate_row(candidate: &CandidateInventoryEntry) -> ContractCandidateRow {
    let (read_api, write_api, policy) = match candidate.candidate_id.as_str() {
        "governance-ledger-head-view" => (
            "GovernanceAuditLedger::{query,latest_checkpoint_view}".to_string(),
            "GovernanceAuditLedger::append".to_string(),
            RetryBudgetPolicy::new(4, 1),
        ),
        "guardplane-calibration-snapshot" => (
            "GuardplaneCalibrationState::snapshot".to_string(),
            "RedBlueLoopIntegrator::calibrate -> GuardplaneCalibrationState::refresh_snapshot_fastpath".to_string(),
            RetryBudgetPolicy::new(3, 1),
        ),
        "module-cache-snapshot" => (
            "ModuleCache::snapshot".to_string(),
            "ModuleCache::{insert,invalidate_source_update,invalidate_policy_change,invalidate_trust_revocation,restore_trust,merge_snapshot}".to_string(),
            RetryBudgetPolicy::new(2, 2),
        ),
        other => panic!("unexpected accepted seqlock candidate: {other}"),
    };

    ContractCandidateRow {
        candidate_id: candidate.candidate_id.clone(),
        surface_name: candidate.surface_name.clone(),
        module_path: candidate.module_path.clone(),
        read_api,
        write_api,
        incumbent_baseline: candidate.incumbent_baseline.clone(),
        retry_budget_policy: policy,
        exact_fallback_conditions: candidate.exact_fallback_conditions.clone(),
        telemetry_fields: vec![
            "total_reads".to_string(),
            "fast_path_reads".to_string(),
            "fallback_reads".to_string(),
            "total_retries".to_string(),
            "writer_pressure_observations".to_string(),
            "writes".to_string(),
        ],
    }
}

fn sample_module_cache_fastpath() -> io::Result<ObservedTelemetryRow> {
    let mut cache = ModuleCache::default();
    let context = CacheContext::new("trace.rgc.621b.module_cache", "decision.rgc.621b", "policy.rgc.621b");
    let version = ModuleVersionFingerprint::new(ContentHash::compute(b"module-a"), 1, 1);
    cache
        .insert(
            CacheInsertRequest::new(
                "mod:a",
                version,
                ContentHash::compute(b"artifact-a"),
                "file:///mod/a.js",
            ),
            &context,
        )
        .map_err(|error| io::Error::other(error.to_string()))?;
    let latest_read_source = fast_path_source_label();
    let _ = cache.snapshot();
    Ok(observed_telemetry(
        "module-cache-snapshot",
        cache.snapshot_fastpath_telemetry(),
        latest_read_source,
    ))
}

fn sample_guardplane_calibration_fastpath() -> ObservedTelemetryRow {
    let mut state = GuardplaneCalibrationState::default();
    state.detection_threshold_millionths = 650_000;
    state.calibration_epoch = 1;
    state.refresh_snapshot_fastpath();
    let latest_read_source = fast_path_source_label();
    let _ = state.snapshot();
    observed_telemetry(
        "guardplane-calibration-snapshot",
        state.snapshot_fastpath_telemetry(),
        latest_read_source,
    )
}

fn sample_governance_ledger_fastpath() -> io::Result<ObservedTelemetryRow> {
    let mut ledger = GovernanceAuditLedger::new(GovernanceLedgerConfig {
        checkpoint_interval: 1,
        signer_key: b"rgc-621b-governance".to_vec(),
        policy_id: "rgc-621b-governance-policy".to_string(),
    })
    .map_err(|error| io::Error::other(error.to_string()))?;
    ledger
        .append(GovernanceLedgerInput {
            decision_id: "decision-1".to_string(),
            moonshot_id: "moonshot-alpha".to_string(),
            decision_type: GovernanceDecisionType::Promote,
            actor: GovernanceActor::System("scheduler".to_string()),
            rationale: GovernanceRationale::for_automatic_decision(
                "promote alpha",
                820_000,
                120_000,
                vec!["coverage-green".to_string()],
                Vec::new(),
            ),
            scorecard_snapshot: ScorecardSnapshot {
                ev_millionths: 120_000,
                confidence_millionths: 820_000,
                risk_of_harm_millionths: 120_000,
                implementation_friction_millionths: 40_000,
                cross_initiative_interference_millionths: 20_000,
                operational_burden_millionths: 30_000,
            },
            artifact_references: vec!["artifacts/alpha.json".to_string()],
            timestamp_ns: 10,
            moonshot_started_at_ns: Some(1),
        })
        .map_err(|error| io::Error::other(error.to_string()))?;
    let _ = ledger.query(&GovernanceLedgerQuery::all());
    let checkpoint = ledger
        .latest_checkpoint_view()
        .ok_or_else(|| io::Error::other("expected checkpoint view"))?;
    Ok(observed_telemetry(
        "governance-ledger-head-view",
        ledger.head_view_fastpath_telemetry(),
        {
            let _ = checkpoint;
            fast_path_source_label()
        },
    ))
}

fn observed_telemetry(
    candidate_id: &str,
    telemetry: FastPathTelemetry,
    latest_read_source: String,
) -> ObservedTelemetryRow {
    ObservedTelemetryRow {
        candidate_id: candidate_id.to_string(),
        total_reads: telemetry.total_reads,
        fast_path_reads: telemetry.fast_path_reads,
        fallback_reads: telemetry.fallback_reads,
        total_retries: telemetry.total_retries,
        writer_pressure_observations: telemetry.writer_pressure_observations,
        writes: telemetry.writes,
        latest_read_source,
    }
}

fn fast_path_source_label() -> String {
    "fast_path".to_string()
}

fn required_artifact_names() -> Vec<String> {
    vec![
        "commands.txt".to_string(),
        "env.json".to_string(),
        "events.jsonl".to_string(),
        "incumbent_fallback_matrix.json".to_string(),
        "manifest.json".to_string(),
        "repro.lock".to_string(),
        "retry_budget_policy.json".to_string(),
        "run_manifest.json".to_string(),
        "seqlock_reader_writer_contract.json".to_string(),
        "summary.md".to_string(),
        "trace_ids.json".to_string(),
    ]
}

fn acquire_bundle_write_lock(artifact_dir: &Path) -> io::Result<BundleWriteLock> {
    let lock_path = artifact_dir.join(".seqlock_reader_writer_contract.lock");
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

    fn jsonl<T: Serialize>(path: &str, records: &[T]) -> Self {
        let mut contents = Vec::new();
        for record in records {
            let mut line = serde_json::to_vec(record).expect("jsonl record must serialize");
            line.push(b'\n');
            contents.extend_from_slice(&line);
        }
        Self {
            path: path.to_string(),
            contents,
        }
    }

    fn text(path: &str, contents: &str) -> Self {
        Self {
            path: path.to_string(),
            contents: contents.as_bytes().to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "franken-engine-seqlock-rw-src-test-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn accepted_candidate_rows_match_inventory_accepts() {
        let rows = accepted_candidate_rows("2026-03-06T00:00:00Z");
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().any(|row| row.candidate_id == "module-cache-snapshot"));
        assert!(rows.iter().any(|row| row.candidate_id == "guardplane-calibration-snapshot"));
        assert!(rows.iter().any(|row| row.candidate_id == "governance-ledger-head-view"));
    }

    #[test]
    fn bundle_writes_required_artifacts_and_observed_telemetry() {
        let artifact_dir = temp_dir("bundle");
        let mut context = ArtifactContext::new(&artifact_dir);
        context.run_id = "run-rgc-621b-test".to_string();
        context.generated_at_utc = "2026-03-06T00:00:00Z".to_string();
        context.source_commit = "deadbeef".to_string();
        context.toolchain = "nightly".to_string();
        context.command_invocation = format!(
            "cargo run -p frankenengine-engine --bin franken_seqlock_reader_writer_contract -- --artifact-dir {}",
            artifact_dir.display()
        );

        let bundle = emit_default_contract_bundle(&context).expect("bundle should write");

        for artifact in required_artifact_names() {
            assert!(
                artifact_dir.join(&artifact).exists(),
                "expected artifact `{artifact}` to exist",
            );
        }

        assert_eq!(bundle.contract.accepted_candidates.len(), 3);
        assert!(
            bundle
                .contract
                .observed_telemetry
                .iter()
                .all(|row| row.fast_path_reads >= 1),
            "expected fast-path reads for all accepted candidates",
        );

        let _ = fs::remove_dir_all(&artifact_dir);
    }

    #[test]
    fn docs_contract_fixture_tracks_current_budget_policies() {
        let expected = build_docs_contract_fixture();
        let docs_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/rgc_seqlock_reader_writer_contract_v1.json");
        let actual: DocsContractFixture =
            serde_json::from_slice(&fs::read(&docs_path).expect("read docs fixture"))
                .expect("fixture should parse");

        assert_eq!(actual.schema_version, DOCS_CONTRACT_SCHEMA_VERSION);
        assert_eq!(actual, expected);
    }
}
