//! Flamegraph pipeline and artifact storage for Section 10.6 (`bd-1nn`).
//!
//! This module provides deterministic:
//! - CPU/allocation flamegraph generation from folded-stack inputs
//! - before/after diff flamegraph generation
//! - evidence-linked artifact storage via the storage adapter boundary
//! - metadata-query retrieval for benchmark/optimization workflows
//!
//! Storage integration is anchored to `StoreKind::BenchmarkLedger`, which maps
//! to `frankensqlite::benchmark::ledger` through the `storage_adapter` contract.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::storage_adapter::{
    BatchPutEntry, EventContext, StorageAdapter, StorageError, StoreKind, StoreQuery,
};

pub const FLAMEGRAPH_COMPONENT: &str = "flamegraph_pipeline";
pub const FLAMEGRAPH_SCHEMA_VERSION: &str = "franken-engine.flamegraph-artifact.v1";
pub const FLAMEGRAPH_STORAGE_INTEGRATION_POINT: &str = "frankensqlite::benchmark::ledger";

const FLAMEGRAPH_STORE_KEY_PREFIX: &str = "flamegraph";
const MIN_SIGNIFICANT_SAMPLE_COUNT: u64 = 10;
const SVG_WIDTH: u64 = 1200;
const SVG_LEFT_MARGIN: u64 = 16;
const SVG_RIGHT_MARGIN: u64 = 240;
const SVG_TOP_MARGIN: u64 = 40;
const SVG_BAR_HEIGHT: u64 = 20;
const SVG_BAR_GAP: u64 = 6;
const SVG_ROW_LIMIT: usize = 32;

const ERROR_INVALID_REQUEST: &str = "FE-FLAME-1001";
const ERROR_INVALID_TIMESTAMP: &str = "FE-FLAME-1002";
const ERROR_INVALID_FOLDED_STACK: &str = "FE-FLAME-1003";
const ERROR_MISMATCHED_DIFF_INPUT: &str = "FE-FLAME-1004";
const ERROR_INVALID_SVG: &str = "FE-FLAME-1005";
const ERROR_SERIALIZATION: &str = "FE-FLAME-1006";
const ERROR_STORAGE: &str = "FE-FLAME-1007";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlamegraphKind {
    Cpu,
    Allocation,
    DiffCpu,
    DiffAllocation,
}

impl FlamegraphKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Allocation => "allocation",
            Self::DiffCpu => "diff_cpu",
            Self::DiffAllocation => "diff_allocation",
        }
    }

    fn is_diff(self) -> bool {
        matches!(self, Self::DiffCpu | Self::DiffAllocation)
    }
}

impl fmt::Display for FlamegraphKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldedStackSample {
    pub stack: String,
    pub sample_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlamegraphDiffEntry {
    pub stack: String,
    pub baseline_samples: u64,
    pub candidate_samples: u64,
    pub delta_samples: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlamegraphMetadata {
    pub benchmark_run_id: String,
    pub baseline_benchmark_run_id: Option<String>,
    pub workload_id: String,
    pub benchmark_profile: String,
    pub config_fingerprint: String,
    pub git_commit: String,
    pub generated_at_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlamegraphEvidenceLink {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub benchmark_run_id: String,
    pub optimization_decision_id: String,
    pub evidence_node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlamegraphArtifact {
    pub schema_version: String,
    pub artifact_id: String,
    pub kind: FlamegraphKind,
    pub metadata: FlamegraphMetadata,
    pub evidence_link: FlamegraphEvidenceLink,
    pub folded_stacks: Vec<FoldedStackSample>,
    pub folded_stacks_text: String,
    pub svg: String,
    pub total_samples: u64,
    pub diff_from_artifact_id: Option<String>,
    pub diff_entries: Vec<FlamegraphDiffEntry>,
    pub warnings: Vec<String>,
    pub storage_integration_point: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlamegraphPipelineEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub artifact_id: Option<String>,
    pub flamegraph_kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlamegraphPipelineDecision {
    pub pipeline_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub rollback_required: bool,
    pub storage_backend: String,
    pub storage_integration_point: String,
    pub artifacts: Vec<FlamegraphArtifact>,
    pub store_keys: Vec<String>,
    pub events: Vec<FlamegraphPipelineEvent>,
}

impl FlamegraphPipelineDecision {
    pub fn is_success(&self) -> bool {
        self.outcome == "pass"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlamegraphPipelineRequest {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub benchmark_run_id: String,
    pub optimization_decision_id: String,
    pub workload_id: String,
    pub benchmark_profile: String,
    pub config_fingerprint: String,
    pub git_commit: String,
    pub generated_at_utc: String,
    pub cpu_folded_stacks: String,
    pub allocation_folded_stacks: String,
    pub baseline_benchmark_run_id: Option<String>,
    pub baseline_cpu_folded_stacks: Option<String>,
    pub baseline_allocation_folded_stacks: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FlamegraphQuery {
    pub benchmark_run_id: Option<String>,
    pub workload_id: Option<String>,
    pub git_commit: Option<String>,
    pub kind: Option<FlamegraphKind>,
    pub decision_id: Option<String>,
    pub trace_id: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Error)]
pub enum FlamegraphPipelineError {
    #[error("invalid request field `{field}`: {detail}")]
    InvalidRequest { field: String, detail: String },
    #[error("invalid timestamp `{value}`: expected RFC3339 UTC")]
    InvalidTimestamp { value: String },
    #[error("invalid folded stack payload `{field}` at line {line_number}: {detail}")]
    InvalidFoldedStack {
        field: String,
        line_number: usize,
        detail: String,
    },
    #[error("folded stack payload `{field}` cannot be empty")]
    EmptyFoldedStack { field: String },
    #[error("baseline diff inputs must be provided for both cpu and allocation")]
    MismatchedDiffInput,
    #[error("generated SVG failed validation for `{kind}`")]
    InvalidSvg { kind: FlamegraphKind },
    #[error("serialization failure: {detail}")]
    SerializationFailure { detail: String },
    #[error("storage failure: {0}")]
    StorageFailure(#[from] StorageError),
}

impl FlamegraphPipelineError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest { .. } => ERROR_INVALID_REQUEST,
            Self::InvalidTimestamp { .. } => ERROR_INVALID_TIMESTAMP,
            Self::InvalidFoldedStack { .. } | Self::EmptyFoldedStack { .. } => {
                ERROR_INVALID_FOLDED_STACK
            }
            Self::MismatchedDiffInput => ERROR_MISMATCHED_DIFF_INPUT,
            Self::InvalidSvg { .. } => ERROR_INVALID_SVG,
            Self::SerializationFailure { .. } => ERROR_SERIALIZATION,
            Self::StorageFailure(_) => ERROR_STORAGE,
        }
    }

    pub fn requires_rollback(&self) -> bool {
        matches!(self, Self::StorageFailure(_))
    }
}

struct PipelineSuccess {
    artifacts: Vec<FlamegraphArtifact>,
    store_keys: Vec<String>,
}

/// Runs the flamegraph pipeline with deterministic artifact generation and
/// atomic storage semantics (via `put_batch`).
pub fn run_flamegraph_pipeline<A: StorageAdapter>(
    adapter: &mut A,
    request: &FlamegraphPipelineRequest,
) -> FlamegraphPipelineDecision {
    let pipeline_id = build_pipeline_id(request);
    let mut events = vec![make_event(
        request,
        "pipeline_started",
        "pass",
        None,
        None,
        None,
    )];

    match run_pipeline_impl(adapter, request, &mut events) {
        Ok(success) => {
            events.push(make_event(
                request,
                "pipeline_completed",
                "pass",
                None,
                None,
                None,
            ));
            FlamegraphPipelineDecision {
                pipeline_id,
                trace_id: request.trace_id.clone(),
                decision_id: request.decision_id.clone(),
                policy_id: request.policy_id.clone(),
                outcome: "pass".to_string(),
                error_code: None,
                rollback_required: false,
                storage_backend: adapter.backend_name().to_string(),
                storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.to_string(),
                artifacts: success.artifacts,
                store_keys: success.store_keys,
                events,
            }
        }
        Err(error) => {
            let error_code = error.stable_code().to_string();
            events.push(make_event(
                request,
                "pipeline_completed",
                "fail",
                Some(error_code.clone()),
                None,
                None,
            ));
            FlamegraphPipelineDecision {
                pipeline_id,
                trace_id: request.trace_id.clone(),
                decision_id: request.decision_id.clone(),
                policy_id: request.policy_id.clone(),
                outcome: "fail".to_string(),
                error_code: Some(error_code),
                rollback_required: error.requires_rollback(),
                storage_backend: adapter.backend_name().to_string(),
                storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.to_string(),
                artifacts: Vec::new(),
                store_keys: Vec::new(),
                events,
            }
        }
    }
}

/// Query stored flamegraph artifacts from benchmark-ledger storage.
pub fn query_flamegraph_artifacts<A: StorageAdapter>(
    adapter: &mut A,
    query: &FlamegraphQuery,
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
) -> Result<Vec<FlamegraphArtifact>, FlamegraphPipelineError> {
    let context = EventContext::new(trace_id, decision_id, policy_id).map_err(|error| {
        FlamegraphPipelineError::InvalidRequest {
            field: "event_context".to_string(),
            detail: error.to_string(),
        }
    })?;

    if matches!(query.limit, Some(0)) {
        return Err(FlamegraphPipelineError::InvalidRequest {
            field: "limit".to_string(),
            detail: "limit cannot be zero".to_string(),
        });
    }

    let mut metadata_filters = BTreeMap::new();
    metadata_filters.insert("record_kind".to_string(), "flamegraph_artifact".to_string());
    if let Some(workload_id) = &query.workload_id {
        metadata_filters.insert("workload_id".to_string(), workload_id.clone());
    }
    if let Some(git_commit) = &query.git_commit {
        metadata_filters.insert("git_commit".to_string(), git_commit.clone());
    }
    if let Some(kind) = query.kind {
        metadata_filters.insert("artifact_kind".to_string(), kind.as_str().to_string());
    }
    if let Some(filtered_decision_id) = &query.decision_id {
        metadata_filters.insert("decision_id".to_string(), filtered_decision_id.clone());
    }
    if let Some(filtered_trace_id) = &query.trace_id {
        metadata_filters.insert("trace_id".to_string(), filtered_trace_id.clone());
    }

    let key_prefix = if let Some(run_id) = &query.benchmark_run_id {
        format!("{FLAMEGRAPH_STORE_KEY_PREFIX}/{run_id}/")
    } else {
        format!("{FLAMEGRAPH_STORE_KEY_PREFIX}/")
    };

    let rows = adapter.query(
        StoreKind::BenchmarkLedger,
        &StoreQuery {
            key_prefix: Some(key_prefix),
            metadata_filters,
            limit: query.limit,
        },
        &context,
    )?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let artifact: FlamegraphArtifact = serde_json::from_slice(&row.value).map_err(|error| {
            FlamegraphPipelineError::SerializationFailure {
                detail: format!("failed to decode artifact from key `{}`: {error}", row.key),
            }
        })?;
        validate_flamegraph_artifact(&artifact)?;
        out.push(artifact);
    }

    out.sort_by(|lhs, rhs| lhs.artifact_id.cmp(&rhs.artifact_id));
    Ok(out)
}

/// Validates stored artifact structure and deterministic invariants.
pub fn validate_flamegraph_artifact(
    artifact: &FlamegraphArtifact,
) -> Result<(), FlamegraphPipelineError> {
    if artifact.schema_version != FLAMEGRAPH_SCHEMA_VERSION {
        return Err(FlamegraphPipelineError::InvalidRequest {
            field: "schema_version".to_string(),
            detail: format!(
                "expected `{FLAMEGRAPH_SCHEMA_VERSION}`, got `{}`",
                artifact.schema_version
            ),
        });
    }
    if artifact.artifact_id.trim().is_empty() {
        return Err(FlamegraphPipelineError::InvalidRequest {
            field: "artifact_id".to_string(),
            detail: "artifact_id cannot be empty".to_string(),
        });
    }
    if !looks_like_svg(&artifact.svg) {
        return Err(FlamegraphPipelineError::InvalidSvg {
            kind: artifact.kind,
        });
    }
    if artifact.storage_integration_point != FLAMEGRAPH_STORAGE_INTEGRATION_POINT {
        return Err(FlamegraphPipelineError::InvalidRequest {
            field: "storage_integration_point".to_string(),
            detail: format!(
                "expected `{FLAMEGRAPH_STORAGE_INTEGRATION_POINT}`, got `{}`",
                artifact.storage_integration_point
            ),
        });
    }

    let parsed = parse_folded_stacks("folded_stacks_text", &artifact.folded_stacks_text)?;
    if parsed != artifact.folded_stacks {
        return Err(FlamegraphPipelineError::InvalidRequest {
            field: "folded_stacks".to_string(),
            detail: "folded_stacks and folded_stacks_text differ".to_string(),
        });
    }

    let computed_total: u64 = artifact
        .folded_stacks
        .iter()
        .map(|sample| sample.sample_count)
        .sum();
    if computed_total != artifact.total_samples {
        return Err(FlamegraphPipelineError::InvalidRequest {
            field: "total_samples".to_string(),
            detail: format!(
                "expected total_samples={}, computed={computed_total}",
                artifact.total_samples
            ),
        });
    }

    Ok(())
}

fn run_pipeline_impl<A: StorageAdapter>(
    adapter: &mut A,
    request: &FlamegraphPipelineRequest,
    events: &mut Vec<FlamegraphPipelineEvent>,
) -> Result<PipelineSuccess, FlamegraphPipelineError> {
    let normalized_timestamp = validate_request(request)?;
    let context = EventContext::new(
        request.trace_id.clone(),
        request.decision_id.clone(),
        request.policy_id.clone(),
    )
    .map_err(|error| FlamegraphPipelineError::InvalidRequest {
        field: "event_context".to_string(),
        detail: error.to_string(),
    })?;

    let metadata = FlamegraphMetadata {
        benchmark_run_id: request.benchmark_run_id.trim().to_string(),
        baseline_benchmark_run_id: request
            .baseline_benchmark_run_id
            .as_ref()
            .map(|value| value.trim().to_string()),
        workload_id: request.workload_id.trim().to_string(),
        benchmark_profile: request.benchmark_profile.trim().to_string(),
        config_fingerprint: request.config_fingerprint.trim().to_string(),
        git_commit: request.git_commit.trim().to_string(),
        generated_at_utc: normalized_timestamp,
    };

    let evidence_link = FlamegraphEvidenceLink {
        trace_id: request.trace_id.trim().to_string(),
        decision_id: request.decision_id.trim().to_string(),
        policy_id: request.policy_id.trim().to_string(),
        benchmark_run_id: request.benchmark_run_id.trim().to_string(),
        optimization_decision_id: request.optimization_decision_id.trim().to_string(),
        evidence_node_id: build_evidence_node_id(request),
    };

    let cpu_samples = parse_folded_stacks("cpu_folded_stacks", &request.cpu_folded_stacks)?;
    events.push(make_event(
        request,
        "folded_stacks_parsed",
        "pass",
        None,
        None,
        Some(FlamegraphKind::Cpu.as_str().to_string()),
    ));

    let alloc_samples = parse_folded_stacks(
        "allocation_folded_stacks",
        &request.allocation_folded_stacks,
    )?;
    events.push(make_event(
        request,
        "folded_stacks_parsed",
        "pass",
        None,
        None,
        Some(FlamegraphKind::Allocation.as_str().to_string()),
    ));

    let mut artifacts = vec![
        build_standard_artifact(FlamegraphKind::Cpu, &metadata, &evidence_link, cpu_samples)?,
        build_standard_artifact(
            FlamegraphKind::Allocation,
            &metadata,
            &evidence_link,
            alloc_samples,
        )?,
    ];

    for artifact in &artifacts {
        events.push(make_event(
            request,
            "flamegraph_generated",
            "pass",
            None,
            Some(artifact.artifact_id.clone()),
            Some(artifact.kind.as_str().to_string()),
        ));
    }

    let has_baseline_cpu = request.baseline_cpu_folded_stacks.is_some();
    let has_baseline_alloc = request.baseline_allocation_folded_stacks.is_some();
    if has_baseline_cpu != has_baseline_alloc {
        return Err(FlamegraphPipelineError::MismatchedDiffInput);
    }

    if let (Some(baseline_cpu_raw), Some(baseline_alloc_raw)) = (
        request.baseline_cpu_folded_stacks.as_deref(),
        request.baseline_allocation_folded_stacks.as_deref(),
    ) {
        let baseline_cpu = parse_folded_stacks("baseline_cpu_folded_stacks", baseline_cpu_raw)?;
        let baseline_alloc =
            parse_folded_stacks("baseline_allocation_folded_stacks", baseline_alloc_raw)?;

        events.push(make_event(
            request,
            "folded_stacks_parsed",
            "pass",
            None,
            None,
            Some("baseline_cpu".to_string()),
        ));
        events.push(make_event(
            request,
            "folded_stacks_parsed",
            "pass",
            None,
            None,
            Some("baseline_allocation".to_string()),
        ));

        let baseline_cpu_id = build_baseline_reference_id(
            &metadata,
            &evidence_link,
            FlamegraphKind::DiffCpu,
            &baseline_cpu,
        );
        let baseline_alloc_id = build_baseline_reference_id(
            &metadata,
            &evidence_link,
            FlamegraphKind::DiffAllocation,
            &baseline_alloc,
        );

        let candidate_cpu = artifacts[0].folded_stacks.clone();
        let candidate_alloc = artifacts[1].folded_stacks.clone();

        let cpu_diff = build_diff_artifact(
            FlamegraphKind::DiffCpu,
            &metadata,
            &evidence_link,
            &baseline_cpu_id,
            baseline_cpu,
            candidate_cpu,
        )?;
        let alloc_diff = build_diff_artifact(
            FlamegraphKind::DiffAllocation,
            &metadata,
            &evidence_link,
            &baseline_alloc_id,
            baseline_alloc,
            candidate_alloc,
        )?;

        events.push(make_event(
            request,
            "flamegraph_generated",
            "pass",
            None,
            Some(cpu_diff.artifact_id.clone()),
            Some(cpu_diff.kind.as_str().to_string()),
        ));
        events.push(make_event(
            request,
            "flamegraph_generated",
            "pass",
            None,
            Some(alloc_diff.artifact_id.clone()),
            Some(alloc_diff.kind.as_str().to_string()),
        ));

        artifacts.push(cpu_diff);
        artifacts.push(alloc_diff);
    }

    artifacts.sort_by_key(|artifact| artifact.kind);

    for artifact in &artifacts {
        validate_flamegraph_artifact(artifact)?;
    }

    let mut batch_entries = Vec::with_capacity(artifacts.len());
    for artifact in &artifacts {
        let key = format!(
            "{}/{}/{}",
            FLAMEGRAPH_STORE_KEY_PREFIX, metadata.benchmark_run_id, artifact.artifact_id
        );
        let value = serde_json::to_vec(artifact).map_err(|error| {
            FlamegraphPipelineError::SerializationFailure {
                detail: error.to_string(),
            }
        })?;
        batch_entries.push(BatchPutEntry {
            key,
            value,
            metadata: artifact_metadata(artifact),
        });
    }

    let stored_records = adapter.put_batch(StoreKind::BenchmarkLedger, batch_entries, &context)?;

    let mut store_keys: Vec<String> = stored_records
        .iter()
        .map(|record| record.key.clone())
        .collect();
    store_keys.sort();
    for record in stored_records {
        events.push(make_event(
            request,
            "flamegraph_stored",
            "pass",
            None,
            Some(record.key),
            record.metadata.get("artifact_kind").cloned(),
        ));
    }

    Ok(PipelineSuccess {
        artifacts,
        store_keys,
    })
}

fn artifact_metadata(artifact: &FlamegraphArtifact) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert("record_kind".to_string(), "flamegraph_artifact".to_string());
    metadata.insert(
        "artifact_kind".to_string(),
        artifact.kind.as_str().to_string(),
    );
    metadata.insert(
        "benchmark_run_id".to_string(),
        artifact.metadata.benchmark_run_id.clone(),
    );
    metadata.insert(
        "workload_id".to_string(),
        artifact.metadata.workload_id.clone(),
    );
    metadata.insert(
        "git_commit".to_string(),
        artifact.metadata.git_commit.clone(),
    );
    metadata.insert(
        "generated_at_utc".to_string(),
        artifact.metadata.generated_at_utc.clone(),
    );
    metadata.insert(
        "decision_id".to_string(),
        artifact.evidence_link.decision_id.clone(),
    );
    metadata.insert(
        "trace_id".to_string(),
        artifact.evidence_link.trace_id.clone(),
    );
    metadata.insert(
        "policy_id".to_string(),
        artifact.evidence_link.policy_id.clone(),
    );
    metadata.insert(
        "optimization_decision_id".to_string(),
        artifact.evidence_link.optimization_decision_id.clone(),
    );
    metadata.insert(
        "storage_integration_point".to_string(),
        FLAMEGRAPH_STORAGE_INTEGRATION_POINT.to_string(),
    );
    metadata
}

fn validate_request(
    request: &FlamegraphPipelineRequest,
) -> Result<String, FlamegraphPipelineError> {
    for (field, value) in [
        ("trace_id", request.trace_id.as_str()),
        ("decision_id", request.decision_id.as_str()),
        ("policy_id", request.policy_id.as_str()),
        ("benchmark_run_id", request.benchmark_run_id.as_str()),
        (
            "optimization_decision_id",
            request.optimization_decision_id.as_str(),
        ),
        ("workload_id", request.workload_id.as_str()),
        ("benchmark_profile", request.benchmark_profile.as_str()),
        ("config_fingerprint", request.config_fingerprint.as_str()),
        ("git_commit", request.git_commit.as_str()),
        ("generated_at_utc", request.generated_at_utc.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(FlamegraphPipelineError::InvalidRequest {
                field: field.to_string(),
                detail: "value cannot be empty".to_string(),
            });
        }
    }

    if let Some(baseline_run_id) = &request.baseline_benchmark_run_id
        && baseline_run_id.trim().is_empty()
    {
        return Err(FlamegraphPipelineError::InvalidRequest {
            field: "baseline_benchmark_run_id".to_string(),
            detail: "value cannot be empty when provided".to_string(),
        });
    }

    let parsed: DateTime<Utc> = DateTime::parse_from_rfc3339(request.generated_at_utc.trim())
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| FlamegraphPipelineError::InvalidTimestamp {
            value: request.generated_at_utc.clone(),
        })?;

    Ok(parsed.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn parse_folded_stacks(
    field: &str,
    payload: &str,
) -> Result<Vec<FoldedStackSample>, FlamegraphPipelineError> {
    let mut by_stack = BTreeMap::<String, u64>::new();

    for (idx, raw_line) in payload.lines().enumerate() {
        let line_number = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 2 {
            return Err(FlamegraphPipelineError::InvalidFoldedStack {
                field: field.to_string(),
                line_number,
                detail: "expected `<frame_a;frame_b count>`".to_string(),
            });
        }

        let count_token = tokens.last().copied().unwrap_or_default();
        let stack_token = tokens[..tokens.len() - 1].join(" ");
        let sample_count = count_token.parse::<u64>().map_err(|_| {
            FlamegraphPipelineError::InvalidFoldedStack {
                field: field.to_string(),
                line_number,
                detail: format!("invalid sample count `{count_token}`"),
            }
        })?;
        if sample_count == 0 {
            return Err(FlamegraphPipelineError::InvalidFoldedStack {
                field: field.to_string(),
                line_number,
                detail: "sample count must be > 0".to_string(),
            });
        }

        let canonical_stack = normalize_stack(&stack_token).ok_or_else(|| {
            FlamegraphPipelineError::InvalidFoldedStack {
                field: field.to_string(),
                line_number,
                detail: "stack must contain non-empty frames separated by `;`".to_string(),
            }
        })?;

        let current = by_stack.entry(canonical_stack).or_insert(0);
        *current = current.checked_add(sample_count).ok_or_else(|| {
            FlamegraphPipelineError::InvalidFoldedStack {
                field: field.to_string(),
                line_number,
                detail: "sample count overflow".to_string(),
            }
        })?;
    }

    if by_stack.is_empty() {
        return Err(FlamegraphPipelineError::EmptyFoldedStack {
            field: field.to_string(),
        });
    }

    Ok(by_stack
        .into_iter()
        .map(|(stack, sample_count)| FoldedStackSample {
            stack,
            sample_count,
        })
        .collect())
}

fn normalize_stack(stack: &str) -> Option<String> {
    let frames: Vec<String> = stack
        .split(';')
        .map(str::trim)
        .filter(|frame| !frame.is_empty())
        .map(ToOwned::to_owned)
        .collect();
    if frames.is_empty() {
        return None;
    }
    Some(frames.join(";"))
}

fn build_standard_artifact(
    kind: FlamegraphKind,
    metadata: &FlamegraphMetadata,
    evidence_link: &FlamegraphEvidenceLink,
    folded_stacks: Vec<FoldedStackSample>,
) -> Result<FlamegraphArtifact, FlamegraphPipelineError> {
    let mut warnings = Vec::new();
    let total_samples: u64 = folded_stacks.iter().map(|entry| entry.sample_count).sum();
    if total_samples < MIN_SIGNIFICANT_SAMPLE_COUNT {
        warnings.push(format!(
            "low sample count ({total_samples}) may be statistically insignificant"
        ));
    }
    let folded_stacks_text = encode_folded_stacks(&folded_stacks);
    let svg = build_svg(kind, &folded_stacks, &[]);
    if !looks_like_svg(&svg) {
        return Err(FlamegraphPipelineError::InvalidSvg { kind });
    }
    let artifact_id = build_artifact_id(
        kind,
        metadata,
        evidence_link,
        &folded_stacks,
        None,
        &[],
        &warnings,
    );

    Ok(FlamegraphArtifact {
        schema_version: FLAMEGRAPH_SCHEMA_VERSION.to_string(),
        artifact_id,
        kind,
        metadata: metadata.clone(),
        evidence_link: evidence_link.clone(),
        folded_stacks,
        folded_stacks_text,
        svg,
        total_samples,
        diff_from_artifact_id: None,
        diff_entries: Vec::new(),
        warnings,
        storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.to_string(),
    })
}

fn build_diff_artifact(
    kind: FlamegraphKind,
    metadata: &FlamegraphMetadata,
    evidence_link: &FlamegraphEvidenceLink,
    diff_from_artifact_id: &str,
    baseline: Vec<FoldedStackSample>,
    candidate: Vec<FoldedStackSample>,
) -> Result<FlamegraphArtifact, FlamegraphPipelineError> {
    let mut warnings = Vec::new();
    let mut diff_entries = build_diff_entries(&baseline, &candidate)?;

    if diff_entries.is_empty() {
        warnings.push("candidate and baseline folded stacks are identical".to_string());
    }

    let folded_stacks = if diff_entries.is_empty() {
        vec![FoldedStackSample {
            stack: "no_change".to_string(),
            sample_count: 1,
        }]
    } else {
        diff_entries
            .iter()
            .map(|entry| FoldedStackSample {
                stack: entry.stack.clone(),
                sample_count: entry.delta_samples.unsigned_abs(),
            })
            .collect()
    };

    let folded_stacks_text = encode_folded_stacks(&folded_stacks);
    let total_samples: u64 = folded_stacks.iter().map(|entry| entry.sample_count).sum();
    if total_samples < MIN_SIGNIFICANT_SAMPLE_COUNT {
        warnings.push(format!(
            "low sample count ({total_samples}) may be statistically insignificant"
        ));
    }

    diff_entries.sort_by(|lhs, rhs| lhs.stack.cmp(&rhs.stack));
    let svg = build_svg(kind, &folded_stacks, &diff_entries);
    if !looks_like_svg(&svg) {
        return Err(FlamegraphPipelineError::InvalidSvg { kind });
    }

    let artifact_id = build_artifact_id(
        kind,
        metadata,
        evidence_link,
        &folded_stacks,
        Some(diff_from_artifact_id),
        &diff_entries,
        &warnings,
    );

    Ok(FlamegraphArtifact {
        schema_version: FLAMEGRAPH_SCHEMA_VERSION.to_string(),
        artifact_id,
        kind,
        metadata: metadata.clone(),
        evidence_link: evidence_link.clone(),
        folded_stacks,
        folded_stacks_text,
        svg,
        total_samples,
        diff_from_artifact_id: Some(diff_from_artifact_id.to_string()),
        diff_entries,
        warnings,
        storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.to_string(),
    })
}

fn build_diff_entries(
    baseline: &[FoldedStackSample],
    candidate: &[FoldedStackSample],
) -> Result<Vec<FlamegraphDiffEntry>, FlamegraphPipelineError> {
    let baseline_map: BTreeMap<String, u64> = baseline
        .iter()
        .map(|entry| (entry.stack.clone(), entry.sample_count))
        .collect();
    let candidate_map: BTreeMap<String, u64> = candidate
        .iter()
        .map(|entry| (entry.stack.clone(), entry.sample_count))
        .collect();

    let mut stacks: Vec<String> = baseline_map
        .keys()
        .chain(candidate_map.keys())
        .cloned()
        .collect();
    stacks.sort();
    stacks.dedup();

    let mut out = Vec::new();
    for stack in stacks {
        let baseline_samples = baseline_map.get(&stack).copied().unwrap_or(0);
        let candidate_samples = candidate_map.get(&stack).copied().unwrap_or(0);
        let delta = i128::from(candidate_samples) - i128::from(baseline_samples);
        if delta == 0 {
            continue;
        }
        if delta < i128::from(i64::MIN) || delta > i128::from(i64::MAX) {
            return Err(FlamegraphPipelineError::InvalidRequest {
                field: "diff_entries".to_string(),
                detail: "delta overflow".to_string(),
            });
        }
        out.push(FlamegraphDiffEntry {
            stack,
            baseline_samples,
            candidate_samples,
            delta_samples: delta as i64,
        });
    }

    Ok(out)
}

fn encode_folded_stacks(samples: &[FoldedStackSample]) -> String {
    let mut lines: Vec<String> = samples
        .iter()
        .map(|sample| format!("{} {}", sample.stack, sample.sample_count))
        .collect();
    lines.sort();
    format!("{}\n", lines.join("\n"))
}

fn build_svg(
    kind: FlamegraphKind,
    samples: &[FoldedStackSample],
    diff_entries: &[FlamegraphDiffEntry],
) -> String {
    let mut sorted_samples = samples.to_vec();
    sorted_samples.sort_by_key(|sample| (Reverse(sample.sample_count), sample.stack.clone()));
    if sorted_samples.len() > SVG_ROW_LIMIT {
        sorted_samples.truncate(SVG_ROW_LIMIT);
    }

    let total: u64 = sorted_samples
        .iter()
        .map(|sample| sample.sample_count)
        .sum();
    let row_height = SVG_BAR_HEIGHT + SVG_BAR_GAP;
    let height = SVG_TOP_MARGIN + row_height * (sorted_samples.len() as u64) + 40;
    let available_width = SVG_WIDTH - SVG_LEFT_MARGIN - SVG_RIGHT_MARGIN;

    let mut diff_by_stack = BTreeMap::new();
    for entry in diff_entries {
        diff_by_stack.insert(entry.stack.clone(), entry.delta_samples);
    }

    let mut svg = String::new();
    svg.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{SVG_WIDTH}\" height=\"{height}\" viewBox=\"0 0 {SVG_WIDTH} {height}\">"
    ));
    svg.push_str(&format!(
        "<text x=\"{SVG_LEFT_MARGIN}\" y=\"24\" font-family=\"monospace\" font-size=\"14\">{} flamegraph</text>",
        kind.as_str()
    ));

    for (idx, sample) in sorted_samples.iter().enumerate() {
        let y = SVG_TOP_MARGIN + (idx as u64) * row_height;
        let raw_width = sample
            .sample_count
            .saturating_mul(available_width)
            .checked_div(total)
            .unwrap_or(0);
        let width = if raw_width == 0 && sample.sample_count > 0 {
            1
        } else {
            raw_width
        };

        let color = if kind.is_diff() {
            match diff_by_stack
                .get(&sample.stack)
                .copied()
                .unwrap_or_default()
                .cmp(&0)
            {
                std::cmp::Ordering::Greater => "#d9534f",
                std::cmp::Ordering::Less => "#0275d8",
                std::cmp::Ordering::Equal => "#7f8c8d",
            }
        } else {
            match kind {
                FlamegraphKind::Cpu => "#f39c12",
                FlamegraphKind::Allocation => "#16a085",
                FlamegraphKind::DiffCpu | FlamegraphKind::DiffAllocation => "#7f8c8d",
            }
        };

        svg.push_str(&format!(
            "<rect x=\"{SVG_LEFT_MARGIN}\" y=\"{y}\" width=\"{width}\" height=\"{SVG_BAR_HEIGHT}\" fill=\"{color}\"/>"
        ));

        let text = xml_escape(&sample.stack);
        let label = format!("{text} ({})", sample.sample_count);
        svg.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-family=\"monospace\" font-size=\"11\">{}</text>",
            SVG_LEFT_MARGIN + width + 8,
            y + SVG_BAR_HEIGHT - 5,
            label
        ));
    }

    svg.push_str("</svg>");
    svg
}

fn looks_like_svg(svg: &str) -> bool {
    let trimmed = svg.trim();
    trimmed.starts_with("<svg")
        && trimmed.ends_with("</svg>")
        && trimmed.contains("<rect")
        && trimmed.contains("<text")
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn build_pipeline_id(request: &FlamegraphPipelineRequest) -> String {
    digest_prefix(
        &[
            request.trace_id.as_str(),
            request.decision_id.as_str(),
            request.policy_id.as_str(),
            request.benchmark_run_id.as_str(),
            request.optimization_decision_id.as_str(),
            request.workload_id.as_str(),
            request.generated_at_utc.as_str(),
        ]
        .join("|"),
        24,
        "fgpipe",
    )
}

fn build_evidence_node_id(request: &FlamegraphPipelineRequest) -> String {
    digest_prefix(
        &[
            request.trace_id.as_str(),
            request.decision_id.as_str(),
            request.policy_id.as_str(),
            request.benchmark_run_id.as_str(),
            request.optimization_decision_id.as_str(),
        ]
        .join("|"),
        24,
        "evidence",
    )
}

fn build_baseline_reference_id(
    metadata: &FlamegraphMetadata,
    evidence_link: &FlamegraphEvidenceLink,
    kind: FlamegraphKind,
    baseline: &[FoldedStackSample],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update("baseline_reference");
    hasher.update(kind.as_str());
    hasher.update(metadata.generated_at_utc.as_bytes());
    hasher.update(metadata.benchmark_run_id.as_bytes());
    hasher.update(
        metadata
            .baseline_benchmark_run_id
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update(evidence_link.optimization_decision_id.as_bytes());
    for sample in baseline {
        hasher.update(sample.stack.as_bytes());
        hasher.update(sample.sample_count.to_be_bytes());
    }
    let digest = hasher.finalize();
    let digest_hex = hex::encode(digest);
    format!("fgbase-{}", &digest_hex[..24])
}

fn build_artifact_id(
    kind: FlamegraphKind,
    metadata: &FlamegraphMetadata,
    evidence_link: &FlamegraphEvidenceLink,
    folded_stacks: &[FoldedStackSample],
    diff_from_artifact_id: Option<&str>,
    diff_entries: &[FlamegraphDiffEntry],
    warnings: &[String],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update("flamegraph_artifact");
    hasher.update(kind.as_str());
    hasher.update(metadata.benchmark_run_id.as_bytes());
    hasher.update(
        metadata
            .baseline_benchmark_run_id
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update(metadata.workload_id.as_bytes());
    hasher.update(metadata.benchmark_profile.as_bytes());
    hasher.update(metadata.config_fingerprint.as_bytes());
    hasher.update(metadata.git_commit.as_bytes());
    hasher.update(metadata.generated_at_utc.as_bytes());
    hasher.update(evidence_link.trace_id.as_bytes());
    hasher.update(evidence_link.decision_id.as_bytes());
    hasher.update(evidence_link.policy_id.as_bytes());
    hasher.update(evidence_link.benchmark_run_id.as_bytes());
    hasher.update(evidence_link.optimization_decision_id.as_bytes());
    hasher.update(evidence_link.evidence_node_id.as_bytes());
    if let Some(reference) = diff_from_artifact_id {
        hasher.update(reference.as_bytes());
    }
    for sample in folded_stacks {
        hasher.update(sample.stack.as_bytes());
        hasher.update(sample.sample_count.to_be_bytes());
    }
    for entry in diff_entries {
        hasher.update(entry.stack.as_bytes());
        hasher.update(entry.baseline_samples.to_be_bytes());
        hasher.update(entry.candidate_samples.to_be_bytes());
        hasher.update(entry.delta_samples.to_be_bytes());
    }
    for warning in warnings {
        hasher.update(warning.as_bytes());
    }
    let digest = hasher.finalize();
    let digest_hex = hex::encode(digest);
    format!("fg-{}", &digest_hex[..24])
}

fn digest_prefix(input: &str, width: usize, prefix: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    let digest_hex = hex::encode(digest);
    format!("{prefix}-{}", &digest_hex[..width])
}

fn make_event(
    request: &FlamegraphPipelineRequest,
    event: &str,
    outcome: &str,
    error_code: Option<String>,
    artifact_id: Option<String>,
    flamegraph_kind: Option<String>,
) -> FlamegraphPipelineEvent {
    FlamegraphPipelineEvent {
        trace_id: request.trace_id.clone(),
        decision_id: request.decision_id.clone(),
        policy_id: request.policy_id.clone(),
        component: FLAMEGRAPH_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code,
        artifact_id,
        flamegraph_kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_adapter::InMemoryStorageAdapter;

    // ── FlamegraphKind ────────────────────────────────────────────
    #[test]
    fn flamegraph_kind_as_str() {
        assert_eq!(FlamegraphKind::Cpu.as_str(), "cpu");
        assert_eq!(FlamegraphKind::Allocation.as_str(), "allocation");
        assert_eq!(FlamegraphKind::DiffCpu.as_str(), "diff_cpu");
        assert_eq!(FlamegraphKind::DiffAllocation.as_str(), "diff_allocation");
    }

    #[test]
    fn flamegraph_kind_is_diff() {
        assert!(!FlamegraphKind::Cpu.is_diff());
        assert!(!FlamegraphKind::Allocation.is_diff());
        assert!(FlamegraphKind::DiffCpu.is_diff());
        assert!(FlamegraphKind::DiffAllocation.is_diff());
    }

    #[test]
    fn flamegraph_kind_display() {
        assert_eq!(format!("{}", FlamegraphKind::Cpu), "cpu");
        assert_eq!(
            format!("{}", FlamegraphKind::DiffAllocation),
            "diff_allocation"
        );
    }

    #[test]
    fn flamegraph_kind_serde_round_trip() {
        for kind in [
            FlamegraphKind::Cpu,
            FlamegraphKind::Allocation,
            FlamegraphKind::DiffCpu,
            FlamegraphKind::DiffAllocation,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: FlamegraphKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // ── FoldedStackSample serde ───────────────────────────────────
    #[test]
    fn folded_stack_sample_serde_round_trip() {
        let sample = FoldedStackSample {
            stack: "main;foo;bar".to_string(),
            sample_count: 42,
        };
        let json = serde_json::to_string(&sample).unwrap();
        let back: FoldedStackSample = serde_json::from_str(&json).unwrap();
        assert_eq!(sample, back);
    }

    // ── FlamegraphDiffEntry serde ─────────────────────────────────
    #[test]
    fn flamegraph_diff_entry_serde_round_trip() {
        let entry = FlamegraphDiffEntry {
            stack: "main;alloc".to_string(),
            baseline_samples: 100,
            candidate_samples: 120,
            delta_samples: 20,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: FlamegraphDiffEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // ── FlamegraphMetadata serde ──────────────────────────────────
    #[test]
    fn flamegraph_metadata_serde_round_trip() {
        let meta = test_metadata();
        let json = serde_json::to_string(&meta).unwrap();
        let back: FlamegraphMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, back);
    }

    // ── FlamegraphEvidenceLink serde ──────────────────────────────
    #[test]
    fn flamegraph_evidence_link_serde_round_trip() {
        let link = test_evidence_link();
        let json = serde_json::to_string(&link).unwrap();
        let back: FlamegraphEvidenceLink = serde_json::from_str(&json).unwrap();
        assert_eq!(link, back);
    }

    // ── FlamegraphPipelineEvent serde ─────────────────────────────
    #[test]
    fn flamegraph_pipeline_event_serde_round_trip() {
        let evt = FlamegraphPipelineEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: FLAMEGRAPH_COMPONENT.to_string(),
            event: "test".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            artifact_id: Some("art1".to_string()),
            flamegraph_kind: Some("cpu".to_string()),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let back: FlamegraphPipelineEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(evt, back);
    }

    // ── FlamegraphPipelineDecision ────────────────────────────────
    #[test]
    fn pipeline_decision_is_success() {
        let dec = FlamegraphPipelineDecision {
            pipeline_id: "p1".to_string(),
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "pol1".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
            rollback_required: false,
            storage_backend: "in_memory".to_string(),
            storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.to_string(),
            artifacts: Vec::new(),
            store_keys: Vec::new(),
            events: Vec::new(),
        };
        assert!(dec.is_success());
    }

    #[test]
    fn pipeline_decision_is_not_success() {
        let dec = FlamegraphPipelineDecision {
            pipeline_id: "p1".to_string(),
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "pol1".to_string(),
            outcome: "fail".to_string(),
            error_code: Some("FE-FLAME-1001".to_string()),
            rollback_required: false,
            storage_backend: "in_memory".to_string(),
            storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.to_string(),
            artifacts: Vec::new(),
            store_keys: Vec::new(),
            events: Vec::new(),
        };
        assert!(!dec.is_success());
    }

    // ── FlamegraphQuery default ───────────────────────────────────
    #[test]
    fn flamegraph_query_default() {
        let q = FlamegraphQuery::default();
        assert!(q.benchmark_run_id.is_none());
        assert!(q.workload_id.is_none());
        assert!(q.git_commit.is_none());
        assert!(q.kind.is_none());
        assert!(q.limit.is_none());
    }

    // ── Error stable codes ────────────────────────────────────────
    #[test]
    fn error_stable_codes() {
        assert_eq!(
            FlamegraphPipelineError::InvalidRequest {
                field: "f".into(),
                detail: "d".into()
            }
            .stable_code(),
            "FE-FLAME-1001"
        );
        assert_eq!(
            FlamegraphPipelineError::InvalidTimestamp { value: "v".into() }.stable_code(),
            "FE-FLAME-1002"
        );
        assert_eq!(
            FlamegraphPipelineError::InvalidFoldedStack {
                field: "f".into(),
                line_number: 1,
                detail: "d".into()
            }
            .stable_code(),
            "FE-FLAME-1003"
        );
        assert_eq!(
            FlamegraphPipelineError::EmptyFoldedStack { field: "f".into() }.stable_code(),
            "FE-FLAME-1003"
        );
        assert_eq!(
            FlamegraphPipelineError::MismatchedDiffInput.stable_code(),
            "FE-FLAME-1004"
        );
        assert_eq!(
            FlamegraphPipelineError::InvalidSvg {
                kind: FlamegraphKind::Cpu
            }
            .stable_code(),
            "FE-FLAME-1005"
        );
        assert_eq!(
            FlamegraphPipelineError::SerializationFailure { detail: "d".into() }.stable_code(),
            "FE-FLAME-1006"
        );
    }

    #[test]
    fn error_requires_rollback() {
        assert!(
            !FlamegraphPipelineError::InvalidRequest {
                field: "f".into(),
                detail: "d".into()
            }
            .requires_rollback()
        );
        assert!(!FlamegraphPipelineError::MismatchedDiffInput.requires_rollback());
    }

    #[test]
    fn error_display_invalid_request() {
        let e = FlamegraphPipelineError::InvalidRequest {
            field: "trace_id".into(),
            detail: "empty".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("trace_id"));
        assert!(s.contains("empty"));
    }

    #[test]
    fn error_display_invalid_timestamp() {
        let e = FlamegraphPipelineError::InvalidTimestamp {
            value: "bad".into(),
        };
        assert!(format!("{e}").contains("bad"));
    }

    #[test]
    fn error_display_invalid_folded_stack() {
        let e = FlamegraphPipelineError::InvalidFoldedStack {
            field: "cpu".into(),
            line_number: 3,
            detail: "bad count".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("cpu"));
        assert!(s.contains("3"));
    }

    #[test]
    fn error_display_empty_folded_stack() {
        let e = FlamegraphPipelineError::EmptyFoldedStack {
            field: "cpu".into(),
        };
        assert!(format!("{e}").contains("cpu"));
    }

    #[test]
    fn error_display_mismatched_diff() {
        let e = FlamegraphPipelineError::MismatchedDiffInput;
        assert!(format!("{e}").contains("baseline"));
    }

    // ── normalize_stack ───────────────────────────────────────────
    #[test]
    fn normalize_stack_basic() {
        assert_eq!(normalize_stack("a;b;c"), Some("a;b;c".to_string()));
    }

    #[test]
    fn normalize_stack_trims_spaces() {
        assert_eq!(normalize_stack(" a ; b ; c "), Some("a;b;c".to_string()));
    }

    #[test]
    fn normalize_stack_removes_empty_frames() {
        assert_eq!(normalize_stack("a;;b"), Some("a;b".to_string()));
    }

    #[test]
    fn normalize_stack_empty_returns_none() {
        assert_eq!(normalize_stack(""), None);
    }

    #[test]
    fn normalize_stack_only_semicolons_returns_none() {
        assert_eq!(normalize_stack(";;;"), None);
    }

    // ── parse_folded_stacks ───────────────────────────────────────
    #[test]
    fn parse_folded_stacks_basic() {
        let result = parse_folded_stacks("test", "main;foo 100\nmain;bar 200\n").unwrap();
        assert_eq!(result.len(), 2);
        let total: u64 = result.iter().map(|s| s.sample_count).sum();
        assert_eq!(total, 300);
    }

    #[test]
    fn parse_folded_stacks_merges_duplicates() {
        let result = parse_folded_stacks("test", "main;foo 100\nmain;foo 50\n").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sample_count, 150);
    }

    #[test]
    fn parse_folded_stacks_skips_blank_lines() {
        let result = parse_folded_stacks("test", "\nmain;foo 10\n\nmain;bar 20\n\n").unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn parse_folded_stacks_empty_payload_errors() {
        let err = parse_folded_stacks("test", "").unwrap_err();
        assert_eq!(err.stable_code(), ERROR_INVALID_FOLDED_STACK);
    }

    #[test]
    fn parse_folded_stacks_only_whitespace_errors() {
        let err = parse_folded_stacks("test", "  \n  \n").unwrap_err();
        assert_eq!(err.stable_code(), ERROR_INVALID_FOLDED_STACK);
    }

    #[test]
    fn parse_folded_stacks_invalid_count_errors() {
        let err = parse_folded_stacks("test", "main;foo abc\n").unwrap_err();
        assert_eq!(err.stable_code(), ERROR_INVALID_FOLDED_STACK);
    }

    #[test]
    fn parse_folded_stacks_zero_count_errors() {
        let err = parse_folded_stacks("test", "main;foo 0\n").unwrap_err();
        assert_eq!(err.stable_code(), ERROR_INVALID_FOLDED_STACK);
    }

    #[test]
    fn parse_folded_stacks_missing_count_errors() {
        let err = parse_folded_stacks("test", "main;foo\n").unwrap_err();
        assert_eq!(err.stable_code(), ERROR_INVALID_FOLDED_STACK);
    }

    // ── encode_folded_stacks ──────────────────────────────────────
    #[test]
    fn encode_folded_stacks_basic() {
        let samples = vec![
            FoldedStackSample {
                stack: "b;c".to_string(),
                sample_count: 20,
            },
            FoldedStackSample {
                stack: "a;b".to_string(),
                sample_count: 10,
            },
        ];
        let text = encode_folded_stacks(&samples);
        assert!(text.contains("a;b 10"));
        assert!(text.contains("b;c 20"));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn encode_folded_stacks_sorted() {
        let samples = vec![
            FoldedStackSample {
                stack: "z;z".to_string(),
                sample_count: 1,
            },
            FoldedStackSample {
                stack: "a;a".to_string(),
                sample_count: 1,
            },
        ];
        let text = encode_folded_stacks(&samples);
        let lines: Vec<&str> = text.trim().lines().collect();
        assert!(lines[0] < lines[1]);
    }

    // ── looks_like_svg ────────────────────────────────────────────
    #[test]
    fn looks_like_svg_valid() {
        let svg = "<svg><rect/><text>hello</text></svg>";
        assert!(looks_like_svg(svg));
    }

    #[test]
    fn looks_like_svg_invalid_no_svg_tag() {
        assert!(!looks_like_svg("<div>hello</div>"));
    }

    #[test]
    fn looks_like_svg_invalid_no_rect() {
        assert!(!looks_like_svg("<svg><text>hello</text></svg>"));
    }

    #[test]
    fn looks_like_svg_invalid_no_text() {
        assert!(!looks_like_svg("<svg><rect/></svg>"));
    }

    // ── xml_escape ────────────────────────────────────────────────
    #[test]
    fn xml_escape_special_chars() {
        assert_eq!(
            xml_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    #[test]
    fn xml_escape_no_change() {
        assert_eq!(xml_escape("hello world"), "hello world");
    }

    // ── build_svg ─────────────────────────────────────────────────
    #[test]
    fn build_svg_generates_valid_svg() {
        let samples = vec![FoldedStackSample {
            stack: "main;work".to_string(),
            sample_count: 100,
        }];
        let svg = build_svg(FlamegraphKind::Cpu, &samples, &[]);
        assert!(looks_like_svg(&svg));
        assert!(svg.contains("cpu flamegraph"));
    }

    #[test]
    fn build_svg_diff_uses_colors() {
        let samples = vec![FoldedStackSample {
            stack: "main;work".to_string(),
            sample_count: 50,
        }];
        let diff = vec![FlamegraphDiffEntry {
            stack: "main;work".to_string(),
            baseline_samples: 30,
            candidate_samples: 50,
            delta_samples: 20,
        }];
        let svg = build_svg(FlamegraphKind::DiffCpu, &samples, &diff);
        assert!(looks_like_svg(&svg));
        assert!(svg.contains("#d9534f")); // positive delta = red
    }

    #[test]
    fn build_svg_truncates_to_row_limit() {
        let samples: Vec<FoldedStackSample> = (0..100)
            .map(|i| FoldedStackSample {
                stack: format!("stack_{i}"),
                sample_count: 100 - i as u64,
            })
            .collect();
        let svg = build_svg(FlamegraphKind::Cpu, &samples, &[]);
        assert!(looks_like_svg(&svg));
    }

    // ── build_diff_entries ────────────────────────────────────────
    #[test]
    fn build_diff_entries_basic() {
        let baseline = vec![FoldedStackSample {
            stack: "a;b".to_string(),
            sample_count: 100,
        }];
        let candidate = vec![FoldedStackSample {
            stack: "a;b".to_string(),
            sample_count: 120,
        }];
        let entries = build_diff_entries(&baseline, &candidate).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].delta_samples, 20);
    }

    #[test]
    fn build_diff_entries_identical_is_empty() {
        let samples = vec![FoldedStackSample {
            stack: "a;b".to_string(),
            sample_count: 100,
        }];
        let entries = build_diff_entries(&samples, &samples).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn build_diff_entries_new_stack() {
        let baseline = vec![];
        let candidate = vec![FoldedStackSample {
            stack: "new;stack".to_string(),
            sample_count: 50,
        }];
        let entries = build_diff_entries(&baseline, &candidate).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].baseline_samples, 0);
        assert_eq!(entries[0].candidate_samples, 50);
        assert_eq!(entries[0].delta_samples, 50);
    }

    #[test]
    fn build_diff_entries_removed_stack() {
        let baseline = vec![FoldedStackSample {
            stack: "old;stack".to_string(),
            sample_count: 30,
        }];
        let candidate = vec![];
        let entries = build_diff_entries(&baseline, &candidate).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].delta_samples, -30);
    }

    // ── validate_flamegraph_artifact ──────────────────────────────
    fn test_metadata() -> FlamegraphMetadata {
        FlamegraphMetadata {
            benchmark_run_id: "run-1".to_string(),
            baseline_benchmark_run_id: None,
            workload_id: "wl-1".to_string(),
            benchmark_profile: "small".to_string(),
            config_fingerprint: "fp-1".to_string(),
            git_commit: "abc123".to_string(),
            generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn test_evidence_link() -> FlamegraphEvidenceLink {
        FlamegraphEvidenceLink {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            benchmark_run_id: "run-1".to_string(),
            optimization_decision_id: "opt-1".to_string(),
            evidence_node_id: "ev-1".to_string(),
        }
    }

    fn test_artifact() -> FlamegraphArtifact {
        let folded_stacks = vec![FoldedStackSample {
            stack: "main;work".to_string(),
            sample_count: 100,
        }];
        let folded_stacks_text = encode_folded_stacks(&folded_stacks);
        let svg = build_svg(FlamegraphKind::Cpu, &folded_stacks, &[]);
        FlamegraphArtifact {
            schema_version: FLAMEGRAPH_SCHEMA_VERSION.to_string(),
            artifact_id: "fg-test123".to_string(),
            kind: FlamegraphKind::Cpu,
            metadata: test_metadata(),
            evidence_link: test_evidence_link(),
            folded_stacks,
            folded_stacks_text,
            svg,
            total_samples: 100,
            diff_from_artifact_id: None,
            diff_entries: Vec::new(),
            warnings: Vec::new(),
            storage_integration_point: FLAMEGRAPH_STORAGE_INTEGRATION_POINT.to_string(),
        }
    }

    #[test]
    fn validate_artifact_valid() {
        validate_flamegraph_artifact(&test_artifact()).unwrap();
    }

    #[test]
    fn validate_artifact_bad_schema_version() {
        let mut a = test_artifact();
        a.schema_version = "wrong".to_string();
        let err = validate_flamegraph_artifact(&a).unwrap_err();
        assert_eq!(err.stable_code(), ERROR_INVALID_REQUEST);
    }

    #[test]
    fn validate_artifact_empty_id() {
        let mut a = test_artifact();
        a.artifact_id = "  ".to_string();
        let err = validate_flamegraph_artifact(&a).unwrap_err();
        assert_eq!(err.stable_code(), ERROR_INVALID_REQUEST);
    }

    #[test]
    fn validate_artifact_bad_svg() {
        let mut a = test_artifact();
        a.svg = "not svg".to_string();
        let err = validate_flamegraph_artifact(&a).unwrap_err();
        assert_eq!(err.stable_code(), ERROR_INVALID_SVG);
    }

    #[test]
    fn validate_artifact_bad_integration_point() {
        let mut a = test_artifact();
        a.storage_integration_point = "wrong".to_string();
        let err = validate_flamegraph_artifact(&a).unwrap_err();
        assert_eq!(err.stable_code(), ERROR_INVALID_REQUEST);
    }

    #[test]
    fn validate_artifact_mismatched_total() {
        let mut a = test_artifact();
        a.total_samples = 999;
        let err = validate_flamegraph_artifact(&a).unwrap_err();
        assert_eq!(err.stable_code(), ERROR_INVALID_REQUEST);
    }

    #[test]
    fn validate_artifact_mismatched_stacks_text() {
        let mut a = test_artifact();
        a.folded_stacks_text = "different;stack 50\n".to_string();
        let err = validate_flamegraph_artifact(&a).unwrap_err();
        assert_eq!(err.stable_code(), ERROR_INVALID_REQUEST);
    }

    // ── digest_prefix ─────────────────────────────────────────────
    #[test]
    fn digest_prefix_deterministic() {
        let a = digest_prefix("test-input", 16, "pfx");
        let b = digest_prefix("test-input", 16, "pfx");
        assert_eq!(a, b);
        assert!(a.starts_with("pfx-"));
    }

    #[test]
    fn digest_prefix_different_inputs() {
        let a = digest_prefix("input-a", 16, "pfx");
        let b = digest_prefix("input-b", 16, "pfx");
        assert_ne!(a, b);
    }

    // ── build_pipeline_id ─────────────────────────────────────────
    #[test]
    fn build_pipeline_id_deterministic() {
        let req = test_request();
        let a = build_pipeline_id(&req);
        let b = build_pipeline_id(&req);
        assert_eq!(a, b);
        assert!(a.starts_with("fgpipe-"));
    }

    // ── Constants ─────────────────────────────────────────────────
    #[test]
    fn constants_check() {
        assert_eq!(FLAMEGRAPH_COMPONENT, "flamegraph_pipeline");
        assert!(!FLAMEGRAPH_SCHEMA_VERSION.is_empty());
        assert!(!FLAMEGRAPH_STORAGE_INTEGRATION_POINT.is_empty());
    }

    // ── run_flamegraph_pipeline (integration) ─────────────────────
    fn test_request() -> FlamegraphPipelineRequest {
        FlamegraphPipelineRequest {
            trace_id: "trace-1".to_string(),
            decision_id: "dec-1".to_string(),
            policy_id: "pol-1".to_string(),
            benchmark_run_id: "run-1".to_string(),
            optimization_decision_id: "opt-1".to_string(),
            workload_id: "wl-1".to_string(),
            benchmark_profile: "small".to_string(),
            config_fingerprint: "fp-1".to_string(),
            git_commit: "abc123".to_string(),
            generated_at_utc: "2026-01-01T00:00:00Z".to_string(),
            cpu_folded_stacks: "main;cpu_work 100\nmain;other 50\n".to_string(),
            allocation_folded_stacks: "main;alloc 200\n".to_string(),
            baseline_benchmark_run_id: None,
            baseline_cpu_folded_stacks: None,
            baseline_allocation_folded_stacks: None,
        }
    }

    #[test]
    fn run_pipeline_success() {
        let mut adapter = InMemoryStorageAdapter::new();
        let req = test_request();
        let decision = run_flamegraph_pipeline(&mut adapter, &req);
        assert!(decision.is_success());
        assert_eq!(decision.outcome, "pass");
        assert!(decision.error_code.is_none());
        assert!(!decision.rollback_required);
        assert_eq!(decision.artifacts.len(), 2); // cpu + allocation
        assert_eq!(decision.store_keys.len(), 2);
    }

    #[test]
    fn run_pipeline_with_diff() {
        let mut adapter = InMemoryStorageAdapter::new();
        let mut req = test_request();
        req.baseline_benchmark_run_id = Some("baseline-run".to_string());
        req.baseline_cpu_folded_stacks = Some("main;cpu_work 80\nmain;other 40\n".to_string());
        req.baseline_allocation_folded_stacks = Some("main;alloc 180\n".to_string());
        let decision = run_flamegraph_pipeline(&mut adapter, &req);
        assert!(decision.is_success());
        assert_eq!(decision.artifacts.len(), 4); // cpu + alloc + diff_cpu + diff_alloc
    }

    #[test]
    fn run_pipeline_mismatched_diff_input() {
        let mut adapter = InMemoryStorageAdapter::new();
        let mut req = test_request();
        req.baseline_cpu_folded_stacks = Some("main;cpu 100\n".to_string());
        // baseline_allocation_folded_stacks is None -> mismatch
        let decision = run_flamegraph_pipeline(&mut adapter, &req);
        assert!(!decision.is_success());
        assert_eq!(
            decision.error_code.as_deref(),
            Some(ERROR_MISMATCHED_DIFF_INPUT)
        );
    }

    #[test]
    fn run_pipeline_empty_trace_id_fails() {
        let mut adapter = InMemoryStorageAdapter::new();
        let mut req = test_request();
        req.trace_id = "".to_string();
        let decision = run_flamegraph_pipeline(&mut adapter, &req);
        assert!(!decision.is_success());
        assert_eq!(decision.error_code.as_deref(), Some(ERROR_INVALID_REQUEST));
    }

    #[test]
    fn run_pipeline_invalid_timestamp_fails() {
        let mut adapter = InMemoryStorageAdapter::new();
        let mut req = test_request();
        req.generated_at_utc = "not-a-timestamp".to_string();
        let decision = run_flamegraph_pipeline(&mut adapter, &req);
        assert!(!decision.is_success());
        assert_eq!(
            decision.error_code.as_deref(),
            Some(ERROR_INVALID_TIMESTAMP)
        );
    }

    #[test]
    fn run_pipeline_empty_cpu_stacks_fails() {
        let mut adapter = InMemoryStorageAdapter::new();
        let mut req = test_request();
        req.cpu_folded_stacks = "".to_string();
        let decision = run_flamegraph_pipeline(&mut adapter, &req);
        assert!(!decision.is_success());
    }

    #[test]
    fn run_pipeline_storage_failure() {
        let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
        let req = test_request();
        let decision = run_flamegraph_pipeline(&mut adapter, &req);
        assert!(!decision.is_success());
        assert_eq!(decision.error_code.as_deref(), Some(ERROR_STORAGE));
        assert!(decision.rollback_required);
    }

    #[test]
    fn run_pipeline_deterministic() {
        let req = test_request();
        let mut a1 = InMemoryStorageAdapter::new();
        let mut a2 = InMemoryStorageAdapter::new();
        let d1 = run_flamegraph_pipeline(&mut a1, &req);
        let d2 = run_flamegraph_pipeline(&mut a2, &req);
        assert_eq!(d1.pipeline_id, d2.pipeline_id);
        assert_eq!(d1.artifacts.len(), d2.artifacts.len());
        for (art1, art2) in d1.artifacts.iter().zip(d2.artifacts.iter()) {
            assert_eq!(art1.artifact_id, art2.artifact_id);
            assert_eq!(art1.svg, art2.svg);
        }
    }

    #[test]
    fn run_pipeline_events_contain_start_and_complete() {
        let mut adapter = InMemoryStorageAdapter::new();
        let req = test_request();
        let decision = run_flamegraph_pipeline(&mut adapter, &req);
        let event_names: Vec<&str> = decision.events.iter().map(|e| e.event.as_str()).collect();
        assert!(event_names.contains(&"pipeline_started"));
        assert!(event_names.contains(&"pipeline_completed"));
    }

    #[test]
    fn run_pipeline_empty_baseline_run_id_fails() {
        let mut adapter = InMemoryStorageAdapter::new();
        let mut req = test_request();
        req.baseline_benchmark_run_id = Some("  ".to_string());
        let decision = run_flamegraph_pipeline(&mut adapter, &req);
        assert!(!decision.is_success());
    }

    #[test]
    fn flamegraph_kind_ord() {
        assert!(FlamegraphKind::Cpu < FlamegraphKind::Allocation);
        assert!(FlamegraphKind::Allocation < FlamegraphKind::DiffCpu);
        assert!(FlamegraphKind::DiffCpu < FlamegraphKind::DiffAllocation);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn flamegraph_kind_serde_all_variants() {
        let variants = [
            FlamegraphKind::Cpu,
            FlamegraphKind::Allocation,
            FlamegraphKind::DiffCpu,
            FlamegraphKind::DiffAllocation,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FlamegraphKind = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn flamegraph_kind_as_str_all_distinct() {
        let variants = [
            FlamegraphKind::Cpu,
            FlamegraphKind::Allocation,
            FlamegraphKind::DiffCpu,
            FlamegraphKind::DiffAllocation,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            assert!(seen.insert(v.as_str()), "duplicate as_str: {}", v.as_str());
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn flamegraph_kind_is_diff_correct() {
        assert!(!FlamegraphKind::Cpu.is_diff());
        assert!(!FlamegraphKind::Allocation.is_diff());
        assert!(FlamegraphKind::DiffCpu.is_diff());
        assert!(FlamegraphKind::DiffAllocation.is_diff());
    }

    #[test]
    fn folded_stack_sample_serde_roundtrip() {
        let sample = FoldedStackSample {
            stack: "main;foo;bar".to_string(),
            sample_count: 42,
        };
        let json = serde_json::to_string(&sample).unwrap();
        let back: FoldedStackSample = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sample);
    }

    #[test]
    fn flamegraph_diff_entry_serde_roundtrip() {
        let entry = FlamegraphDiffEntry {
            stack: "main;alloc".to_string(),
            baseline_samples: 100,
            candidate_samples: 120,
            delta_samples: 20,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: FlamegraphDiffEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entry);
    }

    #[test]
    fn flamegraph_query_default_serde_roundtrip() {
        let query = FlamegraphQuery::default();
        let json = serde_json::to_string(&query).unwrap();
        let back: FlamegraphQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(back, query);
        assert!(back.benchmark_run_id.is_none());
        assert!(back.limit.is_none());
    }

    #[test]
    fn flamegraph_pipeline_error_display() {
        let err = FlamegraphPipelineError::InvalidRequest {
            field: "trace_id".to_string(),
            detail: "cannot be empty".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("trace_id"));
        assert!(msg.contains("cannot be empty"));
    }
}
