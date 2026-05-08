//! Advisory shadow-autopilot decision composer types.
//!
//! The composer reads normalized shadow journal events and existing autopilot
//! output metadata, then emits operator-facing artifacts. It is advisory only:
//! recommendations name commands for a human or separate agent to run, but this
//! module never executes them.

#![forbid(unsafe_code)]

use std::{collections::BTreeMap, error::Error, fmt, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Stable status artifact schema.
pub const SHADOW_DECISION_STATUS_SCHEMA_VERSION: &str =
    "franken-engine.swarm-autopilot-shadow-status.v1";

/// Stable recommendations artifact schema.
pub const SHADOW_DECISION_RECOMMENDATIONS_SCHEMA_VERSION: &str =
    "franken-engine.swarm-autopilot-shadow-recommendations.v1";

/// Stable event artifact schema.
pub const SHADOW_DECISION_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.swarm-autopilot-shadow-decision-composer.event.v1";

/// Required source families for a complete shadow decision pass.
pub const REQUIRED_SHADOW_DECISION_SOURCE_KEYS: [&str; 6] = [
    "br_queue",
    "bv_robot_plan",
    "agent_mail",
    "rch_status",
    "git_state",
    "artifact_bundles",
];

/// Default snapshot freshness window used by source watcher fixtures.
pub const DEFAULT_SHADOW_DECISION_FRESHNESS_WINDOW_SECONDS: i64 = 300;

/// Default bounded recommendation count.
pub const DEFAULT_SHADOW_DECISION_MAX_RECOMMENDATIONS: usize = 16;

/// Input envelope for one deterministic advisory decision composition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowDecisionComposerInput {
    pub shadow_run_id: String,
    pub source_revision: String,
    pub generated_epoch_seconds: i64,
    pub default_freshness_window_seconds: i64,
    pub max_recommendations: usize,
    pub journal_events: Vec<JournalSourceEvent>,
    pub existing_autopilot_outputs: Vec<ExistingAutopilotOutput>,
    pub artifact_paths: ArtifactPaths,
}

impl ShadowDecisionComposerInput {
    /// Construct an input envelope with repo-default freshness and cap values.
    pub fn new(
        shadow_run_id: impl Into<String>,
        source_revision: impl Into<String>,
        generated_epoch_seconds: i64,
        journal_events: Vec<JournalSourceEvent>,
        output_dir: impl AsRef<Path>,
    ) -> Self {
        Self {
            shadow_run_id: shadow_run_id.into(),
            source_revision: source_revision.into(),
            generated_epoch_seconds,
            default_freshness_window_seconds: DEFAULT_SHADOW_DECISION_FRESHNESS_WINDOW_SECONDS,
            max_recommendations: DEFAULT_SHADOW_DECISION_MAX_RECOMMENDATIONS,
            journal_events,
            existing_autopilot_outputs: Vec::new(),
            artifact_paths: ArtifactPaths::for_output_dir(output_dir),
        }
    }
}

/// Normalized source snapshot or journal event consumed by the composer.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct JournalSourceEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_event_id: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_payload_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected_epoch_seconds: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected_timestamp_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_window_seconds: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fresh: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_payload_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_locator: Option<String>,
    #[serde(default)]
    pub local_fallback_contamination: bool,
    #[serde(default)]
    pub error_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_payload: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_payload_json: Option<String>,
}

/// Metadata for an existing autopilot output used as input evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExistingAutopilotOutput {
    pub path: String,
    pub schema_version: String,
    pub content_hash: String,
}

/// Normalized source state used internally and exposed in tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshot {
    pub source_key: String,
    pub source_id: String,
    pub source_kind: String,
    pub schema_version: String,
    pub content_hash: String,
    pub collected_epoch_seconds: i64,
    pub freshness_window_seconds: i64,
    pub fresh: bool,
    pub degraded: bool,
    pub raw_payload_ref: String,
    pub local_fallback_contamination: bool,
    pub error_codes: Vec<String>,
    pub payload: Value,
}

/// Source status shape serialized into `shadow_status.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshotStatus {
    pub source_key: String,
    pub source_id: String,
    pub source_kind: String,
    pub schema_version: String,
    pub content_hash: String,
    pub collected_epoch_seconds: i64,
    pub freshness_window_seconds: i64,
    pub fresh: bool,
    pub degraded: bool,
    pub raw_payload_ref: String,
    pub local_fallback_contamination: bool,
    pub error_codes: Vec<String>,
}

/// Complete in-memory artifact bundle for one composition run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowDecisionArtifacts {
    pub shadow_status: ShadowStatus,
    pub recommendations: RecommendationBundle,
    pub operator_notice_md: String,
    pub events_jsonl: String,
    pub commands_txt: String,
    pub report_md: String,
}

/// Shadow status JSON artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowStatus {
    pub schema_version: String,
    pub shadow_run_id: String,
    pub source_revision: String,
    pub generated_epoch_seconds: i64,
    pub truth_state: ShadowTruthState,
    pub decision: ShadowDecision,
    pub source_snapshot_status: BTreeMap<String, SourceSnapshotStatus>,
    pub source_snapshot_ids: Vec<String>,
    pub advisory_recommendations: Vec<AdvisoryRecommendation>,
    pub rejected_mutation_claims: Vec<RejectedMutationClaim>,
    pub existing_autopilot_outputs: Vec<ExistingAutopilotOutput>,
    pub stale_sources: Vec<String>,
    pub missing_sources: Vec<String>,
    pub error_codes: Vec<String>,
    pub mutation_policy: MutationPolicy,
    pub sibling_reuse: SiblingReuse,
    pub artifact_paths: ArtifactPaths,
}

/// Recommendations JSON artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecommendationBundle {
    pub schema_version: String,
    pub shadow_run_id: String,
    pub truth_state: ShadowTruthState,
    pub decision: ShadowDecision,
    pub recommendations: Vec<AdvisoryRecommendation>,
    pub mutation_policy: MutationPolicy,
    pub source_snapshot_ids: Vec<String>,
    pub error_codes: Vec<String>,
    pub artifact_paths: RecommendationArtifactPaths,
}

/// One advisory operator recommendation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisoryRecommendation {
    pub recommendation_id: String,
    pub rank: u32,
    pub action_class: String,
    pub command_text: String,
    pub executes_mutation: bool,
    pub remediation_only: bool,
    pub source_event_ids: Vec<String>,
    pub source_hashes: Vec<String>,
    pub source_collected_epoch_seconds: Vec<i64>,
    pub degradation_state: String,
    pub reason_codes: Vec<String>,
    pub evidence_paths: Vec<String>,
}

/// Rejected mutation claim recorded in the status artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedMutationClaim {
    pub claim_id: String,
    pub rejection_error_code: String,
    pub executed: bool,
}

/// Advisory composer truth state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowTruthState {
    Confirmed,
    Degraded,
    Blocked,
    Contaminated,
}

/// Advisory composer decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowDecision {
    Pass,
    Degraded,
    FailClosed,
}

/// Immutable no-mutation policy stamped into every artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationPolicy {
    pub advisory_only: bool,
    pub proof_only: bool,
    pub mutates_br: bool,
    pub reassigns_beads: bool,
    pub releases_reservations: bool,
    pub sends_agent_mail: bool,
    pub runs_cargo: bool,
    pub runs_rch: bool,
    pub mutates_git: bool,
    pub mutates_remote_workers: bool,
    pub changes_live_queue_policy: bool,
    pub writes_outside_output_dir: bool,
}

impl MutationPolicy {
    /// Construct the hard fail-closed policy for the advisory composer.
    pub fn advisory_only() -> Self {
        Self {
            advisory_only: true,
            proof_only: true,
            mutates_br: false,
            reassigns_beads: false,
            releases_reservations: false,
            sends_agent_mail: false,
            runs_cargo: false,
            runs_rch: false,
            mutates_git: false,
            mutates_remote_workers: false,
            changes_live_queue_policy: false,
            writes_outside_output_dir: false,
        }
    }
}

/// Required sibling-reuse contract surfaced in status artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiblingReuse {
    pub persistence: String,
    pub tui: String,
    pub service_api: String,
}

impl SiblingReuse {
    /// Construct the repo-level sibling-reuse declaration.
    pub fn required() -> Self {
        Self {
            persistence: "/dp/frankensqlite".to_string(),
            tui: "/dp/frankentui".to_string(),
            service_api: "/dp/fastapi_rust".to_string(),
        }
    }
}

/// Output artifact paths emitted by the composer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactPaths {
    pub shadow_status_json: String,
    pub recommendations_json: String,
    pub operator_notice_md: String,
    pub events_jsonl: String,
    pub commands_txt: String,
    pub report_md: String,
}

impl ArtifactPaths {
    /// Construct canonical artifact paths under an output directory.
    pub fn for_output_dir(output_dir: impl AsRef<Path>) -> Self {
        let output_dir = output_dir.as_ref();
        let path = |file_name: &str| output_dir.join(file_name).to_string_lossy().into_owned();
        Self {
            shadow_status_json: path("shadow_status.json"),
            recommendations_json: path("recommendations.json"),
            operator_notice_md: path("operator_notice.md"),
            events_jsonl: path("events.jsonl"),
            commands_txt: path("commands.txt"),
            report_md: path("report.md"),
        }
    }
}

/// Narrow artifact path shape serialized into `recommendations.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecommendationArtifactPaths {
    pub shadow_status_json: String,
    pub recommendations_json: String,
}

impl From<&ArtifactPaths> for RecommendationArtifactPaths {
    fn from(paths: &ArtifactPaths) -> Self {
        Self {
            shadow_status_json: paths.shadow_status_json.clone(),
            recommendations_json: paths.recommendations_json.clone(),
        }
    }
}

/// Composer error with deterministic messages for tests and operator notices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShadowDecisionError {
    InvalidInput(String),
    Json(String),
    Io(String),
}

impl fmt::Display for ShadowDecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => {
                write!(formatter, "invalid shadow decision input: {message}")
            }
            Self::Json(message) => write!(formatter, "shadow decision JSON error: {message}"),
            Self::Io(message) => write!(formatter, "shadow decision I/O error: {message}"),
        }
    }
}

impl Error for ShadowDecisionError {}
