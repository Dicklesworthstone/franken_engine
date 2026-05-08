//! Advisory shadow-autopilot decision composer types.
//!
//! The composer reads normalized shadow journal events and existing autopilot
//! output metadata, then emits operator-facing artifacts. It is advisory only:
//! recommendations name commands for a human or separate agent to run, but this
//! module never executes them.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt, fs,
    path::{Component, Path},
};

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

impl From<serde_json::Error> for ShadowDecisionError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}

impl From<std::io::Error> for ShadowDecisionError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

/// Compose advisory status, recommendation, and notice artifacts.
pub fn compose_shadow_decision(
    input: &ShadowDecisionComposerInput,
) -> Result<ShadowDecisionArtifacts, ShadowDecisionError> {
    validate_input(input)?;

    let mut sources = input
        .journal_events
        .iter()
        .map(|event| normalize_journal_event(event, input.default_freshness_window_seconds))
        .collect::<Result<Vec<_>, _>>()?;
    sources.sort_by(|left, right| {
        left.source_key
            .cmp(&right.source_key)
            .then(left.source_id.cmp(&right.source_id))
    });

    let latest_sources = latest_sources_by_key(&sources);
    let source_snapshot_status = latest_sources
        .iter()
        .map(|(key, source)| (key.clone(), source_status(source)))
        .collect::<BTreeMap<_, _>>();
    let source_snapshot_ids = sources
        .iter()
        .map(|source| source.source_id.clone())
        .collect::<Vec<_>>();
    let present_keys = sources
        .iter()
        .map(|source| source.source_key.as_str())
        .collect::<BTreeSet<_>>();
    let missing_sources = REQUIRED_SHADOW_DECISION_SOURCE_KEYS
        .iter()
        .filter(|source_key| !present_keys.contains(**source_key))
        .map(|source_key| (*source_key).to_string())
        .collect::<Vec<_>>();
    let stale_sources = stale_source_keys(&sources, input.generated_epoch_seconds);
    let source_error_codes = source_error_codes(&sources);

    let rch_contaminated = sources
        .iter()
        .any(|source| source.local_fallback_contamination)
        || source_error_codes
            .iter()
            .any(|code| code == "FE-SWARM-AUTOPILOT-SHADOW-RCH-LOCAL-FALLBACK");
    let contradictory_ownership = source_error_codes
        .iter()
        .any(|code| code == "FE-SWARM-AUTOPILOT-SHADOW-CONTRADICTORY-OWNERSHIP");
    let unsupported_mutation = source_error_codes
        .iter()
        .any(|code| code == "FE-SWARM-AUTOPILOT-SHADOW-UNSUPPORTED-MUTATION");
    let source_degraded = sources.iter().any(|source| source.degraded);

    let br_payload = payload_for(&latest_sources, "br_queue");
    let mail_payload = payload_for(&latest_sources, "agent_mail");
    let git_payload = payload_for(&latest_sources, "git_state");
    let artifact_payload = payload_for(&latest_sources, "artifact_bundles");

    let ready_items = br_ready_items(br_payload);
    let in_progress_items = br_in_progress_items(br_payload);
    let stalled_beads = stalled_beads(&in_progress_items, input.generated_epoch_seconds);
    let stale_reservations = stale_reservations(mail_payload, input.generated_epoch_seconds);
    let dirty_worktree = boolish(git_payload.and_then(|payload| payload.get("dirty")));
    let missing_no_mock = missing_no_mock_proof(artifact_payload);

    let recommendations = advisory_recommendations(
        &latest_sources,
        &input.artifact_paths,
        &ready_items,
        &in_progress_items,
        &stalled_beads,
        !stale_reservations.is_empty(),
        rch_contaminated,
        contradictory_ownership,
        dirty_worktree,
        missing_no_mock,
        source_degraded
            && source_error_codes
                .iter()
                .any(|code| code == "FE-SWARM-AUTOPILOT-SHADOW-DEGRADED-SOURCE"),
        input.max_recommendations,
    );

    let mut error_codes = Vec::new();
    if !missing_sources.is_empty() {
        error_codes.push("FE-SWARM-AUTOPILOT-SHADOW-MISSING-SOURCE".to_string());
    }
    if !stale_sources.is_empty() {
        error_codes.push("FE-SWARM-AUTOPILOT-SHADOW-STALE-SOURCE".to_string());
    }
    if !stalled_beads.is_empty() {
        error_codes.push("FE-SWARM-AUTOPILOT-SHADOW-STALED-BEAD".to_string());
    }
    if !stale_reservations.is_empty() {
        error_codes.push("FE-SWARM-AUTOPILOT-SHADOW-STALE-RESERVATION".to_string());
    }
    error_codes.extend(source_error_codes);
    if dirty_worktree {
        error_codes.push("FE-SWARM-AUTOPILOT-SHADOW-DIRTY-WORKTREE".to_string());
    }
    if missing_no_mock {
        error_codes.push("FE-SWARM-AUTOPILOT-SHADOW-MISSING-NO-MOCK-PROOF".to_string());
    }
    dedupe_sorted(&mut error_codes);

    let truth_state = if rch_contaminated || unsupported_mutation {
        ShadowTruthState::Contaminated
    } else if !missing_sources.is_empty() || !stale_sources.is_empty() || contradictory_ownership {
        ShadowTruthState::Blocked
    } else if source_degraded
        || dirty_worktree
        || !stale_reservations.is_empty()
        || !stalled_beads.is_empty()
        || missing_no_mock
    {
        ShadowTruthState::Degraded
    } else {
        ShadowTruthState::Confirmed
    };
    let decision = match truth_state {
        ShadowTruthState::Confirmed => ShadowDecision::Pass,
        ShadowTruthState::Degraded => ShadowDecision::Degraded,
        ShadowTruthState::Blocked | ShadowTruthState::Contaminated => ShadowDecision::FailClosed,
    };

    let mutation_policy = MutationPolicy::advisory_only();
    let sibling_reuse = SiblingReuse::required();
    let rejected_mutation_claims = if unsupported_mutation {
        vec![RejectedMutationClaim {
            claim_id: "unsupported-mutation-claim".to_string(),
            rejection_error_code: "FE-SWARM-AUTOPILOT-SHADOW-UNSUPPORTED-MUTATION".to_string(),
            executed: false,
        }]
    } else {
        Vec::new()
    };

    let shadow_status = ShadowStatus {
        schema_version: SHADOW_DECISION_STATUS_SCHEMA_VERSION.to_string(),
        shadow_run_id: input.shadow_run_id.clone(),
        source_revision: input.source_revision.clone(),
        generated_epoch_seconds: input.generated_epoch_seconds,
        truth_state,
        decision,
        source_snapshot_status,
        source_snapshot_ids: source_snapshot_ids.clone(),
        advisory_recommendations: recommendations.clone(),
        rejected_mutation_claims,
        existing_autopilot_outputs: input.existing_autopilot_outputs.clone(),
        stale_sources,
        missing_sources,
        error_codes: error_codes.clone(),
        mutation_policy: mutation_policy.clone(),
        sibling_reuse,
        artifact_paths: input.artifact_paths.clone(),
    };
    let recommendations = RecommendationBundle {
        schema_version: SHADOW_DECISION_RECOMMENDATIONS_SCHEMA_VERSION.to_string(),
        shadow_run_id: input.shadow_run_id.clone(),
        truth_state,
        decision,
        recommendations,
        mutation_policy,
        source_snapshot_ids,
        error_codes,
        artifact_paths: RecommendationArtifactPaths::from(&input.artifact_paths),
    };
    let operator_notice_md = render_operator_notice(truth_state, decision, &recommendations);
    let events_jsonl = render_events_jsonl(&input.shadow_run_id, decision, &input.artifact_paths)?;
    let commands_txt = render_commands_txt();
    let report_md = render_report(&input.artifact_paths);

    Ok(ShadowDecisionArtifacts {
        shadow_status,
        recommendations,
        operator_notice_md,
        events_jsonl,
        commands_txt,
        report_md,
    })
}

/// Normalize one journal event into the source snapshot contract.
pub fn normalize_journal_event(
    event: &JournalSourceEvent,
    default_freshness_window_seconds: i64,
) -> Result<SourceSnapshot, ShadowDecisionError> {
    if default_freshness_window_seconds < 0 {
        return Err(ShadowDecisionError::InvalidInput(
            "default freshness window must be non-negative".to_string(),
        ));
    }

    let payload = event_payload(event)?;
    let mut error_codes = event.error_codes.clone();
    error_codes.extend(payload_error_codes(&payload));
    dedupe_sorted(&mut error_codes);

    let source_kind = event
        .source_kind
        .as_deref()
        .and_then(non_empty)
        .unwrap_or("unknown");
    let source_key = event
        .source_key
        .as_deref()
        .and_then(non_empty)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| infer_source_key(source_kind).to_string());
    let source_id = event
        .source_id
        .as_deref()
        .and_then(non_empty)
        .map(ToOwned::to_owned)
        .or_else(|| event.journal_event_id.as_ref().map(value_to_string))
        .unwrap_or_else(|| source_key.clone());
    let collected_epoch_seconds = event
        .collected_epoch_seconds
        .or_else(|| {
            event
                .collected_timestamp_ms
                .map(|timestamp_ms| timestamp_ms / 1000)
        })
        .unwrap_or(0);
    let freshness_window_seconds = event
        .freshness_window_seconds
        .unwrap_or(default_freshness_window_seconds);
    if freshness_window_seconds < 0 {
        return Err(ShadowDecisionError::InvalidInput(format!(
            "source `{source_key}` has negative freshness window"
        )));
    }

    Ok(SourceSnapshot {
        source_key,
        source_id,
        source_kind: source_kind.to_string(),
        schema_version: event
            .schema_version
            .as_deref()
            .and_then(non_empty)
            .unwrap_or("unknown")
            .to_string(),
        content_hash: event
            .content_hash
            .as_deref()
            .or(event.payload_content_hash.as_deref())
            .or(event.normalized_payload_hash.as_deref())
            .and_then(non_empty)
            .unwrap_or("sha256:unknown")
            .to_string(),
        collected_epoch_seconds,
        freshness_window_seconds,
        fresh: event.fresh.unwrap_or(true),
        degraded: event.degraded.unwrap_or(!error_codes.is_empty()),
        raw_payload_ref: event
            .raw_payload_ref
            .as_deref()
            .or(event.source_locator.as_deref())
            .and_then(non_empty)
            .unwrap_or("journal-events-jsonl")
            .to_string(),
        local_fallback_contamination: event.local_fallback_contamination,
        error_codes,
        payload,
    })
}

/// Write the composed artifacts, constrained to the provided output directory.
pub fn write_shadow_decision_artifacts(
    output_dir: impl AsRef<Path>,
    artifacts: &ShadowDecisionArtifacts,
) -> Result<(), ShadowDecisionError> {
    let output_dir = output_dir.as_ref();
    ensure_artifact_paths_under(output_dir, &artifacts.shadow_status.artifact_paths)?;
    fs::create_dir_all(output_dir)?;

    write_json_artifact(
        &artifacts.shadow_status.artifact_paths.shadow_status_json,
        &artifacts.shadow_status,
    )?;
    write_json_artifact(
        &artifacts.shadow_status.artifact_paths.recommendations_json,
        &artifacts.recommendations,
    )?;
    fs::write(
        &artifacts.shadow_status.artifact_paths.operator_notice_md,
        &artifacts.operator_notice_md,
    )?;
    fs::write(
        &artifacts.shadow_status.artifact_paths.events_jsonl,
        &artifacts.events_jsonl,
    )?;
    fs::write(
        &artifacts.shadow_status.artifact_paths.commands_txt,
        &artifacts.commands_txt,
    )?;
    fs::write(
        &artifacts.shadow_status.artifact_paths.report_md,
        &artifacts.report_md,
    )?;
    Ok(())
}

fn validate_input(input: &ShadowDecisionComposerInput) -> Result<(), ShadowDecisionError> {
    if input.shadow_run_id.trim().is_empty() {
        return Err(ShadowDecisionError::InvalidInput(
            "shadow_run_id must not be empty".to_string(),
        ));
    }
    if input.source_revision.trim().is_empty() {
        return Err(ShadowDecisionError::InvalidInput(
            "source_revision must not be empty".to_string(),
        ));
    }
    if input.generated_epoch_seconds < 0 {
        return Err(ShadowDecisionError::InvalidInput(
            "generated_epoch_seconds must be non-negative".to_string(),
        ));
    }
    if input.default_freshness_window_seconds < 0 {
        return Err(ShadowDecisionError::InvalidInput(
            "default freshness window must be non-negative".to_string(),
        ));
    }
    if input.max_recommendations == 0 {
        return Err(ShadowDecisionError::InvalidInput(
            "max_recommendations must be positive".to_string(),
        ));
    }
    Ok(())
}

fn event_payload(event: &JournalSourceEvent) -> Result<Value, ShadowDecisionError> {
    if let Some(payload) = event.normalized_payload.as_ref().and_then(object_or_array) {
        return Ok(payload.clone());
    }
    if let Some(payload) = event.payload.as_ref().and_then(object_or_array) {
        return Ok(payload.clone());
    }
    if let Some(payload_json) = event.normalized_payload_json.as_deref() {
        let parsed = serde_json::from_str::<Value>(payload_json)?;
        if let Some(payload) = object_or_array(&parsed) {
            return Ok(payload.clone());
        }
    }
    Ok(Value::Object(serde_json::Map::new()))
}

fn object_or_array(value: &Value) -> Option<&Value> {
    if value.is_object() || value.is_array() {
        Some(value)
    } else {
        None
    }
}

fn payload_error_codes(payload: &Value) -> Vec<String> {
    payload
        .get("error_codes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(value_to_string)
        .collect()
}

fn infer_source_key(source_kind: &str) -> &str {
    match source_kind {
        "br_queue_snapshot_json" => "br_queue",
        "bv_robot_plan_json" => "bv_robot_plan",
        "agent_mail_snapshot_json" => "agent_mail",
        "rch_status_snapshot_json" => "rch_status",
        "git_state_snapshot_json" => "git_state",
        "artifact_bundle_snapshot_json" => "artifact_bundles",
        other => other,
    }
}

fn non_empty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => "null".to_string(),
        Value::Array(_) | Value::Object(_) => {
            serde_json::to_string(value).unwrap_or_else(|_| "unprintable-json-value".to_string())
        }
    }
}

fn latest_sources_by_key(sources: &[SourceSnapshot]) -> BTreeMap<String, SourceSnapshot> {
    let mut latest_sources = BTreeMap::new();
    for source in sources {
        latest_sources
            .entry(source.source_key.clone())
            .and_modify(|existing: &mut SourceSnapshot| {
                if source_snapshot_order(source, existing).is_gt() {
                    *existing = source.clone();
                }
            })
            .or_insert_with(|| source.clone());
    }
    latest_sources
}

fn source_snapshot_order(left: &SourceSnapshot, right: &SourceSnapshot) -> std::cmp::Ordering {
    left.collected_epoch_seconds
        .cmp(&right.collected_epoch_seconds)
        .then(left.source_id.cmp(&right.source_id))
}

fn source_status(source: &SourceSnapshot) -> SourceSnapshotStatus {
    SourceSnapshotStatus {
        source_key: source.source_key.clone(),
        source_id: source.source_id.clone(),
        source_kind: source.source_kind.clone(),
        schema_version: source.schema_version.clone(),
        content_hash: source.content_hash.clone(),
        collected_epoch_seconds: source.collected_epoch_seconds,
        freshness_window_seconds: source.freshness_window_seconds,
        fresh: source.fresh,
        degraded: source.degraded,
        raw_payload_ref: source.raw_payload_ref.clone(),
        local_fallback_contamination: source.local_fallback_contamination,
        error_codes: source.error_codes.clone(),
    }
}

fn stale_source_keys(sources: &[SourceSnapshot], now_epoch_seconds: i64) -> Vec<String> {
    let mut keys = sources
        .iter()
        .filter(|source| {
            !source.fresh
                || now_epoch_seconds - source.collected_epoch_seconds
                    > source.freshness_window_seconds
        })
        .map(|source| source.source_key.clone())
        .collect::<Vec<_>>();
    dedupe_sorted(&mut keys);
    keys
}

fn source_error_codes(sources: &[SourceSnapshot]) -> Vec<String> {
    let mut codes = sources
        .iter()
        .flat_map(|source| source.error_codes.iter().cloned())
        .collect::<Vec<_>>();
    dedupe_sorted(&mut codes);
    codes
}

fn payload_for<'a>(
    latest_sources: &'a BTreeMap<String, SourceSnapshot>,
    source_key: &str,
) -> Option<&'a Value> {
    latest_sources.get(source_key).map(|source| &source.payload)
}

fn br_ready_items(br_payload: Option<&Value>) -> Vec<&Value> {
    br_payload
        .and_then(|payload| {
            payload
                .get("ready")
                .and_then(Value::as_array)
                .or_else(|| payload.get("ready_issues").and_then(Value::as_array))
                .or_else(|| payload.get("items").and_then(Value::as_array))
                .or_else(|| payload.as_array())
        })
        .into_iter()
        .flatten()
        .collect()
}

fn br_in_progress_items(br_payload: Option<&Value>) -> Vec<&Value> {
    br_payload
        .and_then(|payload| {
            payload
                .pointer("/in_progress/issues")
                .and_then(Value::as_array)
                .or_else(|| payload.get("in_progress").and_then(Value::as_array))
        })
        .into_iter()
        .flatten()
        .collect()
}

fn stalled_beads<'a>(in_progress_items: &[&'a Value], now_epoch_seconds: i64) -> Vec<&'a Value> {
    in_progress_items
        .iter()
        .copied()
        .filter(|item| {
            value_i64(item.get("updated_epoch_seconds")).unwrap_or(now_epoch_seconds) + 3600
                < now_epoch_seconds
        })
        .collect()
}

fn stale_reservations(mail_payload: Option<&Value>, now_epoch_seconds: i64) -> Vec<&Value> {
    mail_payload
        .and_then(|payload| payload.get("active_reservations"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|reservation| {
            boolish(reservation.get("stale"))
                || value_i64(reservation.get("expires_epoch_seconds"))
                    .is_some_and(|expires_epoch_seconds| expires_epoch_seconds < now_epoch_seconds)
        })
        .collect()
}

fn value_i64(value: Option<&Value>) -> Option<i64> {
    value.and_then(|value| {
        value
            .as_i64()
            .or_else(|| {
                value
                    .as_u64()
                    .and_then(|unsigned| i64::try_from(unsigned).ok())
            })
            .or_else(|| value.as_str().and_then(|string| string.parse::<i64>().ok()))
    })
}

fn boolish(value: Option<&Value>) -> bool {
    value.is_some_and(|value| {
        value.as_bool().unwrap_or(false)
            || value
                .as_str()
                .is_some_and(|string| string.eq_ignore_ascii_case("true"))
    })
}

fn missing_no_mock_proof(artifact_payload: Option<&Value>) -> bool {
    artifact_payload
        .and_then(|payload| payload.get("no_mock_proof_artifacts"))
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
}

#[allow(clippy::too_many_arguments)]
fn advisory_recommendations(
    latest_sources: &BTreeMap<String, SourceSnapshot>,
    artifact_paths: &ArtifactPaths,
    ready_items: &[&Value],
    in_progress_items: &[&Value],
    stalled_beads: &[&Value],
    has_stale_reservations: bool,
    rch_contaminated: bool,
    contradictory_ownership: bool,
    dirty_worktree: bool,
    missing_no_mock: bool,
    degraded_source_refresh_needed: bool,
    max_recommendations: usize,
) -> Vec<AdvisoryRecommendation> {
    let mut recommendations = Vec::new();
    if ready_items.is_empty() && in_progress_items.is_empty() {
        recommendations.push(recommendation(
            latest_sources,
            artifact_paths,
            "shadow-rec-observe-idle-queue",
            10,
            "observe_idle_queue",
            "br ready --json",
            &["FE-SWARM-AUTOPILOT-SHADOW-IDLE-QUEUE"],
            &["br_queue", "bv_robot_plan"],
            "none",
        ));
    }
    if let Some(first_lane) = in_progress_items.first() {
        let bead_id = first_lane
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN");
        recommendations.push(recommendation(
            latest_sources,
            artifact_paths,
            "shadow-rec-continue-owned-lane",
            20,
            "continue_owned_lane",
            &format!("br show {bead_id} --json"),
            &["FE-SWARM-AUTOPILOT-SHADOW-ACTIVE-LANE"],
            &["br_queue", "bv_robot_plan"],
            "none",
        ));
    }
    if let Some(first_stalled) = stalled_beads.first() {
        let bead_id = first_stalled
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN");
        recommendations.push(recommendation(
            latest_sources,
            artifact_paths,
            "shadow-rec-review-stalled-bead",
            30,
            "review_stalled_bead",
            &format!("br show {bead_id} --json"),
            &["FE-SWARM-AUTOPILOT-SHADOW-STALED-BEAD"],
            &["br_queue", "agent_mail"],
            "degraded",
        ));
    }
    if has_stale_reservations {
        recommendations.push(recommendation(
            latest_sources,
            artifact_paths,
            "shadow-rec-review-stale-reservation",
            40,
            "review_stale_reservation",
            "br list --status=in_progress --json",
            &["FE-SWARM-AUTOPILOT-SHADOW-STALE-RESERVATION"],
            &["agent_mail"],
            "degraded",
        ));
    }
    if rch_contaminated {
        recommendations.push(recommendation(
            latest_sources,
            artifact_paths,
            "shadow-rec-rerun-rch-remote-proof",
            50,
            "rerun_rch_remote_proof",
            "RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_shadow cargo check --workspace",
            &["FE-SWARM-AUTOPILOT-SHADOW-RCH-LOCAL-FALLBACK"],
            &["rch_status"],
            "contaminated",
        ));
    }
    if contradictory_ownership {
        recommendations.push(recommendation(
            latest_sources,
            artifact_paths,
            "shadow-rec-reconcile-ownership",
            60,
            "reconcile_bead_ownership",
            "br show <conflicted-bead> --json && br list --status=in_progress --json",
            &["FE-SWARM-AUTOPILOT-SHADOW-CONTRADICTORY-OWNERSHIP"],
            &["br_queue", "agent_mail"],
            "blocked",
        ));
    }
    if dirty_worktree {
        recommendations.push(recommendation(
            latest_sources,
            artifact_paths,
            "shadow-rec-inspect-dirty-worktree",
            70,
            "inspect_dirty_worktree",
            "git status --short --branch",
            &["FE-SWARM-AUTOPILOT-SHADOW-DIRTY-WORKTREE"],
            &["git_state"],
            "degraded",
        ));
    }
    if missing_no_mock {
        recommendations.push(recommendation(
            latest_sources,
            artifact_paths,
            "shadow-rec-request-no-mock-proof",
            80,
            "request_no_mock_proof",
            "bash scripts/e2e/swarm_autopilot_no_mock_drill_smoke.sh check",
            &["FE-SWARM-AUTOPILOT-SHADOW-MISSING-NO-MOCK-PROOF"],
            &["artifact_bundles"],
            "degraded",
        ));
    }
    if degraded_source_refresh_needed {
        recommendations.push(recommendation(
            latest_sources,
            artifact_paths,
            "shadow-rec-refresh-degraded-sources",
            90,
            "refresh_degraded_sources",
            "bash scripts/e2e/swarm_autopilot_shadow_source_watchers_smoke.sh check",
            &["FE-SWARM-AUTOPILOT-SHADOW-DEGRADED-SOURCE"],
            &["agent_mail", "rch_status"],
            "degraded",
        ));
    }

    recommendations.sort_by(|left, right| {
        left.rank
            .cmp(&right.rank)
            .then(left.recommendation_id.cmp(&right.recommendation_id))
    });
    let mut seen = BTreeSet::new();
    recommendations.retain(|recommendation| seen.insert(recommendation.recommendation_id.clone()));
    recommendations.truncate(max_recommendations);
    recommendations
}

fn recommendation(
    latest_sources: &BTreeMap<String, SourceSnapshot>,
    artifact_paths: &ArtifactPaths,
    recommendation_id: &str,
    rank: u32,
    action_class: &str,
    command_text: &str,
    reason_codes: &[&str],
    source_keys: &[&str],
    degradation_state: &str,
) -> AdvisoryRecommendation {
    let evidence_sources = source_keys
        .iter()
        .filter_map(|source_key| latest_sources.get(*source_key))
        .collect::<Vec<_>>();
    AdvisoryRecommendation {
        recommendation_id: recommendation_id.to_string(),
        rank,
        action_class: action_class.to_string(),
        command_text: command_text.to_string(),
        executes_mutation: false,
        remediation_only: true,
        source_event_ids: evidence_sources
            .iter()
            .map(|source| source.source_id.clone())
            .collect(),
        source_hashes: evidence_sources
            .iter()
            .map(|source| source.content_hash.clone())
            .collect(),
        source_collected_epoch_seconds: evidence_sources
            .iter()
            .map(|source| source.collected_epoch_seconds)
            .collect(),
        degradation_state: degradation_state.to_string(),
        reason_codes: reason_codes
            .iter()
            .map(|code| (*code).to_string())
            .collect(),
        evidence_paths: vec![
            artifact_paths.shadow_status_json.clone(),
            artifact_paths.recommendations_json.clone(),
            artifact_paths.events_jsonl.clone(),
        ],
    }
}

fn render_operator_notice(
    truth_state: ShadowTruthState,
    decision: ShadowDecision,
    recommendations: &RecommendationBundle,
) -> String {
    let top_action = recommendations
        .recommendations
        .first()
        .map(|recommendation| recommendation.action_class.as_str())
        .unwrap_or("none");
    format!(
        "# Shadow Autopilot Operator Notice\n\n- truth_state: {}\n- decision: {}\n- top_action: {top_action}\n- advisory_only: true\n- proof_only: true\n- daemon_mutation: none\n",
        serde_name(truth_state),
        serde_name(decision)
    )
}

fn render_events_jsonl(
    shadow_run_id: &str,
    decision: ShadowDecision,
    artifact_paths: &ArtifactPaths,
) -> Result<String, ShadowDecisionError> {
    let input_event = serde_json::json!({
        "schema_version": SHADOW_DECISION_EVENT_SCHEMA_VERSION,
        "shadow_run_id": shadow_run_id,
        "event_name": "inputs_loaded",
        "outcome": "captured",
        "detail": "journal_events"
    });
    let output_event = serde_json::json!({
        "schema_version": SHADOW_DECISION_EVENT_SCHEMA_VERSION,
        "shadow_run_id": shadow_run_id,
        "event_name": "artifacts_written",
        "outcome": serde_name(decision),
        "detail": artifact_paths.shadow_status_json
    });
    Ok(format!(
        "{}\n{}\n",
        serde_json::to_string(&input_event)?,
        serde_json::to_string(&output_event)?
    ))
}

fn render_commands_txt() -> String {
    "frankenengine_engine::shadow_decision_composer::compose_shadow_decision\n".to_string()
}

fn render_report(artifact_paths: &ArtifactPaths) -> String {
    format!(
        "# Shadow Decision Composer\n\n- shadow_status: {}\n- recommendations: {}\n- operator_notice: {}\n- events: {}\n",
        artifact_paths.shadow_status_json,
        artifact_paths.recommendations_json,
        artifact_paths.operator_notice_md,
        artifact_paths.events_jsonl
    )
}

fn serde_name<T>(value: T) -> String
where
    T: Serialize,
{
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "unknown".to_string())
}

fn ensure_artifact_paths_under(
    output_dir: &Path,
    paths: &ArtifactPaths,
) -> Result<(), ShadowDecisionError> {
    reject_parent_dir_component("output dir", output_dir)?;
    let output_dir_is_absolute = output_dir.is_absolute();
    let artifact_paths = [
        &paths.shadow_status_json,
        &paths.recommendations_json,
        &paths.operator_notice_md,
        &paths.events_jsonl,
        &paths.commands_txt,
        &paths.report_md,
    ];
    for artifact_path in artifact_paths {
        let artifact_path = Path::new(artifact_path);
        reject_parent_dir_component("artifact path", artifact_path)?;
        if artifact_path.is_absolute() != output_dir_is_absolute || !artifact_path.starts_with(output_dir) {
            return Err(ShadowDecisionError::InvalidInput(format!(
                "artifact path `{}` is outside output dir `{}`",
                artifact_path.display(),
                output_dir.display()
            )));
        }
    }
    Ok(())
}

fn reject_parent_dir_component(label: &str, path: &Path) -> Result<(), ShadowDecisionError> {
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ShadowDecisionError::InvalidInput(format!(
            "{label} `{}` must not contain parent-directory traversal",
            path.display()
        )));
    }
    Ok(())
}

fn write_json_artifact<T>(path: &str, value: &T) -> Result<(), ShadowDecisionError>
where
    T: Serialize,
{
    fs::write(path, serde_json::to_string_pretty(value)?)?;
    Ok(())
}

fn dedupe_sorted(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_path_guard_accepts_canonical_paths_under_output_dir() {
        let output_dir = Path::new("/tmp/franken-shadow-output");
        let paths = ArtifactPaths::for_output_dir(output_dir);

        ensure_artifact_paths_under(output_dir, &paths)
            .expect("canonical artifact paths under output dir should be accepted");
    }

    #[test]
    fn artifact_path_guard_rejects_parent_dir_escape() {
        let output_dir = Path::new("/tmp/franken-shadow-output");
        let mut paths = ArtifactPaths::for_output_dir(output_dir);
        paths.shadow_status_json =
            "/tmp/franken-shadow-output/../escape/shadow_status.json".to_string();

        let err = ensure_artifact_paths_under(output_dir, &paths)
            .expect_err("parent traversal must not pass the output-dir guard");
        assert!(
            err.to_string().contains("parent-directory traversal"),
            "unexpected error: {err}"
        );
    }
}
