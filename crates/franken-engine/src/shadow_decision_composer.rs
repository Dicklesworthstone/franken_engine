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
    fmt,
    fs::{self, File, OpenOptions},
    path::{Component, Path, PathBuf},
    sync::Mutex,
};

use rustix::fs::{FlockOperation, flock};
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

const SHADOW_DECISION_BUNDLE_LOCK_FILE: &str = ".shadow_decision_composer.lock";

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

/// Global lock map for output directories to prevent concurrent writes.
static OUTPUT_DIR_LOCKS: std::sync::LazyLock<Mutex<BTreeMap<PathBuf, std::sync::Arc<Mutex<()>>>>> =
    std::sync::LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Advisory filesystem lock held for one output-dir artifact bundle write.
struct OutputDirFileLock {
    file: File,
}

impl Drop for OutputDirFileLock {
    fn drop(&mut self) {
        let _ = flock(&self.file, FlockOperation::Unlock);
    }
}

/// Acquire a process-local lock for the given output directory.
///
/// Both `OUTPUT_DIR_LOCKS` (outer map) and the per-directory inner mutex
/// recover from poisoning rather than `.unwrap()`-panicking. A panic in
/// any prior writer left the lock poisoned, but the guarded state is
/// well-defined regardless: the outer mutex protects a `BTreeMap<PathBuf,
/// Arc<Mutex<()>>>` — pure lock metadata, no torn user state — and the
/// per-directory mutex protects nothing but its own held-ness (the
/// filesystem flock + atomic-rename writes do the real serialization).
/// Before this fix, a single panic during validation / JSON serialization
/// permanently bricked the affected output directory (per-dir mutex) or,
/// for the outer map, EVERY directory, by aborting subsequent calls
/// with the `.unwrap()` on poison. (bd-ctry0)
fn acquire_output_dir_lock(output_dir: &Path) -> std::sync::Arc<Mutex<()>> {
    let canonical_path = output_dir
        .canonicalize()
        .unwrap_or_else(|_| output_dir.to_path_buf());
    let mut locks = OUTPUT_DIR_LOCKS
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    locks
        .entry(canonical_path)
        .or_insert_with(|| std::sync::Arc::new(Mutex::new(())))
        .clone()
}

/// Acquire an advisory filesystem lock for the output directory.
///
/// The persistent lock file is intentionally not deleted on release: the
/// advisory lock is tied to the open file descriptor and is released on drop.
/// Keeping the file avoids unlink races between independent writer processes.
fn acquire_output_dir_file_lock(
    output_dir: &Path,
    operation: FlockOperation,
) -> Result<OutputDirFileLock, ShadowDecisionError> {
    let lock_path = output_dir.join(SHADOW_DECISION_BUNDLE_LOCK_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    flock(&file, operation).map_err(|error| {
        ShadowDecisionError::Io(format!(
            "failed to acquire shadow decision bundle lock `{}`: {error}",
            lock_path.display()
        ))
    })?;
    Ok(OutputDirFileLock { file })
}

/// Write content to a file atomically using temp file + rename.
fn write_file_atomic(path: &str, content: &[u8]) -> Result<(), ShadowDecisionError> {
    let target_path = Path::new(path);
    let temp_path = format!("{}.tmp.{}", path, std::process::id());

    // Write to temporary file first
    fs::write(&temp_path, content)?;

    // Atomically rename to final destination
    fs::rename(&temp_path, target_path)?;

    Ok(())
}

/// Write JSON artifact atomically to prevent partial reads during concurrent writes.
fn write_json_artifact_atomic<T>(path: &str, value: &T) -> Result<(), ShadowDecisionError>
where
    T: Serialize,
{
    let json_bytes = serde_json::to_string_pretty(value)?.into_bytes();
    write_file_atomic(path, &json_bytes)
}

/// Write the composed artifacts, constrained to the provided output directory.
/// Uses per-directory locking and atomic writes to prevent concurrent write conflicts.
pub fn write_shadow_decision_artifacts(
    output_dir: impl AsRef<Path>,
    artifacts: &ShadowDecisionArtifacts,
) -> Result<(), ShadowDecisionError> {
    let output_dir = output_dir.as_ref();
    ensure_artifact_paths_under(output_dir, &artifacts.shadow_status.artifact_paths)?;
    fs::create_dir_all(output_dir)?;

    // Acquire per-directory locks to prevent concurrent writers from creating mixed bundles.
    // The in-process mutex keeps local threads ordered; the filesystem lock
    // serializes independent frankenctl/script processes targeting the same
    // output directory.
    let lock_arc = acquire_output_dir_lock(output_dir);
    // Poison recovery: see `acquire_output_dir_lock` for the rationale —
    // the inner mutex guards no user state. (bd-ctry0)
    let _process_lock = lock_arc.lock().unwrap_or_else(|poison| poison.into_inner());
    let _file_lock = acquire_output_dir_file_lock(output_dir, FlockOperation::LockExclusive)?;

    // Write non-critical files first with atomic writes
    write_file_atomic(
        &artifacts.shadow_status.artifact_paths.operator_notice_md,
        artifacts.operator_notice_md.as_bytes(),
    )?;
    write_file_atomic(
        &artifacts.shadow_status.artifact_paths.events_jsonl,
        artifacts.events_jsonl.as_bytes(),
    )?;
    write_file_atomic(
        &artifacts.shadow_status.artifact_paths.commands_txt,
        artifacts.commands_txt.as_bytes(),
    )?;
    write_file_atomic(
        &artifacts.shadow_status.artifact_paths.report_md,
        artifacts.report_md.as_bytes(),
    )?;

    // Write recommendations second-to-last
    write_json_artifact_atomic(
        &artifacts.shadow_status.artifact_paths.recommendations_json,
        &artifacts.recommendations,
    )?;

    // Write shadow_status_json last as it serves as the bundle completion signal
    write_json_artifact_atomic(
        &artifacts.shadow_status.artifact_paths.shadow_status_json,
        &artifacts.shadow_status,
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

#[allow(clippy::too_many_arguments)]
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
        if artifact_path.is_absolute() != output_dir_is_absolute
            || !artifact_path.starts_with(output_dir)
        {
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

fn dedupe_sorted(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_journal_event(
        source_key: &str,
        collected_epoch_seconds: i64,
        fresh: bool,
    ) -> JournalSourceEvent {
        JournalSourceEvent {
            source_key: Some(source_key.to_string()),
            source_id: Some(format!("{source_key}-event")),
            source_kind: Some(format!("{source_key}_snapshot_json")),
            schema_version: Some("test.source.v1".to_string()),
            content_hash: Some(format!("sha256:{source_key}")),
            collected_epoch_seconds: Some(collected_epoch_seconds),
            freshness_window_seconds: Some(300),
            fresh: Some(fresh),
            payload: Some(serde_json::json!({})),
            ..Default::default()
        }
    }

    fn complete_required_events(collected_epoch_seconds: i64) -> Vec<JournalSourceEvent> {
        REQUIRED_SHADOW_DECISION_SOURCE_KEYS
            .iter()
            .map(|source_key| test_journal_event(source_key, collected_epoch_seconds, true))
            .collect()
    }

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

    #[test]
    fn output_dir_file_lock_blocks_second_writer_until_release() {
        let output_dir = std::env::temp_dir().join(format!(
            "franken-shadow-lock-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&output_dir).expect("lock test output dir should be created");

        let first = acquire_output_dir_file_lock(&output_dir, FlockOperation::LockExclusive)
            .expect("first lock holder should acquire exclusive lock");
        let second =
            acquire_output_dir_file_lock(&output_dir, FlockOperation::NonBlockingLockExclusive);
        assert!(
            second.is_err(),
            "second writer must not acquire the bundle lock while first writer holds it"
        );

        drop(first);
        let third =
            acquire_output_dir_file_lock(&output_dir, FlockOperation::NonBlockingLockExclusive)
                .expect("bundle lock should be acquirable after the first holder drops");
        drop(third);

        assert!(
            output_dir.join(SHADOW_DECISION_BUNDLE_LOCK_FILE).is_file(),
            "persistent advisory lock file should remain for future writers"
        );
    }

    #[test]
    fn validate_input_rejects_empty_shadow_run_id() {
        let input = ShadowDecisionComposerInput {
            shadow_run_id: "".to_string(),
            source_revision: "abc123".to_string(),
            generated_epoch_seconds: 1715173200,
            default_freshness_window_seconds: 300,
            max_recommendations: 16,
            journal_events: vec![],
            existing_autopilot_outputs: vec![],
            artifact_paths: ArtifactPaths::for_output_dir("/tmp/test"),
        };

        let result = validate_input(&input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ShadowDecisionError::InvalidInput(_)));
        assert!(err.to_string().contains("shadow_run_id must not be empty"));
    }

    #[test]
    fn validate_input_rejects_negative_generated_epoch_seconds() {
        let input = ShadowDecisionComposerInput {
            shadow_run_id: "test-run-123".to_string(),
            source_revision: "abc123".to_string(),
            generated_epoch_seconds: -1,
            default_freshness_window_seconds: 300,
            max_recommendations: 16,
            journal_events: vec![],
            existing_autopilot_outputs: vec![],
            artifact_paths: ArtifactPaths::for_output_dir("/tmp/test"),
        };

        let result = validate_input(&input);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("generated_epoch_seconds must be non-negative")
        );
    }

    #[test]
    fn compose_shadow_decision_with_stale_sources_marks_blocked() {
        let now = 1715173200;
        let mut journal_events = complete_required_events(now);
        journal_events[0].collected_epoch_seconds = Some(now - 600);
        journal_events[0].fresh = Some(false);
        let stale_source_key = journal_events[0].source_key.clone().unwrap();
        let input = ShadowDecisionComposerInput {
            shadow_run_id: "test-run-123".to_string(),
            source_revision: "abc123".to_string(),
            generated_epoch_seconds: now,
            default_freshness_window_seconds: 300,
            max_recommendations: 16,
            journal_events,
            existing_autopilot_outputs: vec![],
            artifact_paths: ArtifactPaths::for_output_dir("/tmp/test"),
        };

        let result = compose_shadow_decision(&input);
        assert!(result.is_ok());
        let artifacts = result.unwrap();
        assert_eq!(
            artifacts.shadow_status.truth_state,
            ShadowTruthState::Blocked
        );
        assert_eq!(artifacts.shadow_status.decision, ShadowDecision::FailClosed);
        assert!(
            artifacts
                .shadow_status
                .stale_sources
                .contains(&stale_source_key)
        );
        assert!(
            !artifacts
                .shadow_status
                .source_snapshot_status
                .get(&stale_source_key)
                .expect("stale source status should be present")
                .fresh
        );
    }

    #[test]
    fn normalize_journal_event_handles_valid_json() {
        let event = JournalSourceEvent {
            source_key: Some("br_queue".to_string()),
            source_id: Some("br-event-1".to_string()),
            normalized_payload_json: Some(r#"{"key": "value", "number": 42}"#.to_string()),
            ..Default::default()
        };

        let result = normalize_journal_event(&event, 300);
        assert!(result.is_ok());
        let normalized = result.unwrap();
        assert_eq!(normalized.source_key, "br_queue");
        assert_eq!(normalized.source_id, "br-event-1");
        assert_eq!(normalized.payload["key"], "value");
        assert_eq!(normalized.payload["number"], 42);
    }

    #[test]
    fn normalize_journal_event_handles_invalid_json() {
        let event = JournalSourceEvent {
            normalized_payload_json: Some("invalid json {".to_string()),
            ..Default::default()
        };

        let result = normalize_journal_event(&event, 300);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ShadowDecisionError::Json(_)));
        assert!(err.to_string().contains("shadow decision JSON error"));
    }

    #[test]
    fn normalize_journal_event_empty_data_creates_empty_object() {
        let event = JournalSourceEvent::default();

        let result = normalize_journal_event(&event, 300);
        assert!(result.is_ok());
        let normalized = result.unwrap();
        assert!(normalized.payload.as_object().unwrap().is_empty());
    }

    #[test]
    fn artifact_paths_for_output_dir_creates_correct_paths() {
        let output_dir = Path::new("/test/output");
        let paths = ArtifactPaths::for_output_dir(output_dir);

        assert!(paths.shadow_status_json.contains("shadow_status.json"));
        assert!(paths.recommendations_json.contains("recommendations.json"));
        assert!(paths.shadow_status_json.starts_with("/test/output"));
        assert!(paths.recommendations_json.starts_with("/test/output"));
    }

    #[test]
    fn recommendation_artifact_paths_creates_valid_structure() {
        let paths = RecommendationArtifactPaths {
            shadow_status_json: "/test/shadow_status.json".to_string(),
            recommendations_json: "/test/recommendations.json".to_string(),
        };

        assert_eq!(paths.shadow_status_json, "/test/shadow_status.json");
        assert_eq!(paths.recommendations_json, "/test/recommendations.json");
    }

    #[test]
    fn shadow_decision_error_display_formatting() {
        let err1 = ShadowDecisionError::InvalidInput("test error".to_string());
        assert_eq!(
            err1.to_string(),
            "invalid shadow decision input: test error"
        );

        let err2 = ShadowDecisionError::Json("parse error".to_string());
        assert_eq!(err2.to_string(), "shadow decision JSON error: parse error");

        let err3 = ShadowDecisionError::Io("io error".to_string());
        assert_eq!(err3.to_string(), "shadow decision I/O error: io error");
    }

    #[test]
    fn shadow_truth_state_serialization() {
        let confirmed = ShadowTruthState::Confirmed;
        let degraded = ShadowTruthState::Degraded;
        let blocked = ShadowTruthState::Blocked;
        let contaminated = ShadowTruthState::Contaminated;

        let confirmed_json = serde_json::to_string(&confirmed).unwrap();
        let degraded_json = serde_json::to_string(&degraded).unwrap();
        let blocked_json = serde_json::to_string(&blocked).unwrap();
        let contaminated_json = serde_json::to_string(&contaminated).unwrap();

        assert_eq!(confirmed_json, r#""confirmed""#);
        assert_eq!(degraded_json, r#""degraded""#);
        assert_eq!(blocked_json, r#""blocked""#);
        assert_eq!(contaminated_json, r#""contaminated""#);

        assert_eq!(
            serde_json::from_str::<ShadowTruthState>(&confirmed_json).unwrap(),
            confirmed
        );
        assert_eq!(
            serde_json::from_str::<ShadowTruthState>(&degraded_json).unwrap(),
            degraded
        );
    }

    #[test]
    fn shadow_decision_serialization() {
        let pass = ShadowDecision::Pass;
        let degraded = ShadowDecision::Degraded;
        let fail_closed = ShadowDecision::FailClosed;

        let pass_json = serde_json::to_string(&pass).unwrap();
        let degraded_json = serde_json::to_string(&degraded).unwrap();
        let fail_closed_json = serde_json::to_string(&fail_closed).unwrap();

        assert_eq!(pass_json, r#""pass""#);
        assert_eq!(degraded_json, r#""degraded""#);
        assert_eq!(fail_closed_json, r#""fail_closed""#);

        assert_eq!(
            serde_json::from_str::<ShadowDecision>(&pass_json).unwrap(),
            pass
        );
        assert_eq!(
            serde_json::from_str::<ShadowDecision>(&fail_closed_json).unwrap(),
            fail_closed
        );
    }

    #[test]
    fn mutation_policy_defaults() {
        let policy = MutationPolicy::advisory_only();
        assert!(policy.advisory_only);
        assert!(policy.proof_only);
        assert!(!policy.mutates_br);
        assert!(!policy.reassigns_beads);
        assert!(!policy.releases_reservations);
        assert!(!policy.sends_agent_mail);
        assert!(!policy.runs_cargo);
        assert!(!policy.runs_rch);
        assert!(!policy.mutates_git);
        assert!(!policy.mutates_remote_workers);
        assert!(!policy.changes_live_queue_policy);
        assert!(!policy.writes_outside_output_dir);
    }

    #[test]
    fn sibling_reuse_creation() {
        let reuse = SiblingReuse::required();

        assert_eq!(reuse.persistence, "/dp/frankensqlite");
        assert_eq!(reuse.tui, "/dp/frankentui");
        assert_eq!(reuse.service_api, "/dp/fastapi_rust");
    }

    #[test]
    fn advisory_recommendation_structure() {
        let rec = AdvisoryRecommendation {
            recommendation_id: "rec_456".to_string(),
            rank: 5,
            action_class: "inspect".to_string(),
            command_text: "br ready --json".to_string(),
            executes_mutation: false,
            remediation_only: true,
            source_event_ids: vec!["br-event-1".to_string()],
            source_hashes: vec!["sha256:br_queue".to_string()],
            source_collected_epoch_seconds: vec![1715173200],
            degradation_state: "none".to_string(),
            reason_codes: vec!["FE-SWARM-AUTOPILOT-SHADOW-IDLE-QUEUE".to_string()],
            evidence_paths: vec!["/test/shadow_status.json".to_string()],
        };

        assert_eq!(rec.recommendation_id, "rec_456");
        assert_eq!(rec.rank, 5);
        assert_eq!(rec.command_text, "br ready --json");
        assert!(!rec.executes_mutation);
        assert!(rec.remediation_only);
        assert_eq!(rec.source_event_ids, vec!["br-event-1"]);
    }

    #[test]
    fn dedupe_sorted_removes_duplicates_and_sorts() {
        let mut values = vec![
            "c".to_string(),
            "a".to_string(),
            "b".to_string(),
            "a".to_string(),
        ];
        dedupe_sorted(&mut values);
        assert_eq!(values, vec!["a", "b", "c"]);
    }

    #[test]
    fn dedupe_sorted_handles_empty_vec() {
        let mut values: Vec<String> = vec![];
        dedupe_sorted(&mut values);
        assert!(values.is_empty());
    }

    #[test]
    fn dedupe_sorted_handles_single_item() {
        let mut values = vec!["single".to_string()];
        dedupe_sorted(&mut values);
        assert_eq!(values, vec!["single"]);
    }

    #[test]
    fn reject_parent_dir_component_accepts_safe_paths() {
        let safe_path = Path::new("safe/path/file.txt");
        let result = reject_parent_dir_component("test", safe_path);
        assert!(result.is_ok());
    }

    #[test]
    fn reject_parent_dir_component_rejects_parent_traversal() {
        let unsafe_path = Path::new("../unsafe/path/file.txt");
        let result = reject_parent_dir_component("test", unsafe_path);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("parent-directory traversal")
        );
    }

    #[test]
    fn source_snapshot_status_serialization() {
        let status = SourceSnapshotStatus {
            source_key: "br_queue".to_string(),
            source_id: "br-event-1".to_string(),
            source_kind: "br_queue_snapshot_json".to_string(),
            schema_version: "test.source.v1".to_string(),
            content_hash: "sha256:br_queue".to_string(),
            collected_epoch_seconds: 1715173200,
            freshness_window_seconds: 300,
            fresh: true,
            degraded: false,
            raw_payload_ref: "journal-events-jsonl".to_string(),
            local_fallback_contamination: false,
            error_codes: vec![],
        };

        let serialized = serde_json::to_value(&status).unwrap();
        assert_eq!(
            serialized.get("source_key").and_then(Value::as_str),
            Some("br_queue")
        );
        assert_eq!(serialized.get("fresh").and_then(Value::as_bool), Some(true));
        assert_eq!(
            serialized.get("degraded").and_then(Value::as_bool),
            Some(false)
        );
    }

    // Additional test coverage for production code paths

    #[test]
    fn normalize_journal_event_rejects_negative_default_freshness_window() {
        let event = JournalSourceEvent::default();
        let result = normalize_journal_event(&event, -10);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ShadowDecisionError::InvalidInput(_)));
        assert!(
            err.to_string()
                .contains("default freshness window must be non-negative")
        );
    }

    #[test]
    fn normalize_journal_event_rejects_negative_source_freshness_window() {
        let event = JournalSourceEvent {
            source_key: Some("test_source".to_string()),
            freshness_window_seconds: Some(-5),
            ..Default::default()
        };
        let result = normalize_journal_event(&event, 300);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("has negative freshness window"));
    }

    #[test]
    fn normalize_journal_event_handles_malformed_json_payload() {
        let event = JournalSourceEvent {
            normalized_payload_json: Some("{broken json".to_string()),
            ..Default::default()
        };
        let result = normalize_journal_event(&event, 300);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ShadowDecisionError::Json(_)));
    }

    #[test]
    fn compose_shadow_decision_with_missing_sources_produces_blocked_state() {
        let input = ShadowDecisionComposerInput {
            shadow_run_id: "test-run-123".to_string(),
            source_revision: "abc123".to_string(),
            generated_epoch_seconds: 1715173200,
            default_freshness_window_seconds: 300,
            max_recommendations: 16,
            journal_events: vec![], // Empty - missing required sources
            existing_autopilot_outputs: vec![],
            artifact_paths: ArtifactPaths::for_output_dir("/tmp/test"),
        };

        let result = compose_shadow_decision(&input);
        assert!(result.is_ok());
        let artifacts = result.unwrap();
        assert_eq!(
            artifacts.shadow_status.truth_state,
            ShadowTruthState::Blocked
        );
        assert_eq!(artifacts.shadow_status.decision, ShadowDecision::FailClosed);
        assert!(
            artifacts
                .shadow_status
                .error_codes
                .contains(&"FE-SWARM-AUTOPILOT-SHADOW-MISSING-SOURCE".to_string())
        );
    }

    #[test]
    fn compose_shadow_decision_with_contamination_produces_contaminated_state() {
        let event = JournalSourceEvent {
            source_key: Some("br_queue".to_string()),
            local_fallback_contamination: true,
            collected_epoch_seconds: Some(1715173200),
            payload: Some(serde_json::json!({})),
            ..Default::default()
        };
        let input = ShadowDecisionComposerInput {
            shadow_run_id: "test-run-123".to_string(),
            source_revision: "abc123".to_string(),
            generated_epoch_seconds: 1715173200,
            default_freshness_window_seconds: 300,
            max_recommendations: 16,
            journal_events: vec![event],
            existing_autopilot_outputs: vec![],
            artifact_paths: ArtifactPaths::for_output_dir("/tmp/test"),
        };

        let result = compose_shadow_decision(&input);
        assert!(result.is_ok());
        let artifacts = result.unwrap();
        assert_eq!(
            artifacts.shadow_status.truth_state,
            ShadowTruthState::Contaminated
        );
        assert_eq!(artifacts.shadow_status.decision, ShadowDecision::FailClosed);
    }

    #[test]
    fn compose_shadow_decision_with_stale_source_produces_blocked_state() {
        let old_timestamp = 1715173200 - 600; // 10 minutes ago
        let mut journal_events = complete_required_events(1715173200);
        journal_events[0].collected_epoch_seconds = Some(old_timestamp);
        journal_events[0].fresh = Some(false);
        let input = ShadowDecisionComposerInput {
            shadow_run_id: "test-run-123".to_string(),
            source_revision: "abc123".to_string(),
            generated_epoch_seconds: 1715173200,
            default_freshness_window_seconds: 300,
            max_recommendations: 16,
            journal_events,
            existing_autopilot_outputs: vec![],
            artifact_paths: ArtifactPaths::for_output_dir("/tmp/test"),
        };

        let result = compose_shadow_decision(&input);
        assert!(result.is_ok());
        let artifacts = result.unwrap();
        assert_eq!(
            artifacts.shadow_status.truth_state,
            ShadowTruthState::Blocked
        );
        assert_eq!(artifacts.shadow_status.decision, ShadowDecision::FailClosed);
    }

    #[test]
    fn mutation_policy_advisory_only_is_fail_closed() {
        let policy = MutationPolicy::advisory_only();

        assert!(policy.advisory_only);
        assert!(policy.proof_only);
        assert!(!policy.mutates_br);
        assert!(!policy.reassigns_beads);
        assert!(!policy.releases_reservations);
        assert!(!policy.sends_agent_mail);
        assert!(!policy.runs_cargo);
        assert!(!policy.runs_rch);
        assert!(!policy.mutates_git);
        assert!(!policy.mutates_remote_workers);
        assert!(!policy.changes_live_queue_policy);
        assert!(!policy.writes_outside_output_dir);
    }

    #[test]
    fn sibling_reuse_required_provides_expected_paths() {
        let reuse = SiblingReuse::required();

        assert_eq!(reuse.persistence, "/dp/frankensqlite");
        assert_eq!(reuse.tui, "/dp/frankentui");
        assert_eq!(reuse.service_api, "/dp/fastapi_rust");
    }

    #[test]
    fn shadow_decision_composer_input_new_creates_valid_input() {
        let events = vec![JournalSourceEvent::default()];
        let input = ShadowDecisionComposerInput::new(
            "test-run-456",
            "def789",
            1715173200,
            events,
            "/tmp/output",
        );

        assert_eq!(input.shadow_run_id, "test-run-456");
        assert_eq!(input.source_revision, "def789");
        assert_eq!(input.generated_epoch_seconds, 1715173200);
        assert_eq!(
            input.default_freshness_window_seconds,
            DEFAULT_SHADOW_DECISION_FRESHNESS_WINDOW_SECONDS
        );
        assert_eq!(
            input.max_recommendations,
            DEFAULT_SHADOW_DECISION_MAX_RECOMMENDATIONS
        );
        assert_eq!(input.journal_events.len(), 1);
        assert!(input.existing_autopilot_outputs.is_empty());
    }

    #[test]
    fn error_conversion_from_serde_json_error() {
        let json_err = serde_json::from_str::<Value>("invalid json").unwrap_err();
        let shadow_err: ShadowDecisionError = json_err.into();

        assert!(matches!(shadow_err, ShadowDecisionError::Json(_)));
        assert!(
            shadow_err
                .to_string()
                .contains("shadow decision JSON error:")
        );
    }

    #[test]
    fn error_conversion_from_io_error() {
        let io_err = std::fs::read("nonexistent_file_path_12345").unwrap_err();
        let shadow_err: ShadowDecisionError = io_err.into();

        assert!(matches!(shadow_err, ShadowDecisionError::Io(_)));
        assert!(
            shadow_err
                .to_string()
                .contains("shadow decision I/O error:")
        );
    }

    // bd-ctry0: a panic inside a writer thread used to poison the
    // per-directory mutex (and, via the outer map, every other
    // directory's slot too) so every subsequent
    // write_shadow_decision_artifacts call aborted on `.unwrap()`.
    // These pins keep the recovery wired up.

    #[test]
    fn acquire_output_dir_lock_recovers_from_outer_map_poison() {
        let dir = std::env::temp_dir().join(format!(
            "bd-ctry0-outer-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("test setup: create temp dir");

        // Force-poison the global OUTPUT_DIR_LOCKS mutex by panicking
        // inside a thread that holds the guard.
        let _ = std::thread::spawn(|| {
            let _g = OUTPUT_DIR_LOCKS.lock().expect("guard taken in poisoning thread");
            panic!("intentional panic to poison OUTPUT_DIR_LOCKS for bd-ctry0 test");
        })
        .join();
        assert!(
            OUTPUT_DIR_LOCKS.is_poisoned(),
            "the poisoning thread must have left OUTPUT_DIR_LOCKS poisoned",
        );

        // Despite the poison, the next call must succeed — pre-fix it
        // would have panicked on `.unwrap()`.
        let _lock = acquire_output_dir_lock(&dir);

        // Cleanup — drop the poison by replacing the inner map (best-effort;
        // some other test runs in the same process may re-poison it, but
        // that's fine: the recovery path always works).
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn acquire_output_dir_lock_recovers_from_inner_mutex_poison() {
        let dir = std::env::temp_dir().join(format!(
            "bd-ctry0-inner-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("test setup: create temp dir");

        // Get the per-dir Arc<Mutex<()>> and poison it from a worker thread.
        let lock_arc = acquire_output_dir_lock(&dir);
        let poisoner_arc = lock_arc.clone();
        let _ = std::thread::spawn(move || {
            let _g = poisoner_arc
                .lock()
                .expect("per-dir guard in poisoning thread");
            panic!("intentional panic to poison per-dir mutex for bd-ctry0 test");
        })
        .join();
        assert!(
            lock_arc.is_poisoned(),
            "the poisoning thread must have left the per-dir mutex poisoned",
        );

        // Pre-fix, the next .lock() in write_shadow_decision_artifacts would
        // have called `.unwrap()` and aborted the writer. Now it must
        // recover — exercise the same idiom the production path uses.
        let _guard = lock_arc.lock().unwrap_or_else(|poison| poison.into_inner());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
