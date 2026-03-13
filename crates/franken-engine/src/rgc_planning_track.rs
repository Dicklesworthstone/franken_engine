//! RGC planning-track aggregate contract and artifact emitter.
//!
//! Bead: bd-1lsy.1 [RGC-010]
//!
//! This module composes the already-versioned planning-track inputs into the
//! epic-level artifact bundle promised by the parent bead acceptance criteria:
//!
//! - `scope_contract_snapshot.json`
//! - `milestone_gatebook.json`
//! - `risk_acceptance_ledger.json`
//! - `wave_handoff_matrix.json`
//! - `run_manifest.json`
//! - `events.jsonl`
//! - `commands.txt`
//! - `summary.md`
//! - `trace_ids`

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use crate::control_plane::{DecisionId, PolicyId, TraceId};
use crate::hash_tiers::ContentHash;
use crate::rgc_execution_waves::{
    CoordinationDryRunReport, ExecutionWaveProtocol, WaveHandoffPackage,
    default_rgc_execution_wave_protocol, default_wave_handoff_package, run_coordination_dry_run,
    validate_execution_wave_protocol, validate_wave_handoff_package,
};
use crate::wave_handoff_contract::{
    HandoffEvent, HandoffPackage, HandoffValidationReport, WaveId, WaveTransitionContract,
    simulate_wave_transition,
};

pub const SCHEMA_VERSION: &str = "franken-engine.rgc-planning-track.v1";
pub const SCOPE_CONTRACT_SCHEMA_VERSION: &str = "franken-engine.rgc.scope-contract-snapshot.v1";
pub const MILESTONE_GATEBOOK_SCHEMA_VERSION: &str =
    "franken-engine.rgc.milestone-gatebook.aggregate.v1";
pub const RISK_ACCEPTANCE_LEDGER_SCHEMA_VERSION: &str =
    "franken-engine.rgc.risk-acceptance-ledger.v1";
pub const WAVE_HANDOFF_MATRIX_SCHEMA_VERSION: &str = "franken-engine.rgc.wave-handoff-matrix.v1";
pub const EVENT_SCHEMA_VERSION: &str = "franken-engine.rgc-planning-track.event.v1";
pub const BEAD_ID: &str = "bd-1lsy.1";
pub const COMPONENT: &str = "rgc_planning_track";

const TRACK_ID: &str = "RGC-010";
const TRACK_NAME: &str = "Program Contract, Scope Freeze, and Milestone Gatebook";
const SCOPE_SOURCE_JSON_PATH: &str = "docs/rgc_executable_compatibility_target_matrix_v1.json";
const MILESTONE_SOURCE_JSON_PATH: &str = "docs/rgc_milestone_gatebook_v1.json";
const RISK_SOURCE_JSON_PATH: &str = "docs/rgc_risk_register_v1.json";
const WAVE_PROTOCOL_DOC_PATH: &str = "docs/RGC_EXECUTION_WAVE_PROTOCOL.md";
const FRX_HANDOFF_DOC_PATH: &str = "docs/FRX_CROSS_TRACK_HANDOFF_PROTOCOL_V1.md";
const FRX_HANDOFF_SCHEMA_PATH: &str = "docs/frx_handoff_packet_schema_v1.json";

const RISK_EXPIRY_ERROR_CODE: &str = "FE-RGC-010-RISK-0001";
const GATE_COMMAND_ERROR_CODE: &str = "FE-RGC-010-GATE-0001";
const DEPENDENCY_ORDER_ERROR_CODE: &str = "FE-RGC-010-ORDER-0001";
const WAVE_VALIDATION_ERROR_CODE: &str = "FE-RGC-010-WAVE-0001";

const SCOPE_SOURCE_JSON: &str =
    include_str!("../../../docs/rgc_executable_compatibility_target_matrix_v1.json");
const MILESTONE_SOURCE_JSON: &str = include_str!("../../../docs/rgc_milestone_gatebook_v1.json");
const RISK_SOURCE_JSON: &str = include_str!("../../../docs/rgc_risk_register_v1.json");

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum RgcPlanningTrackError {
    Io { path: PathBuf, source: io::Error },
    JsonParse { path: PathBuf, reason: String },
    TimestampParse { field: &'static str, value: String },
    MissingLinkage { field: &'static str, key: String },
    CoordinationValidation { reason: String },
}

impl fmt::Display for RgcPlanningTrackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "I/O error at {}: {source}", path.display())
            }
            Self::JsonParse { path, reason } => {
                write!(f, "failed to parse {}: {reason}", path.display())
            }
            Self::TimestampParse { field, value } => {
                write!(f, "failed to parse timestamp for {field}: {value}")
            }
            Self::MissingLinkage { field, key } => {
                write!(f, "missing required planning linkage for {field}: {key}")
            }
            Self::CoordinationValidation { reason } => f.write_str(reason),
        }
    }
}

impl std::error::Error for RgcPlanningTrackError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackRef {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CompatibilityMatrixSource {
    schema_version: String,
    bead_id: String,
    track: TrackRef,
    scope: MatrixScopeSource,
    required_structured_log_fields: Vec<String>,
    milestone_targets: Vec<MatrixMilestoneTarget>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MatrixScopeSource {
    project_epic: String,
    snapshot_source: String,
    snapshot_generated_at_utc: String,
    open_bead_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MatrixMilestoneTarget {
    milestone: String,
    description: String,
    required_beads: Vec<String>,
    stop_go_rule: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct MilestoneGatebookSource {
    schema_version: String,
    bead_id: String,
    track: TrackRef,
    automation: GatebookAutomation,
    blocker_classes: Vec<BlockerClassSource>,
    milestones: Vec<GatebookMilestone>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct GatebookAutomation {
    required_structured_log_fields: Vec<String>,
    required_artifact_triad: Vec<String>,
    decision_event_required_fields: Vec<String>,
    default_mode: String,
    report_only_transition_rules: Vec<TransitionRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TransitionRule {
    milestone: String,
    report_only_until_utc: String,
    fail_closed_after_utc: String,
    transition_predicate: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockerClassSource {
    pub class_id: String,
    pub required_evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct GatebookMilestone {
    milestone: String,
    objective: String,
    gate_owner: String,
    pass_predicates: Vec<PassPredicateSource>,
    required_artifacts: Vec<String>,
    rollback_triggers: Vec<RollbackTriggerSource>,
    ci_gate: CiGateSource,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PassPredicateSource {
    pub predicate_id: String,
    pub description: String,
    pub metric: String,
    pub comparator: String,
    pub threshold: serde_json::Value,
    pub unit: String,
    pub source_beads: Vec<String>,
    pub evaluation_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackTriggerSource {
    pub trigger_id: String,
    pub condition_expression: String,
    pub required_probe_command: String,
    pub rollback_action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiGateSource {
    pub workflow_id: String,
    pub command: String,
    pub report_only_until_utc: String,
    pub fail_closed_after_utc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RiskRegisterSource {
    schema_version: String,
    bead_id: String,
    track: TrackRef,
    review_policy: ReviewPolicySource,
    risks: Vec<RiskEntrySource>,
    operator_verification: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReviewPolicySource {
    fail_closed_on_stale_review: bool,
    stale_threshold_days: u64,
    milestone_reviews: Vec<MilestoneReviewSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MilestoneReviewSource {
    milestone: String,
    gate_id: String,
    required_reviewers: Vec<String>,
    cadence: String,
    required_evidence_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RiskEntrySource {
    risk_id: String,
    title: String,
    domain: String,
    risk_level: String,
    owner_role: String,
    mitigation_beads: Vec<String>,
    mitigation_summary: String,
    rollback_plan: String,
    last_reviewed_utc: String,
    next_review_due_utc: String,
    milestones_pending: Vec<String>,
    open_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeContractSnapshot {
    pub schema_version: String,
    pub bead_id: String,
    pub track: TrackRef,
    pub source_bead_id: String,
    pub source_schema_version: String,
    pub project_epic: String,
    pub snapshot_generated_at_utc: String,
    pub snapshot_source: String,
    pub open_bead_ids: Vec<String>,
    pub required_structured_log_fields: Vec<String>,
    pub milestone_evidence_links: Vec<MilestoneEvidenceLink>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MilestoneEvidenceLink {
    pub milestone: String,
    pub description: String,
    pub required_beads: Vec<String>,
    pub gate_id: String,
    pub gate_command: String,
    pub required_artifacts: Vec<String>,
    pub dependent_track_evidence: Vec<String>,
    pub stop_go_rule: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanningMilestoneGatebook {
    pub schema_version: String,
    pub bead_id: String,
    pub track: TrackRef,
    pub source_bead_id: String,
    pub source_schema_version: String,
    pub blocker_classes: Vec<BlockerClassSource>,
    pub structured_log_fields: Vec<String>,
    pub required_artifact_triad: Vec<String>,
    pub decision_event_required_fields: Vec<String>,
    pub default_mode: String,
    pub dependency_order_preserved: bool,
    pub all_cargo_commands_rch_backed: bool,
    pub milestones: Vec<PlanningMilestone>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanningMilestone {
    pub milestone: String,
    pub objective: String,
    pub gate_owner: String,
    pub required_beads: Vec<String>,
    pub required_artifacts: Vec<String>,
    pub pass_predicates: Vec<PassPredicateSource>,
    pub rollback_triggers: Vec<RollbackTriggerSource>,
    pub ci_gate: CiGateSource,
    pub cargo_commands_rch_backed: bool,
    pub dependent_track_evidence: Vec<DependentTrackEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependentTrackEvidence {
    pub bead_id: String,
    pub evidence_ref: String,
    pub verification_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAcceptanceStatus {
    Current,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAcceptanceLedger {
    pub schema_version: String,
    pub bead_id: String,
    pub track: TrackRef,
    pub source_bead_id: String,
    pub source_schema_version: String,
    pub generated_at_utc: String,
    pub fail_closed_on_stale_review: bool,
    pub stale_threshold_days: u64,
    pub all_acceptances_current: bool,
    pub expired_risk_ids: Vec<String>,
    pub entries: Vec<RiskAcceptanceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAcceptanceEntry {
    pub risk_id: String,
    pub title: String,
    pub domain: String,
    pub risk_level: String,
    pub owner_role: String,
    pub mitigation_beads: Vec<String>,
    pub mitigation_summary: String,
    pub rollback_plan: String,
    pub last_reviewed_utc: String,
    pub accepted_until_utc: String,
    pub acceptance_status: RiskAcceptanceStatus,
    pub review_gate_ids: Vec<String>,
    pub review_required_evidence_fields: Vec<String>,
    pub milestones_pending: Vec<String>,
    pub open_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationState {
    pub valid: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WaveHandoffMatrix {
    pub schema_version: String,
    pub bead_id: String,
    pub track: TrackRef,
    pub source_doc_path: String,
    pub handoff_doc_path: String,
    pub handoff_schema_path: String,
    pub protocol_validation: ValidationState,
    pub handoff_validation: ValidationState,
    pub transition_validation: HandoffValidationReport,
    pub transition_events: Vec<HandoffEvent>,
    pub coordination_dry_run: CoordinationDryRunReport,
    pub protocol: ExecutionWaveProtocol,
    pub default_handoff_package: WaveHandoffPackage,
    pub transition_contract: WaveTransitionContract,
    pub dependent_track_evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanningTrackEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub artifact_ref: Option<String>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    pub schema_version: String,
    pub bead_id: String,
    pub generated_at_unix_ms: u64,
    pub generated_at_utc: String,
    pub report_hash: String,
    pub scope_contract_snapshot: String,
    pub milestone_gatebook: String,
    pub risk_acceptance_ledger: String,
    pub wave_handoff_matrix: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
    pub summary_md: String,
    pub trace_ids: String,
    pub dependency_order_preserved: bool,
    pub all_gate_commands_rch_backed: bool,
    pub all_risk_acceptances_current: bool,
    pub expired_risk_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanningTrackContractBundle {
    pub schema_version: String,
    pub bead_id: String,
    pub generated_at_unix_ms: u64,
    pub generated_at_utc: String,
    pub scope_contract_snapshot: ScopeContractSnapshot,
    pub milestone_gatebook: PlanningMilestoneGatebook,
    pub risk_acceptance_ledger: RiskAcceptanceLedger,
    pub wave_handoff_matrix: WaveHandoffMatrix,
    pub report_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RgcPlanningTrackBundleArtifacts {
    pub out_dir: PathBuf,
    pub scope_contract_snapshot_path: PathBuf,
    pub milestone_gatebook_path: PathBuf,
    pub risk_acceptance_ledger_path: PathBuf,
    pub wave_handoff_matrix_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub summary_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub report_hash: String,
    pub expired_risk_count: usize,
    pub all_gate_commands_rch_backed: bool,
}

pub fn build_rgc_planning_track_bundle_with_generated_at(
    generated_at_unix_ms: u64,
) -> Result<PlanningTrackContractBundle, RgcPlanningTrackError> {
    let generated_at = utc_from_unix_ms(generated_at_unix_ms);
    let matrix = parse_embedded_json::<CompatibilityMatrixSource>(
        SCOPE_SOURCE_JSON,
        SCOPE_SOURCE_JSON_PATH,
    )?;
    let gatebook = parse_embedded_json::<MilestoneGatebookSource>(
        MILESTONE_SOURCE_JSON,
        MILESTONE_SOURCE_JSON_PATH,
    )?;
    let risk_register =
        parse_embedded_json::<RiskRegisterSource>(RISK_SOURCE_JSON, RISK_SOURCE_JSON_PATH)?;

    let scope_contract_snapshot = build_scope_contract_snapshot(&matrix, &gatebook)?;
    let milestone_gatebook = build_milestone_gatebook(&matrix, &gatebook)?;
    let risk_acceptance_ledger = build_risk_acceptance_ledger(&risk_register, generated_at)?;
    let wave_handoff_matrix = build_wave_handoff_matrix(generated_at_unix_ms)?;

    let mut bundle = PlanningTrackContractBundle {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        generated_at_unix_ms,
        generated_at_utc: generated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        scope_contract_snapshot,
        milestone_gatebook,
        risk_acceptance_ledger,
        wave_handoff_matrix,
        report_hash: String::new(),
    };
    bundle.report_hash = compute_bundle_hash(&bundle);
    Ok(bundle)
}

pub fn write_rgc_planning_track_bundle(
    out_dir: &Path,
    argv: &[String],
) -> Result<RgcPlanningTrackBundleArtifacts, RgcPlanningTrackError> {
    let generated_at_unix_ms = current_unix_ms();
    let bundle = build_rgc_planning_track_bundle_with_generated_at(generated_at_unix_ms)?;

    let scope_contract_snapshot_path = out_dir.join("scope_contract_snapshot.json");
    let milestone_gatebook_path = out_dir.join("milestone_gatebook.json");
    let risk_acceptance_ledger_path = out_dir.join("risk_acceptance_ledger.json");
    let wave_handoff_matrix_path = out_dir.join("wave_handoff_matrix.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");
    let summary_path = out_dir.join("summary.md");
    let trace_ids_path = out_dir.join("trace_ids");

    let scope_bytes = json_pretty_bytes(
        &bundle.scope_contract_snapshot,
        &scope_contract_snapshot_path,
    )?;
    let milestone_bytes = json_pretty_bytes(&bundle.milestone_gatebook, &milestone_gatebook_path)?;
    let risk_bytes =
        json_pretty_bytes(&bundle.risk_acceptance_ledger, &risk_acceptance_ledger_path)?;
    let wave_bytes = json_pretty_bytes(&bundle.wave_handoff_matrix, &wave_handoff_matrix_path)?;

    let events = build_events(
        &bundle,
        &scope_contract_snapshot_path,
        &milestone_gatebook_path,
        &risk_acceptance_ledger_path,
        &wave_handoff_matrix_path,
    );
    let manifest = BundleManifest {
        schema_version: SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        generated_at_unix_ms: bundle.generated_at_unix_ms,
        generated_at_utc: bundle.generated_at_utc.clone(),
        report_hash: bundle.report_hash.clone(),
        scope_contract_snapshot: file_name_string(&scope_contract_snapshot_path),
        milestone_gatebook: file_name_string(&milestone_gatebook_path),
        risk_acceptance_ledger: file_name_string(&risk_acceptance_ledger_path),
        wave_handoff_matrix: file_name_string(&wave_handoff_matrix_path),
        run_manifest: file_name_string(&run_manifest_path),
        events_jsonl: file_name_string(&events_path),
        commands_txt: file_name_string(&commands_path),
        summary_md: file_name_string(&summary_path),
        trace_ids: file_name_string(&trace_ids_path),
        dependency_order_preserved: bundle.milestone_gatebook.dependency_order_preserved,
        all_gate_commands_rch_backed: bundle.milestone_gatebook.all_cargo_commands_rch_backed,
        all_risk_acceptances_current: bundle.risk_acceptance_ledger.all_acceptances_current,
        expired_risk_count: bundle.risk_acceptance_ledger.expired_risk_ids.len(),
    };
    let manifest_bytes = json_pretty_bytes(&manifest, &run_manifest_path)?;
    let events_jsonl = render_events_jsonl(&events)?;
    let commands = render_commands(out_dir, argv);
    let summary = render_summary(&bundle);
    let trace_ids = render_trace_ids(&events);

    write_atomic(&scope_contract_snapshot_path, &scope_bytes)?;
    write_atomic(&milestone_gatebook_path, &milestone_bytes)?;
    write_atomic(&risk_acceptance_ledger_path, &risk_bytes)?;
    write_atomic(&wave_handoff_matrix_path, &wave_bytes)?;
    write_atomic(&run_manifest_path, &manifest_bytes)?;
    write_atomic(&events_path, events_jsonl.as_bytes())?;
    write_atomic(&commands_path, commands.as_bytes())?;
    write_atomic(&summary_path, summary.as_bytes())?;
    write_atomic(&trace_ids_path, trace_ids.as_bytes())?;

    Ok(RgcPlanningTrackBundleArtifacts {
        out_dir: out_dir.to_path_buf(),
        scope_contract_snapshot_path,
        milestone_gatebook_path,
        risk_acceptance_ledger_path,
        wave_handoff_matrix_path,
        run_manifest_path,
        events_path,
        commands_path,
        summary_path,
        trace_ids_path,
        report_hash: bundle.report_hash,
        expired_risk_count: bundle.risk_acceptance_ledger.expired_risk_ids.len(),
        all_gate_commands_rch_backed: bundle.milestone_gatebook.all_cargo_commands_rch_backed,
    })
}

fn build_scope_contract_snapshot(
    matrix: &CompatibilityMatrixSource,
    gatebook: &MilestoneGatebookSource,
) -> Result<ScopeContractSnapshot, RgcPlanningTrackError> {
    let gatebook_by_milestone: BTreeMap<&str, &GatebookMilestone> = gatebook
        .milestones
        .iter()
        .map(|milestone| (milestone.milestone.as_str(), milestone))
        .collect();

    let milestone_evidence_links = matrix
        .milestone_targets
        .iter()
        .map(|target| {
            let gate = gatebook_by_milestone
                .get(target.milestone.as_str())
                .copied()
                .ok_or_else(|| RgcPlanningTrackError::MissingLinkage {
                    field: "gatebook.milestones",
                    key: target.milestone.clone(),
                })?;
            let mut dependent_track_evidence = gate.required_artifacts.clone();
            dependent_track_evidence.extend(
                gate.pass_predicates
                    .iter()
                    .map(|predicate| predicate.evaluation_command.clone()),
            );
            dependent_track_evidence.push(gate.ci_gate.command.clone());
            dependent_track_evidence.sort();
            dependent_track_evidence.dedup();

            Ok(MilestoneEvidenceLink {
                milestone: target.milestone.clone(),
                description: target.description.clone(),
                required_beads: target.required_beads.clone(),
                gate_id: gate.ci_gate.workflow_id.clone(),
                gate_command: gate.ci_gate.command.clone(),
                required_artifacts: gate.required_artifacts.clone(),
                dependent_track_evidence,
                stop_go_rule: target.stop_go_rule.clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ScopeContractSnapshot {
        schema_version: SCOPE_CONTRACT_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        track: TrackRef {
            id: TRACK_ID.to_string(),
            name: TRACK_NAME.to_string(),
        },
        source_bead_id: matrix.bead_id.clone(),
        source_schema_version: matrix.schema_version.clone(),
        project_epic: matrix.scope.project_epic.clone(),
        snapshot_generated_at_utc: matrix.scope.snapshot_generated_at_utc.clone(),
        snapshot_source: matrix.scope.snapshot_source.clone(),
        open_bead_ids: matrix.scope.open_bead_ids.clone(),
        required_structured_log_fields: matrix.required_structured_log_fields.clone(),
        milestone_evidence_links,
    })
}

fn build_milestone_gatebook(
    matrix: &CompatibilityMatrixSource,
    gatebook: &MilestoneGatebookSource,
) -> Result<PlanningMilestoneGatebook, RgcPlanningTrackError> {
    let matrix_by_milestone: BTreeMap<&str, &MatrixMilestoneTarget> = matrix
        .milestone_targets
        .iter()
        .map(|target| (target.milestone.as_str(), target))
        .collect();

    let expected_order = ["M1", "M2", "M3", "M4", "M5"];
    let dependency_order_preserved = gatebook
        .milestones
        .iter()
        .map(|milestone| milestone.milestone.as_str())
        .eq(expected_order.iter().copied());

    let milestones: Vec<PlanningMilestone> = gatebook
        .milestones
        .iter()
        .map(|milestone| {
            let matrix_target = matrix_by_milestone
                .get(milestone.milestone.as_str())
                .copied()
                .ok_or_else(|| RgcPlanningTrackError::MissingLinkage {
                    field: "matrix.milestone_targets",
                    key: milestone.milestone.clone(),
                })?;
            let required_beads = matrix_target.required_beads.clone();
            let dependent_track_evidence =
                milestone
                    .pass_predicates
                    .iter()
                    .flat_map(|predicate| {
                        predicate.source_beads.iter().cloned().map(|bead_id| {
                            DependentTrackEvidence {
                                bead_id,
                                evidence_ref: milestone.required_artifacts.join(", "),
                                verification_command: predicate.evaluation_command.clone(),
                            }
                        })
                    })
                    .collect::<Vec<_>>();

            let cargo_commands_rch_backed = gate_cargo_commands_rch_backed(milestone)
                .into_iter()
                .all(|valid| valid);

            Ok(PlanningMilestone {
                milestone: milestone.milestone.clone(),
                objective: milestone.objective.clone(),
                gate_owner: milestone.gate_owner.clone(),
                required_beads,
                required_artifacts: milestone.required_artifacts.clone(),
                pass_predicates: milestone.pass_predicates.clone(),
                rollback_triggers: milestone.rollback_triggers.clone(),
                ci_gate: milestone.ci_gate.clone(),
                cargo_commands_rch_backed,
                dependent_track_evidence,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let all_cargo_commands_rch_backed = milestones
        .iter()
        .all(|milestone| milestone.cargo_commands_rch_backed);

    Ok(PlanningMilestoneGatebook {
        schema_version: MILESTONE_GATEBOOK_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        track: TrackRef {
            id: TRACK_ID.to_string(),
            name: TRACK_NAME.to_string(),
        },
        source_bead_id: gatebook.bead_id.clone(),
        source_schema_version: gatebook.schema_version.clone(),
        blocker_classes: gatebook.blocker_classes.clone(),
        structured_log_fields: gatebook.automation.required_structured_log_fields.clone(),
        required_artifact_triad: gatebook.automation.required_artifact_triad.clone(),
        decision_event_required_fields: gatebook.automation.decision_event_required_fields.clone(),
        default_mode: gatebook.automation.default_mode.clone(),
        dependency_order_preserved,
        all_cargo_commands_rch_backed,
        milestones,
    })
}

fn build_risk_acceptance_ledger(
    risk_register: &RiskRegisterSource,
    generated_at: DateTime<Utc>,
) -> Result<RiskAcceptanceLedger, RgcPlanningTrackError> {
    let review_map: BTreeMap<&str, &MilestoneReviewSource> = risk_register
        .review_policy
        .milestone_reviews
        .iter()
        .map(|review| (review.milestone.as_str(), review))
        .collect();
    let mut expired_risk_ids = Vec::new();
    let mut entries = Vec::new();

    for risk in &risk_register.risks {
        let accepted_until = parse_utc_timestamp("next_review_due_utc", &risk.next_review_due_utc)?;
        let status = if accepted_until < generated_at {
            expired_risk_ids.push(risk.risk_id.clone());
            RiskAcceptanceStatus::Expired
        } else {
            RiskAcceptanceStatus::Current
        };

        let mut review_gate_ids = BTreeSet::new();
        let mut review_required_evidence_fields = BTreeSet::new();
        for milestone in &risk.milestones_pending {
            let review = review_map.get(milestone.as_str()).copied().ok_or_else(|| {
                RgcPlanningTrackError::MissingLinkage {
                    field: "review_policy.milestone_reviews",
                    key: milestone.clone(),
                }
            })?;
            review_gate_ids.insert(review.gate_id.clone());
            for field in &review.required_evidence_fields {
                review_required_evidence_fields.insert(field.clone());
            }
        }

        entries.push(RiskAcceptanceEntry {
            risk_id: risk.risk_id.clone(),
            title: risk.title.clone(),
            domain: risk.domain.clone(),
            risk_level: risk.risk_level.clone(),
            owner_role: risk.owner_role.clone(),
            mitigation_beads: risk.mitigation_beads.clone(),
            mitigation_summary: risk.mitigation_summary.clone(),
            rollback_plan: risk.rollback_plan.clone(),
            last_reviewed_utc: risk.last_reviewed_utc.clone(),
            accepted_until_utc: risk.next_review_due_utc.clone(),
            acceptance_status: status,
            review_gate_ids: review_gate_ids.into_iter().collect(),
            review_required_evidence_fields: review_required_evidence_fields.into_iter().collect(),
            milestones_pending: risk.milestones_pending.clone(),
            open_actions: risk.open_actions.clone(),
        });
    }

    Ok(RiskAcceptanceLedger {
        schema_version: RISK_ACCEPTANCE_LEDGER_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        track: TrackRef {
            id: TRACK_ID.to_string(),
            name: TRACK_NAME.to_string(),
        },
        source_bead_id: risk_register.bead_id.clone(),
        source_schema_version: risk_register.schema_version.clone(),
        generated_at_utc: generated_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        fail_closed_on_stale_review: risk_register.review_policy.fail_closed_on_stale_review,
        stale_threshold_days: risk_register.review_policy.stale_threshold_days,
        all_acceptances_current: expired_risk_ids.is_empty(),
        expired_risk_ids,
        entries,
    })
}

fn build_wave_handoff_matrix(
    generated_at_unix_ms: u64,
) -> Result<WaveHandoffMatrix, RgcPlanningTrackError> {
    let protocol = default_rgc_execution_wave_protocol();
    validate_execution_wave_protocol(&protocol).map_err(|error| {
        RgcPlanningTrackError::CoordinationValidation {
            reason: error.to_string(),
        }
    })?;

    let handoff_package = default_wave_handoff_package();
    validate_wave_handoff_package(&protocol, &handoff_package).map_err(|error| {
        RgcPlanningTrackError::CoordinationValidation {
            reason: error.to_string(),
        }
    })?;

    let trace_id = TraceId::from_parts(generated_at_unix_ms.saturating_add(41), 1).to_string();
    let decision_id =
        DecisionId::from_parts(generated_at_unix_ms.saturating_add(41), 2).to_string();
    let coordination_dry_run = run_coordination_dry_run(
        &protocol,
        &handoff_package,
        protocol.anti_stall.warn_after_seconds,
        &trace_id,
        &decision_id,
    )
    .map_err(|error| RgcPlanningTrackError::CoordinationValidation {
        reason: error.to_string(),
    })?;

    let transition_contract = WaveTransitionContract::baseline(WaveId::Wave1);
    let transition_package = HandoffPackage::baseline();
    let transition_trace =
        TraceId::from_parts(generated_at_unix_ms.saturating_add(42), 3).to_string();
    let transition_decision =
        DecisionId::from_parts(generated_at_unix_ms.saturating_add(42), 4).to_string();
    let transition_policy = PolicyId::new("rgc.planning-track.wave-handoff", 1).to_string();
    let (transition_validation, transition_events) = simulate_wave_transition(
        &transition_trace,
        &transition_decision,
        &transition_policy,
        &transition_contract,
        &transition_package,
    );

    Ok(WaveHandoffMatrix {
        schema_version: WAVE_HANDOFF_MATRIX_SCHEMA_VERSION.to_string(),
        bead_id: BEAD_ID.to_string(),
        track: TrackRef {
            id: TRACK_ID.to_string(),
            name: TRACK_NAME.to_string(),
        },
        source_doc_path: WAVE_PROTOCOL_DOC_PATH.to_string(),
        handoff_doc_path: FRX_HANDOFF_DOC_PATH.to_string(),
        handoff_schema_path: FRX_HANDOFF_SCHEMA_PATH.to_string(),
        protocol_validation: ValidationState {
            valid: true,
            detail: None,
        },
        handoff_validation: ValidationState {
            valid: true,
            detail: None,
        },
        transition_validation,
        transition_events,
        coordination_dry_run,
        protocol,
        default_handoff_package: handoff_package,
        transition_contract,
        dependent_track_evidence: vec![
            WAVE_PROTOCOL_DOC_PATH.to_string(),
            FRX_HANDOFF_DOC_PATH.to_string(),
            FRX_HANDOFF_SCHEMA_PATH.to_string(),
        ],
    })
}

fn build_events(
    bundle: &PlanningTrackContractBundle,
    scope_path: &Path,
    milestone_path: &Path,
    risk_path: &Path,
    wave_path: &Path,
) -> Vec<PlanningTrackEvent> {
    let base_ts = bundle.generated_at_unix_ms;

    let scope_order_ok = sorted_unique(&bundle.scope_contract_snapshot.open_bead_ids);
    let scope_event = event_for(
        base_ts,
        1,
        1,
        EventForInput {
            policy_name: "rgc.planning-track.scope",
            event: "scope_contract_snapshot_built",
            ok: scope_order_ok,
            error_code: if scope_order_ok {
                None
            } else {
                Some(DEPENDENCY_ORDER_ERROR_CODE)
            },
            artifact_ref: Some(scope_path),
            detail: if scope_order_ok {
                Some("scope snapshot remains sorted and duplicate-free".to_string())
            } else {
                Some("scope snapshot lost sorted/unique bead ordering".to_string())
            },
        },
    );

    let milestone_ok = bundle.milestone_gatebook.dependency_order_preserved
        && bundle.milestone_gatebook.all_cargo_commands_rch_backed;
    let milestone_error = if !bundle.milestone_gatebook.dependency_order_preserved {
        Some(DEPENDENCY_ORDER_ERROR_CODE)
    } else if !bundle.milestone_gatebook.all_cargo_commands_rch_backed {
        Some(GATE_COMMAND_ERROR_CODE)
    } else {
        None
    };
    let milestone_detail = if milestone_ok {
        Some("milestone order and cargo gate commands remain fail-closed".to_string())
    } else if !bundle.milestone_gatebook.dependency_order_preserved {
        Some("milestone order drifted away from M1..M5".to_string())
    } else {
        Some("at least one cargo-bearing milestone command is not rch-backed".to_string())
    };
    let milestone_event = event_for(
        base_ts,
        2,
        2,
        EventForInput {
            policy_name: "rgc.planning-track.gates",
            event: "milestone_gatebook_verified",
            ok: milestone_ok,
            error_code: milestone_error,
            artifact_ref: Some(milestone_path),
            detail: milestone_detail,
        },
    );

    let risk_ok = bundle.risk_acceptance_ledger.all_acceptances_current;
    let risk_detail = if risk_ok {
        Some("all risk acceptance entries remain within review window".to_string())
    } else {
        Some(format!(
            "expired risk acceptances: {}",
            bundle.risk_acceptance_ledger.expired_risk_ids.join(", ")
        ))
    };
    let risk_event = event_for(
        base_ts,
        3,
        3,
        EventForInput {
            policy_name: "rgc.planning-track.risk",
            event: "risk_acceptance_review",
            ok: risk_ok,
            error_code: if risk_ok {
                None
            } else {
                Some(RISK_EXPIRY_ERROR_CODE)
            },
            artifact_ref: Some(risk_path),
            detail: risk_detail,
        },
    );

    let wave_ok = bundle.wave_handoff_matrix.protocol_validation.valid
        && bundle.wave_handoff_matrix.handoff_validation.valid
        && bundle.wave_handoff_matrix.transition_validation.valid;
    let wave_event = event_for(
        base_ts,
        4,
        4,
        EventForInput {
            policy_name: "rgc.planning-track.wave",
            event: "wave_handoff_validated",
            ok: wave_ok,
            error_code: if wave_ok {
                None
            } else {
                Some(WAVE_VALIDATION_ERROR_CODE)
            },
            artifact_ref: Some(wave_path),
            detail: if wave_ok {
                Some(
                    "wave protocol, handoff package, and baseline transition all validated"
                        .to_string(),
                )
            } else {
                Some("wave validation failed closed".to_string())
            },
        },
    );

    let overall_ok = scope_order_ok && milestone_ok && risk_ok && wave_ok;
    let (bundle_error_code, bundle_detail) = select_bundle_failure(
        scope_order_ok,
        bundle.milestone_gatebook.dependency_order_preserved,
        bundle.milestone_gatebook.all_cargo_commands_rch_backed,
        risk_ok,
        wave_ok,
    );
    let bundle_event = event_for(
        base_ts,
        5,
        5,
        EventForInput {
            policy_name: "rgc.planning-track.bundle",
            event: "planning_track_bundle_written",
            ok: overall_ok,
            error_code: bundle_error_code,
            artifact_ref: None,
            detail: Some(format!(
                "report_hash={}; {}",
                bundle.report_hash,
                bundle_detail.unwrap_or("bundle green")
            )),
        },
    );

    vec![
        scope_event,
        milestone_event,
        risk_event,
        wave_event,
        bundle_event,
    ]
}

struct EventForInput<'a> {
    policy_name: &'a str,
    event: &'a str,
    ok: bool,
    error_code: Option<&'a str>,
    artifact_ref: Option<&'a Path>,
    detail: Option<String>,
}

fn event_for(
    generated_at_unix_ms: u64,
    trace_suffix: u64,
    decision_suffix: u64,
    input: EventForInput<'_>,
) -> PlanningTrackEvent {
    let EventForInput {
        policy_name,
        event,
        ok,
        error_code,
        artifact_ref,
        detail,
    } = input;
    PlanningTrackEvent {
        schema_version: EVENT_SCHEMA_VERSION.to_string(),
        trace_id: TraceId::from_parts(generated_at_unix_ms, u128::from(trace_suffix)).to_string(),
        decision_id: DecisionId::from_parts(generated_at_unix_ms, u128::from(decision_suffix))
            .to_string(),
        policy_id: PolicyId::new(policy_name, 1).to_string(),
        component: COMPONENT.to_string(),
        event: event.to_string(),
        outcome: if ok {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: error_code.map(ToString::to_string),
        artifact_ref: artifact_ref.map(|path| path.display().to_string()),
        detail,
    }
}

fn render_events_jsonl(events: &[PlanningTrackEvent]) -> Result<String, RgcPlanningTrackError> {
    let mut rendered = String::new();
    for event in events {
        let line =
            serde_json::to_string(event).map_err(|error| RgcPlanningTrackError::JsonParse {
                path: PathBuf::from("events.jsonl"),
                reason: error.to_string(),
            })?;
        rendered.push_str(&line);
        rendered.push('\n');
    }
    Ok(rendered)
}

fn render_commands(out_dir: &Path, argv: &[String]) -> String {
    let argv_line = render_shell_command(argv);
    let script_path = repo_root_from_manifest_dir().join("scripts/e2e/run_rgc_planning_track.sh");
    let quoted_out_dir = shell_quote(&out_dir.display().to_string());
    let quoted_script = shell_quote(&script_path.display().to_string());
    format!(
        "# Original invocation\n{argv_line}\n\n# Preferred operator wrapper (rch-backed)\n{quoted_script} {quoted_out_dir}\n\n# Direct replayable heavy verification via rch\nrch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_planning_track cargo run -p frankenengine-engine --bin franken_rgc_planning_track -- --out-dir {quoted_out_dir}\nrch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_rgc_planning_track cargo check -p frankenengine-engine --test rgc_planning_track_integration\n",
    )
}

fn render_summary(bundle: &PlanningTrackContractBundle) -> String {
    let mut summary = String::new();
    summary.push_str("# RGC Planning Track Bundle\n\n");
    summary.push_str(&format!(
        "- Report hash: `{}`\n- Dependency order preserved: `{}`\n- All gate cargo commands use `rch`: `{}`\n- All risk acceptances current: `{}`\n- Expired risks: `{}`\n\n",
        bundle.report_hash,
        bundle.milestone_gatebook.dependency_order_preserved,
        bundle.milestone_gatebook.all_cargo_commands_rch_backed,
        bundle.risk_acceptance_ledger.all_acceptances_current,
        if bundle.risk_acceptance_ledger.expired_risk_ids.is_empty() {
            "none".to_string()
        } else {
            bundle
                .risk_acceptance_ledger
                .expired_risk_ids
                .join(", ")
        }
    ));
    summary.push_str("## Emitted Artifacts\n");
    for artifact in [
        "scope_contract_snapshot.json",
        "milestone_gatebook.json",
        "risk_acceptance_ledger.json",
        "wave_handoff_matrix.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "summary.md",
        "trace_ids",
    ] {
        summary.push_str(&format!("- `{artifact}`\n"));
    }
    summary.push_str("\n## Wave Validation\n");
    summary.push_str(&format!(
        "- Coordination dry run action: `{}`\n- Transition validation passed: `{}`\n",
        bundle
            .wave_handoff_matrix
            .coordination_dry_run
            .action
            .as_str(),
        bundle.wave_handoff_matrix.transition_validation.valid
    ));
    summary
}

fn render_trace_ids(events: &[PlanningTrackEvent]) -> String {
    let mut rendered = String::new();
    for event in events {
        rendered.push_str(&event.trace_id);
        rendered.push('\n');
    }
    rendered
}

fn parse_embedded_json<T>(json: &str, path: &str) -> Result<T, RgcPlanningTrackError>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str(json).map_err(|error| RgcPlanningTrackError::JsonParse {
        path: PathBuf::from(path),
        reason: error.to_string(),
    })
}

fn parse_utc_timestamp(
    field: &'static str,
    value: &str,
) -> Result<DateTime<Utc>, RgcPlanningTrackError> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| RgcPlanningTrackError::TimestampParse {
            field,
            value: value.to_string(),
        })
}

fn gate_cargo_commands_rch_backed(milestone: &GatebookMilestone) -> Vec<bool> {
    let mut commands = milestone
        .pass_predicates
        .iter()
        .map(|predicate| predicate.evaluation_command.as_str())
        .collect::<Vec<_>>();
    commands.extend(
        milestone
            .rollback_triggers
            .iter()
            .map(|trigger| trigger.required_probe_command.as_str()),
    );
    commands.push(milestone.ci_gate.command.as_str());
    commands
        .into_iter()
        .filter(|command| command.contains("cargo "))
        .map(command_uses_rch)
        .collect()
}

fn command_uses_rch(command: &str) -> bool {
    let trimmed = command.trim();
    !trimmed.contains("cargo ") || trimmed.starts_with("rch ")
}

fn select_bundle_failure(
    scope_order_ok: bool,
    dependency_order_ok: bool,
    cargo_commands_ok: bool,
    risk_ok: bool,
    wave_ok: bool,
) -> (Option<&'static str>, Option<&'static str>) {
    if !scope_order_ok {
        (
            Some(DEPENDENCY_ORDER_ERROR_CODE),
            Some("scope snapshot ordering is invalid"),
        )
    } else if !dependency_order_ok {
        (
            Some(DEPENDENCY_ORDER_ERROR_CODE),
            Some("milestone order drifted away from M1..M5"),
        )
    } else if !cargo_commands_ok {
        (
            Some(GATE_COMMAND_ERROR_CODE),
            Some("cargo-bearing gate command is not rch-backed"),
        )
    } else if !risk_ok {
        (
            Some(RISK_EXPIRY_ERROR_CODE),
            Some("risk acceptance ledger contains expired entries"),
        )
    } else if !wave_ok {
        (
            Some(WAVE_VALIDATION_ERROR_CODE),
            Some("wave handoff validation failed"),
        )
    } else {
        (None, None)
    }
}

fn sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn compute_bundle_hash(bundle: &PlanningTrackContractBundle) -> String {
    let mut clone = bundle.clone();
    clone.report_hash.clear();
    match serde_json::to_vec(&clone) {
        Ok(bytes) => ContentHash::compute(&bytes).to_hex(),
        Err(_) => ContentHash::compute(SCHEMA_VERSION.as_bytes()).to_hex(),
    }
}

fn repo_root_from_manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

fn json_pretty_bytes<T: Serialize>(
    value: &T,
    path: &Path,
) -> Result<Vec<u8>, RgcPlanningTrackError> {
    serde_json::to_vec_pretty(value).map_err(|error| RgcPlanningTrackError::JsonParse {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

fn file_name_string(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

fn current_unix_ms() -> u64 {
    u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), RgcPlanningTrackError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| RgcPlanningTrackError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let temp_path = unique_temp_path(path);
    fs::write(&temp_path, bytes).map_err(|source| RgcPlanningTrackError::Io {
        path: temp_path.clone(),
        source,
    })?;
    fs::rename(&temp_path, path).map_err(|source| RgcPlanningTrackError::Io {
        path: path.to_path_buf(),
        source,
    })
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

fn utc_from_unix_ms(unix_ms: u64) -> DateTime<Utc> {
    let secs = i64::try_from(unix_ms / 1_000).unwrap_or(0);
    let nanos = u32::try_from((unix_ms % 1_000) * 1_000_000).unwrap_or(0);
    Utc.timestamp_opt(secs, nanos)
        .single()
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().expect("unix epoch"))
}

fn render_shell_command(argv: &[String]) -> String {
    if argv.is_empty() {
        return "franken_rgc_planning_track".to_string();
    }
    argv.iter()
        .map(|arg| shell_quote(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    if arg.bytes().all(|byte| {
        matches!(
            byte,
            b'a'..=b'z'
                | b'A'..=b'Z'
                | b'0'..=b'9'
                | b'/'
                | b'.'
                | b'_'
                | b'-'
                | b':'
                | b'='
                | b'+'
        )
    }) {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_commands_must_be_rch_wrapped() {
        assert!(command_uses_rch(
            "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target cargo test -p frankenengine-engine"
        ));
        assert!(!command_uses_rch("cargo test -p frankenengine-engine"));
        assert!(command_uses_rch("./scripts/run_phase_a_exit_gate.sh check"));
    }

    #[test]
    fn risk_acceptance_status_flips_after_due_timestamp() {
        let risk_register =
            parse_embedded_json::<RiskRegisterSource>(RISK_SOURCE_JSON, RISK_SOURCE_JSON_PATH)
                .expect("risk register");
        let before_due = Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).single().unwrap();
        let after_due = Utc.with_ymd_and_hms(2026, 3, 13, 0, 0, 0).single().unwrap();

        let before = build_risk_acceptance_ledger(&risk_register, before_due).expect("ledger");
        let after = build_risk_acceptance_ledger(&risk_register, after_due).expect("ledger");

        assert!(before.all_acceptances_current);
        assert!(!after.all_acceptances_current);
        assert!(!after.expired_risk_ids.is_empty());
    }

    #[test]
    fn scope_snapshot_order_must_be_strict() {
        assert!(sorted_unique(&[
            "bd-1lsy.1".to_string(),
            "bd-1lsy.2".to_string(),
            "bd-1lsy.3".to_string()
        ]));
        assert!(!sorted_unique(&[
            "bd-1lsy.2".to_string(),
            "bd-1lsy.1".to_string()
        ]));
        assert!(!sorted_unique(&[
            "bd-1lsy.1".to_string(),
            "bd-1lsy.1".to_string()
        ]));
    }

    #[test]
    fn bundle_failure_selection_prefers_specific_root_cause() {
        assert_eq!(
            select_bundle_failure(false, true, true, true, true),
            (
                Some(DEPENDENCY_ORDER_ERROR_CODE),
                Some("scope snapshot ordering is invalid")
            )
        );
        assert_eq!(
            select_bundle_failure(true, true, false, false, false),
            (
                Some(GATE_COMMAND_ERROR_CODE),
                Some("cargo-bearing gate command is not rch-backed")
            )
        );
        assert_eq!(
            select_bundle_failure(true, true, true, false, true),
            (
                Some(RISK_EXPIRY_ERROR_CODE),
                Some("risk acceptance ledger contains expired entries")
            )
        );
    }

    #[test]
    fn risk_acceptance_ledger_requires_review_mapping() {
        let register = RiskRegisterSource {
            schema_version: "rgc.risk-register.v1".to_string(),
            bead_id: "bd-1lsy.1.3".to_string(),
            track: TrackRef {
                id: "RGC-013".to_string(),
                name: "Risk Register".to_string(),
            },
            review_policy: ReviewPolicySource {
                fail_closed_on_stale_review: true,
                stale_threshold_days: 14,
                milestone_reviews: vec![],
            },
            risks: vec![RiskEntrySource {
                risk_id: "RISK-1".to_string(),
                title: "Missing milestone mapping".to_string(),
                domain: "governance".to_string(),
                risk_level: "high".to_string(),
                owner_role: "RuntimeLead".to_string(),
                mitigation_beads: vec!["bd-1lsy.1".to_string()],
                mitigation_summary: "none".to_string(),
                rollback_plan: "rollback".to_string(),
                last_reviewed_utc: "2026-03-01T00:00:00Z".to_string(),
                next_review_due_utc: "2026-03-10T00:00:00Z".to_string(),
                milestones_pending: vec!["M1".to_string()],
                open_actions: vec!["add mapping".to_string()],
            }],
            operator_verification: vec![],
        };

        let error = build_risk_acceptance_ledger(
            &register,
            Utc.with_ymd_and_hms(2026, 3, 2, 0, 0, 0).single().unwrap(),
        )
        .expect_err("missing review mapping must fail closed");
        assert!(matches!(
            error,
            RgcPlanningTrackError::MissingLinkage {
                field: "review_policy.milestone_reviews",
                ..
            }
        ));
    }
}
