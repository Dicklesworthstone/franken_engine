//! Runtime diagnostics and evidence export surfaces.
//!
//! This module provides deterministic, machine-readable runtime diagnostics and
//! evidence export APIs that can be wrapped by CLI entrypoints.
//!
//! Plan reference: Section 10.8 item 1 (`bd-2mm`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::containment_executor::{ContainmentReceipt, ContainmentState};
use crate::evidence_ledger::{DecisionType, EvidenceEntry};
use crate::expected_loss_selector::ContainmentAction;
use crate::hostcall_telemetry::{HostcallResult, HostcallTelemetryRecord};
use crate::module_compatibility_matrix::{CompatibilityScenarioReport, DivergenceCategory};
use crate::security_epoch::SecurityEpoch;

const COMPONENT: &str = "runtime_diagnostics_cli";
const SUPPORT_BUNDLE_SCHEMA_VERSION: &str = "franken-engine.runtime-diagnostics.support-bundle.v1";
const DEFAULT_SUPPORT_BUNDLE_REDACTION_MARKER: &str = "sha256:REDACTED";
const PREFLIGHT_DOCTOR_FAILURE_CODE: &str = "FE-RUNTIME-DIAGNOSTICS-DOCTOR-0001";
const ONBOARDING_SCORECARD_SCHEMA_VERSION: &str =
    "franken-engine.runtime-diagnostics.onboarding-scorecard.v1";
const COMPATIBILITY_ADVISORY_SCHEMA_VERSION: &str =
    "franken-engine.runtime-diagnostics.compatibility-advisory.v1";
const ROLLOUT_DECISION_ARTIFACT_SCHEMA_VERSION: &str =
    "franken-engine.runtime-diagnostics.rollout-decision-artifact.v1";
const ROLLOUT_DECISION_FAILURE_CODE: &str = "FE-RUNTIME-DIAGNOSTICS-ROLLOUT-0001";
const GA_EVIDENCE_PACKAGE_SCHEMA_VERSION: &str =
    "franken-engine.runtime-diagnostics.ga-evidence-package.v1";
const GA_EVIDENCE_PACKAGE_FAILURE_CODE: &str = "FE-RUNTIME-DIAGNOSTICS-GA-0001";

/// Stable log envelope required by plan acceptance criteria.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Severity used by evidence export filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSeverity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for EvidenceSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => f.write_str("info"),
            Self::Warning => f.write_str("warning"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

/// Parse severity from CLI/user input.
pub fn parse_evidence_severity(input: &str) -> Option<EvidenceSeverity> {
    match input.trim().to_ascii_lowercase().as_str() {
        "info" => Some(EvidenceSeverity::Info),
        "warning" => Some(EvidenceSeverity::Warning),
        "critical" => Some(EvidenceSeverity::Critical),
        _ => None,
    }
}

/// Parse decision type from CLI/user input.
pub fn parse_decision_type(input: &str) -> Option<DecisionType> {
    match input.trim().to_ascii_lowercase().as_str() {
        "security_action" => Some(DecisionType::SecurityAction),
        "policy_update" => Some(DecisionType::PolicyUpdate),
        "epoch_transition" => Some(DecisionType::EpochTransition),
        "revocation" => Some(DecisionType::Revocation),
        "extension_lifecycle" => Some(DecisionType::ExtensionLifecycle),
        "capability_decision" => Some(DecisionType::CapabilityDecision),
        "contract_evaluation" => Some(DecisionType::ContractEvaluation),
        "remote_authorization" => Some(DecisionType::RemoteAuthorization),
        _ => None,
    }
}

/// Loaded extension state in the diagnostics input surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeExtensionState {
    pub extension_id: String,
    pub containment_state: ContainmentState,
}

/// GC pressure sample for one extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcPressureSample {
    pub extension_id: String,
    pub used_bytes: u64,
    pub budget_bytes: u64,
}

/// Scheduler lane sample used to compute utilization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerLaneSample {
    pub lane: String,
    pub queue_depth: u64,
    pub max_depth: u64,
    pub tasks_submitted: u64,
    pub tasks_scheduled: u64,
    pub tasks_completed: u64,
    pub tasks_timed_out: u64,
}

/// Deterministic runtime-state input consumed by diagnostics collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStateInput {
    pub snapshot_timestamp_ns: u64,
    pub loaded_extensions: Vec<RuntimeExtensionState>,
    pub active_policies: Vec<String>,
    pub security_epoch: SecurityEpoch,
    pub gc_pressure: Vec<GcPressureSample>,
    pub scheduler_lanes: Vec<SchedulerLaneSample>,
}

/// Hostcall telemetry envelope with explicit trace/policy linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostcallTelemetryEnvelope {
    pub trace_id: String,
    pub policy_id: String,
    pub record: HostcallTelemetryRecord,
}

/// Containment receipt envelope with explicit trace/policy linkage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentReceiptEnvelope {
    pub trace_id: String,
    pub policy_id: String,
    pub receipt: ContainmentReceipt,
}

/// Replay artifact pointer exported by incident tooling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayArtifactRecord {
    pub trace_id: String,
    pub extension_id: String,
    pub timestamp_ns: u64,
    pub artifact_id: String,
    pub replay_pointer: String,
}

/// Unified input file schema consumed by the diagnostics CLI binary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeDiagnosticsCliInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub runtime_state: RuntimeStateInput,
    pub evidence_entries: Vec<EvidenceEntry>,
    pub hostcall_records: Vec<HostcallTelemetryEnvelope>,
    pub containment_receipts: Vec<ContainmentReceiptEnvelope>,
    pub replay_artifacts: Vec<ReplayArtifactRecord>,
}

/// GC pressure diagnostics row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcPressureDiagnostics {
    pub extension_id: String,
    pub used_bytes: u64,
    pub budget_bytes: u64,
    pub pressure_millionths: u64,
    pub over_budget: bool,
}

/// Scheduler lane diagnostics row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerLaneDiagnostics {
    pub lane: String,
    pub queue_depth: u64,
    pub max_depth: u64,
    pub utilization_millionths: u64,
    pub tasks_submitted: u64,
    pub tasks_scheduled: u64,
    pub tasks_completed: u64,
    pub tasks_timed_out: u64,
}

/// Output of diagnostics collection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDiagnosticsOutput {
    pub snapshot_timestamp_ns: u64,
    pub loaded_extensions: Vec<RuntimeExtensionState>,
    pub active_policies: Vec<String>,
    pub security_epoch: SecurityEpoch,
    pub gc_pressure: Vec<GcPressureDiagnostics>,
    pub scheduler_lanes: Vec<SchedulerLaneDiagnostics>,
    pub logs: Vec<StructuredLogEvent>,
}

/// Collect a deterministic runtime diagnostics snapshot.
pub fn collect_runtime_diagnostics(
    input: &RuntimeStateInput,
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
) -> RuntimeDiagnosticsOutput {
    let mut loaded_extensions = input.loaded_extensions.clone();
    loaded_extensions.sort_by(|left, right| left.extension_id.cmp(&right.extension_id));

    let active_policies = input
        .active_policies
        .iter()
        .map(|policy| policy.trim())
        .filter(|policy| !policy.is_empty())
        .map(std::string::ToString::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let mut gc_pressure = input
        .gc_pressure
        .iter()
        .map(|sample| {
            let pressure_millionths =
                compute_pressure_millionths(sample.used_bytes, sample.budget_bytes);
            GcPressureDiagnostics {
                extension_id: sample.extension_id.clone(),
                used_bytes: sample.used_bytes,
                budget_bytes: sample.budget_bytes,
                pressure_millionths,
                over_budget: sample.budget_bytes > 0 && sample.used_bytes > sample.budget_bytes,
            }
        })
        .collect::<Vec<_>>();
    gc_pressure.sort_by(|left, right| left.extension_id.cmp(&right.extension_id));

    let mut scheduler_lanes = input
        .scheduler_lanes
        .iter()
        .map(|lane| SchedulerLaneDiagnostics {
            lane: lane.lane.clone(),
            queue_depth: lane.queue_depth,
            max_depth: lane.max_depth,
            utilization_millionths: compute_pressure_millionths(lane.queue_depth, lane.max_depth),
            tasks_submitted: lane.tasks_submitted,
            tasks_scheduled: lane.tasks_scheduled,
            tasks_completed: lane.tasks_completed,
            tasks_timed_out: lane.tasks_timed_out,
        })
        .collect::<Vec<_>>();
    scheduler_lanes.sort_by(|left, right| left.lane.cmp(&right.lane));

    let logs = vec![StructuredLogEvent {
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        component: COMPONENT.to_string(),
        event: "runtime_diagnostics_snapshot".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    }];

    RuntimeDiagnosticsOutput {
        snapshot_timestamp_ns: input.snapshot_timestamp_ns,
        loaded_extensions,
        active_policies,
        security_epoch: input.security_epoch,
        gc_pressure,
        scheduler_lanes,
        logs,
    }
}

/// Render diagnostics output in a deterministic human-readable form.
pub fn render_diagnostics_summary(output: &RuntimeDiagnosticsOutput) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "snapshot_timestamp_ns: {}",
        output.snapshot_timestamp_ns
    ));
    lines.push(format!(
        "security_epoch: {}",
        output.security_epoch.as_u64()
    ));
    lines.push(format!(
        "loaded_extensions: {}",
        output.loaded_extensions.len()
    ));
    for extension in &output.loaded_extensions {
        lines.push(format!(
            "  - {} [{}]",
            extension.extension_id, extension.containment_state
        ));
    }
    lines.push(format!("active_policies: {}", output.active_policies.len()));
    for policy in &output.active_policies {
        lines.push(format!("  - {}", policy));
    }
    lines.push(format!("gc_pressure_rows: {}", output.gc_pressure.len()));
    for gc in &output.gc_pressure {
        lines.push(format!(
            "  - {} pressure={} over_budget={}",
            gc.extension_id, gc.pressure_millionths, gc.over_budget
        ));
    }
    lines.push(format!("scheduler_lanes: {}", output.scheduler_lanes.len()));
    for lane in &output.scheduler_lanes {
        lines.push(format!(
            "  - {} queue_depth={} utilization={}",
            lane.lane, lane.queue_depth, lane.utilization_millionths
        ));
    }
    lines.join("\n")
}

/// Evidence export filter surface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExportFilter {
    pub extension_id: Option<String>,
    pub trace_id: Option<String>,
    pub start_timestamp_ns: Option<u64>,
    pub end_timestamp_ns: Option<u64>,
    pub severity: Option<EvidenceSeverity>,
    pub decision_type: Option<DecisionType>,
}

impl EvidenceExportFilter {
    fn matches_timestamp(&self, timestamp_ns: u64) -> bool {
        if let Some(start) = self.start_timestamp_ns
            && timestamp_ns < start
        {
            return false;
        }
        if let Some(end) = self.end_timestamp_ns
            && timestamp_ns > end
        {
            return false;
        }
        true
    }

    fn matches_extension(&self, extension_id: &Option<String>) -> bool {
        match (&self.extension_id, extension_id) {
            (Some(expected), Some(actual)) => expected == actual,
            (Some(_), None) => false,
            (None, _) => true,
        }
    }

    fn matches_trace(&self, trace_id: &str) -> bool {
        self.trace_id
            .as_deref()
            .is_none_or(|expected| expected == trace_id)
    }

    fn matches_severity(&self, severity: EvidenceSeverity) -> bool {
        self.severity.is_none_or(|expected| severity >= expected)
    }

    fn matches_decision_type(&self, decision_type: Option<DecisionType>) -> bool {
        match (self.decision_type, decision_type) {
            (Some(expected), Some(actual)) => expected == actual,
            (Some(_), None) => false,
            (None, _) => true,
        }
    }
}

/// Canonical record kind exported by the evidence CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRecordKind {
    DecisionReceipt,
    HostcallTelemetry,
    ContainmentAction,
    PolicyChange,
    ReplayArtifact,
}

impl fmt::Display for EvidenceRecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecisionReceipt => f.write_str("decision_receipt"),
            Self::HostcallTelemetry => f.write_str("hostcall_telemetry"),
            Self::ContainmentAction => f.write_str("containment_action"),
            Self::PolicyChange => f.write_str("policy_change"),
            Self::ReplayArtifact => f.write_str("replay_artifact"),
        }
    }
}

/// One exported evidence record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceExportRecord {
    pub kind: EvidenceRecordKind,
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub extension_id: Option<String>,
    pub timestamp_ns: u64,
    pub severity: EvidenceSeverity,
    pub decision_type: Option<DecisionType>,
    pub payload: Value,
}

/// Export summary for operator and CI checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExportSummary {
    pub total_records: usize,
    pub counts_by_kind: BTreeMap<String, u64>,
    pub counts_by_severity: BTreeMap<String, u64>,
}

/// Output from evidence export command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceExportOutput {
    pub filter: EvidenceExportFilter,
    pub records: Vec<EvidenceExportRecord>,
    pub summary: EvidenceExportSummary,
    pub logs: Vec<StructuredLogEvent>,
}

/// Redaction policy for support-bundle payload sanitization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundleRedactionPolicy {
    pub key_fragments: Vec<String>,
    pub replacement: String,
}

impl Default for SupportBundleRedactionPolicy {
    fn default() -> Self {
        let mut key_fragments = vec![
            "secret".to_string(),
            "token".to_string(),
            "password".to_string(),
            "credential".to_string(),
            "private_key".to_string(),
            "signature".to_string(),
        ];
        key_fragments.sort();
        key_fragments.dedup();
        Self {
            key_fragments,
            replacement: DEFAULT_SUPPORT_BUNDLE_REDACTION_MARKER.to_string(),
        }
    }
}

impl SupportBundleRedactionPolicy {
    pub fn with_additional_fragments<I>(additional: I) -> Self
    where
        I: IntoIterator<Item = String>,
    {
        let mut policy = Self::default();
        policy.extend_fragments(additional);
        policy
    }

    pub fn extend_fragments<I>(&mut self, additional: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.key_fragments.extend(additional);
        self.key_fragments = self
            .key_fragments
            .iter()
            .map(|fragment| fragment.trim().to_ascii_lowercase())
            .filter(|fragment| !fragment.is_empty())
            .collect::<Vec<_>>();
        self.key_fragments.sort();
        self.key_fragments.dedup();
    }

    fn should_redact_key(&self, key: &str) -> bool {
        let normalized = key.trim().to_ascii_lowercase();
        self.key_fragments
            .iter()
            .any(|fragment| normalized.contains(fragment))
    }
}

/// Indexed file entry included in a support-bundle index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundleFileIndexEntry {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Machine-readable support-bundle index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundleIndex {
    pub schema_version: String,
    pub bundle_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub total_records: usize,
    pub total_redacted_fields: u64,
    pub files: Vec<SupportBundleFileIndexEntry>,
    pub reproducible_commands: Vec<String>,
}

/// Materialized support-bundle file payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundleFile {
    pub path: String,
    pub content: String,
    pub sha256: String,
    pub bytes: u64,
}

/// Deterministic support-bundle export output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SupportBundleOutput {
    pub filter: EvidenceExportFilter,
    pub redaction_policy: SupportBundleRedactionPolicy,
    pub index: SupportBundleIndex,
    pub files: Vec<SupportBundleFile>,
    pub logs: Vec<StructuredLogEvent>,
}

/// Operator-facing preflight verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightVerdict {
    Green,
    Yellow,
    Red,
}

impl PreflightVerdict {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Red => "red",
        }
    }
}

impl fmt::Display for PreflightVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}

/// Deterministic blocker surfaced by the preflight doctor command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightBlocker {
    pub blocker_id: String,
    pub severity: EvidenceSeverity,
    pub rationale: String,
    pub remediation: String,
    pub reproducible_command: String,
    pub evidence_links: Vec<String>,
}

/// Mandatory-field validation status for fail-closed gate consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightMandatoryFieldStatus {
    pub valid: bool,
    pub missing_fields: Vec<String>,
    pub inconsistent_fields: Vec<String>,
}

/// Deterministic preflight doctor output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreflightDoctorOutput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub verdict: PreflightVerdict,
    pub rationale: String,
    pub blockers: Vec<PreflightBlocker>,
    pub mandatory_field_status: PreflightMandatoryFieldStatus,
    pub diagnostics: RuntimeDiagnosticsOutput,
    pub evidence_summary: EvidenceExportSummary,
    pub support_bundle: SupportBundleOutput,
    pub logs: Vec<StructuredLogEvent>,
}

/// Rollout readiness class for onboarding scorecards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingReadinessClass {
    Ready,
    Conditional,
    Blocked,
}

impl fmt::Display for OnboardingReadinessClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ready => f.write_str("ready"),
            Self::Conditional => f.write_str("conditional"),
            Self::Blocked => f.write_str("blocked"),
        }
    }
}

/// Coarse remediation effort estimate for onboarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingRemediationEffort {
    Low,
    Medium,
    High,
}

impl fmt::Display for OnboardingRemediationEffort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => f.write_str("low"),
            Self::Medium => f.write_str("medium"),
            Self::High => f.write_str("high"),
        }
    }
}

/// Deterministic external signal merged into onboarding scorecards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingScorecardSignal {
    pub signal_id: String,
    pub source: String,
    pub severity: EvidenceSeverity,
    pub summary: String,
    pub remediation: String,
    pub reproducible_command: String,
    pub evidence_links: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_hint: Option<String>,
}

/// Coarse user-impact class for compatibility advisories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityUserImpactClass {
    BreakingBehavior,
    MigrationRequired,
    CompatibilityGap,
    EcosystemInconsistency,
    UpstreamRuntimeDrift,
}

impl fmt::Display for CompatibilityUserImpactClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BreakingBehavior => f.write_str("breaking_behavior"),
            Self::MigrationRequired => f.write_str("migration_required"),
            Self::CompatibilityGap => f.write_str("compatibility_gap"),
            Self::EcosystemInconsistency => f.write_str("ecosystem_inconsistency"),
            Self::UpstreamRuntimeDrift => f.write_str("upstream_runtime_drift"),
        }
    }
}

/// Deterministic advisory row generated from one compatibility divergence case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityAdvisoryRecord {
    pub signal_id: String,
    pub case_id: String,
    pub divergence_category: String,
    pub severity: EvidenceSeverity,
    pub user_impact: CompatibilityUserImpactClass,
    pub remediation_complexity: OnboardingRemediationEffort,
    pub guidance: String,
    pub summary: String,
    pub reproducible_command: String,
    pub evidence_links: Vec<String>,
}

/// Input contract for compatibility-advisory synthesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityAdvisoryInput {
    pub source_report: String,
    pub scenario_report: CompatibilityScenarioReport,
}

/// Output contract for compatibility-advisory synthesis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityAdvisoryOutput {
    pub schema_version: String,
    pub scenario_id: String,
    pub source_report: String,
    pub advisory_count: usize,
    pub advisories: Vec<CompatibilityAdvisoryRecord>,
    pub signals: Vec<OnboardingScorecardSignal>,
    pub logs: Vec<StructuredLogEvent>,
}

/// Input surface for deterministic onboarding-scorecard generation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnboardingScorecardInput {
    pub workload_id: String,
    pub package_name: String,
    pub target_platforms: Vec<String>,
    pub preflight: PreflightDoctorOutput,
    pub external_signals: Vec<OnboardingScorecardSignal>,
}

/// Deterministic risk breakdown used by scorecards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingScoreBreakdown {
    pub baseline_risk_millionths: u64,
    pub signal_risk_millionths: u64,
    pub total_risk_millionths: u64,
    pub critical_signals: u64,
    pub warning_signals: u64,
    pub info_signals: u64,
}

/// Ordered next-step remediation action for operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingRemediationStep {
    pub step_id: String,
    pub severity: EvidenceSeverity,
    pub summary: String,
    pub remediation: String,
    pub owner: String,
    pub reproducible_command: String,
    pub evidence_links: Vec<String>,
}

/// Deterministic onboarding scorecard output for rollout decisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnboardingScorecardOutput {
    pub schema_version: String,
    pub workload_id: String,
    pub package_name: String,
    pub target_platforms: Vec<String>,
    pub readiness: OnboardingReadinessClass,
    pub remediation_effort: OnboardingRemediationEffort,
    pub score: OnboardingScoreBreakdown,
    pub unresolved_signals: Vec<OnboardingScorecardSignal>,
    pub next_steps: Vec<OnboardingRemediationStep>,
    pub reproducible_commands: Vec<String>,
    pub logs: Vec<StructuredLogEvent>,
}

/// Recommended rollout action produced from consolidated advisory evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutRecommendation {
    Promote,
    CanaryHold,
    Rollback,
    Defer,
}

impl fmt::Display for RolloutRecommendation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Promote => f.write_str("promote"),
            Self::CanaryHold => f.write_str("canary_hold"),
            Self::Rollback => f.write_str("rollback"),
            Self::Defer => f.write_str("defer"),
        }
    }
}

/// Deterministic input for rollout-decision artifact consolidation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RolloutDecisionArtifactInput {
    pub onboarding_scorecard: OnboardingScorecardOutput,
    pub compatibility_advisories: Vec<OnboardingScorecardSignal>,
    pub platform_matrix_signals: Vec<OnboardingScorecardSignal>,
}

/// Mandatory field validation status for rollout-decision gate consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutDecisionMandatoryFieldStatus {
    pub valid: bool,
    pub missing_fields: Vec<String>,
    pub inconsistent_fields: Vec<String>,
}

/// Consolidated deterministic rollout artifact consumed by pilot/GA gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutDecisionArtifactOutput {
    pub schema_version: String,
    pub workload_id: String,
    pub package_name: String,
    pub recommendation: RolloutRecommendation,
    pub readiness: OnboardingReadinessClass,
    pub remediation_effort: OnboardingRemediationEffort,
    pub score: OnboardingScoreBreakdown,
    pub mandatory_field_status: RolloutDecisionMandatoryFieldStatus,
    pub ga_gate_consumable: bool,
    pub pilot_gate_consumable: bool,
    pub rationale: String,
    pub merged_signals: Vec<OnboardingScorecardSignal>,
    pub evidence_links: Vec<String>,
    pub reproducible_commands: Vec<String>,
    pub logs: Vec<StructuredLogEvent>,
}

/// Evidence category required by the GA evidence package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GaEvidenceArtifactCategory {
    Conformance,
    Performance,
    Security,
}

impl fmt::Display for GaEvidenceArtifactCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conformance => f.write_str("conformance"),
            Self::Performance => f.write_str("performance"),
            Self::Security => f.write_str("security"),
        }
    }
}

/// External artifact link captured by the GA evidence package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GaEvidenceArtifactLink {
    pub category: GaEvidenceArtifactCategory,
    pub path: String,
    pub description: String,
}

/// Deterministic input surface for GA evidence-package assembly.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GaEvidencePackageInput {
    pub release_candidate_id: String,
    pub support_bundle: SupportBundleOutput,
    pub onboarding_scorecard: OnboardingScorecardOutput,
    pub rollout_decision_artifact: RolloutDecisionArtifactOutput,
    pub external_evidence_links: Vec<GaEvidenceArtifactLink>,
    pub third_party_replay_commands: Vec<String>,
}

/// Fail-closed validation status for GA evidence-package consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GaEvidencePackageMandatoryFieldStatus {
    pub valid: bool,
    pub missing_fields: Vec<String>,
    pub inconsistent_fields: Vec<String>,
}

/// Consolidated rollout risk disposition embedded in the GA evidence package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GaEvidenceRiskDisposition {
    pub readiness: OnboardingReadinessClass,
    pub recommendation: RolloutRecommendation,
    pub remediation_effort: OnboardingRemediationEffort,
    pub rationale: String,
    pub critical_signals: u64,
    pub warning_signals: u64,
    pub info_signals: u64,
    pub unresolved_signal_ids: Vec<String>,
    pub next_steps: Vec<OnboardingRemediationStep>,
}

/// Machine-readable GA evidence package index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GaEvidencePackageIndex {
    pub schema_version: String,
    pub package_id: String,
    pub release_candidate_id: String,
    pub workload_id: String,
    pub package_name: String,
    pub target_platforms: Vec<String>,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub support_bundle_id: String,
    pub ga_gate_consumable: bool,
    pub total_external_artifacts: usize,
    pub files: Vec<SupportBundleFileIndexEntry>,
    pub reproducible_commands: Vec<String>,
}

/// Deterministic GA evidence package output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GaEvidencePackageOutput {
    pub schema_version: String,
    pub release_candidate_id: String,
    pub workload_id: String,
    pub package_name: String,
    pub target_platforms: Vec<String>,
    pub mandatory_field_status: GaEvidencePackageMandatoryFieldStatus,
    pub ga_gate_consumable: bool,
    pub support_bundle_id: String,
    pub risk_disposition: GaEvidenceRiskDisposition,
    pub external_evidence_links: Vec<GaEvidenceArtifactLink>,
    pub reproducible_commands: Vec<String>,
    pub index: GaEvidencePackageIndex,
    pub files: Vec<SupportBundleFile>,
    pub logs: Vec<StructuredLogEvent>,
}

/// Export deterministic evidence records from all supported sources.
pub fn export_evidence_bundle(
    input: &RuntimeDiagnosticsCliInput,
    filter: EvidenceExportFilter,
) -> EvidenceExportOutput {
    let mut records = Vec::new();

    for entry in &input.evidence_entries {
        let extension_id = entry.metadata.get("extension_id").cloned();
        let kind = if matches!(
            entry.decision_type,
            DecisionType::PolicyUpdate | DecisionType::EpochTransition
        ) {
            EvidenceRecordKind::PolicyChange
        } else {
            EvidenceRecordKind::DecisionReceipt
        };

        let record = EvidenceExportRecord {
            kind,
            trace_id: entry.trace_id.clone(),
            decision_id: Some(entry.decision_id.clone()),
            policy_id: Some(entry.policy_id.clone()),
            extension_id,
            timestamp_ns: entry.timestamp_ns,
            severity: severity_from_evidence_entry(entry),
            decision_type: Some(entry.decision_type),
            payload: serde_json::to_value(entry).expect("evidence entry must serialize"),
        };

        if matches_export_filter(&filter, &record) {
            records.push(record);
        }
    }

    for envelope in &input.hostcall_records {
        let record = EvidenceExportRecord {
            kind: EvidenceRecordKind::HostcallTelemetry,
            trace_id: envelope.trace_id.clone(),
            decision_id: envelope.record.decision_id.clone(),
            policy_id: Some(envelope.policy_id.clone()),
            extension_id: Some(envelope.record.extension_id.clone()),
            timestamp_ns: envelope.record.timestamp_ns,
            severity: severity_from_hostcall(&envelope.record.result_status),
            decision_type: None,
            payload: serde_json::to_value(&envelope.record)
                .expect("hostcall record must serialize"),
        };

        if matches_export_filter(&filter, &record) {
            records.push(record);
        }
    }

    for envelope in &input.containment_receipts {
        let record = EvidenceExportRecord {
            kind: EvidenceRecordKind::ContainmentAction,
            trace_id: envelope.trace_id.clone(),
            decision_id: envelope.receipt.metadata.get("decision_id").cloned(),
            policy_id: Some(envelope.policy_id.clone()),
            extension_id: Some(envelope.receipt.target_extension_id.clone()),
            timestamp_ns: envelope.receipt.timestamp_ns,
            severity: severity_from_containment_action(envelope.receipt.action),
            decision_type: Some(DecisionType::SecurityAction),
            payload: serde_json::to_value(&envelope.receipt)
                .expect("containment receipt must serialize"),
        };

        if matches_export_filter(&filter, &record) {
            records.push(record);
        }
    }

    for artifact in &input.replay_artifacts {
        let record = EvidenceExportRecord {
            kind: EvidenceRecordKind::ReplayArtifact,
            trace_id: artifact.trace_id.clone(),
            decision_id: None,
            policy_id: None,
            extension_id: Some(artifact.extension_id.clone()),
            timestamp_ns: artifact.timestamp_ns,
            severity: EvidenceSeverity::Info,
            decision_type: None,
            payload: serde_json::to_value(artifact).expect("replay artifact must serialize"),
        };

        if matches_export_filter(&filter, &record) {
            records.push(record);
        }
    }

    records.sort_by(|left, right| {
        left.timestamp_ns
            .cmp(&right.timestamp_ns)
            .then(left.kind.cmp(&right.kind))
            .then(left.trace_id.cmp(&right.trace_id))
            .then(left.decision_id.cmp(&right.decision_id))
            .then(left.extension_id.cmp(&right.extension_id))
    });

    let mut counts_by_kind = BTreeMap::new();
    let mut counts_by_severity = BTreeMap::new();
    for record in &records {
        *counts_by_kind.entry(record.kind.to_string()).or_insert(0) += 1;
        *counts_by_severity
            .entry(record.severity.to_string())
            .or_insert(0) += 1;
    }

    let logs = vec![StructuredLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: "evidence_export".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    }];

    EvidenceExportOutput {
        filter,
        summary: EvidenceExportSummary {
            total_records: records.len(),
            counts_by_kind,
            counts_by_severity,
        },
        records,
        logs,
    }
}

/// Render evidence export output in deterministic human-readable form.
pub fn render_evidence_summary(output: &EvidenceExportOutput) -> String {
    let mut lines = Vec::new();
    if output.records.is_empty() {
        lines.push("No evidence entries found for the specified filters.".to_string());
        return lines.join("\n");
    }

    lines.push(format!("total_records: {}", output.summary.total_records));
    lines.push("counts_by_kind:".to_string());
    for (kind, count) in &output.summary.counts_by_kind {
        lines.push(format!("  - {}={}", kind, count));
    }
    lines.push("counts_by_severity:".to_string());
    for (severity, count) in &output.summary.counts_by_severity {
        lines.push(format!("  - {}={}", severity, count));
    }
    lines.join("\n")
}

/// Export a deterministic, sanitized support bundle from runtime diagnostics input.
pub fn export_support_bundle(
    input: &RuntimeDiagnosticsCliInput,
    filter: EvidenceExportFilter,
    redaction_policy: SupportBundleRedactionPolicy,
) -> SupportBundleOutput {
    let diagnostics = collect_runtime_diagnostics(
        &input.runtime_state,
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
    );

    let mut evidence_output = export_evidence_bundle(input, filter.clone());
    let mut total_redacted_fields = 0_u64;
    for record in &mut evidence_output.records {
        let (redacted_payload, redacted_count) =
            redact_sensitive_fields(record.payload.clone(), &redaction_policy);
        record.payload = redacted_payload;
        total_redacted_fields = total_redacted_fields.saturating_add(redacted_count);
    }

    let reproducible_commands = vec![
        "runtime_diagnostics diagnostics --input <path> --summary".to_string(),
        "runtime_diagnostics export-evidence --input <path> --summary".to_string(),
        "runtime_diagnostics support-bundle --input <path> --summary".to_string(),
        "runtime_diagnostics doctor --input <path> --summary".to_string(),
    ];

    let run_manifest = serde_json::json!({
        "schema_version": SUPPORT_BUNDLE_SCHEMA_VERSION,
        "trace_id": input.trace_id,
        "decision_id": input.decision_id,
        "policy_id": input.policy_id,
        "total_records": evidence_output.summary.total_records,
        "total_redacted_fields": total_redacted_fields,
        "filter": filter,
    });

    let mut logs = evidence_output.logs.clone();
    logs.push(StructuredLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: "support_bundle_export".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    });
    logs.sort_by(|left, right| {
        left.event
            .cmp(&right.event)
            .then(left.trace_id.cmp(&right.trace_id))
            .then(left.decision_id.cmp(&right.decision_id))
            .then(left.policy_id.cmp(&right.policy_id))
    });

    let summary_md = {
        let mut lines = Vec::new();
        lines.push("# Runtime Support Bundle Summary".to_string());
        lines.push(String::new());
        lines.push(format!("- trace_id: `{}`", input.trace_id));
        lines.push(format!("- decision_id: `{}`", input.decision_id));
        lines.push(format!("- policy_id: `{}`", input.policy_id));
        lines.push(format!(
            "- total_records: `{}`",
            evidence_output.summary.total_records
        ));
        lines.push(format!(
            "- total_redacted_fields: `{}`",
            total_redacted_fields
        ));
        lines.push(String::new());
        lines.push("## Repro Commands".to_string());
        lines.push(String::new());
        for command in &reproducible_commands {
            lines.push(format!("- `{command}`"));
        }
        lines.join("\n")
    };

    let mut files = vec![
        make_support_bundle_file(
            "support_bundle/run_manifest.json",
            serde_json::to_string_pretty(&run_manifest).expect("run manifest must serialize"),
        ),
        make_support_bundle_file(
            "support_bundle/events.jsonl",
            render_support_bundle_events_jsonl(&logs),
        ),
        make_support_bundle_file(
            "support_bundle/commands.txt",
            reproducible_commands.join("\n"),
        ),
        make_support_bundle_file(
            "support_bundle/runtime_diagnostics.json",
            serde_json::to_string_pretty(&diagnostics)
                .expect("runtime diagnostics output must serialize"),
        ),
        make_support_bundle_file(
            "support_bundle/evidence_records.jsonl",
            render_evidence_records_jsonl(&evidence_output.records),
        ),
        make_support_bundle_file("support_bundle/summary.md", summary_md),
    ];

    files.sort_by(|left, right| left.path.cmp(&right.path));
    let file_index_entries = files
        .iter()
        .map(|file| SupportBundleFileIndexEntry {
            path: file.path.clone(),
            sha256: file.sha256.clone(),
            bytes: file.bytes,
        })
        .collect::<Vec<_>>();

    let bundle_id = compute_support_bundle_id(&file_index_entries, total_redacted_fields);
    let index = SupportBundleIndex {
        schema_version: SUPPORT_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id,
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        total_records: evidence_output.summary.total_records,
        total_redacted_fields,
        files: file_index_entries,
        reproducible_commands,
    };

    files.push(make_support_bundle_file(
        "support_bundle/index.json",
        serde_json::to_string_pretty(&index).expect("support bundle index must serialize"),
    ));
    files.sort_by(|left, right| left.path.cmp(&right.path));

    SupportBundleOutput {
        filter,
        redaction_policy,
        index,
        files,
        logs,
    }
}

/// Render support-bundle output in deterministic human-readable form.
pub fn render_support_bundle_summary(output: &SupportBundleOutput) -> String {
    let mut lines = Vec::new();
    lines.push(format!("bundle_id: {}", output.index.bundle_id));
    lines.push(format!("schema_version: {}", output.index.schema_version));
    lines.push(format!("trace_id: {}", output.index.trace_id));
    lines.push(format!("decision_id: {}", output.index.decision_id));
    lines.push(format!("policy_id: {}", output.index.policy_id));
    lines.push(format!("total_records: {}", output.index.total_records));
    lines.push(format!(
        "total_redacted_fields: {}",
        output.index.total_redacted_fields
    ));
    lines.push("files:".to_string());
    for file in &output.index.files {
        lines.push(format!(
            "  - {} (bytes={}, sha256={})",
            file.path, file.bytes, file.sha256
        ));
    }
    lines.push("reproducible_commands:".to_string());
    for command in &output.index.reproducible_commands {
        lines.push(format!("  - {command}"));
    }
    lines.join("\n")
}

/// Run deterministic workload preflight diagnostics and produce a fail-closed
/// readiness verdict with reproducible remediation guidance.
pub fn run_preflight_doctor(
    input: &RuntimeDiagnosticsCliInput,
    filter: EvidenceExportFilter,
    redaction_policy: SupportBundleRedactionPolicy,
) -> PreflightDoctorOutput {
    let diagnostics = collect_runtime_diagnostics(
        &input.runtime_state,
        &input.trace_id,
        &input.decision_id,
        &input.policy_id,
    );
    let evidence_output = export_evidence_bundle(input, filter.clone());
    let support_bundle = export_support_bundle(input, filter, redaction_policy);
    let mandatory_field_status =
        validate_preflight_mandatory_fields(input, &evidence_output, &support_bundle);

    let mut blockers = Vec::new();
    if !mandatory_field_status.valid {
        blockers.push(PreflightBlocker {
            blocker_id: "mandatory_field_contract".to_string(),
            severity: EvidenceSeverity::Critical,
            rationale: "required readiness fields are missing or inconsistent".to_string(),
            remediation:
                "rerun support bundle export and fix missing/inconsistent readiness fields"
                    .to_string(),
            reproducible_command: "runtime_diagnostics support-bundle --input <path> --summary"
                .to_string(),
            evidence_links: vec![
                "support_bundle/run_manifest.json".to_string(),
                "support_bundle/index.json".to_string(),
                "support_bundle/events.jsonl".to_string(),
            ],
        });
    }

    for gc in diagnostics.gc_pressure.iter().filter(|row| row.over_budget) {
        blockers.push(PreflightBlocker {
            blocker_id: format!("gc_over_budget:{}", gc.extension_id),
            severity: EvidenceSeverity::Critical,
            rationale: format!(
                "extension {} exceeds memory budget (used={} budget={})",
                gc.extension_id, gc.used_bytes, gc.budget_bytes
            ),
            remediation: "reduce heap pressure or raise deterministic budget before promotion"
                .to_string(),
            reproducible_command: "runtime_diagnostics diagnostics --input <path> --summary"
                .to_string(),
            evidence_links: vec!["support_bundle/runtime_diagnostics.json".to_string()],
        });
    }

    for lane in diagnostics
        .scheduler_lanes
        .iter()
        .filter(|row| row.tasks_timed_out > 0)
    {
        blockers.push(PreflightBlocker {
            blocker_id: format!("scheduler_timeouts:{}", lane.lane),
            severity: EvidenceSeverity::Warning,
            rationale: format!(
                "scheduler lane {} reported {} timed-out tasks",
                lane.lane, lane.tasks_timed_out
            ),
            remediation: "stabilize scheduler lane timeout behavior before rollout".to_string(),
            reproducible_command: "runtime_diagnostics diagnostics --input <path> --summary"
                .to_string(),
            evidence_links: vec!["support_bundle/runtime_diagnostics.json".to_string()],
        });
    }

    let critical_records = *evidence_output
        .summary
        .counts_by_severity
        .get("critical")
        .unwrap_or(&0);
    if critical_records > 0 {
        blockers.push(PreflightBlocker {
            blocker_id: "critical_evidence_records_present".to_string(),
            severity: EvidenceSeverity::Critical,
            rationale: format!("{critical_records} critical evidence records present"),
            remediation: "inspect critical records and resolve containment/security failures"
                .to_string(),
            reproducible_command:
                "runtime_diagnostics export-evidence --input <path> --summary --severity critical"
                    .to_string(),
            evidence_links: vec!["support_bundle/evidence_records.jsonl".to_string()],
        });
    }

    let warning_records = *evidence_output
        .summary
        .counts_by_severity
        .get("warning")
        .unwrap_or(&0);
    if warning_records > 0 {
        blockers.push(PreflightBlocker {
            blocker_id: "warning_evidence_records_present".to_string(),
            severity: EvidenceSeverity::Warning,
            rationale: format!("{warning_records} warning evidence records present"),
            remediation: "review warning records and confirm acceptable rollout posture"
                .to_string(),
            reproducible_command:
                "runtime_diagnostics export-evidence --input <path> --summary --severity warning"
                    .to_string(),
            evidence_links: vec!["support_bundle/evidence_records.jsonl".to_string()],
        });
    }

    blockers.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(left.blocker_id.cmp(&right.blocker_id))
    });

    let critical_count = blockers
        .iter()
        .filter(|blocker| blocker.severity == EvidenceSeverity::Critical)
        .count();
    let warning_count = blockers
        .iter()
        .filter(|blocker| blocker.severity == EvidenceSeverity::Warning)
        .count();

    let verdict = if critical_count > 0 {
        PreflightVerdict::Red
    } else if warning_count > 0 {
        PreflightVerdict::Yellow
    } else {
        PreflightVerdict::Green
    };

    let rationale = format!(
        "critical_blockers={} warning_blockers={} evidence_records={}",
        critical_count, warning_count, evidence_output.summary.total_records
    );

    let mut logs = diagnostics.logs.clone();
    logs.extend(evidence_output.logs.clone());
    logs.extend(support_bundle.logs.clone());
    logs.push(StructuredLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: "preflight_doctor".to_string(),
        outcome: match verdict {
            PreflightVerdict::Green => "pass".to_string(),
            PreflightVerdict::Yellow => "warn".to_string(),
            PreflightVerdict::Red => "fail".to_string(),
        },
        error_code: if verdict == PreflightVerdict::Red {
            Some(PREFLIGHT_DOCTOR_FAILURE_CODE.to_string())
        } else {
            None
        },
    });
    logs.sort_by(|left, right| {
        left.event
            .cmp(&right.event)
            .then(left.trace_id.cmp(&right.trace_id))
            .then(left.decision_id.cmp(&right.decision_id))
            .then(left.policy_id.cmp(&right.policy_id))
            .then(left.outcome.cmp(&right.outcome))
            .then(left.error_code.cmp(&right.error_code))
    });
    logs.dedup_by(|left, right| left == right);

    PreflightDoctorOutput {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        verdict,
        rationale,
        blockers,
        mandatory_field_status,
        diagnostics,
        evidence_summary: evidence_output.summary,
        support_bundle,
        logs,
    }
}

/// Render preflight output in deterministic human-readable form.
pub fn render_preflight_summary(output: &PreflightDoctorOutput) -> String {
    let mut lines = vec![
        format!("verdict: {}", output.verdict),
        format!("rationale: {}", output.rationale),
        format!(
            "mandatory_fields_valid: {}",
            output.mandatory_field_status.valid
        ),
    ];

    if !output.mandatory_field_status.missing_fields.is_empty() {
        lines.push("missing_fields:".to_string());
        for field in &output.mandatory_field_status.missing_fields {
            lines.push(format!("  - {field}"));
        }
    }

    if !output.mandatory_field_status.inconsistent_fields.is_empty() {
        lines.push("inconsistent_fields:".to_string());
        for field in &output.mandatory_field_status.inconsistent_fields {
            lines.push(format!("  - {field}"));
        }
    }

    lines.push(format!("blockers: {}", output.blockers.len()));
    for blocker in &output.blockers {
        lines.push(format!(
            "  - [{}] {} :: {}",
            blocker.severity, blocker.blocker_id, blocker.rationale
        ));
        lines.push(format!("    remediation: {}", blocker.remediation));
        lines.push(format!(
            "    reproducible_command: {}",
            blocker.reproducible_command
        ));
    }

    lines.push(format!(
        "support_bundle_id: {}",
        output.support_bundle.index.bundle_id
    ));
    lines.push("reproducible_commands:".to_string());
    for command in &output.support_bundle.index.reproducible_commands {
        lines.push(format!("  - {command}"));
    }
    lines.join("\n")
}

fn compatibility_advisory_profile(
    category: DivergenceCategory,
) -> (
    EvidenceSeverity,
    CompatibilityUserImpactClass,
    OnboardingRemediationEffort,
    &'static str,
) {
    match category {
        DivergenceCategory::EngineBug => (
            EvidenceSeverity::Critical,
            CompatibilityUserImpactClass::BreakingBehavior,
            OnboardingRemediationEffort::High,
            "treat as release blocker; patch FrankenEngine behavior and rerun lockstep evidence",
        ),
        DivergenceCategory::IntentionalImprovement => (
            EvidenceSeverity::Warning,
            CompatibilityUserImpactClass::MigrationRequired,
            OnboardingRemediationEffort::Medium,
            "document strictness/security intent and provide compat-mode migration guidance",
        ),
        DivergenceCategory::CompatibilityDebt => (
            EvidenceSeverity::Warning,
            CompatibilityUserImpactClass::CompatibilityGap,
            OnboardingRemediationEffort::High,
            "schedule compatibility remediation and add focused parity vectors before promotion",
        ),
        DivergenceCategory::EcosystemAmbiguity => (
            EvidenceSeverity::Warning,
            CompatibilityUserImpactClass::EcosystemInconsistency,
            OnboardingRemediationEffort::Medium,
            "pin deterministic policy for this edge and track upstream consensus progress",
        ),
        DivergenceCategory::ReferenceRuntimeBug => (
            EvidenceSeverity::Info,
            CompatibilityUserImpactClass::UpstreamRuntimeDrift,
            OnboardingRemediationEffort::Low,
            "link upstream bug, preserve local workaround, and keep replay evidence attached",
        ),
    }
}

/// Build deterministic compatibility advisories from scenario-report outcomes.
pub fn build_compatibility_advisories(
    input: &CompatibilityAdvisoryInput,
) -> CompatibilityAdvisoryOutput {
    let scenario_id = normalize_or_default(&input.scenario_report.scenario_id, "unknown-scenario");
    let source_report = normalize_or_default(&input.source_report, "<scenario-report.json>");
    let reproducible_command = format!(
        "runtime_diagnostics compatibility-advisories --scenario-report {} --summary",
        source_report
    );

    let mut advisories = Vec::<CompatibilityAdvisoryRecord>::new();
    let mut signals = Vec::<OnboardingScorecardSignal>::new();

    for outcome in &input.scenario_report.outcomes {
        let Some(category) = outcome.divergence_category else {
            continue;
        };
        let (severity, user_impact, remediation_complexity, fallback_guidance) =
            compatibility_advisory_profile(category);
        let guidance = normalize_or_default(
            outcome
                .actionable_guidance
                .as_deref()
                .unwrap_or(fallback_guidance),
            fallback_guidance,
        );
        let case_id = normalize_or_default(&outcome.case_id, "unknown-case");
        let signal_id = format!("compatibility:{}:{}", scenario_id, case_id);
        let summary = format!(
            "case={} category={} impact={}",
            case_id,
            category.as_str(),
            user_impact
        );
        let evidence_links = vec![
            format!("{}#scenario={}", source_report, scenario_id),
            format!("{}#case={}", source_report, case_id),
        ];
        let remediation = format!(
            "{} [impact={} remediation_complexity={}]",
            guidance, user_impact, remediation_complexity
        );

        advisories.push(CompatibilityAdvisoryRecord {
            signal_id: signal_id.clone(),
            case_id: case_id.clone(),
            divergence_category: category.as_str().to_string(),
            severity,
            user_impact,
            remediation_complexity,
            guidance: guidance.clone(),
            summary: summary.clone(),
            reproducible_command: reproducible_command.clone(),
            evidence_links: evidence_links.clone(),
        });

        signals.push(OnboardingScorecardSignal {
            signal_id,
            source: "compatibility_advisory".to_string(),
            severity,
            summary,
            remediation,
            reproducible_command: reproducible_command.clone(),
            evidence_links,
            owner_hint: Some(default_owner_for_source("compatibility_advisory", severity)),
        });
    }

    advisories.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(left.case_id.cmp(&right.case_id))
            .then(left.signal_id.cmp(&right.signal_id))
    });
    signals.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(left.signal_id.cmp(&right.signal_id))
            .then(left.source.cmp(&right.source))
    });

    let advisory_count = advisories.len();
    let logs = vec![StructuredLogEvent {
        trace_id: input.scenario_report.trace_id.clone(),
        decision_id: input.scenario_report.decision_id.clone(),
        policy_id: input.scenario_report.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: "compatibility_advisory".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    }];

    CompatibilityAdvisoryOutput {
        schema_version: COMPATIBILITY_ADVISORY_SCHEMA_VERSION.to_string(),
        scenario_id,
        source_report,
        advisory_count,
        advisories,
        signals,
        logs,
    }
}

/// Render compatibility-advisory output in deterministic human-readable form.
pub fn render_compatibility_advisory_summary(output: &CompatibilityAdvisoryOutput) -> String {
    let mut severity_counts = BTreeMap::<String, u64>::new();
    let mut category_counts = BTreeMap::<String, u64>::new();
    for advisory in &output.advisories {
        *severity_counts
            .entry(advisory.severity.to_string())
            .or_insert(0) += 1;
        *category_counts
            .entry(advisory.divergence_category.clone())
            .or_insert(0) += 1;
    }

    let mut lines = vec![
        format!("schema_version: {}", output.schema_version),
        format!("scenario_id: {}", output.scenario_id),
        format!("source_report: {}", output.source_report),
        format!("advisory_count: {}", output.advisory_count),
    ];

    lines.push("severity_counts:".to_string());
    for (severity, count) in severity_counts {
        lines.push(format!("  - {}: {}", severity, count));
    }
    lines.push("divergence_category_counts:".to_string());
    for (category, count) in category_counts {
        lines.push(format!("  - {}: {}", category, count));
    }
    lines.push("signals:".to_string());
    for signal in &output.signals {
        lines.push(format!(
            "  - [{}] {} :: {}",
            signal.severity, signal.signal_id, signal.summary
        ));
    }

    lines.join("\n")
}

/// Build a deterministic onboarding scorecard from preflight + external signals.
pub fn build_onboarding_scorecard(input: &OnboardingScorecardInput) -> OnboardingScorecardOutput {
    let mut unresolved_signals = input
        .preflight
        .blockers
        .iter()
        .map(|blocker| OnboardingScorecardSignal {
            signal_id: format!("preflight:{}", blocker.blocker_id),
            source: "preflight_doctor".to_string(),
            severity: blocker.severity,
            summary: blocker.rationale.clone(),
            remediation: blocker.remediation.clone(),
            reproducible_command: blocker.reproducible_command.clone(),
            evidence_links: blocker.evidence_links.clone(),
            owner_hint: Some(default_owner_for_source(
                "preflight_doctor",
                blocker.severity,
            )),
        })
        .collect::<Vec<_>>();
    unresolved_signals.extend(input.external_signals.clone());

    for signal in &mut unresolved_signals {
        normalize_onboarding_signal(signal);
    }

    unresolved_signals.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(left.signal_id.cmp(&right.signal_id))
            .then(left.source.cmp(&right.source))
    });

    let critical_signals = u64::try_from(
        unresolved_signals
            .iter()
            .filter(|signal| signal.severity == EvidenceSeverity::Critical)
            .count(),
    )
    .unwrap_or(u64::MAX);
    let warning_signals = u64::try_from(
        unresolved_signals
            .iter()
            .filter(|signal| signal.severity == EvidenceSeverity::Warning)
            .count(),
    )
    .unwrap_or(u64::MAX);
    let info_signals = u64::try_from(
        unresolved_signals
            .iter()
            .filter(|signal| signal.severity == EvidenceSeverity::Info)
            .count(),
    )
    .unwrap_or(u64::MAX);

    let baseline_risk_millionths: u64 = match input.preflight.verdict {
        PreflightVerdict::Green => 100_000_u64,
        PreflightVerdict::Yellow => 400_000_u64,
        PreflightVerdict::Red => 700_000_u64,
    };
    let signal_risk_millionths = critical_signals
        .saturating_mul(120_000_u64)
        .saturating_add(warning_signals.saturating_mul(50_000_u64))
        .saturating_add(info_signals.saturating_mul(10_000_u64));
    let total_risk_millionths = baseline_risk_millionths
        .saturating_add(signal_risk_millionths)
        .min(1_000_000_u64);

    let readiness = if critical_signals > 0 || total_risk_millionths >= 750_000 {
        OnboardingReadinessClass::Blocked
    } else if warning_signals > 0 || total_risk_millionths >= 350_000 {
        OnboardingReadinessClass::Conditional
    } else {
        OnboardingReadinessClass::Ready
    };

    let total_signals = u64::try_from(unresolved_signals.len()).unwrap_or(u64::MAX);
    let remediation_effort = if critical_signals >= 2 || total_signals >= 8 {
        OnboardingRemediationEffort::High
    } else if critical_signals >= 1 || warning_signals >= 3 || total_signals >= 4 {
        OnboardingRemediationEffort::Medium
    } else {
        OnboardingRemediationEffort::Low
    };

    let mut reproducible_commands = unresolved_signals
        .iter()
        .map(|signal| signal.reproducible_command.clone())
        .chain(
            input
                .preflight
                .support_bundle
                .index
                .reproducible_commands
                .iter()
                .cloned(),
        )
        .collect::<Vec<_>>();
    reproducible_commands.sort();
    reproducible_commands.dedup();

    let next_steps = unresolved_signals
        .iter()
        .take(5)
        .map(|signal| OnboardingRemediationStep {
            step_id: signal.signal_id.clone(),
            severity: signal.severity,
            summary: signal.summary.clone(),
            remediation: signal.remediation.clone(),
            owner: signal.owner_hint.clone().unwrap_or_else(|| {
                default_owner_for_source(signal.source.as_str(), signal.severity)
            }),
            reproducible_command: signal.reproducible_command.clone(),
            evidence_links: signal.evidence_links.clone(),
        })
        .collect::<Vec<_>>();

    let mut target_platforms = input
        .target_platforms
        .iter()
        .map(|platform| platform.trim())
        .filter(|platform| !platform.is_empty())
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>();
    target_platforms.sort();
    target_platforms.dedup();

    let logs = vec![StructuredLogEvent {
        trace_id: input.preflight.trace_id.clone(),
        decision_id: input.preflight.decision_id.clone(),
        policy_id: input.preflight.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: "onboarding_scorecard".to_string(),
        outcome: if readiness == OnboardingReadinessClass::Blocked {
            "fail".to_string()
        } else {
            "pass".to_string()
        },
        error_code: if readiness == OnboardingReadinessClass::Blocked {
            Some(PREFLIGHT_DOCTOR_FAILURE_CODE.to_string())
        } else {
            None
        },
    }];

    OnboardingScorecardOutput {
        schema_version: ONBOARDING_SCORECARD_SCHEMA_VERSION.to_string(),
        workload_id: normalize_or_default(&input.workload_id, "unknown-workload"),
        package_name: normalize_or_default(&input.package_name, "unknown-package"),
        target_platforms,
        readiness,
        remediation_effort,
        score: OnboardingScoreBreakdown {
            baseline_risk_millionths,
            signal_risk_millionths,
            total_risk_millionths,
            critical_signals,
            warning_signals,
            info_signals,
        },
        unresolved_signals,
        next_steps,
        reproducible_commands,
        logs,
    }
}

/// Render onboarding scorecard output in deterministic human-readable form.
pub fn render_onboarding_scorecard_summary(output: &OnboardingScorecardOutput) -> String {
    let mut lines = vec![
        format!("schema_version: {}", output.schema_version),
        format!("workload_id: {}", output.workload_id),
        format!("package_name: {}", output.package_name),
        format!("readiness: {}", output.readiness),
        format!("remediation_effort: {}", output.remediation_effort),
        format!(
            "risk_total_millionths: {}",
            output.score.total_risk_millionths
        ),
        format!(
            "signals: critical={} warning={} info={}",
            output.score.critical_signals, output.score.warning_signals, output.score.info_signals
        ),
    ];

    if !output.target_platforms.is_empty() {
        lines.push("target_platforms:".to_string());
        for platform in &output.target_platforms {
            lines.push(format!("  - {platform}"));
        }
    }

    lines.push(format!("next_steps: {}", output.next_steps.len()));
    for step in &output.next_steps {
        lines.push(format!(
            "  - [{}] {} owner={} cmd={}",
            step.severity, step.step_id, step.owner, step.reproducible_command
        ));
    }

    lines.push("reproducible_commands:".to_string());
    for command in &output.reproducible_commands {
        lines.push(format!("  - {command}"));
    }

    lines.join("\n")
}

/// Build a deterministic consolidated rollout decision artifact.
pub fn build_rollout_decision_artifact(
    input: &RolloutDecisionArtifactInput,
) -> RolloutDecisionArtifactOutput {
    let mut merged_by_key = BTreeMap::<String, OnboardingScorecardSignal>::new();
    for mut signal in input
        .onboarding_scorecard
        .unresolved_signals
        .iter()
        .cloned()
        .chain(input.compatibility_advisories.iter().cloned())
        .chain(input.platform_matrix_signals.iter().cloned())
    {
        normalize_onboarding_signal(&mut signal);
        let key = rollout_signal_key(&signal);
        if let Some(existing) = merged_by_key.get_mut(&key) {
            merge_rollout_signal(existing, signal);
        } else {
            merged_by_key.insert(key, signal);
        }
    }

    let mut merged_signals = merged_by_key.into_values().collect::<Vec<_>>();
    merged_signals.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then(left.source.cmp(&right.source))
            .then(left.signal_id.cmp(&right.signal_id))
    });

    let critical_signals = merged_signals
        .iter()
        .filter(|signal| signal.severity == EvidenceSeverity::Critical)
        .count();
    let warning_signals = merged_signals
        .iter()
        .filter(|signal| signal.severity == EvidenceSeverity::Warning)
        .count();
    let has_compatibility_critical = merged_signals.iter().any(|signal| {
        signal.source == "compatibility_advisory" && signal.severity == EvidenceSeverity::Critical
    });
    let has_platform_critical = merged_signals.iter().any(|signal| {
        signal.source == "platform_matrix" && signal.severity == EvidenceSeverity::Critical
    });

    let mut evidence_links = merged_signals
        .iter()
        .flat_map(|signal| signal.evidence_links.iter().cloned())
        .collect::<Vec<_>>();
    evidence_links.sort();
    evidence_links.dedup();
    if evidence_links.is_empty() {
        evidence_links.push("support_bundle/preflight_report.json".to_string());
    }

    let mut reproducible_commands = input.onboarding_scorecard.reproducible_commands.clone();
    reproducible_commands.extend(
        merged_signals
            .iter()
            .map(|signal| signal.reproducible_command.clone()),
    );
    reproducible_commands.sort();
    reproducible_commands.dedup();
    if reproducible_commands.is_empty() {
        reproducible_commands
            .push("runtime_diagnostics doctor --input <path> --summary".to_string());
    }

    let mandatory_field_status = validate_rollout_decision_mandatory_fields(
        &input.onboarding_scorecard,
        &merged_signals,
        &evidence_links,
        &reproducible_commands,
    );
    let recommendation = choose_rollout_recommendation(
        input.onboarding_scorecard.readiness,
        critical_signals,
        warning_signals,
        has_compatibility_critical,
        has_platform_critical,
        mandatory_field_status.valid,
    );
    let gate_consumable = mandatory_field_status.valid;

    let rationale = format!(
        "recommendation={} readiness={} critical_signals={} warning_signals={} mandatory_fields_valid={}",
        recommendation,
        input.onboarding_scorecard.readiness,
        critical_signals,
        warning_signals,
        mandatory_field_status.valid
    );

    let logs = vec![StructuredLogEvent {
        trace_id: input
            .onboarding_scorecard
            .logs
            .first()
            .map(|log| log.trace_id.clone())
            .unwrap_or_else(|| "unknown-trace".to_string()),
        decision_id: input
            .onboarding_scorecard
            .logs
            .first()
            .map(|log| log.decision_id.clone())
            .unwrap_or_else(|| "unknown-decision".to_string()),
        policy_id: input
            .onboarding_scorecard
            .logs
            .first()
            .map(|log| log.policy_id.clone())
            .unwrap_or_else(|| "unknown-policy".to_string()),
        component: COMPONENT.to_string(),
        event: "rollout_decision_artifact".to_string(),
        outcome: if gate_consumable {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if gate_consumable {
            None
        } else {
            Some(ROLLOUT_DECISION_FAILURE_CODE.to_string())
        },
    }];

    RolloutDecisionArtifactOutput {
        schema_version: ROLLOUT_DECISION_ARTIFACT_SCHEMA_VERSION.to_string(),
        workload_id: input.onboarding_scorecard.workload_id.clone(),
        package_name: input.onboarding_scorecard.package_name.clone(),
        recommendation,
        readiness: input.onboarding_scorecard.readiness,
        remediation_effort: input.onboarding_scorecard.remediation_effort,
        score: input.onboarding_scorecard.score.clone(),
        mandatory_field_status,
        ga_gate_consumable: gate_consumable,
        pilot_gate_consumable: gate_consumable,
        rationale,
        merged_signals,
        evidence_links,
        reproducible_commands,
        logs,
    }
}

/// Render rollout-decision artifact output in deterministic human-readable form.
pub fn render_rollout_decision_artifact_summary(output: &RolloutDecisionArtifactOutput) -> String {
    let mut lines = vec![
        format!("schema_version: {}", output.schema_version),
        format!("workload_id: {}", output.workload_id),
        format!("package_name: {}", output.package_name),
        format!("recommendation: {}", output.recommendation),
        format!("readiness: {}", output.readiness),
        format!(
            "mandatory_fields_valid: {}",
            output.mandatory_field_status.valid
        ),
        format!("ga_gate_consumable: {}", output.ga_gate_consumable),
        format!("pilot_gate_consumable: {}", output.pilot_gate_consumable),
        format!("rationale: {}", output.rationale),
        format!("merged_signals: {}", output.merged_signals.len()),
    ];

    if !output.mandatory_field_status.missing_fields.is_empty() {
        lines.push("missing_fields:".to_string());
        for field in &output.mandatory_field_status.missing_fields {
            lines.push(format!("  - {field}"));
        }
    }

    if !output.mandatory_field_status.inconsistent_fields.is_empty() {
        lines.push("inconsistent_fields:".to_string());
        for field in &output.mandatory_field_status.inconsistent_fields {
            lines.push(format!("  - {field}"));
        }
    }

    lines.push("reproducible_commands:".to_string());
    for command in &output.reproducible_commands {
        lines.push(format!("  - {command}"));
    }

    lines.push("evidence_links:".to_string());
    for link in &output.evidence_links {
        lines.push(format!("  - {link}"));
    }

    lines.join("\n")
}

/// Build a deterministic GA evidence package over rollout-facing artifacts.
pub fn build_ga_evidence_package(input: &GaEvidencePackageInput) -> GaEvidencePackageOutput {
    let mut external_evidence_links = input.external_evidence_links.clone();
    for link in &mut external_evidence_links {
        normalize_ga_evidence_link(link);
    }
    external_evidence_links.sort_by(|left, right| {
        left.category
            .cmp(&right.category)
            .then(left.path.cmp(&right.path))
            .then(left.description.cmp(&right.description))
    });
    external_evidence_links.dedup();

    let mut third_party_replay_commands = input
        .third_party_replay_commands
        .iter()
        .map(|command| normalize_or_default(command, ""))
        .filter(|command| !command.is_empty())
        .collect::<Vec<_>>();
    third_party_replay_commands.sort();
    third_party_replay_commands.dedup();

    let mut reproducible_commands = input.support_bundle.index.reproducible_commands.clone();
    reproducible_commands.extend(input.onboarding_scorecard.reproducible_commands.clone());
    reproducible_commands.extend(
        input
            .rollout_decision_artifact
            .reproducible_commands
            .clone(),
    );
    reproducible_commands.extend(third_party_replay_commands.clone());
    reproducible_commands.sort();
    reproducible_commands.dedup();

    let mandatory_field_status = validate_ga_evidence_package_mandatory_fields(
        input,
        &external_evidence_links,
        &third_party_replay_commands,
    );
    let ga_gate_consumable =
        mandatory_field_status.valid && input.rollout_decision_artifact.ga_gate_consumable;

    let risk_disposition = build_ga_evidence_risk_disposition(
        &input.onboarding_scorecard,
        &input.rollout_decision_artifact,
    );

    let mut logs = input.support_bundle.logs.clone();
    logs.extend(input.onboarding_scorecard.logs.clone());
    logs.extend(input.rollout_decision_artifact.logs.clone());
    logs.push(StructuredLogEvent {
        trace_id: input.support_bundle.index.trace_id.clone(),
        decision_id: input.support_bundle.index.decision_id.clone(),
        policy_id: input.support_bundle.index.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: "ga_evidence_package".to_string(),
        outcome: if ga_gate_consumable {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if ga_gate_consumable {
            None
        } else {
            Some(GA_EVIDENCE_PACKAGE_FAILURE_CODE.to_string())
        },
    });
    logs.sort_by(|left, right| {
        left.trace_id
            .cmp(&right.trace_id)
            .then(left.decision_id.cmp(&right.decision_id))
            .then(left.policy_id.cmp(&right.policy_id))
            .then(left.component.cmp(&right.component))
            .then(left.event.cmp(&right.event))
            .then(left.outcome.cmp(&right.outcome))
            .then(left.error_code.cmp(&right.error_code))
    });
    logs.dedup();

    let rc_id = normalize_or_default(&input.release_candidate_id, "unknown-release-candidate");
    let summary = render_ga_evidence_package_summary_inner(GaEvidencePackageSummaryView {
        release_candidate_id: &rc_id,
        ga_gate_consumable,
        mandatory_field_status: &mandatory_field_status,
        risk_disposition: &risk_disposition,
        external_evidence_links: &external_evidence_links,
        reproducible_commands: &reproducible_commands,
        workload_id: &input.onboarding_scorecard.workload_id,
        package_name: &input.onboarding_scorecard.package_name,
        target_platforms: &input.onboarding_scorecard.target_platforms,
        support_bundle_id: &input.support_bundle.index.bundle_id,
    });

    let mut files = vec![
        make_support_bundle_file(
            "ga_evidence_package/support_bundle_index.json",
            serde_json::to_string_pretty(&input.support_bundle.index)
                .expect("support bundle index must serialize"),
        ),
        make_support_bundle_file(
            "ga_evidence_package/onboarding_scorecard.json",
            serde_json::to_string_pretty(&input.onboarding_scorecard)
                .expect("onboarding scorecard must serialize"),
        ),
        make_support_bundle_file(
            "ga_evidence_package/rollout_decision_artifact.json",
            serde_json::to_string_pretty(&input.rollout_decision_artifact)
                .expect("rollout decision artifact must serialize"),
        ),
        make_support_bundle_file(
            "ga_evidence_package/risk_disposition.json",
            serde_json::to_string_pretty(&risk_disposition)
                .expect("risk disposition must serialize"),
        ),
        make_support_bundle_file(
            "ga_evidence_package/external_evidence_links.json",
            serde_json::to_string_pretty(&external_evidence_links)
                .expect("external evidence links must serialize"),
        ),
        make_support_bundle_file(
            "ga_evidence_package/third_party_replay_commands.txt",
            third_party_replay_commands.join("\n"),
        ),
        make_support_bundle_file(
            "ga_evidence_package/events.jsonl",
            render_support_bundle_events_jsonl(&logs),
        ),
        make_support_bundle_file("ga_evidence_package/summary.md", summary),
    ];

    let file_index_entries = files
        .iter()
        .map(|file| SupportBundleFileIndexEntry {
            path: file.path.clone(),
            sha256: file.sha256.clone(),
            bytes: file.bytes,
        })
        .collect::<Vec<_>>();

    let index = GaEvidencePackageIndex {
        schema_version: GA_EVIDENCE_PACKAGE_SCHEMA_VERSION.to_string(),
        package_id: compute_ga_evidence_package_id(
            &file_index_entries,
            &external_evidence_links,
            &reproducible_commands,
            &input.release_candidate_id,
            ga_gate_consumable,
        ),
        release_candidate_id: normalize_or_default(
            &input.release_candidate_id,
            "unknown-release-candidate",
        ),
        workload_id: input.onboarding_scorecard.workload_id.clone(),
        package_name: input.onboarding_scorecard.package_name.clone(),
        target_platforms: input.onboarding_scorecard.target_platforms.clone(),
        trace_id: input.support_bundle.index.trace_id.clone(),
        decision_id: input.support_bundle.index.decision_id.clone(),
        policy_id: input.support_bundle.index.policy_id.clone(),
        support_bundle_id: input.support_bundle.index.bundle_id.clone(),
        ga_gate_consumable,
        total_external_artifacts: external_evidence_links.len(),
        files: file_index_entries,
        reproducible_commands: reproducible_commands.clone(),
    };

    files.push(make_support_bundle_file(
        "ga_evidence_package/index.json",
        serde_json::to_string_pretty(&index).expect("ga evidence package index must serialize"),
    ));

    GaEvidencePackageOutput {
        schema_version: GA_EVIDENCE_PACKAGE_SCHEMA_VERSION.to_string(),
        release_candidate_id: index.release_candidate_id.clone(),
        workload_id: input.onboarding_scorecard.workload_id.clone(),
        package_name: input.onboarding_scorecard.package_name.clone(),
        target_platforms: input.onboarding_scorecard.target_platforms.clone(),
        mandatory_field_status,
        ga_gate_consumable,
        support_bundle_id: input.support_bundle.index.bundle_id.clone(),
        risk_disposition,
        external_evidence_links,
        reproducible_commands,
        index,
        files,
        logs,
    }
}

/// Render GA evidence package output in deterministic human-readable form.
pub fn render_ga_evidence_package_summary(output: &GaEvidencePackageOutput) -> String {
    render_ga_evidence_package_summary_inner(GaEvidencePackageSummaryView {
        release_candidate_id: &output.release_candidate_id,
        ga_gate_consumable: output.ga_gate_consumable,
        mandatory_field_status: &output.mandatory_field_status,
        risk_disposition: &output.risk_disposition,
        external_evidence_links: &output.external_evidence_links,
        reproducible_commands: &output.reproducible_commands,
        workload_id: &output.workload_id,
        package_name: &output.package_name,
        target_platforms: &output.target_platforms,
        support_bundle_id: &output.support_bundle_id,
    })
}

struct GaEvidencePackageSummaryView<'a> {
    release_candidate_id: &'a str,
    ga_gate_consumable: bool,
    mandatory_field_status: &'a GaEvidencePackageMandatoryFieldStatus,
    risk_disposition: &'a GaEvidenceRiskDisposition,
    external_evidence_links: &'a [GaEvidenceArtifactLink],
    reproducible_commands: &'a [String],
    workload_id: &'a str,
    package_name: &'a str,
    target_platforms: &'a [String],
    support_bundle_id: &'a str,
}

fn render_ga_evidence_package_summary_inner(summary: GaEvidencePackageSummaryView<'_>) -> String {
    let mut lines = vec![
        format!("schema_version: {}", GA_EVIDENCE_PACKAGE_SCHEMA_VERSION),
        format!("release_candidate_id: {}", summary.release_candidate_id),
        format!("workload_id: {}", summary.workload_id),
        format!("package_name: {}", summary.package_name),
        format!("support_bundle_id: {}", summary.support_bundle_id),
        format!(
            "mandatory_fields_valid: {}",
            summary.mandatory_field_status.valid
        ),
        format!("ga_gate_consumable: {}", summary.ga_gate_consumable),
        format!(
            "recommendation: {}",
            summary.risk_disposition.recommendation
        ),
        format!("readiness: {}", summary.risk_disposition.readiness),
        format!(
            "signals: critical={} warning={} info={}",
            summary.risk_disposition.critical_signals,
            summary.risk_disposition.warning_signals,
            summary.risk_disposition.info_signals
        ),
        format!("rationale: {}", summary.risk_disposition.rationale),
    ];

    if !summary.target_platforms.is_empty() {
        lines.push("target_platforms:".to_string());
        for platform in summary.target_platforms {
            lines.push(format!("  - {platform}"));
        }
    }

    if !summary.mandatory_field_status.missing_fields.is_empty() {
        lines.push("missing_fields:".to_string());
        for field in &summary.mandatory_field_status.missing_fields {
            lines.push(format!("  - {field}"));
        }
    }

    if !summary
        .mandatory_field_status
        .inconsistent_fields
        .is_empty()
    {
        lines.push("inconsistent_fields:".to_string());
        for field in &summary.mandatory_field_status.inconsistent_fields {
            lines.push(format!("  - {field}"));
        }
    }

    lines.push("external_evidence_links:".to_string());
    for link in summary.external_evidence_links {
        lines.push(format!(
            "  - [{}] {} :: {}",
            link.category, link.path, link.description
        ));
    }

    lines.push("reproducible_commands:".to_string());
    for command in summary.reproducible_commands {
        lines.push(format!("  - {command}"));
    }

    lines.join("\n")
}

fn build_ga_evidence_risk_disposition(
    onboarding_scorecard: &OnboardingScorecardOutput,
    rollout_decision_artifact: &RolloutDecisionArtifactOutput,
) -> GaEvidenceRiskDisposition {
    let critical_signals = u64::try_from(
        rollout_decision_artifact
            .merged_signals
            .iter()
            .filter(|signal| signal.severity == EvidenceSeverity::Critical)
            .count(),
    )
    .unwrap_or(u64::MAX);
    let warning_signals = u64::try_from(
        rollout_decision_artifact
            .merged_signals
            .iter()
            .filter(|signal| signal.severity == EvidenceSeverity::Warning)
            .count(),
    )
    .unwrap_or(u64::MAX);
    let info_signals = u64::try_from(
        rollout_decision_artifact
            .merged_signals
            .iter()
            .filter(|signal| signal.severity == EvidenceSeverity::Info)
            .count(),
    )
    .unwrap_or(u64::MAX);

    let mut unresolved_signal_ids = rollout_decision_artifact
        .merged_signals
        .iter()
        .map(|signal| signal.signal_id.clone())
        .collect::<Vec<_>>();
    unresolved_signal_ids.sort();
    unresolved_signal_ids.dedup();

    GaEvidenceRiskDisposition {
        readiness: onboarding_scorecard.readiness,
        recommendation: rollout_decision_artifact.recommendation,
        remediation_effort: onboarding_scorecard.remediation_effort,
        rationale: rollout_decision_artifact.rationale.clone(),
        critical_signals,
        warning_signals,
        info_signals,
        unresolved_signal_ids,
        next_steps: onboarding_scorecard.next_steps.clone(),
    }
}

fn choose_rollout_recommendation(
    readiness: OnboardingReadinessClass,
    critical_signals: usize,
    warning_signals: usize,
    has_compatibility_critical: bool,
    has_platform_critical: bool,
    mandatory_fields_valid: bool,
) -> RolloutRecommendation {
    if !mandatory_fields_valid {
        return RolloutRecommendation::Defer;
    }
    if has_compatibility_critical || has_platform_critical {
        return RolloutRecommendation::Rollback;
    }

    match readiness {
        OnboardingReadinessClass::Ready => {
            if critical_signals > 0 {
                RolloutRecommendation::Defer
            } else if warning_signals > 0 {
                RolloutRecommendation::CanaryHold
            } else {
                RolloutRecommendation::Promote
            }
        }
        OnboardingReadinessClass::Conditional => {
            if critical_signals > 0 {
                RolloutRecommendation::Defer
            } else {
                RolloutRecommendation::CanaryHold
            }
        }
        OnboardingReadinessClass::Blocked => {
            if critical_signals > 0 {
                RolloutRecommendation::Rollback
            } else {
                RolloutRecommendation::Defer
            }
        }
    }
}

fn rollout_signal_key(signal: &OnboardingScorecardSignal) -> String {
    format!("{}::{}", signal.source, signal.signal_id)
}

fn merge_rollout_signal(
    existing: &mut OnboardingScorecardSignal,
    incoming: OnboardingScorecardSignal,
) {
    let incoming_owner = incoming.owner_hint.clone();
    if incoming.severity > existing.severity {
        existing.severity = incoming.severity;
        existing.summary = incoming.summary.clone();
        existing.remediation = incoming.remediation.clone();
        existing.reproducible_command = incoming.reproducible_command.clone();
        existing.owner_hint = incoming_owner.clone();
    } else if incoming.severity == existing.severity {
        let incoming_rank = (
            incoming.summary.as_str(),
            incoming.remediation.as_str(),
            incoming.reproducible_command.as_str(),
        );
        let existing_rank = (
            existing.summary.as_str(),
            existing.remediation.as_str(),
            existing.reproducible_command.as_str(),
        );
        if incoming_rank < existing_rank {
            existing.summary = incoming.summary.clone();
            existing.remediation = incoming.remediation.clone();
            existing.reproducible_command = incoming.reproducible_command.clone();
        }
        if existing.owner_hint.is_none() {
            existing.owner_hint = incoming_owner;
        }
    } else if existing.owner_hint.is_none() {
        existing.owner_hint = incoming_owner;
    }

    existing.evidence_links.extend(incoming.evidence_links);
    existing.evidence_links.sort();
    existing.evidence_links.dedup();
}

fn normalize_or_default(value: &str, fallback: &str) -> String {
    let normalized = value.trim();
    if normalized.is_empty() {
        fallback.to_string()
    } else {
        normalized.to_string()
    }
}

fn normalize_onboarding_signal(signal: &mut OnboardingScorecardSignal) {
    signal.signal_id = normalize_or_default(&signal.signal_id, "signal");
    signal.source = normalize_or_default(&signal.source, "external");
    signal.summary = normalize_or_default(&signal.summary, "unspecified signal");
    signal.remediation = normalize_or_default(&signal.remediation, "investigate signal");
    signal.reproducible_command = normalize_or_default(
        &signal.reproducible_command,
        "runtime_diagnostics doctor --input <path> --summary",
    );
    signal.evidence_links.sort();
    signal.evidence_links.dedup();
    signal.owner_hint = signal
        .owner_hint
        .as_deref()
        .map(str::trim)
        .filter(|owner| !owner.is_empty())
        .map(std::string::ToString::to_string);
}

fn normalize_ga_evidence_link(link: &mut GaEvidenceArtifactLink) {
    link.path = normalize_or_default(&link.path, "");
    link.description = normalize_or_default(&link.description, "evidence artifact");
}

fn default_owner_for_source(source: &str, severity: EvidenceSeverity) -> String {
    match source {
        "preflight_doctor" => match severity {
            EvidenceSeverity::Critical => "runtime-security".to_string(),
            EvidenceSeverity::Warning => "runtime-operations".to_string(),
            EvidenceSeverity::Info => "runtime-observability".to_string(),
        },
        "compatibility_advisory" => "compatibility-lane".to_string(),
        "platform_matrix" => "platform-matrix-lane".to_string(),
        _ => "workload-onboarding".to_string(),
    }
}

fn validate_rollout_decision_mandatory_fields(
    onboarding_scorecard: &OnboardingScorecardOutput,
    merged_signals: &[OnboardingScorecardSignal],
    evidence_links: &[String],
    reproducible_commands: &[String],
) -> RolloutDecisionMandatoryFieldStatus {
    let mut missing_fields = Vec::new();
    let mut inconsistent_fields = Vec::new();

    if onboarding_scorecard.schema_version.trim().is_empty() {
        missing_fields.push("onboarding_scorecard.schema_version".to_string());
    }
    if onboarding_scorecard.workload_id.trim().is_empty() {
        missing_fields.push("workload_id".to_string());
    }
    if onboarding_scorecard.package_name.trim().is_empty() {
        missing_fields.push("package_name".to_string());
    }
    if onboarding_scorecard.logs.is_empty() {
        missing_fields.push("onboarding_scorecard.logs".to_string());
    }
    if reproducible_commands.is_empty() {
        missing_fields.push("reproducible_commands".to_string());
    }
    if evidence_links.is_empty() {
        missing_fields.push("evidence_links".to_string());
    }

    if onboarding_scorecard.reproducible_commands.is_empty() {
        inconsistent_fields.push("onboarding_scorecard.reproducible_commands".to_string());
    }

    let allowed_sources = [
        "preflight_doctor",
        "compatibility_advisory",
        "platform_matrix",
        "external",
    ];
    for signal in merged_signals {
        if !allowed_sources.contains(&signal.source.as_str()) {
            inconsistent_fields.push(format!("signal_source:{}", signal.source));
        }
    }

    if onboarding_scorecard.target_platforms.is_empty()
        && merged_signals
            .iter()
            .any(|signal| signal.source == "platform_matrix")
    {
        inconsistent_fields.push("target_platforms".to_string());
    }

    missing_fields.sort();
    missing_fields.dedup();
    inconsistent_fields.sort();
    inconsistent_fields.dedup();

    RolloutDecisionMandatoryFieldStatus {
        valid: missing_fields.is_empty() && inconsistent_fields.is_empty(),
        missing_fields,
        inconsistent_fields,
    }
}

fn validate_ga_evidence_package_mandatory_fields(
    input: &GaEvidencePackageInput,
    external_evidence_links: &[GaEvidenceArtifactLink],
    third_party_replay_commands: &[String],
) -> GaEvidencePackageMandatoryFieldStatus {
    let mut missing_fields = Vec::new();
    let mut inconsistent_fields = Vec::new();

    if input.release_candidate_id.trim().is_empty() {
        missing_fields.push("release_candidate_id".to_string());
    }
    if input.support_bundle.index.bundle_id.trim().is_empty() {
        missing_fields.push("support_bundle.index.bundle_id".to_string());
    }
    if input.support_bundle.index.trace_id.trim().is_empty() {
        missing_fields.push("support_bundle.index.trace_id".to_string());
    }
    if input.support_bundle.index.decision_id.trim().is_empty() {
        missing_fields.push("support_bundle.index.decision_id".to_string());
    }
    if input.support_bundle.index.policy_id.trim().is_empty() {
        missing_fields.push("support_bundle.index.policy_id".to_string());
    }
    if input.onboarding_scorecard.workload_id.trim().is_empty() {
        missing_fields.push("onboarding_scorecard.workload_id".to_string());
    }
    if input.onboarding_scorecard.package_name.trim().is_empty() {
        missing_fields.push("onboarding_scorecard.package_name".to_string());
    }
    if input.onboarding_scorecard.target_platforms.is_empty() {
        missing_fields.push("onboarding_scorecard.target_platforms".to_string());
    }
    if input.onboarding_scorecard.logs.is_empty() {
        missing_fields.push("onboarding_scorecard.logs".to_string());
    }
    if input.onboarding_scorecard.reproducible_commands.is_empty() {
        missing_fields.push("onboarding_scorecard.reproducible_commands".to_string());
    }
    if input.rollout_decision_artifact.logs.is_empty() {
        missing_fields.push("rollout_decision_artifact.logs".to_string());
    }
    if third_party_replay_commands.is_empty() {
        missing_fields.push("third_party_replay_commands".to_string());
    }

    for category in [
        GaEvidenceArtifactCategory::Conformance,
        GaEvidenceArtifactCategory::Performance,
        GaEvidenceArtifactCategory::Security,
    ] {
        if !external_evidence_links
            .iter()
            .any(|link| link.category == category && !link.path.trim().is_empty())
        {
            missing_fields.push(format!("external_evidence_links:{category}"));
        }
    }

    if !input.rollout_decision_artifact.mandatory_field_status.valid {
        inconsistent_fields.push("rollout_decision_artifact.mandatory_field_status".to_string());
    }
    if input.rollout_decision_artifact.workload_id != input.onboarding_scorecard.workload_id {
        inconsistent_fields.push("workload_id".to_string());
    }
    if input.rollout_decision_artifact.package_name != input.onboarding_scorecard.package_name {
        inconsistent_fields.push("package_name".to_string());
    }

    if let Some(log) = input.onboarding_scorecard.logs.first() {
        if log.trace_id != input.support_bundle.index.trace_id {
            inconsistent_fields.push("trace_id".to_string());
        }
        if log.decision_id != input.support_bundle.index.decision_id {
            inconsistent_fields.push("decision_id".to_string());
        }
        if log.policy_id != input.support_bundle.index.policy_id {
            inconsistent_fields.push("policy_id".to_string());
        }
    }

    if let Some(log) = input.rollout_decision_artifact.logs.first() {
        if log.trace_id != input.support_bundle.index.trace_id {
            inconsistent_fields.push("trace_id".to_string());
        }
        if log.decision_id != input.support_bundle.index.decision_id {
            inconsistent_fields.push("decision_id".to_string());
        }
        if log.policy_id != input.support_bundle.index.policy_id {
            inconsistent_fields.push("policy_id".to_string());
        }
    }

    missing_fields.sort();
    missing_fields.dedup();
    inconsistent_fields.sort();
    inconsistent_fields.dedup();

    GaEvidencePackageMandatoryFieldStatus {
        valid: missing_fields.is_empty() && inconsistent_fields.is_empty(),
        missing_fields,
        inconsistent_fields,
    }
}

fn validate_preflight_mandatory_fields(
    input: &RuntimeDiagnosticsCliInput,
    evidence_output: &EvidenceExportOutput,
    support_bundle: &SupportBundleOutput,
) -> PreflightMandatoryFieldStatus {
    let mut missing_fields = Vec::new();
    let mut inconsistent_fields = Vec::new();

    if input.trace_id.trim().is_empty() {
        missing_fields.push("trace_id".to_string());
    }
    if input.decision_id.trim().is_empty() {
        missing_fields.push("decision_id".to_string());
    }
    if input.policy_id.trim().is_empty() {
        missing_fields.push("policy_id".to_string());
    }

    if support_bundle.index.trace_id.trim().is_empty() {
        missing_fields.push("support_bundle.index.trace_id".to_string());
    }
    if support_bundle.index.decision_id.trim().is_empty() {
        missing_fields.push("support_bundle.index.decision_id".to_string());
    }
    if support_bundle.index.policy_id.trim().is_empty() {
        missing_fields.push("support_bundle.index.policy_id".to_string());
    }
    if support_bundle.index.reproducible_commands.is_empty() {
        missing_fields.push("support_bundle.index.reproducible_commands".to_string());
    }

    let required_paths = [
        "support_bundle/run_manifest.json",
        "support_bundle/events.jsonl",
        "support_bundle/commands.txt",
        "support_bundle/runtime_diagnostics.json",
        "support_bundle/evidence_records.jsonl",
        "support_bundle/summary.md",
        "support_bundle/index.json",
    ];
    for path in required_paths {
        if !support_bundle.files.iter().any(|entry| entry.path == path) {
            missing_fields.push(format!("support_bundle.file:{path}"));
        }
    }

    if support_bundle.index.trace_id != input.trace_id {
        inconsistent_fields.push("trace_id".to_string());
    }
    if support_bundle.index.decision_id != input.decision_id {
        inconsistent_fields.push("decision_id".to_string());
    }
    if support_bundle.index.policy_id != input.policy_id {
        inconsistent_fields.push("policy_id".to_string());
    }
    if support_bundle.index.total_records != evidence_output.summary.total_records {
        inconsistent_fields.push(format!(
            "total_records:{}!={}",
            support_bundle.index.total_records, evidence_output.summary.total_records
        ));
    }

    missing_fields.sort();
    missing_fields.dedup();
    inconsistent_fields.sort();
    inconsistent_fields.dedup();

    PreflightMandatoryFieldStatus {
        valid: missing_fields.is_empty() && inconsistent_fields.is_empty(),
        missing_fields,
        inconsistent_fields,
    }
}

fn render_evidence_records_jsonl(records: &[EvidenceExportRecord]) -> String {
    let mut lines = Vec::new();
    for record in records {
        lines.push(
            serde_json::to_string(record).expect("support bundle evidence record must serialize"),
        );
    }
    lines.join("\n")
}

fn render_support_bundle_events_jsonl(events: &[StructuredLogEvent]) -> String {
    let mut lines = Vec::new();
    for event in events {
        lines.push(serde_json::to_string(event).expect("support bundle event must serialize"));
    }
    lines.join("\n")
}

fn make_support_bundle_file(path: &str, content: String) -> SupportBundleFile {
    let sha256 = compute_sha256_hex(content.as_bytes());
    SupportBundleFile {
        path: path.to_string(),
        bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
        content,
        sha256,
    }
}

fn compute_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn compute_support_bundle_id(
    files: &[SupportBundleFileIndexEntry],
    total_redacted_fields: u64,
) -> String {
    let mut material = String::new();
    for file in files {
        material.push_str(file.path.as_str());
        material.push(':');
        material.push_str(file.sha256.as_str());
        material.push(':');
        material.push_str(&file.bytes.to_string());
        material.push('\n');
    }
    material.push_str("redacted=");
    material.push_str(&total_redacted_fields.to_string());
    let hex = compute_sha256_hex(material.as_bytes());
    format!("bundle-{}", hex.get(..16).unwrap_or(&hex))
}

fn compute_ga_evidence_package_id(
    files: &[SupportBundleFileIndexEntry],
    external_evidence_links: &[GaEvidenceArtifactLink],
    reproducible_commands: &[String],
    release_candidate_id: &str,
    ga_gate_consumable: bool,
) -> String {
    let mut material = String::new();
    material.push_str("release_candidate_id=");
    material.push_str(release_candidate_id.trim());
    material.push('\n');
    material.push_str("ga_gate_consumable=");
    material.push_str(if ga_gate_consumable { "true" } else { "false" });
    material.push('\n');

    for file in files {
        material.push_str(file.path.as_str());
        material.push(':');
        material.push_str(file.sha256.as_str());
        material.push(':');
        material.push_str(&file.bytes.to_string());
        material.push('\n');
    }

    for link in external_evidence_links {
        material.push_str(&link.category.to_string());
        material.push(':');
        material.push_str(link.path.as_str());
        material.push(':');
        material.push_str(link.description.as_str());
        material.push('\n');
    }

    for command in reproducible_commands {
        material.push_str(command.as_str());
        material.push('\n');
    }

    let hex = compute_sha256_hex(material.as_bytes());
    format!("ga-package-{}", hex.get(..16).unwrap_or(&hex))
}

fn redact_sensitive_fields(
    value: Value,
    redaction_policy: &SupportBundleRedactionPolicy,
) -> (Value, u64) {
    match value {
        Value::Object(map) => {
            let mut items = map.into_iter().collect::<Vec<_>>();
            items.sort_by(|left, right| left.0.cmp(&right.0));
            let mut out = serde_json::Map::new();
            let mut redacted = 0_u64;
            for (key, nested_value) in items {
                if redaction_policy.should_redact_key(key.as_str()) {
                    out.insert(key, Value::String(redaction_policy.replacement.clone()));
                    redacted = redacted.saturating_add(1);
                    continue;
                }
                let (nested, nested_redacted) =
                    redact_sensitive_fields(nested_value, redaction_policy);
                out.insert(key, nested);
                redacted = redacted.saturating_add(nested_redacted);
            }
            (Value::Object(out), redacted)
        }
        Value::Array(values) => {
            let mut out = Vec::with_capacity(values.len());
            let mut redacted = 0_u64;
            for value in values {
                let (nested, nested_redacted) = redact_sensitive_fields(value, redaction_policy);
                out.push(nested);
                redacted = redacted.saturating_add(nested_redacted);
            }
            (Value::Array(out), redacted)
        }
        other => (other, 0),
    }
}

fn compute_pressure_millionths(used: u64, budget: u64) -> u64 {
    if budget == 0 {
        if used == 0 {
            return 0;
        }
        return 1_000_000;
    }

    let ratio = used.saturating_mul(1_000_000) / budget;
    ratio.min(1_000_000)
}

fn matches_export_filter(filter: &EvidenceExportFilter, record: &EvidenceExportRecord) -> bool {
    filter.matches_trace(&record.trace_id)
        && filter.matches_extension(&record.extension_id)
        && filter.matches_timestamp(record.timestamp_ns)
        && filter.matches_severity(record.severity)
        && filter.matches_decision_type(record.decision_type)
}

fn severity_from_evidence_entry(entry: &EvidenceEntry) -> EvidenceSeverity {
    match entry.decision_type {
        DecisionType::Revocation | DecisionType::EpochTransition => EvidenceSeverity::Critical,
        DecisionType::PolicyUpdate => EvidenceSeverity::Warning,
        DecisionType::SecurityAction => {
            let action = entry.chosen_action.action_name.to_ascii_lowercase();
            match action.as_str() {
                "terminate" | "quarantine" | "suspend" => EvidenceSeverity::Critical,
                "sandbox" | "challenge" => EvidenceSeverity::Warning,
                _ => EvidenceSeverity::Info,
            }
        }
        _ => EvidenceSeverity::Info,
    }
}

fn severity_from_hostcall(result: &HostcallResult) -> EvidenceSeverity {
    match result {
        HostcallResult::Success => EvidenceSeverity::Info,
        HostcallResult::Denied { .. } => EvidenceSeverity::Warning,
        HostcallResult::Error { .. } | HostcallResult::Timeout => EvidenceSeverity::Critical,
    }
}

fn severity_from_containment_action(action: ContainmentAction) -> EvidenceSeverity {
    match action {
        ContainmentAction::Allow => EvidenceSeverity::Info,
        ContainmentAction::Challenge | ContainmentAction::Sandbox => EvidenceSeverity::Warning,
        ContainmentAction::Suspend
        | ContainmentAction::Terminate
        | ContainmentAction::Quarantine => EvidenceSeverity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::containment_executor::ContainmentReceipt;
    use crate::evidence_ledger::{
        CandidateAction, ChosenAction, DecisionType, EvidenceEntryBuilder, InMemoryLedger, Witness,
    };
    use crate::expected_loss_selector::ContainmentAction;
    use crate::hash_tiers::ContentHash;
    use crate::hostcall_telemetry::{
        FlowLabel, HostcallResult, HostcallType, RecordInput, RecorderConfig, ResourceDelta,
        TelemetryRecorder,
    };
    use crate::module_compatibility_matrix::{
        CompatibilityEvent, CompatibilityMode, CompatibilityObservationOutcome,
        CompatibilityRuntime, DivergenceCategory, DivergencePolicy, ReferenceRuntime,
    };

    fn sample_runtime_state() -> RuntimeStateInput {
        RuntimeStateInput {
            snapshot_timestamp_ns: 1_000,
            loaded_extensions: vec![
                RuntimeExtensionState {
                    extension_id: "ext-b".to_string(),
                    containment_state: ContainmentState::Running,
                },
                RuntimeExtensionState {
                    extension_id: "ext-a".to_string(),
                    containment_state: ContainmentState::Sandboxed,
                },
            ],
            active_policies: vec![
                "policy-z".to_string(),
                "policy-a".to_string(),
                "policy-z".to_string(),
            ],
            security_epoch: SecurityEpoch::from_raw(7),
            gc_pressure: vec![
                GcPressureSample {
                    extension_id: "ext-b".to_string(),
                    used_bytes: 700,
                    budget_bytes: 1_000,
                },
                GcPressureSample {
                    extension_id: "ext-a".to_string(),
                    used_bytes: 500,
                    budget_bytes: 400,
                },
            ],
            scheduler_lanes: vec![
                SchedulerLaneSample {
                    lane: "ready".to_string(),
                    queue_depth: 20,
                    max_depth: 100,
                    tasks_submitted: 50,
                    tasks_scheduled: 40,
                    tasks_completed: 35,
                    tasks_timed_out: 1,
                },
                SchedulerLaneSample {
                    lane: "cancel".to_string(),
                    queue_depth: 1,
                    max_depth: 10,
                    tasks_submitted: 3,
                    tasks_scheduled: 3,
                    tasks_completed: 3,
                    tasks_timed_out: 0,
                },
            ],
        }
    }

    fn sample_evidence_entries() -> Vec<EvidenceEntry> {
        let mut out = Vec::new();

        let security = EvidenceEntryBuilder::new(
            "trace-1",
            "dec-1",
            "policy-a",
            SecurityEpoch::from_raw(7),
            DecisionType::SecurityAction,
        )
        .timestamp_ns(101)
        .candidate(CandidateAction::new("sandbox", 120_000))
        .chosen(ChosenAction {
            action_name: "sandbox".to_string(),
            expected_loss_millionths: 120_000,
            rationale: "min-loss".to_string(),
        })
        .witness(Witness {
            witness_id: "w-1".to_string(),
            witness_type: "posterior".to_string(),
            value: "0.91".to_string(),
        })
        .meta("extension_id", "ext-a")
        .build()
        .expect("security entry should build");
        out.push(security);

        let policy_change = EvidenceEntryBuilder::new(
            "trace-1",
            "dec-2",
            "policy-a",
            SecurityEpoch::from_raw(7),
            DecisionType::PolicyUpdate,
        )
        .timestamp_ns(102)
        .candidate(CandidateAction::new("rotate", 1))
        .chosen(ChosenAction {
            action_name: "rotate".to_string(),
            expected_loss_millionths: 1,
            rationale: "refresh key".to_string(),
        })
        .build()
        .expect("policy entry should build");
        out.push(policy_change);

        out
    }

    fn sample_hostcall_envelopes() -> Vec<HostcallTelemetryEnvelope> {
        let mut recorder = TelemetryRecorder::new(RecorderConfig::default());
        let record_id = recorder
            .record(
                103,
                RecordInput {
                    extension_id: "ext-a".to_string(),
                    hostcall_type: HostcallType::FsRead,
                    capability_used: crate::capability::RuntimeCapability::FsRead,
                    arguments_hash: ContentHash::compute(b"args"),
                    result_status: HostcallResult::Denied {
                        reason: "policy".to_string(),
                    },
                    duration_ns: 2_000,
                    resource_delta: ResourceDelta::default(),
                    flow_label: FlowLabel::new("public", "public"),
                    decision_id: Some("dec-1".to_string()),
                },
            )
            .expect("recording hostcall should succeed");
        let record = recorder
            .get(record_id)
            .cloned()
            .expect("record should exist after successful recording");

        vec![HostcallTelemetryEnvelope {
            trace_id: "trace-1".to_string(),
            policy_id: "policy-a".to_string(),
            record,
        }]
    }

    fn sample_containment_receipts() -> Vec<ContainmentReceiptEnvelope> {
        let mut metadata = BTreeMap::new();
        metadata.insert("decision_id".to_string(), "dec-1".to_string());
        let mut receipt = ContainmentReceipt {
            receipt_id: "cr-1".to_string(),
            action: ContainmentAction::Sandbox,
            target_extension_id: "ext-a".to_string(),
            previous_state: ContainmentState::Running,
            new_state: ContainmentState::Sandboxed,
            timestamp_ns: 104,
            duration_ns: 0,
            success: true,
            cooperative: false,
            evidence_refs: vec!["ev-1".to_string()],
            epoch: SecurityEpoch::from_raw(7),
            content_hash: ContentHash::compute(b"placeholder"),
            metadata,
        };
        receipt.content_hash = ContentHash::compute(receipt.receipt_id.as_bytes());

        vec![ContainmentReceiptEnvelope {
            trace_id: "trace-1".to_string(),
            policy_id: "policy-a".to_string(),
            receipt,
        }]
    }

    fn sample_input() -> RuntimeDiagnosticsCliInput {
        RuntimeDiagnosticsCliInput {
            trace_id: "trace-runtime-cli".to_string(),
            decision_id: "decision-runtime-cli".to_string(),
            policy_id: "policy-runtime-cli".to_string(),
            runtime_state: sample_runtime_state(),
            evidence_entries: sample_evidence_entries(),
            hostcall_records: sample_hostcall_envelopes(),
            containment_receipts: sample_containment_receipts(),
            replay_artifacts: vec![ReplayArtifactRecord {
                trace_id: "trace-1".to_string(),
                extension_id: "ext-a".to_string(),
                timestamp_ns: 105,
                artifact_id: "replay-1".to_string(),
                replay_pointer: "artifacts/replay/trace-1.json".to_string(),
            }],
        }
    }

    #[test]
    fn diagnostics_snapshot_is_deterministic_and_sorted() {
        let state = sample_runtime_state();
        let left = collect_runtime_diagnostics(&state, "trace", "decision", "policy");
        let right = collect_runtime_diagnostics(&state, "trace", "decision", "policy");

        assert_eq!(left, right);
        assert_eq!(left.loaded_extensions[0].extension_id, "ext-a");
        assert_eq!(left.loaded_extensions[1].extension_id, "ext-b");
        assert_eq!(left.active_policies, vec!["policy-a", "policy-z"]);
        assert_eq!(left.scheduler_lanes[0].lane, "cancel");
        assert_eq!(left.scheduler_lanes[1].lane, "ready");
        assert!(left.logs.iter().all(|event| {
            !event.trace_id.is_empty()
                && !event.decision_id.is_empty()
                && !event.policy_id.is_empty()
                && !event.component.is_empty()
                && !event.event.is_empty()
                && !event.outcome.is_empty()
        }));
    }

    #[test]
    fn evidence_export_filters_narrow_results() {
        let input = sample_input();
        let filter = EvidenceExportFilter {
            extension_id: Some("ext-a".to_string()),
            trace_id: Some("trace-1".to_string()),
            start_timestamp_ns: Some(103),
            end_timestamp_ns: Some(104),
            severity: Some(EvidenceSeverity::Warning),
            decision_type: None,
        };

        let output = export_evidence_bundle(&input, filter);
        assert_eq!(output.summary.total_records, 2);
        assert!(output.records.iter().all(|record| {
            record.trace_id == "trace-1"
                && record.extension_id.as_deref() == Some("ext-a")
                && (103..=104).contains(&record.timestamp_ns)
                && record.severity == EvidenceSeverity::Warning
        }));
    }

    #[test]
    fn evidence_export_is_deterministic_for_same_query() {
        let input = sample_input();
        let filter = EvidenceExportFilter::default();
        let first = export_evidence_bundle(&input, filter.clone());
        let second = export_evidence_bundle(&input, filter);
        assert_eq!(first, second);
    }

    #[test]
    fn evidence_export_empty_result_is_valid() {
        let input = sample_input();
        let output = export_evidence_bundle(
            &input,
            EvidenceExportFilter {
                extension_id: Some("missing-extension".to_string()),
                ..EvidenceExportFilter::default()
            },
        );

        assert_eq!(output.summary.total_records, 0);
        assert!(output.records.is_empty());
        assert_eq!(
            render_evidence_summary(&output),
            "No evidence entries found for the specified filters."
        );
    }

    #[test]
    fn severity_and_decision_type_parsers_accept_known_values() {
        assert_eq!(
            parse_evidence_severity("critical"),
            Some(EvidenceSeverity::Critical)
        );
        assert_eq!(
            parse_decision_type("policy_update"),
            Some(DecisionType::PolicyUpdate)
        );
        assert_eq!(parse_evidence_severity("unknown"), None);
        assert_eq!(parse_decision_type("unknown"), None);
    }

    #[test]
    fn export_includes_required_kinds() {
        let input = sample_input();
        let output = export_evidence_bundle(&input, EvidenceExportFilter::default());

        let kinds = output
            .records
            .iter()
            .map(|record| record.kind)
            .collect::<BTreeSet<_>>();

        assert!(kinds.contains(&EvidenceRecordKind::DecisionReceipt));
        assert!(kinds.contains(&EvidenceRecordKind::PolicyChange));
        assert!(kinds.contains(&EvidenceRecordKind::HostcallTelemetry));
        assert!(kinds.contains(&EvidenceRecordKind::ContainmentAction));
        assert!(kinds.contains(&EvidenceRecordKind::ReplayArtifact));
    }

    #[test]
    fn integration_like_export_over_ledger_data_remains_stable() {
        let mut ledger = InMemoryLedger::new();
        for entry in sample_evidence_entries() {
            crate::evidence_ledger::EvidenceEmitter::emit(&mut ledger, entry)
                .expect("ledger emit should succeed");
        }

        let mut input = sample_input();
        input.evidence_entries = ledger.entries().to_vec();

        let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
        assert!(output.summary.total_records >= 5);
        assert!(
            output
                .logs
                .iter()
                .any(|event| event.event == "evidence_export")
        );
    }

    // -- serde roundtrips -----------------------------------------------------

    #[test]
    fn evidence_severity_serde_roundtrip() {
        for sev in &[
            EvidenceSeverity::Info,
            EvidenceSeverity::Warning,
            EvidenceSeverity::Critical,
        ] {
            let json = serde_json::to_string(sev).unwrap();
            let back: EvidenceSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*sev, back);
        }
    }

    #[test]
    fn evidence_record_kind_serde_roundtrip() {
        for kind in &[
            EvidenceRecordKind::DecisionReceipt,
            EvidenceRecordKind::HostcallTelemetry,
            EvidenceRecordKind::ContainmentAction,
            EvidenceRecordKind::PolicyChange,
            EvidenceRecordKind::ReplayArtifact,
        ] {
            let json = serde_json::to_string(kind).unwrap();
            let back: EvidenceRecordKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn structured_log_event_serde_roundtrip() {
        let event = StructuredLogEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "test".to_string(),
            event: "snap".to_string(),
            outcome: "pass".to_string(),
            error_code: Some("E001".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: StructuredLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn evidence_export_filter_serde_roundtrip() {
        let filter = EvidenceExportFilter {
            extension_id: Some("ext-a".to_string()),
            trace_id: Some("t1".to_string()),
            start_timestamp_ns: Some(100),
            end_timestamp_ns: Some(200),
            severity: Some(EvidenceSeverity::Warning),
            decision_type: Some(DecisionType::Revocation),
        };
        let json = serde_json::to_string(&filter).unwrap();
        let back: EvidenceExportFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(filter, back);
    }

    #[test]
    fn gc_pressure_sample_serde_roundtrip() {
        let sample = GcPressureSample {
            extension_id: "ext-1".to_string(),
            used_bytes: 500,
            budget_bytes: 1000,
        };
        let json = serde_json::to_string(&sample).unwrap();
        let back: GcPressureSample = serde_json::from_str(&json).unwrap();
        assert_eq!(sample, back);
    }

    #[test]
    fn scheduler_lane_sample_serde_roundtrip() {
        let sample = SchedulerLaneSample {
            lane: "fast".to_string(),
            queue_depth: 5,
            max_depth: 50,
            tasks_submitted: 100,
            tasks_scheduled: 90,
            tasks_completed: 80,
            tasks_timed_out: 2,
        };
        let json = serde_json::to_string(&sample).unwrap();
        let back: SchedulerLaneSample = serde_json::from_str(&json).unwrap();
        assert_eq!(sample, back);
    }

    #[test]
    fn replay_artifact_record_serde_roundtrip() {
        let record = ReplayArtifactRecord {
            trace_id: "t1".to_string(),
            extension_id: "ext-1".to_string(),
            timestamp_ns: 42,
            artifact_id: "a1".to_string(),
            replay_pointer: "path/to/artifact".to_string(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: ReplayArtifactRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    // -- Display tests --------------------------------------------------------

    #[test]
    fn evidence_severity_display() {
        assert_eq!(EvidenceSeverity::Info.to_string(), "info");
        assert_eq!(EvidenceSeverity::Warning.to_string(), "warning");
        assert_eq!(EvidenceSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn evidence_record_kind_display() {
        assert_eq!(
            EvidenceRecordKind::DecisionReceipt.to_string(),
            "decision_receipt"
        );
        assert_eq!(
            EvidenceRecordKind::HostcallTelemetry.to_string(),
            "hostcall_telemetry"
        );
        assert_eq!(
            EvidenceRecordKind::ContainmentAction.to_string(),
            "containment_action"
        );
        assert_eq!(
            EvidenceRecordKind::PolicyChange.to_string(),
            "policy_change"
        );
        assert_eq!(
            EvidenceRecordKind::ReplayArtifact.to_string(),
            "replay_artifact"
        );
    }

    // -- parser edge cases ----------------------------------------------------

    #[test]
    fn parse_evidence_severity_case_insensitive() {
        assert_eq!(
            parse_evidence_severity("INFO"),
            Some(EvidenceSeverity::Info)
        );
        assert_eq!(
            parse_evidence_severity("  Warning  "),
            Some(EvidenceSeverity::Warning)
        );
        assert_eq!(
            parse_evidence_severity("CRITICAL"),
            Some(EvidenceSeverity::Critical)
        );
    }

    #[test]
    fn parse_decision_type_all_known_values() {
        let cases = [
            ("security_action", DecisionType::SecurityAction),
            ("policy_update", DecisionType::PolicyUpdate),
            ("epoch_transition", DecisionType::EpochTransition),
            ("revocation", DecisionType::Revocation),
            ("extension_lifecycle", DecisionType::ExtensionLifecycle),
            ("capability_decision", DecisionType::CapabilityDecision),
            ("contract_evaluation", DecisionType::ContractEvaluation),
            ("remote_authorization", DecisionType::RemoteAuthorization),
        ];
        for (input, expected) in &cases {
            assert_eq!(
                parse_decision_type(input),
                Some(*expected),
                "failed for input: {}",
                input
            );
        }
    }

    #[test]
    fn parse_decision_type_case_insensitive() {
        assert_eq!(
            parse_decision_type("SECURITY_ACTION"),
            Some(DecisionType::SecurityAction)
        );
        assert_eq!(
            parse_decision_type("  Policy_Update  "),
            Some(DecisionType::PolicyUpdate)
        );
    }

    // -- compute_pressure_millionths ------------------------------------------

    #[test]
    fn pressure_zero_budget_zero_used_is_zero() {
        assert_eq!(compute_pressure_millionths(0, 0), 0);
    }

    #[test]
    fn pressure_zero_budget_nonzero_used_is_million() {
        assert_eq!(compute_pressure_millionths(100, 0), 1_000_000);
    }

    #[test]
    fn pressure_exact_budget_is_million() {
        assert_eq!(compute_pressure_millionths(1000, 1000), 1_000_000);
    }

    #[test]
    fn pressure_half_budget_is_half_million() {
        assert_eq!(compute_pressure_millionths(500, 1000), 500_000);
    }

    #[test]
    fn pressure_over_budget_capped_at_million() {
        assert_eq!(compute_pressure_millionths(2000, 1000), 1_000_000);
    }

    // -- EvidenceExportFilter matching ----------------------------------------

    #[test]
    fn filter_default_matches_all() {
        let filter = EvidenceExportFilter::default();
        assert!(filter.matches_timestamp(0));
        assert!(filter.matches_timestamp(u64::MAX));
        assert!(filter.matches_extension(&None));
        assert!(filter.matches_extension(&Some("any".to_string())));
        assert!(filter.matches_trace("any"));
        assert!(filter.matches_severity(EvidenceSeverity::Info));
        assert!(filter.matches_decision_type(None));
    }

    #[test]
    fn filter_timestamp_range() {
        let filter = EvidenceExportFilter {
            start_timestamp_ns: Some(100),
            end_timestamp_ns: Some(200),
            ..EvidenceExportFilter::default()
        };
        assert!(!filter.matches_timestamp(99));
        assert!(filter.matches_timestamp(100));
        assert!(filter.matches_timestamp(150));
        assert!(filter.matches_timestamp(200));
        assert!(!filter.matches_timestamp(201));
    }

    #[test]
    fn filter_extension_match() {
        let filter = EvidenceExportFilter {
            extension_id: Some("ext-a".to_string()),
            ..EvidenceExportFilter::default()
        };
        assert!(filter.matches_extension(&Some("ext-a".to_string())));
        assert!(!filter.matches_extension(&Some("ext-b".to_string())));
        assert!(!filter.matches_extension(&None));
    }

    #[test]
    fn filter_trace_match() {
        let filter = EvidenceExportFilter {
            trace_id: Some("t-1".to_string()),
            ..EvidenceExportFilter::default()
        };
        assert!(filter.matches_trace("t-1"));
        assert!(!filter.matches_trace("t-2"));
    }

    // -- diagnostics snapshot edge cases --------------------------------------

    #[test]
    fn diagnostics_empty_state() {
        let state = RuntimeStateInput {
            snapshot_timestamp_ns: 0,
            loaded_extensions: vec![],
            active_policies: vec![],
            security_epoch: SecurityEpoch::from_raw(1),
            gc_pressure: vec![],
            scheduler_lanes: vec![],
        };
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        assert!(out.loaded_extensions.is_empty());
        assert!(out.active_policies.is_empty());
        assert!(out.gc_pressure.is_empty());
        assert!(out.scheduler_lanes.is_empty());
        assert_eq!(out.logs.len(), 1);
    }

    #[test]
    fn diagnostics_deduplicates_policies() {
        let state = RuntimeStateInput {
            snapshot_timestamp_ns: 0,
            loaded_extensions: vec![],
            active_policies: vec![
                "a".to_string(),
                "b".to_string(),
                "a".to_string(),
                "b".to_string(),
            ],
            security_epoch: SecurityEpoch::from_raw(1),
            gc_pressure: vec![],
            scheduler_lanes: vec![],
        };
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        assert_eq!(out.active_policies, vec!["a", "b"]);
    }

    #[test]
    fn diagnostics_filters_empty_policies() {
        let state = RuntimeStateInput {
            snapshot_timestamp_ns: 0,
            loaded_extensions: vec![],
            active_policies: vec!["".to_string(), "  ".to_string(), "real".to_string()],
            security_epoch: SecurityEpoch::from_raw(1),
            gc_pressure: vec![],
            scheduler_lanes: vec![],
        };
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        assert_eq!(out.active_policies, vec!["real"]);
    }

    #[test]
    fn gc_pressure_over_budget_flag() {
        let state = RuntimeStateInput {
            snapshot_timestamp_ns: 0,
            loaded_extensions: vec![],
            active_policies: vec![],
            security_epoch: SecurityEpoch::from_raw(1),
            gc_pressure: vec![
                GcPressureSample {
                    extension_id: "over".to_string(),
                    used_bytes: 2000,
                    budget_bytes: 1000,
                },
                GcPressureSample {
                    extension_id: "under".to_string(),
                    used_bytes: 500,
                    budget_bytes: 1000,
                },
            ],
            scheduler_lanes: vec![],
        };
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        let over = out
            .gc_pressure
            .iter()
            .find(|g| g.extension_id == "over")
            .unwrap();
        let under = out
            .gc_pressure
            .iter()
            .find(|g| g.extension_id == "under")
            .unwrap();
        assert!(over.over_budget);
        assert!(!under.over_budget);
    }

    // -- render_diagnostics_summary -------------------------------------------

    #[test]
    fn render_diagnostics_summary_contains_epoch() {
        let state = sample_runtime_state();
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        let rendered = render_diagnostics_summary(&out);
        assert!(rendered.contains("security_epoch: 7"));
    }

    #[test]
    fn render_diagnostics_summary_contains_extension_count() {
        let state = sample_runtime_state();
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        let rendered = render_diagnostics_summary(&out);
        assert!(rendered.contains("loaded_extensions: 2"));
    }

    // -- render_evidence_summary ----------------------------------------------

    #[test]
    fn render_evidence_summary_nonempty_has_counts() {
        let input = sample_input();
        let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
        let rendered = render_evidence_summary(&output);
        assert!(rendered.contains("total_records:"));
        assert!(rendered.contains("counts_by_kind:"));
        assert!(rendered.contains("counts_by_severity:"));
    }

    // -- severity functions ---------------------------------------------------

    #[test]
    fn severity_from_containment_covers_all_actions() {
        assert_eq!(
            severity_from_containment_action(ContainmentAction::Allow),
            EvidenceSeverity::Info
        );
        assert_eq!(
            severity_from_containment_action(ContainmentAction::Challenge),
            EvidenceSeverity::Warning
        );
        assert_eq!(
            severity_from_containment_action(ContainmentAction::Sandbox),
            EvidenceSeverity::Warning
        );
        assert_eq!(
            severity_from_containment_action(ContainmentAction::Suspend),
            EvidenceSeverity::Critical
        );
        assert_eq!(
            severity_from_containment_action(ContainmentAction::Terminate),
            EvidenceSeverity::Critical
        );
        assert_eq!(
            severity_from_containment_action(ContainmentAction::Quarantine),
            EvidenceSeverity::Critical
        );
    }

    #[test]
    fn severity_from_hostcall_result() {
        assert_eq!(
            severity_from_hostcall(&HostcallResult::Success),
            EvidenceSeverity::Info
        );
        assert_eq!(
            severity_from_hostcall(&HostcallResult::Denied {
                reason: "nope".to_string()
            }),
            EvidenceSeverity::Warning
        );
        assert_eq!(
            severity_from_hostcall(&HostcallResult::Error { code: 500 }),
            EvidenceSeverity::Critical
        );
        assert_eq!(
            severity_from_hostcall(&HostcallResult::Timeout),
            EvidenceSeverity::Critical
        );
    }

    // -- EvidenceExportSummary serde ------------------------------------------

    #[test]
    fn evidence_export_summary_serde_roundtrip() {
        let mut counts_by_kind = BTreeMap::new();
        counts_by_kind.insert("decision_receipt".to_string(), 3);
        let mut counts_by_severity = BTreeMap::new();
        counts_by_severity.insert("info".to_string(), 2);
        let summary = EvidenceExportSummary {
            total_records: 5,
            counts_by_kind,
            counts_by_severity,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: EvidenceExportSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    // -- severity ordering ----------------------------------------------------

    #[test]
    fn evidence_severity_ordering() {
        assert!(EvidenceSeverity::Info < EvidenceSeverity::Warning);
        assert!(EvidenceSeverity::Warning < EvidenceSeverity::Critical);
    }

    // -- evidence record kind ordering ----------------------------------------

    #[test]
    fn evidence_record_kind_ordering() {
        assert!(EvidenceRecordKind::DecisionReceipt < EvidenceRecordKind::ReplayArtifact);
    }

    // -- Enrichment: Display uniqueness via BTreeSet --

    #[test]
    fn evidence_severity_display_all_unique() {
        let displays: BTreeSet<String> = [
            EvidenceSeverity::Info,
            EvidenceSeverity::Warning,
            EvidenceSeverity::Critical,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn evidence_record_kind_display_all_unique() {
        let displays: BTreeSet<String> = [
            EvidenceRecordKind::DecisionReceipt,
            EvidenceRecordKind::HostcallTelemetry,
            EvidenceRecordKind::ContainmentAction,
            EvidenceRecordKind::PolicyChange,
            EvidenceRecordKind::ReplayArtifact,
        ]
        .iter()
        .map(|k| k.to_string())
        .collect();
        assert_eq!(displays.len(), 5);
    }

    #[test]
    fn filter_severity_minimum_threshold() {
        let filter = EvidenceExportFilter {
            severity: Some(EvidenceSeverity::Warning),
            ..EvidenceExportFilter::default()
        };
        // Severity filter matches Warning and above (ordering-based: severity >= expected)
        assert!(!filter.matches_severity(EvidenceSeverity::Info));
        assert!(filter.matches_severity(EvidenceSeverity::Warning));
        assert!(filter.matches_severity(EvidenceSeverity::Critical));
    }

    #[test]
    fn runtime_extension_state_serde_roundtrip() {
        let state = RuntimeExtensionState {
            extension_id: "ext-test".to_string(),
            containment_state: ContainmentState::Sandboxed,
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: RuntimeExtensionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn runtime_state_input_serde_roundtrip() {
        let state = sample_runtime_state();
        let json = serde_json::to_string(&state).unwrap();
        let back: RuntimeStateInput = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn diagnostics_snapshot_sorts_gc_pressure() {
        let state = sample_runtime_state();
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        // gc_pressure should be sorted by extension_id
        for window in out.gc_pressure.windows(2) {
            assert!(window[0].extension_id <= window[1].extension_id);
        }
    }

    #[test]
    fn evidence_export_output_serde_roundtrip() {
        let input = sample_input();
        let output = export_evidence_bundle(&input, EvidenceExportFilter::default());
        let json = serde_json::to_string(&output).unwrap();
        let back: EvidenceExportOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(output, back);
    }

    #[test]
    fn filter_decision_type_matching() {
        let filter = EvidenceExportFilter {
            decision_type: Some(DecisionType::SecurityAction),
            ..EvidenceExportFilter::default()
        };
        assert!(filter.matches_decision_type(Some(DecisionType::SecurityAction)));
        assert!(!filter.matches_decision_type(Some(DecisionType::PolicyUpdate)));
        assert!(!filter.matches_decision_type(None));
    }

    #[test]
    fn structured_log_event_clone_equality() {
        let e = StructuredLogEvent {
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            component: "engine".into(),
            event: "startup".into(),
            outcome: "ok".into(),
            error_code: None,
        };
        let cloned = e.clone();
        assert_eq!(e, cloned);
    }

    #[test]
    fn gc_pressure_sample_clone_equality() {
        let s = GcPressureSample {
            extension_id: "ext-1".into(),
            used_bytes: 1024,
            budget_bytes: 4096,
        };
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn scheduler_lane_sample_clone_equality() {
        let s = SchedulerLaneSample {
            lane: "lane-0".into(),
            queue_depth: 5,
            max_depth: 100,
            tasks_submitted: 50,
            tasks_scheduled: 45,
            tasks_completed: 40,
            tasks_timed_out: 2,
        };
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn evidence_export_filter_clone_equality() {
        let f = EvidenceExportFilter {
            decision_type: Some(DecisionType::SecurityAction),
            ..EvidenceExportFilter::default()
        };
        let cloned = f.clone();
        assert_eq!(f, cloned);
    }

    #[test]
    fn replay_artifact_record_clone_equality() {
        let r = ReplayArtifactRecord {
            trace_id: "t-1".into(),
            extension_id: "ext-1".into(),
            timestamp_ns: 5000,
            artifact_id: "a-1".into(),
            replay_pointer: "ptr-1".into(),
        };
        let cloned = r.clone();
        assert_eq!(r, cloned);
    }

    #[test]
    fn structured_log_event_json_field_presence() {
        let e = StructuredLogEvent {
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            component: "engine".into(),
            event: "startup".into(),
            outcome: "ok".into(),
            error_code: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"event\""));
        assert!(json.contains("\"outcome\""));
    }

    #[test]
    fn gc_pressure_sample_json_field_presence() {
        let s = GcPressureSample {
            extension_id: "ext-1".into(),
            used_bytes: 1024,
            budget_bytes: 4096,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"extension_id\""));
        assert!(json.contains("\"used_bytes\""));
        assert!(json.contains("\"budget_bytes\""));
    }

    #[test]
    fn replay_artifact_record_json_field_presence() {
        let r = ReplayArtifactRecord {
            trace_id: "t-1".into(),
            extension_id: "ext-1".into(),
            timestamp_ns: 5000,
            artifact_id: "a-1".into(),
            replay_pointer: "ptr-1".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"extension_id\""));
        assert!(json.contains("\"timestamp_ns\""));
        assert!(json.contains("\"artifact_id\""));
        assert!(json.contains("\"replay_pointer\""));
    }

    #[test]
    fn evidence_severity_serde_roundtrip_all() {
        for s in [
            EvidenceSeverity::Info,
            EvidenceSeverity::Warning,
            EvidenceSeverity::Critical,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: EvidenceSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn evidence_severity_display_nonempty() {
        for s in [
            EvidenceSeverity::Info,
            EvidenceSeverity::Warning,
            EvidenceSeverity::Critical,
        ] {
            assert!(!format!("{s}").is_empty());
        }
    }

    #[test]
    fn parse_evidence_severity_unknown_returns_none() {
        assert!(parse_evidence_severity("bogus").is_none());
        assert!(parse_evidence_severity("").is_none());
    }

    #[test]
    fn parse_decision_type_unknown_returns_none() {
        assert!(parse_decision_type("bogus").is_none());
        assert!(parse_decision_type("").is_none());
    }

    // ── Enrichment: Copy semantics ──────────────────────────────

    #[test]
    fn evidence_severity_copy_from_array() {
        let arr = [
            EvidenceSeverity::Info,
            EvidenceSeverity::Warning,
            EvidenceSeverity::Critical,
        ];
        let copied = arr[1];
        assert_eq!(copied, EvidenceSeverity::Warning);
        assert_eq!(arr[1], EvidenceSeverity::Warning);
    }

    #[test]
    fn evidence_record_kind_copy_from_array() {
        let arr = [
            EvidenceRecordKind::DecisionReceipt,
            EvidenceRecordKind::HostcallTelemetry,
            EvidenceRecordKind::ContainmentAction,
            EvidenceRecordKind::PolicyChange,
            EvidenceRecordKind::ReplayArtifact,
        ];
        let copied = arr[3];
        assert_eq!(copied, EvidenceRecordKind::PolicyChange);
        assert_eq!(arr[3], EvidenceRecordKind::PolicyChange);
    }

    // ── Enrichment: Debug distinctness ──────────────────────────

    #[test]
    fn evidence_severity_debug_all_distinct() {
        let dbgs: BTreeSet<String> = [
            EvidenceSeverity::Info,
            EvidenceSeverity::Warning,
            EvidenceSeverity::Critical,
        ]
        .iter()
        .map(|s| format!("{s:?}"))
        .collect();
        assert_eq!(dbgs.len(), 3);
    }

    #[test]
    fn evidence_record_kind_debug_all_distinct() {
        let dbgs: BTreeSet<String> = [
            EvidenceRecordKind::DecisionReceipt,
            EvidenceRecordKind::HostcallTelemetry,
            EvidenceRecordKind::ContainmentAction,
            EvidenceRecordKind::PolicyChange,
            EvidenceRecordKind::ReplayArtifact,
        ]
        .iter()
        .map(|k| format!("{k:?}"))
        .collect();
        assert_eq!(dbgs.len(), 5);
    }

    // ── Enrichment: Serde variant distinctness ──────────────────

    #[test]
    fn evidence_severity_serde_all_variants_produce_distinct_json() {
        let jsons: BTreeSet<String> = [
            EvidenceSeverity::Info,
            EvidenceSeverity::Warning,
            EvidenceSeverity::Critical,
        ]
        .iter()
        .map(|s| serde_json::to_string(s).unwrap())
        .collect();
        assert_eq!(jsons.len(), 3);
    }

    #[test]
    fn evidence_record_kind_serde_all_variants_produce_distinct_json() {
        let jsons: BTreeSet<String> = [
            EvidenceRecordKind::DecisionReceipt,
            EvidenceRecordKind::HostcallTelemetry,
            EvidenceRecordKind::ContainmentAction,
            EvidenceRecordKind::PolicyChange,
            EvidenceRecordKind::ReplayArtifact,
        ]
        .iter()
        .map(|k| serde_json::to_string(k).unwrap())
        .collect();
        assert_eq!(jsons.len(), 5);
    }

    // ── Enrichment: Clone independence ──────────────────────────

    #[test]
    fn structured_log_event_clone_independence() {
        let e = StructuredLogEvent {
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            component: "engine".into(),
            event: "startup".into(),
            outcome: "ok".into(),
            error_code: None,
        };
        let mut cloned = e.clone();
        cloned.trace_id = "modified".into();
        assert_eq!(e.trace_id, "t-1");
    }

    #[test]
    fn gc_pressure_sample_clone_independence() {
        let s = GcPressureSample {
            extension_id: "ext-1".into(),
            used_bytes: 1024,
            budget_bytes: 4096,
        };
        let mut cloned = s.clone();
        cloned.used_bytes = 9999;
        assert_eq!(s.used_bytes, 1024);
    }

    #[test]
    fn scheduler_lane_sample_clone_independence() {
        let s = SchedulerLaneSample {
            lane: "lane-0".into(),
            queue_depth: 5,
            max_depth: 100,
            tasks_submitted: 50,
            tasks_scheduled: 45,
            tasks_completed: 40,
            tasks_timed_out: 2,
        };
        let mut cloned = s.clone();
        cloned.queue_depth = 999;
        assert_eq!(s.queue_depth, 5);
    }

    #[test]
    fn evidence_export_filter_clone_independence() {
        let f = EvidenceExportFilter {
            extension_id: Some("ext-1".into()),
            ..EvidenceExportFilter::default()
        };
        let mut cloned = f.clone();
        cloned.extension_id = Some("modified".into());
        assert_eq!(f.extension_id.as_deref(), Some("ext-1"));
    }

    #[test]
    fn replay_artifact_record_clone_independence() {
        let r = ReplayArtifactRecord {
            trace_id: "t-1".into(),
            extension_id: "ext-1".into(),
            timestamp_ns: 5000,
            artifact_id: "a-1".into(),
            replay_pointer: "ptr-1".into(),
        };
        let mut cloned = r.clone();
        cloned.artifact_id = "modified".into();
        assert_eq!(r.artifact_id, "a-1");
    }

    // ── Enrichment: JSON field-name stability ───────────────────

    #[test]
    fn scheduler_lane_sample_json_field_names() {
        let s = SchedulerLaneSample {
            lane: "lane-0".into(),
            queue_depth: 5,
            max_depth: 100,
            tasks_submitted: 50,
            tasks_scheduled: 45,
            tasks_completed: 40,
            tasks_timed_out: 2,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"lane\""));
        assert!(json.contains("\"queue_depth\""));
        assert!(json.contains("\"max_depth\""));
        assert!(json.contains("\"tasks_submitted\""));
        assert!(json.contains("\"tasks_scheduled\""));
        assert!(json.contains("\"tasks_completed\""));
        assert!(json.contains("\"tasks_timed_out\""));
    }

    #[test]
    fn evidence_export_filter_json_field_names() {
        let f = EvidenceExportFilter {
            extension_id: Some("ext".into()),
            trace_id: Some("t".into()),
            start_timestamp_ns: Some(100),
            end_timestamp_ns: Some(200),
            severity: Some(EvidenceSeverity::Info),
            decision_type: Some(DecisionType::SecurityAction),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"extension_id\""));
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"start_timestamp_ns\""));
        assert!(json.contains("\"end_timestamp_ns\""));
        assert!(json.contains("\"severity\""));
        assert!(json.contains("\"decision_type\""));
    }

    #[test]
    fn evidence_export_summary_json_field_names() {
        let summary = EvidenceExportSummary {
            total_records: 5,
            counts_by_kind: BTreeMap::new(),
            counts_by_severity: BTreeMap::new(),
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"total_records\""));
        assert!(json.contains("\"counts_by_kind\""));
        assert!(json.contains("\"counts_by_severity\""));
    }

    #[test]
    fn gc_pressure_diagnostics_json_field_names() {
        let d = GcPressureDiagnostics {
            extension_id: "ext".into(),
            used_bytes: 100,
            budget_bytes: 200,
            pressure_millionths: 500_000,
            over_budget: false,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"extension_id\""));
        assert!(json.contains("\"used_bytes\""));
        assert!(json.contains("\"budget_bytes\""));
        assert!(json.contains("\"pressure_millionths\""));
        assert!(json.contains("\"over_budget\""));
    }

    #[test]
    fn scheduler_lane_diagnostics_json_field_names() {
        let d = SchedulerLaneDiagnostics {
            lane: "lane".into(),
            queue_depth: 5,
            max_depth: 100,
            utilization_millionths: 50_000,
            tasks_submitted: 10,
            tasks_scheduled: 8,
            tasks_completed: 7,
            tasks_timed_out: 1,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"lane\""));
        assert!(json.contains("\"utilization_millionths\""));
    }

    // ── Enrichment: serde roundtrips ────────────────────────────

    #[test]
    fn evidence_record_kind_serde_roundtrip_all() {
        for k in [
            EvidenceRecordKind::DecisionReceipt,
            EvidenceRecordKind::HostcallTelemetry,
            EvidenceRecordKind::ContainmentAction,
            EvidenceRecordKind::PolicyChange,
            EvidenceRecordKind::ReplayArtifact,
        ] {
            let json = serde_json::to_string(&k).unwrap();
            let back: EvidenceRecordKind = serde_json::from_str(&json).unwrap();
            assert_eq!(k, back);
        }
    }

    #[test]
    fn gc_pressure_diagnostics_serde_roundtrip() {
        let d = GcPressureDiagnostics {
            extension_id: "ext".into(),
            used_bytes: 100,
            budget_bytes: 200,
            pressure_millionths: 500_000,
            over_budget: false,
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: GcPressureDiagnostics = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn scheduler_lane_diagnostics_serde_roundtrip() {
        let d = SchedulerLaneDiagnostics {
            lane: "lane".into(),
            queue_depth: 5,
            max_depth: 100,
            utilization_millionths: 50_000,
            tasks_submitted: 10,
            tasks_scheduled: 8,
            tasks_completed: 7,
            tasks_timed_out: 1,
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: SchedulerLaneDiagnostics = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn evidence_export_filter_serde_roundtrip_with_all_fields() {
        let f = EvidenceExportFilter {
            extension_id: Some("ext".into()),
            trace_id: Some("t".into()),
            start_timestamp_ns: Some(100),
            end_timestamp_ns: Some(200),
            severity: Some(EvidenceSeverity::Warning),
            decision_type: Some(DecisionType::Revocation),
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: EvidenceExportFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn replay_artifact_record_serde_roundtrip_full() {
        let r = ReplayArtifactRecord {
            trace_id: "t".into(),
            extension_id: "ext".into(),
            timestamp_ns: 5000,
            artifact_id: "a".into(),
            replay_pointer: "ptr".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ReplayArtifactRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // ── Enrichment: Debug nonempty ──────────────────────────────

    #[test]
    fn structured_log_event_debug_nonempty() {
        let e = StructuredLogEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "o".into(),
            error_code: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("StructuredLogEvent"));
    }

    #[test]
    fn evidence_export_filter_debug_nonempty() {
        let f = EvidenceExportFilter::default();
        let dbg = format!("{f:?}");
        assert!(dbg.contains("EvidenceExportFilter"));
    }

    #[test]
    fn runtime_diagnostics_output_debug_nonempty() {
        let state = sample_runtime_state();
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        let dbg = format!("{out:?}");
        assert!(dbg.contains("RuntimeDiagnosticsOutput"));
    }

    // ── Enrichment: boundary/edge cases ─────────────────────────

    #[test]
    fn compute_pressure_zero_budget_zero_used() {
        assert_eq!(compute_pressure_millionths(0, 0), 0);
    }

    #[test]
    fn compute_pressure_zero_budget_nonzero_used() {
        assert_eq!(compute_pressure_millionths(100, 0), 1_000_000);
    }

    #[test]
    fn compute_pressure_at_exact_budget() {
        assert_eq!(compute_pressure_millionths(1000, 1000), 1_000_000);
    }

    #[test]
    fn compute_pressure_half_budget() {
        assert_eq!(compute_pressure_millionths(500, 1000), 500_000);
    }

    #[test]
    fn compute_pressure_over_budget_capped() {
        assert_eq!(compute_pressure_millionths(2000, 1000), 1_000_000);
    }

    #[test]
    fn parse_severity_case_insensitive() {
        assert_eq!(
            parse_evidence_severity("INFO"),
            Some(EvidenceSeverity::Info)
        );
        assert_eq!(
            parse_evidence_severity("Warning"),
            Some(EvidenceSeverity::Warning)
        );
        assert_eq!(
            parse_evidence_severity("CRITICAL"),
            Some(EvidenceSeverity::Critical)
        );
    }

    #[test]
    fn parse_severity_with_whitespace() {
        assert_eq!(
            parse_evidence_severity("  info  "),
            Some(EvidenceSeverity::Info)
        );
    }

    #[test]
    fn parse_decision_type_all_variants() {
        assert_eq!(
            parse_decision_type("security_action"),
            Some(DecisionType::SecurityAction)
        );
        assert_eq!(
            parse_decision_type("policy_update"),
            Some(DecisionType::PolicyUpdate)
        );
        assert_eq!(
            parse_decision_type("epoch_transition"),
            Some(DecisionType::EpochTransition)
        );
        assert_eq!(
            parse_decision_type("revocation"),
            Some(DecisionType::Revocation)
        );
        assert_eq!(
            parse_decision_type("extension_lifecycle"),
            Some(DecisionType::ExtensionLifecycle)
        );
        assert_eq!(
            parse_decision_type("capability_decision"),
            Some(DecisionType::CapabilityDecision)
        );
        assert_eq!(
            parse_decision_type("contract_evaluation"),
            Some(DecisionType::ContractEvaluation)
        );
        assert_eq!(
            parse_decision_type("remote_authorization"),
            Some(DecisionType::RemoteAuthorization)
        );
    }

    #[test]
    fn render_evidence_summary_empty_records() {
        let output = EvidenceExportOutput {
            filter: EvidenceExportFilter::default(),
            records: vec![],
            summary: EvidenceExportSummary {
                total_records: 0,
                counts_by_kind: BTreeMap::new(),
                counts_by_severity: BTreeMap::new(),
            },
            logs: vec![],
        };
        let rendered = render_evidence_summary(&output);
        assert!(rendered.contains("No evidence entries found"));
    }

    #[test]
    fn evidence_severity_serde_uses_snake_case() {
        assert_eq!(
            serde_json::to_string(&EvidenceSeverity::Info).unwrap(),
            "\"info\""
        );
        assert_eq!(
            serde_json::to_string(&EvidenceSeverity::Warning).unwrap(),
            "\"warning\""
        );
        assert_eq!(
            serde_json::to_string(&EvidenceSeverity::Critical).unwrap(),
            "\"critical\""
        );
    }

    #[test]
    fn evidence_record_kind_serde_uses_snake_case() {
        assert_eq!(
            serde_json::to_string(&EvidenceRecordKind::DecisionReceipt).unwrap(),
            "\"decision_receipt\""
        );
        assert_eq!(
            serde_json::to_string(&EvidenceRecordKind::HostcallTelemetry).unwrap(),
            "\"hostcall_telemetry\""
        );
    }

    #[test]
    fn filter_timestamp_range_boundary() {
        let filter = EvidenceExportFilter {
            start_timestamp_ns: Some(100),
            end_timestamp_ns: Some(200),
            ..EvidenceExportFilter::default()
        };
        assert!(!filter.matches_timestamp(99));
        assert!(filter.matches_timestamp(100));
        assert!(filter.matches_timestamp(150));
        assert!(filter.matches_timestamp(200));
        assert!(!filter.matches_timestamp(201));
    }

    #[test]
    fn filter_no_constraints_matches_everything() {
        let filter = EvidenceExportFilter::default();
        assert!(filter.matches_timestamp(0));
        assert!(filter.matches_timestamp(u64::MAX));
        assert!(filter.matches_trace("any_trace"));
        assert!(filter.matches_extension(&None));
        assert!(filter.matches_extension(&Some("ext".into())));
        assert!(filter.matches_severity(EvidenceSeverity::Info));
        assert!(filter.matches_decision_type(None));
        assert!(filter.matches_decision_type(Some(DecisionType::Revocation)));
    }

    #[test]
    fn diagnostics_log_component_is_stable() {
        let state = RuntimeStateInput {
            snapshot_timestamp_ns: 0,
            loaded_extensions: vec![],
            active_policies: vec![],
            security_epoch: SecurityEpoch::from_raw(1),
            gc_pressure: vec![],
            scheduler_lanes: vec![],
        };
        let out = collect_runtime_diagnostics(&state, "t", "d", "p");
        assert_eq!(out.logs[0].component, "runtime_diagnostics_cli");
        assert_eq!(out.logs[0].event, "runtime_diagnostics_snapshot");
        assert_eq!(out.logs[0].outcome, "pass");
    }

    #[test]
    fn evidence_export_filter_default_all_none() {
        let f = EvidenceExportFilter::default();
        assert!(f.extension_id.is_none());
        assert!(f.trace_id.is_none());
        assert!(f.start_timestamp_ns.is_none());
        assert!(f.end_timestamp_ns.is_none());
        assert!(f.severity.is_none());
        assert!(f.decision_type.is_none());
    }

    #[test]
    fn gc_pressure_diagnostics_clone_equality() {
        let d = GcPressureDiagnostics {
            extension_id: "ext".into(),
            used_bytes: 100,
            budget_bytes: 200,
            pressure_millionths: 500_000,
            over_budget: false,
        };
        let cloned = d.clone();
        assert_eq!(d, cloned);
    }

    #[test]
    fn scheduler_lane_diagnostics_clone_equality() {
        let d = SchedulerLaneDiagnostics {
            lane: "lane".into(),
            queue_depth: 5,
            max_depth: 100,
            utilization_millionths: 50_000,
            tasks_submitted: 10,
            tasks_scheduled: 8,
            tasks_completed: 7,
            tasks_timed_out: 1,
        };
        let cloned = d.clone();
        assert_eq!(d, cloned);
    }

    #[test]
    fn support_bundle_redacts_sensitive_fields_and_is_deterministic() {
        let mut input = sample_input();
        let first = input
            .evidence_entries
            .first_mut()
            .expect("sample input must have at least one evidence entry");
        first
            .metadata
            .insert("api_token".to_string(), "secret-token-value".to_string());

        let policy = SupportBundleRedactionPolicy::default();
        let first_export = export_support_bundle(&input, EvidenceExportFilter::default(), policy);
        let second_export = export_support_bundle(
            &input,
            EvidenceExportFilter::default(),
            SupportBundleRedactionPolicy::default(),
        );

        assert_eq!(first_export, second_export);
        assert!(first_export.index.total_redacted_fields >= 1);
        assert!(
            first_export
                .index
                .files
                .iter()
                .any(|file| file.path == "support_bundle/evidence_records.jsonl")
        );

        let evidence_file = first_export
            .files
            .iter()
            .find(|file| file.path == "support_bundle/evidence_records.jsonl")
            .expect("evidence records file must be present");
        assert!(!evidence_file.content.contains("secret-token-value"));
        assert!(
            evidence_file
                .content
                .contains(DEFAULT_SUPPORT_BUNDLE_REDACTION_MARKER)
        );
    }

    #[test]
    fn support_bundle_summary_lists_repro_commands() {
        let output = export_support_bundle(
            &sample_input(),
            EvidenceExportFilter::default(),
            SupportBundleRedactionPolicy::default(),
        );
        let rendered = render_support_bundle_summary(&output);

        assert!(rendered.contains("bundle_id: bundle-"));
        assert!(rendered.contains("total_records:"));
        assert!(rendered.contains("reproducible_commands:"));
        assert!(rendered.contains("runtime_diagnostics support-bundle --input <path> --summary"));
    }

    fn sample_compatibility_outcome(
        case_id: &str,
        category: DivergenceCategory,
        guidance: &str,
    ) -> CompatibilityObservationOutcome {
        CompatibilityObservationOutcome {
            case_id: case_id.to_string(),
            runtime: CompatibilityRuntime::FrankenEngine,
            mode: CompatibilityMode::Native,
            observed_behavior: "native behavior".to_string(),
            expected_behavior: "native behavior".to_string(),
            matched: true,
            divergence: Some(DivergencePolicy {
                diverges_from: vec![ReferenceRuntime::Node],
                reason: category.as_str().to_string(),
                impact: "detected in synthetic compatibility report".to_string(),
                waiver_id: "waiver-1".to_string(),
                migration_guidance: guidance.to_string(),
            }),
            divergence_category: Some(category),
            actionable_guidance: Some(guidance.to_string()),
            event: CompatibilityEvent {
                seq: 0,
                trace_id: "trace-compat".to_string(),
                decision_id: "decision-compat".to_string(),
                policy_id: "policy-compat".to_string(),
                component: "module_compatibility_matrix".to_string(),
                event: "compatibility_observation".to_string(),
                outcome: "allow".to_string(),
                error_code: "none".to_string(),
                case_id: case_id.to_string(),
                runtime: "franken_engine".to_string(),
                mode: "native".to_string(),
                detail: "deterministic synthetic observation".to_string(),
            },
        }
    }

    #[test]
    fn compatibility_advisories_map_categories_to_expected_profiles() {
        let report = CompatibilityScenarioReport {
            schema_version: "franken-engine.module-interop-scenario-report.v1".to_string(),
            scenario_id: "scenario-compat".to_string(),
            trace_id: "trace-compat".to_string(),
            decision_id: "decision-compat".to_string(),
            policy_id: "policy-compat".to_string(),
            generated_at_unix_ms: 1_234,
            total_observations: 2,
            matched_observations: 2,
            divergence_category_counts: BTreeMap::new(),
            actionable_guidance: BTreeMap::new(),
            outcomes: vec![
                sample_compatibility_outcome(
                    "case-engine-bug",
                    DivergenceCategory::EngineBug,
                    "patch runtime lane semantics",
                ),
                sample_compatibility_outcome(
                    "case-reference-runtime",
                    DivergenceCategory::ReferenceRuntimeBug,
                    "track upstream bug and keep workaround",
                ),
            ],
        };

        let output = build_compatibility_advisories(&CompatibilityAdvisoryInput {
            source_report: "artifacts/compat/scenario_report.json".to_string(),
            scenario_report: report,
        });

        assert_eq!(output.advisory_count, 2);
        assert_eq!(output.signals.len(), 2);
        assert!(
            output
                .signals
                .iter()
                .all(|signal| signal.source == "compatibility_advisory")
        );

        let critical = output
            .advisories
            .iter()
            .find(|advisory| advisory.case_id == "case-engine-bug")
            .expect("critical advisory should exist");
        assert_eq!(critical.severity, EvidenceSeverity::Critical);
        assert_eq!(
            critical.user_impact,
            CompatibilityUserImpactClass::BreakingBehavior
        );
        assert_eq!(
            critical.remediation_complexity,
            OnboardingRemediationEffort::High
        );
        assert!(
            critical
                .reproducible_command
                .contains("runtime_diagnostics compatibility-advisories")
        );

        let info = output
            .advisories
            .iter()
            .find(|advisory| advisory.case_id == "case-reference-runtime")
            .expect("reference-runtime advisory should exist");
        assert_eq!(info.severity, EvidenceSeverity::Info);
        assert_eq!(
            info.user_impact,
            CompatibilityUserImpactClass::UpstreamRuntimeDrift
        );
        assert_eq!(
            info.remediation_complexity,
            OnboardingRemediationEffort::Low
        );
    }

    #[test]
    fn compatibility_advisory_summary_includes_counts() {
        let report = CompatibilityScenarioReport {
            schema_version: "franken-engine.module-interop-scenario-report.v1".to_string(),
            scenario_id: "scenario-compat-summary".to_string(),
            trace_id: "trace-compat".to_string(),
            decision_id: "decision-compat".to_string(),
            policy_id: "policy-compat".to_string(),
            generated_at_unix_ms: 4_321,
            total_observations: 1,
            matched_observations: 1,
            divergence_category_counts: BTreeMap::new(),
            actionable_guidance: BTreeMap::new(),
            outcomes: vec![sample_compatibility_outcome(
                "case-compat-debt",
                DivergenceCategory::CompatibilityDebt,
                "close parity gap in module resolver",
            )],
        };

        let output = build_compatibility_advisories(&CompatibilityAdvisoryInput {
            source_report: "artifacts/compat/summary_report.json".to_string(),
            scenario_report: report,
        });
        let rendered = render_compatibility_advisory_summary(&output);
        assert!(rendered.contains("schema_version:"));
        assert!(rendered.contains("advisory_count: 1"));
        assert!(rendered.contains("divergence_category_counts:"));
        assert!(rendered.contains("compatibility_debt"));
        assert!(rendered.contains("signals:"));
    }

    #[test]
    fn onboarding_scorecard_is_deterministic() {
        let preflight = run_preflight_doctor(
            &sample_input(),
            EvidenceExportFilter::default(),
            SupportBundleRedactionPolicy::default(),
        );
        let input = OnboardingScorecardInput {
            workload_id: "pkg/weather-ext".to_string(),
            package_name: "weather-ext".to_string(),
            target_platforms: vec!["linux-x64".to_string(), "linux-x64".to_string()],
            preflight: preflight.clone(),
            external_signals: vec![
                OnboardingScorecardSignal {
                    signal_id: "compat:001".to_string(),
                    source: "compatibility_advisory".to_string(),
                    severity: EvidenceSeverity::Warning,
                    summary: "node parity drift in fs module".to_string(),
                    remediation: "apply deterministic shim for fs edge behavior".to_string(),
                    reproducible_command: "runtime_diagnostics doctor --input <path> --summary"
                        .to_string(),
                    evidence_links: vec!["artifacts/lockstep/report.json".to_string()],
                    owner_hint: Some("compatibility-lane".to_string()),
                },
                OnboardingScorecardSignal {
                    signal_id: "platform:002".to_string(),
                    source: "platform_matrix".to_string(),
                    severity: EvidenceSeverity::Critical,
                    summary: "arm64 rollout gap blocks parity".to_string(),
                    remediation: "close arm64 matrix gaps before enablement".to_string(),
                    reproducible_command:
                        "runtime_diagnostics rollout-decision-artifact --input <path> --summary"
                            .to_string(),
                    evidence_links: vec!["artifacts/platform/matrix-arm64.json".to_string()],
                    owner_hint: Some("platform-matrix-lane".to_string()),
                },
                OnboardingScorecardSignal {
                    signal_id: "platform:003".to_string(),
                    source: "platform_matrix".to_string(),
                    severity: EvidenceSeverity::Critical,
                    summary: "windows-x64 smoke lane missing deterministic replay".to_string(),
                    remediation: "publish replay receipts for windows-x64 lane".to_string(),
                    reproducible_command:
                        "runtime_diagnostics rollout-decision-artifact --input <path> --summary"
                            .to_string(),
                    evidence_links: vec!["artifacts/platform/matrix-windows.json".to_string()],
                    owner_hint: Some("platform-matrix-lane".to_string()),
                },
            ],
        };

        let left = build_onboarding_scorecard(&input);
        let right = build_onboarding_scorecard(&input);
        assert_eq!(left, right);
        assert_eq!(left.readiness, OnboardingReadinessClass::Blocked);
        assert_eq!(left.remediation_effort, OnboardingRemediationEffort::High);
        assert_eq!(left.target_platforms, vec!["linux-x64".to_string()]);
    }

    #[test]
    fn onboarding_scorecard_ready_for_clean_input() {
        let mut input = sample_input();
        input.evidence_entries.clear();
        input.containment_receipts.clear();
        input
            .hostcall_records
            .retain(|record| matches!(record.record.result_status, HostcallResult::Success));
        for sample in &mut input.runtime_state.gc_pressure {
            sample.used_bytes = sample.used_bytes.min(sample.budget_bytes);
        }
        for lane in &mut input.runtime_state.scheduler_lanes {
            lane.tasks_timed_out = 0;
            lane.queue_depth = 0;
        }

        let preflight = run_preflight_doctor(
            &input,
            EvidenceExportFilter::default(),
            SupportBundleRedactionPolicy::default(),
        );
        assert_eq!(preflight.verdict, PreflightVerdict::Green);

        let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
            workload_id: "pkg/clean-ext".to_string(),
            package_name: "clean-ext".to_string(),
            target_platforms: vec!["linux-x64".to_string(), "macos-arm64".to_string()],
            preflight,
            external_signals: Vec::new(),
        });

        assert_eq!(scorecard.readiness, OnboardingReadinessClass::Ready);
        assert_eq!(
            scorecard.remediation_effort,
            OnboardingRemediationEffort::Low
        );
        assert_eq!(scorecard.score.critical_signals, 0);
        assert_eq!(scorecard.score.warning_signals, 0);
        assert_eq!(scorecard.score.info_signals, 0);
        assert!(scorecard.next_steps.is_empty());
    }

    #[test]
    fn onboarding_scorecard_summary_includes_commands() {
        let preflight = run_preflight_doctor(
            &sample_input(),
            EvidenceExportFilter::default(),
            SupportBundleRedactionPolicy::default(),
        );
        let scorecard = build_onboarding_scorecard(&OnboardingScorecardInput {
            workload_id: "pkg/example".to_string(),
            package_name: "example".to_string(),
            target_platforms: vec!["linux-x64".to_string()],
            preflight,
            external_signals: Vec::new(),
        });

        let rendered = render_onboarding_scorecard_summary(&scorecard);
        assert!(rendered.contains("schema_version:"));
        assert!(rendered.contains("readiness: blocked"));
        assert!(rendered.contains("reproducible_commands:"));
        assert!(rendered.contains("runtime_diagnostics doctor --input <path> --summary"));
    }

    #[test]
    fn rollout_decision_artifact_promotes_clean_workloads() {
        let mut input = sample_input();
        input.evidence_entries.clear();
        input.containment_receipts.clear();
        input
            .hostcall_records
            .retain(|record| matches!(record.record.result_status, HostcallResult::Success));
        for sample in &mut input.runtime_state.gc_pressure {
            sample.used_bytes = sample.used_bytes.min(sample.budget_bytes);
        }
        for lane in &mut input.runtime_state.scheduler_lanes {
            lane.tasks_timed_out = 0;
            lane.queue_depth = 0;
        }

        let preflight = run_preflight_doctor(
            &input,
            EvidenceExportFilter::default(),
            SupportBundleRedactionPolicy::default(),
        );
        let onboarding = build_onboarding_scorecard(&OnboardingScorecardInput {
            workload_id: "pkg/clean-ext".to_string(),
            package_name: "clean-ext".to_string(),
            target_platforms: vec!["linux-x64".to_string()],
            preflight,
            external_signals: Vec::new(),
        });

        let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
            onboarding_scorecard: onboarding,
            compatibility_advisories: Vec::new(),
            platform_matrix_signals: Vec::new(),
        });

        assert_eq!(artifact.recommendation, RolloutRecommendation::Promote);
        assert!(artifact.mandatory_field_status.valid);
        assert!(artifact.ga_gate_consumable);
        assert!(artifact.pilot_gate_consumable);
        assert!(!artifact.evidence_links.is_empty());
    }

    #[test]
    fn rollout_decision_artifact_prefers_rollback_for_platform_critical_signal() {
        let mut input = sample_input();
        input.evidence_entries.clear();
        input.containment_receipts.clear();
        input
            .hostcall_records
            .retain(|record| matches!(record.record.result_status, HostcallResult::Success));
        for sample in &mut input.runtime_state.gc_pressure {
            sample.used_bytes = sample.used_bytes.min(sample.budget_bytes);
        }
        for lane in &mut input.runtime_state.scheduler_lanes {
            lane.tasks_timed_out = 0;
            lane.queue_depth = 0;
        }

        let preflight = run_preflight_doctor(
            &input,
            EvidenceExportFilter::default(),
            SupportBundleRedactionPolicy::default(),
        );
        let onboarding = build_onboarding_scorecard(&OnboardingScorecardInput {
            workload_id: "pkg/clean-ext".to_string(),
            package_name: "clean-ext".to_string(),
            target_platforms: vec!["linux-x64".to_string()],
            preflight,
            external_signals: Vec::new(),
        });

        let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
            onboarding_scorecard: onboarding,
            compatibility_advisories: Vec::new(),
            platform_matrix_signals: vec![OnboardingScorecardSignal {
                signal_id: "matrix:linux-x64".to_string(),
                source: "platform_matrix".to_string(),
                severity: EvidenceSeverity::Critical,
                summary: "critical drift in linux-x64 lockstep output".to_string(),
                remediation: "rollback linux-x64 promotion and re-run matrix".to_string(),
                reproducible_command: "scripts/run_rgc_cross_platform_matrix_gate.sh ci"
                    .to_string(),
                evidence_links: vec![
                    "artifacts/rgc_cross_platform_matrix/latest/report.json".to_string(),
                ],
                owner_hint: Some("platform-matrix-lane".to_string()),
            }],
        });

        assert_eq!(artifact.recommendation, RolloutRecommendation::Rollback);
        assert!(
            artifact
                .merged_signals
                .iter()
                .any(|signal| signal.source == "platform_matrix"
                    && signal.severity == EvidenceSeverity::Critical)
        );
    }

    #[test]
    fn rollout_decision_artifact_conflict_resolution_prefers_higher_severity() {
        let mut input = sample_input();
        input.evidence_entries.clear();
        input.containment_receipts.clear();
        input
            .hostcall_records
            .retain(|record| matches!(record.record.result_status, HostcallResult::Success));
        for sample in &mut input.runtime_state.gc_pressure {
            sample.used_bytes = sample.used_bytes.min(sample.budget_bytes);
        }
        for lane in &mut input.runtime_state.scheduler_lanes {
            lane.tasks_timed_out = 0;
            lane.queue_depth = 0;
        }

        let preflight = run_preflight_doctor(
            &input,
            EvidenceExportFilter::default(),
            SupportBundleRedactionPolicy::default(),
        );
        let onboarding = build_onboarding_scorecard(&OnboardingScorecardInput {
            workload_id: "pkg/clean-ext".to_string(),
            package_name: "clean-ext".to_string(),
            target_platforms: vec!["linux-x64".to_string()],
            preflight,
            external_signals: vec![OnboardingScorecardSignal {
                signal_id: "compat:fs".to_string(),
                source: "compatibility_advisory".to_string(),
                severity: EvidenceSeverity::Warning,
                summary: "warning-level parity drift".to_string(),
                remediation: "review shim behavior".to_string(),
                reproducible_command: "scripts/run_frx_lockstep_oracle_suite.sh ci".to_string(),
                evidence_links: vec![
                    "artifacts/frx_lockstep_oracle/latest/report.json".to_string(),
                ],
                owner_hint: Some("compatibility-lane".to_string()),
            }],
        });

        let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
            onboarding_scorecard: onboarding,
            compatibility_advisories: vec![OnboardingScorecardSignal {
                signal_id: "compat:fs".to_string(),
                source: "compatibility_advisory".to_string(),
                severity: EvidenceSeverity::Critical,
                summary: "critical parity drift".to_string(),
                remediation: "block promotion until drift is resolved".to_string(),
                reproducible_command: "scripts/run_frx_lockstep_oracle_suite.sh ci".to_string(),
                evidence_links: vec![
                    "artifacts/frx_lockstep_oracle/latest/report.json".to_string(),
                ],
                owner_hint: Some("compatibility-lane".to_string()),
            }],
            platform_matrix_signals: Vec::new(),
        });

        assert!(
            artifact
                .merged_signals
                .iter()
                .any(|signal| signal.signal_id == "compat:fs"
                    && signal.severity == EvidenceSeverity::Critical
                    && signal.summary == "critical parity drift")
        );
    }

    #[test]
    fn rollout_decision_artifact_fails_closed_when_required_fields_missing() {
        let preflight = run_preflight_doctor(
            &sample_input(),
            EvidenceExportFilter::default(),
            SupportBundleRedactionPolicy::default(),
        );
        let mut onboarding = build_onboarding_scorecard(&OnboardingScorecardInput {
            workload_id: "pkg/example".to_string(),
            package_name: "example".to_string(),
            target_platforms: vec!["linux-x64".to_string()],
            preflight,
            external_signals: Vec::new(),
        });
        onboarding.workload_id.clear();
        onboarding.logs.clear();

        let artifact = build_rollout_decision_artifact(&RolloutDecisionArtifactInput {
            onboarding_scorecard: onboarding,
            compatibility_advisories: Vec::new(),
            platform_matrix_signals: Vec::new(),
        });

        assert_eq!(artifact.recommendation, RolloutRecommendation::Defer);
        assert!(!artifact.mandatory_field_status.valid);
        assert!(!artifact.ga_gate_consumable);
        assert!(!artifact.pilot_gate_consumable);

        let summary = render_rollout_decision_artifact_summary(&artifact);
        assert!(summary.contains("missing_fields:"));
        assert!(summary.contains("mandatory_fields_valid: false"));
    }
}
