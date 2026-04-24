use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::capability_witness::{CapabilityEscrowReceiptRecord, ProofKind, WitnessReplayJoinRow};
use crate::slot_registry::{
    PromotionStatus, PromotionTransition, ReplacementProgressEvent, ReplacementProgressSnapshot,
    SlotEntry, SlotRegistry,
};

pub const FRANKENTUI_ADAPTER_SCHEMA_VERSION: u32 = 1;
const UNKNOWN_LABEL: &str = "unknown";

/// Boundary payloads from engine runtime state to `/dp/frankentui` presentation.
/// This module intentionally carries structured data only; policy and runtime
/// decision logic must remain outside the TUI layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrankentuiViewPayload {
    IncidentReplay(IncidentReplayView),
    PolicyExplanation(PolicyExplanationCardView),
    ControlDashboard(ControlDashboardView),
    ControlPlaneInvariantsDashboard(Box<ControlPlaneInvariantsDashboardView>),
    FlowDecisionDashboard(FlowDecisionDashboardView),
    CapabilityDeltaDashboard(CapabilityDeltaDashboardView),
    ReplacementProgressDashboard(ReplacementProgressDashboardView),
    ProofSpecializationLineageDashboard(ProofSpecializationLineageDashboardView),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterStream {
    IncidentReplay,
    PolicyExplanation,
    ControlDashboard,
    ControlPlaneInvariantsDashboard,
    FlowDecisionDashboard,
    CapabilityDeltaDashboard,
    ReplacementProgressDashboard,
    ProofSpecializationLineageDashboard,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateKind {
    Snapshot,
    Delta,
    Heartbeat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterEnvelope {
    pub schema_version: u32,
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub generated_at_unix_ms: u64,
    pub stream: AdapterStream,
    pub update_kind: UpdateKind,
    pub payload: FrankentuiViewPayload,
}

impl AdapterEnvelope {
    pub fn new(
        trace_id: impl Into<String>,
        generated_at_unix_ms: u64,
        stream: AdapterStream,
        update_kind: UpdateKind,
        payload: FrankentuiViewPayload,
    ) -> Self {
        Self {
            schema_version: FRANKENTUI_ADAPTER_SCHEMA_VERSION,
            trace_id: normalize_non_empty(trace_id.into()),
            decision_id: None,
            policy_id: None,
            generated_at_unix_ms,
            stream,
            update_kind,
            payload,
        }
    }

    pub fn with_decision_context(
        mut self,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        self.decision_id = Some(normalize_non_empty(decision_id.into()));
        self.policy_id = Some(normalize_non_empty(policy_id.into()));
        self
    }

    pub fn encode_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentReplayView {
    pub trace_id: String,
    pub scenario_name: String,
    pub deterministic: bool,
    pub replay_status: ReplayStatus,
    pub events: Vec<ReplayEventView>,
    pub artifact_handles: Vec<String>,
}

impl IncidentReplayView {
    pub fn snapshot(
        trace_id: impl Into<String>,
        scenario_name: impl Into<String>,
        events: Vec<ReplayEventView>,
    ) -> Self {
        Self {
            trace_id: normalize_non_empty(trace_id.into()),
            scenario_name: normalize_non_empty(scenario_name.into()),
            deterministic: true,
            replay_status: if events.is_empty() {
                ReplayStatus::NoEvents
            } else {
                ReplayStatus::Complete
            },
            events,
            artifact_handles: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    Running,
    Complete,
    Failed,
    NoEvents,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayEventView {
    pub sequence: u64,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub timestamp_unix_ms: u64,
}

impl ReplayEventView {
    pub fn new(
        sequence: u64,
        component: impl Into<String>,
        event: impl Into<String>,
        outcome: impl Into<String>,
        timestamp_unix_ms: u64,
    ) -> Self {
        Self {
            sequence,
            component: normalize_non_empty(component.into()),
            event: normalize_non_empty(event.into()),
            outcome: normalize_non_empty(outcome.into()),
            error_code: None,
            timestamp_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyExplanationCardView {
    pub decision_id: String,
    pub policy_id: String,
    pub selected_action: String,
    pub confidence_millionths: i64,
    pub expected_loss_millionths: i64,
    pub action_candidates: Vec<ActionCandidateView>,
    pub key_drivers: Vec<DriverView>,
}

impl PolicyExplanationCardView {
    pub fn from_partial(input: PolicyExplanationPartial) -> Self {
        Self {
            decision_id: normalize_non_empty(input.decision_id),
            policy_id: normalize_non_empty(input.policy_id),
            selected_action: normalize_non_empty(input.selected_action),
            confidence_millionths: input.confidence_millionths.unwrap_or(0),
            expected_loss_millionths: input.expected_loss_millionths.unwrap_or(0),
            action_candidates: input.action_candidates,
            key_drivers: input.key_drivers,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PolicyExplanationPartial {
    pub decision_id: String,
    pub policy_id: String,
    pub selected_action: String,
    pub confidence_millionths: Option<i64>,
    pub expected_loss_millionths: Option<i64>,
    #[serde(default)]
    pub action_candidates: Vec<ActionCandidateView>,
    #[serde(default)]
    pub key_drivers: Vec<DriverView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionCandidateView {
    pub action: String,
    pub expected_loss_millionths: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriverView {
    pub name: String,
    pub contribution_millionths: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlDashboardView {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: u64,
    pub runtime_mode: String,
    pub metrics: Vec<DashboardMetricView>,
    pub extension_rows: Vec<ExtensionStatusRow>,
    pub incident_counts: BTreeMap<String, u64>,
}

impl ControlDashboardView {
    pub fn from_partial(input: ControlDashboardPartial) -> Self {
        Self {
            cluster: normalize_non_empty(input.cluster),
            zone: normalize_non_empty(input.zone),
            security_epoch: input.security_epoch.unwrap_or(0),
            runtime_mode: normalize_non_empty(input.runtime_mode),
            metrics: input.metrics,
            extension_rows: input.extension_rows,
            incident_counts: input.incident_counts,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ControlDashboardPartial {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: Option<u64>,
    pub runtime_mode: String,
    #[serde(default)]
    pub metrics: Vec<DashboardMetricView>,
    #[serde(default)]
    pub extension_rows: Vec<ExtensionStatusRow>,
    #[serde(default)]
    pub incident_counts: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardMetricView {
    pub metric: String,
    pub value: i64,
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionStatusRow {
    pub extension_id: String,
    pub state: String,
    pub trust_level: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DashboardSeverity {
    #[default]
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcomeKind {
    Allow,
    Deny,
    Fallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationState {
    Open,
    Fulfilled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancellationKind {
    Unload,
    Quarantine,
    Suspend,
    Terminate,
    Revocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReplayHealthStatus {
    Pass,
    Fail,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    #[default]
    Recovering,
    Recovered,
    Waived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SchemaCompatibilityStatus {
    #[default]
    Unknown,
    Compatible,
    NeedsMigration,
    Incompatible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceStreamEntryView {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub action_type: String,
    pub decision_outcome: DecisionOutcomeKind,
    pub expected_loss_millionths: i64,
    pub extension_id: String,
    pub region_id: String,
    pub severity: DashboardSeverity,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub timestamp_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DecisionOutcomesPanelView {
    pub allow_count: u64,
    pub deny_count: u64,
    pub fallback_count: u64,
    pub average_expected_loss_millionths: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationStatusRowView {
    pub obligation_id: String,
    pub extension_id: String,
    pub region_id: String,
    pub state: ObligationState,
    pub severity: DashboardSeverity,
    pub due_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObligationStatusPanelView {
    pub open_count: u64,
    pub fulfilled_count: u64,
    pub failed_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionLifecycleRowView {
    pub region_id: String,
    pub is_active: bool,
    pub active_extensions: u64,
    pub created_at_unix_ms: u64,
    pub closed_at_unix_ms: Option<u64>,
    pub quiescent_close_time_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RegionLifecyclePanelView {
    pub active_region_count: u64,
    pub region_creations_in_window: u64,
    pub region_destructions_in_window: u64,
    pub average_quiescent_close_time_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationEventView {
    pub extension_id: String,
    pub region_id: String,
    pub cancellation_kind: CancellationKind,
    pub severity: DashboardSeverity,
    pub detail: String,
    pub timestamp_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReplayHealthPanelView {
    pub last_run_status: ReplayHealthStatus,
    pub divergence_count: u64,
    pub last_replay_timestamp_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkTrendPointView {
    pub timestamp_unix_ms: u64,
    pub throughput_tps: u64,
    pub latency_p95_ms: u64,
    pub memory_peak_mb: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BenchmarkTrendsPanelView {
    pub points: Vec<BenchmarkTrendPointView>,
    pub throughput_floor_tps: u64,
    pub latency_p95_ceiling_ms: u64,
    pub memory_peak_ceiling_mb: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeModeActivationView {
    pub activation_id: String,
    pub activation_type: String,
    pub extension_id: String,
    pub region_id: String,
    pub severity: DashboardSeverity,
    pub recovery_status: RecoveryStatus,
    pub activated_at_unix_ms: u64,
    pub recovered_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SchemaVersionPanelView {
    pub evidence_schema_version: u32,
    pub last_migration_unix_ms: Option<u64>,
    pub compatibility_status: SchemaCompatibilityStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DashboardAlertMetric {
    ObligationFailureRateMillionths,
    ReplayDivergenceCount,
    SafeModeActivationCount,
    CancellationEventCount,
    FallbackActivationCount,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdComparator {
    GreaterThan,
    GreaterOrEqual,
    LessThan,
    LessOrEqual,
    Equal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardAlertRule {
    pub rule_id: String,
    pub description: String,
    pub metric: DashboardAlertMetric,
    pub comparator: ThresholdComparator,
    pub threshold: i64,
    pub severity: DashboardSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggeredAlertView {
    pub rule_id: String,
    pub description: String,
    pub metric: DashboardAlertMetric,
    pub observed_value: i64,
    pub threshold: i64,
    pub severity: DashboardSeverity,
    pub triggered_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardRefreshPolicy {
    pub evidence_stream_refresh_secs: u64,
    pub aggregate_refresh_secs: u64,
}

impl Default for DashboardRefreshPolicy {
    fn default() -> Self {
        Self {
            evidence_stream_refresh_secs: 5,
            aggregate_refresh_secs: 60,
        }
    }
}

impl DashboardRefreshPolicy {
    fn normalized(self) -> Self {
        let evidence_stream_refresh_secs = if self.evidence_stream_refresh_secs == 0 {
            5
        } else {
            self.evidence_stream_refresh_secs.max(5)
        };
        let aggregate_refresh_secs = if self.aggregate_refresh_secs == 0 {
            60
        } else {
            self.aggregate_refresh_secs.max(60)
        };
        Self {
            evidence_stream_refresh_secs,
            aggregate_refresh_secs,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneInvariantsDashboardView {
    pub cluster: String,
    pub zone: String,
    pub runtime_mode: String,
    pub generated_at_unix_ms: u64,
    pub refresh_policy: DashboardRefreshPolicy,
    pub evidence_stream_last_updated_unix_ms: u64,
    pub aggregates_last_updated_unix_ms: u64,
    pub evidence_stream: Vec<EvidenceStreamEntryView>,
    pub decision_outcomes: DecisionOutcomesPanelView,
    pub obligation_status: ObligationStatusPanelView,
    pub obligation_rows: Vec<ObligationStatusRowView>,
    pub region_lifecycle: RegionLifecyclePanelView,
    pub region_rows: Vec<RegionLifecycleRowView>,
    pub cancellation_events: Vec<CancellationEventView>,
    pub replay_health: ReplayHealthPanelView,
    pub benchmark_trends: BenchmarkTrendsPanelView,
    pub safe_mode_activations: Vec<SafeModeActivationView>,
    pub schema_version: SchemaVersionPanelView,
    pub alert_rules: Vec<DashboardAlertRule>,
}

impl ControlPlaneInvariantsDashboardView {
    pub fn from_partial(input: ControlPlaneInvariantsPartial) -> Self {
        let mut evidence_stream = input.evidence_stream;
        evidence_stream.sort_by(|left, right| {
            left.timestamp_unix_ms
                .cmp(&right.timestamp_unix_ms)
                .then(left.trace_id.cmp(&right.trace_id))
                .then(left.decision_id.cmp(&right.decision_id))
                .then(left.policy_id.cmp(&right.policy_id))
        });
        for entry in &mut evidence_stream {
            entry.trace_id = normalize_non_empty(std::mem::take(&mut entry.trace_id));
            entry.decision_id = normalize_non_empty(std::mem::take(&mut entry.decision_id));
            entry.policy_id = normalize_non_empty(std::mem::take(&mut entry.policy_id));
            entry.action_type = normalize_non_empty(std::mem::take(&mut entry.action_type));
            entry.extension_id = normalize_non_empty(std::mem::take(&mut entry.extension_id));
            entry.region_id = normalize_non_empty(std::mem::take(&mut entry.region_id));
            entry.component = normalize_non_empty(std::mem::take(&mut entry.component));
            entry.event = normalize_non_empty(std::mem::take(&mut entry.event));
            entry.outcome = normalize_non_empty(std::mem::take(&mut entry.outcome));
            entry.error_code = normalize_optional_non_empty(entry.error_code.take());
        }

        let mut obligation_rows = input.obligation_rows;
        obligation_rows.sort_by(|left, right| {
            left.obligation_id
                .cmp(&right.obligation_id)
                .then(left.updated_at_unix_ms.cmp(&right.updated_at_unix_ms))
        });
        for row in &mut obligation_rows {
            row.obligation_id = normalize_non_empty(std::mem::take(&mut row.obligation_id));
            row.extension_id = normalize_non_empty(std::mem::take(&mut row.extension_id));
            row.region_id = normalize_non_empty(std::mem::take(&mut row.region_id));
            row.detail = normalize_non_empty(std::mem::take(&mut row.detail));
        }

        let mut region_rows = input.region_rows;
        region_rows.sort_by(|left, right| left.region_id.cmp(&right.region_id));
        for row in &mut region_rows {
            row.region_id = normalize_non_empty(std::mem::take(&mut row.region_id));
        }

        let mut cancellation_events = input.cancellation_events;
        cancellation_events.sort_by(|left, right| {
            left.timestamp_unix_ms
                .cmp(&right.timestamp_unix_ms)
                .then(left.extension_id.cmp(&right.extension_id))
                .then(left.region_id.cmp(&right.region_id))
        });
        for event in &mut cancellation_events {
            event.extension_id = normalize_non_empty(std::mem::take(&mut event.extension_id));
            event.region_id = normalize_non_empty(std::mem::take(&mut event.region_id));
            event.detail = normalize_non_empty(std::mem::take(&mut event.detail));
        }

        let mut benchmark_points = input.benchmark_points;
        benchmark_points.sort_by_key(|left| left.timestamp_unix_ms);

        let mut safe_mode_activations = input.safe_mode_activations;
        safe_mode_activations.sort_by(|left, right| {
            left.activated_at_unix_ms
                .cmp(&right.activated_at_unix_ms)
                .then(left.activation_id.cmp(&right.activation_id))
        });
        for activation in &mut safe_mode_activations {
            activation.activation_id =
                normalize_non_empty(std::mem::take(&mut activation.activation_id));
            activation.activation_type =
                normalize_non_empty(std::mem::take(&mut activation.activation_type));
            activation.extension_id =
                normalize_non_empty(std::mem::take(&mut activation.extension_id));
            activation.region_id = normalize_non_empty(std::mem::take(&mut activation.region_id));
        }

        let mut alert_rules = input.alert_rules;
        alert_rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        for rule in &mut alert_rules {
            rule.rule_id = normalize_non_empty(std::mem::take(&mut rule.rule_id));
            rule.description = normalize_non_empty(std::mem::take(&mut rule.description));
        }

        let refresh_policy = input.refresh_policy.unwrap_or_default().normalized();
        let generated_at_unix_ms = input.generated_at_unix_ms.unwrap_or(0);
        let evidence_stream_last_updated_unix_ms = input
            .evidence_stream_last_updated_unix_ms
            .or_else(|| evidence_stream.last().map(|entry| entry.timestamp_unix_ms))
            .unwrap_or(generated_at_unix_ms);
        let aggregates_last_updated_unix_ms = input
            .aggregates_last_updated_unix_ms
            .unwrap_or(generated_at_unix_ms);

        let decision_outcomes = input
            .decision_outcomes
            .unwrap_or_else(|| summarize_decision_outcomes(&evidence_stream));
        let obligation_status = input
            .obligation_status
            .unwrap_or_else(|| summarize_obligation_status(&obligation_rows));
        let region_lifecycle = input
            .region_lifecycle
            .unwrap_or_else(|| summarize_region_lifecycle(&region_rows));
        let replay_health = input.replay_health.unwrap_or_default();
        let schema_version = input.schema_version.unwrap_or_default();
        let benchmark_trends = BenchmarkTrendsPanelView {
            points: benchmark_points,
            throughput_floor_tps: input.throughput_floor_tps.unwrap_or(0),
            latency_p95_ceiling_ms: input.latency_p95_ceiling_ms.unwrap_or(0),
            memory_peak_ceiling_mb: input.memory_peak_ceiling_mb.unwrap_or(0),
        };

        Self {
            cluster: normalize_non_empty(input.cluster),
            zone: normalize_non_empty(input.zone),
            runtime_mode: normalize_non_empty(input.runtime_mode),
            generated_at_unix_ms,
            refresh_policy,
            evidence_stream_last_updated_unix_ms,
            aggregates_last_updated_unix_ms,
            evidence_stream,
            decision_outcomes,
            obligation_status,
            obligation_rows,
            region_lifecycle,
            region_rows,
            cancellation_events,
            replay_health,
            benchmark_trends,
            safe_mode_activations,
            schema_version,
            alert_rules,
        }
    }

    pub fn filtered(&self, filter: &ControlPlaneDashboardFilter) -> Self {
        let evidence_stream = self
            .evidence_stream
            .iter()
            .filter(|entry| evidence_entry_matches_filter(entry, filter))
            .cloned()
            .collect::<Vec<_>>();
        let obligation_rows = self
            .obligation_rows
            .iter()
            .filter(|row| obligation_row_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();
        let region_rows = self
            .region_rows
            .iter()
            .filter(|row| region_row_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();
        let cancellation_events = self
            .cancellation_events
            .iter()
            .filter(|event| cancellation_event_matches_filter(event, filter))
            .cloned()
            .collect::<Vec<_>>();
        let benchmark_points = self
            .benchmark_trends
            .points
            .iter()
            .filter(|point| timestamp_matches_range(point.timestamp_unix_ms, filter))
            .cloned()
            .collect::<Vec<_>>();
        let safe_mode_activations = self
            .safe_mode_activations
            .iter()
            .filter(|activation| safe_mode_activation_matches_filter(activation, filter))
            .cloned()
            .collect::<Vec<_>>();

        Self {
            cluster: self.cluster.clone(),
            zone: self.zone.clone(),
            runtime_mode: self.runtime_mode.clone(),
            generated_at_unix_ms: self.generated_at_unix_ms,
            refresh_policy: self.refresh_policy.clone(),
            evidence_stream_last_updated_unix_ms: self.evidence_stream_last_updated_unix_ms,
            aggregates_last_updated_unix_ms: self.aggregates_last_updated_unix_ms,
            decision_outcomes: summarize_decision_outcomes(&evidence_stream),
            obligation_status: summarize_obligation_status(&obligation_rows),
            region_lifecycle: summarize_region_lifecycle(&region_rows),
            replay_health: self.replay_health.clone(),
            benchmark_trends: BenchmarkTrendsPanelView {
                points: benchmark_points,
                throughput_floor_tps: self.benchmark_trends.throughput_floor_tps,
                latency_p95_ceiling_ms: self.benchmark_trends.latency_p95_ceiling_ms,
                memory_peak_ceiling_mb: self.benchmark_trends.memory_peak_ceiling_mb,
            },
            schema_version: self.schema_version.clone(),
            alert_rules: self.alert_rules.clone(),
            evidence_stream,
            obligation_rows,
            region_rows,
            cancellation_events,
            safe_mode_activations,
        }
    }

    pub fn evaluate_alerts(&self, rules: &[DashboardAlertRule]) -> Vec<TriggeredAlertView> {
        let mut triggered = rules
            .iter()
            .filter_map(|rule| {
                let observed = dashboard_metric_value(self, rule.metric);
                threshold_matches(rule.comparator, observed, rule.threshold).then(|| {
                    TriggeredAlertView {
                        rule_id: rule.rule_id.clone(),
                        description: rule.description.clone(),
                        metric: rule.metric,
                        observed_value: observed,
                        threshold: rule.threshold,
                        severity: rule.severity,
                        triggered_at_unix_ms: self.generated_at_unix_ms,
                    }
                })
            })
            .collect::<Vec<_>>();
        triggered.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        triggered
    }

    pub fn triggered_alerts(&self) -> Vec<TriggeredAlertView> {
        self.evaluate_alerts(&self.alert_rules)
    }

    pub fn meets_refresh_sla(&self) -> bool {
        let evidence_lag_ms = self
            .generated_at_unix_ms
            .saturating_sub(self.evidence_stream_last_updated_unix_ms);
        let aggregate_lag_ms = self
            .generated_at_unix_ms
            .saturating_sub(self.aggregates_last_updated_unix_ms);
        let evidence_budget_ms = self
            .refresh_policy
            .evidence_stream_refresh_secs
            .saturating_mul(1_000);
        let aggregate_budget_ms = self
            .refresh_policy
            .aggregate_refresh_secs
            .saturating_mul(1_000);
        evidence_lag_ms <= evidence_budget_ms && aggregate_lag_ms <= aggregate_budget_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ControlPlaneInvariantsPartial {
    pub cluster: String,
    pub zone: String,
    pub runtime_mode: String,
    pub generated_at_unix_ms: Option<u64>,
    pub refresh_policy: Option<DashboardRefreshPolicy>,
    pub evidence_stream_last_updated_unix_ms: Option<u64>,
    pub aggregates_last_updated_unix_ms: Option<u64>,
    #[serde(default)]
    pub evidence_stream: Vec<EvidenceStreamEntryView>,
    pub decision_outcomes: Option<DecisionOutcomesPanelView>,
    #[serde(default)]
    pub obligation_rows: Vec<ObligationStatusRowView>,
    pub obligation_status: Option<ObligationStatusPanelView>,
    #[serde(default)]
    pub region_rows: Vec<RegionLifecycleRowView>,
    pub region_lifecycle: Option<RegionLifecyclePanelView>,
    #[serde(default)]
    pub cancellation_events: Vec<CancellationEventView>,
    pub replay_health: Option<ReplayHealthPanelView>,
    #[serde(default)]
    pub benchmark_points: Vec<BenchmarkTrendPointView>,
    pub throughput_floor_tps: Option<u64>,
    pub latency_p95_ceiling_ms: Option<u64>,
    pub memory_peak_ceiling_mb: Option<u64>,
    #[serde(default)]
    pub safe_mode_activations: Vec<SafeModeActivationView>,
    pub schema_version: Option<SchemaVersionPanelView>,
    #[serde(default)]
    pub alert_rules: Vec<DashboardAlertRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ControlPlaneDashboardFilter {
    pub extension_id: Option<String>,
    pub region_id: Option<String>,
    pub severity: Option<DashboardSeverity>,
    pub start_unix_ms: Option<u64>,
    pub end_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FlowSensitivityLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclassificationOutcome {
    Approved,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfinementStatus {
    Full,
    Partial,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelMapNodeView {
    pub label_id: String,
    pub sensitivity: FlowSensitivityLevel,
    pub description: String,
    pub extension_overlays: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelMapEdgeView {
    pub source_label: String,
    pub sink_clearance: String,
    pub route_policy_id: Option<String>,
    pub route_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct LabelMapView {
    pub nodes: Vec<LabelMapNodeView>,
    pub edges: Vec<LabelMapEdgeView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedFlowView {
    pub flow_id: String,
    pub extension_id: String,
    pub source_label: String,
    pub sink_clearance: String,
    pub sensitivity: FlowSensitivityLevel,
    pub blocked_reason: String,
    pub attempted_exfiltration: bool,
    pub code_path_ref: String,
    pub extension_context_ref: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub error_code: Option<String>,
    pub occurred_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclassificationDecisionView {
    pub decision_id: String,
    pub extension_id: String,
    pub source_label: String,
    pub sink_clearance: String,
    pub sensitivity: FlowSensitivityLevel,
    pub outcome: DeclassificationOutcome,
    pub policy_id: String,
    pub loss_assessment_summary: String,
    pub rationale: String,
    pub receipt_ref: String,
    pub replay_ref: String,
    pub decided_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowProofCoverageView {
    pub proof_id: String,
    pub source_label: String,
    pub sink_clearance: String,
    pub covered: bool,
    pub proof_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfinementProofView {
    pub extension_id: String,
    pub status: ConfinementStatus,
    pub covered_flow_count: u64,
    pub uncovered_flow_count: u64,
    pub proof_rows: Vec<FlowProofCoverageView>,
    pub uncovered_flow_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowDecisionAlertView {
    pub alert_id: String,
    pub extension_id: String,
    pub severity: DashboardSeverity,
    pub reason: String,
    pub blocked_flow_count: u64,
    pub generated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowDecisionDashboardView {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: u64,
    pub generated_at_unix_ms: u64,
    pub label_map: LabelMapView,
    pub blocked_flows: Vec<BlockedFlowView>,
    pub declassification_history: Vec<DeclassificationDecisionView>,
    pub confinement_proofs: Vec<ConfinementProofView>,
    pub alert_indicators: Vec<FlowDecisionAlertView>,
}

impl FlowDecisionDashboardView {
    pub fn from_partial(input: FlowDecisionPartial) -> Self {
        let mut label_map = input.label_map;
        label_map
            .nodes
            .sort_by(|left, right| left.label_id.cmp(&right.label_id));
        label_map.edges.sort_by(|left, right| {
            left.source_label
                .cmp(&right.source_label)
                .then(left.sink_clearance.cmp(&right.sink_clearance))
                .then(left.route_policy_id.cmp(&right.route_policy_id))
        });
        for node in &mut label_map.nodes {
            node.label_id = normalize_non_empty(std::mem::take(&mut node.label_id));
            node.description = normalize_non_empty(std::mem::take(&mut node.description));
            node.extension_overlays.sort();
            for extension in &mut node.extension_overlays {
                *extension = normalize_non_empty(std::mem::take(extension));
            }
        }
        for edge in &mut label_map.edges {
            edge.source_label = normalize_non_empty(std::mem::take(&mut edge.source_label));
            edge.sink_clearance = normalize_non_empty(std::mem::take(&mut edge.sink_clearance));
            edge.route_policy_id = normalize_optional_non_empty(edge.route_policy_id.take());
        }

        let mut blocked_flows = input.blocked_flows;
        blocked_flows.sort_by(|left, right| {
            left.occurred_at_unix_ms
                .cmp(&right.occurred_at_unix_ms)
                .then(left.extension_id.cmp(&right.extension_id))
                .then(left.flow_id.cmp(&right.flow_id))
        });
        for flow in &mut blocked_flows {
            flow.flow_id = normalize_non_empty(std::mem::take(&mut flow.flow_id));
            flow.extension_id = normalize_non_empty(std::mem::take(&mut flow.extension_id));
            flow.source_label = normalize_non_empty(std::mem::take(&mut flow.source_label));
            flow.sink_clearance = normalize_non_empty(std::mem::take(&mut flow.sink_clearance));
            flow.blocked_reason = normalize_non_empty(std::mem::take(&mut flow.blocked_reason));
            flow.code_path_ref = normalize_non_empty(std::mem::take(&mut flow.code_path_ref));
            flow.extension_context_ref =
                normalize_non_empty(std::mem::take(&mut flow.extension_context_ref));
            flow.trace_id = normalize_non_empty(std::mem::take(&mut flow.trace_id));
            flow.decision_id = normalize_non_empty(std::mem::take(&mut flow.decision_id));
            flow.policy_id = normalize_non_empty(std::mem::take(&mut flow.policy_id));
            flow.error_code = normalize_optional_non_empty(flow.error_code.take());
        }

        let mut declassification_history = input.declassification_history;
        declassification_history.sort_by(|left, right| {
            left.decided_at_unix_ms
                .cmp(&right.decided_at_unix_ms)
                .then(left.extension_id.cmp(&right.extension_id))
                .then(left.decision_id.cmp(&right.decision_id))
        });
        for decision in &mut declassification_history {
            decision.decision_id = normalize_non_empty(std::mem::take(&mut decision.decision_id));
            decision.extension_id = normalize_non_empty(std::mem::take(&mut decision.extension_id));
            decision.source_label = normalize_non_empty(std::mem::take(&mut decision.source_label));
            decision.sink_clearance =
                normalize_non_empty(std::mem::take(&mut decision.sink_clearance));
            decision.policy_id = normalize_non_empty(std::mem::take(&mut decision.policy_id));
            decision.loss_assessment_summary =
                normalize_non_empty(std::mem::take(&mut decision.loss_assessment_summary));
            decision.rationale = normalize_non_empty(std::mem::take(&mut decision.rationale));
            decision.receipt_ref = normalize_non_empty(std::mem::take(&mut decision.receipt_ref));
            decision.replay_ref = normalize_non_empty(std::mem::take(&mut decision.replay_ref));
        }

        let mut confinement_proofs = input.confinement_proofs;
        confinement_proofs.sort_by(|left, right| left.extension_id.cmp(&right.extension_id));
        for proof in &mut confinement_proofs {
            proof.extension_id = normalize_non_empty(std::mem::take(&mut proof.extension_id));
            proof.proof_rows.sort_by(|left, right| {
                left.source_label
                    .cmp(&right.source_label)
                    .then(left.sink_clearance.cmp(&right.sink_clearance))
                    .then(left.proof_id.cmp(&right.proof_id))
            });
            for row in &mut proof.proof_rows {
                row.proof_id = normalize_non_empty(std::mem::take(&mut row.proof_id));
                row.source_label = normalize_non_empty(std::mem::take(&mut row.source_label));
                row.sink_clearance = normalize_non_empty(std::mem::take(&mut row.sink_clearance));
                row.proof_ref = normalize_non_empty(std::mem::take(&mut row.proof_ref));
            }
            proof.uncovered_flow_refs.sort();
            for uncovered in &mut proof.uncovered_flow_refs {
                *uncovered = normalize_non_empty(std::mem::take(uncovered));
            }
        }

        let generated_at_unix_ms = input.generated_at_unix_ms.expect("serde deserialization should succeed");
        let alert_threshold = input.blocked_flow_alert_threshold.unwrap_or(5);
        let mut alert_indicators = if input.alert_indicators.is_empty() {
            compute_flow_alert_indicators(
                &blocked_flows,
                &confinement_proofs,
                generated_at_unix_ms,
                alert_threshold,
            )
        } else {
            input.alert_indicators
        };
        alert_indicators.sort_by(|left, right| left.alert_id.cmp(&right.alert_id));
        for alert in &mut alert_indicators {
            alert.alert_id = normalize_non_empty(std::mem::take(&mut alert.alert_id));
            alert.extension_id = normalize_non_empty(std::mem::take(&mut alert.extension_id));
            alert.reason = normalize_non_empty(std::mem::take(&mut alert.reason));
        }

        Self {
            cluster: normalize_non_empty(input.cluster),
            zone: normalize_non_empty(input.zone),
            security_epoch: input.security_epoch.expect("serde deserialization should succeed"),
            generated_at_unix_ms,
            label_map,
            blocked_flows,
            declassification_history,
            confinement_proofs,
            alert_indicators,
        }
    }

    pub fn filtered(&self, filter: &FlowDecisionDashboardFilter) -> Self {
        let blocked_flows = self
            .blocked_flows
            .iter()
            .filter(|flow| blocked_flow_matches_filter(flow, filter))
            .cloned()
            .collect::<Vec<_>>();
        let declassification_history = self
            .declassification_history
            .iter()
            .filter(|decision| declassification_matches_filter(decision, filter))
            .cloned()
            .collect::<Vec<_>>();
        let confinement_proofs = self
            .confinement_proofs
            .iter()
            .filter(|proof| confinement_proof_matches_filter(proof, filter))
            .cloned()
            .collect::<Vec<_>>();
        let relevant_extensions = blocked_flows
            .iter()
            .map(|flow| flow.extension_id.clone())
            .chain(
                declassification_history
                    .iter()
                    .map(|decision| decision.extension_id.clone()),
            )
            .collect::<BTreeSet<_>>();
        let alert_indicators = self
            .alert_indicators
            .iter()
            .filter(|alert| relevant_extensions.contains(&alert.extension_id))
            .cloned()
            .collect::<Vec<_>>();
        let label_map = self.filtered_label_map(filter, &relevant_extensions);

        Self {
            cluster: self.cluster.clone(),
            zone: self.zone.clone(),
            security_epoch: self.security_epoch,
            generated_at_unix_ms: self.generated_at_unix_ms,
            label_map,
            blocked_flows,
            declassification_history,
            confinement_proofs,
            alert_indicators,
        }
    }

    fn filtered_label_map(
        &self,
        filter: &FlowDecisionDashboardFilter,
        relevant_extensions: &BTreeSet<String>,
    ) -> LabelMapView {
        let mut nodes = self
            .label_map
            .nodes
            .iter()
            .filter(|node| {
                filter
                    .source_label
                    .as_deref()
                    .is_none_or(|label| node.label_id.eq_ignore_ascii_case(label))
                    && (relevant_extensions.is_empty()
                        || node
                            .extension_overlays
                            .iter()
                            .any(|extension| relevant_extensions.contains(extension)))
            })
            .cloned()
            .collect::<Vec<_>>();
        let node_labels = nodes
            .iter()
            .map(|node| node.label_id.clone())
            .collect::<BTreeSet<_>>();
        let edges = self
            .label_map
            .edges
            .iter()
            .filter(|edge| {
                node_labels.contains(&edge.source_label)
                    && (filter
                        .sink_clearance
                        .as_deref()
                        .is_none_or(|sink| edge.sink_clearance.eq_ignore_ascii_case(sink)))
            })
            .cloned()
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.label_id.cmp(&right.label_id));
        LabelMapView { nodes, edges }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FlowDecisionPartial {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: Option<u64>,
    pub generated_at_unix_ms: Option<u64>,
    pub label_map: LabelMapView,
    #[serde(default)]
    pub blocked_flows: Vec<BlockedFlowView>,
    #[serde(default)]
    pub declassification_history: Vec<DeclassificationDecisionView>,
    #[serde(default)]
    pub confinement_proofs: Vec<ConfinementProofView>,
    #[serde(default)]
    pub alert_indicators: Vec<FlowDecisionAlertView>,
    pub blocked_flow_alert_threshold: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FlowDecisionDashboardFilter {
    pub extension_id: Option<String>,
    pub source_label: Option<String>,
    pub sink_clearance: Option<String>,
    pub sensitivity: Option<FlowSensitivityLevel>,
    pub start_unix_ms: Option<u64>,
    pub end_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplacementRiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStatus {
    Investigating,
    Resolved,
    Waived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotStatusOverviewRow {
    pub slot_id: String,
    pub slot_kind: String,
    pub implementation_kind: String,
    pub promotion_status: String,
    pub risk_level: ReplacementRiskLevel,
    pub last_transition_unix_ms: u64,
    pub health: String,
    pub lineage_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageTrendPoint {
    pub timestamp_unix_ms: u64,
    pub native_coverage_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeCoverageMeter {
    pub native_slots: usize,
    pub delegate_slots: usize,
    pub native_coverage_millionths: u64,
    pub trend: Vec<CoverageTrendPoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockedPromotionView {
    pub slot_id: String,
    pub gate_failure_code: String,
    pub failure_detail: String,
    pub recommended_remediation: String,
    pub lineage_ref: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackEventView {
    pub slot_id: String,
    pub receipt_id: String,
    pub reason: String,
    pub status: RollbackStatus,
    pub occurred_at_unix_ms: u64,
    pub lineage_ref: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementOpportunityInput {
    pub slot_id: String,
    pub slot_kind: String,
    pub performance_uplift_millionths: u64,
    pub invocation_frequency_per_minute: u64,
    pub risk_reduction_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementOpportunityView {
    pub slot_id: String,
    pub slot_kind: String,
    pub expected_value_score_millionths: i64,
    pub performance_uplift_millionths: u64,
    pub invocation_frequency_per_minute: u64,
    pub risk_reduction_millionths: u64,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplacementProgressDashboardView {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: u64,
    pub generated_at_unix_ms: u64,
    pub slot_status_overview: Vec<SlotStatusOverviewRow>,
    pub native_coverage: NativeCoverageMeter,
    pub blocked_promotions: Vec<BlockedPromotionView>,
    pub rollback_events: Vec<RollbackEventView>,
    pub next_best_replacements: Vec<ReplacementOpportunityView>,
}

impl ReplacementProgressDashboardView {
    pub fn from_partial(input: ReplacementProgressPartial) -> Self {
        let mut slot_status_overview = input.slot_status_overview;
        slot_status_overview.sort_by(|left, right| {
            left.slot_id
                .cmp(&right.slot_id)
                .then(left.slot_kind.cmp(&right.slot_kind))
        });

        for row in &mut slot_status_overview {
            row.slot_id = normalize_non_empty(std::mem::take(&mut row.slot_id));
            row.slot_kind = normalize_non_empty(std::mem::take(&mut row.slot_kind));
            row.implementation_kind =
                normalize_non_empty(std::mem::take(&mut row.implementation_kind));
            row.promotion_status = normalize_non_empty(std::mem::take(&mut row.promotion_status));
            row.health = normalize_non_empty(std::mem::take(&mut row.health));
            row.lineage_ref = normalize_non_empty(std::mem::take(&mut row.lineage_ref));
        }

        let mut native_coverage_history = input.native_coverage_history;
        native_coverage_history.sort_by(|left, right| {
            left.timestamp_unix_ms.cmp(&right.timestamp_unix_ms).then(
                left.native_coverage_millionths
                    .cmp(&right.native_coverage_millionths),
            )
        });
        for point in &mut native_coverage_history {
            point.native_coverage_millionths =
                canonicalize_coverage_millionths(point.native_coverage_millionths);
        }

        let native_coverage = match input.native_coverage {
            Some(mut meter) => {
                meter.native_coverage_millionths =
                    canonicalize_coverage_millionths(meter.native_coverage_millionths);
                meter.trend.sort_by(|left, right| {
                    left.timestamp_unix_ms.cmp(&right.timestamp_unix_ms).then(
                        left.native_coverage_millionths
                            .cmp(&right.native_coverage_millionths),
                    )
                });
                for point in &mut meter.trend {
                    point.native_coverage_millionths =
                        canonicalize_coverage_millionths(point.native_coverage_millionths);
                }
                meter
            }
            None => build_native_coverage_meter(&slot_status_overview, native_coverage_history),
        };

        let mut blocked_promotions = input.blocked_promotions;
        blocked_promotions.sort_by(|left, right| {
            left.slot_id
                .cmp(&right.slot_id)
                .then(left.gate_failure_code.cmp(&right.gate_failure_code))
        });
        for blocked in &mut blocked_promotions {
            blocked.slot_id = normalize_non_empty(std::mem::take(&mut blocked.slot_id));
            blocked.gate_failure_code =
                normalize_non_empty(std::mem::take(&mut blocked.gate_failure_code));
            blocked.failure_detail =
                normalize_non_empty(std::mem::take(&mut blocked.failure_detail));
            blocked.recommended_remediation =
                normalize_non_empty(std::mem::take(&mut blocked.recommended_remediation));
            blocked.lineage_ref = normalize_non_empty(std::mem::take(&mut blocked.lineage_ref));
            blocked.evidence_ref = normalize_non_empty(std::mem::take(&mut blocked.evidence_ref));
        }

        let mut rollback_events = input.rollback_events;
        rollback_events.sort_by(|left, right| {
            left.occurred_at_unix_ms
                .cmp(&right.occurred_at_unix_ms)
                .then(left.slot_id.cmp(&right.slot_id))
                .then(left.receipt_id.cmp(&right.receipt_id))
        });
        for rollback in &mut rollback_events {
            rollback.slot_id = normalize_non_empty(std::mem::take(&mut rollback.slot_id));
            rollback.receipt_id = normalize_non_empty(std::mem::take(&mut rollback.receipt_id));
            rollback.reason = normalize_non_empty(std::mem::take(&mut rollback.reason));
            rollback.lineage_ref = normalize_non_empty(std::mem::take(&mut rollback.lineage_ref));
            rollback.evidence_ref = normalize_non_empty(std::mem::take(&mut rollback.evidence_ref));
        }

        let mut next_best_replacements = if input.next_best_replacements.is_empty() {
            rank_replacement_opportunities(input.replacement_inputs)
        } else {
            input.next_best_replacements
        };
        next_best_replacements.sort_by(|left, right| {
            right
                .expected_value_score_millionths
                .cmp(&left.expected_value_score_millionths)
                .then(left.slot_id.cmp(&right.slot_id))
        });
        for replacement in &mut next_best_replacements {
            replacement.slot_id = normalize_non_empty(std::mem::take(&mut replacement.slot_id));
            replacement.slot_kind = normalize_non_empty(std::mem::take(&mut replacement.slot_kind));
            replacement.rationale = normalize_non_empty(std::mem::take(&mut replacement.rationale));
        }

        Self {
            cluster: normalize_non_empty(input.cluster),
            zone: normalize_non_empty(input.zone),
            security_epoch: input.security_epoch.unwrap_or(0),
            generated_at_unix_ms: input.generated_at_unix_ms.unwrap_or(0),
            slot_status_overview,
            native_coverage,
            blocked_promotions,
            rollback_events,
            next_best_replacements,
        }
    }

    pub fn from_slot_registry_snapshot(
        registry: &SlotRegistry,
        snapshot: &ReplacementProgressSnapshot,
        cluster: impl Into<String>,
        zone: impl Into<String>,
        security_epoch: u64,
        generated_at_unix_ms: u64,
    ) -> Self {
        let slot_status_overview = registry
            .iter()
            .map(|(slot_id, entry)| {
                let slot_id_str = slot_id.as_str();
                SlotStatusOverviewRow {
                    slot_id: slot_id_str.to_string(),
                    slot_kind: entry.kind.to_string(),
                    implementation_kind: if entry.status.is_native() {
                        "native".to_string()
                    } else {
                        "delegate".to_string()
                    },
                    promotion_status: replacement_promotion_status_label(&entry.status).to_string(),
                    risk_level: replacement_risk_level(&entry.status),
                    last_transition_unix_ms: replacement_last_transition_unix_ms(
                        entry,
                        generated_at_unix_ms,
                    ),
                    health: replacement_health_label(&entry.status).to_string(),
                    lineage_ref: replacement_lineage_ref(slot_id_str),
                }
            })
            .collect::<Vec<_>>();

        let blocked_promotions = snapshot
            .events
            .iter()
            .filter_map(replacement_blocked_promotion_from_event)
            .collect::<Vec<_>>();
        let rollback_events =
            replacement_rollback_events_from_registry(registry, snapshot, generated_at_unix_ms);
        let next_best_replacements = snapshot
            .recommended_replacement_order
            .iter()
            .map(|candidate| ReplacementOpportunityView {
                slot_id: candidate.slot_id.as_str().to_string(),
                slot_kind: candidate.slot_kind.to_string(),
                expected_value_score_millionths: candidate.weighted_expected_value_score_millionths,
                performance_uplift_millionths: clamp_non_negative_i64_to_u64(
                    candidate.throughput_uplift_millionths,
                ),
                invocation_frequency_per_minute: candidate.invocation_weight_millionths,
                risk_reduction_millionths: clamp_non_negative_i64_to_u64(
                    candidate.security_risk_reduction_millionths,
                ),
                rationale: format!(
                    "promotion_status={} delegate_backed={} expected_value={} weighted_expected_value={}",
                    candidate.promotion_status,
                    candidate.delegate_backed,
                    candidate.expected_value_score_millionths,
                    candidate.weighted_expected_value_score_millionths
                ),
            })
            .collect::<Vec<_>>();
        let native_coverage = NativeCoverageMeter {
            native_slots: snapshot.native_slots,
            delegate_slots: snapshot.delegate_slots,
            native_coverage_millionths: snapshot.native_coverage_millionths,
            trend: vec![CoverageTrendPoint {
                timestamp_unix_ms: generated_at_unix_ms,
                native_coverage_millionths: snapshot.native_coverage_millionths,
            }],
        };

        Self::from_partial(ReplacementProgressPartial {
            cluster: cluster.into(),
            zone: zone.into(),
            security_epoch: Some(security_epoch),
            generated_at_unix_ms: Some(generated_at_unix_ms),
            slot_status_overview,
            native_coverage_history: Vec::new(),
            native_coverage: Some(native_coverage),
            blocked_promotions,
            rollback_events,
            replacement_inputs: Vec::new(),
            next_best_replacements,
        })
    }

    pub fn refreshed_from_slot_registry_snapshot(
        &self,
        registry: &SlotRegistry,
        snapshot: &ReplacementProgressSnapshot,
        generated_at_unix_ms: u64,
    ) -> Self {
        Self::from_slot_registry_snapshot(
            registry,
            snapshot,
            self.cluster.clone(),
            self.zone.clone(),
            self.security_epoch,
            generated_at_unix_ms,
        )
    }

    pub fn filtered(&self, filter: &ReplacementDashboardFilter) -> Self {
        let slot_status_overview = self
            .slot_status_overview
            .iter()
            .filter(|row| slot_row_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();

        let slot_ids = slot_status_overview
            .iter()
            .map(|row| row.slot_id.clone())
            .collect::<BTreeSet<_>>();

        let blocked_promotions = self
            .blocked_promotions
            .iter()
            .filter(|entry| slot_ids.contains(&entry.slot_id))
            .cloned()
            .collect::<Vec<_>>();
        let rollback_events = self
            .rollback_events
            .iter()
            .filter(|entry| slot_ids.contains(&entry.slot_id))
            .cloned()
            .collect::<Vec<_>>();
        let next_best_replacements = self
            .next_best_replacements
            .iter()
            .filter(|entry| slot_ids.contains(&entry.slot_id))
            .cloned()
            .collect::<Vec<_>>();
        let native_coverage =
            build_native_coverage_meter(&slot_status_overview, self.native_coverage.trend.clone());

        Self {
            cluster: self.cluster.clone(),
            zone: self.zone.clone(),
            security_epoch: self.security_epoch,
            generated_at_unix_ms: self.generated_at_unix_ms,
            slot_status_overview,
            native_coverage,
            blocked_promotions,
            rollback_events,
            next_best_replacements,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReplacementProgressPartial {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: Option<u64>,
    pub generated_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub slot_status_overview: Vec<SlotStatusOverviewRow>,
    #[serde(default)]
    pub native_coverage_history: Vec<CoverageTrendPoint>,
    pub native_coverage: Option<NativeCoverageMeter>,
    #[serde(default)]
    pub blocked_promotions: Vec<BlockedPromotionView>,
    #[serde(default)]
    pub rollback_events: Vec<RollbackEventView>,
    #[serde(default)]
    pub replacement_inputs: Vec<ReplacementOpportunityInput>,
    #[serde(default)]
    pub next_best_replacements: Vec<ReplacementOpportunityView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ReplacementDashboardFilter {
    pub slot_kind: Option<String>,
    pub risk_level: Option<ReplacementRiskLevel>,
    pub promotion_status: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofInventoryKind {
    CapabilityWitness,
    FlowProof,
    ReplayMotif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProofValidityStatus {
    #[default]
    Valid,
    ExpiringSoon,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofSpecializationInvalidationReason {
    EpochChange,
    ProofExpired,
    ProofRevoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecializationFallbackReason {
    ProofUnavailable,
    ProofExpired,
    ProofRevoked,
    ValidationFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofInventoryRowView {
    pub proof_id: String,
    pub proof_kind: ProofInventoryKind,
    pub validity_status: ProofValidityStatus,
    pub epoch_id: u64,
    pub linked_specialization_count: u64,
    pub enabled_specialization_ids: Vec<String>,
    pub proof_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveSpecializationRowView {
    pub specialization_id: String,
    pub target_id: String,
    pub target_kind: String,
    pub optimization_class: String,
    pub latency_reduction_millionths: u64,
    pub throughput_increase_millionths: u64,
    pub proof_input_ids: Vec<String>,
    pub transformation_ref: String,
    pub receipt_ref: String,
    pub activated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationInvalidationRowView {
    pub invalidation_id: String,
    pub specialization_id: String,
    pub target_id: String,
    pub reason: ProofSpecializationInvalidationReason,
    pub reason_detail: String,
    pub proof_id: Option<String>,
    pub old_epoch_id: Option<u64>,
    pub new_epoch_id: Option<u64>,
    pub fallback_confirmed: bool,
    pub fallback_confirmation_ref: String,
    pub occurred_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationFallbackEventView {
    pub event_id: String,
    pub specialization_id: Option<String>,
    pub target_id: String,
    pub reason: SpecializationFallbackReason,
    pub reason_detail: String,
    pub unspecialized_path_ref: String,
    pub compilation_ref: String,
    pub occurred_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SpecializationPerformanceImpactView {
    pub active_specialization_count: u64,
    pub aggregate_latency_reduction_millionths: u64,
    pub aggregate_throughput_increase_millionths: u64,
    pub specialization_coverage_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofSpecializationAlertView {
    pub alert_id: String,
    pub severity: DashboardSeverity,
    pub reason: String,
    pub affected_count: u64,
    pub generated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofSpecializationLineageDashboardView {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: u64,
    pub generated_at_unix_ms: u64,
    pub proof_inventory: Vec<ProofInventoryRowView>,
    pub active_specializations: Vec<ActiveSpecializationRowView>,
    pub invalidation_feed: Vec<SpecializationInvalidationRowView>,
    pub fallback_events: Vec<SpecializationFallbackEventView>,
    pub performance_impact: SpecializationPerformanceImpactView,
    pub alert_indicators: Vec<ProofSpecializationAlertView>,
}

impl ProofSpecializationLineageDashboardView {
    pub fn from_partial(input: ProofSpecializationLineagePartial) -> Self {
        let mut proof_inventory = input.proof_inventory;
        proof_inventory.sort_by(|left, right| {
            left.proof_id
                .cmp(&right.proof_id)
                .then(left.epoch_id.cmp(&right.epoch_id))
                .then(left.proof_ref.cmp(&right.proof_ref))
        });
        for proof in &mut proof_inventory {
            proof.proof_id = normalize_non_empty(std::mem::take(&mut proof.proof_id));
            proof.proof_ref = normalize_non_empty(std::mem::take(&mut proof.proof_ref));
            for specialization_id in &mut proof.enabled_specialization_ids {
                *specialization_id = normalize_non_empty(std::mem::take(specialization_id));
            }
            proof.enabled_specialization_ids.sort();
        }

        let mut active_specializations = input.active_specializations;
        active_specializations.sort_by(|left, right| {
            left.target_id
                .cmp(&right.target_id)
                .then(left.specialization_id.cmp(&right.specialization_id))
        });
        for specialization in &mut active_specializations {
            specialization.specialization_id =
                normalize_non_empty(std::mem::take(&mut specialization.specialization_id));
            specialization.target_id =
                normalize_non_empty(std::mem::take(&mut specialization.target_id));
            specialization.target_kind =
                normalize_non_empty(std::mem::take(&mut specialization.target_kind));
            specialization.optimization_class =
                normalize_non_empty(std::mem::take(&mut specialization.optimization_class));
            specialization.transformation_ref =
                normalize_non_empty(std::mem::take(&mut specialization.transformation_ref));
            specialization.receipt_ref =
                normalize_non_empty(std::mem::take(&mut specialization.receipt_ref));
            for proof_id in &mut specialization.proof_input_ids {
                *proof_id = normalize_non_empty(std::mem::take(proof_id));
            }
            specialization.proof_input_ids.sort();
        }

        let mut invalidation_feed = input.invalidation_feed;
        invalidation_feed.sort_by(|left, right| {
            left.occurred_at_unix_ms
                .cmp(&right.occurred_at_unix_ms)
                .then(left.target_id.cmp(&right.target_id))
                .then(left.invalidation_id.cmp(&right.invalidation_id))
        });
        for invalidation in &mut invalidation_feed {
            invalidation.invalidation_id =
                normalize_non_empty(std::mem::take(&mut invalidation.invalidation_id));
            invalidation.specialization_id =
                normalize_non_empty(std::mem::take(&mut invalidation.specialization_id));
            invalidation.target_id =
                normalize_non_empty(std::mem::take(&mut invalidation.target_id));
            invalidation.reason_detail =
                normalize_non_empty(std::mem::take(&mut invalidation.reason_detail));
            invalidation.proof_id = normalize_optional_non_empty(invalidation.proof_id.take());
            invalidation.fallback_confirmation_ref =
                normalize_non_empty(std::mem::take(&mut invalidation.fallback_confirmation_ref));
        }

        let mut fallback_events = input.fallback_events;
        fallback_events.sort_by(|left, right| {
            left.occurred_at_unix_ms
                .cmp(&right.occurred_at_unix_ms)
                .then(left.target_id.cmp(&right.target_id))
                .then(left.event_id.cmp(&right.event_id))
        });
        for event in &mut fallback_events {
            event.event_id = normalize_non_empty(std::mem::take(&mut event.event_id));
            event.specialization_id = normalize_optional_non_empty(event.specialization_id.take());
            event.target_id = normalize_non_empty(std::mem::take(&mut event.target_id));
            event.reason_detail = normalize_non_empty(std::mem::take(&mut event.reason_detail));
            event.unspecialized_path_ref =
                normalize_non_empty(std::mem::take(&mut event.unspecialized_path_ref));
            event.compilation_ref = normalize_non_empty(std::mem::take(&mut event.compilation_ref));
        }

        let generated_at_unix_ms = input.generated_at_unix_ms.expect("serde deserialization should succeed");
        let performance_impact = match input.performance_impact {
            Some(mut provided) => {
                provided.specialization_coverage_millionths =
                    canonicalize_coverage_millionths(provided.specialization_coverage_millionths);
                provided
            }
            None => {
                build_specialization_performance_impact(&active_specializations, &proof_inventory)
            }
        };

        let bulk_invalidation_alert_threshold =
            input.bulk_invalidation_alert_threshold.unwrap_or(10).max(1);
        let degraded_coverage_alert_threshold_millionths = canonicalize_coverage_millionths(
            input
                .degraded_coverage_alert_threshold_millionths
                .unwrap_or(750_000),
        );
        let mut alert_indicators = if input.alert_indicators.is_empty() {
            compute_proof_specialization_alerts(
                &invalidation_feed,
                performance_impact.specialization_coverage_millionths,
                generated_at_unix_ms,
                bulk_invalidation_alert_threshold,
                degraded_coverage_alert_threshold_millionths,
            )
        } else {
            input.alert_indicators
        };
        alert_indicators.sort_by(|left, right| left.alert_id.cmp(&right.alert_id));
        for alert in &mut alert_indicators {
            alert.alert_id = normalize_non_empty(std::mem::take(&mut alert.alert_id));
            alert.reason = normalize_non_empty(std::mem::take(&mut alert.reason));
        }

        Self {
            cluster: normalize_non_empty(input.cluster),
            zone: normalize_non_empty(input.zone),
            security_epoch: input.security_epoch.expect("serde deserialization should succeed"),
            generated_at_unix_ms,
            proof_inventory,
            active_specializations,
            invalidation_feed,
            fallback_events,
            performance_impact,
            alert_indicators,
        }
    }

    pub fn filtered(&self, filter: &ProofSpecializationDashboardFilter) -> Self {
        let active_specializations = self
            .active_specializations
            .iter()
            .filter(|row| proof_specialization_row_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();

        let filtered_specialization_ids = active_specializations
            .iter()
            .map(|row| row.specialization_id.clone())
            .collect::<BTreeSet<_>>();

        let invalidation_feed = self
            .invalidation_feed
            .iter()
            .filter(|row| proof_specialization_invalidation_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();

        let fallback_events = self
            .fallback_events
            .iter()
            .filter(|row| proof_specialization_fallback_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();

        let referenced_proof_ids = active_specializations
            .iter()
            .flat_map(|row| row.proof_input_ids.iter().cloned())
            .chain(
                invalidation_feed
                    .iter()
                    .filter_map(|row| row.proof_id.clone()),
            )
            .collect::<BTreeSet<_>>();

        let proof_inventory = self
            .proof_inventory
            .iter()
            .filter(|proof| {
                filter
                    .proof_id
                    .as_deref()
                    .is_none_or(|proof_id| proof.proof_id.eq_ignore_ascii_case(proof_id))
                    && (referenced_proof_ids.is_empty()
                        || referenced_proof_ids.contains(&proof.proof_id)
                        || proof
                            .enabled_specialization_ids
                            .iter()
                            .any(|id| filtered_specialization_ids.contains(id)))
            })
            .cloned()
            .collect::<Vec<_>>();

        let performance_impact =
            build_specialization_performance_impact(&active_specializations, &proof_inventory);
        let mut alert_indicators = compute_proof_specialization_alerts(
            &invalidation_feed,
            performance_impact.specialization_coverage_millionths,
            self.generated_at_unix_ms,
            10,
            750_000,
        );
        alert_indicators.retain(|alert| {
            self.alert_indicators
                .iter()
                .any(|existing| existing.alert_id == alert.alert_id)
                || alert.alert_id == "bulk-invalidation"
                || alert.alert_id == "specialization-coverage-degraded"
        });

        Self {
            cluster: self.cluster.clone(),
            zone: self.zone.clone(),
            security_epoch: self.security_epoch,
            generated_at_unix_ms: self.generated_at_unix_ms,
            proof_inventory,
            active_specializations,
            invalidation_feed,
            fallback_events,
            performance_impact,
            alert_indicators,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProofSpecializationLineagePartial {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: Option<u64>,
    pub generated_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub proof_inventory: Vec<ProofInventoryRowView>,
    #[serde(default)]
    pub active_specializations: Vec<ActiveSpecializationRowView>,
    #[serde(default)]
    pub invalidation_feed: Vec<SpecializationInvalidationRowView>,
    #[serde(default)]
    pub fallback_events: Vec<SpecializationFallbackEventView>,
    pub performance_impact: Option<SpecializationPerformanceImpactView>,
    #[serde(default)]
    pub alert_indicators: Vec<ProofSpecializationAlertView>,
    pub bulk_invalidation_alert_threshold: Option<u64>,
    pub degraded_coverage_alert_threshold_millionths: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProofSpecializationDashboardFilter {
    pub target_id: Option<String>,
    pub proof_id: Option<String>,
    pub optimization_class: Option<String>,
    pub start_unix_ms: Option<u64>,
    pub end_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OverrideReviewStatus {
    #[default]
    Pending,
    Approved,
    Rejected,
    Waived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrantExpiryStatus {
    #[default]
    Active,
    ExpiringSoon,
    Expired,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentCapabilityDeltaRowView {
    pub extension_id: String,
    pub witness_id: String,
    pub policy_id: String,
    pub witness_epoch: u64,
    pub lifecycle_state: String,
    pub active_witness_capabilities: Vec<String>,
    pub manifest_declared_capabilities: Vec<String>,
    pub over_privileged_capabilities: Vec<String>,
    pub over_privilege_ratio_millionths: u64,
    pub over_privilege_replay_ref: String,
    pub latest_receipt_timestamp_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityJustificationDrillView {
    pub capability: String,
    pub justification: String,
    pub static_analysis_ref: Option<String>,
    pub ablation_result_ref: Option<String>,
    pub theorem_check_ref: Option<String>,
    pub operator_attestation_ref: Option<String>,
    pub inherited_ref: Option<String>,
    pub playback_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposedMinimalCapabilityDeltaRowView {
    pub extension_id: String,
    pub witness_id: String,
    pub current_capabilities: Vec<String>,
    pub proposed_minimal_capabilities: Vec<String>,
    pub removed_capabilities: Vec<String>,
    pub capability_justifications: Vec<CapabilityJustificationDrillView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDeltaEscrowEventView {
    pub receipt_id: String,
    pub extension_id: String,
    pub capability: Option<String>,
    pub decision_kind: String,
    pub outcome: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub error_code: Option<String>,
    pub timestamp_ns: u64,
    pub receipt_ref: String,
    pub replay_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideRationaleView {
    pub override_id: String,
    pub extension_id: String,
    pub capability: Option<String>,
    pub rationale: String,
    pub signed_justification_ref: String,
    pub review_status: OverrideReviewStatus,
    pub grant_expiry_status: GrantExpiryStatus,
    pub requested_at_unix_ms: u64,
    pub reviewed_at_unix_ms: Option<u64>,
    pub expires_at_unix_ms: Option<u64>,
    pub receipt_ref: String,
    pub replay_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityPromotionBatchReviewView {
    pub batch_id: String,
    pub extension_ids: Vec<String>,
    pub witness_ids: Vec<String>,
    pub pending_review_count: u64,
    pub generated_at_unix_ms: u64,
    pub workflow_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDeltaAlertView {
    pub alert_id: String,
    pub extension_id: Option<String>,
    pub severity: DashboardSeverity,
    pub reason: String,
    pub generated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDeltaDashboardView {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: u64,
    pub generated_at_unix_ms: u64,
    pub current_capability_rows: Vec<CurrentCapabilityDeltaRowView>,
    pub proposed_minimal_rows: Vec<ProposedMinimalCapabilityDeltaRowView>,
    pub escrow_event_feed: Vec<CapabilityDeltaEscrowEventView>,
    pub override_rationale_rows: Vec<OverrideRationaleView>,
    pub batch_review_queue: Vec<CapabilityPromotionBatchReviewView>,
    pub alert_indicators: Vec<CapabilityDeltaAlertView>,
    pub event_subscription_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CapabilityDeltaPartial {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: Option<u64>,
    pub generated_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub current_capability_rows: Vec<CurrentCapabilityDeltaRowView>,
    #[serde(default)]
    pub proposed_minimal_rows: Vec<ProposedMinimalCapabilityDeltaRowView>,
    #[serde(default)]
    pub escrow_event_feed: Vec<CapabilityDeltaEscrowEventView>,
    #[serde(default)]
    pub override_rationale_rows: Vec<OverrideRationaleView>,
    #[serde(default)]
    pub batch_review_queue: Vec<CapabilityPromotionBatchReviewView>,
    #[serde(default)]
    pub alert_indicators: Vec<CapabilityDeltaAlertView>,
    pub event_subscription_cursor: Option<String>,
    pub high_escrow_alert_threshold: Option<u64>,
    pub pending_override_alert_threshold: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CapabilityDeltaDashboardFilter {
    pub extension_id: Option<String>,
    pub capability: Option<String>,
    pub outcome: Option<String>,
    pub min_over_privilege_ratio_millionths: Option<u64>,
    pub grant_expiry_status: Option<GrantExpiryStatus>,
    pub start_timestamp_ns: Option<u64>,
    pub end_timestamp_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CapabilityDeltaReplayJoinPartial {
    pub cluster: String,
    pub zone: String,
    pub security_epoch: Option<u64>,
    pub generated_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub replay_rows: Vec<WitnessReplayJoinRow>,
    #[serde(default)]
    pub manifest_declared_capabilities: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub override_rationale_rows: Vec<OverrideRationaleView>,
    #[serde(default)]
    pub batch_review_queue: Vec<CapabilityPromotionBatchReviewView>,
    pub event_subscription_cursor: Option<String>,
    pub high_escrow_alert_threshold: Option<u64>,
    pub pending_override_alert_threshold: Option<u64>,
}

impl CapabilityDeltaDashboardView {
    pub fn from_partial(input: CapabilityDeltaPartial) -> Self {
        let mut current_capability_rows = input.current_capability_rows;
        for row in &mut current_capability_rows {
            row.extension_id = normalize_non_empty(std::mem::take(&mut row.extension_id));
            row.witness_id = normalize_non_empty(std::mem::take(&mut row.witness_id));
            row.policy_id = normalize_non_empty(std::mem::take(&mut row.policy_id));
            row.lifecycle_state = normalize_non_empty(std::mem::take(&mut row.lifecycle_state));
            row.over_privilege_replay_ref =
                normalize_non_empty(std::mem::take(&mut row.over_privilege_replay_ref));
            row.active_witness_capabilities.sort();
            row.active_witness_capabilities.dedup();
            for capability in &mut row.active_witness_capabilities {
                *capability = normalize_non_empty(std::mem::take(capability));
            }
            row.manifest_declared_capabilities.sort();
            row.manifest_declared_capabilities.dedup();
            for capability in &mut row.manifest_declared_capabilities {
                *capability = normalize_non_empty(std::mem::take(capability));
            }
            row.over_privileged_capabilities.sort();
            row.over_privileged_capabilities.dedup();
            for capability in &mut row.over_privileged_capabilities {
                *capability = normalize_non_empty(std::mem::take(capability));
            }
            row.over_privilege_ratio_millionths = compute_over_privilege_ratio_millionths(
                row.active_witness_capabilities.len(),
                row.over_privileged_capabilities.len(),
            );
        }
        current_capability_rows.sort_by(|left, right| {
            right
                .over_privilege_ratio_millionths
                .cmp(&left.over_privilege_ratio_millionths)
                .then(left.extension_id.cmp(&right.extension_id))
                .then(left.witness_id.cmp(&right.witness_id))
        });

        let mut proposed_minimal_rows = input.proposed_minimal_rows;
        for row in &mut proposed_minimal_rows {
            row.extension_id = normalize_non_empty(std::mem::take(&mut row.extension_id));
            row.witness_id = normalize_non_empty(std::mem::take(&mut row.witness_id));
            row.current_capabilities.sort();
            row.current_capabilities.dedup();
            for capability in &mut row.current_capabilities {
                *capability = normalize_non_empty(std::mem::take(capability));
            }
            row.proposed_minimal_capabilities.sort();
            row.proposed_minimal_capabilities.dedup();
            for capability in &mut row.proposed_minimal_capabilities {
                *capability = normalize_non_empty(std::mem::take(capability));
            }
            row.removed_capabilities.sort();
            row.removed_capabilities.dedup();
            for capability in &mut row.removed_capabilities {
                *capability = normalize_non_empty(std::mem::take(capability));
            }
            row.capability_justifications
                .sort_by(|left, right| left.capability.cmp(&right.capability));
            for capability_justification in &mut row.capability_justifications {
                capability_justification.capability =
                    normalize_non_empty(std::mem::take(&mut capability_justification.capability));
                capability_justification.justification = normalize_non_empty(std::mem::take(
                    &mut capability_justification.justification,
                ));
                capability_justification.static_analysis_ref = normalize_optional_non_empty(
                    capability_justification.static_analysis_ref.take(),
                );
                capability_justification.ablation_result_ref = normalize_optional_non_empty(
                    capability_justification.ablation_result_ref.take(),
                );
                capability_justification.theorem_check_ref =
                    normalize_optional_non_empty(capability_justification.theorem_check_ref.take());
                capability_justification.operator_attestation_ref = normalize_optional_non_empty(
                    capability_justification.operator_attestation_ref.take(),
                );
                capability_justification.inherited_ref =
                    normalize_optional_non_empty(capability_justification.inherited_ref.take());
                capability_justification.playback_ref =
                    normalize_non_empty(std::mem::take(&mut capability_justification.playback_ref));
            }
        }
        proposed_minimal_rows.sort_by(|left, right| {
            left.extension_id
                .cmp(&right.extension_id)
                .then(left.witness_id.cmp(&right.witness_id))
        });

        let mut escrow_event_feed = input.escrow_event_feed;
        escrow_event_feed.sort_by(|left, right| {
            left.timestamp_ns
                .cmp(&right.timestamp_ns)
                .then(left.extension_id.cmp(&right.extension_id))
                .then(left.receipt_id.cmp(&right.receipt_id))
        });
        for escrow_event in &mut escrow_event_feed {
            escrow_event.receipt_id =
                normalize_non_empty(std::mem::take(&mut escrow_event.receipt_id));
            escrow_event.extension_id =
                normalize_non_empty(std::mem::take(&mut escrow_event.extension_id));
            escrow_event.capability = normalize_optional_non_empty(escrow_event.capability.take());
            escrow_event.decision_kind =
                normalize_non_empty(std::mem::take(&mut escrow_event.decision_kind));
            escrow_event.outcome = normalize_non_empty(std::mem::take(&mut escrow_event.outcome));
            escrow_event.trace_id = normalize_non_empty(std::mem::take(&mut escrow_event.trace_id));
            escrow_event.decision_id =
                normalize_non_empty(std::mem::take(&mut escrow_event.decision_id));
            escrow_event.policy_id =
                normalize_non_empty(std::mem::take(&mut escrow_event.policy_id));
            escrow_event.error_code = normalize_optional_non_empty(escrow_event.error_code.take());
            escrow_event.receipt_ref =
                normalize_non_empty(std::mem::take(&mut escrow_event.receipt_ref));
            escrow_event.replay_ref =
                normalize_non_empty(std::mem::take(&mut escrow_event.replay_ref));
        }

        let mut override_rationale_rows = input.override_rationale_rows;
        override_rationale_rows.sort_by(|left, right| {
            left.requested_at_unix_ms
                .cmp(&right.requested_at_unix_ms)
                .then(left.override_id.cmp(&right.override_id))
        });
        for override_row in &mut override_rationale_rows {
            override_row.override_id =
                normalize_non_empty(std::mem::take(&mut override_row.override_id));
            override_row.extension_id =
                normalize_non_empty(std::mem::take(&mut override_row.extension_id));
            override_row.capability = normalize_optional_non_empty(override_row.capability.take());
            override_row.rationale =
                normalize_non_empty(std::mem::take(&mut override_row.rationale));
            override_row.signed_justification_ref =
                normalize_non_empty(std::mem::take(&mut override_row.signed_justification_ref));
            override_row.receipt_ref =
                normalize_non_empty(std::mem::take(&mut override_row.receipt_ref));
            override_row.replay_ref =
                normalize_non_empty(std::mem::take(&mut override_row.replay_ref));
        }

        let generated_at_unix_ms = input.generated_at_unix_ms.expect("serde deserialization should succeed");
        let mut batch_review_queue = if input.batch_review_queue.is_empty() {
            derive_capability_batch_review_queue(&current_capability_rows, generated_at_unix_ms)
        } else {
            input.batch_review_queue
        };
        batch_review_queue.sort_by(|left, right| {
            right
                .pending_review_count
                .cmp(&left.pending_review_count)
                .then(left.batch_id.cmp(&right.batch_id))
        });
        for batch in &mut batch_review_queue {
            batch.batch_id = normalize_non_empty(std::mem::take(&mut batch.batch_id));
            batch.workflow_ref = normalize_non_empty(std::mem::take(&mut batch.workflow_ref));
            batch.extension_ids.sort();
            batch.extension_ids.dedup();
            for extension_id in &mut batch.extension_ids {
                *extension_id = normalize_non_empty(std::mem::take(extension_id));
            }
            batch.witness_ids.sort();
            batch.witness_ids.dedup();
            for witness_id in &mut batch.witness_ids {
                *witness_id = normalize_non_empty(std::mem::take(witness_id));
            }
        }

        let high_escrow_alert_threshold = input.high_escrow_alert_threshold.unwrap_or(5).max(1);
        let pending_override_alert_threshold =
            input.pending_override_alert_threshold.unwrap_or(1).max(1);
        let mut alert_indicators = if input.alert_indicators.is_empty() {
            compute_capability_delta_alerts(
                &current_capability_rows,
                &escrow_event_feed,
                &override_rationale_rows,
                generated_at_unix_ms,
                high_escrow_alert_threshold,
                pending_override_alert_threshold,
            )
        } else {
            input.alert_indicators
        };
        alert_indicators.sort_by(|left, right| left.alert_id.cmp(&right.alert_id));
        for alert in &mut alert_indicators {
            alert.alert_id = normalize_non_empty(std::mem::take(&mut alert.alert_id));
            alert.extension_id = normalize_optional_non_empty(alert.extension_id.take());
            alert.reason = normalize_non_empty(std::mem::take(&mut alert.reason));
        }

        let event_subscription_cursor = input.event_subscription_cursor.and_then(|cursor| {
            let normalized = normalize_non_empty(cursor);
            (normalized != UNKNOWN_LABEL).then_some(normalized)
        });

        Self {
            cluster: normalize_non_empty(input.cluster),
            zone: normalize_non_empty(input.zone),
            security_epoch: input.security_epoch.expect("serde deserialization should succeed"),
            generated_at_unix_ms,
            current_capability_rows,
            proposed_minimal_rows,
            escrow_event_feed,
            override_rationale_rows,
            batch_review_queue,
            alert_indicators,
            event_subscription_cursor,
        }
    }

    pub fn filtered(&self, filter: &CapabilityDeltaDashboardFilter) -> Self {
        let current_capability_rows = self
            .current_capability_rows
            .iter()
            .filter(|row| capability_delta_current_row_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();
        let proposed_minimal_rows = self
            .proposed_minimal_rows
            .iter()
            .filter(|row| capability_delta_proposed_row_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();
        let escrow_event_feed = self
            .escrow_event_feed
            .iter()
            .filter(|row| capability_delta_escrow_row_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();
        let override_rationale_rows = self
            .override_rationale_rows
            .iter()
            .filter(|row| capability_delta_override_row_matches_filter(row, filter))
            .cloned()
            .collect::<Vec<_>>();

        let relevant_extensions = current_capability_rows
            .iter()
            .map(|row| row.extension_id.clone())
            .chain(
                proposed_minimal_rows
                    .iter()
                    .map(|row| row.extension_id.clone()),
            )
            .chain(escrow_event_feed.iter().map(|row| row.extension_id.clone()))
            .chain(
                override_rationale_rows
                    .iter()
                    .map(|row| row.extension_id.clone()),
            )
            .collect::<BTreeSet<_>>();

        let batch_review_queue = self
            .batch_review_queue
            .iter()
            .filter(|batch| {
                relevant_extensions.is_empty()
                    || batch
                        .extension_ids
                        .iter()
                        .any(|extension_id| relevant_extensions.contains(extension_id))
            })
            .cloned()
            .collect::<Vec<_>>();

        let alert_indicators = self
            .alert_indicators
            .iter()
            .filter(|alert| {
                alert
                    .extension_id
                    .as_deref()
                    .is_none_or(|extension_id| relevant_extensions.contains(extension_id))
            })
            .cloned()
            .collect::<Vec<_>>();

        Self {
            cluster: self.cluster.clone(),
            zone: self.zone.clone(),
            security_epoch: self.security_epoch,
            generated_at_unix_ms: self.generated_at_unix_ms,
            current_capability_rows,
            proposed_minimal_rows,
            escrow_event_feed,
            override_rationale_rows,
            batch_review_queue,
            alert_indicators,
            event_subscription_cursor: self.event_subscription_cursor.clone(),
        }
    }

    pub fn from_replay_join_partial(input: CapabilityDeltaReplayJoinPartial) -> Self {
        let CapabilityDeltaReplayJoinPartial {
            cluster,
            zone,
            security_epoch,
            generated_at_unix_ms,
            replay_rows,
            manifest_declared_capabilities,
            override_rationale_rows,
            batch_review_queue,
            event_subscription_cursor,
            high_escrow_alert_threshold,
            pending_override_alert_threshold,
        } = input;

        let mut normalized_manifest_declared_capabilities = BTreeMap::<String, Vec<String>>::new();
        for (extension_id, capabilities) in manifest_declared_capabilities {
            let extension_id = normalize_non_empty(extension_id);
            let mut normalized_capabilities = capabilities
                .into_iter()
                .map(normalize_non_empty)
                .collect::<Vec<_>>();
            normalized_capabilities.sort();
            normalized_capabilities.dedup();
            normalized_manifest_declared_capabilities.insert(extension_id, normalized_capabilities);
        }

        let mut current_capability_rows = Vec::new();
        let mut proposed_minimal_rows = Vec::new();
        let mut escrow_event_feed = Vec::new();
        let mut override_rationale_by_id = BTreeMap::<String, OverrideRationaleView>::new();

        for replay_row in replay_rows {
            let extension_id = replay_row.witness.extension_id.to_string();
            let witness_id = replay_row.witness.witness_id.to_string();
            let policy_id = replay_row.witness.policy_id.to_string();
            let lifecycle_state = replay_row.witness.lifecycle_state.to_string();

            let mut proposed_minimal_capabilities = replay_row
                .witness
                .witness
                .required_capabilities
                .iter()
                .map(|capability| capability.as_str().to_string())
                .collect::<Vec<_>>();
            proposed_minimal_capabilities.sort();
            proposed_minimal_capabilities.dedup();

            let manifest_capabilities = normalized_manifest_declared_capabilities
                .get(&extension_id)
                .cloned()
                .unwrap_or_else(|| proposed_minimal_capabilities.clone());
            let over_privileged_capabilities = proposed_minimal_capabilities
                .iter()
                .filter(|capability| {
                    !manifest_capabilities
                        .iter()
                        .any(|manifest| manifest.eq_ignore_ascii_case(capability))
                })
                .cloned()
                .collect::<Vec<_>>();
            let removed_capabilities = manifest_capabilities
                .iter()
                .filter(|capability| {
                    !proposed_minimal_capabilities
                        .iter()
                        .any(|minimal| minimal.eq_ignore_ascii_case(capability))
                })
                .cloned()
                .collect::<Vec<_>>();

            let capability_justifications = proposed_minimal_capabilities
                .iter()
                .map(|capability| build_capability_justification_drill(&replay_row, capability))
                .collect::<Vec<_>>();

            current_capability_rows.push(CurrentCapabilityDeltaRowView {
                extension_id: extension_id.clone(),
                witness_id: witness_id.clone(),
                policy_id: policy_id.clone(),
                witness_epoch: replay_row.witness.epoch.as_u64(),
                lifecycle_state,
                active_witness_capabilities: proposed_minimal_capabilities.clone(),
                manifest_declared_capabilities: manifest_capabilities.clone(),
                over_privileged_capabilities,
                over_privilege_ratio_millionths: 0,
                over_privilege_replay_ref: format!("frankentui://replay/witness/{witness_id}"),
                latest_receipt_timestamp_ns: replay_row
                    .receipts
                    .iter()
                    .map(|receipt| receipt.timestamp_ns)
                    .max(),
            });

            proposed_minimal_rows.push(ProposedMinimalCapabilityDeltaRowView {
                extension_id: extension_id.clone(),
                witness_id,
                current_capabilities: manifest_capabilities,
                proposed_minimal_capabilities,
                removed_capabilities,
                capability_justifications,
            });

            for receipt in replay_row.receipts {
                let event = build_capability_delta_escrow_event(&extension_id, &receipt);
                if is_override_decision_kind(&event.decision_kind) {
                    let override_row =
                        build_override_rationale_from_escrow_event(&event, generated_at_unix_ms);
                    override_rationale_by_id.insert(override_row.override_id.clone(), override_row);
                }
                escrow_event_feed.push(event);
            }
        }

        for override_row in override_rationale_rows {
            override_rationale_by_id.insert(override_row.override_id.clone(), override_row);
        }

        Self::from_partial(CapabilityDeltaPartial {
            cluster,
            zone,
            security_epoch,
            generated_at_unix_ms,
            current_capability_rows,
            proposed_minimal_rows,
            escrow_event_feed,
            override_rationale_rows: override_rationale_by_id.into_values().collect::<Vec<_>>(),
            batch_review_queue,
            alert_indicators: Vec::new(),
            event_subscription_cursor,
            high_escrow_alert_threshold,
            pending_override_alert_threshold,
        })
    }
}

fn compute_over_privilege_ratio_millionths(
    total_capabilities: usize,
    over_privileged: usize,
) -> u64 {
    if total_capabilities == 0 {
        return 0;
    }
    #[allow(clippy::cast_possible_truncation)]
    {
        ((over_privileged as u128 * 1_000_000u128) / total_capabilities as u128) as u64
    }
}

fn derive_capability_batch_review_queue(
    current_rows: &[CurrentCapabilityDeltaRowView],
    generated_at_unix_ms: u64,
) -> Vec<CapabilityPromotionBatchReviewView> {
    if current_rows.is_empty() {
        return Vec::new();
    }
    let mut extension_ids = current_rows
        .iter()
        .map(|row| row.extension_id.clone())
        .collect::<Vec<_>>();
    extension_ids.sort();
    extension_ids.dedup();
    let mut witness_ids = current_rows
        .iter()
        .map(|row| row.witness_id.clone())
        .collect::<Vec<_>>();
    witness_ids.sort();
    witness_ids.dedup();

    let pending_review_count = current_rows
        .iter()
        .filter(|row| row.over_privilege_ratio_millionths > 0)
        .count() as u64;
    vec![CapabilityPromotionBatchReviewView {
        batch_id: "capability-delta-review-default".to_string(),
        extension_ids,
        witness_ids,
        pending_review_count,
        generated_at_unix_ms,
        workflow_ref: "frankentui://witness-promotion/batch/default".to_string(),
    }]
}

fn build_capability_justification_drill(
    replay_row: &WitnessReplayJoinRow,
    capability: &str,
) -> CapabilityJustificationDrillView {
    let mut static_analysis_ref = None;
    let mut ablation_result_ref = None;
    let mut theorem_check_ref = None;
    let mut operator_attestation_ref = None;
    let mut inherited_ref = None;
    let mut justification_parts = Vec::new();

    for proof in replay_row
        .witness
        .witness
        .proof_obligations
        .iter()
        .filter(|proof| proof.capability.as_str().eq_ignore_ascii_case(capability))
    {
        let proof_ref = format!("frankentui://proof/{}", proof.proof_artifact_id);
        match proof.kind {
            ProofKind::StaticAnalysis => {
                if static_analysis_ref.is_none() {
                    static_analysis_ref = Some(proof_ref);
                }
            }
            ProofKind::DynamicAblation => {
                if ablation_result_ref.is_none() {
                    ablation_result_ref = Some(proof_ref);
                }
            }
            ProofKind::PolicyTheoremCheck => {
                if theorem_check_ref.is_none() {
                    theorem_check_ref = Some(proof_ref);
                }
            }
            ProofKind::OperatorAttestation => {
                if operator_attestation_ref.is_none() {
                    operator_attestation_ref = Some(proof_ref);
                }
            }
            ProofKind::InheritedFromPredecessor => {
                if inherited_ref.is_none() {
                    inherited_ref = Some(proof_ref);
                }
            }
        }
        let justification = normalize_non_empty(proof.justification.clone());
        if !justification_parts
            .iter()
            .any(|item| item == &justification)
        {
            justification_parts.push(justification);
        }
    }

    let justification = if justification_parts.is_empty() {
        "no explicit proof obligation recorded".to_string()
    } else {
        justification_parts.join("; ")
    };
    let playback_ref = theorem_check_ref
        .clone()
        .or_else(|| ablation_result_ref.clone())
        .or_else(|| static_analysis_ref.clone())
        .or_else(|| operator_attestation_ref.clone())
        .or_else(|| inherited_ref.clone())
        .unwrap_or_else(|| format!("frankentui://proof/capability/{capability}"));

    CapabilityJustificationDrillView {
        capability: capability.to_string(),
        justification,
        static_analysis_ref,
        ablation_result_ref,
        theorem_check_ref,
        operator_attestation_ref,
        inherited_ref,
        playback_ref,
    }
}

fn build_capability_delta_escrow_event(
    extension_id: &str,
    receipt: &CapabilityEscrowReceiptRecord,
) -> CapabilityDeltaEscrowEventView {
    CapabilityDeltaEscrowEventView {
        receipt_id: receipt.receipt_id.clone(),
        extension_id: extension_id.to_string(),
        capability: receipt
            .capability
            .as_ref()
            .map(|capability| capability.as_str().to_string()),
        decision_kind: receipt.decision_kind.clone(),
        outcome: receipt.outcome.clone(),
        trace_id: receipt.trace_id.clone(),
        decision_id: receipt.decision_id.clone(),
        policy_id: receipt.policy_id.clone(),
        error_code: receipt.error_code.clone(),
        timestamp_ns: receipt.timestamp_ns,
        receipt_ref: format!("frankentui://escrow-receipt/{}", receipt.receipt_id),
        replay_ref: format!("frankentui://replay/escrow/{}", receipt.receipt_id),
    }
}

fn is_override_decision_kind(decision_kind: &str) -> bool {
    let decision_kind = decision_kind.trim().to_ascii_lowercase();
    decision_kind.contains("override") || decision_kind.contains("emergency_grant")
}

fn build_override_rationale_from_escrow_event(
    event: &CapabilityDeltaEscrowEventView,
    generated_at_unix_ms: Option<u64>,
) -> OverrideRationaleView {
    let requested_at_unix_ms = event.timestamp_ns / 1_000_000;
    let effective_now_unix_ms = generated_at_unix_ms.unwrap_or(requested_at_unix_ms);
    let review_status = derive_override_review_status(&event.outcome);
    let mut expires_at_unix_ms = if is_override_decision_kind(&event.decision_kind) {
        Some(requested_at_unix_ms.saturating_add(86_400_000))
    } else {
        None
    };
    let mut grant_expiry_status = if is_override_decision_kind(&event.decision_kind) {
        GrantExpiryStatus::Active
    } else {
        GrantExpiryStatus::NotApplicable
    };
    let outcome_lower = event.outcome.to_ascii_lowercase();
    if outcome_lower.contains("expired") {
        grant_expiry_status = GrantExpiryStatus::Expired;
    } else if let Some(expiry) = expires_at_unix_ms {
        if expiry <= effective_now_unix_ms {
            grant_expiry_status = GrantExpiryStatus::Expired;
        } else if expiry.saturating_sub(effective_now_unix_ms) <= 3_600_000 {
            grant_expiry_status = GrantExpiryStatus::ExpiringSoon;
        }
    } else {
        expires_at_unix_ms = None;
    }

    OverrideRationaleView {
        override_id: event.receipt_id.clone(),
        extension_id: event.extension_id.clone(),
        capability: event.capability.clone(),
        rationale: format!(
            "decision_kind={} outcome={} trace_id={}",
            event.decision_kind, event.outcome, event.trace_id
        ),
        signed_justification_ref: format!("frankentui://signed-override/{}", event.receipt_id),
        review_status,
        grant_expiry_status,
        requested_at_unix_ms,
        reviewed_at_unix_ms: if review_status == OverrideReviewStatus::Pending {
            None
        } else {
            Some(requested_at_unix_ms)
        },
        expires_at_unix_ms,
        receipt_ref: event.receipt_ref.clone(),
        replay_ref: event.replay_ref.clone(),
    }
}

fn derive_override_review_status(outcome: &str) -> OverrideReviewStatus {
    let normalized = outcome.trim().to_ascii_lowercase();
    if normalized.contains("reject") || normalized.contains("deny") {
        return OverrideReviewStatus::Rejected;
    }
    if normalized.contains("waive") {
        return OverrideReviewStatus::Waived;
    }
    if normalized.contains("approve") || normalized.contains("grant") {
        return OverrideReviewStatus::Approved;
    }
    OverrideReviewStatus::Pending
}

fn compute_capability_delta_alerts(
    current_rows: &[CurrentCapabilityDeltaRowView],
    escrow_event_feed: &[CapabilityDeltaEscrowEventView],
    override_rows: &[OverrideRationaleView],
    generated_at_unix_ms: u64,
    high_escrow_alert_threshold: u64,
    pending_override_alert_threshold: u64,
) -> Vec<CapabilityDeltaAlertView> {
    let mut alerts = Vec::new();

    let mut escrow_counts_by_extension = BTreeMap::<String, u64>::new();
    for event in escrow_event_feed {
        let entry = escrow_counts_by_extension
            .entry(event.extension_id.clone())
            .or_default();
        *entry = entry.saturating_add(1);
    }
    for (extension_id, count) in escrow_counts_by_extension {
        if count >= high_escrow_alert_threshold {
            alerts.push(CapabilityDeltaAlertView {
                alert_id: format!("high-escrow-rate-{extension_id}"),
                extension_id: Some(extension_id),
                severity: if count >= high_escrow_alert_threshold.saturating_mul(2) {
                    DashboardSeverity::Critical
                } else {
                    DashboardSeverity::Warning
                },
                reason: format!(
                    "escrow_events={} exceeds threshold={}",
                    count, high_escrow_alert_threshold
                ),
                generated_at_unix_ms,
            });
        }
    }

    for current_row in current_rows {
        if current_row.over_privilege_ratio_millionths > 0 {
            alerts.push(CapabilityDeltaAlertView {
                alert_id: format!("over-privilege-{}", current_row.extension_id),
                extension_id: Some(current_row.extension_id.clone()),
                severity: if current_row.over_privilege_ratio_millionths >= 250_000 {
                    DashboardSeverity::Critical
                } else {
                    DashboardSeverity::Warning
                },
                reason: format!(
                    "over_privilege_ratio_millionths={} witness_id={}",
                    current_row.over_privilege_ratio_millionths, current_row.witness_id
                ),
                generated_at_unix_ms,
            });
        }
    }

    let pending_override_count = override_rows
        .iter()
        .filter(|row| row.review_status == OverrideReviewStatus::Pending)
        .count() as u64;
    if pending_override_count >= pending_override_alert_threshold {
        alerts.push(CapabilityDeltaAlertView {
            alert_id: "pending-override-reviews".to_string(),
            extension_id: None,
            severity: if pending_override_count
                >= pending_override_alert_threshold.saturating_mul(2)
            {
                DashboardSeverity::Critical
            } else {
                DashboardSeverity::Warning
            },
            reason: format!(
                "pending_override_reviews={} threshold={}",
                pending_override_count, pending_override_alert_threshold
            ),
            generated_at_unix_ms,
        });
    }

    let expired_overrides = override_rows
        .iter()
        .filter(|row| row.grant_expiry_status == GrantExpiryStatus::Expired)
        .count() as u64;
    if expired_overrides > 0 {
        alerts.push(CapabilityDeltaAlertView {
            alert_id: "expired-emergency-grants".to_string(),
            extension_id: None,
            severity: DashboardSeverity::Critical,
            reason: format!("expired_emergency_grants={expired_overrides}"),
            generated_at_unix_ms,
        });
    }

    let expiring_soon_overrides = override_rows
        .iter()
        .filter(|row| row.grant_expiry_status == GrantExpiryStatus::ExpiringSoon)
        .count() as u64;
    if expiring_soon_overrides > 0 {
        alerts.push(CapabilityDeltaAlertView {
            alert_id: "expiring-emergency-grants".to_string(),
            extension_id: None,
            severity: DashboardSeverity::Warning,
            reason: format!("expiring_soon_emergency_grants={expiring_soon_overrides}"),
            generated_at_unix_ms,
        });
    }

    alerts.sort_by(|left, right| left.alert_id.cmp(&right.alert_id));
    alerts
}

fn capability_delta_current_row_matches_filter(
    row: &CurrentCapabilityDeltaRowView,
    filter: &CapabilityDeltaDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !row.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(capability) = filter.capability.as_deref()
        && !row
            .active_witness_capabilities
            .iter()
            .chain(row.manifest_declared_capabilities.iter())
            .chain(row.over_privileged_capabilities.iter())
            .any(|value| value.eq_ignore_ascii_case(capability))
    {
        return false;
    }
    if let Some(min_ratio) = filter.min_over_privilege_ratio_millionths
        && row.over_privilege_ratio_millionths < min_ratio
    {
        return false;
    }
    if let Some(timestamp_ns) = row.latest_receipt_timestamp_ns
        && !capability_delta_timestamp_matches_range(timestamp_ns, filter)
    {
        return false;
    }
    true
}

fn capability_delta_proposed_row_matches_filter(
    row: &ProposedMinimalCapabilityDeltaRowView,
    filter: &CapabilityDeltaDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !row.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(capability) = filter.capability.as_deref()
        && !row
            .current_capabilities
            .iter()
            .chain(row.proposed_minimal_capabilities.iter())
            .chain(row.removed_capabilities.iter())
            .chain(
                row.capability_justifications
                    .iter()
                    .map(|row| &row.capability),
            )
            .any(|value| value.eq_ignore_ascii_case(capability))
    {
        return false;
    }
    true
}

fn capability_delta_escrow_row_matches_filter(
    row: &CapabilityDeltaEscrowEventView,
    filter: &CapabilityDeltaDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !row.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(capability) = filter.capability.as_deref()
        && !row
            .capability
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(capability))
    {
        return false;
    }
    if let Some(outcome) = filter.outcome.as_deref()
        && !row.outcome.eq_ignore_ascii_case(outcome)
    {
        return false;
    }
    capability_delta_timestamp_matches_range(row.timestamp_ns, filter)
}

fn capability_delta_override_row_matches_filter(
    row: &OverrideRationaleView,
    filter: &CapabilityDeltaDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !row.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(capability) = filter.capability.as_deref()
        && !row
            .capability
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(capability))
    {
        return false;
    }
    if let Some(grant_expiry_status) = filter.grant_expiry_status
        && row.grant_expiry_status != grant_expiry_status
    {
        return false;
    }
    capability_delta_timestamp_matches_range(
        row.requested_at_unix_ms.saturating_mul(1_000_000),
        filter,
    )
}

fn capability_delta_timestamp_matches_range(
    timestamp_ns: u64,
    filter: &CapabilityDeltaDashboardFilter,
) -> bool {
    if let Some(start_timestamp_ns) = filter.start_timestamp_ns
        && timestamp_ns < start_timestamp_ns
    {
        return false;
    }
    if let Some(end_timestamp_ns) = filter.end_timestamp_ns
        && timestamp_ns > end_timestamp_ns
    {
        return false;
    }
    true
}

pub fn build_native_coverage_meter(
    slot_status_overview: &[SlotStatusOverviewRow],
    trend: Vec<CoverageTrendPoint>,
) -> NativeCoverageMeter {
    let native_slots = slot_status_overview
        .iter()
        .filter(|row| implementation_is_native(&row.implementation_kind))
        .count();
    let delegate_slots = slot_status_overview.len().saturating_sub(native_slots);
    let native_coverage_millionths = if slot_status_overview.is_empty() {
        0
    } else {
        #[allow(clippy::cast_possible_truncation)]
        {
            ((native_slots as u128 * 1_000_000u128) / slot_status_overview.len() as u128) as u64
        }
    };

    NativeCoverageMeter {
        native_slots,
        delegate_slots,
        native_coverage_millionths,
        trend,
    }
}

pub fn rank_replacement_opportunities(
    inputs: Vec<ReplacementOpportunityInput>,
) -> Vec<ReplacementOpportunityView> {
    let mut ranked = inputs
        .into_iter()
        .map(|input| {
            let expected_value_score_millionths = compute_expected_value_score_millionths(&input);
            ReplacementOpportunityView {
                slot_id: normalize_non_empty(input.slot_id),
                slot_kind: normalize_non_empty(input.slot_kind),
                expected_value_score_millionths,
                performance_uplift_millionths: input.performance_uplift_millionths,
                invocation_frequency_per_minute: input.invocation_frequency_per_minute,
                risk_reduction_millionths: input.risk_reduction_millionths,
                rationale: format!(
                    "perf_uplift={} freq_per_min={} risk_reduction={}",
                    input.performance_uplift_millionths,
                    input.invocation_frequency_per_minute,
                    input.risk_reduction_millionths
                ),
            }
        })
        .collect::<Vec<_>>();

    ranked.sort_by(|left, right| {
        right
            .expected_value_score_millionths
            .cmp(&left.expected_value_score_millionths)
            .then(left.slot_id.cmp(&right.slot_id))
    });
    ranked
}

pub fn build_specialization_performance_impact(
    active_specializations: &[ActiveSpecializationRowView],
    proof_inventory: &[ProofInventoryRowView],
) -> SpecializationPerformanceImpactView {
    let active_specialization_count = active_specializations.len() as u64;
    let aggregate_latency_reduction_millionths =
        active_specializations.iter().fold(0u64, |sum, row| {
            sum.saturating_add(row.latency_reduction_millionths)
        });
    let aggregate_throughput_increase_millionths =
        active_specializations.iter().fold(0u64, |sum, row| {
            sum.saturating_add(row.throughput_increase_millionths)
        });
    let linked_specialization_total = proof_inventory.iter().fold(0u64, |sum, row| {
        sum.saturating_add(row.linked_specialization_count)
    });
    let specialization_coverage_millionths = if linked_specialization_total == 0 {
        if active_specializations.is_empty() {
            1_000_000
        } else {
            0
        }
    } else {
        #[allow(clippy::cast_possible_truncation)]
        {
            ((u128::from(active_specialization_count) * 1_000_000u128)
                / u128::from(linked_specialization_total)) as u64
        }
    };

    SpecializationPerformanceImpactView {
        active_specialization_count,
        aggregate_latency_reduction_millionths,
        aggregate_throughput_increase_millionths,
        specialization_coverage_millionths: canonicalize_coverage_millionths(
            specialization_coverage_millionths,
        ),
    }
}

fn compute_proof_specialization_alerts(
    invalidation_feed: &[SpecializationInvalidationRowView],
    specialization_coverage_millionths: u64,
    generated_at_unix_ms: u64,
    bulk_invalidation_alert_threshold: u64,
    degraded_coverage_alert_threshold_millionths: u64,
) -> Vec<ProofSpecializationAlertView> {
    let mut alerts = Vec::new();
    let invalidation_count = invalidation_feed.len() as u64;
    let bulk_threshold = bulk_invalidation_alert_threshold.max(1);
    if invalidation_count >= bulk_threshold {
        alerts.push(ProofSpecializationAlertView {
            alert_id: "bulk-invalidation".to_string(),
            severity: if invalidation_count >= bulk_threshold.saturating_mul(2) {
                DashboardSeverity::Critical
            } else {
                DashboardSeverity::Warning
            },
            reason: format!(
                "invalidations={} exceeds threshold={}",
                invalidation_count, bulk_threshold
            ),
            affected_count: invalidation_count,
            generated_at_unix_ms,
        });
    }

    let degraded_threshold =
        canonicalize_coverage_millionths(degraded_coverage_alert_threshold_millionths);
    if specialization_coverage_millionths < degraded_threshold {
        alerts.push(ProofSpecializationAlertView {
            alert_id: "specialization-coverage-degraded".to_string(),
            severity: if specialization_coverage_millionths < degraded_threshold / 2 {
                DashboardSeverity::Critical
            } else {
                DashboardSeverity::Warning
            },
            reason: format!(
                "specialization_coverage_millionths={} below threshold={}",
                specialization_coverage_millionths, degraded_threshold
            ),
            affected_count: degraded_threshold.saturating_sub(specialization_coverage_millionths),
            generated_at_unix_ms,
        });
    }

    alerts.sort_by(|left, right| left.alert_id.cmp(&right.alert_id));
    alerts
}

fn proof_specialization_row_matches_filter(
    row: &ActiveSpecializationRowView,
    filter: &ProofSpecializationDashboardFilter,
) -> bool {
    if let Some(target_id) = filter.target_id.as_deref()
        && !row.target_id.eq_ignore_ascii_case(target_id)
    {
        return false;
    }
    if let Some(optimization_class) = filter.optimization_class.as_deref()
        && !row
            .optimization_class
            .eq_ignore_ascii_case(optimization_class)
    {
        return false;
    }
    if let Some(proof_id) = filter.proof_id.as_deref()
        && !row
            .proof_input_ids
            .iter()
            .any(|id| id.eq_ignore_ascii_case(proof_id))
    {
        return false;
    }
    proof_specialization_timestamp_matches_range(row.activated_at_unix_ms, filter)
}

fn proof_specialization_invalidation_matches_filter(
    row: &SpecializationInvalidationRowView,
    filter: &ProofSpecializationDashboardFilter,
) -> bool {
    if let Some(target_id) = filter.target_id.as_deref()
        && !row.target_id.eq_ignore_ascii_case(target_id)
    {
        return false;
    }
    if let Some(proof_id) = filter.proof_id.as_deref()
        && !row
            .proof_id
            .as_deref()
            .is_some_and(|id| id.eq_ignore_ascii_case(proof_id))
    {
        return false;
    }
    proof_specialization_timestamp_matches_range(row.occurred_at_unix_ms, filter)
}

fn proof_specialization_fallback_matches_filter(
    row: &SpecializationFallbackEventView,
    filter: &ProofSpecializationDashboardFilter,
) -> bool {
    if let Some(target_id) = filter.target_id.as_deref()
        && !row.target_id.eq_ignore_ascii_case(target_id)
    {
        return false;
    }
    proof_specialization_timestamp_matches_range(row.occurred_at_unix_ms, filter)
}

fn proof_specialization_timestamp_matches_range(
    timestamp_unix_ms: u64,
    filter: &ProofSpecializationDashboardFilter,
) -> bool {
    if let Some(start_unix_ms) = filter.start_unix_ms
        && timestamp_unix_ms < start_unix_ms
    {
        return false;
    }
    if let Some(end_unix_ms) = filter.end_unix_ms
        && timestamp_unix_ms > end_unix_ms
    {
        return false;
    }
    true
}

fn compute_flow_alert_indicators(
    blocked_flows: &[BlockedFlowView],
    confinement_proofs: &[ConfinementProofView],
    generated_at_unix_ms: u64,
    blocked_flow_alert_threshold: u64,
) -> Vec<FlowDecisionAlertView> {
    let mut alerts = Vec::new();
    let mut blocked_counts_by_extension = BTreeMap::<String, u64>::new();
    for flow in blocked_flows {
        let entry = blocked_counts_by_extension
            .entry(flow.extension_id.clone())
            .or_default();
        *entry = entry.saturating_add(1);
    }
    for (extension_id, blocked_flow_count) in blocked_counts_by_extension {
        if blocked_flow_count >= blocked_flow_alert_threshold {
            let severity = if blocked_flow_count >= blocked_flow_alert_threshold.saturating_mul(2) {
                DashboardSeverity::Critical
            } else {
                DashboardSeverity::Warning
            };
            alerts.push(FlowDecisionAlertView {
                alert_id: format!("blocked-rate-{extension_id}"),
                extension_id: extension_id.clone(),
                severity,
                reason: format!(
                    "blocked_flow_count={} exceeds threshold={}",
                    blocked_flow_count, blocked_flow_alert_threshold
                ),
                blocked_flow_count,
                generated_at_unix_ms,
            });
        }
    }
    for proof in confinement_proofs {
        if proof.status != ConfinementStatus::Full {
            alerts.push(FlowDecisionAlertView {
                alert_id: format!("confinement-{}", proof.extension_id),
                extension_id: proof.extension_id.clone(),
                severity: if proof.status == ConfinementStatus::Degraded {
                    DashboardSeverity::Critical
                } else {
                    DashboardSeverity::Warning
                },
                reason: format!("confinement_status={:?}", proof.status),
                blocked_flow_count: proof.uncovered_flow_count,
                generated_at_unix_ms,
            });
        }
    }
    alerts.sort_by(|left, right| left.alert_id.cmp(&right.alert_id));
    alerts
}

fn blocked_flow_matches_filter(
    flow: &BlockedFlowView,
    filter: &FlowDecisionDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !flow.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(source_label) = filter.source_label.as_deref()
        && !flow.source_label.eq_ignore_ascii_case(source_label)
    {
        return false;
    }
    if let Some(sink_clearance) = filter.sink_clearance.as_deref()
        && !flow.sink_clearance.eq_ignore_ascii_case(sink_clearance)
    {
        return false;
    }
    if let Some(sensitivity) = filter.sensitivity
        && flow.sensitivity != sensitivity
    {
        return false;
    }
    flow_timestamp_matches_range(flow.occurred_at_unix_ms, filter)
}

fn declassification_matches_filter(
    decision: &DeclassificationDecisionView,
    filter: &FlowDecisionDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !decision.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(source_label) = filter.source_label.as_deref()
        && !decision.source_label.eq_ignore_ascii_case(source_label)
    {
        return false;
    }
    if let Some(sink_clearance) = filter.sink_clearance.as_deref()
        && !decision.sink_clearance.eq_ignore_ascii_case(sink_clearance)
    {
        return false;
    }
    if let Some(sensitivity) = filter.sensitivity
        && decision.sensitivity != sensitivity
    {
        return false;
    }
    flow_timestamp_matches_range(decision.decided_at_unix_ms, filter)
}

fn confinement_proof_matches_filter(
    proof: &ConfinementProofView,
    filter: &FlowDecisionDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !proof.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(source_label) = filter.source_label.as_deref()
        && !proof
            .proof_rows
            .iter()
            .any(|row| row.source_label.eq_ignore_ascii_case(source_label))
    {
        return false;
    }
    if let Some(sink_clearance) = filter.sink_clearance.as_deref()
        && !proof
            .proof_rows
            .iter()
            .any(|row| row.sink_clearance.eq_ignore_ascii_case(sink_clearance))
    {
        return false;
    }
    if let Some(sensitivity) = filter.sensitivity
        && sensitivity == FlowSensitivityLevel::Critical
        && proof.status == ConfinementStatus::Full
    {
        return false;
    }
    true
}

fn flow_timestamp_matches_range(
    timestamp_unix_ms: u64,
    filter: &FlowDecisionDashboardFilter,
) -> bool {
    if let Some(start_unix_ms) = filter.start_unix_ms
        && timestamp_unix_ms < start_unix_ms
    {
        return false;
    }
    if let Some(end_unix_ms) = filter.end_unix_ms
        && timestamp_unix_ms > end_unix_ms
    {
        return false;
    }
    true
}

fn summarize_decision_outcomes(entries: &[EvidenceStreamEntryView]) -> DecisionOutcomesPanelView {
    let mut allow_count = 0u64;
    let mut deny_count = 0u64;
    let mut fallback_count = 0u64;
    let mut total_expected_loss = 0i128;

    for entry in entries {
        match entry.decision_outcome {
            DecisionOutcomeKind::Allow => allow_count = allow_count.saturating_add(1),
            DecisionOutcomeKind::Deny => deny_count = deny_count.saturating_add(1),
            DecisionOutcomeKind::Fallback => fallback_count = fallback_count.saturating_add(1),
        }
        total_expected_loss =
            total_expected_loss.saturating_add(i128::from(entry.expected_loss_millionths));
    }

    let average_expected_loss_millionths = if entries.is_empty() {
        0
    } else {
        (total_expected_loss / i128::try_from(entries.len()).unwrap_or(1))
            .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
    };

    DecisionOutcomesPanelView {
        allow_count,
        deny_count,
        fallback_count,
        average_expected_loss_millionths,
    }
}

fn summarize_obligation_status(rows: &[ObligationStatusRowView]) -> ObligationStatusPanelView {
    let mut open_count = 0u64;
    let mut fulfilled_count = 0u64;
    let mut failed_count = 0u64;
    for row in rows {
        match row.state {
            ObligationState::Open => open_count = open_count.saturating_add(1),
            ObligationState::Fulfilled => fulfilled_count = fulfilled_count.saturating_add(1),
            ObligationState::Failed => failed_count = failed_count.saturating_add(1),
        }
    }
    ObligationStatusPanelView {
        open_count,
        fulfilled_count,
        failed_count,
    }
}

fn summarize_region_lifecycle(rows: &[RegionLifecycleRowView]) -> RegionLifecyclePanelView {
    let active_region_count = rows.iter().filter(|row| row.is_active).count() as u64;
    let region_creations_in_window =
        rows.iter().filter(|row| row.created_at_unix_ms > 0).count() as u64;
    let region_destructions_in_window = rows
        .iter()
        .filter(|row| row.closed_at_unix_ms.is_some())
        .count() as u64;
    let close_times = rows
        .iter()
        .filter_map(|row| row.quiescent_close_time_ms)
        .collect::<Vec<_>>();
    let average_quiescent_close_time_ms = if close_times.is_empty() {
        0
    } else {
        close_times
            .iter()
            .copied()
            .fold(0u64, |acc, x| acc.saturating_add(x))
            / close_times.len() as u64
    };
    RegionLifecyclePanelView {
        active_region_count,
        region_creations_in_window,
        region_destructions_in_window,
        average_quiescent_close_time_ms,
    }
}

fn evidence_entry_matches_filter(
    entry: &EvidenceStreamEntryView,
    filter: &ControlPlaneDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !entry.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(region_id) = filter.region_id.as_deref()
        && !entry.region_id.eq_ignore_ascii_case(region_id)
    {
        return false;
    }
    if let Some(severity) = filter.severity
        && entry.severity != severity
    {
        return false;
    }
    timestamp_matches_range(entry.timestamp_unix_ms, filter)
}

fn obligation_row_matches_filter(
    row: &ObligationStatusRowView,
    filter: &ControlPlaneDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !row.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(region_id) = filter.region_id.as_deref()
        && !row.region_id.eq_ignore_ascii_case(region_id)
    {
        return false;
    }
    if let Some(severity) = filter.severity
        && row.severity != severity
    {
        return false;
    }
    timestamp_matches_range(row.updated_at_unix_ms, filter)
}

fn region_row_matches_filter(
    row: &RegionLifecycleRowView,
    filter: &ControlPlaneDashboardFilter,
) -> bool {
    if let Some(region_id) = filter.region_id.as_deref()
        && !row.region_id.eq_ignore_ascii_case(region_id)
    {
        return false;
    }
    // A region is alive during [start, end] if it was created at or before
    // end_unix_ms AND either not yet closed or closed at or after start_unix_ms.
    if let Some(end) = filter.end_unix_ms
        && row.created_at_unix_ms > end
    {
        return false;
    }
    if let Some(start) = filter.start_unix_ms
        && let Some(closed) = row.closed_at_unix_ms
        && closed < start
    {
        return false;
    }
    true
}

fn cancellation_event_matches_filter(
    event: &CancellationEventView,
    filter: &ControlPlaneDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !event.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(region_id) = filter.region_id.as_deref()
        && !event.region_id.eq_ignore_ascii_case(region_id)
    {
        return false;
    }
    if let Some(severity) = filter.severity
        && event.severity != severity
    {
        return false;
    }
    timestamp_matches_range(event.timestamp_unix_ms, filter)
}

fn safe_mode_activation_matches_filter(
    activation: &SafeModeActivationView,
    filter: &ControlPlaneDashboardFilter,
) -> bool {
    if let Some(extension_id) = filter.extension_id.as_deref()
        && !activation.extension_id.eq_ignore_ascii_case(extension_id)
    {
        return false;
    }
    if let Some(region_id) = filter.region_id.as_deref()
        && !activation.region_id.eq_ignore_ascii_case(region_id)
    {
        return false;
    }
    if let Some(severity) = filter.severity
        && activation.severity != severity
    {
        return false;
    }
    timestamp_matches_range(activation.activated_at_unix_ms, filter)
}

fn timestamp_matches_range(timestamp_unix_ms: u64, filter: &ControlPlaneDashboardFilter) -> bool {
    if let Some(start_unix_ms) = filter.start_unix_ms
        && timestamp_unix_ms < start_unix_ms
    {
        return false;
    }
    if let Some(end_unix_ms) = filter.end_unix_ms
        && timestamp_unix_ms > end_unix_ms
    {
        return false;
    }
    true
}

fn dashboard_metric_value(
    view: &ControlPlaneInvariantsDashboardView,
    metric: DashboardAlertMetric,
) -> i64 {
    match metric {
        DashboardAlertMetric::ObligationFailureRateMillionths => {
            let total = view
                .obligation_status
                .open_count
                .saturating_add(view.obligation_status.fulfilled_count)
                .saturating_add(view.obligation_status.failed_count);
            if total == 0 {
                0
            } else {
                #[allow(clippy::cast_possible_wrap)]
                {
                    ((u128::from(view.obligation_status.failed_count) * 1_000_000u128)
                        / u128::from(total)) as i64
                }
            }
        }
        DashboardAlertMetric::ReplayDivergenceCount => view.replay_health.divergence_count as i64,
        DashboardAlertMetric::SafeModeActivationCount => view.safe_mode_activations.len() as i64,
        DashboardAlertMetric::CancellationEventCount => view.cancellation_events.len() as i64,
        DashboardAlertMetric::FallbackActivationCount => {
            view.decision_outcomes.fallback_count as i64
        }
    }
}

fn threshold_matches(comparator: ThresholdComparator, observed: i64, threshold: i64) -> bool {
    match comparator {
        ThresholdComparator::GreaterThan => observed > threshold,
        ThresholdComparator::GreaterOrEqual => observed >= threshold,
        ThresholdComparator::LessThan => observed < threshold,
        ThresholdComparator::LessOrEqual => observed <= threshold,
        ThresholdComparator::Equal => observed == threshold,
    }
}

fn normalize_non_empty(value: String) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        UNKNOWN_LABEL.to_string()
    } else {
        trimmed.to_string()
    }
}

fn normalize_optional_non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn canonicalize_coverage_millionths(value: u64) -> u64 {
    value.min(1_000_000)
}

fn slot_row_matches_filter(
    row: &SlotStatusOverviewRow,
    filter: &ReplacementDashboardFilter,
) -> bool {
    if let Some(slot_kind) = filter.slot_kind.as_deref()
        && !row.slot_kind.eq_ignore_ascii_case(slot_kind)
    {
        return false;
    }
    if let Some(risk_level) = filter.risk_level
        && row.risk_level != risk_level
    {
        return false;
    }
    if let Some(promotion_status) = filter.promotion_status.as_deref()
        && !row.promotion_status.eq_ignore_ascii_case(promotion_status)
    {
        return false;
    }
    true
}

fn implementation_is_native(kind: &str) -> bool {
    kind.eq_ignore_ascii_case("native")
}

fn replacement_promotion_status_label(status: &PromotionStatus) -> &'static str {
    match status {
        PromotionStatus::Delegate => "delegate",
        PromotionStatus::PromotionCandidate { .. } => "promotion_candidate",
        PromotionStatus::Promoted { .. } => "promoted",
        PromotionStatus::Demoted { .. } => "demoted",
    }
}

fn replacement_health_label(status: &PromotionStatus) -> &'static str {
    match status {
        PromotionStatus::Delegate => "pending_replacement",
        PromotionStatus::PromotionCandidate { .. } => "candidate",
        PromotionStatus::Promoted { .. } => "healthy",
        PromotionStatus::Demoted { .. } => "degraded",
    }
}

fn replacement_risk_level(status: &PromotionStatus) -> ReplacementRiskLevel {
    match status {
        PromotionStatus::Promoted { .. } => ReplacementRiskLevel::Low,
        PromotionStatus::Delegate => ReplacementRiskLevel::Medium,
        PromotionStatus::PromotionCandidate { .. } | PromotionStatus::Demoted { .. } => {
            ReplacementRiskLevel::High
        }
    }
}

fn replacement_last_transition_unix_ms(entry: &SlotEntry, fallback_unix_ms: u64) -> u64 {
    entry
        .promotion_lineage
        .last()
        .and_then(|event| parse_timestamp_unix_ms(&event.timestamp))
        .unwrap_or(fallback_unix_ms)
}

fn replacement_lineage_ref(slot_id: &str) -> String {
    format!(
        "frankentui://replacement-lineage/{}",
        normalize_non_empty(slot_id.to_string())
    )
}

fn replacement_evidence_ref(
    slot_id: &str,
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
) -> String {
    format!(
        "frankentui://replacement-evidence/{}?trace_id={}&decision_id={}&policy_id={}",
        normalize_non_empty(slot_id.to_string()),
        normalize_non_empty(trace_id.to_string()),
        normalize_non_empty(decision_id.to_string()),
        normalize_non_empty(policy_id.to_string())
    )
}

fn replacement_blocked_promotion_from_event(
    event: &ReplacementProgressEvent,
) -> Option<BlockedPromotionView> {
    let slot_id = event.slot_id.as_deref().map(|value| value.trim())?;
    if slot_id.is_empty() {
        return None;
    }
    let event_name = event.event.to_ascii_lowercase();
    let outcome = event.outcome.to_ascii_lowercase();
    let is_promotion_event = event_name.contains("promotion") || event_name.contains("candidate");
    let is_blocking_outcome = matches!(
        outcome.as_str(),
        "blocked" | "failed" | "denied" | "rejected"
    );
    if !is_promotion_event || !(is_blocking_outcome || event.error_code.is_some()) {
        return None;
    }

    let lineage_ref = replacement_lineage_ref(slot_id);
    let evidence_ref = replacement_evidence_ref(
        slot_id,
        &event.trace_id,
        &event.decision_id,
        &event.policy_id,
    );
    Some(BlockedPromotionView {
        slot_id: slot_id.to_string(),
        gate_failure_code: normalize_non_empty(
            event
                .error_code
                .clone()
                .unwrap_or_else(|| "promotion_blocked".to_string()),
        ),
        failure_detail: normalize_non_empty(event.detail.clone()),
        recommended_remediation: format!(
            "inspect {} and replay lineage via {}",
            evidence_ref, lineage_ref
        ),
        lineage_ref,
        evidence_ref,
    })
}

fn replacement_rollback_events_from_registry(
    registry: &SlotRegistry,
    snapshot: &ReplacementProgressSnapshot,
    fallback_unix_ms: u64,
) -> Vec<RollbackEventView> {
    let mut events = Vec::new();
    for (slot_id, entry) in registry.iter() {
        for (lineage_index, lineage_event) in entry.promotion_lineage.iter().enumerate() {
            if !matches!(
                lineage_event.transition,
                PromotionTransition::DemotedToDelegate | PromotionTransition::RolledBack
            ) {
                continue;
            }
            let slot_id_str = slot_id.as_str();
            let reason = match (&entry.status, lineage_event.transition) {
                (PromotionStatus::Demoted { reason, .. }, _) => normalize_non_empty(reason.clone()),
                (_, PromotionTransition::DemotedToDelegate) => "demoted".to_string(),
                (_, PromotionTransition::RolledBack) => "rollback".to_string(),
                _ => "rollback".to_string(),
            };
            let status = if matches!(entry.status, PromotionStatus::Demoted { .. }) {
                RollbackStatus::Investigating
            } else {
                RollbackStatus::Resolved
            };
            events.push(RollbackEventView {
                slot_id: slot_id_str.to_string(),
                receipt_id: lineage_event
                    .receipt_id
                    .clone()
                    .unwrap_or_else(|| format!("lineage-{}-{}", slot_id_str, lineage_index)),
                reason,
                status,
                occurred_at_unix_ms: parse_timestamp_unix_ms(&lineage_event.timestamp)
                    .unwrap_or_else(|| {
                        fallback_unix_ms.saturating_sub(
                            entry.promotion_lineage.len().saturating_sub(lineage_index) as u64,
                        )
                    }),
                lineage_ref: replacement_lineage_ref(slot_id_str),
                evidence_ref: replacement_evidence_ref(
                    slot_id_str,
                    &snapshot.trace_id,
                    &snapshot.decision_id,
                    &snapshot.policy_id,
                ),
            });
        }
    }
    events.sort_by(|left, right| {
        left.occurred_at_unix_ms
            .cmp(&right.occurred_at_unix_ms)
            .then(left.slot_id.cmp(&right.slot_id))
            .then(left.receipt_id.cmp(&right.receipt_id))
    });
    events
}

fn parse_timestamp_unix_ms(timestamp: &str) -> Option<u64> {
    let trimmed = timestamp.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<u64>().ok()
}

fn clamp_non_negative_i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).expect("serde deserialization should succeed")
}

fn compute_expected_value_score_millionths(input: &ReplacementOpportunityInput) -> i64 {
    let perf_component = i128::from(input.performance_uplift_millionths)
        .saturating_mul(i128::from(input.invocation_frequency_per_minute).saturating_add(1))
        .saturating_div(100);
    let risk_component = i128::from(input.risk_reduction_millionths).saturating_mul(3);
    perf_component
        .saturating_add(risk_component)
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot_registry::{
        AuthorityEnvelope, ReplacementProgressEvent, SlotCapability, SlotId, SlotKind,
        SlotRegistry, SlotReplacementSignal,
    };

    #[test]
    fn replay_snapshot_marks_empty_event_set() {
        let replay = IncidentReplayView::snapshot("trace-1", "incident-alpha", vec![]);
        assert_eq!(replay.replay_status, ReplayStatus::NoEvents);
        assert_eq!(replay.trace_id, "trace-1");
    }

    #[test]
    fn policy_explanation_partial_defaults_missing_fields() {
        let partial = PolicyExplanationPartial {
            decision_id: "  ".to_string(),
            policy_id: "".to_string(),
            selected_action: "   ".to_string(),
            confidence_millionths: None,
            expected_loss_millionths: None,
            action_candidates: vec![],
            key_drivers: vec![],
        };

        let card = PolicyExplanationCardView::from_partial(partial);

        assert_eq!(card.decision_id, "unknown");
        assert_eq!(card.policy_id, "unknown");
        assert_eq!(card.selected_action, "unknown");
        assert_eq!(card.confidence_millionths, 0);
        assert_eq!(card.expected_loss_millionths, 0);
    }

    #[test]
    fn control_dashboard_partial_defaults_missing_fields() {
        let dashboard = ControlDashboardView::from_partial(ControlDashboardPartial::default());
        assert_eq!(dashboard.cluster, "unknown");
        assert_eq!(dashboard.zone, "unknown");
        assert_eq!(dashboard.runtime_mode, "unknown");
        assert_eq!(dashboard.security_epoch, 0);
    }

    #[test]
    fn control_plane_invariants_dashboard_populates_required_panels() {
        let dashboard =
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                cluster: "prod".to_string(),
                zone: "us-east-1".to_string(),
                runtime_mode: "secure".to_string(),
                generated_at_unix_ms: Some(1_700_000_000_500),
                evidence_stream: vec![
                    EvidenceStreamEntryView {
                        trace_id: "trace-a".to_string(),
                        decision_id: "decision-a".to_string(),
                        policy_id: "policy-a".to_string(),
                        action_type: "allow".to_string(),
                        decision_outcome: DecisionOutcomeKind::Allow,
                        expected_loss_millionths: 120_000,
                        extension_id: "ext-a".to_string(),
                        region_id: "region-1".to_string(),
                        severity: DashboardSeverity::Info,
                        component: "guardplane".to_string(),
                        event: "decision_evaluated".to_string(),
                        outcome: "allow".to_string(),
                        error_code: None,
                        timestamp_unix_ms: 1_700_000_000_300,
                    },
                    EvidenceStreamEntryView {
                        trace_id: "trace-b".to_string(),
                        decision_id: "decision-b".to_string(),
                        policy_id: "policy-a".to_string(),
                        action_type: "fallback".to_string(),
                        decision_outcome: DecisionOutcomeKind::Fallback,
                        expected_loss_millionths: 300_000,
                        extension_id: "ext-b".to_string(),
                        region_id: "region-2".to_string(),
                        severity: DashboardSeverity::Warning,
                        component: "guardplane".to_string(),
                        event: "safe_mode_activated".to_string(),
                        outcome: "fallback".to_string(),
                        error_code: Some("FE-SAFE-001".to_string()),
                        timestamp_unix_ms: 1_700_000_000_320,
                    },
                ],
                obligation_rows: vec![
                    ObligationStatusRowView {
                        obligation_id: "obl-1".to_string(),
                        extension_id: "ext-a".to_string(),
                        region_id: "region-1".to_string(),
                        state: ObligationState::Open,
                        severity: DashboardSeverity::Warning,
                        due_at_unix_ms: 1_700_000_001_000,
                        updated_at_unix_ms: 1_700_000_000_330,
                        detail: "awaiting replay verification".to_string(),
                    },
                    ObligationStatusRowView {
                        obligation_id: "obl-2".to_string(),
                        extension_id: "ext-b".to_string(),
                        region_id: "region-2".to_string(),
                        state: ObligationState::Failed,
                        severity: DashboardSeverity::Critical,
                        due_at_unix_ms: 1_700_000_001_100,
                        updated_at_unix_ms: 1_700_000_000_340,
                        detail: "checkpoint timeout".to_string(),
                    },
                ],
                region_rows: vec![
                    RegionLifecycleRowView {
                        region_id: "region-1".to_string(),
                        is_active: true,
                        active_extensions: 2,
                        created_at_unix_ms: 1_700_000_000_000,
                        closed_at_unix_ms: None,
                        quiescent_close_time_ms: None,
                    },
                    RegionLifecycleRowView {
                        region_id: "region-2".to_string(),
                        is_active: false,
                        active_extensions: 0,
                        created_at_unix_ms: 1_700_000_000_050,
                        closed_at_unix_ms: Some(1_700_000_000_300),
                        quiescent_close_time_ms: Some(220),
                    },
                ],
                cancellation_events: vec![CancellationEventView {
                    extension_id: "ext-b".to_string(),
                    region_id: "region-2".to_string(),
                    cancellation_kind: CancellationKind::Quarantine,
                    severity: DashboardSeverity::Critical,
                    detail: "forced quarantine".to_string(),
                    timestamp_unix_ms: 1_700_000_000_350,
                }],
                replay_health: Some(ReplayHealthPanelView {
                    last_run_status: ReplayHealthStatus::Pass,
                    divergence_count: 0,
                    last_replay_timestamp_unix_ms: Some(1_700_000_000_360),
                }),
                benchmark_points: vec![BenchmarkTrendPointView {
                    timestamp_unix_ms: 1_700_000_000_200,
                    throughput_tps: 2_100,
                    latency_p95_ms: 93,
                    memory_peak_mb: 640,
                }],
                throughput_floor_tps: Some(2_000),
                latency_p95_ceiling_ms: Some(100),
                memory_peak_ceiling_mb: Some(700),
                safe_mode_activations: vec![SafeModeActivationView {
                    activation_id: "sm-1".to_string(),
                    activation_type: "attestation_stale".to_string(),
                    extension_id: "ext-b".to_string(),
                    region_id: "region-2".to_string(),
                    severity: DashboardSeverity::Warning,
                    recovery_status: RecoveryStatus::Recovering,
                    activated_at_unix_ms: 1_700_000_000_320,
                    recovered_at_unix_ms: None,
                }],
                schema_version: Some(SchemaVersionPanelView {
                    evidence_schema_version: 4,
                    last_migration_unix_ms: Some(1_699_999_999_000),
                    compatibility_status: SchemaCompatibilityStatus::Compatible,
                }),
                refresh_policy: Some(DashboardRefreshPolicy {
                    evidence_stream_refresh_secs: 4,
                    aggregate_refresh_secs: 30,
                }),
                evidence_stream_last_updated_unix_ms: Some(1_700_000_000_498),
                aggregates_last_updated_unix_ms: Some(1_700_000_000_480),
                alert_rules: vec![DashboardAlertRule {
                    rule_id: "alert-obligation-failure".to_string(),
                    description: "obligation failure rate > 0".to_string(),
                    metric: DashboardAlertMetric::ObligationFailureRateMillionths,
                    comparator: ThresholdComparator::GreaterThan,
                    threshold: 0,
                    severity: DashboardSeverity::Critical,
                }],
                ..Default::default()
            });

        assert_eq!(dashboard.decision_outcomes.allow_count, 1);
        assert_eq!(dashboard.decision_outcomes.fallback_count, 1);
        assert_eq!(dashboard.obligation_status.open_count, 1);
        assert_eq!(dashboard.obligation_status.failed_count, 1);
        assert_eq!(dashboard.region_lifecycle.active_region_count, 1);
        assert_eq!(dashboard.cancellation_events.len(), 1);
        assert_eq!(
            dashboard.replay_health.last_run_status,
            ReplayHealthStatus::Pass
        );
        assert_eq!(dashboard.benchmark_trends.points.len(), 1);
        assert_eq!(dashboard.safe_mode_activations.len(), 1);
        assert_eq!(dashboard.schema_version.evidence_schema_version, 4);
        assert!(dashboard.meets_refresh_sla());
        assert_eq!(dashboard.triggered_alerts().len(), 1);
    }

    #[test]
    fn control_plane_invariants_filter_narrows_panels_consistently() {
        let dashboard =
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                cluster: "prod".to_string(),
                zone: "us-west-2".to_string(),
                runtime_mode: "secure".to_string(),
                generated_at_unix_ms: Some(1_700_000_000_600),
                evidence_stream: vec![
                    EvidenceStreamEntryView {
                        trace_id: "trace-1".to_string(),
                        decision_id: "decision-1".to_string(),
                        policy_id: "policy-a".to_string(),
                        action_type: "deny".to_string(),
                        decision_outcome: DecisionOutcomeKind::Deny,
                        expected_loss_millionths: 500_000,
                        extension_id: "ext-a".to_string(),
                        region_id: "region-a".to_string(),
                        severity: DashboardSeverity::Critical,
                        component: "guardplane".to_string(),
                        event: "blocked".to_string(),
                        outcome: "deny".to_string(),
                        error_code: Some("FE-POL-001".to_string()),
                        timestamp_unix_ms: 1_700_000_000_550,
                    },
                    EvidenceStreamEntryView {
                        trace_id: "trace-2".to_string(),
                        decision_id: "decision-2".to_string(),
                        policy_id: "policy-a".to_string(),
                        action_type: "allow".to_string(),
                        decision_outcome: DecisionOutcomeKind::Allow,
                        expected_loss_millionths: 100_000,
                        extension_id: "ext-b".to_string(),
                        region_id: "region-b".to_string(),
                        severity: DashboardSeverity::Info,
                        component: "guardplane".to_string(),
                        event: "allowed".to_string(),
                        outcome: "allow".to_string(),
                        error_code: None,
                        timestamp_unix_ms: 1_700_000_000_560,
                    },
                ],
                obligation_rows: vec![
                    ObligationStatusRowView {
                        obligation_id: "obl-1".to_string(),
                        extension_id: "ext-a".to_string(),
                        region_id: "region-a".to_string(),
                        state: ObligationState::Failed,
                        severity: DashboardSeverity::Critical,
                        due_at_unix_ms: 1_700_000_000_800,
                        updated_at_unix_ms: 1_700_000_000_555,
                        detail: "failed".to_string(),
                    },
                    ObligationStatusRowView {
                        obligation_id: "obl-2".to_string(),
                        extension_id: "ext-b".to_string(),
                        region_id: "region-b".to_string(),
                        state: ObligationState::Fulfilled,
                        severity: DashboardSeverity::Info,
                        due_at_unix_ms: 1_700_000_000_900,
                        updated_at_unix_ms: 1_700_000_000_565,
                        detail: "ok".to_string(),
                    },
                ],
                region_rows: vec![
                    RegionLifecycleRowView {
                        region_id: "region-a".to_string(),
                        is_active: true,
                        active_extensions: 1,
                        created_at_unix_ms: 1_700_000_000_100,
                        closed_at_unix_ms: None,
                        quiescent_close_time_ms: None,
                    },
                    RegionLifecycleRowView {
                        region_id: "region-b".to_string(),
                        is_active: true,
                        active_extensions: 1,
                        created_at_unix_ms: 1_700_000_000_200,
                        closed_at_unix_ms: None,
                        quiescent_close_time_ms: None,
                    },
                ],
                cancellation_events: vec![
                    CancellationEventView {
                        extension_id: "ext-a".to_string(),
                        region_id: "region-a".to_string(),
                        cancellation_kind: CancellationKind::Quarantine,
                        severity: DashboardSeverity::Critical,
                        detail: "quarantine".to_string(),
                        timestamp_unix_ms: 1_700_000_000_556,
                    },
                    CancellationEventView {
                        extension_id: "ext-b".to_string(),
                        region_id: "region-b".to_string(),
                        cancellation_kind: CancellationKind::Unload,
                        severity: DashboardSeverity::Info,
                        detail: "normal unload".to_string(),
                        timestamp_unix_ms: 1_700_000_000_566,
                    },
                ],
                ..Default::default()
            });

        let filtered = dashboard.filtered(&ControlPlaneDashboardFilter {
            extension_id: Some("ext-a".to_string()),
            region_id: Some("region-a".to_string()),
            severity: Some(DashboardSeverity::Critical),
            start_unix_ms: Some(1_700_000_000_540),
            end_unix_ms: Some(1_700_000_000_560),
        });

        assert_eq!(filtered.evidence_stream.len(), 1);
        assert_eq!(filtered.obligation_rows.len(), 1);
        assert_eq!(filtered.cancellation_events.len(), 1);
        assert_eq!(filtered.decision_outcomes.deny_count, 1);
        assert_eq!(filtered.obligation_status.failed_count, 1);
        assert_eq!(filtered.region_rows.len(), 1);
    }

    #[test]
    fn control_plane_invariants_dashboard_handles_missing_sources_without_panicking() {
        let dashboard =
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                generated_at_unix_ms: Some(1_700_000_001_200),
                ..Default::default()
            });

        assert_eq!(dashboard.cluster, "unknown");
        assert_eq!(dashboard.zone, "unknown");
        assert_eq!(dashboard.runtime_mode, "unknown");
        assert!(dashboard.evidence_stream.is_empty());
        assert!(dashboard.obligation_rows.is_empty());
        assert!(dashboard.region_rows.is_empty());
        assert!(dashboard.cancellation_events.is_empty());
        assert!(dashboard.safe_mode_activations.is_empty());
        assert_eq!(
            dashboard.decision_outcomes,
            DecisionOutcomesPanelView::default()
        );
        assert_eq!(
            dashboard.obligation_status,
            ObligationStatusPanelView::default()
        );
        assert_eq!(
            dashboard.region_lifecycle,
            RegionLifecyclePanelView::default()
        );
        assert_eq!(
            dashboard.replay_health.last_run_status,
            ReplayHealthStatus::Unknown
        );
        assert_eq!(
            dashboard.schema_version.compatibility_status,
            SchemaCompatibilityStatus::Unknown
        );
        assert!(dashboard.triggered_alerts().is_empty());
        assert!(dashboard.meets_refresh_sla());
    }

    #[test]
    fn control_plane_invariants_dashboard_detects_refresh_sla_breach() {
        let dashboard =
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                cluster: "prod".to_string(),
                zone: "us-east-1".to_string(),
                runtime_mode: "secure".to_string(),
                generated_at_unix_ms: Some(1_700_000_100_000),
                refresh_policy: Some(DashboardRefreshPolicy {
                    evidence_stream_refresh_secs: 5,
                    aggregate_refresh_secs: 60,
                }),
                evidence_stream_last_updated_unix_ms: Some(1_700_000_093_000),
                aggregates_last_updated_unix_ms: Some(1_700_000_030_000),
                ..Default::default()
            });

        assert!(!dashboard.meets_refresh_sla());
    }

    #[test]
    fn control_plane_invariants_obligation_failure_alert_avoids_false_positives() {
        let alert_rule = DashboardAlertRule {
            rule_id: "alert-obligation-failure".to_string(),
            description: "obligation failure rate > 0".to_string(),
            metric: DashboardAlertMetric::ObligationFailureRateMillionths,
            comparator: ThresholdComparator::GreaterThan,
            threshold: 0,
            severity: DashboardSeverity::Critical,
        };

        let dashboard_without_failures =
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                cluster: "prod".to_string(),
                zone: "us-east-1".to_string(),
                runtime_mode: "secure".to_string(),
                generated_at_unix_ms: Some(1_700_000_120_000),
                obligation_rows: vec![
                    ObligationStatusRowView {
                        obligation_id: "obl-open".to_string(),
                        extension_id: "ext-a".to_string(),
                        region_id: "region-a".to_string(),
                        state: ObligationState::Open,
                        severity: DashboardSeverity::Info,
                        due_at_unix_ms: 1_700_000_121_000,
                        updated_at_unix_ms: 1_700_000_120_100,
                        detail: "pending".to_string(),
                    },
                    ObligationStatusRowView {
                        obligation_id: "obl-done".to_string(),
                        extension_id: "ext-a".to_string(),
                        region_id: "region-a".to_string(),
                        state: ObligationState::Fulfilled,
                        severity: DashboardSeverity::Info,
                        due_at_unix_ms: 1_700_000_121_100,
                        updated_at_unix_ms: 1_700_000_120_200,
                        detail: "completed".to_string(),
                    },
                ],
                alert_rules: vec![alert_rule.clone()],
                ..Default::default()
            });

        assert!(
            dashboard_without_failures.triggered_alerts().is_empty(),
            "zero-failure obligation sets must not trigger the failure-rate alert"
        );

        let dashboard_with_failure =
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                cluster: "prod".to_string(),
                zone: "us-east-1".to_string(),
                runtime_mode: "secure".to_string(),
                generated_at_unix_ms: Some(1_700_000_120_000),
                obligation_rows: vec![
                    ObligationStatusRowView {
                        obligation_id: "obl-open".to_string(),
                        extension_id: "ext-a".to_string(),
                        region_id: "region-a".to_string(),
                        state: ObligationState::Open,
                        severity: DashboardSeverity::Info,
                        due_at_unix_ms: 1_700_000_121_000,
                        updated_at_unix_ms: 1_700_000_120_100,
                        detail: "pending".to_string(),
                    },
                    ObligationStatusRowView {
                        obligation_id: "obl-done".to_string(),
                        extension_id: "ext-a".to_string(),
                        region_id: "region-a".to_string(),
                        state: ObligationState::Fulfilled,
                        severity: DashboardSeverity::Info,
                        due_at_unix_ms: 1_700_000_121_100,
                        updated_at_unix_ms: 1_700_000_120_200,
                        detail: "completed".to_string(),
                    },
                    ObligationStatusRowView {
                        obligation_id: "obl-fail".to_string(),
                        extension_id: "ext-a".to_string(),
                        region_id: "region-a".to_string(),
                        state: ObligationState::Failed,
                        severity: DashboardSeverity::Critical,
                        due_at_unix_ms: 1_700_000_121_200,
                        updated_at_unix_ms: 1_700_000_120_300,
                        detail: "timeout".to_string(),
                    },
                ],
                alert_rules: vec![alert_rule],
                ..Default::default()
            });

        let alerts = dashboard_with_failure.triggered_alerts();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, "alert-obligation-failure");
        assert_eq!(
            alerts[0].metric,
            DashboardAlertMetric::ObligationFailureRateMillionths
        );
        assert_eq!(alerts[0].observed_value, 333_333);
    }

    #[test]
    fn flow_decision_dashboard_builds_alerts_and_filters_views() {
        let dashboard = FlowDecisionDashboardView::from_partial(FlowDecisionPartial {
            cluster: "prod".to_string(),
            zone: "us-east-2".to_string(),
            security_epoch: Some(19),
            generated_at_unix_ms: Some(1_700_000_001_000),
            label_map: LabelMapView {
                nodes: vec![
                    LabelMapNodeView {
                        label_id: "pii".to_string(),
                        sensitivity: FlowSensitivityLevel::High,
                        description: "user pii".to_string(),
                        extension_overlays: vec!["ext-a".to_string()],
                    },
                    LabelMapNodeView {
                        label_id: "public".to_string(),
                        sensitivity: FlowSensitivityLevel::Low,
                        description: "public data".to_string(),
                        extension_overlays: vec!["ext-a".to_string(), "ext-b".to_string()],
                    },
                ],
                edges: vec![LabelMapEdgeView {
                    source_label: "pii".to_string(),
                    sink_clearance: "high".to_string(),
                    route_policy_id: Some("policy-flow-1".to_string()),
                    route_enabled: true,
                }],
            },
            blocked_flows: vec![
                BlockedFlowView {
                    flow_id: "flow-1".to_string(),
                    extension_id: "ext-a".to_string(),
                    source_label: "pii".to_string(),
                    sink_clearance: "external".to_string(),
                    sensitivity: FlowSensitivityLevel::Critical,
                    blocked_reason: "sink clearance mismatch".to_string(),
                    attempted_exfiltration: true,
                    code_path_ref: "src/ext_a/main.ts:42".to_string(),
                    extension_context_ref: "frankentui://extension/ext-a".to_string(),
                    trace_id: "trace-flow-1".to_string(),
                    decision_id: "decision-flow-1".to_string(),
                    policy_id: "policy-flow-1".to_string(),
                    error_code: Some("FE-IFC-BLOCK".to_string()),
                    occurred_at_unix_ms: 1_700_000_000_900,
                },
                BlockedFlowView {
                    flow_id: "flow-2".to_string(),
                    extension_id: "ext-a".to_string(),
                    source_label: "pii".to_string(),
                    sink_clearance: "external".to_string(),
                    sensitivity: FlowSensitivityLevel::Critical,
                    blocked_reason: "sink clearance mismatch".to_string(),
                    attempted_exfiltration: true,
                    code_path_ref: "src/ext_a/main.ts:55".to_string(),
                    extension_context_ref: "frankentui://extension/ext-a".to_string(),
                    trace_id: "trace-flow-2".to_string(),
                    decision_id: "decision-flow-2".to_string(),
                    policy_id: "policy-flow-1".to_string(),
                    error_code: Some("FE-IFC-BLOCK".to_string()),
                    occurred_at_unix_ms: 1_700_000_000_910,
                },
            ],
            declassification_history: vec![DeclassificationDecisionView {
                decision_id: "decl-1".to_string(),
                extension_id: "ext-a".to_string(),
                source_label: "pii".to_string(),
                sink_clearance: "external".to_string(),
                sensitivity: FlowSensitivityLevel::Critical,
                outcome: DeclassificationOutcome::Denied,
                policy_id: "policy-flow-1".to_string(),
                loss_assessment_summary: "expected loss too high".to_string(),
                rationale: "deny exfiltration route".to_string(),
                receipt_ref: "frankentui://declassification/decl-1".to_string(),
                replay_ref: "frankentui://replay/decl-1".to_string(),
                decided_at_unix_ms: 1_700_000_000_920,
            }],
            confinement_proofs: vec![ConfinementProofView {
                extension_id: "ext-a".to_string(),
                status: ConfinementStatus::Degraded,
                covered_flow_count: 10,
                uncovered_flow_count: 2,
                proof_rows: vec![FlowProofCoverageView {
                    proof_id: "proof-1".to_string(),
                    source_label: "pii".to_string(),
                    sink_clearance: "external".to_string(),
                    covered: false,
                    proof_ref: "frankentui://proof/proof-1".to_string(),
                }],
                uncovered_flow_refs: vec!["frankentui://flow/flow-1".to_string()],
            }],
            blocked_flow_alert_threshold: Some(2),
            ..Default::default()
        });

        assert_eq!(dashboard.alert_indicators.len(), 2);
        assert_eq!(dashboard.blocked_flows.len(), 2);
        assert_eq!(dashboard.declassification_history.len(), 1);
        assert_eq!(dashboard.confinement_proofs.len(), 1);

        let filtered = dashboard.filtered(&FlowDecisionDashboardFilter {
            extension_id: Some("ext-a".to_string()),
            source_label: Some("pii".to_string()),
            sink_clearance: Some("external".to_string()),
            sensitivity: Some(FlowSensitivityLevel::Critical),
            start_unix_ms: Some(1_700_000_000_905),
            end_unix_ms: Some(1_700_000_001_000),
        });

        assert_eq!(filtered.blocked_flows.len(), 1);
        assert_eq!(filtered.declassification_history.len(), 1);
        assert_eq!(filtered.confinement_proofs.len(), 1);
        assert_eq!(filtered.alert_indicators.len(), 2);
        assert_eq!(filtered.label_map.nodes.len(), 1);
    }

    #[test]
    fn proof_specialization_lineage_dashboard_builds_aggregates_and_filters() {
        let dashboard = ProofSpecializationLineageDashboardView::from_partial(
            ProofSpecializationLineagePartial {
                cluster: "prod".to_string(),
                zone: "us-east-1".to_string(),
                security_epoch: Some(31),
                generated_at_unix_ms: Some(1_700_000_002_000),
                proof_inventory: vec![
                    ProofInventoryRowView {
                        proof_id: " proof-cap-1 ".to_string(),
                        proof_kind: ProofInventoryKind::CapabilityWitness,
                        validity_status: ProofValidityStatus::Valid,
                        epoch_id: 31,
                        linked_specialization_count: 2,
                        enabled_specialization_ids: vec![
                            " spec-b ".to_string(),
                            "spec-a".to_string(),
                        ],
                        proof_ref: " frankentui://proof/proof-cap-1 ".to_string(),
                    },
                    ProofInventoryRowView {
                        proof_id: "proof-flow-2".to_string(),
                        proof_kind: ProofInventoryKind::FlowProof,
                        validity_status: ProofValidityStatus::ExpiringSoon,
                        epoch_id: 31,
                        linked_specialization_count: 2,
                        enabled_specialization_ids: vec![
                            "spec-c".to_string(),
                            "spec-b".to_string(),
                        ],
                        proof_ref: "frankentui://proof/proof-flow-2".to_string(),
                    },
                ],
                active_specializations: vec![
                    ActiveSpecializationRowView {
                        specialization_id: "spec-b".to_string(),
                        target_id: "ext-b".to_string(),
                        target_kind: "extension".to_string(),
                        optimization_class: "hostcall_dispatch_specialization".to_string(),
                        latency_reduction_millionths: 120_000,
                        throughput_increase_millionths: 200_000,
                        proof_input_ids: vec![
                            "proof-cap-1".to_string(),
                            "proof-flow-2".to_string(),
                        ],
                        transformation_ref: "frankentui://transform/spec-b".to_string(),
                        receipt_ref: "frankentui://receipt/spec-b".to_string(),
                        activated_at_unix_ms: 1_700_000_001_950,
                    },
                    ActiveSpecializationRowView {
                        specialization_id: "spec-a".to_string(),
                        target_id: "ext-a".to_string(),
                        target_kind: "extension".to_string(),
                        optimization_class: "ifc_check_elision".to_string(),
                        latency_reduction_millionths: 350_000,
                        throughput_increase_millionths: 480_000,
                        proof_input_ids: vec!["proof-cap-1".to_string()],
                        transformation_ref: "frankentui://transform/spec-a".to_string(),
                        receipt_ref: "frankentui://receipt/spec-a".to_string(),
                        activated_at_unix_ms: 1_700_000_001_940,
                    },
                ],
                invalidation_feed: vec![
                    SpecializationInvalidationRowView {
                        invalidation_id: "inv-1".to_string(),
                        specialization_id: "spec-a".to_string(),
                        target_id: "ext-a".to_string(),
                        reason: ProofSpecializationInvalidationReason::EpochChange,
                        reason_detail: "epoch advanced".to_string(),
                        proof_id: Some("proof-cap-1".to_string()),
                        old_epoch_id: Some(30),
                        new_epoch_id: Some(31),
                        fallback_confirmed: true,
                        fallback_confirmation_ref: "frankentui://fallback/spec-a".to_string(),
                        occurred_at_unix_ms: 1_700_000_001_960,
                    },
                    SpecializationInvalidationRowView {
                        invalidation_id: "inv-2".to_string(),
                        specialization_id: "spec-b".to_string(),
                        target_id: "ext-b".to_string(),
                        reason: ProofSpecializationInvalidationReason::ProofRevoked,
                        reason_detail: "revocation head advanced".to_string(),
                        proof_id: Some("proof-flow-2".to_string()),
                        old_epoch_id: None,
                        new_epoch_id: None,
                        fallback_confirmed: true,
                        fallback_confirmation_ref: "frankentui://fallback/spec-b".to_string(),
                        occurred_at_unix_ms: 1_700_000_001_970,
                    },
                ],
                fallback_events: vec![SpecializationFallbackEventView {
                    event_id: "fb-1".to_string(),
                    specialization_id: Some("spec-a".to_string()),
                    target_id: "ext-a".to_string(),
                    reason: SpecializationFallbackReason::ValidationFailed,
                    reason_detail: "equivalence proof failed".to_string(),
                    unspecialized_path_ref: "frankentui://path/ext-a/unspecialized".to_string(),
                    compilation_ref: "frankentui://compile/ext-a/42".to_string(),
                    occurred_at_unix_ms: 1_700_000_001_980,
                }],
                bulk_invalidation_alert_threshold: Some(2),
                degraded_coverage_alert_threshold_millionths: Some(900_000),
                ..Default::default()
            },
        );

        assert_eq!(dashboard.performance_impact.active_specialization_count, 2);
        assert_eq!(
            dashboard
                .performance_impact
                .aggregate_latency_reduction_millionths,
            470_000
        );
        assert_eq!(
            dashboard
                .performance_impact
                .aggregate_throughput_increase_millionths,
            680_000
        );
        assert_eq!(
            dashboard
                .performance_impact
                .specialization_coverage_millionths,
            500_000
        );
        assert_eq!(dashboard.alert_indicators.len(), 2);
        assert_eq!(dashboard.proof_inventory[0].proof_id, "proof-cap-1");
        assert_eq!(
            dashboard.proof_inventory[0].enabled_specialization_ids,
            vec!["spec-a".to_string(), "spec-b".to_string()]
        );

        let filtered = dashboard.filtered(&ProofSpecializationDashboardFilter {
            target_id: Some("ext-a".to_string()),
            proof_id: Some("proof-cap-1".to_string()),
            optimization_class: Some("ifc_check_elision".to_string()),
            start_unix_ms: Some(1_700_000_001_930),
            end_unix_ms: Some(1_700_000_002_000),
        });

        assert_eq!(filtered.active_specializations.len(), 1);
        assert_eq!(
            filtered.active_specializations[0].specialization_id,
            "spec-a"
        );
        assert_eq!(filtered.invalidation_feed.len(), 1);
        assert_eq!(filtered.fallback_events.len(), 1);
        assert_eq!(filtered.proof_inventory.len(), 1);
        assert_eq!(filtered.performance_impact.active_specialization_count, 1);
    }

    #[test]
    fn capability_delta_dashboard_builds_alerts_and_filters() {
        let dashboard = CapabilityDeltaDashboardView::from_partial(CapabilityDeltaPartial {
            cluster: "prod".to_string(),
            zone: "us-east-1".to_string(),
            security_epoch: Some(44),
            generated_at_unix_ms: Some(1_700_000_005_000),
            current_capability_rows: vec![
                CurrentCapabilityDeltaRowView {
                    extension_id: " ext-a ".to_string(),
                    witness_id: " witness-a ".to_string(),
                    policy_id: " policy-a ".to_string(),
                    witness_epoch: 44,
                    lifecycle_state: " active ".to_string(),
                    active_witness_capabilities: vec![
                        "fs.read".to_string(),
                        "network.fetch".to_string(),
                    ],
                    manifest_declared_capabilities: vec!["fs.read".to_string()],
                    over_privileged_capabilities: vec!["network.fetch".to_string()],
                    over_privilege_ratio_millionths: 0,
                    over_privilege_replay_ref: " frankentui://replay/witness/witness-a "
                        .to_string(),
                    latest_receipt_timestamp_ns: Some(1_700_000_005_500_000_000),
                },
                CurrentCapabilityDeltaRowView {
                    extension_id: "ext-b".to_string(),
                    witness_id: "witness-b".to_string(),
                    policy_id: "policy-b".to_string(),
                    witness_epoch: 44,
                    lifecycle_state: "active".to_string(),
                    active_witness_capabilities: vec!["fs.read".to_string()],
                    manifest_declared_capabilities: vec!["fs.read".to_string()],
                    over_privileged_capabilities: vec![],
                    over_privilege_ratio_millionths: 0,
                    over_privilege_replay_ref: "frankentui://replay/witness/witness-b".to_string(),
                    latest_receipt_timestamp_ns: Some(1_700_000_005_100_000_000),
                },
            ],
            proposed_minimal_rows: vec![ProposedMinimalCapabilityDeltaRowView {
                extension_id: "ext-a".to_string(),
                witness_id: "witness-a".to_string(),
                current_capabilities: vec![
                    "fs.read".to_string(),
                    "network.fetch".to_string(),
                    "network.fetch".to_string(),
                ],
                proposed_minimal_capabilities: vec!["fs.read".to_string()],
                removed_capabilities: vec!["network.fetch".to_string()],
                capability_justifications: vec![CapabilityJustificationDrillView {
                    capability: "fs.read".to_string(),
                    justification: "static path requires file read".to_string(),
                    static_analysis_ref: Some("frankentui://proof/static/fs-read".to_string()),
                    ablation_result_ref: None,
                    theorem_check_ref: Some("frankentui://proof/theorem/fs-read".to_string()),
                    operator_attestation_ref: None,
                    inherited_ref: None,
                    playback_ref: "frankentui://proof/theorem/fs-read".to_string(),
                }],
            }],
            escrow_event_feed: vec![
                CapabilityDeltaEscrowEventView {
                    receipt_id: "receipt-1".to_string(),
                    extension_id: "ext-a".to_string(),
                    capability: Some("network.fetch".to_string()),
                    decision_kind: "challenge".to_string(),
                    outcome: "pending".to_string(),
                    trace_id: "trace-1".to_string(),
                    decision_id: "decision-1".to_string(),
                    policy_id: "policy-a".to_string(),
                    error_code: None,
                    timestamp_ns: 1_700_000_005_200_000_000,
                    receipt_ref: "frankentui://escrow-receipt/receipt-1".to_string(),
                    replay_ref: "frankentui://replay/escrow/receipt-1".to_string(),
                },
                CapabilityDeltaEscrowEventView {
                    receipt_id: "receipt-2".to_string(),
                    extension_id: "ext-a".to_string(),
                    capability: Some("network.fetch".to_string()),
                    decision_kind: "emergency_grant".to_string(),
                    outcome: "approved".to_string(),
                    trace_id: "trace-2".to_string(),
                    decision_id: "decision-2".to_string(),
                    policy_id: "policy-a".to_string(),
                    error_code: None,
                    timestamp_ns: 1_700_000_005_300_000_000,
                    receipt_ref: "frankentui://escrow-receipt/receipt-2".to_string(),
                    replay_ref: "frankentui://replay/escrow/receipt-2".to_string(),
                },
            ],
            override_rationale_rows: vec![OverrideRationaleView {
                override_id: "override-1".to_string(),
                extension_id: "ext-a".to_string(),
                capability: Some("network.fetch".to_string()),
                rationale: "break-glass override".to_string(),
                signed_justification_ref: "frankentui://signed-override/override-1".to_string(),
                review_status: OverrideReviewStatus::Pending,
                grant_expiry_status: GrantExpiryStatus::ExpiringSoon,
                requested_at_unix_ms: 1_700_000_004_900,
                reviewed_at_unix_ms: None,
                expires_at_unix_ms: Some(1_700_000_005_100),
                receipt_ref: "frankentui://escrow-receipt/receipt-2".to_string(),
                replay_ref: "frankentui://replay/escrow/receipt-2".to_string(),
            }],
            high_escrow_alert_threshold: Some(2),
            pending_override_alert_threshold: Some(1),
            ..Default::default()
        });

        assert_eq!(dashboard.current_capability_rows.len(), 2);
        assert_eq!(dashboard.current_capability_rows[0].extension_id, "ext-a");
        assert_eq!(
            dashboard.current_capability_rows[0].over_privilege_ratio_millionths,
            500_000
        );
        assert_eq!(dashboard.escrow_event_feed.len(), 2);
        assert!(!dashboard.alert_indicators.is_empty());
        assert_eq!(dashboard.proposed_minimal_rows.len(), 1);

        let filtered = dashboard.filtered(&CapabilityDeltaDashboardFilter {
            extension_id: Some("ext-a".to_string()),
            capability: Some("network.fetch".to_string()),
            outcome: Some("approved".to_string()),
            min_over_privilege_ratio_millionths: Some(100_000),
            grant_expiry_status: Some(GrantExpiryStatus::ExpiringSoon),
            start_timestamp_ns: Some(1_700_000_004_800_000_000),
            end_timestamp_ns: Some(1_700_000_005_600_000_000),
        });

        assert_eq!(filtered.current_capability_rows.len(), 1);
        assert_eq!(filtered.escrow_event_feed.len(), 1);
        assert_eq!(filtered.override_rationale_rows.len(), 1);
        assert_eq!(filtered.proposed_minimal_rows.len(), 1);
    }

    #[test]
    fn capability_delta_dashboard_from_replay_join_partial_maps_witness_and_receipts() {
        let extension_id = crate::engine_object_id::EngineObjectId([0x11; 32]);
        let witness_id = crate::engine_object_id::EngineObjectId([0x22; 32]);
        let policy_id = crate::engine_object_id::EngineObjectId([0x33; 32]);
        let witness = crate::capability_witness::CapabilityWitness {
            witness_id: witness_id.clone(),
            schema_version: crate::capability_witness::WitnessSchemaVersion::CURRENT,
            extension_id: extension_id.clone(),
            policy_id: policy_id.clone(),
            lifecycle_state: crate::capability_witness::LifecycleState::Active,
            required_capabilities: std::collections::BTreeSet::from([
                crate::policy_theorem_compiler::Capability::new("fs.read"),
                crate::policy_theorem_compiler::Capability::new("network.fetch"),
            ]),
            denied_capabilities: std::collections::BTreeSet::new(),
            proof_obligations: vec![
                crate::capability_witness::ProofObligation {
                    capability: crate::policy_theorem_compiler::Capability::new("fs.read"),
                    kind: crate::capability_witness::ProofKind::StaticAnalysis,
                    proof_artifact_id: crate::engine_object_id::EngineObjectId([0x41; 32]),
                    justification: "file read path required".to_string(),
                    artifact_hash: crate::hash_tiers::ContentHash::compute(b"proof-static"),
                },
                crate::capability_witness::ProofObligation {
                    capability: crate::policy_theorem_compiler::Capability::new("network.fetch"),
                    kind: crate::capability_witness::ProofKind::PolicyTheoremCheck,
                    proof_artifact_id: crate::engine_object_id::EngineObjectId([0x42; 32]),
                    justification: "remote attest fetch route".to_string(),
                    artifact_hash: crate::hash_tiers::ContentHash::compute(b"proof-theorem"),
                },
            ],
            denial_records: vec![],
            confidence: crate::capability_witness::ConfidenceInterval {
                lower_millionths: 800_000,
                upper_millionths: 950_000,
                n_trials: 20,
                n_successes: 18,
            },
            replay_seed: 42,
            transcript_hash: crate::hash_tiers::ContentHash::compute(b"witness-transcript"),
            rollback_token: None,
            synthesizer_signature: vec![0xAA; 64],
            promotion_signatures: vec![vec![0xBB; 64]],
            epoch: crate::security_epoch::SecurityEpoch::from_raw(44),
            timestamp_ns: 1_700_000_005_000_000_000,
            content_hash: crate::hash_tiers::ContentHash::compute(b"witness-content"),
            metadata: BTreeMap::new(),
        };

        let replay_row = WitnessReplayJoinRow {
            witness: crate::capability_witness::WitnessIndexRecord {
                witness_id,
                extension_id: extension_id.clone(),
                policy_id,
                epoch: crate::security_epoch::SecurityEpoch::from_raw(44),
                lifecycle_state: crate::capability_witness::LifecycleState::Active,
                promotion_timestamp_ns: 1_700_000_004_900_000_000,
                content_hash: crate::hash_tiers::ContentHash::compute(b"index-content"),
                witness,
            },
            receipts: vec![
                CapabilityEscrowReceiptRecord {
                    receipt_id: "escrow-1".to_string(),
                    extension_id: extension_id.clone(),
                    capability: Some(crate::policy_theorem_compiler::Capability::new(
                        "network.fetch",
                    )),
                    decision_kind: "challenge".to_string(),
                    outcome: "pending".to_string(),
                    timestamp_ns: 1_700_000_005_100_000_000,
                    trace_id: "trace-escrow-1".to_string(),
                    decision_id: "decision-escrow-1".to_string(),
                    policy_id: "policy-escrow".to_string(),
                    error_code: None,
                },
                CapabilityEscrowReceiptRecord {
                    receipt_id: "escrow-2".to_string(),
                    extension_id,
                    capability: Some(crate::policy_theorem_compiler::Capability::new(
                        "network.fetch",
                    )),
                    decision_kind: "operator_override".to_string(),
                    outcome: "approved".to_string(),
                    timestamp_ns: 1_700_000_005_200_000_000,
                    trace_id: "trace-escrow-2".to_string(),
                    decision_id: "decision-escrow-2".to_string(),
                    policy_id: "policy-escrow".to_string(),
                    error_code: None,
                },
            ],
        };

        let dashboard = CapabilityDeltaDashboardView::from_replay_join_partial(
            CapabilityDeltaReplayJoinPartial {
                cluster: "prod".to_string(),
                zone: "us-east-1".to_string(),
                security_epoch: Some(44),
                generated_at_unix_ms: Some(1_700_000_005_300),
                replay_rows: vec![replay_row],
                manifest_declared_capabilities: BTreeMap::from([(
                    "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
                    vec!["fs.read".to_string()],
                )]),
                high_escrow_alert_threshold: Some(2),
                pending_override_alert_threshold: Some(1),
                ..Default::default()
            },
        );

        assert_eq!(dashboard.current_capability_rows.len(), 1);
        assert_eq!(
            dashboard.current_capability_rows[0].over_privileged_capabilities,
            vec!["network.fetch".to_string()]
        );
        assert_eq!(dashboard.proposed_minimal_rows.len(), 1);
        assert_eq!(dashboard.escrow_event_feed.len(), 2);
        assert_eq!(dashboard.override_rationale_rows.len(), 1);
        assert_eq!(dashboard.override_rationale_rows[0].override_id, "escrow-2");
        assert!(
            dashboard.proposed_minimal_rows[0]
                .capability_justifications
                .iter()
                .any(|row| row.capability == "network.fetch"
                    && row.theorem_check_ref.as_deref().is_some())
        );
    }

    #[test]
    fn envelope_json_round_trip_is_stable() {
        let payload = FrankentuiViewPayload::ControlDashboard(ControlDashboardView {
            cluster: "prod".to_string(),
            zone: "us-east-1".to_string(),
            security_epoch: 7,
            runtime_mode: "secure".to_string(),
            metrics: vec![DashboardMetricView {
                metric: "containment_latency_p95_ms".to_string(),
                value: 42,
                unit: "ms".to_string(),
            }],
            extension_rows: vec![ExtensionStatusRow {
                extension_id: "weather-ext".to_string(),
                state: "running".to_string(),
                trust_level: "trusted".to_string(),
            }],
            incident_counts: BTreeMap::new(),
        });

        let envelope = AdapterEnvelope::new(
            "trace-abc",
            1_700_000_000_000,
            AdapterStream::ControlDashboard,
            UpdateKind::Snapshot,
            payload,
        )
        .with_decision_context("decision-1", "policy-1");

        let encoded = envelope.encode_json().expect("encoding should succeed");
        let decoded: AdapterEnvelope =
            serde_json::from_slice(&encoded).expect("decoding should succeed");

        assert_eq!(decoded, envelope);
    }

    #[test]
    fn replacement_progress_partial_ranks_opportunities_and_builds_coverage() {
        let view = ReplacementProgressDashboardView::from_partial(ReplacementProgressPartial {
            cluster: "prod".to_string(),
            zone: "us-east-1".to_string(),
            security_epoch: Some(14),
            generated_at_unix_ms: Some(1_700_000_000_300),
            slot_status_overview: vec![
                SlotStatusOverviewRow {
                    slot_id: "parser".to_string(),
                    slot_kind: "parser".to_string(),
                    implementation_kind: "delegate".to_string(),
                    promotion_status: "promotion_candidate".to_string(),
                    risk_level: ReplacementRiskLevel::Medium,
                    last_transition_unix_ms: 1_700_000_000_100,
                    health: "attention".to_string(),
                    lineage_ref: "frankentui://replacement-lineage/parser".to_string(),
                },
                SlotStatusOverviewRow {
                    slot_id: "module-loader".to_string(),
                    slot_kind: "module_loader".to_string(),
                    implementation_kind: "native".to_string(),
                    promotion_status: "promoted".to_string(),
                    risk_level: ReplacementRiskLevel::Low,
                    last_transition_unix_ms: 1_700_000_000_080,
                    health: "healthy".to_string(),
                    lineage_ref: "frankentui://replacement-lineage/module-loader".to_string(),
                },
            ],
            replacement_inputs: vec![
                ReplacementOpportunityInput {
                    slot_id: "parser".to_string(),
                    slot_kind: "parser".to_string(),
                    performance_uplift_millionths: 420_000,
                    invocation_frequency_per_minute: 190,
                    risk_reduction_millionths: 300_000,
                },
                ReplacementOpportunityInput {
                    slot_id: "async-runtime".to_string(),
                    slot_kind: "async_runtime".to_string(),
                    performance_uplift_millionths: 900_000,
                    invocation_frequency_per_minute: 10,
                    risk_reduction_millionths: 120_000,
                },
            ],
            ..Default::default()
        });

        assert_eq!(view.native_coverage.native_slots, 1);
        assert_eq!(view.native_coverage.delegate_slots, 1);
        assert_eq!(view.native_coverage.native_coverage_millionths, 500_000);
        assert_eq!(view.next_best_replacements.len(), 2);
        assert_eq!(view.next_best_replacements[0].slot_id, "parser");
        assert_eq!(view.next_best_replacements[1].slot_id, "async-runtime");
    }

    #[test]
    fn replacement_progress_filter_keeps_associated_panels_in_sync() {
        let view = ReplacementProgressDashboardView::from_partial(ReplacementProgressPartial {
            cluster: "prod".to_string(),
            zone: "us-west-2".to_string(),
            slot_status_overview: vec![
                SlotStatusOverviewRow {
                    slot_id: "parser".to_string(),
                    slot_kind: "parser".to_string(),
                    implementation_kind: "delegate".to_string(),
                    promotion_status: "promotion_candidate".to_string(),
                    risk_level: ReplacementRiskLevel::High,
                    last_transition_unix_ms: 10,
                    health: "blocked".to_string(),
                    lineage_ref: "frankentui://replacement-lineage/parser".to_string(),
                },
                SlotStatusOverviewRow {
                    slot_id: "gc".to_string(),
                    slot_kind: "garbage_collector".to_string(),
                    implementation_kind: "native".to_string(),
                    promotion_status: "promoted".to_string(),
                    risk_level: ReplacementRiskLevel::Low,
                    last_transition_unix_ms: 11,
                    health: "healthy".to_string(),
                    lineage_ref: "frankentui://replacement-lineage/gc".to_string(),
                },
            ],
            blocked_promotions: vec![
                BlockedPromotionView {
                    slot_id: "parser".to_string(),
                    gate_failure_code: "FE-GATE-001".to_string(),
                    failure_detail: "differential mismatch".to_string(),
                    recommended_remediation: "rerun divergence minimizer".to_string(),
                    lineage_ref: "frankentui://replacement-lineage/parser".to_string(),
                    evidence_ref: "frankentui://evidence/parser".to_string(),
                },
                BlockedPromotionView {
                    slot_id: "gc".to_string(),
                    gate_failure_code: "FE-GATE-002".to_string(),
                    failure_detail: "none".to_string(),
                    recommended_remediation: "n/a".to_string(),
                    lineage_ref: "frankentui://replacement-lineage/gc".to_string(),
                    evidence_ref: "frankentui://evidence/gc".to_string(),
                },
            ],
            rollback_events: vec![
                RollbackEventView {
                    slot_id: "parser".to_string(),
                    receipt_id: "rcpt-parser".to_string(),
                    reason: "canary regression".to_string(),
                    status: RollbackStatus::Investigating,
                    occurred_at_unix_ms: 99,
                    lineage_ref: "frankentui://replacement-lineage/parser".to_string(),
                    evidence_ref: "frankentui://evidence/parser".to_string(),
                },
                RollbackEventView {
                    slot_id: "gc".to_string(),
                    receipt_id: "rcpt-gc".to_string(),
                    reason: "none".to_string(),
                    status: RollbackStatus::Resolved,
                    occurred_at_unix_ms: 100,
                    lineage_ref: "frankentui://replacement-lineage/gc".to_string(),
                    evidence_ref: "frankentui://evidence/gc".to_string(),
                },
            ],
            next_best_replacements: vec![
                ReplacementOpportunityView {
                    slot_id: "parser".to_string(),
                    slot_kind: "parser".to_string(),
                    expected_value_score_millionths: 10,
                    performance_uplift_millionths: 1,
                    invocation_frequency_per_minute: 1,
                    risk_reduction_millionths: 1,
                    rationale: "parser".to_string(),
                },
                ReplacementOpportunityView {
                    slot_id: "gc".to_string(),
                    slot_kind: "garbage_collector".to_string(),
                    expected_value_score_millionths: 9,
                    performance_uplift_millionths: 1,
                    invocation_frequency_per_minute: 1,
                    risk_reduction_millionths: 1,
                    rationale: "gc".to_string(),
                },
            ],
            ..Default::default()
        });

        let filtered = view.filtered(&ReplacementDashboardFilter {
            slot_kind: Some("parser".to_string()),
            risk_level: Some(ReplacementRiskLevel::High),
            promotion_status: Some("promotion_candidate".to_string()),
        });

        assert_eq!(filtered.slot_status_overview.len(), 1);
        assert_eq!(filtered.slot_status_overview[0].slot_id, "parser");
        assert_eq!(filtered.blocked_promotions.len(), 1);
        assert_eq!(filtered.rollback_events.len(), 1);
        assert_eq!(filtered.next_best_replacements.len(), 1);
        assert_eq!(filtered.native_coverage.native_slots, 0);
        assert_eq!(filtered.native_coverage.delegate_slots, 1);
    }

    fn replacement_test_authority() -> AuthorityEnvelope {
        AuthorityEnvelope {
            required: vec![SlotCapability::EmitEvidence],
            permitted: vec![SlotCapability::EmitEvidence, SlotCapability::ReadSource],
        }
    }

    fn replacement_register_slot(registry: &mut SlotRegistry, id: &str, kind: SlotKind) -> SlotId {
        let slot_id = SlotId::new(id).expect("valid slot id");
        registry
            .register_delegate(
                slot_id.clone(),
                kind,
                replacement_test_authority(),
                format!("delegate-{id}"),
                "1000".to_string(),
            )
            .expect("register delegate");
        slot_id
    }

    #[test]
    fn replacement_progress_from_slot_registry_snapshot_builds_drilldown_refs() {
        let mut registry = SlotRegistry::new();
        let parser_id = replacement_register_slot(&mut registry, "parser", SlotKind::Parser);
        let gc_id = replacement_register_slot(&mut registry, "gc", SlotKind::GarbageCollector);

        registry
            .begin_candidacy(&gc_id, "candidate-gc".to_string(), "2000".to_string())
            .expect("gc candidacy");
        registry
            .promote(
                &gc_id,
                "native-gc".to_string(),
                &replacement_test_authority(),
                "receipt-gc".to_string(),
                "3000".to_string(),
            )
            .expect("gc promote");
        registry
            .demote(&gc_id, "canary regression".to_string(), "4000".to_string())
            .expect("gc demote");

        let mut signals = BTreeMap::new();
        signals.insert(
            parser_id,
            SlotReplacementSignal {
                invocation_weight_millionths: 900_000,
                throughput_uplift_millionths: 500_000,
                security_risk_reduction_millionths: 300_000,
            },
        );
        signals.insert(
            gc_id,
            SlotReplacementSignal {
                invocation_weight_millionths: 100_000,
                throughput_uplift_millionths: 100_000,
                security_risk_reduction_millionths: 20_000,
            },
        );
        let snapshot = registry
            .snapshot_replacement_progress(
                "trace-slot-1",
                "decision-slot-1",
                "policy-slot-1",
                &signals,
            )
            .expect("snapshot");

        let dashboard = ReplacementProgressDashboardView::from_slot_registry_snapshot(
            &registry,
            &snapshot,
            "prod",
            "us-east-1",
            42,
            5_000,
        );

        assert_eq!(dashboard.cluster, "prod");
        assert_eq!(dashboard.zone, "us-east-1");
        assert_eq!(dashboard.security_epoch, 42);
        assert!(
            dashboard
                .slot_status_overview
                .iter()
                .any(|row| row.slot_id == "parser"
                    && row.lineage_ref == "frankentui://replacement-lineage/parser")
        );
        assert_eq!(dashboard.next_best_replacements[0].slot_id, "parser");
        assert!(
            dashboard
                .rollback_events
                .iter()
                .any(|row| row.slot_id == "gc" && row.evidence_ref.contains("trace-slot-1"))
        );
    }

    #[test]
    fn replacement_progress_from_slot_registry_snapshot_surfaces_blocked_promotions() {
        let mut registry = SlotRegistry::new();
        let parser_id = replacement_register_slot(&mut registry, "parser", SlotKind::Parser);
        let mut signals = BTreeMap::new();
        signals.insert(
            parser_id,
            SlotReplacementSignal {
                invocation_weight_millionths: 1_000_000,
                throughput_uplift_millionths: 300_000,
                security_risk_reduction_millionths: 120_000,
            },
        );
        let mut snapshot = registry
            .snapshot_replacement_progress(
                "trace-slot-2",
                "decision-slot-2",
                "policy-slot-2",
                &signals,
            )
            .expect("snapshot");
        snapshot.events.push(ReplacementProgressEvent {
            trace_id: "trace-slot-2".to_string(),
            decision_id: "decision-slot-2".to_string(),
            policy_id: "policy-slot-2".to_string(),
            component: "self_replacement_progress".to_string(),
            event: "promotion_gate_failed".to_string(),
            outcome: "blocked".to_string(),
            error_code: Some("FE-GATE-007".to_string()),
            slot_id: Some("parser".to_string()),
            detail: "differential mismatch".to_string(),
        });

        let dashboard = ReplacementProgressDashboardView::from_slot_registry_snapshot(
            &registry,
            &snapshot,
            "prod",
            "us-east-2",
            7,
            6_000,
        );

        assert_eq!(dashboard.blocked_promotions.len(), 1);
        assert_eq!(
            dashboard.blocked_promotions[0].gate_failure_code,
            "FE-GATE-007"
        );
        assert_eq!(
            dashboard.blocked_promotions[0].lineage_ref,
            "frankentui://replacement-lineage/parser"
        );
        assert!(
            dashboard.blocked_promotions[0]
                .evidence_ref
                .contains("decision-slot-2")
        );
    }

    #[test]
    fn replacement_progress_refresh_from_slot_registry_snapshot_updates_on_demotion() {
        let mut registry = SlotRegistry::new();
        let parser_id = replacement_register_slot(&mut registry, "parser", SlotKind::Parser);

        let mut signals = BTreeMap::new();
        signals.insert(
            parser_id.clone(),
            SlotReplacementSignal {
                invocation_weight_millionths: 1_000_000,
                throughput_uplift_millionths: 450_000,
                security_risk_reduction_millionths: 200_000,
            },
        );
        let snapshot_before = registry
            .snapshot_replacement_progress(
                "trace-slot-3",
                "decision-slot-3",
                "policy-slot-3",
                &signals,
            )
            .expect("snapshot before");
        let view_before = ReplacementProgressDashboardView::from_slot_registry_snapshot(
            &registry,
            &snapshot_before,
            "prod",
            "us-central-1",
            21,
            7_000,
        );

        registry
            .begin_candidacy(
                &parser_id,
                "candidate-parser".to_string(),
                "8000".to_string(),
            )
            .expect("parser candidacy");
        registry
            .promote(
                &parser_id,
                "native-parser".to_string(),
                &replacement_test_authority(),
                "receipt-parser".to_string(),
                "9000".to_string(),
            )
            .expect("parser promote");
        registry
            .demote(
                &parser_id,
                "post-promotion drift".to_string(),
                "10000".to_string(),
            )
            .expect("parser demote");
        let snapshot_after = registry
            .snapshot_replacement_progress(
                "trace-slot-3",
                "decision-slot-3",
                "policy-slot-3",
                &signals,
            )
            .expect("snapshot after");
        let refreshed =
            view_before.refreshed_from_slot_registry_snapshot(&registry, &snapshot_after, 10_500);

        assert_eq!(refreshed.cluster, "prod");
        assert_eq!(refreshed.zone, "us-central-1");
        assert_eq!(refreshed.security_epoch, 21);
        assert_eq!(refreshed.generated_at_unix_ms, 10_500);
        assert!(
            refreshed
                .slot_status_overview
                .iter()
                .any(|row| row.slot_id == "parser" && row.promotion_status == "demoted")
        );
        assert!(
            refreshed
                .rollback_events
                .iter()
                .any(|event| event.slot_id == "parser")
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrips for enum types
    // -----------------------------------------------------------------------

    #[test]
    fn replay_status_serde_roundtrip() {
        for s in [
            ReplayStatus::Running,
            ReplayStatus::Complete,
            ReplayStatus::Failed,
            ReplayStatus::NoEvents,
        ] {
            let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
            let restored: ReplayStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(restored, s);
        }
    }

    #[test]
    fn dashboard_severity_serde_roundtrip() {
        for s in [
            DashboardSeverity::Info,
            DashboardSeverity::Warning,
            DashboardSeverity::Critical,
        ] {
            let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
            let restored: DashboardSeverity = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(restored, s);
        }
    }

    #[test]
    fn decision_outcome_kind_serde_roundtrip() {
        for k in [
            DecisionOutcomeKind::Allow,
            DecisionOutcomeKind::Deny,
            DecisionOutcomeKind::Fallback,
        ] {
            let json = serde_json::to_string(&k).expect("serde deserialization should succeed");
            let restored: DecisionOutcomeKind = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(restored, k);
        }
    }

    #[test]
    fn obligation_state_serde_roundtrip() {
        for s in [
            ObligationState::Open,
            ObligationState::Fulfilled,
            ObligationState::Failed,
        ] {
            let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
            let restored: ObligationState = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(restored, s);
        }
    }

    #[test]
    fn cancellation_kind_serde_roundtrip() {
        for k in [
            CancellationKind::Unload,
            CancellationKind::Quarantine,
            CancellationKind::Suspend,
            CancellationKind::Terminate,
            CancellationKind::Revocation,
        ] {
            let json = serde_json::to_string(&k).expect("serde deserialization should succeed");
            let restored: CancellationKind = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(restored, k);
        }
    }

    #[test]
    fn update_kind_serde_roundtrip() {
        for k in [
            UpdateKind::Snapshot,
            UpdateKind::Delta,
            UpdateKind::Heartbeat,
        ] {
            let json = serde_json::to_string(&k).expect("serde deserialization should succeed");
            let restored: UpdateKind = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(restored, k);
        }
    }

    #[test]
    fn adapter_stream_serde_roundtrip() {
        for s in [
            AdapterStream::IncidentReplay,
            AdapterStream::PolicyExplanation,
            AdapterStream::ControlDashboard,
            AdapterStream::ControlPlaneInvariantsDashboard,
            AdapterStream::FlowDecisionDashboard,
            AdapterStream::CapabilityDeltaDashboard,
            AdapterStream::ReplacementProgressDashboard,
            AdapterStream::ProofSpecializationLineageDashboard,
        ] {
            let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
            let restored: AdapterStream = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(restored, s);
        }
    }

    #[test]
    fn replay_health_status_serde_roundtrip() {
        for s in [
            ReplayHealthStatus::Pass,
            ReplayHealthStatus::Fail,
            ReplayHealthStatus::Unknown,
        ] {
            let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
            let restored: ReplayHealthStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(restored, s);
        }
    }

    #[test]
    fn recovery_status_serde_roundtrip() {
        for s in [
            RecoveryStatus::Recovering,
            RecoveryStatus::Recovered,
            RecoveryStatus::Waived,
        ] {
            let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
            let restored: RecoveryStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(restored, s);
        }
    }

    #[test]
    fn schema_compatibility_status_serde_roundtrip() {
        for s in [
            SchemaCompatibilityStatus::Unknown,
            SchemaCompatibilityStatus::Compatible,
            SchemaCompatibilityStatus::NeedsMigration,
            SchemaCompatibilityStatus::Incompatible,
        ] {
            let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
            let restored: SchemaCompatibilityStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(restored, s);
        }
    }

    #[test]
    fn dashboard_alert_metric_serde_roundtrip() {
        for m in [
            DashboardAlertMetric::ObligationFailureRateMillionths,
            DashboardAlertMetric::ReplayDivergenceCount,
            DashboardAlertMetric::SafeModeActivationCount,
            DashboardAlertMetric::CancellationEventCount,
            DashboardAlertMetric::FallbackActivationCount,
        ] {
            let json = serde_json::to_string(&m).expect("serde deserialization should succeed");
            let restored: DashboardAlertMetric = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(restored, m);
        }
    }

    #[test]
    fn threshold_comparator_serde_roundtrip() {
        for c in [
            ThresholdComparator::GreaterThan,
            ThresholdComparator::GreaterOrEqual,
            ThresholdComparator::LessThan,
            ThresholdComparator::LessOrEqual,
            ThresholdComparator::Equal,
        ] {
            let json = serde_json::to_string(&c).expect("serde deserialization should succeed");
            let restored: ThresholdComparator = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(restored, c);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrips for struct types
    // -----------------------------------------------------------------------

    #[test]
    fn replay_event_view_serde_roundtrip() {
        let ev = ReplayEventView::new(1, "engine", "start", "ok", 100);
        let json = serde_json::to_string(&ev).expect("serde deserialization should succeed");
        let restored: ReplayEventView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(restored, ev);
    }

    #[test]
    fn action_candidate_view_serde_roundtrip() {
        let ac = ActionCandidateView {
            action: "contain".to_string(),
            expected_loss_millionths: 50_000,
        };
        let json = serde_json::to_string(&ac).expect("serde deserialization should succeed");
        let restored: ActionCandidateView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(restored, ac);
    }

    #[test]
    fn driver_view_serde_roundtrip() {
        let dv = DriverView {
            name: "risk_score".to_string(),
            contribution_millionths: 300_000,
        };
        let json = serde_json::to_string(&dv).expect("serde deserialization should succeed");
        let restored: DriverView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(restored, dv);
    }

    #[test]
    fn dashboard_metric_view_serde_roundtrip() {
        let mv = DashboardMetricView {
            metric: "latency_p95_ms".to_string(),
            value: 42,
            unit: "ms".to_string(),
        };
        let json = serde_json::to_string(&mv).expect("serde deserialization should succeed");
        let restored: DashboardMetricView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(restored, mv);
    }

    #[test]
    fn extension_status_row_serde_roundtrip() {
        let row = ExtensionStatusRow {
            extension_id: "weather-ext".to_string(),
            state: "running".to_string(),
            trust_level: "trusted".to_string(),
        };
        let json = serde_json::to_string(&row).expect("serde deserialization should succeed");
        let restored: ExtensionStatusRow = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(restored, row);
    }

    #[test]
    fn dashboard_refresh_policy_serde_roundtrip() {
        let rp = DashboardRefreshPolicy {
            evidence_stream_refresh_secs: 10,
            aggregate_refresh_secs: 120,
        };
        let json = serde_json::to_string(&rp).expect("serde deserialization should succeed");
        let restored: DashboardRefreshPolicy = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(restored, rp);
    }

    #[test]
    fn benchmark_trend_point_serde_roundtrip() {
        let pt = BenchmarkTrendPointView {
            timestamp_unix_ms: 1_700_000_000_000,
            throughput_tps: 5000,
            latency_p95_ms: 12,
            memory_peak_mb: 512,
        };
        let json = serde_json::to_string(&pt).expect("serde deserialization should succeed");
        let restored: BenchmarkTrendPointView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(restored, pt);
    }

    // -----------------------------------------------------------------------
    // Enrichment: edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_non_empty_trims_and_replaces_blank() {
        assert_eq!(normalize_non_empty("  hello  ".to_string()), "hello");
        assert_eq!(normalize_non_empty("".to_string()), "unknown");
        assert_eq!(normalize_non_empty("   ".to_string()), "unknown");
    }

    #[test]
    fn incident_replay_with_events_marks_complete() {
        let ev = ReplayEventView::new(0, "engine", "init", "ok", 100);
        let replay = IncidentReplayView::snapshot("trace-1", "scenario", vec![ev]);
        assert_eq!(replay.replay_status, ReplayStatus::Complete);
        assert!(replay.deterministic);
    }

    #[test]
    fn adapter_envelope_encode_json_deterministic() {
        let payload = FrankentuiViewPayload::IncidentReplay(IncidentReplayView::snapshot(
            "trace-1",
            "scenario-1",
            vec![],
        ));
        let env = AdapterEnvelope::new(
            "trace-1",
            1000,
            AdapterStream::IncidentReplay,
            UpdateKind::Snapshot,
            payload,
        );
        let enc1 = env.encode_json().expect("serde deserialization should succeed");
        let enc2 = env.encode_json().expect("serde deserialization should succeed");
        assert_eq!(enc1, enc2);
    }

    #[test]
    fn dashboard_severity_default_is_info() {
        assert_eq!(DashboardSeverity::default(), DashboardSeverity::Info);
    }

    #[test]
    fn replay_health_status_default_is_unknown() {
        assert_eq!(ReplayHealthStatus::default(), ReplayHealthStatus::Unknown);
    }

    #[test]
    fn recovery_status_default_is_recovering() {
        assert_eq!(RecoveryStatus::default(), RecoveryStatus::Recovering);
    }

    #[test]
    fn dashboard_refresh_policy_default_values() {
        let rp = DashboardRefreshPolicy::default();
        assert_eq!(rp.evidence_stream_refresh_secs, 5);
        assert_eq!(rp.aggregate_refresh_secs, 60);
    }

    #[test]
    fn schema_version_panel_default_is_unknown() {
        let sv = SchemaVersionPanelView::default();
        assert_eq!(sv.compatibility_status, SchemaCompatibilityStatus::Unknown);
        assert_eq!(sv.evidence_schema_version, 0);
    }

    #[test]
    fn policy_explanation_partial_serde_roundtrip() {
        let partial = PolicyExplanationPartial {
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            selected_action: "contain".to_string(),
            confidence_millionths: Some(750_000),
            expected_loss_millionths: Some(120_000),
            action_candidates: vec![ActionCandidateView {
                action: "contain".to_string(),
                expected_loss_millionths: 120_000,
            }],
            key_drivers: vec![DriverView {
                name: "risk".to_string(),
                contribution_millionths: 600_000,
            }],
        };
        let json = serde_json::to_string(&partial).expect("serde deserialization should succeed");
        let restored: PolicyExplanationPartial = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(restored, partial);
    }

    #[test]
    fn snake_case_serde_enum_values_are_lowercase() {
        let json = serde_json::to_string(&ReplayStatus::NoEvents).expect("serde deserialization should succeed");
        assert_eq!(json, "\"no_events\"");

        let json = serde_json::to_string(&UpdateKind::Heartbeat).expect("serde deserialization should succeed");
        assert_eq!(json, "\"heartbeat\"");

        let json = serde_json::to_string(&CancellationKind::Quarantine).expect("serde deserialization should succeed");
        assert_eq!(json, "\"quarantine\"");

        let json =
            serde_json::to_string(&DashboardAlertMetric::ObligationFailureRateMillionths).expect("serde deserialization should succeed");
        assert_eq!(json, "\"obligation_failure_rate_millionths\"");
    }

    // -----------------------------------------------------------------------
    // Enrichment: untested leaf enum serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn flow_sensitivity_level_serde_roundtrip() {
        for v in [
            FlowSensitivityLevel::Low,
            FlowSensitivityLevel::Medium,
            FlowSensitivityLevel::High,
            FlowSensitivityLevel::Critical,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let restored: FlowSensitivityLevel = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn declassification_outcome_serde_roundtrip() {
        for v in [
            DeclassificationOutcome::Approved,
            DeclassificationOutcome::Denied,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let restored: DeclassificationOutcome = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn confinement_status_serde_roundtrip() {
        for v in [
            ConfinementStatus::Full,
            ConfinementStatus::Partial,
            ConfinementStatus::Degraded,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let restored: ConfinementStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn replacement_risk_level_serde_roundtrip() {
        for v in [
            ReplacementRiskLevel::Low,
            ReplacementRiskLevel::Medium,
            ReplacementRiskLevel::High,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let restored: ReplacementRiskLevel = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn rollback_status_serde_roundtrip() {
        for v in [
            RollbackStatus::Investigating,
            RollbackStatus::Resolved,
            RollbackStatus::Waived,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let restored: RollbackStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn proof_inventory_kind_serde_roundtrip() {
        for v in [
            ProofInventoryKind::CapabilityWitness,
            ProofInventoryKind::FlowProof,
            ProofInventoryKind::ReplayMotif,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let restored: ProofInventoryKind = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn proof_validity_status_serde_roundtrip() {
        for v in [
            ProofValidityStatus::Valid,
            ProofValidityStatus::ExpiringSoon,
            ProofValidityStatus::Expired,
            ProofValidityStatus::Revoked,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let restored: ProofValidityStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn proof_specialization_invalidation_reason_serde_roundtrip() {
        for v in [
            ProofSpecializationInvalidationReason::EpochChange,
            ProofSpecializationInvalidationReason::ProofExpired,
            ProofSpecializationInvalidationReason::ProofRevoked,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let restored: ProofSpecializationInvalidationReason =
                serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn specialization_fallback_reason_serde_roundtrip() {
        for v in [
            SpecializationFallbackReason::ProofUnavailable,
            SpecializationFallbackReason::ProofExpired,
            SpecializationFallbackReason::ProofRevoked,
            SpecializationFallbackReason::ValidationFailed,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let restored: SpecializationFallbackReason = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn override_review_status_serde_roundtrip() {
        for v in [
            OverrideReviewStatus::Pending,
            OverrideReviewStatus::Approved,
            OverrideReviewStatus::Rejected,
            OverrideReviewStatus::Waived,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let restored: OverrideReviewStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, restored);
        }
    }

    #[test]
    fn grant_expiry_status_serde_roundtrip() {
        for v in [
            GrantExpiryStatus::Active,
            GrantExpiryStatus::ExpiringSoon,
            GrantExpiryStatus::Expired,
            GrantExpiryStatus::NotApplicable,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let restored: GrantExpiryStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: default value assertions
    // -----------------------------------------------------------------------

    #[test]
    fn flow_sensitivity_level_default_is_low() {
        assert_eq!(FlowSensitivityLevel::default(), FlowSensitivityLevel::Low);
    }

    #[test]
    fn proof_validity_status_default_is_valid() {
        assert_eq!(ProofValidityStatus::default(), ProofValidityStatus::Valid);
    }

    #[test]
    fn override_review_status_default_is_pending() {
        assert_eq!(
            OverrideReviewStatus::default(),
            OverrideReviewStatus::Pending
        );
    }

    #[test]
    fn grant_expiry_status_default_is_active() {
        assert_eq!(GrantExpiryStatus::default(), GrantExpiryStatus::Active);
    }

    #[test]
    fn decision_outcomes_panel_default_all_zero() {
        let d = DecisionOutcomesPanelView::default();
        assert_eq!(d.allow_count, 0);
        assert_eq!(d.deny_count, 0);
        assert_eq!(d.fallback_count, 0);
        assert_eq!(d.average_expected_loss_millionths, 0);
    }

    #[test]
    fn specialization_performance_impact_default_all_zero() {
        let d = SpecializationPerformanceImpactView::default();
        assert_eq!(d.active_specialization_count, 0);
        assert_eq!(d.aggregate_latency_reduction_millionths, 0);
        assert_eq!(d.aggregate_throughput_increase_millionths, 0);
        assert_eq!(d.specialization_coverage_millionths, 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn obligation_status_row_view_serde_roundtrip() {
        let row = ObligationStatusRowView {
            obligation_id: "o-1".to_string(),
            extension_id: "ext-a".to_string(),
            region_id: "r-1".to_string(),
            state: ObligationState::Open,
            severity: DashboardSeverity::Warning,
            due_at_unix_ms: 1000,
            updated_at_unix_ms: 900,
            detail: "pending check".to_string(),
        };
        let json = serde_json::to_string(&row).expect("serde deserialization should succeed");
        let restored: ObligationStatusRowView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(row, restored);
    }

    #[test]
    fn cancellation_event_view_serde_roundtrip() {
        let ev = CancellationEventView {
            extension_id: "ext-a".to_string(),
            region_id: "r-1".to_string(),
            cancellation_kind: CancellationKind::Quarantine,
            severity: DashboardSeverity::Critical,
            detail: "policy violation".to_string(),
            timestamp_unix_ms: 5000,
        };
        let json = serde_json::to_string(&ev).expect("serde deserialization should succeed");
        let restored: CancellationEventView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(ev, restored);
    }

    #[test]
    fn label_map_node_view_serde_roundtrip() {
        let node = LabelMapNodeView {
            label_id: "lbl-1".to_string(),
            sensitivity: FlowSensitivityLevel::High,
            description: "PII label".to_string(),
            extension_overlays: vec!["ext-a".to_string()],
        };
        let json = serde_json::to_string(&node).expect("serde deserialization should succeed");
        let restored: LabelMapNodeView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(node, restored);
    }

    #[test]
    fn slot_status_overview_row_serde_roundtrip() {
        let row = SlotStatusOverviewRow {
            slot_id: "slot-1".to_string(),
            slot_kind: "compute".to_string(),
            implementation_kind: "native".to_string(),
            promotion_status: "promoted".to_string(),
            risk_level: ReplacementRiskLevel::Low,
            last_transition_unix_ms: 2000,
            health: "healthy".to_string(),
            lineage_ref: "ref-1".to_string(),
        };
        let json = serde_json::to_string(&row).expect("serde deserialization should succeed");
        let restored: SlotStatusOverviewRow = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(row, restored);
    }

    #[test]
    fn rollback_event_view_serde_roundtrip() {
        let ev = RollbackEventView {
            slot_id: "slot-1".to_string(),
            receipt_id: "r-1".to_string(),
            reason: "perf regression".to_string(),
            status: RollbackStatus::Investigating,
            occurred_at_unix_ms: 3000,
            lineage_ref: "ref-a".to_string(),
            evidence_ref: "ref-b".to_string(),
        };
        let json = serde_json::to_string(&ev).expect("serde deserialization should succeed");
        let restored: RollbackEventView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(ev, restored);
    }

    #[test]
    fn proof_inventory_row_view_serde_roundtrip() {
        let row = ProofInventoryRowView {
            proof_id: "p-1".to_string(),
            proof_kind: ProofInventoryKind::CapabilityWitness,
            validity_status: ProofValidityStatus::Valid,
            epoch_id: 5,
            linked_specialization_count: 2,
            enabled_specialization_ids: vec!["s-1".to_string()],
            proof_ref: "ref-p".to_string(),
        };
        let json = serde_json::to_string(&row).expect("serde deserialization should succeed");
        let restored: ProofInventoryRowView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(row, restored);
    }

    #[test]
    fn override_rationale_view_serde_roundtrip() {
        let ov = OverrideRationaleView {
            override_id: "ov-1".to_string(),
            extension_id: "ext-a".to_string(),
            capability: Some("cap:fs".to_string()),
            rationale: "required for migration".to_string(),
            signed_justification_ref: "ref-j".to_string(),
            review_status: OverrideReviewStatus::Approved,
            grant_expiry_status: GrantExpiryStatus::ExpiringSoon,
            requested_at_unix_ms: 1000,
            reviewed_at_unix_ms: Some(2000),
            expires_at_unix_ms: Some(5000),
            receipt_ref: "ref-r".to_string(),
            replay_ref: "ref-rp".to_string(),
        };
        let json = serde_json::to_string(&ov).expect("serde deserialization should succeed");
        let restored: OverrideRationaleView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(ov, restored);
    }

    #[test]
    fn capability_delta_alert_view_serde_roundtrip() {
        let alert = CapabilityDeltaAlertView {
            alert_id: "a-1".to_string(),
            extension_id: Some("ext-a".to_string()),
            severity: DashboardSeverity::Warning,
            reason: "over-privileged".to_string(),
            generated_at_unix_ms: 4000,
        };
        let json = serde_json::to_string(&alert).expect("serde deserialization should succeed");
        let restored: CapabilityDeltaAlertView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(alert, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: filter/partial default assertions
    // -----------------------------------------------------------------------

    #[test]
    fn control_plane_dashboard_filter_default_all_none() {
        let f = ControlPlaneDashboardFilter::default();
        assert!(f.extension_id.is_none());
        assert!(f.region_id.is_none());
        assert!(f.severity.is_none());
        assert!(f.start_unix_ms.is_none());
        assert!(f.end_unix_ms.is_none());
    }

    #[test]
    fn flow_decision_dashboard_filter_default_all_none() {
        let f = FlowDecisionDashboardFilter::default();
        assert!(f.extension_id.is_none());
        assert!(f.source_label.is_none());
        assert!(f.sink_clearance.is_none());
        assert!(f.sensitivity.is_none());
        assert!(f.start_unix_ms.is_none());
        assert!(f.end_unix_ms.is_none());
    }

    // -- Enrichment: missing serde roundtrips --

    #[test]
    fn frankentui_view_payload_serde_roundtrip() {
        let payload = FrankentuiViewPayload::IncidentReplay(IncidentReplayView::snapshot(
            "trace-1",
            "scenario-1",
            vec![],
        ));
        let json = serde_json::to_string(&payload).expect("serde deserialization should succeed");
        let restored: FrankentuiViewPayload = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(payload, restored);
    }

    #[test]
    fn incident_replay_view_serde_roundtrip() {
        let ev = ReplayEventView::new(0, "engine", "init", "ok", 100);
        let view = IncidentReplayView::snapshot("trace-1", "scenario-1", vec![ev]);
        let json = serde_json::to_string(&view).expect("serde deserialization should succeed");
        let restored: IncidentReplayView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(view, restored);
    }

    #[test]
    fn evidence_stream_entry_view_serde_roundtrip() {
        let entry = EvidenceStreamEntryView {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            action_type: "observe".to_string(),
            decision_outcome: DecisionOutcomeKind::Allow,
            expected_loss_millionths: 500,
            extension_id: "ext-1".to_string(),
            region_id: "region-1".to_string(),
            severity: DashboardSeverity::Warning,
            component: "engine".to_string(),
            event: "decision".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            timestamp_unix_ms: 1000,
        };
        let json = serde_json::to_string(&entry).expect("serde deserialization should succeed");
        let restored: EvidenceStreamEntryView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(entry, restored);
    }

    #[test]
    fn dashboard_alert_rule_serde_roundtrip() {
        let rule = DashboardAlertRule {
            rule_id: "alert-1".to_string(),
            description: "High failure rate".to_string(),
            metric: DashboardAlertMetric::ObligationFailureRateMillionths,
            comparator: ThresholdComparator::GreaterThan,
            threshold: 100_000,
            severity: DashboardSeverity::Critical,
        };
        let json = serde_json::to_string(&rule).expect("serde deserialization should succeed");
        let restored: DashboardAlertRule = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(rule, restored);
    }

    #[test]
    fn triggered_alert_view_serde_roundtrip() {
        let alert = TriggeredAlertView {
            rule_id: "r1".to_string(),
            description: "alert-desc".to_string(),
            metric: DashboardAlertMetric::ReplayDivergenceCount,
            observed_value: 10,
            threshold: 5,
            severity: DashboardSeverity::Warning,
            triggered_at_unix_ms: 2000,
        };
        let json = serde_json::to_string(&alert).expect("serde deserialization should succeed");
        let restored: TriggeredAlertView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(alert, restored);
    }

    #[test]
    fn label_map_edge_view_serde_roundtrip() {
        let edge = LabelMapEdgeView {
            source_label: "A".to_string(),
            sink_clearance: "B".to_string(),
            route_policy_id: Some("policy-1".to_string()),
            route_enabled: true,
        };
        let json = serde_json::to_string(&edge).expect("serde deserialization should succeed");
        let restored: LabelMapEdgeView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(edge, restored);
    }

    #[test]
    fn blocked_flow_view_serde_roundtrip() {
        let flow = BlockedFlowView {
            flow_id: "flow-1".to_string(),
            extension_id: "ext-1".to_string(),
            source_label: "secret".to_string(),
            sink_clearance: "public".to_string(),
            sensitivity: FlowSensitivityLevel::High,
            blocked_reason: "policy violation".to_string(),
            attempted_exfiltration: false,
            code_path_ref: "src/main.rs:42".to_string(),
            extension_context_ref: "ctx-1".to_string(),
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            error_code: None,
            occurred_at_unix_ms: 3000,
        };
        let json = serde_json::to_string(&flow).expect("serde deserialization should succeed");
        let restored: BlockedFlowView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(flow, restored);
    }

    #[test]
    fn coverage_trend_point_serde_roundtrip() {
        let pt = CoverageTrendPoint {
            timestamp_unix_ms: 5000,
            native_coverage_millionths: 900_000,
        };
        let json = serde_json::to_string(&pt).expect("serde deserialization should succeed");
        let restored: CoverageTrendPoint = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(pt, restored);
    }

    #[test]
    fn replacement_dashboard_filter_default_all_none() {
        let f = ReplacementDashboardFilter::default();
        assert!(f.slot_kind.is_none());
        assert!(f.risk_level.is_none());
        assert!(f.promotion_status.is_none());
    }

    // -- Enrichment: helper function coverage --

    #[test]
    fn normalize_non_empty_whitespace_only_returns_unknown() {
        assert_eq!(normalize_non_empty("   ".to_string()), "unknown");
    }

    #[test]
    fn normalize_non_empty_empty_returns_unknown() {
        assert_eq!(normalize_non_empty(String::new()), "unknown");
    }

    #[test]
    fn normalize_non_empty_trims_leading_trailing() {
        assert_eq!(normalize_non_empty("  hello  ".to_string()), "hello");
    }

    #[test]
    fn normalize_optional_non_empty_none_stays_none() {
        assert!(normalize_optional_non_empty(None).is_none());
    }

    #[test]
    fn normalize_optional_non_empty_blank_becomes_none() {
        assert!(normalize_optional_non_empty(Some("  ".to_string())).is_none());
    }

    #[test]
    fn normalize_optional_non_empty_valid_trims() {
        assert_eq!(
            normalize_optional_non_empty(Some("  val  ".to_string())),
            Some("val".to_string())
        );
    }

    #[test]
    fn canonicalize_coverage_clamps_above_million() {
        assert_eq!(canonicalize_coverage_millionths(2_000_000), 1_000_000);
    }

    #[test]
    fn canonicalize_coverage_passthrough_below_million() {
        assert_eq!(canonicalize_coverage_millionths(500_000), 500_000);
    }

    #[test]
    fn canonicalize_coverage_at_million_is_identity() {
        assert_eq!(canonicalize_coverage_millionths(1_000_000), 1_000_000);
    }

    #[test]
    fn implementation_is_native_case_insensitive() {
        assert!(implementation_is_native("native"));
        assert!(implementation_is_native("NATIVE"));
        assert!(implementation_is_native("Native"));
        assert!(!implementation_is_native("delegate"));
        assert!(!implementation_is_native(""));
    }

    // -- Enrichment: threshold_matches all comparators --

    #[test]
    fn threshold_matches_greater_than() {
        assert!(threshold_matches(ThresholdComparator::GreaterThan, 5, 3));
        assert!(!threshold_matches(ThresholdComparator::GreaterThan, 3, 3));
        assert!(!threshold_matches(ThresholdComparator::GreaterThan, 2, 3));
    }

    #[test]
    fn threshold_matches_greater_or_equal() {
        assert!(threshold_matches(ThresholdComparator::GreaterOrEqual, 5, 3));
        assert!(threshold_matches(ThresholdComparator::GreaterOrEqual, 3, 3));
        assert!(!threshold_matches(
            ThresholdComparator::GreaterOrEqual,
            2,
            3
        ));
    }

    #[test]
    fn threshold_matches_less_than() {
        assert!(threshold_matches(ThresholdComparator::LessThan, 2, 3));
        assert!(!threshold_matches(ThresholdComparator::LessThan, 3, 3));
        assert!(!threshold_matches(ThresholdComparator::LessThan, 5, 3));
    }

    #[test]
    fn threshold_matches_less_or_equal() {
        assert!(threshold_matches(ThresholdComparator::LessOrEqual, 2, 3));
        assert!(threshold_matches(ThresholdComparator::LessOrEqual, 3, 3));
        assert!(!threshold_matches(ThresholdComparator::LessOrEqual, 5, 3));
    }

    #[test]
    fn threshold_matches_equal() {
        assert!(threshold_matches(ThresholdComparator::Equal, 3, 3));
        assert!(!threshold_matches(ThresholdComparator::Equal, 2, 3));
        assert!(!threshold_matches(ThresholdComparator::Equal, 4, 3));
    }

    // -- Enrichment: build_native_coverage_meter --

    #[test]
    fn build_native_coverage_meter_empty_slots() {
        let meter = build_native_coverage_meter(&[], vec![]);
        assert_eq!(meter.native_slots, 0);
        assert_eq!(meter.delegate_slots, 0);
        assert_eq!(meter.native_coverage_millionths, 0);
    }

    #[test]
    fn build_native_coverage_meter_all_native() {
        let rows = vec![
            SlotStatusOverviewRow {
                slot_id: "s1".to_string(),
                slot_kind: "compute".to_string(),
                implementation_kind: "native".to_string(),
                risk_level: ReplacementRiskLevel::Low,
                promotion_status: "promoted".to_string(),
                last_transition_unix_ms: 1000,
                health: "healthy".to_string(),
                lineage_ref: "lr1".to_string(),
            },
            SlotStatusOverviewRow {
                slot_id: "s2".to_string(),
                slot_kind: "io".to_string(),
                implementation_kind: "NATIVE".to_string(),
                risk_level: ReplacementRiskLevel::Low,
                promotion_status: "promoted".to_string(),
                last_transition_unix_ms: 2000,
                health: "healthy".to_string(),
                lineage_ref: "lr2".to_string(),
            },
        ];
        let meter = build_native_coverage_meter(&rows, vec![]);
        assert_eq!(meter.native_slots, 2);
        assert_eq!(meter.delegate_slots, 0);
        assert_eq!(meter.native_coverage_millionths, 1_000_000);
    }

    #[test]
    fn build_native_coverage_meter_mixed() {
        let rows = vec![
            SlotStatusOverviewRow {
                slot_id: "s1".to_string(),
                slot_kind: "a".to_string(),
                implementation_kind: "native".to_string(),
                risk_level: ReplacementRiskLevel::Low,
                promotion_status: "p".to_string(),
                last_transition_unix_ms: 0,
                health: "ok".to_string(),
                lineage_ref: String::new(),
            },
            SlotStatusOverviewRow {
                slot_id: "s2".to_string(),
                slot_kind: "b".to_string(),
                implementation_kind: "delegate".to_string(),
                risk_level: ReplacementRiskLevel::Medium,
                promotion_status: "p".to_string(),
                last_transition_unix_ms: 0,
                health: "ok".to_string(),
                lineage_ref: String::new(),
            },
        ];
        let meter = build_native_coverage_meter(&rows, vec![]);
        assert_eq!(meter.native_slots, 1);
        assert_eq!(meter.delegate_slots, 1);
        assert_eq!(meter.native_coverage_millionths, 500_000);
    }

    // -- Enrichment: rank_replacement_opportunities --

    #[test]
    fn rank_replacement_opportunities_empty() {
        let ranked = rank_replacement_opportunities(vec![]);
        assert!(ranked.is_empty());
    }

    #[test]
    fn rank_replacement_opportunities_sorts_by_ev_desc() {
        let inputs = vec![
            ReplacementOpportunityInput {
                slot_id: "low".to_string(),
                slot_kind: "a".to_string(),
                performance_uplift_millionths: 100_000,
                invocation_frequency_per_minute: 1,
                risk_reduction_millionths: 0,
            },
            ReplacementOpportunityInput {
                slot_id: "high".to_string(),
                slot_kind: "b".to_string(),
                performance_uplift_millionths: 500_000,
                invocation_frequency_per_minute: 10,
                risk_reduction_millionths: 100_000,
            },
        ];
        let ranked = rank_replacement_opportunities(inputs);
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].slot_id, "high");
        assert_eq!(ranked[1].slot_id, "low");
    }

    // -- Enrichment: build_specialization_performance_impact --

    #[test]
    fn build_spec_perf_impact_empty_inputs() {
        let impact = build_specialization_performance_impact(&[], &[]);
        assert_eq!(impact.active_specialization_count, 0);
        assert_eq!(impact.aggregate_latency_reduction_millionths, 0);
        assert_eq!(impact.aggregate_throughput_increase_millionths, 0);
        assert_eq!(impact.specialization_coverage_millionths, 1_000_000);
    }

    #[test]
    fn build_spec_perf_impact_aggregates_latency_and_throughput() {
        let specs = vec![
            ActiveSpecializationRowView {
                specialization_id: "sp1".to_string(),
                target_id: "t1".to_string(),
                target_kind: "fn".to_string(),
                optimization_class: "oc".to_string(),
                proof_input_ids: vec!["p1".to_string()],
                latency_reduction_millionths: 100_000,
                throughput_increase_millionths: 200_000,
                transformation_ref: "tr1".to_string(),
                receipt_ref: "r1".to_string(),
                activated_at_unix_ms: 1000,
            },
            ActiveSpecializationRowView {
                specialization_id: "sp2".to_string(),
                target_id: "t2".to_string(),
                target_kind: "fn".to_string(),
                optimization_class: "oc".to_string(),
                proof_input_ids: vec!["p2".to_string()],
                latency_reduction_millionths: 50_000,
                throughput_increase_millionths: 80_000,
                transformation_ref: "tr2".to_string(),
                receipt_ref: "r2".to_string(),
                activated_at_unix_ms: 2000,
            },
        ];
        let impact = build_specialization_performance_impact(&specs, &[]);
        assert_eq!(impact.active_specialization_count, 2);
        assert_eq!(impact.aggregate_latency_reduction_millionths, 150_000);
        assert_eq!(impact.aggregate_throughput_increase_millionths, 280_000);
    }

    // -- Enrichment: ReplayEventView constructor --

    #[test]
    fn replay_event_view_new_normalizes_fields() {
        let ev = ReplayEventView::new(1, "  comp  ", "  evt  ", "  ok  ", 9999);
        assert_eq!(ev.sequence, 1);
        assert_eq!(ev.component, "comp");
        assert_eq!(ev.event, "evt");
        assert_eq!(ev.outcome, "ok");
        assert_eq!(ev.timestamp_unix_ms, 9999);
        assert!(ev.error_code.is_none());
    }

    #[test]
    fn replay_event_view_new_blank_becomes_unknown() {
        let ev = ReplayEventView::new(0, "", "", "", 0);
        assert_eq!(ev.component, "unknown");
        assert_eq!(ev.event, "unknown");
        assert_eq!(ev.outcome, "unknown");
    }

    // -- Enrichment: ControlDashboardView::from_partial --

    #[test]
    fn control_dashboard_from_partial_defaults_epoch() {
        let partial = ControlDashboardPartial {
            cluster: "us-east".to_string(),
            zone: "z1".to_string(),
            security_epoch: None,
            runtime_mode: "production".to_string(),
            ..Default::default()
        };
        let view = ControlDashboardView::from_partial(partial);
        assert_eq!(view.security_epoch, 0);
        assert_eq!(view.cluster, "us-east");
    }

    #[test]
    fn control_dashboard_from_partial_with_epoch() {
        let partial = ControlDashboardPartial {
            cluster: "eu".to_string(),
            zone: "z2".to_string(),
            security_epoch: Some(42),
            runtime_mode: "staging".to_string(),
            ..Default::default()
        };
        let view = ControlDashboardView::from_partial(partial);
        assert_eq!(view.security_epoch, 42);
    }

    // -- Enrichment: IncidentReplayView::snapshot --

    #[test]
    fn incident_replay_snapshot_with_events_is_complete() {
        let events = vec![ReplayEventView::new(1, "c", "e", "o", 100)];
        let replay = IncidentReplayView::snapshot("t", "s", events);
        assert_eq!(replay.replay_status, ReplayStatus::Complete);
        assert!(replay.deterministic);
        assert_eq!(replay.events.len(), 1);
    }

    #[test]
    fn incident_replay_snapshot_normalizes_blank_fields() {
        let replay = IncidentReplayView::snapshot("  ", "  ", vec![]);
        assert_eq!(replay.trace_id, "unknown");
        assert_eq!(replay.scenario_name, "unknown");
    }

    // -- Enrichment: AdapterEnvelope builder --

    #[test]
    fn adapter_envelope_new_has_schema_version() {
        let replay = IncidentReplayView::snapshot("t", "s", vec![]);
        let env = AdapterEnvelope::new(
            "trace-1",
            1000,
            AdapterStream::IncidentReplay,
            UpdateKind::Snapshot,
            FrankentuiViewPayload::IncidentReplay(replay),
        );
        assert_eq!(env.schema_version, FRANKENTUI_ADAPTER_SCHEMA_VERSION);
        assert!(env.decision_id.is_none());
        assert!(env.policy_id.is_none());
    }

    #[test]
    fn adapter_envelope_with_decision_context_sets_ids() {
        let replay = IncidentReplayView::snapshot("t", "s", vec![]);
        let env = AdapterEnvelope::new(
            "trace-1",
            1000,
            AdapterStream::IncidentReplay,
            UpdateKind::Snapshot,
            FrankentuiViewPayload::IncidentReplay(replay),
        )
        .with_decision_context("dec-1", "pol-1");
        assert_eq!(env.decision_id, Some("dec-1".to_string()));
        assert_eq!(env.policy_id, Some("pol-1".to_string()));
    }

    // -- Enrichment: DashboardRefreshPolicy::normalized --

    #[test]
    fn dashboard_refresh_policy_normalized_clamps_evidence_to_five() {
        let policy = DashboardRefreshPolicy {
            evidence_stream_refresh_secs: 30,
            aggregate_refresh_secs: 120,
        }
        .normalized();
        // .max(5) preserves 30 (the larger value).
        assert_eq!(policy.evidence_stream_refresh_secs, 30);
    }

    #[test]
    fn dashboard_refresh_policy_normalized_zero_evidence_defaults_five() {
        let policy = DashboardRefreshPolicy {
            evidence_stream_refresh_secs: 0,
            aggregate_refresh_secs: 60,
        }
        .normalized();
        assert_eq!(policy.evidence_stream_refresh_secs, 5);
    }

    #[test]
    fn dashboard_refresh_policy_normalized_zero_aggregate_defaults_sixty() {
        let policy = DashboardRefreshPolicy {
            evidence_stream_refresh_secs: 5,
            aggregate_refresh_secs: 0,
        }
        .normalized();
        assert_eq!(policy.aggregate_refresh_secs, 60);
    }

    // -- Enrichment: compute_expected_value_score --

    #[test]
    fn expected_value_score_zero_inputs() {
        let input = ReplacementOpportunityInput {
            slot_id: "s".to_string(),
            slot_kind: "k".to_string(),
            performance_uplift_millionths: 0,
            invocation_frequency_per_minute: 0,
            risk_reduction_millionths: 0,
        };
        assert_eq!(compute_expected_value_score_millionths(&input), 0);
    }

    #[test]
    fn expected_value_score_risk_only() {
        let input = ReplacementOpportunityInput {
            slot_id: "s".to_string(),
            slot_kind: "k".to_string(),
            performance_uplift_millionths: 0,
            invocation_frequency_per_minute: 0,
            risk_reduction_millionths: 100_000,
        };
        let score = compute_expected_value_score_millionths(&input);
        assert_eq!(score, 300_000); // 100_000 * 3
    }

    // -- Enrichment: ProofSpecializationDashboardFilter default --

    #[test]
    fn proof_specialization_dashboard_filter_default_all_none() {
        let f = ProofSpecializationDashboardFilter::default();
        assert!(f.target_id.is_none());
        assert!(f.optimization_class.is_none());
        assert!(f.proof_id.is_none());
        assert!(f.start_unix_ms.is_none());
        assert!(f.end_unix_ms.is_none());
    }

    // -- Enrichment: CapabilityDeltaDashboardFilter default --

    #[test]
    fn capability_delta_dashboard_filter_default_all_none() {
        let f = CapabilityDeltaDashboardFilter::default();
        assert!(f.extension_id.is_none());
        assert!(f.capability.is_none());
    }

    // -----------------------------------------------------------------------
    // Enrichment: enum serde roundtrips covering all variants
    // -----------------------------------------------------------------------

    #[test]
    fn decision_outcome_kind_serde_all_variants() {
        for v in [
            DecisionOutcomeKind::Allow,
            DecisionOutcomeKind::Deny,
            DecisionOutcomeKind::Fallback,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: DecisionOutcomeKind = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn obligation_state_serde_all_variants() {
        for v in [
            ObligationState::Open,
            ObligationState::Fulfilled,
            ObligationState::Failed,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: ObligationState = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn cancellation_kind_serde_all_variants() {
        for v in [
            CancellationKind::Unload,
            CancellationKind::Quarantine,
            CancellationKind::Suspend,
            CancellationKind::Terminate,
            CancellationKind::Revocation,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: CancellationKind = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn replay_health_status_serde_all_variants() {
        for v in [
            ReplayHealthStatus::Pass,
            ReplayHealthStatus::Fail,
            ReplayHealthStatus::Unknown,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: ReplayHealthStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn recovery_status_serde_all_variants() {
        for v in [
            RecoveryStatus::Recovering,
            RecoveryStatus::Recovered,
            RecoveryStatus::Waived,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: RecoveryStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn schema_compatibility_status_serde_all_variants() {
        for v in [
            SchemaCompatibilityStatus::Unknown,
            SchemaCompatibilityStatus::Compatible,
            SchemaCompatibilityStatus::NeedsMigration,
            SchemaCompatibilityStatus::Incompatible,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: SchemaCompatibilityStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn declassification_outcome_serde_all_variants() {
        for v in [
            DeclassificationOutcome::Approved,
            DeclassificationOutcome::Denied,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: DeclassificationOutcome = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn confinement_status_serde_all_variants() {
        for v in [
            ConfinementStatus::Full,
            ConfinementStatus::Partial,
            ConfinementStatus::Degraded,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: ConfinementStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn replacement_risk_level_serde_all_variants() {
        for v in [
            ReplacementRiskLevel::Low,
            ReplacementRiskLevel::Medium,
            ReplacementRiskLevel::High,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: ReplacementRiskLevel = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn rollback_status_serde_all_variants() {
        for v in [
            RollbackStatus::Investigating,
            RollbackStatus::Resolved,
            RollbackStatus::Waived,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: RollbackStatus = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn proof_inventory_kind_serde_all_variants() {
        for v in [
            ProofInventoryKind::CapabilityWitness,
            ProofInventoryKind::FlowProof,
            ProofInventoryKind::ReplayMotif,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: ProofInventoryKind = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn proof_specialization_invalidation_reason_serde_all_variants() {
        for v in [
            ProofSpecializationInvalidationReason::EpochChange,
            ProofSpecializationInvalidationReason::ProofExpired,
            ProofSpecializationInvalidationReason::ProofRevoked,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: ProofSpecializationInvalidationReason = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, back);
        }
    }

    #[test]
    fn specialization_fallback_reason_serde_all_variants() {
        for v in [
            SpecializationFallbackReason::ProofUnavailable,
            SpecializationFallbackReason::ProofExpired,
            SpecializationFallbackReason::ProofRevoked,
            SpecializationFallbackReason::ValidationFailed,
        ] {
            let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
            let back: SpecializationFallbackReason = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn dashboard_metric_view_custom_unit_roundtrip() {
        let m = DashboardMetricView {
            metric: "latency_p99".into(),
            value: 42_000,
            unit: "ms".into(),
        };
        let json = serde_json::to_string(&m).expect("serde deserialization should succeed");
        let back: DashboardMetricView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(m, back);
    }

    #[test]
    fn extension_status_row_fields_roundtrip() {
        let row = ExtensionStatusRow {
            extension_id: "ext-001".into(),
            state: "active".into(),
            trust_level: "trusted".into(),
        };
        let json = serde_json::to_string(&row).expect("serde deserialization should succeed");
        let back: ExtensionStatusRow = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(row, back);
    }

    #[test]
    fn blocked_promotion_view_serde_roundtrip() {
        let bpv = BlockedPromotionView {
            slot_id: "scheduler".into(),
            gate_failure_code: "FE-1001".into(),
            failure_detail: "failing equivalence".into(),
            recommended_remediation: "fix tests".into(),
            lineage_ref: "lineage-001".into(),
            evidence_ref: "evidence-001".into(),
        };
        let json = serde_json::to_string(&bpv).expect("serde deserialization should succeed");
        let back: BlockedPromotionView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(bpv, back);
    }

    #[test]
    fn replacement_opportunity_view_serde_roundtrip() {
        let rov = ReplacementOpportunityView {
            slot_id: "parser".into(),
            slot_kind: "parser".into(),
            expected_value_score_millionths: 700_000,
            performance_uplift_millionths: 500_000,
            invocation_frequency_per_minute: 1000,
            risk_reduction_millionths: 200_000,
            rationale: "high-value slot".into(),
        };
        let json = serde_json::to_string(&rov).expect("serde deserialization should succeed");
        let back: ReplacementOpportunityView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(rov, back);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn safe_mode_activation_view_serde_roundtrip() {
        let view = SafeModeActivationView {
            activation_id: "act-001".into(),
            activation_type: "emergency".into(),
            extension_id: "ext-001".into(),
            region_id: "region-001".into(),
            severity: DashboardSeverity::Critical,
            recovery_status: RecoveryStatus::Recovered,
            activated_at_unix_ms: 1000,
            recovered_at_unix_ms: Some(2000),
        };
        let json = serde_json::to_string(&view).expect("serde deserialization should succeed");
        let back: SafeModeActivationView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(view, back);
    }

    #[test]
    fn replay_health_panel_view_serde_roundtrip() {
        let view = ReplayHealthPanelView {
            last_run_status: ReplayHealthStatus::Pass,
            divergence_count: 3,
            last_replay_timestamp_unix_ms: Some(9000),
        };
        let json = serde_json::to_string(&view).expect("serde deserialization should succeed");
        let back: ReplayHealthPanelView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(view, back);
    }

    #[test]
    fn benchmark_trends_panel_view_serde_roundtrip() {
        let view = BenchmarkTrendsPanelView {
            points: vec![BenchmarkTrendPointView {
                timestamp_unix_ms: 100,
                throughput_tps: 5000,
                latency_p95_ms: 12,
                memory_peak_mb: 256,
            }],
            throughput_floor_tps: 1000,
            latency_p95_ceiling_ms: 50,
            memory_peak_ceiling_mb: 512,
        };
        let json = serde_json::to_string(&view).expect("serde deserialization should succeed");
        let back: BenchmarkTrendsPanelView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(view, back);
    }

    #[test]
    fn region_lifecycle_row_view_serde_roundtrip() {
        let view = RegionLifecycleRowView {
            region_id: "region-001".into(),
            is_active: true,
            active_extensions: 5,
            created_at_unix_ms: 1000,
            closed_at_unix_ms: None,
            quiescent_close_time_ms: None,
        };
        let json = serde_json::to_string(&view).expect("serde deserialization should succeed");
        let back: RegionLifecycleRowView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(view, back);
    }

    #[test]
    fn region_lifecycle_panel_view_default_all_zero() {
        let panel = RegionLifecyclePanelView::default();
        assert_eq!(panel.active_region_count, 0);
        assert_eq!(panel.region_creations_in_window, 0);
        assert_eq!(panel.region_destructions_in_window, 0);
        assert_eq!(panel.average_quiescent_close_time_ms, 0);
    }

    #[test]
    fn region_lifecycle_panel_view_serde_roundtrip() {
        let panel = RegionLifecyclePanelView {
            active_region_count: 3,
            region_creations_in_window: 5,
            region_destructions_in_window: 2,
            average_quiescent_close_time_ms: 150,
        };
        let json = serde_json::to_string(&panel).expect("serde deserialization should succeed");
        let back: RegionLifecyclePanelView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(panel, back);
    }

    #[test]
    fn replay_health_panel_view_default_divergence_zero() {
        let panel = ReplayHealthPanelView::default();
        assert_eq!(panel.divergence_count, 0);
        assert_eq!(panel.last_replay_timestamp_unix_ms, None);
    }

    #[test]
    fn safe_mode_activation_view_none_recovered_at() {
        let view = SafeModeActivationView {
            activation_id: "act-002".into(),
            activation_type: "graceful".into(),
            extension_id: "ext-002".into(),
            region_id: "region-002".into(),
            severity: DashboardSeverity::Warning,
            recovery_status: RecoveryStatus::Recovering,
            activated_at_unix_ms: 5000,
            recovered_at_unix_ms: None,
        };
        let json = serde_json::to_string(&view).expect("serde deserialization should succeed");
        assert!(json.contains("\"recovered_at_unix_ms\":null"));
        let back: SafeModeActivationView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(view, back);
    }

    #[test]
    fn policy_explanation_card_from_partial_none_defaults_zero() {
        let partial = PolicyExplanationPartial {
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            selected_action: "allow".into(),
            confidence_millionths: None,
            expected_loss_millionths: None,
            action_candidates: Vec::new(),
            key_drivers: Vec::new(),
        };
        let card = PolicyExplanationCardView::from_partial(partial);
        assert_eq!(card.confidence_millionths, 0);
        assert_eq!(card.expected_loss_millionths, 0);
    }

    #[test]
    fn control_dashboard_from_partial_blank_zone_becomes_unknown() {
        let partial = ControlDashboardPartial {
            cluster: "   ".into(),
            zone: "".into(),
            security_epoch: None,
            runtime_mode: " ".into(),
            metrics: Vec::new(),
            extension_rows: Vec::new(),
            incident_counts: BTreeMap::new(),
        };
        let view = ControlDashboardView::from_partial(partial);
        assert_eq!(view.cluster, "unknown");
        assert_eq!(view.zone, "unknown");
        assert_eq!(view.runtime_mode, "unknown");
        assert_eq!(view.security_epoch, 0);
    }

    #[test]
    fn dashboard_alert_metric_serde_all_variants() {
        let variants = [
            DashboardAlertMetric::ObligationFailureRateMillionths,
            DashboardAlertMetric::ReplayDivergenceCount,
            DashboardAlertMetric::SafeModeActivationCount,
            DashboardAlertMetric::CancellationEventCount,
            DashboardAlertMetric::FallbackActivationCount,
        ];
        let mut names = std::collections::BTreeSet::new();
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde deserialization should succeed");
            let back: DashboardAlertMetric = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, &back);
            names.insert(json);
        }
        assert_eq!(names.len(), variants.len());
    }

    #[test]
    fn threshold_comparator_serde_all_variants() {
        let variants = [
            ThresholdComparator::GreaterThan,
            ThresholdComparator::GreaterOrEqual,
            ThresholdComparator::LessThan,
            ThresholdComparator::LessOrEqual,
            ThresholdComparator::Equal,
        ];
        let mut names = std::collections::BTreeSet::new();
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde deserialization should succeed");
            let back: ThresholdComparator = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
            assert_eq!(v, &back);
            names.insert(json);
        }
        assert_eq!(names.len(), variants.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: PearlTower 2026-02-26 — helper function coverage
    // -----------------------------------------------------------------------

    #[test]
    fn compute_over_privilege_ratio_zero_total_returns_zero() {
        assert_eq!(compute_over_privilege_ratio_millionths(0, 0), 0);
        assert_eq!(compute_over_privilege_ratio_millionths(0, 5), 0);
    }

    #[test]
    fn compute_over_privilege_ratio_all_over_privileged() {
        assert_eq!(compute_over_privilege_ratio_millionths(4, 4), 1_000_000);
    }

    #[test]
    fn compute_over_privilege_ratio_half() {
        assert_eq!(compute_over_privilege_ratio_millionths(10, 5), 500_000);
    }

    #[test]
    fn derive_batch_review_queue_empty_rows() {
        let queue = derive_capability_batch_review_queue(&[], 1000);
        assert!(queue.is_empty());
    }

    #[test]
    fn derive_batch_review_queue_counts_over_privileged() {
        let rows = vec![
            CurrentCapabilityDeltaRowView {
                extension_id: "ext-a".into(),
                witness_id: "w-1".into(),
                policy_id: "p-1".into(),
                witness_epoch: 1,
                lifecycle_state: "active".into(),
                active_witness_capabilities: vec!["cap-a".into()],
                manifest_declared_capabilities: vec!["cap-a".into()],
                over_privileged_capabilities: vec!["cap-x".into()],
                over_privilege_ratio_millionths: 500_000,
                over_privilege_replay_ref: "ref-1".into(),
                latest_receipt_timestamp_ns: None,
            },
            CurrentCapabilityDeltaRowView {
                extension_id: "ext-b".into(),
                witness_id: "w-2".into(),
                policy_id: "p-2".into(),
                witness_epoch: 1,
                lifecycle_state: "active".into(),
                active_witness_capabilities: vec![],
                manifest_declared_capabilities: vec![],
                over_privileged_capabilities: vec![],
                over_privilege_ratio_millionths: 0,
                over_privilege_replay_ref: "ref-2".into(),
                latest_receipt_timestamp_ns: None,
            },
        ];
        let queue = derive_capability_batch_review_queue(&rows, 5000);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].pending_review_count, 1); // only ext-a has ratio > 0
        assert_eq!(queue[0].extension_ids.len(), 2);
    }

    #[test]
    fn is_override_decision_kind_matches_override() {
        assert!(is_override_decision_kind("operator_override"));
        assert!(is_override_decision_kind("OVERRIDE"));
        assert!(is_override_decision_kind("emergency_grant_override"));
    }

    #[test]
    fn is_override_decision_kind_matches_emergency_grant() {
        assert!(is_override_decision_kind("emergency_grant"));
        assert!(is_override_decision_kind("EMERGENCY_GRANT"));
    }

    #[test]
    fn is_override_decision_kind_rejects_normal() {
        assert!(!is_override_decision_kind("allow"));
        assert!(!is_override_decision_kind("deny"));
        assert!(!is_override_decision_kind("standard_review"));
    }

    #[test]
    fn derive_override_review_status_reject() {
        assert_eq!(
            derive_override_review_status("rejected"),
            OverrideReviewStatus::Rejected
        );
        assert_eq!(
            derive_override_review_status("DENY"),
            OverrideReviewStatus::Rejected
        );
    }

    #[test]
    fn derive_override_review_status_waive() {
        assert_eq!(
            derive_override_review_status("waived"),
            OverrideReviewStatus::Waived
        );
    }

    #[test]
    fn derive_override_review_status_approve() {
        assert_eq!(
            derive_override_review_status("approved"),
            OverrideReviewStatus::Approved
        );
        assert_eq!(
            derive_override_review_status("granted"),
            OverrideReviewStatus::Approved
        );
    }

    #[test]
    fn derive_override_review_status_pending_fallback() {
        assert_eq!(
            derive_override_review_status("unknown_outcome"),
            OverrideReviewStatus::Pending
        );
    }

    #[test]
    fn build_override_rationale_active_grant() {
        let event = CapabilityDeltaEscrowEventView {
            receipt_id: "r-1".into(),
            extension_id: "ext-1".into(),
            capability: Some("fs.read".into()),
            decision_kind: "override".into(),
            outcome: "approved".into(),
            trace_id: "trace-1".into(),
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            error_code: None,
            timestamp_ns: 100_000_000_000, // 100_000 ms
            receipt_ref: "ref-r".into(),
            replay_ref: "ref-replay".into(),
        };
        // generated_at is close to requested, so grant is Active
        let rationale = build_override_rationale_from_escrow_event(&event, Some(100_500));
        assert_eq!(rationale.review_status, OverrideReviewStatus::Approved);
        assert_eq!(rationale.grant_expiry_status, GrantExpiryStatus::Active);
        assert!(rationale.expires_at_unix_ms.is_some());
        assert_eq!(rationale.requested_at_unix_ms, 100_000);
    }

    #[test]
    fn build_override_rationale_expired_grant() {
        let event = CapabilityDeltaEscrowEventView {
            receipt_id: "r-2".into(),
            extension_id: "ext-2".into(),
            capability: None,
            decision_kind: "emergency_grant".into(),
            outcome: "approved".into(),
            trace_id: "trace-2".into(),
            decision_id: "d-2".into(),
            policy_id: "p-2".into(),
            error_code: None,
            timestamp_ns: 100_000_000_000, // 100_000 ms
            receipt_ref: "ref-r2".into(),
            replay_ref: "ref-replay2".into(),
        };
        // generated_at is way past the 86400s TTL
        let rationale =
            build_override_rationale_from_escrow_event(&event, Some(100_000 + 86_400_001));
        assert_eq!(rationale.grant_expiry_status, GrantExpiryStatus::Expired);
    }

    #[test]
    fn build_override_rationale_expiring_soon() {
        let event = CapabilityDeltaEscrowEventView {
            receipt_id: "r-3".into(),
            extension_id: "ext-3".into(),
            capability: Some("net.connect".into()),
            decision_kind: "override".into(),
            outcome: "approved".into(),
            trace_id: "trace-3".into(),
            decision_id: "d-3".into(),
            policy_id: "p-3".into(),
            error_code: None,
            timestamp_ns: 100_000_000_000,
            receipt_ref: "ref-r3".into(),
            replay_ref: "ref-replay3".into(),
        };
        // 30 minutes before expiry (within 1 hour window)
        let expires_at = 100_000 + 86_400_000;
        let now = expires_at - 1_800_000; // 30 minutes before
        let rationale = build_override_rationale_from_escrow_event(&event, Some(now));
        assert_eq!(
            rationale.grant_expiry_status,
            GrantExpiryStatus::ExpiringSoon
        );
    }

    #[test]
    fn build_override_rationale_outcome_expired_string() {
        let event = CapabilityDeltaEscrowEventView {
            receipt_id: "r-4".into(),
            extension_id: "ext-4".into(),
            capability: None,
            decision_kind: "override".into(),
            outcome: "expired_auto".into(),
            trace_id: "trace-4".into(),
            decision_id: "d-4".into(),
            policy_id: "p-4".into(),
            error_code: None,
            timestamp_ns: 100_000_000_000,
            receipt_ref: "ref-r4".into(),
            replay_ref: "ref-replay4".into(),
        };
        let rationale = build_override_rationale_from_escrow_event(&event, Some(100_500));
        assert_eq!(rationale.grant_expiry_status, GrantExpiryStatus::Expired);
    }

    #[test]
    fn compute_capability_delta_alerts_high_escrow() {
        let escrow = vec![
            CapabilityDeltaEscrowEventView {
                receipt_id: "r1".into(),
                extension_id: "ext-a".into(),
                capability: None,
                decision_kind: "allow".into(),
                outcome: "ok".into(),
                trace_id: "t1".into(),
                decision_id: "d1".into(),
                policy_id: "p1".into(),
                error_code: None,
                timestamp_ns: 1000,
                receipt_ref: "rr1".into(),
                replay_ref: "rp1".into(),
            },
            CapabilityDeltaEscrowEventView {
                receipt_id: "r2".into(),
                extension_id: "ext-a".into(),
                capability: None,
                decision_kind: "allow".into(),
                outcome: "ok".into(),
                trace_id: "t2".into(),
                decision_id: "d2".into(),
                policy_id: "p2".into(),
                error_code: None,
                timestamp_ns: 2000,
                receipt_ref: "rr2".into(),
                replay_ref: "rp2".into(),
            },
        ];
        let alerts = compute_capability_delta_alerts(&[], &escrow, &[], 5000, 2, 10);
        assert!(alerts.iter().any(|a| a.alert_id.contains("high-escrow")));
    }

    #[test]
    fn compute_capability_delta_alerts_over_privilege() {
        let current = vec![CurrentCapabilityDeltaRowView {
            extension_id: "ext-a".into(),
            witness_id: "w-1".into(),
            policy_id: "p-1".into(),
            witness_epoch: 1,
            lifecycle_state: "active".into(),
            active_witness_capabilities: vec![],
            manifest_declared_capabilities: vec![],
            over_privileged_capabilities: vec!["cap-x".into()],
            over_privilege_ratio_millionths: 300_000, // above 250k = Critical
            over_privilege_replay_ref: "ref-1".into(),
            latest_receipt_timestamp_ns: None,
        }];
        let alerts = compute_capability_delta_alerts(&current, &[], &[], 5000, 100, 100);
        let alert = alerts
            .iter()
            .find(|a| a.alert_id.contains("over-privilege"))
            .expect("serde deserialization should succeed");
        assert_eq!(alert.severity, DashboardSeverity::Critical);
    }

    #[test]
    fn compute_capability_delta_alerts_pending_overrides() {
        let overrides = vec![
            OverrideRationaleView {
                override_id: "o-1".into(),
                extension_id: "ext-1".into(),
                capability: None,
                rationale: "test".into(),
                signed_justification_ref: "ref-1".into(),
                review_status: OverrideReviewStatus::Pending,
                grant_expiry_status: GrantExpiryStatus::Active,
                requested_at_unix_ms: 1000,
                reviewed_at_unix_ms: None,
                expires_at_unix_ms: Some(90000),
                receipt_ref: "rr-1".into(),
                replay_ref: "rp-1".into(),
            },
            OverrideRationaleView {
                override_id: "o-2".into(),
                extension_id: "ext-2".into(),
                capability: None,
                rationale: "test".into(),
                signed_justification_ref: "ref-2".into(),
                review_status: OverrideReviewStatus::Pending,
                grant_expiry_status: GrantExpiryStatus::Active,
                requested_at_unix_ms: 2000,
                reviewed_at_unix_ms: None,
                expires_at_unix_ms: Some(90000),
                receipt_ref: "rr-2".into(),
                replay_ref: "rp-2".into(),
            },
        ];
        let alerts = compute_capability_delta_alerts(&[], &[], &overrides, 5000, 100, 2);
        assert!(
            alerts
                .iter()
                .any(|a| a.alert_id == "pending-override-reviews")
        );
    }

    #[test]
    fn compute_capability_delta_alerts_expired_overrides() {
        let overrides = vec![OverrideRationaleView {
            override_id: "o-3".into(),
            extension_id: "ext-3".into(),
            capability: None,
            rationale: "test".into(),
            signed_justification_ref: "ref-3".into(),
            review_status: OverrideReviewStatus::Approved,
            grant_expiry_status: GrantExpiryStatus::Expired,
            requested_at_unix_ms: 1000,
            reviewed_at_unix_ms: Some(1100),
            expires_at_unix_ms: Some(2000),
            receipt_ref: "rr-3".into(),
            replay_ref: "rp-3".into(),
        }];
        let alerts = compute_capability_delta_alerts(&[], &[], &overrides, 5000, 100, 100);
        assert!(
            alerts
                .iter()
                .any(|a| a.alert_id == "expired-emergency-grants")
        );
        let alert = alerts
            .iter()
            .find(|a| a.alert_id == "expired-emergency-grants")
            .expect("serde deserialization should succeed");
        assert_eq!(alert.severity, DashboardSeverity::Critical);
    }

    #[test]
    fn compute_capability_delta_alerts_expiring_soon() {
        let overrides = vec![OverrideRationaleView {
            override_id: "o-4".into(),
            extension_id: "ext-4".into(),
            capability: None,
            rationale: "test".into(),
            signed_justification_ref: "ref-4".into(),
            review_status: OverrideReviewStatus::Approved,
            grant_expiry_status: GrantExpiryStatus::ExpiringSoon,
            requested_at_unix_ms: 1000,
            reviewed_at_unix_ms: Some(1100),
            expires_at_unix_ms: Some(90000),
            receipt_ref: "rr-4".into(),
            replay_ref: "rp-4".into(),
        }];
        let alerts = compute_capability_delta_alerts(&[], &[], &overrides, 5000, 100, 100);
        assert!(
            alerts
                .iter()
                .any(|a| a.alert_id == "expiring-emergency-grants")
        );
    }

    #[test]
    fn compute_proof_specialization_alerts_bulk_invalidation() {
        let invalidations = vec![
            SpecializationInvalidationRowView {
                invalidation_id: "inv-1".into(),
                specialization_id: "s-1".into(),
                target_id: "t-1".into(),
                reason: ProofSpecializationInvalidationReason::EpochChange,
                reason_detail: "epoch changed".into(),
                proof_id: Some("p-1".into()),
                old_epoch_id: Some(1),
                new_epoch_id: Some(2),
                fallback_confirmed: true,
                fallback_confirmation_ref: "ref-fb".into(),
                occurred_at_unix_ms: 1000,
            },
            SpecializationInvalidationRowView {
                invalidation_id: "inv-2".into(),
                specialization_id: "s-2".into(),
                target_id: "t-2".into(),
                reason: ProofSpecializationInvalidationReason::ProofRevoked,
                reason_detail: "revoked".into(),
                proof_id: None,
                old_epoch_id: None,
                new_epoch_id: None,
                fallback_confirmed: false,
                fallback_confirmation_ref: "ref-fb2".into(),
                occurred_at_unix_ms: 2000,
            },
        ];
        let alerts = compute_proof_specialization_alerts(&invalidations, 800_000, 5000, 2, 500_000);
        assert!(alerts.iter().any(|a| a.alert_id == "bulk-invalidation"));
    }

    #[test]
    fn compute_proof_specialization_alerts_degraded_coverage() {
        let alerts = compute_proof_specialization_alerts(&[], 200_000, 5000, 100, 500_000);
        assert!(
            alerts
                .iter()
                .any(|a| a.alert_id == "specialization-coverage-degraded")
        );
        let alert = alerts
            .iter()
            .find(|a| a.alert_id == "specialization-coverage-degraded")
            .expect("serde deserialization should succeed");
        // 200k < 500k/2 = 250k, so Critical
        assert_eq!(alert.severity, DashboardSeverity::Critical);
    }

    #[test]
    fn compute_flow_alert_indicators_blocked_threshold() {
        let blocked = vec![
            BlockedFlowView {
                flow_id: "f-1".into(),
                extension_id: "ext-a".into(),
                source_label: "secret".into(),
                sink_clearance: "public".into(),
                sensitivity: FlowSensitivityLevel::High,
                blocked_reason: "no clearance".into(),
                attempted_exfiltration: false,
                code_path_ref: "cp-1".into(),
                extension_context_ref: "ec-1".into(),
                trace_id: "t-1".into(),
                decision_id: "d-1".into(),
                policy_id: "p-1".into(),
                error_code: None,
                occurred_at_unix_ms: 1000,
            },
            BlockedFlowView {
                flow_id: "f-2".into(),
                extension_id: "ext-a".into(),
                source_label: "secret".into(),
                sink_clearance: "public".into(),
                sensitivity: FlowSensitivityLevel::High,
                blocked_reason: "no clearance".into(),
                attempted_exfiltration: false,
                code_path_ref: "cp-2".into(),
                extension_context_ref: "ec-2".into(),
                trace_id: "t-2".into(),
                decision_id: "d-2".into(),
                policy_id: "p-2".into(),
                error_code: None,
                occurred_at_unix_ms: 2000,
            },
        ];
        let alerts = compute_flow_alert_indicators(&blocked, &[], 5000, 2);
        assert!(alerts.iter().any(|a| a.alert_id.contains("blocked-rate")));
    }

    #[test]
    fn compute_flow_alert_indicators_confinement_degraded() {
        let proofs = vec![ConfinementProofView {
            extension_id: "ext-b".into(),
            status: ConfinementStatus::Degraded,
            covered_flow_count: 3,
            uncovered_flow_count: 5,
            proof_rows: vec![],
            uncovered_flow_refs: vec![],
        }];
        let alerts = compute_flow_alert_indicators(&[], &proofs, 5000, 100);
        let alert = alerts
            .iter()
            .find(|a| a.alert_id.contains("confinement"))
            .expect("serde deserialization should succeed");
        assert_eq!(alert.severity, DashboardSeverity::Critical);
    }

    #[test]
    fn compute_flow_alert_indicators_confinement_partial() {
        let proofs = vec![ConfinementProofView {
            extension_id: "ext-c".into(),
            status: ConfinementStatus::Partial,
            covered_flow_count: 8,
            uncovered_flow_count: 2,
            proof_rows: vec![],
            uncovered_flow_refs: vec![],
        }];
        let alerts = compute_flow_alert_indicators(&[], &proofs, 5000, 100);
        let alert = alerts
            .iter()
            .find(|a| a.alert_id.contains("confinement"))
            .expect("serde deserialization should succeed");
        assert_eq!(alert.severity, DashboardSeverity::Warning);
    }

    #[test]
    fn summarize_decision_outcomes_empty() {
        let panel = summarize_decision_outcomes(&[]);
        assert_eq!(panel.allow_count, 0);
        assert_eq!(panel.deny_count, 0);
        assert_eq!(panel.fallback_count, 0);
        assert_eq!(panel.average_expected_loss_millionths, 0);
    }

    #[test]
    fn summarize_decision_outcomes_mixed() {
        let entries = vec![
            EvidenceStreamEntryView {
                trace_id: "t-1".into(),
                decision_id: "d-1".into(),
                policy_id: "p-1".into(),
                action_type: "invoke".into(),
                decision_outcome: DecisionOutcomeKind::Allow,
                expected_loss_millionths: 100_000,
                extension_id: "ext-1".into(),
                region_id: "r-1".into(),
                severity: DashboardSeverity::Info,
                component: "comp".into(),
                event: "ev".into(),
                outcome: "ok".into(),
                error_code: None,
                timestamp_unix_ms: 1000,
            },
            EvidenceStreamEntryView {
                trace_id: "t-2".into(),
                decision_id: "d-2".into(),
                policy_id: "p-2".into(),
                action_type: "invoke".into(),
                decision_outcome: DecisionOutcomeKind::Deny,
                expected_loss_millionths: 300_000,
                extension_id: "ext-2".into(),
                region_id: "r-2".into(),
                severity: DashboardSeverity::Warning,
                component: "comp".into(),
                event: "ev".into(),
                outcome: "denied".into(),
                error_code: None,
                timestamp_unix_ms: 2000,
            },
            EvidenceStreamEntryView {
                trace_id: "t-3".into(),
                decision_id: "d-3".into(),
                policy_id: "p-3".into(),
                action_type: "invoke".into(),
                decision_outcome: DecisionOutcomeKind::Fallback,
                expected_loss_millionths: 200_000,
                extension_id: "ext-3".into(),
                region_id: "r-3".into(),
                severity: DashboardSeverity::Critical,
                component: "comp".into(),
                event: "ev".into(),
                outcome: "fallback".into(),
                error_code: None,
                timestamp_unix_ms: 3000,
            },
        ];
        let panel = summarize_decision_outcomes(&entries);
        assert_eq!(panel.allow_count, 1);
        assert_eq!(panel.deny_count, 1);
        assert_eq!(panel.fallback_count, 1);
        assert_eq!(panel.average_expected_loss_millionths, 200_000);
    }

    #[test]
    fn summarize_obligation_status_mixed() {
        let rows = vec![
            ObligationStatusRowView {
                obligation_id: "ob-1".into(),
                extension_id: "ext-1".into(),
                region_id: "r-1".into(),
                state: ObligationState::Open,
                severity: DashboardSeverity::Info,
                due_at_unix_ms: 5000,
                updated_at_unix_ms: 1000,
                detail: "pending".into(),
            },
            ObligationStatusRowView {
                obligation_id: "ob-2".into(),
                extension_id: "ext-2".into(),
                region_id: "r-2".into(),
                state: ObligationState::Fulfilled,
                severity: DashboardSeverity::Info,
                due_at_unix_ms: 5000,
                updated_at_unix_ms: 2000,
                detail: "done".into(),
            },
            ObligationStatusRowView {
                obligation_id: "ob-3".into(),
                extension_id: "ext-3".into(),
                region_id: "r-3".into(),
                state: ObligationState::Failed,
                severity: DashboardSeverity::Critical,
                due_at_unix_ms: 5000,
                updated_at_unix_ms: 3000,
                detail: "timed out".into(),
            },
        ];
        let panel = summarize_obligation_status(&rows);
        assert_eq!(panel.open_count, 1);
        assert_eq!(panel.fulfilled_count, 1);
        assert_eq!(panel.failed_count, 1);
    }

    #[test]
    fn summarize_region_lifecycle_empty() {
        let panel = summarize_region_lifecycle(&[]);
        assert_eq!(panel.active_region_count, 0);
        assert_eq!(panel.region_creations_in_window, 0);
        assert_eq!(panel.region_destructions_in_window, 0);
        assert_eq!(panel.average_quiescent_close_time_ms, 0);
    }

    #[test]
    fn summarize_region_lifecycle_mixed() {
        let rows = vec![
            RegionLifecycleRowView {
                region_id: "r-1".into(),
                is_active: true,
                active_extensions: 3,
                created_at_unix_ms: 1000,
                closed_at_unix_ms: None,
                quiescent_close_time_ms: None,
            },
            RegionLifecycleRowView {
                region_id: "r-2".into(),
                is_active: false,
                active_extensions: 0,
                created_at_unix_ms: 500,
                closed_at_unix_ms: Some(800),
                quiescent_close_time_ms: Some(100),
            },
            RegionLifecycleRowView {
                region_id: "r-3".into(),
                is_active: false,
                active_extensions: 0,
                created_at_unix_ms: 200,
                closed_at_unix_ms: Some(600),
                quiescent_close_time_ms: Some(300),
            },
        ];
        let panel = summarize_region_lifecycle(&rows);
        assert_eq!(panel.active_region_count, 1);
        assert_eq!(panel.region_creations_in_window, 3);
        assert_eq!(panel.region_destructions_in_window, 2);
        assert_eq!(panel.average_quiescent_close_time_ms, 200); // (100+300)/2
    }

    #[test]
    fn dashboard_metric_value_obligation_failure_rate() {
        let mut view =
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                cluster: "c".into(),
                zone: "z".into(),
                runtime_mode: "m".into(),
                obligation_status: Some(ObligationStatusPanelView {
                    open_count: 0,
                    fulfilled_count: 7,
                    failed_count: 3,
                }),
                ..Default::default()
            });
        // Shouldn't need to use `view` mutably, just read it
        let _ = &mut view; // suppress unused warning
        let rate =
            dashboard_metric_value(&view, DashboardAlertMetric::ObligationFailureRateMillionths);
        // 3 / 10 = 300_000 millionths
        assert_eq!(rate, 300_000);
    }

    #[test]
    fn dashboard_metric_value_obligation_failure_rate_zero_total() {
        let view = ControlPlaneInvariantsDashboardView::from_partial(
            ControlPlaneInvariantsPartial::default(),
        );
        let rate =
            dashboard_metric_value(&view, DashboardAlertMetric::ObligationFailureRateMillionths);
        assert_eq!(rate, 0);
    }

    #[test]
    fn dashboard_metric_value_replay_divergence_count() {
        let view =
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                cluster: "c".into(),
                zone: "z".into(),
                runtime_mode: "m".into(),
                replay_health: Some(ReplayHealthPanelView {
                    last_run_status: ReplayHealthStatus::Fail,
                    divergence_count: 42,
                    last_replay_timestamp_unix_ms: None,
                }),
                ..Default::default()
            });
        assert_eq!(
            dashboard_metric_value(&view, DashboardAlertMetric::ReplayDivergenceCount),
            42
        );
    }

    #[test]
    fn dashboard_metric_value_safe_mode_activation_count() {
        let view =
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                cluster: "c".into(),
                zone: "z".into(),
                runtime_mode: "m".into(),
                safe_mode_activations: vec![SafeModeActivationView {
                    activation_id: "act-1".into(),
                    activation_type: "emergency".into(),
                    extension_id: "ext-1".into(),
                    region_id: "r-1".into(),
                    severity: DashboardSeverity::Critical,
                    recovery_status: RecoveryStatus::Recovered,
                    activated_at_unix_ms: 1000,
                    recovered_at_unix_ms: Some(2000),
                }],
                ..Default::default()
            });
        assert_eq!(
            dashboard_metric_value(&view, DashboardAlertMetric::SafeModeActivationCount),
            1
        );
    }

    #[test]
    fn dashboard_metric_value_cancellation_event_count() {
        let view =
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                cluster: "c".into(),
                zone: "z".into(),
                runtime_mode: "m".into(),
                cancellation_events: vec![
                    CancellationEventView {
                        extension_id: "ext-1".into(),
                        region_id: "r-1".into(),
                        cancellation_kind: CancellationKind::Quarantine,
                        severity: DashboardSeverity::Warning,
                        detail: "quarantined".into(),
                        timestamp_unix_ms: 1000,
                    },
                    CancellationEventView {
                        extension_id: "ext-2".into(),
                        region_id: "r-2".into(),
                        cancellation_kind: CancellationKind::Terminate,
                        severity: DashboardSeverity::Critical,
                        detail: "terminated".into(),
                        timestamp_unix_ms: 2000,
                    },
                ],
                ..Default::default()
            });
        assert_eq!(
            dashboard_metric_value(&view, DashboardAlertMetric::CancellationEventCount),
            2
        );
    }

    #[test]
    fn dashboard_metric_value_fallback_activation_count() {
        let view =
            ControlPlaneInvariantsDashboardView::from_partial(ControlPlaneInvariantsPartial {
                cluster: "c".into(),
                zone: "z".into(),
                runtime_mode: "m".into(),
                decision_outcomes: Some(DecisionOutcomesPanelView {
                    allow_count: 10,
                    deny_count: 2,
                    fallback_count: 5,
                    average_expected_loss_millionths: 100_000,
                }),
                ..Default::default()
            });
        assert_eq!(
            dashboard_metric_value(&view, DashboardAlertMetric::FallbackActivationCount),
            5
        );
    }

    #[test]
    fn capability_delta_timestamp_in_range() {
        let filter = CapabilityDeltaDashboardFilter {
            start_timestamp_ns: Some(100),
            end_timestamp_ns: Some(500),
            ..Default::default()
        };
        assert!(capability_delta_timestamp_matches_range(200, &filter));
        assert!(!capability_delta_timestamp_matches_range(50, &filter));
        assert!(!capability_delta_timestamp_matches_range(600, &filter));
    }

    #[test]
    fn capability_delta_timestamp_open_ended() {
        let filter = CapabilityDeltaDashboardFilter::default();
        assert!(capability_delta_timestamp_matches_range(0, &filter));
        assert!(capability_delta_timestamp_matches_range(u64::MAX, &filter));
    }

    #[test]
    fn region_row_matches_filter_alive_in_range() {
        let row = RegionLifecycleRowView {
            region_id: "r-1".into(),
            is_active: true,
            active_extensions: 3,
            created_at_unix_ms: 100,
            closed_at_unix_ms: None,
            quiescent_close_time_ms: None,
        };
        let filter = ControlPlaneDashboardFilter {
            start_unix_ms: Some(50),
            end_unix_ms: Some(200),
            ..Default::default()
        };
        assert!(region_row_matches_filter(&row, &filter));
    }

    #[test]
    fn region_row_matches_filter_closed_before_range() {
        let row = RegionLifecycleRowView {
            region_id: "r-2".into(),
            is_active: false,
            active_extensions: 0,
            created_at_unix_ms: 100,
            closed_at_unix_ms: Some(150),
            quiescent_close_time_ms: Some(50),
        };
        let filter = ControlPlaneDashboardFilter {
            start_unix_ms: Some(200),
            end_unix_ms: Some(500),
            ..Default::default()
        };
        assert!(!region_row_matches_filter(&row, &filter));
    }

    #[test]
    fn region_row_matches_filter_created_after_range() {
        let row = RegionLifecycleRowView {
            region_id: "r-3".into(),
            is_active: true,
            active_extensions: 1,
            created_at_unix_ms: 600,
            closed_at_unix_ms: None,
            quiescent_close_time_ms: None,
        };
        let filter = ControlPlaneDashboardFilter {
            start_unix_ms: Some(100),
            end_unix_ms: Some(500),
            ..Default::default()
        };
        assert!(!region_row_matches_filter(&row, &filter));
    }

    #[test]
    fn confinement_proof_filter_critical_sensitivity_full_excluded() {
        let proof = ConfinementProofView {
            extension_id: "ext-a".into(),
            status: ConfinementStatus::Full,
            covered_flow_count: 10,
            uncovered_flow_count: 0,
            proof_rows: vec![],
            uncovered_flow_refs: vec![],
        };
        let filter = FlowDecisionDashboardFilter {
            sensitivity: Some(FlowSensitivityLevel::Critical),
            ..Default::default()
        };
        assert!(!confinement_proof_matches_filter(&proof, &filter));
    }

    #[test]
    fn confinement_proof_filter_critical_sensitivity_degraded_included() {
        let proof = ConfinementProofView {
            extension_id: "ext-b".into(),
            status: ConfinementStatus::Degraded,
            covered_flow_count: 5,
            uncovered_flow_count: 5,
            proof_rows: vec![],
            uncovered_flow_refs: vec![],
        };
        let filter = FlowDecisionDashboardFilter {
            sensitivity: Some(FlowSensitivityLevel::Critical),
            ..Default::default()
        };
        assert!(confinement_proof_matches_filter(&proof, &filter));
    }

    #[test]
    fn expected_value_score_perf_and_risk_combined() {
        let input = ReplacementOpportunityInput {
            slot_id: "s".into(),
            slot_kind: "k".into(),
            performance_uplift_millionths: 500_000,
            invocation_frequency_per_minute: 99,
            risk_reduction_millionths: 200_000,
        };
        let score = compute_expected_value_score_millionths(&input);
        // perf = 500_000 * (99+1) / 100 = 500_000
        // risk = 200_000 * 3 = 600_000
        // total = 1_100_000
        assert_eq!(score, 1_100_000);
    }

    #[test]
    fn proof_specialization_alerts_no_alerts_when_healthy() {
        let alerts = compute_proof_specialization_alerts(&[], 900_000, 5000, 10, 500_000);
        assert!(alerts.is_empty());
    }

    #[test]
    fn flow_alert_indicators_confinement_full_no_alert() {
        let proofs = vec![ConfinementProofView {
            extension_id: "ext-ok".into(),
            status: ConfinementStatus::Full,
            covered_flow_count: 10,
            uncovered_flow_count: 0,
            proof_rows: vec![],
            uncovered_flow_refs: vec![],
        }];
        let alerts = compute_flow_alert_indicators(&[], &proofs, 5000, 100);
        assert!(alerts.is_empty());
    }

    #[test]
    fn capability_delta_escrow_filter_by_outcome() {
        let event = CapabilityDeltaEscrowEventView {
            receipt_id: "r-1".into(),
            extension_id: "ext-1".into(),
            capability: Some("fs.read".into()),
            decision_kind: "allow".into(),
            outcome: "granted".into(),
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            error_code: None,
            timestamp_ns: 5000,
            receipt_ref: "rr-1".into(),
            replay_ref: "rp-1".into(),
        };
        let matching_filter = CapabilityDeltaDashboardFilter {
            outcome: Some("granted".into()),
            ..Default::default()
        };
        assert!(capability_delta_escrow_row_matches_filter(
            &event,
            &matching_filter
        ));

        let non_matching_filter = CapabilityDeltaDashboardFilter {
            outcome: Some("denied".into()),
            ..Default::default()
        };
        assert!(!capability_delta_escrow_row_matches_filter(
            &event,
            &non_matching_filter
        ));
    }

    #[test]
    fn capability_delta_override_filter_by_grant_expiry() {
        let row = OverrideRationaleView {
            override_id: "o-1".into(),
            extension_id: "ext-1".into(),
            capability: Some("net.listen".into()),
            rationale: "emergency".into(),
            signed_justification_ref: "ref".into(),
            review_status: OverrideReviewStatus::Approved,
            grant_expiry_status: GrantExpiryStatus::ExpiringSoon,
            requested_at_unix_ms: 1000,
            reviewed_at_unix_ms: Some(1100),
            expires_at_unix_ms: Some(90000),
            receipt_ref: "rr".into(),
            replay_ref: "rp".into(),
        };
        let filter = CapabilityDeltaDashboardFilter {
            grant_expiry_status: Some(GrantExpiryStatus::ExpiringSoon),
            ..Default::default()
        };
        assert!(capability_delta_override_row_matches_filter(&row, &filter));

        let filter2 = CapabilityDeltaDashboardFilter {
            grant_expiry_status: Some(GrantExpiryStatus::Active),
            ..Default::default()
        };
        assert!(!capability_delta_override_row_matches_filter(
            &row, &filter2
        ));
    }

    #[test]
    fn proof_specialization_row_filter_by_optimization_class() {
        let row = ActiveSpecializationRowView {
            specialization_id: "s-1".into(),
            target_id: "t-1".into(),
            target_kind: "function".into(),
            optimization_class: "inlining".into(),
            latency_reduction_millionths: 100_000,
            throughput_increase_millionths: 50_000,
            proof_input_ids: vec!["proof-a".into()],
            transformation_ref: "tr-1".into(),
            receipt_ref: "rr-1".into(),
            activated_at_unix_ms: 1000,
        };
        let filter = ProofSpecializationDashboardFilter {
            optimization_class: Some("inlining".into()),
            ..Default::default()
        };
        assert!(proof_specialization_row_matches_filter(&row, &filter));

        let filter2 = ProofSpecializationDashboardFilter {
            optimization_class: Some("devirtualization".into()),
            ..Default::default()
        };
        assert!(!proof_specialization_row_matches_filter(&row, &filter2));
    }

    #[test]
    fn proof_specialization_row_filter_by_proof_id() {
        let row = ActiveSpecializationRowView {
            specialization_id: "s-1".into(),
            target_id: "t-1".into(),
            target_kind: "function".into(),
            optimization_class: "inlining".into(),
            latency_reduction_millionths: 0,
            throughput_increase_millionths: 0,
            proof_input_ids: vec!["proof-a".into(), "proof-b".into()],
            transformation_ref: "tr-1".into(),
            receipt_ref: "rr-1".into(),
            activated_at_unix_ms: 1000,
        };
        let filter = ProofSpecializationDashboardFilter {
            proof_id: Some("proof-b".into()),
            ..Default::default()
        };
        assert!(proof_specialization_row_matches_filter(&row, &filter));

        let filter2 = ProofSpecializationDashboardFilter {
            proof_id: Some("proof-z".into()),
            ..Default::default()
        };
        assert!(!proof_specialization_row_matches_filter(&row, &filter2));
    }

    #[test]
    fn blocked_flow_filter_by_sensitivity() {
        let flow = BlockedFlowView {
            flow_id: "f-1".into(),
            extension_id: "ext-1".into(),
            source_label: "secret".into(),
            sink_clearance: "public".into(),
            sensitivity: FlowSensitivityLevel::High,
            blocked_reason: "no clearance".into(),
            attempted_exfiltration: false,
            code_path_ref: "cp".into(),
            extension_context_ref: "ec".into(),
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            error_code: None,
            occurred_at_unix_ms: 1000,
        };
        let filter = FlowDecisionDashboardFilter {
            sensitivity: Some(FlowSensitivityLevel::High),
            ..Default::default()
        };
        assert!(blocked_flow_matches_filter(&flow, &filter));

        let filter2 = FlowDecisionDashboardFilter {
            sensitivity: Some(FlowSensitivityLevel::Low),
            ..Default::default()
        };
        assert!(!blocked_flow_matches_filter(&flow, &filter2));
    }

    #[test]
    fn slot_row_filter_by_risk_level() {
        let row = SlotStatusOverviewRow {
            slot_id: "s-1".into(),
            slot_kind: "parser".into(),
            implementation_kind: "native".into(),
            promotion_status: "promoted".into(),
            risk_level: ReplacementRiskLevel::High,
            last_transition_unix_ms: 1000,
            health: "healthy".into(),
            lineage_ref: "lin-1".into(),
        };
        let filter = ReplacementDashboardFilter {
            risk_level: Some(ReplacementRiskLevel::High),
            ..Default::default()
        };
        assert!(slot_row_matches_filter(&row, &filter));

        let filter2 = ReplacementDashboardFilter {
            risk_level: Some(ReplacementRiskLevel::Low),
            ..Default::default()
        };
        assert!(!slot_row_matches_filter(&row, &filter2));
    }

    // -- Enrichment: PearlTower 2026-02-26 session 4 --

    #[test]
    fn replay_snapshot_non_empty_events_is_complete() {
        let events = vec![ReplayEventView::new(1, "comp", "evt", "ok", 1000)];
        let replay = IncidentReplayView::snapshot("trace-2", "scenario-b", events);
        assert_eq!(replay.replay_status, ReplayStatus::Complete);
        assert!(replay.deterministic);
        assert_eq!(replay.events.len(), 1);
    }

    #[test]
    fn replay_event_view_new_normalizes_empty_fields() {
        let event = ReplayEventView::new(0, "", "  ", "   ", 500);
        assert_eq!(event.component, "unknown");
        assert_eq!(event.event, "unknown");
        assert_eq!(event.outcome, "unknown");
        assert!(event.error_code.is_none());
        assert_eq!(event.sequence, 0);
        assert_eq!(event.timestamp_unix_ms, 500);
    }

    #[test]
    fn adapter_envelope_encode_json_roundtrips() {
        let replay = IncidentReplayView::snapshot("t", "s", vec![]);
        let env = AdapterEnvelope::new(
            "trace-enc",
            42,
            AdapterStream::IncidentReplay,
            UpdateKind::Snapshot,
            FrankentuiViewPayload::IncidentReplay(replay),
        );
        let bytes = env.encode_json().expect("encode");
        let restored: AdapterEnvelope = serde_json::from_slice(&bytes).expect("serde deserialization should succeed");
        assert_eq!(env, restored);
    }

    #[test]
    fn canonicalize_coverage_caps_at_one_million() {
        assert_eq!(canonicalize_coverage_millionths(0), 0);
        assert_eq!(canonicalize_coverage_millionths(500_000), 500_000);
        assert_eq!(canonicalize_coverage_millionths(1_000_000), 1_000_000);
        assert_eq!(canonicalize_coverage_millionths(2_000_000), 1_000_000);
    }

    #[test]
    fn threshold_matches_all_comparators() {
        assert!(threshold_matches(ThresholdComparator::GreaterThan, 5, 3));
        assert!(!threshold_matches(ThresholdComparator::GreaterThan, 3, 3));

        assert!(threshold_matches(ThresholdComparator::GreaterOrEqual, 3, 3));
        assert!(!threshold_matches(
            ThresholdComparator::GreaterOrEqual,
            2,
            3
        ));

        assert!(threshold_matches(ThresholdComparator::LessThan, 2, 3));
        assert!(!threshold_matches(ThresholdComparator::LessThan, 3, 3));

        assert!(threshold_matches(ThresholdComparator::LessOrEqual, 3, 3));
        assert!(!threshold_matches(ThresholdComparator::LessOrEqual, 4, 3));

        assert!(threshold_matches(ThresholdComparator::Equal, 3, 3));
        assert!(!threshold_matches(ThresholdComparator::Equal, 4, 3));
    }

    #[test]
    fn default_enum_values() {
        assert_eq!(DashboardSeverity::default(), DashboardSeverity::Info);
        assert_eq!(ReplayHealthStatus::default(), ReplayHealthStatus::Unknown);
        assert_eq!(RecoveryStatus::default(), RecoveryStatus::Recovering);
        assert_eq!(
            SchemaCompatibilityStatus::default(),
            SchemaCompatibilityStatus::Unknown
        );
        assert_eq!(FlowSensitivityLevel::default(), FlowSensitivityLevel::Low);
        assert_eq!(ProofValidityStatus::default(), ProofValidityStatus::Valid);
        assert_eq!(
            OverrideReviewStatus::default(),
            OverrideReviewStatus::Pending
        );
        assert_eq!(GrantExpiryStatus::default(), GrantExpiryStatus::Active);
    }

    #[test]
    fn build_native_coverage_meter_mixed_slots() {
        let rows = vec![
            SlotStatusOverviewRow {
                slot_id: "s-1".into(),
                slot_kind: "parser".into(),
                implementation_kind: "native".into(),
                promotion_status: "promoted".into(),
                risk_level: ReplacementRiskLevel::Low,
                last_transition_unix_ms: 1000,
                health: "ok".into(),
                lineage_ref: "l".into(),
            },
            SlotStatusOverviewRow {
                slot_id: "s-2".into(),
                slot_kind: "lexer".into(),
                implementation_kind: "delegate".into(),
                promotion_status: "pending".into(),
                risk_level: ReplacementRiskLevel::Medium,
                last_transition_unix_ms: 2000,
                health: "ok".into(),
                lineage_ref: "l".into(),
            },
        ];
        let meter = build_native_coverage_meter(&rows, vec![]);
        assert_eq!(meter.native_slots, 1);
        assert_eq!(meter.delegate_slots, 1);
        assert_eq!(meter.native_coverage_millionths, 500_000);
    }

    #[test]
    fn rank_replacement_opportunities_descending_by_score() {
        let inputs = vec![
            ReplacementOpportunityInput {
                slot_id: "low".into(),
                slot_kind: "parser".into(),
                performance_uplift_millionths: 100,
                invocation_frequency_per_minute: 1,
                risk_reduction_millionths: 10,
            },
            ReplacementOpportunityInput {
                slot_id: "high".into(),
                slot_kind: "lexer".into(),
                performance_uplift_millionths: 500_000,
                invocation_frequency_per_minute: 100,
                risk_reduction_millionths: 200_000,
            },
        ];
        let ranked = rank_replacement_opportunities(inputs);
        assert_eq!(ranked.len(), 2);
        assert_eq!(ranked[0].slot_id, "high");
        assert_eq!(ranked[1].slot_id, "low");
        assert!(
            ranked[0].expected_value_score_millionths > ranked[1].expected_value_score_millionths
        );
        // Rationale includes perf_uplift, freq, risk_reduction
        assert!(ranked[0].rationale.contains("500000"));
        assert!(ranked[0].rationale.contains("100"));
        assert!(ranked[0].rationale.contains("200000"));
    }

    // -- Enrichment: serde roundtrips for untested types (PearlTower 2026-02-27) --

    #[test]
    fn decision_outcomes_panel_view_serde_roundtrip() {
        let v = DecisionOutcomesPanelView {
            allow_count: 100,
            deny_count: 5,
            fallback_count: 2,
            average_expected_loss_millionths: 150_000,
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: DecisionOutcomesPanelView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn obligation_status_panel_view_serde_roundtrip() {
        let v = ObligationStatusPanelView {
            open_count: 10,
            fulfilled_count: 80,
            failed_count: 3,
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: ObligationStatusPanelView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn schema_version_panel_view_serde_roundtrip() {
        let v = SchemaVersionPanelView {
            evidence_schema_version: 3,
            last_migration_unix_ms: Some(1_700_000_000_000),
            compatibility_status: SchemaCompatibilityStatus::Compatible,
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: SchemaVersionPanelView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn benchmark_trend_point_view_serde_roundtrip() {
        let v = BenchmarkTrendPointView {
            timestamp_unix_ms: 1_700_000_000_000,
            throughput_tps: 5000,
            latency_p95_ms: 12,
            memory_peak_mb: 256,
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: BenchmarkTrendPointView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn native_coverage_meter_serde_roundtrip() {
        let v = NativeCoverageMeter {
            native_slots: 8,
            delegate_slots: 2,
            native_coverage_millionths: 800_000,
            trend: vec![CoverageTrendPoint {
                timestamp_unix_ms: 1_000,
                native_coverage_millionths: 750_000,
            }],
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: NativeCoverageMeter = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn replacement_opportunity_input_serde_roundtrip() {
        let v = ReplacementOpportunityInput {
            slot_id: "slot-1".to_string(),
            slot_kind: "parser".to_string(),
            performance_uplift_millionths: 500_000,
            invocation_frequency_per_minute: 100,
            risk_reduction_millionths: 200_000,
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: ReplacementOpportunityInput = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn control_dashboard_view_serde_roundtrip() {
        let v = ControlDashboardView {
            cluster: "prod".to_string(),
            zone: "us-east".to_string(),
            security_epoch: 7,
            runtime_mode: "normal".to_string(),
            metrics: vec![DashboardMetricView {
                metric: "throughput".to_string(),
                value: 5000,
                unit: "tps".to_string(),
            }],
            extension_rows: vec![ExtensionStatusRow {
                extension_id: "ext-a".to_string(),
                state: "active".to_string(),
                trust_level: "trusted".to_string(),
            }],
            incident_counts: {
                let mut m = BTreeMap::new();
                m.insert("high".to_string(), 1);
                m
            },
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: ControlDashboardView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn adapter_envelope_serde_roundtrip() {
        let v = AdapterEnvelope {
            schema_version: 1,
            trace_id: "t-1".to_string(),
            decision_id: Some("d-1".to_string()),
            policy_id: Some("p-1".to_string()),
            generated_at_unix_ms: 1_700_000_000_000,
            stream: AdapterStream::ControlDashboard,
            update_kind: UpdateKind::Snapshot,
            payload: FrankentuiViewPayload::ControlDashboard(ControlDashboardView {
                cluster: "prod".to_string(),
                zone: "us-east".to_string(),
                security_epoch: 7,
                runtime_mode: "normal".to_string(),
                metrics: vec![],
                extension_rows: vec![],
                incident_counts: BTreeMap::new(),
            }),
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: AdapterEnvelope = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn specialization_performance_impact_view_serde_roundtrip() {
        let v = SpecializationPerformanceImpactView {
            active_specialization_count: 5,
            aggregate_latency_reduction_millionths: 300_000,
            aggregate_throughput_increase_millionths: 200_000,
            specialization_coverage_millionths: 750_000,
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: SpecializationPerformanceImpactView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn flow_decision_dashboard_view_empty_serde_roundtrip() {
        let v = FlowDecisionDashboardView {
            cluster: "prod".to_string(),
            zone: "us-east".to_string(),
            security_epoch: 7,
            generated_at_unix_ms: 1_000,
            label_map: LabelMapView {
                nodes: vec![],
                edges: vec![],
            },
            blocked_flows: vec![],
            declassification_history: vec![],
            confinement_proofs: vec![],
            alert_indicators: vec![],
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: FlowDecisionDashboardView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn proof_specialization_lineage_dashboard_view_empty_serde_roundtrip() {
        let v = ProofSpecializationLineageDashboardView {
            cluster: "prod".to_string(),
            zone: "us-east".to_string(),
            security_epoch: 7,
            generated_at_unix_ms: 1_000,
            proof_inventory: vec![],
            active_specializations: vec![],
            invalidation_feed: vec![],
            fallback_events: vec![],
            performance_impact: SpecializationPerformanceImpactView {
                active_specialization_count: 0,
                aggregate_latency_reduction_millionths: 0,
                aggregate_throughput_increase_millionths: 0,
                specialization_coverage_millionths: 0,
            },
            alert_indicators: vec![],
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: ProofSpecializationLineageDashboardView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn capability_delta_dashboard_view_empty_serde_roundtrip() {
        let v = CapabilityDeltaDashboardView {
            cluster: "prod".to_string(),
            zone: "us-east".to_string(),
            security_epoch: 7,
            generated_at_unix_ms: 1_000,
            current_capability_rows: vec![],
            proposed_minimal_rows: vec![],
            escrow_event_feed: vec![],
            override_rationale_rows: vec![],
            batch_review_queue: vec![],
            alert_indicators: vec![],
            event_subscription_cursor: None,
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: CapabilityDeltaDashboardView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn replacement_progress_dashboard_view_empty_serde_roundtrip() {
        let v = ReplacementProgressDashboardView {
            cluster: "prod".to_string(),
            zone: "us-east".to_string(),
            security_epoch: 7,
            generated_at_unix_ms: 1_000,
            slot_status_overview: vec![],
            native_coverage: NativeCoverageMeter {
                native_slots: 0,
                delegate_slots: 0,
                native_coverage_millionths: 0,
                trend: vec![],
            },
            blocked_promotions: vec![],
            rollback_events: vec![],
            next_best_replacements: vec![],
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: ReplacementProgressDashboardView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn flow_decision_alert_view_serde_roundtrip() {
        let v = FlowDecisionAlertView {
            alert_id: "alert-1".to_string(),
            extension_id: "ext-a".to_string(),
            severity: DashboardSeverity::Warning,
            reason: "blocked flows detected".to_string(),
            blocked_flow_count: 3,
            generated_at_unix_ms: 1_000,
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: FlowDecisionAlertView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn proof_specialization_alert_view_serde_roundtrip() {
        let v = ProofSpecializationAlertView {
            alert_id: "alert-2".to_string(),
            severity: DashboardSeverity::Critical,
            reason: "proof expired".to_string(),
            affected_count: 2,
            generated_at_unix_ms: 2_000,
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: ProofSpecializationAlertView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn confinement_proof_view_serde_roundtrip() {
        let v = ConfinementProofView {
            extension_id: "ext-a".to_string(),
            status: ConfinementStatus::Full,
            covered_flow_count: 10,
            uncovered_flow_count: 0,
            proof_rows: vec![],
            uncovered_flow_refs: vec![],
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: ConfinementProofView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn label_map_view_serde_roundtrip() {
        let v = LabelMapView {
            nodes: vec![],
            edges: vec![],
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: LabelMapView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn capability_delta_escrow_event_view_serde_roundtrip() {
        let v = CapabilityDeltaEscrowEventView {
            receipt_id: "rcpt-1".to_string(),
            extension_id: "ext-a".to_string(),
            capability: Some("net:outbound".to_string()),
            decision_kind: "grant".to_string(),
            outcome: "approved".to_string(),
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            error_code: None,
            timestamp_ns: 1_000_000,
            receipt_ref: "ref-1".to_string(),
            replay_ref: "replay-1".to_string(),
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: CapabilityDeltaEscrowEventView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }

    #[test]
    fn capability_promotion_batch_review_view_serde_roundtrip() {
        let v = CapabilityPromotionBatchReviewView {
            batch_id: "batch-1".to_string(),
            extension_ids: vec!["ext-a".to_string()],
            witness_ids: vec!["w-1".to_string()],
            pending_review_count: 1,
            generated_at_unix_ms: 1_000,
            workflow_ref: "wf-1".to_string(),
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: CapabilityPromotionBatchReviewView = serde_json::from_str(&json).expect("serde roundtrip should succeed in tests");
        assert_eq!(v, back);
    }
}
