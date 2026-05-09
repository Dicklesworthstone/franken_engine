//! Shadow daemon handoff contracts for UI/service consumers.
//!
//! This module defines the types and interfaces for emitting advisory-only
//! handoff artifacts to frankentui and fastapi_rust consumers.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::security_epoch::SecurityEpoch;

/// Current version of the handoff contract schema
pub const HANDOFF_CONTRACT_VERSION: &str = "1.0.0";

/// Complete panel bundle for frankentui consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowStatusPanelBundle {
    pub shadow_status: ShadowStatusPanel,
    pub source_freshness: SourceFreshnessPanel,
    pub degraded_gates: DegradedGatesPanel,
    pub replay_drift: ReplayDriftPanel,
    pub recommended_actions: RecommendedActionsPanel,
    pub generated_at: SecurityEpoch,
    pub bundle_version: String,
}

impl Default for ShadowStatusPanelBundle {
    fn default() -> Self {
        Self {
            shadow_status: ShadowStatusPanel::default(),
            source_freshness: SourceFreshnessPanel::default(),
            degraded_gates: DegradedGatesPanel::default(),
            replay_drift: ReplayDriftPanel::default(),
            recommended_actions: RecommendedActionsPanel::default(),
            generated_at: SecurityEpoch::GENESIS,
            bundle_version: HANDOFF_CONTRACT_VERSION.to_string(),
        }
    }
}

/// Shadow daemon health status panel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowStatusPanel {
    pub title: String,
    pub daemon_health: DaemonHealth,
    pub active_journals: u32,
    pub last_decision_timestamp: Option<SecurityEpoch>,
    pub uptime_seconds: u64,
}

impl Default for ShadowStatusPanel {
    fn default() -> Self {
        Self {
            title: "Shadow Daemon Status".to_string(),
            daemon_health: DaemonHealth::Unknown,
            active_journals: 0,
            last_decision_timestamp: None,
            uptime_seconds: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonHealth {
    Healthy,
    Degraded { reason: String },
    Offline,
    Unknown,
}

/// Source freshness monitoring panel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFreshnessPanel {
    pub title: String,
    pub sources: Vec<SourceFreshnessEntry>,
    pub stale_source_count: u32,
}

impl Default for SourceFreshnessPanel {
    fn default() -> Self {
        Self {
            title: "Source Freshness".to_string(),
            sources: Vec::new(),
            stale_source_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceFreshnessEntry {
    pub source_id: String,
    pub last_update: SecurityEpoch,
    pub staleness_seconds: u64,
    pub threshold_seconds: u64,
    pub is_stale: bool,
}

/// Degraded gates monitoring panel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedGatesPanel {
    pub title: String,
    pub gates: Vec<DegradedGateEntry>,
    pub degraded_count: u32,
}

impl Default for DegradedGatesPanel {
    fn default() -> Self {
        Self {
            title: "Degraded Gates".to_string(),
            gates: Vec::new(),
            degraded_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradedGateEntry {
    pub gate_id: String,
    pub degradation_reason: String,
    pub degraded_since: SecurityEpoch,
    pub severity: GateDegradationSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GateDegradationSeverity {
    Warning,
    Critical,
    Blocking,
}

/// Replay drift detection panel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayDriftPanel {
    pub title: String,
    pub drift_entries: Vec<ReplayDriftEntry>,
    pub total_drift_count: u32,
}

impl Default for ReplayDriftPanel {
    fn default() -> Self {
        Self {
            title: "Replay Drift Detection".to_string(),
            drift_entries: Vec::new(),
            total_drift_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayDriftEntry {
    pub journal_id: String,
    pub drift_type: String,
    pub detected_at: SystemTime,
    pub severity: DriftSeverity,
    pub expected_migration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DriftSeverity {
    Minor,
    Major,
    Critical,
}

/// Recommended actions panel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedActionsPanel {
    pub title: String,
    pub actions: Vec<RecommendedAction>,
    pub priority_action_count: u32,
}

impl Default for RecommendedActionsPanel {
    fn default() -> Self {
        Self {
            title: "Recommended Actions".to_string(),
            actions: Vec::new(),
            priority_action_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecommendedAction {
    pub action_id: String,
    pub description: String,
    pub command_preview: String, // Advisory-only, never executed directly
    pub priority: ActionPriority,
    pub estimated_duration: Option<u64>, // seconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActionPriority {
    Low,
    Medium,
    High,
    Urgent,
}

/// Missing source rendering state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingSourcePanel {
    pub title: String,
    pub message: String,
    pub last_successful_fetch: Option<SecurityEpoch>,
    pub retry_in_seconds: Option<u64>,
}

/// Panel bundle builder for constructing handoff artifacts
pub struct PanelBundleBuilder {
    bundle: ShadowStatusPanelBundle,
}

impl Default for PanelBundleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PanelBundleBuilder {
    pub fn new() -> Self {
        Self {
            bundle: ShadowStatusPanelBundle::default(),
        }
    }

    pub fn with_daemon_health(mut self, health: DaemonHealth) -> Self {
        self.bundle.shadow_status.daemon_health = health;
        self
    }

    pub fn with_active_journals(mut self, count: u32) -> Self {
        self.bundle.shadow_status.active_journals = count;
        self
    }

    pub fn with_uptime(mut self, seconds: u64) -> Self {
        self.bundle.shadow_status.uptime_seconds = seconds;
        self
    }

    pub fn with_last_decision(mut self, timestamp: SecurityEpoch) -> Self {
        self.bundle.shadow_status.last_decision_timestamp = Some(timestamp);
        self
    }

    pub fn add_source_freshness(mut self, entry: SourceFreshnessEntry) -> Self {
        if entry.is_stale {
            self.bundle.source_freshness.stale_source_count += 1;
        }
        self.bundle.source_freshness.sources.push(entry);
        self
    }

    pub fn add_degraded_gate(mut self, entry: DegradedGateEntry) -> Self {
        self.bundle.degraded_gates.degraded_count += 1;
        self.bundle.degraded_gates.gates.push(entry);
        self
    }

    pub fn add_replay_drift(mut self, entry: ReplayDriftEntry) -> Self {
        self.bundle.replay_drift.total_drift_count += 1;
        self.bundle.replay_drift.drift_entries.push(entry);
        self
    }

    pub fn add_recommended_action(mut self, action: RecommendedAction) -> Self {
        if matches!(
            action.priority,
            ActionPriority::High | ActionPriority::Urgent
        ) {
            self.bundle.recommended_actions.priority_action_count += 1;
        }
        self.bundle.recommended_actions.actions.push(action);
        self
    }

    pub fn build(self) -> ShadowStatusPanelBundle {
        self.bundle
    }
}

/// Create a missing source panel for graceful degradation
pub fn create_missing_source_panel(
    title: &str,
    message: &str,
    last_fetch: Option<SecurityEpoch>,
) -> MissingSourcePanel {
    MissingSourcePanel {
        title: title.to_string(),
        message: message.to_string(),
        last_successful_fetch: last_fetch,
        retry_in_seconds: Some(30), // Default 30 second retry
    }
}

/// Serialize panel bundle to JSON for frankentui consumption
pub fn serialize_panel_bundle(
    bundle: &ShadowStatusPanelBundle,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(bundle)
}

/// Deserialize panel bundle from JSON
pub fn deserialize_panel_bundle(json: &str) -> Result<ShadowStatusPanelBundle, serde_json::Error> {
    serde_json::from_str(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn test_default_panel_bundle() {
        let bundle = ShadowStatusPanelBundle::default();
        assert_eq!(bundle.bundle_version, HANDOFF_CONTRACT_VERSION);
        assert_eq!(bundle.shadow_status.title, "Shadow Daemon Status");
        assert_eq!(bundle.source_freshness.stale_source_count, 0);
        assert_eq!(bundle.degraded_gates.degraded_count, 0);
        assert_eq!(bundle.replay_drift.total_drift_count, 0);
        assert_eq!(bundle.recommended_actions.priority_action_count, 0);
    }

    #[test]
    fn test_panel_bundle_builder() {
        let epoch = SecurityEpoch::GENESIS;
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let bundle = PanelBundleBuilder::new()
            .with_daemon_health(DaemonHealth::Healthy)
            .with_active_journals(5)
            .with_uptime(3600)
            .with_last_decision(epoch)
            .add_source_freshness(SourceFreshnessEntry {
                source_id: "test-source".to_string(),
                last_update: epoch,
                staleness_seconds: 120,
                threshold_seconds: 300,
                is_stale: false,
            })
            .add_degraded_gate(DegradedGateEntry {
                gate_id: "test-gate".to_string(),
                degradation_reason: "Test degradation".to_string(),
                degraded_since: epoch,
                severity: GateDegradationSeverity::Warning,
            })
            .add_replay_drift(ReplayDriftEntry {
                journal_id: "test-journal".to_string(),
                drift_type: "schema_drift".to_string(),
                detected_at: now,
                severity: DriftSeverity::Minor,
                expected_migration: false,
            })
            .add_recommended_action(RecommendedAction {
                action_id: "test-action".to_string(),
                description: "Test action".to_string(),
                command_preview: "echo 'test'".to_string(),
                priority: ActionPriority::High,
                estimated_duration: Some(60),
            })
            .build();

        assert!(matches!(
            bundle.shadow_status.daemon_health,
            DaemonHealth::Healthy
        ));
        assert_eq!(bundle.shadow_status.active_journals, 5);
        assert_eq!(bundle.shadow_status.uptime_seconds, 3600);
        assert_eq!(bundle.shadow_status.last_decision_timestamp, Some(epoch));
        assert_eq!(bundle.source_freshness.sources.len(), 1);
        assert_eq!(bundle.source_freshness.stale_source_count, 0);
        assert_eq!(bundle.degraded_gates.gates.len(), 1);
        assert_eq!(bundle.degraded_gates.degraded_count, 1);
        assert_eq!(bundle.replay_drift.drift_entries.len(), 1);
        assert_eq!(bundle.replay_drift.total_drift_count, 1);
        assert_eq!(bundle.recommended_actions.actions.len(), 1);
        assert_eq!(bundle.recommended_actions.priority_action_count, 1);
    }

    #[test]
    fn test_missing_source_panel() {
        let epoch = SecurityEpoch::GENESIS;
        let panel = create_missing_source_panel("Test Source", "Source unavailable", Some(epoch));

        assert_eq!(panel.title, "Test Source");
        assert_eq!(panel.message, "Source unavailable");
        assert_eq!(panel.last_successful_fetch, Some(epoch));
        assert_eq!(panel.retry_in_seconds, Some(30));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let bundle = PanelBundleBuilder::new()
            .with_daemon_health(DaemonHealth::Degraded {
                reason: "Test degradation".to_string(),
            })
            .with_active_journals(3)
            .build();

        let json = serialize_panel_bundle(&bundle).expect("Serialization should succeed");
        let deserialized = deserialize_panel_bundle(&json).expect("Deserialization should succeed");

        assert_eq!(
            bundle.shadow_status.active_journals,
            deserialized.shadow_status.active_journals
        );
        if let DaemonHealth::Degraded { reason } = &deserialized.shadow_status.daemon_health {
            assert_eq!(reason, "Test degradation");
        } else {
            panic!("Expected degraded health status");
        }
    }

    #[test]
    fn test_panel_bundle_schema_validation() {
        let bundle = ShadowStatusPanelBundle::default();

        // Validate all required fields are present
        assert!(!bundle.shadow_status.title.is_empty());
        assert!(!bundle.source_freshness.title.is_empty());
        assert!(!bundle.degraded_gates.title.is_empty());
        assert!(!bundle.replay_drift.title.is_empty());
        assert!(!bundle.recommended_actions.title.is_empty());
        assert!(!bundle.bundle_version.is_empty());

        // Validate counts are consistent
        assert_eq!(
            bundle.source_freshness.stale_source_count,
            bundle
                .source_freshness
                .sources
                .iter()
                .filter(|s| s.is_stale)
                .count() as u32
        );
        assert_eq!(
            bundle.degraded_gates.degraded_count,
            bundle.degraded_gates.gates.len() as u32
        );
        assert_eq!(
            bundle.replay_drift.total_drift_count,
            bundle.replay_drift.drift_entries.len() as u32
        );
    }
}
