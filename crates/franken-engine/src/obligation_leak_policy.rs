//! Obligation leak response policy: lab=fatal, prod=diagnostic + scoped failover.
//!
//! In lab mode, any unresolved obligation leak is a hard abort with diagnostics.
//! In production, leaks trigger evidence emission and scoped region failover.
//! Policy is immutable after init to prevent evasion.
//!
//! Plan references: Section 10.11 item 7, 9G.3 (linear-obligation discipline),
//! Top-10 #3 (deterministic evidence graph + replay).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ObligationLeakPolicy — lab vs production behavior
// ---------------------------------------------------------------------------

/// Policy governing how obligation leaks are handled.
/// Set at startup and immutable thereafter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObligationLeakPolicy {
    /// Lab mode: obligation leak triggers panic/abort with full diagnostics.
    Lab,
    /// Production: obligation leak triggers evidence emission + scoped failover.
    Production,
}

impl fmt::Display for ObligationLeakPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lab => write!(f, "lab"),
            Self::Production => write!(f, "production"),
        }
    }
}

// ---------------------------------------------------------------------------
// LeakDiagnostic — structured information about a leak
// ---------------------------------------------------------------------------

/// Full diagnostic payload for an obligation leak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeakDiagnostic {
    pub obligation_id: u64,
    pub channel_id: String,
    pub creator_trace_id: String,
    pub obligation_age_ticks: u64,
    pub region_id: String,
    pub component: String,
}

impl fmt::Display for LeakDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "obligation leak: id={}, channel={}, trace={}, age={}, region={}, component={}",
            self.obligation_id,
            self.channel_id,
            self.creator_trace_id,
            self.obligation_age_ticks,
            self.region_id,
            self.component
        )
    }
}

// ---------------------------------------------------------------------------
// LeakSeverity — severity classification
// ---------------------------------------------------------------------------

/// Severity of the leak event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LeakSeverity {
    Warning,
    Critical,
    Fatal,
}

impl fmt::Display for LeakSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Warning => write!(f, "warning"),
            Self::Critical => write!(f, "critical"),
            Self::Fatal => write!(f, "fatal"),
        }
    }
}

// ---------------------------------------------------------------------------
// FailoverAction — what production mode does on leak
// ---------------------------------------------------------------------------

/// Action taken in production mode on obligation leak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailoverAction {
    /// Region enters forced close (cancel -> drain -> finalize).
    ScopedRegionClose { region_id: String },
    /// Alert emitted without region close (for non-critical paths).
    AlertOnly,
}

impl fmt::Display for FailoverAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScopedRegionClose { region_id } => {
                write!(f, "scoped_region_close:{region_id}")
            }
            Self::AlertOnly => write!(f, "alert_only"),
        }
    }
}

// ---------------------------------------------------------------------------
// LeakEvent — structured evidence event
// ---------------------------------------------------------------------------

/// Structured evidence event for an obligation leak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeakEvent {
    pub trace_id: String,
    pub obligation_id: u64,
    pub channel_id: String,
    pub region_id: String,
    pub component: String,
    pub leak_policy: ObligationLeakPolicy,
    pub failover_action: Option<FailoverAction>,
    pub severity: LeakSeverity,
}

// ---------------------------------------------------------------------------
// LeakMetrics — per-region/channel/component counters
// ---------------------------------------------------------------------------

/// Metrics tracking obligation leak counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeakMetrics {
    /// Leaks per region_id.
    pub by_region: BTreeMap<String, u64>,
    /// Leaks per channel_id.
    pub by_channel: BTreeMap<String, u64>,
    /// Leaks per component.
    pub by_component: BTreeMap<String, u64>,
    /// Total leaks.
    pub total: u64,
}

impl LeakMetrics {
    /// Record a leak for the given dimensions.
    pub fn record(&mut self, region_id: &str, channel_id: &str, component: &str) {
        *self.by_region.entry(region_id.to_string()).or_insert(0) += 1;
        *self.by_channel.entry(channel_id.to_string()).or_insert(0) += 1;
        *self.by_component.entry(component.to_string()).or_insert(0) += 1;
        self.total += 1;
    }
}

// ---------------------------------------------------------------------------
// LeakResponse — result of handling a leak
// ---------------------------------------------------------------------------

/// Result of handling an obligation leak.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeakResponse {
    /// Lab mode: should abort (caller panics).
    Abort { diagnostic: LeakDiagnostic },
    /// Production mode: evidence emitted, optional failover.
    Handled {
        event: LeakEvent,
        failover: Option<FailoverAction>,
    },
}

// ---------------------------------------------------------------------------
// LeakHandler — the policy handler
// ---------------------------------------------------------------------------

/// Handles obligation leak events according to the configured policy.
#[derive(Debug)]
pub struct LeakHandler {
    policy: ObligationLeakPolicy,
    metrics: LeakMetrics,
    events: Vec<LeakEvent>,
}

impl LeakHandler {
    /// Create a new handler with immutable policy.
    pub fn new(policy: ObligationLeakPolicy) -> Self {
        Self {
            policy,
            metrics: LeakMetrics::default(),
            events: Vec::new(),
        }
    }

    /// Current policy.
    pub fn policy(&self) -> ObligationLeakPolicy {
        self.policy
    }

    /// Handle an obligation leak. Returns the response.
    pub fn handle_leak(&mut self, diagnostic: LeakDiagnostic) -> LeakResponse {
        self.metrics.record(
            &diagnostic.region_id,
            &diagnostic.channel_id,
            &diagnostic.component,
        );

        match self.policy {
            ObligationLeakPolicy::Lab => LeakResponse::Abort { diagnostic },
            ObligationLeakPolicy::Production => {
                let failover = FailoverAction::ScopedRegionClose {
                    region_id: diagnostic.region_id.clone(),
                };

                let event = LeakEvent {
                    trace_id: diagnostic.creator_trace_id.clone(),
                    obligation_id: diagnostic.obligation_id,
                    channel_id: diagnostic.channel_id,
                    region_id: diagnostic.region_id,
                    component: diagnostic.component,
                    leak_policy: self.policy,
                    failover_action: Some(failover.clone()),
                    severity: LeakSeverity::Critical,
                };

                self.events.push(event.clone());

                LeakResponse::Handled {
                    event,
                    failover: Some(failover),
                }
            }
        }
    }

    /// Current metrics.
    pub fn metrics(&self) -> &LeakMetrics {
        &self.metrics
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<LeakEvent> {
        std::mem::take(&mut self.events)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_diagnostic() -> LeakDiagnostic {
        LeakDiagnostic {
            obligation_id: 42,
            channel_id: "chan-1".to_string(),
            creator_trace_id: "trace-1".to_string(),
            obligation_age_ticks: 500,
            region_id: "region-1".to_string(),
            component: "policy_controller".to_string(),
        }
    }

    // -- Policy display --

    #[test]
    fn policy_display() {
        assert_eq!(ObligationLeakPolicy::Lab.to_string(), "lab");
        assert_eq!(ObligationLeakPolicy::Production.to_string(), "production");
    }

    // -- Lab mode --

    #[test]
    fn lab_mode_returns_abort() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        let response = handler.handle_leak(test_diagnostic());
        assert!(matches!(response, LeakResponse::Abort { .. }));
    }

    #[test]
    fn lab_mode_abort_includes_diagnostic() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        let diag = test_diagnostic();
        let response = handler.handle_leak(diag.clone());
        if let LeakResponse::Abort { diagnostic } = response {
            assert_eq!(diagnostic, diag);
        } else {
            panic!("expected Abort");
        }
    }

    // -- Production mode --

    #[test]
    fn production_mode_returns_handled() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        let response = handler.handle_leak(test_diagnostic());
        assert!(matches!(response, LeakResponse::Handled { .. }));
    }

    #[test]
    fn production_mode_triggers_scoped_failover() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        let response = handler.handle_leak(test_diagnostic());
        if let LeakResponse::Handled { failover, .. } = response {
            assert!(matches!(
                failover,
                Some(FailoverAction::ScopedRegionClose { .. })
            ));
        } else {
            panic!("expected Handled");
        }
    }

    #[test]
    fn production_mode_emits_event() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        handler.handle_leak(test_diagnostic());

        let events = handler.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].obligation_id, 42);
        assert_eq!(events[0].severity, LeakSeverity::Critical);
        assert_eq!(events[0].leak_policy, ObligationLeakPolicy::Production);
    }

    #[test]
    fn production_event_carries_correct_fields() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        handler.handle_leak(test_diagnostic());

        let events = handler.drain_events();
        let event = &events[0];
        assert_eq!(event.trace_id, "trace-1");
        assert_eq!(event.channel_id, "chan-1");
        assert_eq!(event.region_id, "region-1");
        assert_eq!(event.component, "policy_controller");
    }

    // -- Metrics --

    #[test]
    fn metrics_increment_on_leak() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        handler.handle_leak(test_diagnostic());
        handler.handle_leak(LeakDiagnostic {
            obligation_id: 43,
            channel_id: "chan-2".to_string(),
            creator_trace_id: "trace-2".to_string(),
            obligation_age_ticks: 100,
            region_id: "region-1".to_string(),
            component: "evidence_flusher".to_string(),
        });

        let metrics = handler.metrics();
        assert_eq!(metrics.total, 2);
        assert_eq!(metrics.by_region.get("region-1"), Some(&2));
        assert_eq!(metrics.by_channel.get("chan-1"), Some(&1));
        assert_eq!(metrics.by_channel.get("chan-2"), Some(&1));
        assert_eq!(metrics.by_component.get("policy_controller"), Some(&1));
        assert_eq!(metrics.by_component.get("evidence_flusher"), Some(&1));
    }

    #[test]
    fn lab_mode_also_records_metrics() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        handler.handle_leak(test_diagnostic());
        assert_eq!(handler.metrics().total, 1);
    }

    // -- LeakDiagnostic display --

    #[test]
    fn diagnostic_display() {
        let diag = test_diagnostic();
        let s = diag.to_string();
        assert!(s.contains("obligation leak"));
        assert!(s.contains("42"));
        assert!(s.contains("chan-1"));
        assert!(s.contains("region-1"));
    }

    // -- Severity ordering --

    #[test]
    fn severity_ordering() {
        assert!(LeakSeverity::Warning < LeakSeverity::Critical);
        assert!(LeakSeverity::Critical < LeakSeverity::Fatal);
    }

    #[test]
    fn severity_display() {
        assert_eq!(LeakSeverity::Warning.to_string(), "warning");
        assert_eq!(LeakSeverity::Critical.to_string(), "critical");
        assert_eq!(LeakSeverity::Fatal.to_string(), "fatal");
    }

    // -- FailoverAction display --

    #[test]
    fn failover_action_display() {
        assert_eq!(
            FailoverAction::ScopedRegionClose {
                region_id: "r-1".to_string()
            }
            .to_string(),
            "scoped_region_close:r-1"
        );
        assert_eq!(FailoverAction::AlertOnly.to_string(), "alert_only");
    }

    // -- Deterministic replay --

    #[test]
    fn deterministic_event_sequence() {
        let run = || -> Vec<LeakEvent> {
            let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
            handler.handle_leak(test_diagnostic());
            handler.handle_leak(LeakDiagnostic {
                obligation_id: 99,
                channel_id: "chan-x".to_string(),
                creator_trace_id: "trace-x".to_string(),
                obligation_age_ticks: 200,
                region_id: "region-2".to_string(),
                component: "scheduler".to_string(),
            });
            handler.drain_events()
        };

        let events1 = run();
        let events2 = run();
        assert_eq!(events1, events2);
    }

    // -- Serialization --

    #[test]
    fn leak_diagnostic_serialization_round_trip() {
        let diag = test_diagnostic();
        let json = serde_json::to_string(&diag).expect("serialize derived Serialize");
        let restored: LeakDiagnostic =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(diag, restored);
    }

    #[test]
    fn leak_event_serialization_round_trip() {
        let event = LeakEvent {
            trace_id: "t".to_string(),
            obligation_id: 1,
            channel_id: "c".to_string(),
            region_id: "r".to_string(),
            component: "comp".to_string(),
            leak_policy: ObligationLeakPolicy::Production,
            failover_action: Some(FailoverAction::ScopedRegionClose {
                region_id: "r".to_string(),
            }),
            severity: LeakSeverity::Critical,
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let restored: LeakEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, restored);
    }

    // -- Enrichment: serde roundtrips --

    #[test]
    fn obligation_leak_policy_serde_both_variants() {
        for policy in [ObligationLeakPolicy::Lab, ObligationLeakPolicy::Production] {
            let json = serde_json::to_string(&policy).expect("serialize derived Serialize");
            let restored: ObligationLeakPolicy =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(policy, restored);
        }
    }

    #[test]
    fn leak_severity_serde_all_variants() {
        for sev in [
            LeakSeverity::Warning,
            LeakSeverity::Critical,
            LeakSeverity::Fatal,
        ] {
            let json = serde_json::to_string(&sev).expect("serialize derived Serialize");
            let restored: LeakSeverity =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(sev, restored);
        }
    }

    #[test]
    fn failover_action_serde_both_variants() {
        let actions = vec![
            FailoverAction::ScopedRegionClose {
                region_id: "r-42".to_string(),
            },
            FailoverAction::AlertOnly,
        ];
        for action in actions {
            let json = serde_json::to_string(&action).expect("serialize derived Serialize");
            let restored: FailoverAction =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(action, restored);
        }
    }

    #[test]
    fn leak_response_serde_both_variants() {
        let diag = test_diagnostic();
        // Lab policy returns Abort
        let mut handler_lab = LeakHandler::new(ObligationLeakPolicy::Lab);
        let abort_resp = handler_lab.handle_leak(diag.clone());
        let json = serde_json::to_string(&abort_resp).expect("serialize derived Serialize");
        let restored: LeakResponse =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(abort_resp, restored);

        // Production policy returns Handled
        let mut handler_prod = LeakHandler::new(ObligationLeakPolicy::Production);
        let handled_resp = handler_prod.handle_leak(test_diagnostic());
        let json = serde_json::to_string(&handled_resp).expect("serialize derived Serialize");
        let restored: LeakResponse =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(handled_resp, restored);
    }

    #[test]
    fn leak_metrics_serialization_round_trip() {
        let mut metrics = LeakMetrics::default();
        metrics.record("r", "c", "comp");
        let json = serde_json::to_string(&metrics).expect("serialize derived Serialize");
        let restored: LeakMetrics =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(metrics, restored);
    }

    // -- Enrichment: additional edge cases --

    #[test]
    fn handler_policy_accessor() {
        let handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        assert_eq!(handler.policy(), ObligationLeakPolicy::Lab);
        let handler2 = LeakHandler::new(ObligationLeakPolicy::Production);
        assert_eq!(handler2.policy(), ObligationLeakPolicy::Production);
    }

    #[test]
    fn drain_events_clears_buffer() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        handler.handle_leak(test_diagnostic());
        handler.handle_leak(test_diagnostic());
        let events = handler.drain_events();
        assert_eq!(events.len(), 2);
        let events2 = handler.drain_events();
        assert!(events2.is_empty(), "drain should clear events");
    }

    #[test]
    fn lab_mode_does_not_emit_events() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        handler.handle_leak(test_diagnostic());
        let events = handler.drain_events();
        assert!(events.is_empty(), "lab mode should not emit events");
    }

    #[test]
    fn metrics_default_is_zero() {
        let metrics = LeakMetrics::default();
        assert_eq!(metrics.total, 0);
        assert!(metrics.by_region.is_empty());
        assert!(metrics.by_channel.is_empty());
        assert!(metrics.by_component.is_empty());
    }

    #[test]
    fn metrics_multiple_regions() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        for i in 0..5 {
            handler.handle_leak(LeakDiagnostic {
                obligation_id: i,
                channel_id: format!("chan-{}", i % 2),
                creator_trace_id: format!("trace-{i}"),
                obligation_age_ticks: 100,
                region_id: format!("region-{}", i % 3),
                component: "comp".to_string(),
            });
        }
        let metrics = handler.metrics();
        assert_eq!(metrics.total, 5);
        assert_eq!(metrics.by_region.len(), 3); // region-0, region-1, region-2
        assert_eq!(metrics.by_channel.len(), 2); // chan-0, chan-1
    }

    #[test]
    fn production_failover_region_matches_diagnostic() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        let response = handler.handle_leak(LeakDiagnostic {
            obligation_id: 1,
            channel_id: "c".to_string(),
            creator_trace_id: "t".to_string(),
            obligation_age_ticks: 50,
            region_id: "my-region".to_string(),
            component: "comp".to_string(),
        });
        if let LeakResponse::Handled { failover, .. } = response {
            if let Some(FailoverAction::ScopedRegionClose { region_id }) = failover {
                assert_eq!(region_id, "my-region");
            } else {
                panic!("expected ScopedRegionClose");
            }
        } else {
            panic!("expected Handled");
        }
    }

    #[test]
    fn diagnostic_display_contains_all_fields() {
        let diag = LeakDiagnostic {
            obligation_id: 99,
            channel_id: "ch-x".to_string(),
            creator_trace_id: "tr-y".to_string(),
            obligation_age_ticks: 12345,
            region_id: "reg-z".to_string(),
            component: "my_comp".to_string(),
        };
        let s = diag.to_string();
        assert!(s.contains("99"));
        assert!(s.contains("ch-x"));
        assert!(s.contains("tr-y"));
        assert!(s.contains("12345"));
        assert!(s.contains("reg-z"));
        assert!(s.contains("my_comp"));
    }

    #[test]
    fn policy_equality() {
        assert_eq!(ObligationLeakPolicy::Lab, ObligationLeakPolicy::Lab);
        assert_ne!(ObligationLeakPolicy::Lab, ObligationLeakPolicy::Production);
    }

    #[test]
    fn leak_event_alert_only_failover() {
        let event = LeakEvent {
            trace_id: "t".to_string(),
            obligation_id: 1,
            channel_id: "c".to_string(),
            region_id: "r".to_string(),
            component: "comp".to_string(),
            leak_policy: ObligationLeakPolicy::Production,
            failover_action: Some(FailoverAction::AlertOnly),
            severity: LeakSeverity::Warning,
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let restored: LeakEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, restored);
        assert_eq!(restored.failover_action, Some(FailoverAction::AlertOnly));
    }

    #[test]
    fn leak_event_no_failover() {
        let event = LeakEvent {
            trace_id: "t".to_string(),
            obligation_id: 1,
            channel_id: "c".to_string(),
            region_id: "r".to_string(),
            component: "comp".to_string(),
            leak_policy: ObligationLeakPolicy::Lab,
            failover_action: None,
            severity: LeakSeverity::Fatal,
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let restored: LeakEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, restored);
        assert!(restored.failover_action.is_none());
    }

    // -- Enrichment batch 2: Display uniqueness, serde edge cases, boundary conditions --

    #[test]
    fn policy_display_variants_are_unique() {
        let displays: std::collections::BTreeSet<String> =
            [ObligationLeakPolicy::Lab, ObligationLeakPolicy::Production]
                .iter()
                .map(|p| p.to_string())
                .collect();
        assert_eq!(
            displays.len(),
            2,
            "all policy Display strings must be unique"
        );
    }

    #[test]
    fn severity_display_variants_are_unique() {
        let displays: std::collections::BTreeSet<String> = [
            LeakSeverity::Warning,
            LeakSeverity::Critical,
            LeakSeverity::Fatal,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            3,
            "all severity Display strings must be unique"
        );
    }

    #[test]
    fn failover_action_display_variants_are_unique() {
        let displays: std::collections::BTreeSet<String> = [
            FailoverAction::ScopedRegionClose {
                region_id: "r".to_string(),
            },
            FailoverAction::AlertOnly,
        ]
        .iter()
        .map(|a| a.to_string())
        .collect();
        assert_eq!(
            displays.len(),
            2,
            "all FailoverAction Display strings must be unique"
        );
    }

    #[test]
    fn leak_metrics_record_idempotent_key_increment() {
        let mut metrics = LeakMetrics::default();
        metrics.record("r-1", "c-1", "comp-1");
        metrics.record("r-1", "c-1", "comp-1");
        metrics.record("r-1", "c-1", "comp-1");
        assert_eq!(metrics.total, 3);
        assert_eq!(metrics.by_region.get("r-1"), Some(&3));
        assert_eq!(metrics.by_channel.get("c-1"), Some(&3));
        assert_eq!(metrics.by_component.get("comp-1"), Some(&3));
    }

    #[test]
    fn leak_diagnostic_with_empty_strings() {
        let diag = LeakDiagnostic {
            obligation_id: 0,
            channel_id: String::new(),
            creator_trace_id: String::new(),
            obligation_age_ticks: 0,
            region_id: String::new(),
            component: String::new(),
        };
        let json = serde_json::to_string(&diag).expect("serialize derived Serialize");
        let restored: LeakDiagnostic =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(diag, restored);
        // Display still works with empty fields
        let s = diag.to_string();
        assert!(s.contains("obligation leak"));
    }

    #[test]
    fn leak_diagnostic_with_max_obligation_id() {
        let diag = LeakDiagnostic {
            obligation_id: u64::MAX,
            channel_id: "c".to_string(),
            creator_trace_id: "t".to_string(),
            obligation_age_ticks: u64::MAX,
            region_id: "r".to_string(),
            component: "comp".to_string(),
        };
        let json = serde_json::to_string(&diag).expect("serialize derived Serialize");
        let restored: LeakDiagnostic =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(diag, restored);
        let s = diag.to_string();
        assert!(s.contains(&u64::MAX.to_string()));
    }

    #[test]
    fn leak_metrics_serde_with_multiple_dimensions() {
        let mut metrics = LeakMetrics::default();
        for i in 0..10 {
            metrics.record(
                &format!("region-{}", i % 3),
                &format!("chan-{}", i % 4),
                &format!("comp-{}", i % 2),
            );
        }
        assert_eq!(metrics.total, 10);
        let json = serde_json::to_string(&metrics).expect("serialize derived Serialize");
        let restored: LeakMetrics =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(metrics, restored);
    }

    #[test]
    fn multiple_production_leaks_accumulate_events_in_order() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        for i in 0..5 {
            handler.handle_leak(LeakDiagnostic {
                obligation_id: i,
                channel_id: format!("chan-{i}"),
                creator_trace_id: format!("trace-{i}"),
                obligation_age_ticks: 100 * i,
                region_id: format!("region-{i}"),
                component: "comp".to_string(),
            });
        }
        let events = handler.drain_events();
        assert_eq!(events.len(), 5);
        for (idx, event) in events.iter().enumerate() {
            assert_eq!(event.obligation_id, idx as u64);
        }
    }

    #[test]
    fn leak_response_abort_variant_clone_eq() {
        let diag = test_diagnostic();
        let response = LeakResponse::Abort {
            diagnostic: diag.clone(),
        };
        let cloned = response.clone();
        assert_eq!(response, cloned);
    }

    #[test]
    fn leak_event_severity_warning_serde() {
        let event = LeakEvent {
            trace_id: "t".to_string(),
            obligation_id: 0,
            channel_id: "c".to_string(),
            region_id: "r".to_string(),
            component: "comp".to_string(),
            leak_policy: ObligationLeakPolicy::Production,
            failover_action: None,
            severity: LeakSeverity::Warning,
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let restored: LeakEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(event, restored);
    }

    #[test]
    fn severity_equality_and_copy() {
        let s1 = LeakSeverity::Critical;
        let s2 = s1; // Copy
        assert_eq!(s1, s2);
        assert!(LeakSeverity::Warning != LeakSeverity::Fatal);
    }

    #[test]
    fn leak_metrics_default_serde_roundtrip() {
        let metrics = LeakMetrics::default();
        let json = serde_json::to_string(&metrics).expect("serialize derived Serialize");
        let restored: LeakMetrics =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(metrics, restored);
        assert_eq!(restored.total, 0);
        assert!(restored.by_region.is_empty());
    }

    // -- Enrichment batch 3: isolation, stress, special chars, handler semantics --

    #[test]
    fn policy_copy_semantics() {
        let p1 = ObligationLeakPolicy::Lab;
        let p2 = p1; // Copy
        assert_eq!(p1, p2);
        let p3 = ObligationLeakPolicy::Production;
        let p4 = p3;
        assert_eq!(p3, p4);
    }

    #[test]
    fn handlers_metrics_are_isolated() {
        let mut h1 = LeakHandler::new(ObligationLeakPolicy::Production);
        let mut h2 = LeakHandler::new(ObligationLeakPolicy::Production);
        h1.handle_leak(test_diagnostic());
        h1.handle_leak(test_diagnostic());
        h2.handle_leak(test_diagnostic());
        assert_eq!(h1.metrics().total, 2);
        assert_eq!(h2.metrics().total, 1);
    }

    #[test]
    fn production_event_trace_id_matches_diagnostic_creator_trace() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        let diag = LeakDiagnostic {
            obligation_id: 7,
            channel_id: "c".to_string(),
            creator_trace_id: "unique-trace-abc".to_string(),
            obligation_age_ticks: 10,
            region_id: "r".to_string(),
            component: "comp".to_string(),
        };
        let resp = handler.handle_leak(diag);
        if let LeakResponse::Handled { event, .. } = resp {
            assert_eq!(event.trace_id, "unique-trace-abc");
        } else {
            panic!("expected Handled");
        }
    }

    #[test]
    fn diagnostic_with_special_characters() {
        let diag = LeakDiagnostic {
            obligation_id: 1,
            channel_id: "chan/with:special=chars".to_string(),
            creator_trace_id: "trace \"quoted\"".to_string(),
            obligation_age_ticks: 0,
            region_id: "region\nnewline".to_string(),
            component: "comp\ttab".to_string(),
        };
        let json = serde_json::to_string(&diag).expect("serialize derived Serialize");
        let restored: LeakDiagnostic =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(diag, restored);
    }

    #[test]
    fn failover_action_scoped_region_close_with_empty_region() {
        let action = FailoverAction::ScopedRegionClose {
            region_id: String::new(),
        };
        let display = action.to_string();
        assert_eq!(display, "scoped_region_close:");
    }

    #[test]
    fn leak_response_handled_with_none_failover_serde() {
        let resp = LeakResponse::Handled {
            event: LeakEvent {
                trace_id: "t".to_string(),
                obligation_id: 1,
                channel_id: "c".to_string(),
                region_id: "r".to_string(),
                component: "comp".to_string(),
                leak_policy: ObligationLeakPolicy::Production,
                failover_action: None,
                severity: LeakSeverity::Warning,
            },
            failover: None,
        };
        let json = serde_json::to_string(&resp).expect("serialize derived Serialize");
        let restored: LeakResponse =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(resp, restored);
    }

    #[test]
    fn stress_100_leaks_metrics_total_correct() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        for i in 0..100u64 {
            handler.handle_leak(LeakDiagnostic {
                obligation_id: i,
                channel_id: format!("chan-{}", i % 10),
                creator_trace_id: format!("trace-{i}"),
                obligation_age_ticks: i * 10,
                region_id: format!("region-{}", i % 5),
                component: format!("comp-{}", i % 3),
            });
        }
        let metrics = handler.metrics();
        assert_eq!(metrics.total, 100);
        assert_eq!(metrics.by_region.len(), 5);
        assert_eq!(metrics.by_channel.len(), 10);
        assert_eq!(metrics.by_component.len(), 3);
        let events = handler.drain_events();
        assert_eq!(events.len(), 100);
    }

    #[test]
    fn multiple_drains_are_idempotent() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        handler.handle_leak(test_diagnostic());
        let _ = handler.drain_events();
        let second = handler.drain_events();
        let third = handler.drain_events();
        assert!(second.is_empty());
        assert!(third.is_empty());
    }

    #[test]
    fn lab_abort_diagnostic_preserves_obligation_age() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        let diag = LeakDiagnostic {
            obligation_id: 1,
            channel_id: "c".to_string(),
            creator_trace_id: "t".to_string(),
            obligation_age_ticks: 999_999,
            region_id: "r".to_string(),
            component: "comp".to_string(),
        };
        if let LeakResponse::Abort { diagnostic } = handler.handle_leak(diag) {
            assert_eq!(diagnostic.obligation_age_ticks, 999_999);
        } else {
            panic!("expected Abort");
        }
    }

    #[test]
    fn production_severity_is_always_critical() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        for i in 0..5u64 {
            let resp = handler.handle_leak(LeakDiagnostic {
                obligation_id: i,
                channel_id: "c".to_string(),
                creator_trace_id: "t".to_string(),
                obligation_age_ticks: 0,
                region_id: "r".to_string(),
                component: "comp".to_string(),
            });
            if let LeakResponse::Handled { event, .. } = resp {
                assert_eq!(event.severity, LeakSeverity::Critical);
            } else {
                panic!("expected Handled");
            }
        }
    }

    #[test]
    fn metrics_region_keys_are_deterministically_ordered() {
        let mut metrics = LeakMetrics::default();
        metrics.record("z-region", "c", "comp");
        metrics.record("a-region", "c", "comp");
        metrics.record("m-region", "c", "comp");
        let keys: Vec<&String> = metrics.by_region.keys().collect();
        assert_eq!(keys, vec!["a-region", "m-region", "z-region"]);
    }

    #[test]
    fn diagnostic_clone_is_independent() {
        let diag = test_diagnostic();
        let cloned = diag.clone();
        assert_eq!(diag, cloned);
        // Different memory, same values
        assert_eq!(diag.obligation_id, cloned.obligation_id);
        assert_eq!(diag.channel_id, cloned.channel_id);
    }

    #[test]
    fn leak_event_json_field_presence() {
        let event = LeakEvent {
            trace_id: "t".to_string(),
            obligation_id: 42,
            channel_id: "c".to_string(),
            region_id: "r".to_string(),
            component: "comp".to_string(),
            leak_policy: ObligationLeakPolicy::Production,
            failover_action: Some(FailoverAction::AlertOnly),
            severity: LeakSeverity::Warning,
        };
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"obligation_id\""));
        assert!(json.contains("\"channel_id\""));
        assert!(json.contains("\"region_id\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"leak_policy\""));
        assert!(json.contains("\"failover_action\""));
        assert!(json.contains("\"severity\""));
    }

    #[test]
    fn handler_new_has_zero_metrics_and_empty_events() {
        let handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        assert_eq!(handler.metrics().total, 0);
        assert!(handler.metrics().by_region.is_empty());
    }

    #[test]
    fn severity_all_orderings_transitive() {
        let w = LeakSeverity::Warning;
        let c = LeakSeverity::Critical;
        let f = LeakSeverity::Fatal;
        assert!(w < c);
        assert!(c < f);
        assert!(w < f); // transitivity
    }

    #[test]
    fn leak_diagnostic_json_field_presence() {
        let diag = test_diagnostic();
        let json = serde_json::to_string(&diag).expect("serialize derived Serialize");
        assert!(json.contains("\"obligation_id\""));
        assert!(json.contains("\"channel_id\""));
        assert!(json.contains("\"creator_trace_id\""));
        assert!(json.contains("\"obligation_age_ticks\""));
        assert!(json.contains("\"region_id\""));
        assert!(json.contains("\"component\""));
    }

    #[test]
    fn leak_metrics_equality() {
        let mut m1 = LeakMetrics::default();
        let mut m2 = LeakMetrics::default();
        m1.record("r", "c", "comp");
        m2.record("r", "c", "comp");
        assert_eq!(m1, m2);
        m2.record("r", "c", "comp");
        assert_ne!(m1, m2);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn policy_clone_independence() {
        let p1 = ObligationLeakPolicy::Lab;
        let p2 = p1;
        assert_eq!(p1.to_string(), "lab");
        assert_eq!(p2.to_string(), "lab");
    }

    #[test]
    fn severity_clone_independence() {
        let s1 = LeakSeverity::Fatal;
        let s2 = s1;
        assert_eq!(s1, s2);
        assert_eq!(s1.to_string(), "fatal");
        assert_eq!(s2.to_string(), "fatal");
    }

    #[test]
    fn diagnostic_clone_independence_mutation_does_not_cross() {
        let diag1 = test_diagnostic();
        let mut diag2 = diag1.clone();
        diag2.obligation_id = 9999;
        diag2.channel_id = "mutated".to_string();
        assert_eq!(diag1.obligation_id, 42);
        assert_eq!(diag1.channel_id, "chan-1");
        assert_eq!(diag2.obligation_id, 9999);
    }

    #[test]
    fn failover_action_clone_independence() {
        let a1 = FailoverAction::ScopedRegionClose {
            region_id: "original".to_string(),
        };
        let a2 = a1.clone();
        assert_eq!(a1, a2);
        assert_eq!(a1.to_string(), a2.to_string());
    }

    #[test]
    fn leak_event_clone_independence() {
        let event = LeakEvent {
            trace_id: "t-1".to_string(),
            obligation_id: 10,
            channel_id: "c-1".to_string(),
            region_id: "r-1".to_string(),
            component: "comp-1".to_string(),
            leak_policy: ObligationLeakPolicy::Production,
            failover_action: Some(FailoverAction::AlertOnly),
            severity: LeakSeverity::Warning,
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
        assert_eq!(event.trace_id, cloned.trace_id);
    }

    #[test]
    fn leak_response_handled_clone_independence() {
        let resp = LeakResponse::Handled {
            event: LeakEvent {
                trace_id: "t".to_string(),
                obligation_id: 1,
                channel_id: "c".to_string(),
                region_id: "r".to_string(),
                component: "comp".to_string(),
                leak_policy: ObligationLeakPolicy::Production,
                failover_action: None,
                severity: LeakSeverity::Critical,
            },
            failover: Some(FailoverAction::ScopedRegionClose {
                region_id: "r".to_string(),
            }),
        };
        let cloned = resp.clone();
        assert_eq!(resp, cloned);
    }

    #[test]
    fn leak_metrics_clone_independence() {
        let mut m1 = LeakMetrics::default();
        m1.record("r", "c", "comp");
        let mut m2 = m1.clone();
        m2.record("r2", "c2", "comp2");
        assert_eq!(m1.total, 1);
        assert_eq!(m2.total, 2);
    }

    #[test]
    fn severity_btreeset_insertion_and_ordering() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(LeakSeverity::Fatal);
        set.insert(LeakSeverity::Warning);
        set.insert(LeakSeverity::Critical);
        set.insert(LeakSeverity::Warning);
        assert_eq!(set.len(), 3);
        let ordered: Vec<LeakSeverity> = set.into_iter().collect();
        assert_eq!(
            ordered,
            vec![
                LeakSeverity::Warning,
                LeakSeverity::Critical,
                LeakSeverity::Fatal
            ]
        );
    }

    #[test]
    fn severity_btreeset_dedup() {
        use std::collections::BTreeSet;
        let mut set = BTreeSet::new();
        for _ in 0..100 {
            set.insert(LeakSeverity::Critical);
        }
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn policy_serde_json_string_shape() {
        let json_lab = serde_json::to_string(&ObligationLeakPolicy::Lab)
            .expect("serde deserialization should succeed");
        let json_prod = serde_json::to_string(&ObligationLeakPolicy::Production)
            .expect("serde deserialization should succeed");
        assert!(json_lab.starts_with('"'));
        assert!(json_prod.starts_with('"'));
        assert_ne!(json_lab, json_prod);
    }

    #[test]
    fn severity_serde_json_string_shape() {
        for sev in [
            LeakSeverity::Warning,
            LeakSeverity::Critical,
            LeakSeverity::Fatal,
        ] {
            let json = serde_json::to_string(&sev).expect("serialize derived Serialize");
            assert!(json.starts_with('"'), "severity should serialize as string");
        }
    }

    #[test]
    fn failover_action_serde_tagged_shape() {
        let alert = serde_json::to_string(&FailoverAction::AlertOnly)
            .expect("serde deserialization should succeed");
        let scoped = serde_json::to_string(&FailoverAction::ScopedRegionClose {
            region_id: "r".to_string(),
        })
        .expect("serde deserialization should succeed");
        assert_ne!(alert, scoped);
    }

    #[test]
    fn leak_response_serde_abort_tagged() {
        let resp = LeakResponse::Abort {
            diagnostic: test_diagnostic(),
        };
        let json = serde_json::to_string(&resp).expect("serialize derived Serialize");
        assert!(json.contains("Abort"));
    }

    #[test]
    fn leak_response_serde_handled_tagged() {
        let resp = LeakResponse::Handled {
            event: LeakEvent {
                trace_id: "t".to_string(),
                obligation_id: 1,
                channel_id: "c".to_string(),
                region_id: "r".to_string(),
                component: "comp".to_string(),
                leak_policy: ObligationLeakPolicy::Production,
                failover_action: None,
                severity: LeakSeverity::Warning,
            },
            failover: None,
        };
        let json = serde_json::to_string(&resp).expect("serialize derived Serialize");
        assert!(json.contains("Handled"));
    }

    #[test]
    fn diagnostic_display_format_exact() {
        let diag = LeakDiagnostic {
            obligation_id: 7,
            channel_id: "ch".to_string(),
            creator_trace_id: "tr".to_string(),
            obligation_age_ticks: 300,
            region_id: "rg".to_string(),
            component: "cp".to_string(),
        };
        let expected =
            "obligation leak: id=7, channel=ch, trace=tr, age=300, region=rg, component=cp";
        assert_eq!(diag.to_string(), expected);
    }

    #[test]
    fn handler_interleaved_drain_and_leak() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        handler.handle_leak(test_diagnostic());
        let batch1 = handler.drain_events();
        assert_eq!(batch1.len(), 1);

        handler.handle_leak(test_diagnostic());
        handler.handle_leak(test_diagnostic());
        let batch2 = handler.drain_events();
        assert_eq!(batch2.len(), 2);

        let batch3 = handler.drain_events();
        assert!(batch3.is_empty());
    }

    #[test]
    fn handler_metrics_persist_after_drain() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        handler.handle_leak(test_diagnostic());
        handler.handle_leak(test_diagnostic());
        let _ = handler.drain_events();
        assert_eq!(handler.metrics().total, 2);
    }

    #[test]
    fn deterministic_replay_lab_mode() {
        let run = || -> Vec<LeakResponse> {
            let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
            let mut results = Vec::new();
            for i in 0..3u64 {
                results.push(handler.handle_leak(LeakDiagnostic {
                    obligation_id: i,
                    channel_id: format!("c-{i}"),
                    creator_trace_id: format!("t-{i}"),
                    obligation_age_ticks: i * 100,
                    region_id: format!("r-{i}"),
                    component: "comp".to_string(),
                }));
            }
            results
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn deterministic_replay_metrics() {
        let run = || -> LeakMetrics {
            let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
            for i in 0..10u64 {
                handler.handle_leak(LeakDiagnostic {
                    obligation_id: i,
                    channel_id: format!("c-{}", i % 3),
                    creator_trace_id: format!("t-{i}"),
                    obligation_age_ticks: i,
                    region_id: format!("r-{}", i % 4),
                    component: format!("comp-{}", i % 2),
                });
            }
            handler.metrics().clone()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn metrics_channel_keys_deterministically_ordered() {
        let mut metrics = LeakMetrics::default();
        metrics.record("r", "z-chan", "comp");
        metrics.record("r", "a-chan", "comp");
        metrics.record("r", "m-chan", "comp");
        let keys: Vec<&String> = metrics.by_channel.keys().collect();
        assert_eq!(keys, vec!["a-chan", "m-chan", "z-chan"]);
    }

    #[test]
    fn metrics_component_keys_deterministically_ordered() {
        let mut metrics = LeakMetrics::default();
        metrics.record("r", "c", "zulu");
        metrics.record("r", "c", "alpha");
        metrics.record("r", "c", "mike");
        let keys: Vec<&String> = metrics.by_component.keys().collect();
        assert_eq!(keys, vec!["alpha", "mike", "zulu"]);
    }

    #[test]
    fn stress_500_leaks_events_and_metrics_consistent() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        for i in 0..500u64 {
            handler.handle_leak(LeakDiagnostic {
                obligation_id: i,
                channel_id: format!("chan-{}", i % 20),
                creator_trace_id: format!("trace-{i}"),
                obligation_age_ticks: i,
                region_id: format!("region-{}", i % 7),
                component: format!("comp-{}", i % 4),
            });
        }
        assert_eq!(handler.metrics().total, 500);
        assert_eq!(handler.metrics().by_region.len(), 7);
        assert_eq!(handler.metrics().by_channel.len(), 20);
        assert_eq!(handler.metrics().by_component.len(), 4);
        let events = handler.drain_events();
        assert_eq!(events.len(), 500);
        for (idx, event) in events.iter().enumerate() {
            assert_eq!(event.obligation_id, idx as u64);
        }
    }

    #[test]
    fn stress_lab_mode_no_events_but_metrics_counted() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        for i in 0..200u64 {
            let resp = handler.handle_leak(LeakDiagnostic {
                obligation_id: i,
                channel_id: "c".to_string(),
                creator_trace_id: "t".to_string(),
                obligation_age_ticks: 0,
                region_id: "r".to_string(),
                component: "comp".to_string(),
            });
            assert!(matches!(resp, LeakResponse::Abort { .. }));
        }
        assert_eq!(handler.metrics().total, 200);
        assert!(handler.drain_events().is_empty());
    }

    #[test]
    fn leak_diagnostic_debug_impl() {
        let diag = test_diagnostic();
        let debug = format!("{:?}", diag);
        assert!(debug.contains("LeakDiagnostic"));
        assert!(debug.contains("42"));
    }

    #[test]
    fn leak_event_debug_impl() {
        let event = LeakEvent {
            trace_id: "t".to_string(),
            obligation_id: 77,
            channel_id: "c".to_string(),
            region_id: "r".to_string(),
            component: "comp".to_string(),
            leak_policy: ObligationLeakPolicy::Lab,
            failover_action: None,
            severity: LeakSeverity::Fatal,
        };
        let debug = format!("{:?}", event);
        assert!(debug.contains("LeakEvent"));
        assert!(debug.contains("77"));
    }

    #[test]
    fn leak_handler_debug_impl() {
        let handler = LeakHandler::new(ObligationLeakPolicy::Production);
        let debug = format!("{:?}", handler);
        assert!(debug.contains("LeakHandler"));
        assert!(debug.contains("Production"));
    }

    #[test]
    fn leak_metrics_debug_impl() {
        let mut metrics = LeakMetrics::default();
        metrics.record("r", "c", "comp");
        let debug = format!("{:?}", metrics);
        assert!(debug.contains("LeakMetrics"));
        assert!(debug.contains("total: 1"));
    }

    #[test]
    fn leak_response_debug_impl() {
        let resp = LeakResponse::Abort {
            diagnostic: test_diagnostic(),
        };
        let debug = format!("{:?}", resp);
        assert!(debug.contains("Abort"));
    }

    #[test]
    fn failover_action_debug_impl() {
        let action = FailoverAction::AlertOnly;
        let debug = format!("{:?}", action);
        assert!(debug.contains("AlertOnly"));
    }

    #[test]
    fn empty_handler_drain_returns_empty() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        assert!(handler.drain_events().is_empty());
    }

    #[test]
    fn serde_invalid_json_rejected_for_policy() {
        let result = serde_json::from_str::<ObligationLeakPolicy>("\"NonExistent\"");
        assert!(result.is_err());
    }

    #[test]
    fn serde_invalid_json_rejected_for_severity() {
        let result = serde_json::from_str::<LeakSeverity>("\"Extreme\"");
        assert!(result.is_err());
    }

    #[test]
    fn serde_malformed_json_rejected_for_diagnostic() {
        let result =
            serde_json::from_str::<LeakDiagnostic>("{\"obligation_id\": \"not_a_number\"}");
        assert!(result.is_err());
    }

    #[test]
    fn serde_missing_fields_rejected_for_diagnostic() {
        let result = serde_json::from_str::<LeakDiagnostic>("{\"obligation_id\": 1}");
        assert!(result.is_err());
    }

    #[test]
    fn serde_missing_fields_rejected_for_leak_event() {
        let result = serde_json::from_str::<LeakEvent>("{}");
        assert!(result.is_err());
    }

    #[test]
    fn metrics_record_with_unicode_keys() {
        let mut metrics = LeakMetrics::default();
        metrics.record(
            "region-\u{1F600}",
            "chan-\u{03B1}\u{03B2}",
            "comp-\u{4E16}\u{754C}",
        );
        assert_eq!(metrics.total, 1);
        assert_eq!(metrics.by_region.get("region-\u{1F600}"), Some(&1));
        let json = serde_json::to_string(&metrics).expect("serialize derived Serialize");
        let restored: LeakMetrics =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(metrics, restored);
    }

    #[test]
    fn diagnostic_with_long_strings() {
        let long_string = "x".repeat(10_000);
        let diag = LeakDiagnostic {
            obligation_id: 1,
            channel_id: long_string.clone(),
            creator_trace_id: long_string.clone(),
            obligation_age_ticks: 0,
            region_id: long_string.clone(),
            component: long_string.clone(),
        };
        let json = serde_json::to_string(&diag).expect("serialize derived Serialize");
        let restored: LeakDiagnostic =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(diag, restored);
        assert_eq!(restored.channel_id.len(), 10_000);
    }

    #[test]
    fn failover_action_eq_same_variant_different_data() {
        let a1 = FailoverAction::ScopedRegionClose {
            region_id: "r-1".to_string(),
        };
        let a2 = FailoverAction::ScopedRegionClose {
            region_id: "r-2".to_string(),
        };
        assert_ne!(a1, a2);
    }

    #[test]
    fn failover_action_eq_different_variants() {
        let a1 = FailoverAction::AlertOnly;
        let a2 = FailoverAction::ScopedRegionClose {
            region_id: "r".to_string(),
        };
        assert_ne!(a1, a2);
    }

    #[test]
    fn leak_event_ne_on_different_obligation_ids() {
        let make = |id: u64| LeakEvent {
            trace_id: "t".to_string(),
            obligation_id: id,
            channel_id: "c".to_string(),
            region_id: "r".to_string(),
            component: "comp".to_string(),
            leak_policy: ObligationLeakPolicy::Production,
            failover_action: None,
            severity: LeakSeverity::Critical,
        };
        assert_ne!(make(1), make(2));
        assert_eq!(make(42), make(42));
    }

    #[test]
    fn production_failover_always_scoped_region_close() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        for i in 0..10u64 {
            let resp = handler.handle_leak(LeakDiagnostic {
                obligation_id: i,
                channel_id: "c".to_string(),
                creator_trace_id: "t".to_string(),
                obligation_age_ticks: 0,
                region_id: format!("r-{i}"),
                component: "comp".to_string(),
            });
            if let LeakResponse::Handled { failover, .. } = resp {
                match failover {
                    Some(FailoverAction::ScopedRegionClose { region_id }) => {
                        assert_eq!(region_id, format!("r-{i}"));
                    }
                    other => panic!("expected ScopedRegionClose, got {:?}", other),
                }
            } else {
                panic!("expected Handled");
            }
        }
    }

    #[test]
    fn metrics_sum_by_region_equals_total() {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        for i in 0..50u64 {
            handler.handle_leak(LeakDiagnostic {
                obligation_id: i,
                channel_id: format!("c-{}", i % 5),
                creator_trace_id: "t".to_string(),
                obligation_age_ticks: 0,
                region_id: format!("r-{}", i % 8),
                component: "comp".to_string(),
            });
        }
        let metrics = handler.metrics();
        let region_sum: u64 = metrics.by_region.values().sum();
        assert_eq!(region_sum, metrics.total);
        let channel_sum: u64 = metrics.by_channel.values().sum();
        assert_eq!(channel_sum, metrics.total);
        let component_sum: u64 = metrics.by_component.values().sum();
        assert_eq!(component_sum, metrics.total);
    }

    #[test]
    fn leak_event_serde_all_severity_and_policy_combos() {
        for policy in [ObligationLeakPolicy::Lab, ObligationLeakPolicy::Production] {
            for severity in [
                LeakSeverity::Warning,
                LeakSeverity::Critical,
                LeakSeverity::Fatal,
            ] {
                let event = LeakEvent {
                    trace_id: "t".to_string(),
                    obligation_id: 0,
                    channel_id: "c".to_string(),
                    region_id: "r".to_string(),
                    component: "comp".to_string(),
                    leak_policy: policy,
                    failover_action: None,
                    severity,
                };
                let json = serde_json::to_string(&event).expect("serialize derived Serialize");
                let restored: LeakEvent =
                    serde_json::from_str(&json).expect("deserialize known-valid JSON");
                assert_eq!(event, restored);
            }
        }
    }

    #[test]
    fn deterministic_replay_full_scenario() {
        let run = || {
            let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
            let mut responses = Vec::new();
            for i in 0..20u64 {
                responses.push(handler.handle_leak(LeakDiagnostic {
                    obligation_id: i,
                    channel_id: format!("c-{}", i % 4),
                    creator_trace_id: format!("t-{i}"),
                    obligation_age_ticks: i * 50,
                    region_id: format!("r-{}", i % 3),
                    component: format!("comp-{}", i % 2),
                }));
            }
            let events = handler.drain_events();
            let metrics = handler.metrics().clone();
            (responses, events, metrics)
        };
        let (r1, e1, m1) = run();
        let (r2, e2, m2) = run();
        assert_eq!(r1, r2);
        assert_eq!(e1, e2);
        assert_eq!(m1, m2);
    }
}
