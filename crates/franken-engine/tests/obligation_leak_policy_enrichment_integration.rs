//! Enrichment integration tests for `obligation_leak_policy`.
//!
//! Covers: serde round-trips for all types, LeakHandler lab/production modes,
//! LeakMetrics aggregation, event emission, deterministic replay, Display
//! implementations, clone independence, severity ordering, and boundary
//! conditions.

#![allow(clippy::too_many_arguments)]

use std::collections::BTreeSet;

use frankenengine_engine::obligation_leak_policy::{
    FailoverAction, LeakDiagnostic, LeakEvent, LeakHandler, LeakMetrics, LeakResponse,
    LeakSeverity, ObligationLeakPolicy,
};

// ===========================================================================
// Helpers
// ===========================================================================

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

fn make_diagnostic(id: u64, region: &str, channel: &str, component: &str) -> LeakDiagnostic {
    LeakDiagnostic {
        obligation_id: id,
        channel_id: channel.to_string(),
        creator_trace_id: format!("trace-{id}"),
        obligation_age_ticks: id * 100,
        region_id: region.to_string(),
        component: component.to_string(),
    }
}

// ===========================================================================
// Serde round-trip tests
// ===========================================================================

#[test]
fn integ_policy_serde_both_variants() {
    for policy in [ObligationLeakPolicy::Lab, ObligationLeakPolicy::Production] {
        let json = serde_json::to_string(&policy).unwrap();
        let back: ObligationLeakPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }
}

#[test]
fn integ_severity_serde_all_variants() {
    for sev in [
        LeakSeverity::Warning,
        LeakSeverity::Critical,
        LeakSeverity::Fatal,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: LeakSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

#[test]
fn integ_failover_action_serde_both_variants() {
    let actions = [
        FailoverAction::ScopedRegionClose {
            region_id: "r-42".to_string(),
        },
        FailoverAction::AlertOnly,
    ];
    for action in &actions {
        let json = serde_json::to_string(action).unwrap();
        let back: FailoverAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*action, back);
    }
}

#[test]
fn integ_leak_diagnostic_serde_roundtrip() {
    let diag = test_diagnostic();
    let json = serde_json::to_string(&diag).unwrap();
    let back: LeakDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

#[test]
fn integ_leak_event_serde_roundtrip() {
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
    let json = serde_json::to_string(&event).unwrap();
    let back: LeakEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn integ_leak_event_with_alert_only_serde() {
    let event = LeakEvent {
        trace_id: "t".to_string(),
        obligation_id: 0,
        channel_id: "c".to_string(),
        region_id: "r".to_string(),
        component: "comp".to_string(),
        leak_policy: ObligationLeakPolicy::Production,
        failover_action: Some(FailoverAction::AlertOnly),
        severity: LeakSeverity::Warning,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: LeakEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn integ_leak_event_no_failover_serde() {
    let event = LeakEvent {
        trace_id: "t".to_string(),
        obligation_id: 0,
        channel_id: "c".to_string(),
        region_id: "r".to_string(),
        component: "comp".to_string(),
        leak_policy: ObligationLeakPolicy::Lab,
        failover_action: None,
        severity: LeakSeverity::Fatal,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: LeakEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn integ_leak_metrics_serde_roundtrip() {
    let mut metrics = LeakMetrics::default();
    metrics.record("r-1", "c-1", "comp-1");
    metrics.record("r-2", "c-1", "comp-2");
    let json = serde_json::to_string(&metrics).unwrap();
    let back: LeakMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(metrics, back);
}

#[test]
fn integ_leak_response_serde_abort() {
    let resp = LeakResponse::Abort {
        diagnostic: test_diagnostic(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let back: LeakResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, back);
}

#[test]
fn integ_leak_response_serde_handled() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    let resp = handler.handle_leak(test_diagnostic());
    let json = serde_json::to_string(&resp).unwrap();
    let back: LeakResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, back);
}

// ===========================================================================
// Display tests
// ===========================================================================

#[test]
fn integ_policy_display_unique() {
    let displays: BTreeSet<String> = [ObligationLeakPolicy::Lab, ObligationLeakPolicy::Production]
        .iter()
        .map(|p| p.to_string())
        .collect();
    assert_eq!(displays.len(), 2);
}

#[test]
fn integ_severity_display_unique() {
    let displays: BTreeSet<String> = [
        LeakSeverity::Warning,
        LeakSeverity::Critical,
        LeakSeverity::Fatal,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn integ_failover_action_display_unique() {
    let displays: BTreeSet<String> = [
        FailoverAction::ScopedRegionClose {
            region_id: "r".to_string(),
        },
        FailoverAction::AlertOnly,
    ]
    .iter()
    .map(|a| a.to_string())
    .collect();
    assert_eq!(displays.len(), 2);
}

#[test]
fn integ_diagnostic_display_contains_all_fields() {
    let diag = test_diagnostic();
    let s = diag.to_string();
    assert!(s.contains("42"));
    assert!(s.contains("chan-1"));
    assert!(s.contains("trace-1"));
    assert!(s.contains("500"));
    assert!(s.contains("region-1"));
    assert!(s.contains("policy_controller"));
}

// ===========================================================================
// Lab mode tests
// ===========================================================================

#[test]
fn integ_lab_mode_returns_abort() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    let resp = handler.handle_leak(test_diagnostic());
    assert!(matches!(resp, LeakResponse::Abort { .. }));
}

#[test]
fn integ_lab_mode_abort_includes_diagnostic() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    let diag = test_diagnostic();
    if let LeakResponse::Abort { diagnostic } = handler.handle_leak(diag.clone()) {
        assert_eq!(diagnostic, diag);
    } else {
        panic!("expected Abort");
    }
}

#[test]
fn integ_lab_mode_does_not_emit_events() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    handler.handle_leak(test_diagnostic());
    assert!(handler.drain_events().is_empty());
}

#[test]
fn integ_lab_mode_records_metrics() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    handler.handle_leak(test_diagnostic());
    assert_eq!(handler.metrics().total, 1);
}

// ===========================================================================
// Production mode tests
// ===========================================================================

#[test]
fn integ_production_mode_returns_handled() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    let resp = handler.handle_leak(test_diagnostic());
    assert!(matches!(resp, LeakResponse::Handled { .. }));
}

#[test]
fn integ_production_mode_triggers_scoped_failover() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    if let LeakResponse::Handled { failover, .. } = handler.handle_leak(test_diagnostic()) {
        assert!(matches!(
            failover,
            Some(FailoverAction::ScopedRegionClose { .. })
        ));
    } else {
        panic!("expected Handled");
    }
}

#[test]
fn integ_production_failover_region_matches_diagnostic() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    let diag = make_diagnostic(1, "my-region", "c", "comp");
    if let LeakResponse::Handled { failover, .. } = handler.handle_leak(diag) {
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
fn integ_production_emits_events() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    handler.handle_leak(test_diagnostic());
    let events = handler.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].obligation_id, 42);
    assert_eq!(events[0].severity, LeakSeverity::Critical);
}

#[test]
fn integ_production_event_fields() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    handler.handle_leak(test_diagnostic());
    let events = handler.drain_events();
    let event = &events[0];
    assert_eq!(event.trace_id, "trace-1");
    assert_eq!(event.channel_id, "chan-1");
    assert_eq!(event.region_id, "region-1");
    assert_eq!(event.component, "policy_controller");
    assert_eq!(event.leak_policy, ObligationLeakPolicy::Production);
}

// ===========================================================================
// Metrics tests
// ===========================================================================

#[test]
fn integ_metrics_default_is_zero() {
    let metrics = LeakMetrics::default();
    assert_eq!(metrics.total, 0);
    assert!(metrics.by_region.is_empty());
    assert!(metrics.by_channel.is_empty());
    assert!(metrics.by_component.is_empty());
}

#[test]
fn integ_metrics_increment_on_leak() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    handler.handle_leak(make_diagnostic(1, "r-1", "c-1", "comp-1"));
    handler.handle_leak(make_diagnostic(2, "r-1", "c-2", "comp-2"));
    let metrics = handler.metrics();
    assert_eq!(metrics.total, 2);
    assert_eq!(metrics.by_region.get("r-1"), Some(&2));
    assert_eq!(metrics.by_channel.get("c-1"), Some(&1));
    assert_eq!(metrics.by_channel.get("c-2"), Some(&1));
}

#[test]
fn integ_metrics_deterministic_ordering() {
    let mut metrics = LeakMetrics::default();
    metrics.record("z-region", "c", "comp");
    metrics.record("a-region", "c", "comp");
    metrics.record("m-region", "c", "comp");
    let keys: Vec<&String> = metrics.by_region.keys().collect();
    assert_eq!(keys, vec!["a-region", "m-region", "z-region"]);
}

#[test]
fn integ_metrics_sum_equals_total() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    for i in 0..30u64 {
        handler.handle_leak(make_diagnostic(
            i,
            &format!("r-{}", i % 5),
            &format!("c-{}", i % 3),
            "comp",
        ));
    }
    let metrics = handler.metrics();
    let region_sum: u64 = metrics.by_region.values().sum();
    assert_eq!(region_sum, metrics.total);
}

// ===========================================================================
// Severity ordering tests
// ===========================================================================

#[test]
fn integ_severity_ordering() {
    assert!(LeakSeverity::Warning < LeakSeverity::Critical);
    assert!(LeakSeverity::Critical < LeakSeverity::Fatal);
    assert!(LeakSeverity::Warning < LeakSeverity::Fatal);
}

#[test]
fn integ_severity_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(LeakSeverity::Fatal);
    set.insert(LeakSeverity::Warning);
    set.insert(LeakSeverity::Critical);
    let ordered: Vec<_> = set.into_iter().collect();
    assert_eq!(
        ordered,
        vec![
            LeakSeverity::Warning,
            LeakSeverity::Critical,
            LeakSeverity::Fatal
        ]
    );
}

// ===========================================================================
// Clone independence tests
// ===========================================================================

#[test]
fn integ_diagnostic_clone_independence() {
    let diag = test_diagnostic();
    let mut cloned = diag.clone();
    cloned.obligation_id = 9999;
    cloned.channel_id = "mutated".to_string();
    assert_eq!(diag.obligation_id, 42);
    assert_eq!(diag.channel_id, "chan-1");
}

#[test]
fn integ_leak_event_clone_independence() {
    let event = LeakEvent {
        trace_id: "t".to_string(),
        obligation_id: 10,
        channel_id: "c".to_string(),
        region_id: "r".to_string(),
        component: "comp".to_string(),
        leak_policy: ObligationLeakPolicy::Production,
        failover_action: Some(FailoverAction::AlertOnly),
        severity: LeakSeverity::Warning,
    };
    let cloned = event.clone();
    assert_eq!(event, cloned);
}

#[test]
fn integ_leak_metrics_clone_independence() {
    let mut m1 = LeakMetrics::default();
    m1.record("r", "c", "comp");
    let mut m2 = m1.clone();
    m2.record("r2", "c2", "comp2");
    assert_eq!(m1.total, 1);
    assert_eq!(m2.total, 2);
}

// ===========================================================================
// Handler semantics tests
// ===========================================================================

#[test]
fn integ_handler_policy_accessor() {
    let h = LeakHandler::new(ObligationLeakPolicy::Lab);
    assert_eq!(h.policy(), ObligationLeakPolicy::Lab);
}

#[test]
fn integ_drain_clears_buffer() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    handler.handle_leak(test_diagnostic());
    handler.handle_leak(test_diagnostic());
    let events = handler.drain_events();
    assert_eq!(events.len(), 2);
    assert!(handler.drain_events().is_empty());
}

#[test]
fn integ_metrics_persist_after_drain() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    handler.handle_leak(test_diagnostic());
    let _ = handler.drain_events();
    assert_eq!(handler.metrics().total, 1);
}

#[test]
fn integ_handlers_are_isolated() {
    let mut h1 = LeakHandler::new(ObligationLeakPolicy::Production);
    let mut h2 = LeakHandler::new(ObligationLeakPolicy::Production);
    h1.handle_leak(test_diagnostic());
    h1.handle_leak(test_diagnostic());
    h2.handle_leak(test_diagnostic());
    assert_eq!(h1.metrics().total, 2);
    assert_eq!(h2.metrics().total, 1);
}

// ===========================================================================
// Deterministic replay tests
// ===========================================================================

#[test]
fn integ_deterministic_replay_production() {
    let run = || -> Vec<LeakEvent> {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        handler.handle_leak(test_diagnostic());
        handler.handle_leak(make_diagnostic(99, "r-2", "c-x", "scheduler"));
        handler.drain_events()
    };
    assert_eq!(run(), run());
}

#[test]
fn integ_deterministic_replay_metrics() {
    let run = || -> LeakMetrics {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        for i in 0..10u64 {
            handler.handle_leak(make_diagnostic(
                i,
                &format!("r-{}", i % 4),
                &format!("c-{}", i % 3),
                "comp",
            ));
        }
        handler.metrics().clone()
    };
    assert_eq!(run(), run());
}

#[test]
fn integ_deterministic_replay_lab_responses() {
    let run = || -> Vec<LeakResponse> {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        let mut results = Vec::new();
        for i in 0..3u64 {
            results.push(handler.handle_leak(make_diagnostic(
                i,
                &format!("r-{i}"),
                &format!("c-{i}"),
                "comp",
            )));
        }
        results
    };
    assert_eq!(run(), run());
}

// ===========================================================================
// Boundary and stress tests
// ===========================================================================

#[test]
fn integ_diagnostic_with_empty_strings() {
    let diag = LeakDiagnostic {
        obligation_id: 0,
        channel_id: String::new(),
        creator_trace_id: String::new(),
        obligation_age_ticks: 0,
        region_id: String::new(),
        component: String::new(),
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: LeakDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
    assert!(diag.to_string().contains("obligation leak"));
}

#[test]
fn integ_diagnostic_with_max_id() {
    let diag = LeakDiagnostic {
        obligation_id: u64::MAX,
        channel_id: "c".to_string(),
        creator_trace_id: "t".to_string(),
        obligation_age_ticks: u64::MAX,
        region_id: "r".to_string(),
        component: "comp".to_string(),
    };
    let json = serde_json::to_string(&diag).unwrap();
    let back: LeakDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

#[test]
fn integ_stress_100_production_leaks() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    for i in 0..100u64 {
        handler.handle_leak(make_diagnostic(
            i,
            &format!("r-{}", i % 5),
            &format!("c-{}", i % 10),
            &format!("comp-{}", i % 3),
        ));
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
fn integ_stress_lab_mode_no_events() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    for i in 0..50u64 {
        let resp = handler.handle_leak(make_diagnostic(i, "r", "c", "comp"));
        assert!(matches!(resp, LeakResponse::Abort { .. }));
    }
    assert_eq!(handler.metrics().total, 50);
    assert!(handler.drain_events().is_empty());
}

#[test]
fn integ_serde_invalid_policy_rejected() {
    let result = serde_json::from_str::<ObligationLeakPolicy>("\"NonExistent\"");
    assert!(result.is_err());
}

#[test]
fn integ_serde_invalid_severity_rejected() {
    let result = serde_json::from_str::<LeakSeverity>("\"Extreme\"");
    assert!(result.is_err());
}
