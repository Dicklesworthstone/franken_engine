#![forbid(unsafe_code)]
//! Comprehensive integration tests for the `obligation_leak_policy` module.
//!
//! Covers:
//! - Display impls for all public types
//! - Construction and defaults for LeakMetrics, LeakHandler
//! - State transitions: Lab abort, Production handled, drain events
//! - Error conditions and edge cases
//! - Serde round-trips for every public type
//! - Deterministic replay
//! - LeakSeverity ordering
//! - FailoverAction variants
//! - Multi-region / multi-channel / multi-component metrics accumulation

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::obligation_leak_policy::{
    FailoverAction, LeakDiagnostic, LeakEvent, LeakHandler, LeakMetrics, LeakResponse,
    LeakSeverity, ObligationLeakPolicy,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_diagnostic(
    obligation_id: u64,
    channel: &str,
    trace: &str,
    age: u64,
    region: &str,
    component: &str,
) -> LeakDiagnostic {
    LeakDiagnostic {
        obligation_id,
        channel_id: channel.to_string(),
        creator_trace_id: trace.to_string(),
        obligation_age_ticks: age,
        region_id: region.to_string(),
        component: component.to_string(),
    }
}

fn default_diagnostic() -> LeakDiagnostic {
    make_diagnostic(
        100,
        "ch-alpha",
        "trace-alpha",
        1000,
        "region-a",
        "scheduler",
    )
}

// ===========================================================================
// Section 1: ObligationLeakPolicy Display
// ===========================================================================

#[test]
fn policy_lab_display() {
    assert_eq!(ObligationLeakPolicy::Lab.to_string(), "lab");
}

#[test]
fn policy_production_display() {
    assert_eq!(ObligationLeakPolicy::Production.to_string(), "production");
}

#[test]
fn policy_clone_and_eq() {
    let p = ObligationLeakPolicy::Lab;
    let p2 = p;
    assert_eq!(p, p2);
}

#[test]
fn policy_debug_contains_variant() {
    let dbg = format!("{:?}", ObligationLeakPolicy::Lab);
    assert!(dbg.contains("Lab"));
    let dbg2 = format!("{:?}", ObligationLeakPolicy::Production);
    assert!(dbg2.contains("Production"));
}

// ===========================================================================
// Section 2: LeakDiagnostic
// ===========================================================================

#[test]
fn diagnostic_display_contains_all_fields() {
    let diag = make_diagnostic(42, "chan-1", "trace-1", 500, "region-1", "policy_ctrl");
    let s = diag.to_string();
    assert!(s.contains("obligation leak"));
    assert!(s.contains("42"));
    assert!(s.contains("chan-1"));
    assert!(s.contains("trace-1"));
    assert!(s.contains("500"));
    assert!(s.contains("region-1"));
    assert!(s.contains("policy_ctrl"));
}

#[test]
fn diagnostic_display_exact_format() {
    let diag = make_diagnostic(7, "c", "t", 99, "r", "comp");
    assert_eq!(
        diag.to_string(),
        "obligation leak: id=7, channel=c, trace=t, age=99, region=r, component=comp"
    );
}

#[test]
fn diagnostic_clone_equals_original() {
    let diag = default_diagnostic();
    let cloned = diag.clone();
    assert_eq!(diag, cloned);
}

#[test]
fn diagnostic_partial_eq_different_ids() {
    let d1 = make_diagnostic(1, "c", "t", 10, "r", "comp");
    let d2 = make_diagnostic(2, "c", "t", 10, "r", "comp");
    assert_ne!(d1, d2);
}

#[test]
fn diagnostic_partial_eq_different_channels() {
    let d1 = make_diagnostic(1, "c1", "t", 10, "r", "comp");
    let d2 = make_diagnostic(1, "c2", "t", 10, "r", "comp");
    assert_ne!(d1, d2);
}

#[test]
fn diagnostic_partial_eq_different_ages() {
    let d1 = make_diagnostic(1, "c", "t", 10, "r", "comp");
    let d2 = make_diagnostic(1, "c", "t", 20, "r", "comp");
    assert_ne!(d1, d2);
}

// ===========================================================================
// Section 3: LeakSeverity
// ===========================================================================

#[test]
fn severity_display_warning() {
    assert_eq!(LeakSeverity::Warning.to_string(), "warning");
}

#[test]
fn severity_display_critical() {
    assert_eq!(LeakSeverity::Critical.to_string(), "critical");
}

#[test]
fn severity_display_fatal() {
    assert_eq!(LeakSeverity::Fatal.to_string(), "fatal");
}

#[test]
fn severity_ordering_warning_lt_critical() {
    assert!(LeakSeverity::Warning < LeakSeverity::Critical);
}

#[test]
fn severity_ordering_critical_lt_fatal() {
    assert!(LeakSeverity::Critical < LeakSeverity::Fatal);
}

#[test]
fn severity_ordering_warning_lt_fatal() {
    assert!(LeakSeverity::Warning < LeakSeverity::Fatal);
}

#[test]
fn severity_eq_self() {
    assert_eq!(LeakSeverity::Warning, LeakSeverity::Warning);
    assert_eq!(LeakSeverity::Critical, LeakSeverity::Critical);
    assert_eq!(LeakSeverity::Fatal, LeakSeverity::Fatal);
}

#[test]
fn severity_ord_sorted_vec() {
    let mut severities = vec![
        LeakSeverity::Fatal,
        LeakSeverity::Warning,
        LeakSeverity::Critical,
    ];
    severities.sort();
    assert_eq!(
        severities,
        vec![
            LeakSeverity::Warning,
            LeakSeverity::Critical,
            LeakSeverity::Fatal,
        ]
    );
}

// ===========================================================================
// Section 4: FailoverAction
// ===========================================================================

#[test]
fn failover_scoped_region_close_display() {
    let action = FailoverAction::ScopedRegionClose {
        region_id: "region-42".to_string(),
    };
    assert_eq!(action.to_string(), "scoped_region_close:region-42");
}

#[test]
fn failover_alert_only_display() {
    assert_eq!(FailoverAction::AlertOnly.to_string(), "alert_only");
}

#[test]
fn failover_eq_same_region() {
    let a = FailoverAction::ScopedRegionClose {
        region_id: "r".to_string(),
    };
    let b = FailoverAction::ScopedRegionClose {
        region_id: "r".to_string(),
    };
    assert_eq!(a, b);
}

#[test]
fn failover_ne_different_regions() {
    let a = FailoverAction::ScopedRegionClose {
        region_id: "r1".to_string(),
    };
    let b = FailoverAction::ScopedRegionClose {
        region_id: "r2".to_string(),
    };
    assert_ne!(a, b);
}

#[test]
fn failover_ne_different_variants() {
    let a = FailoverAction::ScopedRegionClose {
        region_id: "r".to_string(),
    };
    let b = FailoverAction::AlertOnly;
    assert_ne!(a, b);
}

#[test]
fn failover_clone() {
    let a = FailoverAction::ScopedRegionClose {
        region_id: "r".to_string(),
    };
    assert_eq!(a, a.clone());
}

// ===========================================================================
// Section 5: LeakMetrics
// ===========================================================================

#[test]
fn metrics_default_all_zero() {
    let m = LeakMetrics::default();
    assert_eq!(m.total, 0);
    assert!(m.by_region.is_empty());
    assert!(m.by_channel.is_empty());
    assert!(m.by_component.is_empty());
}

#[test]
fn metrics_record_single() {
    let mut m = LeakMetrics::default();
    m.record("r1", "c1", "comp1");
    assert_eq!(m.total, 1);
    assert_eq!(m.by_region.get("r1"), Some(&1));
    assert_eq!(m.by_channel.get("c1"), Some(&1));
    assert_eq!(m.by_component.get("comp1"), Some(&1));
}

#[test]
fn metrics_record_multiple_same_dimension() {
    let mut m = LeakMetrics::default();
    m.record("r1", "c1", "comp1");
    m.record("r1", "c2", "comp2");
    assert_eq!(m.total, 2);
    assert_eq!(m.by_region.get("r1"), Some(&2));
    assert_eq!(m.by_channel.get("c1"), Some(&1));
    assert_eq!(m.by_channel.get("c2"), Some(&1));
}

#[test]
fn metrics_record_many_increments() {
    let mut m = LeakMetrics::default();
    for i in 0..100 {
        m.record("r", &format!("c-{i}"), "comp");
    }
    assert_eq!(m.total, 100);
    assert_eq!(m.by_region.get("r"), Some(&100));
    assert_eq!(m.by_component.get("comp"), Some(&100));
    assert_eq!(m.by_channel.len(), 100);
}

#[test]
fn metrics_btreemap_deterministic_key_order() {
    let mut m = LeakMetrics::default();
    m.record("z-region", "c", "comp");
    m.record("a-region", "c", "comp");
    m.record("m-region", "c", "comp");
    let keys: Vec<&String> = m.by_region.keys().collect();
    assert_eq!(keys, vec!["a-region", "m-region", "z-region"]);
}

#[test]
fn metrics_eq() {
    let mut m1 = LeakMetrics::default();
    m1.record("r", "c", "comp");
    let mut m2 = LeakMetrics::default();
    m2.record("r", "c", "comp");
    assert_eq!(m1, m2);
}

// ===========================================================================
// Section 6: LeakHandler — Lab mode
// ===========================================================================

#[test]
fn handler_lab_returns_abort() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    let response = handler.handle_leak(default_diagnostic());
    assert!(matches!(response, LeakResponse::Abort { .. }));
}

#[test]
fn handler_lab_abort_preserves_diagnostic() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    let diag = default_diagnostic();
    let response = handler.handle_leak(diag.clone());
    match response {
        LeakResponse::Abort { diagnostic } => assert_eq!(diagnostic, diag),
        _ => panic!("expected Abort"),
    }
}

#[test]
fn handler_lab_does_not_emit_events() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    handler.handle_leak(default_diagnostic());
    let events = handler.drain_events();
    assert!(events.is_empty());
}

#[test]
fn handler_lab_records_metrics() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    handler.handle_leak(default_diagnostic());
    assert_eq!(handler.metrics().total, 1);
}

#[test]
fn handler_lab_policy_is_lab() {
    let handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    assert_eq!(handler.policy(), ObligationLeakPolicy::Lab);
}

#[test]
fn handler_lab_multiple_aborts() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    for i in 0..5 {
        let diag = make_diagnostic(i, "c", "t", 10, "r", "comp");
        let resp = handler.handle_leak(diag);
        assert!(matches!(resp, LeakResponse::Abort { .. }));
    }
    assert_eq!(handler.metrics().total, 5);
    assert!(handler.drain_events().is_empty());
}

// ===========================================================================
// Section 7: LeakHandler — Production mode
// ===========================================================================

#[test]
fn handler_production_returns_handled() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    let response = handler.handle_leak(default_diagnostic());
    assert!(matches!(response, LeakResponse::Handled { .. }));
}

#[test]
fn handler_production_policy_is_production() {
    let handler = LeakHandler::new(ObligationLeakPolicy::Production);
    assert_eq!(handler.policy(), ObligationLeakPolicy::Production);
}

#[test]
fn handler_production_failover_is_scoped_region_close() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    let diag = make_diagnostic(1, "c", "t", 10, "region-x", "comp");
    match handler.handle_leak(diag) {
        LeakResponse::Handled { failover, .. } => {
            let failover = failover.expect("should have failover");
            match failover {
                FailoverAction::ScopedRegionClose { region_id } => {
                    assert_eq!(region_id, "region-x");
                }
                FailoverAction::AlertOnly => panic!("expected ScopedRegionClose"),
            }
        }
        _ => panic!("expected Handled"),
    }
}

#[test]
fn handler_production_event_fields_match_diagnostic() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    let diag = make_diagnostic(77, "ch-beta", "trace-beta", 200, "region-b", "engine_core");
    handler.handle_leak(diag);

    let events = handler.drain_events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.obligation_id, 77);
    assert_eq!(event.channel_id, "ch-beta");
    assert_eq!(event.trace_id, "trace-beta");
    assert_eq!(event.region_id, "region-b");
    assert_eq!(event.component, "engine_core");
    assert_eq!(event.severity, LeakSeverity::Critical);
    assert_eq!(event.leak_policy, ObligationLeakPolicy::Production);
}

#[test]
fn handler_production_event_failover_action_present() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    handler.handle_leak(default_diagnostic());
    let events = handler.drain_events();
    assert!(events[0].failover_action.is_some());
}

#[test]
fn handler_production_records_metrics() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    handler.handle_leak(make_diagnostic(1, "c1", "t", 10, "r1", "comp"));
    handler.handle_leak(make_diagnostic(2, "c2", "t", 20, "r1", "comp"));
    handler.handle_leak(make_diagnostic(3, "c1", "t", 30, "r2", "comp2"));

    let m = handler.metrics();
    assert_eq!(m.total, 3);
    assert_eq!(m.by_region.get("r1"), Some(&2));
    assert_eq!(m.by_region.get("r2"), Some(&1));
    assert_eq!(m.by_channel.get("c1"), Some(&2));
    assert_eq!(m.by_channel.get("c2"), Some(&1));
    assert_eq!(m.by_component.get("comp"), Some(&2));
    assert_eq!(m.by_component.get("comp2"), Some(&1));
}

#[test]
fn handler_production_drain_events_clears_buffer() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    handler.handle_leak(default_diagnostic());
    handler.handle_leak(default_diagnostic());
    let first_drain = handler.drain_events();
    assert_eq!(first_drain.len(), 2);
    let second_drain = handler.drain_events();
    assert!(second_drain.is_empty());
}

#[test]
fn handler_production_drain_does_not_reset_metrics() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    handler.handle_leak(default_diagnostic());
    let _ = handler.drain_events();
    assert_eq!(handler.metrics().total, 1);
}

#[test]
fn handler_production_multiple_events_accumulate() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    for i in 0..10 {
        handler.handle_leak(make_diagnostic(i, "c", "t", i * 10, "r", "comp"));
    }
    let events = handler.drain_events();
    assert_eq!(events.len(), 10);
    for (i, event) in events.iter().enumerate() {
        assert_eq!(event.obligation_id, i as u64);
    }
}

// ===========================================================================
// Section 8: LeakEvent
// ===========================================================================

#[test]
fn leak_event_eq() {
    let e1 = LeakEvent {
        trace_id: "t".to_string(),
        obligation_id: 1,
        channel_id: "c".to_string(),
        region_id: "r".to_string(),
        component: "comp".to_string(),
        leak_policy: ObligationLeakPolicy::Production,
        failover_action: Some(FailoverAction::AlertOnly),
        severity: LeakSeverity::Warning,
    };
    let e2 = e1.clone();
    assert_eq!(e1, e2);
}

#[test]
fn leak_event_ne_different_severity() {
    let e1 = LeakEvent {
        trace_id: "t".to_string(),
        obligation_id: 1,
        channel_id: "c".to_string(),
        region_id: "r".to_string(),
        component: "comp".to_string(),
        leak_policy: ObligationLeakPolicy::Production,
        failover_action: None,
        severity: LeakSeverity::Warning,
    };
    let e2 = LeakEvent {
        severity: LeakSeverity::Fatal,
        ..e1.clone()
    };
    assert_ne!(e1, e2);
}

#[test]
fn leak_event_ne_different_policy() {
    let e1 = LeakEvent {
        trace_id: "t".to_string(),
        obligation_id: 1,
        channel_id: "c".to_string(),
        region_id: "r".to_string(),
        component: "comp".to_string(),
        leak_policy: ObligationLeakPolicy::Lab,
        failover_action: None,
        severity: LeakSeverity::Warning,
    };
    let e2 = LeakEvent {
        leak_policy: ObligationLeakPolicy::Production,
        ..e1.clone()
    };
    assert_ne!(e1, e2);
}

// ===========================================================================
// Section 9: LeakResponse
// ===========================================================================

#[test]
fn leak_response_abort_variant_matches() {
    let resp = LeakResponse::Abort {
        diagnostic: default_diagnostic(),
    };
    assert!(matches!(resp, LeakResponse::Abort { .. }));
}

#[test]
fn leak_response_handled_variant_matches() {
    let event = LeakEvent {
        trace_id: "t".to_string(),
        obligation_id: 1,
        channel_id: "c".to_string(),
        region_id: "r".to_string(),
        component: "comp".to_string(),
        leak_policy: ObligationLeakPolicy::Production,
        failover_action: None,
        severity: LeakSeverity::Critical,
    };
    let resp = LeakResponse::Handled {
        event,
        failover: None,
    };
    assert!(matches!(resp, LeakResponse::Handled { .. }));
}

#[test]
fn leak_response_clone_eq() {
    let resp = LeakResponse::Abort {
        diagnostic: default_diagnostic(),
    };
    assert_eq!(resp, resp.clone());
}

// ===========================================================================
// Section 10: Serde round-trips
// ===========================================================================

#[test]
fn serde_roundtrip_policy_lab() {
    let p = ObligationLeakPolicy::Lab;
    let json = serde_json::to_string(&p).unwrap();
    let restored: ObligationLeakPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, restored);
}

#[test]
fn serde_roundtrip_policy_production() {
    let p = ObligationLeakPolicy::Production;
    let json = serde_json::to_string(&p).unwrap();
    let restored: ObligationLeakPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, restored);
}

#[test]
fn serde_roundtrip_leak_diagnostic() {
    let diag = make_diagnostic(99, "ch-serde", "tr-serde", 12345, "reg-serde", "comp-serde");
    let json = serde_json::to_string(&diag).unwrap();
    let restored: LeakDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, restored);
}

#[test]
fn serde_roundtrip_leak_severity_all_variants() {
    for sev in [
        LeakSeverity::Warning,
        LeakSeverity::Critical,
        LeakSeverity::Fatal,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let restored: LeakSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, restored);
    }
}

#[test]
fn serde_roundtrip_failover_scoped() {
    let action = FailoverAction::ScopedRegionClose {
        region_id: "r-serde".to_string(),
    };
    let json = serde_json::to_string(&action).unwrap();
    let restored: FailoverAction = serde_json::from_str(&json).unwrap();
    assert_eq!(action, restored);
}

#[test]
fn serde_roundtrip_failover_alert_only() {
    let action = FailoverAction::AlertOnly;
    let json = serde_json::to_string(&action).unwrap();
    let restored: FailoverAction = serde_json::from_str(&json).unwrap();
    assert_eq!(action, restored);
}

#[test]
fn serde_roundtrip_leak_event_with_failover() {
    let event = LeakEvent {
        trace_id: "t-serde".to_string(),
        obligation_id: 42,
        channel_id: "c-serde".to_string(),
        region_id: "r-serde".to_string(),
        component: "comp-serde".to_string(),
        leak_policy: ObligationLeakPolicy::Production,
        failover_action: Some(FailoverAction::ScopedRegionClose {
            region_id: "r-serde".to_string(),
        }),
        severity: LeakSeverity::Critical,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: LeakEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn serde_roundtrip_leak_event_without_failover() {
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
    let json = serde_json::to_string(&event).unwrap();
    let restored: LeakEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn serde_roundtrip_leak_metrics_empty() {
    let m = LeakMetrics::default();
    let json = serde_json::to_string(&m).unwrap();
    let restored: LeakMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(m, restored);
}

#[test]
fn serde_roundtrip_leak_metrics_populated() {
    let mut m = LeakMetrics::default();
    m.record("r1", "c1", "comp1");
    m.record("r2", "c1", "comp2");
    m.record("r1", "c2", "comp1");
    let json = serde_json::to_string(&m).unwrap();
    let restored: LeakMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(m, restored);
}

#[test]
fn serde_roundtrip_leak_response_abort() {
    let resp = LeakResponse::Abort {
        diagnostic: default_diagnostic(),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let restored: LeakResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, restored);
}

#[test]
fn serde_roundtrip_leak_response_handled() {
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
    let resp = LeakResponse::Handled {
        event: event.clone(),
        failover: Some(FailoverAction::AlertOnly),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let restored: LeakResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, restored);
}

// ===========================================================================
// Section 11: Deterministic replay
// ===========================================================================

#[test]
fn deterministic_replay_lab_mode() {
    let run = || -> Vec<LeakResponse> {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        let mut results = Vec::new();
        for i in 0..5 {
            results.push(handler.handle_leak(make_diagnostic(
                i,
                &format!("c-{i}"),
                &format!("t-{i}"),
                i * 100,
                "region",
                "comp",
            )));
        }
        results
    };
    assert_eq!(run(), run());
}

#[test]
fn deterministic_replay_production_mode_events() {
    let run = || -> Vec<LeakEvent> {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        for i in 0..5 {
            handler.handle_leak(make_diagnostic(
                i,
                &format!("c-{i}"),
                &format!("t-{i}"),
                i * 100,
                "region",
                "comp",
            ));
        }
        handler.drain_events()
    };
    assert_eq!(run(), run());
}

#[test]
fn deterministic_replay_production_mode_metrics() {
    let run = || -> LeakMetrics {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        handler.handle_leak(make_diagnostic(1, "c1", "t1", 100, "r1", "comp1"));
        handler.handle_leak(make_diagnostic(2, "c2", "t2", 200, "r1", "comp2"));
        handler.handle_leak(make_diagnostic(3, "c1", "t3", 300, "r2", "comp1"));
        handler.metrics().clone()
    };
    assert_eq!(run(), run());
}

// ===========================================================================
// Section 12: Edge cases and stress
// ===========================================================================

#[test]
fn handler_empty_drain() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    assert!(handler.drain_events().is_empty());
}

#[test]
fn handler_metrics_initially_zero() {
    let handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    assert_eq!(handler.metrics().total, 0);
    assert!(handler.metrics().by_region.is_empty());
}

#[test]
fn handler_large_batch_production() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    for i in 0..1000 {
        handler.handle_leak(make_diagnostic(
            i,
            &format!("c-{}", i % 10),
            &format!("t-{i}"),
            i * 5,
            &format!("r-{}", i % 3),
            &format!("comp-{}", i % 7),
        ));
    }
    assert_eq!(handler.metrics().total, 1000);
    assert_eq!(handler.drain_events().len(), 1000);
    // After drain, no more events
    assert!(handler.drain_events().is_empty());
    // Metrics persist
    assert_eq!(handler.metrics().total, 1000);
}

#[test]
fn handler_large_batch_lab() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    for i in 0..500 {
        let resp = handler.handle_leak(make_diagnostic(i, "c", "t", i, "r", "comp"));
        assert!(matches!(resp, LeakResponse::Abort { .. }));
    }
    assert_eq!(handler.metrics().total, 500);
    assert!(handler.drain_events().is_empty());
}

#[test]
fn diagnostic_with_empty_strings() {
    let diag = make_diagnostic(0, "", "", 0, "", "");
    let s = diag.to_string();
    assert!(s.contains("obligation leak"));
    assert!(s.contains("id=0"));
    // Channel, trace, region, component are empty so appear as adjacent commas
    assert!(s.contains("channel=,"));
}

#[test]
fn diagnostic_with_special_chars() {
    let diag = make_diagnostic(
        1,
        "chan/with:special",
        "trace with spaces",
        999,
        "region_id-123",
        "comp.name",
    );
    assert!(diag.to_string().contains("chan/with:special"));
    assert!(diag.to_string().contains("trace with spaces"));
}

#[test]
fn metrics_record_with_unicode_keys() {
    let mut m = LeakMetrics::default();
    m.record("region-\u{1F600}", "channel-\u{2603}", "comp-\u{00E9}");
    assert_eq!(m.total, 1);
    assert!(m.by_region.contains_key("region-\u{1F600}"));
}

// ===========================================================================
// Section 13: Cross-type interactions
// ===========================================================================

#[test]
fn production_handler_response_matches_event_in_drain() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    let diag = make_diagnostic(55, "ch-z", "tr-z", 5555, "reg-z", "comp-z");
    let response = handler.handle_leak(diag);

    let events = handler.drain_events();
    assert_eq!(events.len(), 1);

    // The event from the response should match the drained event.
    if let LeakResponse::Handled { event, .. } = response {
        assert_eq!(event, events[0]);
    } else {
        panic!("expected Handled");
    }
}

#[test]
fn metrics_by_region_uses_btreemap() {
    // Verify deterministic ordering (BTreeMap guarantee)
    let mut m = LeakMetrics::default();
    m.record("z", "c", "comp");
    m.record("a", "c", "comp");
    m.record("m", "c", "comp");
    let regions: Vec<_> = m.by_region.keys().cloned().collect();
    assert_eq!(regions, vec!["a", "m", "z"]);
}

#[test]
fn serde_json_contains_expected_field_names() {
    let diag = make_diagnostic(1, "c", "t", 10, "r", "comp");
    let json = serde_json::to_string(&diag).unwrap();
    assert!(json.contains("obligation_id"));
    assert!(json.contains("channel_id"));
    assert!(json.contains("creator_trace_id"));
    assert!(json.contains("obligation_age_ticks"));
    assert!(json.contains("region_id"));
    assert!(json.contains("component"));
}

#[test]
fn serde_json_event_contains_expected_field_names() {
    let event = LeakEvent {
        trace_id: "t".to_string(),
        obligation_id: 1,
        channel_id: "c".to_string(),
        region_id: "r".to_string(),
        component: "comp".to_string(),
        leak_policy: ObligationLeakPolicy::Production,
        failover_action: None,
        severity: LeakSeverity::Warning,
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("trace_id"));
    assert!(json.contains("obligation_id"));
    assert!(json.contains("leak_policy"));
    assert!(json.contains("failover_action"));
    assert!(json.contains("severity"));
}

#[test]
fn serde_json_metrics_field_names() {
    let mut m = LeakMetrics::default();
    m.record("r", "c", "comp");
    let json = serde_json::to_string(&m).unwrap();
    assert!(json.contains("by_region"));
    assert!(json.contains("by_channel"));
    assert!(json.contains("by_component"));
    assert!(json.contains("total"));
}

// ===========================================================================
// Section 14: Debug impl checks
// ===========================================================================

#[test]
fn leak_handler_debug() {
    let handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    let dbg = format!("{handler:?}");
    assert!(dbg.contains("LeakHandler"));
    assert!(dbg.contains("Lab"));
}

#[test]
fn leak_diagnostic_debug() {
    let diag = default_diagnostic();
    let dbg = format!("{diag:?}");
    assert!(dbg.contains("LeakDiagnostic"));
    assert!(dbg.contains("100"));
}

#[test]
fn leak_event_debug() {
    let event = LeakEvent {
        trace_id: "t".to_string(),
        obligation_id: 1,
        channel_id: "c".to_string(),
        region_id: "r".to_string(),
        component: "comp".to_string(),
        leak_policy: ObligationLeakPolicy::Production,
        failover_action: None,
        severity: LeakSeverity::Warning,
    };
    let dbg = format!("{event:?}");
    assert!(dbg.contains("LeakEvent"));
}
