//! Second enrichment integration tests for `obligation_leak_policy`.
//!
//! Focuses on: cross-handler isolation, metrics summation invariants,
//! mixed lab/production workflows, serde malformed rejection, Display
//! format stability, event ordering guarantees, and stress scenarios
//! not covered by the first enrichment or base integration suites.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::obligation_leak_policy::{
    FailoverAction, LeakDiagnostic, LeakEvent, LeakHandler, LeakMetrics, LeakResponse,
    LeakSeverity, ObligationLeakPolicy,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn diag(id: u64, region: &str, channel: &str, component: &str) -> LeakDiagnostic {
    LeakDiagnostic {
        obligation_id: id,
        channel_id: channel.to_string(),
        creator_trace_id: format!("trace-{id}"),
        obligation_age_ticks: id * 10,
        region_id: region.to_string(),
        component: component.to_string(),
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[test]
fn enrichment_metrics_region_sum_invariant_across_many_regions() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    for i in 0..100u64 {
        handler.handle_leak(diag(i, &format!("r-{}", i % 11), "c-0", "comp-0"));
    }
    let m = handler.metrics();
    let region_sum: u64 = m.by_region.values().sum();
    assert_eq!(region_sum, m.total);
    assert_eq!(m.total, 100);
    assert_eq!(m.by_region.len(), 11);
}

#[test]
fn enrichment_metrics_channel_sum_invariant() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    for i in 0..77u64 {
        handler.handle_leak(diag(i, "r-0", &format!("ch-{}", i % 7), "comp-0"));
    }
    let m = handler.metrics();
    let channel_sum: u64 = m.by_channel.values().sum();
    assert_eq!(channel_sum, m.total);
    assert_eq!(m.by_channel.len(), 7);
}

#[test]
fn enrichment_metrics_component_sum_invariant() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    for i in 0..60u64 {
        handler.handle_leak(diag(i, "r-0", "c-0", &format!("comp-{}", i % 5)));
    }
    let m = handler.metrics();
    let comp_sum: u64 = m.by_component.values().sum();
    assert_eq!(comp_sum, m.total);
    assert_eq!(m.by_component.len(), 5);
}

#[test]
fn enrichment_two_handlers_fully_isolated() {
    let mut lab = LeakHandler::new(ObligationLeakPolicy::Lab);
    let mut prod = LeakHandler::new(ObligationLeakPolicy::Production);

    for i in 0..10u64 {
        lab.handle_leak(diag(i, "r-lab", "c-lab", "comp-lab"));
    }
    for i in 10..30u64 {
        prod.handle_leak(diag(i, "r-prod", "c-prod", "comp-prod"));
    }

    assert_eq!(lab.metrics().total, 10);
    assert_eq!(prod.metrics().total, 20);
    assert!(lab.drain_events().is_empty());
    assert_eq!(prod.drain_events().len(), 20);
}

#[test]
fn enrichment_lab_response_preserves_all_diagnostic_fields() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    let d = LeakDiagnostic {
        obligation_id: u64::MAX,
        channel_id: "ch-special/chars:ok".to_string(),
        creator_trace_id: "trace-with\"quotes".to_string(),
        obligation_age_ticks: 999_999_999,
        region_id: "region-\ttab".to_string(),
        component: "comp-\nnewline".to_string(),
    };
    let resp = handler.handle_leak(d.clone());
    if let LeakResponse::Abort { diagnostic } = resp {
        assert_eq!(diagnostic.obligation_id, u64::MAX);
        assert_eq!(diagnostic.channel_id, "ch-special/chars:ok");
        assert_eq!(diagnostic.creator_trace_id, "trace-with\"quotes");
        assert_eq!(diagnostic.obligation_age_ticks, 999_999_999);
        assert_eq!(diagnostic.region_id, "region-\ttab");
        assert_eq!(diagnostic.component, "comp-\nnewline");
    } else {
        panic!("expected Abort");
    }
}

#[test]
fn enrichment_production_event_fields_match_diagnostic() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    let d = diag(77, "region-X", "channel-Y", "comp-Z");
    handler.handle_leak(d);
    let events = handler.drain_events();
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.obligation_id, 77);
    assert_eq!(e.region_id, "region-X");
    assert_eq!(e.channel_id, "channel-Y");
    assert_eq!(e.component, "comp-Z");
    assert_eq!(e.trace_id, "trace-77");
    assert_eq!(e.leak_policy, ObligationLeakPolicy::Production);
    assert_eq!(e.severity, LeakSeverity::Critical);
}

#[test]
fn enrichment_production_failover_region_matches_each_diagnostic() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    let regions = ["alpha", "beta", "gamma", "delta"];
    for (i, region) in regions.iter().enumerate() {
        let resp = handler.handle_leak(diag(i as u64, region, "c", "comp"));
        if let LeakResponse::Handled { failover, .. } = resp {
            if let Some(FailoverAction::ScopedRegionClose { region_id }) = failover {
                assert_eq!(region_id, *region);
            } else {
                panic!("expected ScopedRegionClose");
            }
        } else {
            panic!("expected Handled");
        }
    }
}

#[test]
fn enrichment_event_ordering_matches_insertion_order() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    for i in 0..20u64 {
        handler.handle_leak(diag(i, "r", "c", "comp"));
    }
    let events = handler.drain_events();
    for (idx, event) in events.iter().enumerate() {
        assert_eq!(event.obligation_id, idx as u64);
        assert_eq!(event.trace_id, format!("trace-{idx}"));
    }
}

#[test]
fn enrichment_drain_then_add_then_drain_partitions_correctly() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);

    handler.handle_leak(diag(0, "r", "c", "comp"));
    handler.handle_leak(diag(1, "r", "c", "comp"));
    let batch1 = handler.drain_events();
    assert_eq!(batch1.len(), 2);

    handler.handle_leak(diag(2, "r", "c", "comp"));
    let batch2 = handler.drain_events();
    assert_eq!(batch2.len(), 1);
    assert_eq!(batch2[0].obligation_id, 2);

    let batch3 = handler.drain_events();
    assert!(batch3.is_empty());

    // Metrics should reflect all 3
    assert_eq!(handler.metrics().total, 3);
}

#[test]
fn enrichment_serde_leak_response_abort_roundtrip() {
    let resp = LeakResponse::Abort {
        diagnostic: LeakDiagnostic {
            obligation_id: 12345,
            channel_id: "serde-chan".to_string(),
            creator_trace_id: "serde-trace".to_string(),
            obligation_age_ticks: 42,
            region_id: "serde-region".to_string(),
            component: "serde-comp".to_string(),
        },
    };
    let json = serde_json::to_string(&resp).unwrap();
    let back: LeakResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, back);
}

#[test]
fn enrichment_serde_leak_response_handled_with_failover_roundtrip() {
    let resp = LeakResponse::Handled {
        event: LeakEvent {
            trace_id: "t".to_string(),
            obligation_id: 99,
            channel_id: "c".to_string(),
            region_id: "r".to_string(),
            component: "comp".to_string(),
            leak_policy: ObligationLeakPolicy::Production,
            failover_action: Some(FailoverAction::ScopedRegionClose {
                region_id: "r".to_string(),
            }),
            severity: LeakSeverity::Critical,
        },
        failover: Some(FailoverAction::ScopedRegionClose {
            region_id: "r".to_string(),
        }),
    };
    let json = serde_json::to_string(&resp).unwrap();
    let back: LeakResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(resp, back);
}

#[test]
fn enrichment_serde_reject_invalid_policy_json() {
    let result = serde_json::from_str::<ObligationLeakPolicy>("\"Staging\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_serde_reject_invalid_severity_json() {
    let result = serde_json::from_str::<LeakSeverity>("\"Extreme\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_serde_reject_number_for_policy() {
    let result = serde_json::from_str::<ObligationLeakPolicy>("42");
    assert!(result.is_err());
}

#[test]
fn enrichment_serde_reject_incomplete_diagnostic() {
    let result =
        serde_json::from_str::<LeakDiagnostic>(r#"{"obligation_id": 1, "channel_id": "c"}"#);
    assert!(result.is_err());
}

#[test]
fn enrichment_display_diagnostic_format_stability() {
    let d = LeakDiagnostic {
        obligation_id: 7,
        channel_id: "ch".to_string(),
        creator_trace_id: "tr".to_string(),
        obligation_age_ticks: 300,
        region_id: "rg".to_string(),
        component: "cp".to_string(),
    };
    let expected = "obligation leak: id=7, channel=ch, trace=tr, age=300, region=rg, component=cp";
    assert_eq!(d.to_string(), expected);
}

#[test]
fn enrichment_display_policy_format_stability() {
    assert_eq!(ObligationLeakPolicy::Lab.to_string(), "lab");
    assert_eq!(ObligationLeakPolicy::Production.to_string(), "production");
}

#[test]
fn enrichment_display_severity_format_stability() {
    assert_eq!(LeakSeverity::Warning.to_string(), "warning");
    assert_eq!(LeakSeverity::Critical.to_string(), "critical");
    assert_eq!(LeakSeverity::Fatal.to_string(), "fatal");
}

#[test]
fn enrichment_display_failover_format_stability() {
    let scoped = FailoverAction::ScopedRegionClose {
        region_id: "my-region".to_string(),
    };
    assert_eq!(scoped.to_string(), "scoped_region_close:my-region");
    assert_eq!(FailoverAction::AlertOnly.to_string(), "alert_only");
}

#[test]
fn enrichment_severity_ordering_btree_dedup() {
    let mut set = BTreeSet::new();
    set.insert(LeakSeverity::Fatal);
    set.insert(LeakSeverity::Warning);
    set.insert(LeakSeverity::Critical);
    set.insert(LeakSeverity::Fatal); // duplicate
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
fn enrichment_severity_all_pairwise_comparisons() {
    assert!(LeakSeverity::Warning < LeakSeverity::Critical);
    assert!(LeakSeverity::Critical < LeakSeverity::Fatal);
    assert!(LeakSeverity::Warning < LeakSeverity::Fatal);
    assert_eq!(LeakSeverity::Warning, LeakSeverity::Warning);
    assert_eq!(LeakSeverity::Critical, LeakSeverity::Critical);
    assert_eq!(LeakSeverity::Fatal, LeakSeverity::Fatal);
    assert_ne!(LeakSeverity::Warning, LeakSeverity::Critical);
}

#[test]
fn enrichment_metrics_deterministic_key_ordering() {
    let mut m = LeakMetrics::default();
    m.record("z-region", "z-chan", "z-comp");
    m.record("a-region", "a-chan", "a-comp");
    m.record("m-region", "m-chan", "m-comp");

    let region_keys: Vec<&String> = m.by_region.keys().collect();
    assert_eq!(region_keys, vec!["a-region", "m-region", "z-region"]);

    let channel_keys: Vec<&String> = m.by_channel.keys().collect();
    assert_eq!(channel_keys, vec!["a-chan", "m-chan", "z-chan"]);

    let comp_keys: Vec<&String> = m.by_component.keys().collect();
    assert_eq!(comp_keys, vec!["a-comp", "m-comp", "z-comp"]);
}

#[test]
fn enrichment_leak_event_ne_different_severity() {
    let base = LeakEvent {
        trace_id: "t".to_string(),
        obligation_id: 1,
        channel_id: "c".to_string(),
        region_id: "r".to_string(),
        component: "comp".to_string(),
        leak_policy: ObligationLeakPolicy::Production,
        failover_action: None,
        severity: LeakSeverity::Warning,
    };
    let mut other = base.clone();
    other.severity = LeakSeverity::Fatal;
    assert_ne!(base, other);
}

#[test]
fn enrichment_leak_event_ne_different_policy() {
    let base = LeakEvent {
        trace_id: "t".to_string(),
        obligation_id: 1,
        channel_id: "c".to_string(),
        region_id: "r".to_string(),
        component: "comp".to_string(),
        leak_policy: ObligationLeakPolicy::Production,
        failover_action: None,
        severity: LeakSeverity::Warning,
    };
    let mut other = base.clone();
    other.leak_policy = ObligationLeakPolicy::Lab;
    assert_ne!(base, other);
}

#[test]
fn enrichment_deterministic_replay_full_scenario() {
    let run = || {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
        let mut responses = Vec::new();
        for i in 0..25u64 {
            responses.push(handler.handle_leak(diag(
                i,
                &format!("r-{}", i % 3),
                &format!("c-{}", i % 5),
                &format!("comp-{}", i % 2),
            )));
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

#[test]
fn enrichment_deterministic_replay_lab_mode_full() {
    let run = || {
        let mut handler = LeakHandler::new(ObligationLeakPolicy::Lab);
        let mut responses = Vec::new();
        for i in 0..15u64 {
            responses.push(handler.handle_leak(diag(i, "r", "c", "comp")));
        }
        let metrics = handler.metrics().clone();
        (responses, metrics)
    };
    let (r1, m1) = run();
    let (r2, m2) = run();
    assert_eq!(r1, r2);
    assert_eq!(m1, m2);
}

#[test]
fn enrichment_failover_action_ne_different_regions() {
    let a = FailoverAction::ScopedRegionClose {
        region_id: "region-A".to_string(),
    };
    let b = FailoverAction::ScopedRegionClose {
        region_id: "region-B".to_string(),
    };
    assert_ne!(a, b);
}

#[test]
fn enrichment_failover_action_ne_alert_vs_scoped() {
    let alert = FailoverAction::AlertOnly;
    let scoped = FailoverAction::ScopedRegionClose {
        region_id: "r".to_string(),
    };
    assert_ne!(alert, scoped);
}

#[test]
fn enrichment_metrics_serde_roundtrip_after_many_records() {
    let mut m = LeakMetrics::default();
    for i in 0..50 {
        m.record(
            &format!("r-{}", i % 6),
            &format!("c-{}", i % 8),
            &format!("comp-{}", i % 3),
        );
    }
    let json = serde_json::to_string(&m).unwrap();
    let back: LeakMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
    assert_eq!(back.total, 50);
}

#[test]
fn enrichment_leak_event_with_all_failover_variants_serde() {
    let failover_variants: Vec<Option<FailoverAction>> = vec![
        None,
        Some(FailoverAction::AlertOnly),
        Some(FailoverAction::ScopedRegionClose {
            region_id: "rr".to_string(),
        }),
    ];
    for failover in failover_variants {
        let event = LeakEvent {
            trace_id: "t".to_string(),
            obligation_id: 0,
            channel_id: "c".to_string(),
            region_id: "r".to_string(),
            component: "comp".to_string(),
            leak_policy: ObligationLeakPolicy::Production,
            failover_action: failover.clone(),
            severity: LeakSeverity::Warning,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: LeakEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }
}

#[test]
fn enrichment_handler_policy_immutable_after_creation() {
    let handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    assert_eq!(handler.policy(), ObligationLeakPolicy::Lab);
    // No way to change policy after creation -- this is by design
    let handler2 = LeakHandler::new(ObligationLeakPolicy::Production);
    assert_eq!(handler2.policy(), ObligationLeakPolicy::Production);
}

#[test]
fn enrichment_stress_1000_leaks_metrics_consistent() {
    let mut handler = LeakHandler::new(ObligationLeakPolicy::Production);
    for i in 0..1000u64 {
        handler.handle_leak(diag(
            i,
            &format!("r-{}", i % 13),
            &format!("c-{}", i % 17),
            &format!("comp-{}", i % 7),
        ));
    }
    let m = handler.metrics();
    assert_eq!(m.total, 1000);
    assert_eq!(m.by_region.len(), 13);
    assert_eq!(m.by_channel.len(), 17);
    assert_eq!(m.by_component.len(), 7);

    let region_sum: u64 = m.by_region.values().sum();
    let channel_sum: u64 = m.by_channel.values().sum();
    let comp_sum: u64 = m.by_component.values().sum();
    assert_eq!(region_sum, 1000);
    assert_eq!(channel_sum, 1000);
    assert_eq!(comp_sum, 1000);

    let events = handler.drain_events();
    assert_eq!(events.len(), 1000);
}

#[test]
fn enrichment_debug_format_all_types_nonempty() {
    let d = diag(1, "r", "c", "comp");
    assert!(!format!("{:?}", d).is_empty());

    let handler = LeakHandler::new(ObligationLeakPolicy::Lab);
    assert!(!format!("{:?}", handler).is_empty());

    let m = LeakMetrics::default();
    assert!(!format!("{:?}", m).is_empty());

    let event = LeakEvent {
        trace_id: "t".to_string(),
        obligation_id: 0,
        channel_id: "c".to_string(),
        region_id: "r".to_string(),
        component: "comp".to_string(),
        leak_policy: ObligationLeakPolicy::Lab,
        failover_action: None,
        severity: LeakSeverity::Warning,
    };
    assert!(!format!("{:?}", event).is_empty());

    let resp = LeakResponse::Abort {
        diagnostic: diag(0, "r", "c", "comp"),
    };
    assert!(!format!("{:?}", resp).is_empty());
}
