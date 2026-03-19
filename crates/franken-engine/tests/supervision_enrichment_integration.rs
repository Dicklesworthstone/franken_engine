//! Enrichment integration tests for `supervision`.

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

use frankenengine_engine::supervision::{
    HealthStatus, RestartBudget, RestartPolicy, ServiceConfig, ServiceState, Severity,
    Supervisor, SupervisorAction, SupervisorEvent,
};

fn test_config(id: &str) -> ServiceConfig {
    ServiceConfig {
        service_id: id.to_string(),
        restart_policy: RestartPolicy::Permanent,
        restart_budget: RestartBudget { max_restarts: 3, window_ticks: 100 },
        shutdown_order: 0,
    }
}

fn test_supervisor() -> Supervisor {
    let mut sup = Supervisor::new("sup-1", "trace-1");
    sup.add_service(test_config("svc-a"));
    sup.start_service("svc-a");
    sup
}

#[test]
fn enrichment_severity_ordering() {
    assert!(Severity::Restart < Severity::Isolate);
    assert!(Severity::Isolate < Severity::SubtreeRestart);
    assert!(Severity::SubtreeRestart < Severity::SubtreeTerminate);
    assert!(Severity::SubtreeTerminate < Severity::RootEscalation);
}

#[test]
fn enrichment_severity_display_unique() {
    let displays: std::collections::BTreeSet<String> = [
        Severity::Restart, Severity::Isolate, Severity::SubtreeRestart,
        Severity::SubtreeTerminate, Severity::RootEscalation,
    ].iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_severity_serde_all() {
    for s in [Severity::Restart, Severity::Isolate, Severity::SubtreeRestart,
              Severity::SubtreeTerminate, Severity::RootEscalation] {
        let json = serde_json::to_string(&s).unwrap();
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn enrichment_restart_policy_display_unique() {
    let displays: std::collections::BTreeSet<String> = [
        RestartPolicy::Permanent, RestartPolicy::Transient, RestartPolicy::Temporary,
    ].iter().map(|p| p.to_string()).collect();
    assert_eq!(displays.len(), 3);
}

#[test]
fn enrichment_service_state_serde_all() {
    for s in [ServiceState::Starting, ServiceState::Running, ServiceState::Failed,
              ServiceState::Restarting, ServiceState::Isolated, ServiceState::Terminated] {
        let json = serde_json::to_string(&s).unwrap();
        let back: ServiceState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn enrichment_health_status_ordering() {
    assert!(HealthStatus::Healthy < HealthStatus::Degraded);
    assert!(HealthStatus::Degraded < HealthStatus::Critical);
}

#[test]
fn enrichment_supervisor_action_display_unique() {
    let displays: std::collections::BTreeSet<String> = [
        SupervisorAction::Start, SupervisorAction::Restart, SupervisorAction::Isolate,
        SupervisorAction::Terminate, SupervisorAction::Escalate,
    ].iter().map(|a| a.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_restart_budget_default() {
    let d = RestartBudget::default();
    assert_eq!(d.max_restarts, 5);
    assert_eq!(d.window_ticks, 60_000);
}

#[test]
fn enrichment_service_starts_running() {
    let sup = test_supervisor();
    assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Running));
}

#[test]
fn enrichment_failure_with_budget_triggers_restart() {
    let mut sup = test_supervisor();
    let action = sup.report_failure("svc-a", "crash", 10).unwrap();
    assert_eq!(action, SupervisorAction::Restart);
    assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Running));
    assert_eq!(sup.restart_count("svc-a"), Some(1));
}

#[test]
fn enrichment_budget_exhaustion_triggers_escalate() {
    let mut sup = test_supervisor();
    sup.report_failure("svc-a", "c1", 10);
    sup.report_failure("svc-a", "c2", 20);
    sup.report_failure("svc-a", "c3", 30);
    let action = sup.report_failure("svc-a", "c4", 40).unwrap();
    assert_eq!(action, SupervisorAction::Escalate);
    assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Isolated));
}

#[test]
fn enrichment_temporary_never_restarts() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(ServiceConfig {
        service_id: "tmp".to_string(),
        restart_policy: RestartPolicy::Temporary,
        restart_budget: RestartBudget::default(),
        shutdown_order: 0,
    });
    sup.start_service("tmp");
    let action = sup.report_failure("tmp", "crash", 10).unwrap();
    assert_eq!(action, SupervisorAction::Terminate);
    assert_eq!(sup.service_state("tmp"), Some(ServiceState::Terminated));
}

#[test]
fn enrichment_budget_resets_after_window() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(ServiceConfig {
        service_id: "svc".to_string(),
        restart_policy: RestartPolicy::Permanent,
        restart_budget: RestartBudget { max_restarts: 2, window_ticks: 100 },
        shutdown_order: 0,
    });
    sup.start_service("svc");
    sup.report_failure("svc", "c", 10);
    sup.report_failure("svc", "c", 20);
    let action = sup.report_failure("svc", "c", 200).unwrap();
    assert_eq!(action, SupervisorAction::Restart);
}

#[test]
fn enrichment_healthy_when_all_running() {
    let sup = test_supervisor();
    assert_eq!(sup.health(), HealthStatus::Healthy);
}

#[test]
fn enrichment_critical_when_isolated() {
    let mut sup = test_supervisor();
    for i in 0..4 {
        sup.report_failure("svc-a", "crash", i * 10 + 10);
    }
    assert_eq!(sup.health(), HealthStatus::Critical);
}

#[test]
fn enrichment_shutdown_order_respects_priority() {
    let mut sup = Supervisor::new("sup", "t");
    for (id, order) in [("low", 1), ("high", 10), ("mid", 5)] {
        sup.add_service(ServiceConfig {
            service_id: id.to_string(),
            restart_policy: RestartPolicy::Permanent,
            restart_budget: RestartBudget::default(),
            shutdown_order: order,
        });
    }
    let order = sup.shutdown_order();
    assert_eq!(order, vec!["high", "mid", "low"]);
}

#[test]
fn enrichment_events_emitted() {
    let mut sup = test_supervisor();
    sup.report_failure("svc-a", "crash", 10);
    let events = sup.drain_events();
    assert!(events.len() >= 2);
    assert_eq!(events[0].action, SupervisorAction::Start);
}

#[test]
fn enrichment_drain_events_idempotent() {
    let mut sup = test_supervisor();
    sup.report_failure("svc-a", "crash", 10);
    let first = sup.drain_events();
    assert!(!first.is_empty());
    assert!(sup.drain_events().is_empty());
}

#[test]
fn enrichment_service_count_tracks() {
    let mut sup = Supervisor::new("sup", "t");
    assert_eq!(sup.service_count(), 0);
    sup.add_service(test_config("a"));
    assert_eq!(sup.service_count(), 1);
    sup.add_service(test_config("b"));
    assert_eq!(sup.service_count(), 2);
}

#[test]
fn enrichment_nonexistent_service_returns_none() {
    let mut sup = Supervisor::new("sup", "t");
    assert!(!sup.start_service("ghost"));
    assert!(sup.report_failure("ghost", "c", 10).is_none());
    assert!(sup.service_state("ghost").is_none());
    assert!(sup.restart_count("ghost").is_none());
    assert!(sup.service_severity("ghost").is_none());
}

#[test]
fn enrichment_escalated_severity_initially_none() {
    let sup = test_supervisor();
    assert!(sup.escalated_severity().is_none());
}

#[test]
fn enrichment_service_config_serde() {
    let cfg = test_config("svc-1");
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ServiceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn enrichment_supervisor_event_serde() {
    let event = SupervisorEvent {
        trace_id: "t".into(), service_id: "svc".into(),
        action: SupervisorAction::Restart, reason: "crash".into(),
        restart_count: 1, budget_remaining: 2, severity: Severity::Restart,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: SupervisorEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_deterministic_event_sequence() {
    let run = || -> Vec<SupervisorEvent> {
        let mut sup = Supervisor::new("sup", "t");
        sup.add_service(ServiceConfig {
            service_id: "svc".to_string(),
            restart_policy: RestartPolicy::Permanent,
            restart_budget: RestartBudget { max_restarts: 2, window_ticks: 100 },
            shutdown_order: 0,
        });
        sup.start_service("svc");
        sup.report_failure("svc", "c1", 10);
        sup.report_failure("svc", "c2", 20);
        sup.drain_events()
    };
    assert_eq!(run(), run());
}

#[test]
fn enrichment_multiple_services_independent() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(test_config("svc-a"));
    sup.add_service(test_config("svc-b"));
    sup.start_service("svc-a");
    sup.start_service("svc-b");
    for i in 0..4 { sup.report_failure("svc-a", "c", i * 10 + 10); }
    let action = sup.report_failure("svc-b", "c", 50).unwrap();
    assert_eq!(action, SupervisorAction::Restart);
    assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Isolated));
    assert_eq!(sup.service_state("svc-b"), Some(ServiceState::Running));
}

#[test]
fn enrichment_health_healthy_zero_services() {
    let sup = Supervisor::new("sup", "t");
    assert_eq!(sup.health(), HealthStatus::Healthy);
}

#[test]
fn enrichment_zero_budget_escalates_immediately() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(ServiceConfig {
        service_id: "svc".to_string(),
        restart_policy: RestartPolicy::Permanent,
        restart_budget: RestartBudget { max_restarts: 0, window_ticks: 1000 },
        shutdown_order: 0,
    });
    sup.start_service("svc");
    let action = sup.report_failure("svc", "c", 5).unwrap();
    assert!(action == SupervisorAction::Isolate || action == SupervisorAction::Escalate);
    assert_eq!(sup.service_state("svc"), Some(ServiceState::Isolated));
}

#[test]
fn enrichment_health_status_display_all() {
    assert_eq!(HealthStatus::Healthy.to_string(), "healthy");
    assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
    assert_eq!(HealthStatus::Critical.to_string(), "critical");
}

#[test]
fn enrichment_restart_budget_serde() {
    let b = RestartBudget { max_restarts: 5, window_ticks: 200 };
    let json = serde_json::to_string(&b).unwrap();
    let back: RestartBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(b, back);
}

#[test]
fn enrichment_service_severity_default_restart() {
    let sup = test_supervisor();
    assert_eq!(sup.service_severity("svc-a"), Some(Severity::Restart));
}

#[test]
fn enrichment_health_critical_when_terminated() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(ServiceConfig {
        service_id: "svc".to_string(),
        restart_policy: RestartPolicy::Temporary,
        restart_budget: RestartBudget::default(),
        shutdown_order: 0,
    });
    sup.start_service("svc");
    sup.report_failure("svc", "crash", 10);
    assert_eq!(sup.service_state("svc"), Some(ServiceState::Terminated));
    assert_eq!(sup.health(), HealthStatus::Critical);
}

#[test]
fn enrichment_event_trace_id_matches_supervisor() {
    let mut sup = Supervisor::new("sup", "my-trace-42");
    sup.add_service(test_config("svc"));
    sup.start_service("svc");
    sup.report_failure("svc", "crash", 10);
    for event in &sup.drain_events() {
        assert_eq!(event.trace_id, "my-trace-42");
    }
}
