#![forbid(unsafe_code)]

//! Integration tests for supervision: supervision tree with restart budgets,
//! escalation semantics, and monotone severity outcomes.

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

use std::collections::BTreeSet;

use frankenengine_engine::supervision::{
    HealthStatus, RestartBudget, RestartPolicy, ServiceConfig, ServiceState, Severity, Supervisor,
    SupervisorAction, SupervisorEvent,
};

// =========================================================================
// Section 1: Display impls
// =========================================================================

#[test]
fn severity_display_all_variants() {
    let cases = [
        (Severity::Restart, "restart"),
        (Severity::Isolate, "isolate"),
        (Severity::SubtreeRestart, "subtree_restart"),
        (Severity::SubtreeTerminate, "subtree_terminate"),
        (Severity::RootEscalation, "root_escalation"),
    ];
    for (variant, expected) in &cases {
        assert_eq!(
            variant.to_string(),
            *expected,
            "Display mismatch for {variant:?}"
        );
    }
}

#[test]
fn restart_policy_display_all_variants() {
    let cases = [
        (RestartPolicy::Permanent, "permanent"),
        (RestartPolicy::Transient, "transient"),
        (RestartPolicy::Temporary, "temporary"),
    ];
    for (variant, expected) in &cases {
        assert_eq!(variant.to_string(), *expected);
    }
}

#[test]
fn service_state_display_all_variants() {
    let cases = [
        (ServiceState::Starting, "starting"),
        (ServiceState::Running, "running"),
        (ServiceState::Failed, "failed"),
        (ServiceState::Restarting, "restarting"),
        (ServiceState::Isolated, "isolated"),
        (ServiceState::Terminated, "terminated"),
    ];
    for (variant, expected) in &cases {
        assert_eq!(variant.to_string(), *expected);
    }
}

#[test]
fn health_status_display_all_variants() {
    let cases = [
        (HealthStatus::Healthy, "healthy"),
        (HealthStatus::Degraded, "degraded"),
        (HealthStatus::Critical, "critical"),
    ];
    for (variant, expected) in &cases {
        assert_eq!(variant.to_string(), *expected);
    }
}

#[test]
fn supervisor_action_display_all_variants() {
    let cases = [
        (SupervisorAction::Start, "start"),
        (SupervisorAction::Restart, "restart"),
        (SupervisorAction::Isolate, "isolate"),
        (SupervisorAction::Terminate, "terminate"),
        (SupervisorAction::Escalate, "escalate"),
    ];
    for (variant, expected) in &cases {
        assert_eq!(variant.to_string(), *expected);
    }
}

// =========================================================================
// Section 2: Construction and defaults
// =========================================================================

#[test]
fn supervisor_new_empty() {
    let sup = Supervisor::new("sup-1", "trace-abc");
    assert_eq!(sup.id, "sup-1");
    assert_eq!(sup.trace_id, "trace-abc");
    assert_eq!(sup.service_count(), 0);
    assert!(sup.escalated_severity().is_none());
    assert_eq!(sup.health(), HealthStatus::Healthy);
}

#[test]
fn restart_budget_default() {
    let budget = RestartBudget::default();
    assert_eq!(budget.max_restarts, 5);
    assert_eq!(budget.window_ticks, 60_000);
}

#[test]
fn restart_budget_custom() {
    let budget = RestartBudget {
        max_restarts: 10,
        window_ticks: 1_000,
    };
    assert_eq!(budget.max_restarts, 10);
    assert_eq!(budget.window_ticks, 1_000);
}

#[test]
fn service_config_construction() {
    let config = ServiceConfig {
        service_id: "svc-1".to_string(),
        restart_policy: RestartPolicy::Permanent,
        restart_budget: RestartBudget::default(),
        shutdown_order: 5,
    };
    assert_eq!(config.service_id, "svc-1");
    assert_eq!(config.restart_policy, RestartPolicy::Permanent);
    assert_eq!(config.shutdown_order, 5);
}

// =========================================================================
// Section 3: Service lifecycle — happy path
// =========================================================================

fn make_config(
    id: &str,
    policy: RestartPolicy,
    max_restarts: u32,
    window_ticks: u64,
) -> ServiceConfig {
    ServiceConfig {
        service_id: id.to_string(),
        restart_policy: policy,
        restart_budget: RestartBudget {
            max_restarts,
            window_ticks,
        },
        shutdown_order: 0,
    }
}

fn make_permanent(id: &str) -> ServiceConfig {
    make_config(id, RestartPolicy::Permanent, 3, 100)
}

#[test]
fn add_service_and_start() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_permanent("svc-a"));
    assert_eq!(sup.service_count(), 1);
    assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Starting));

    assert!(sup.start_service("svc-a"));
    assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Running));
}

#[test]
fn start_nonexistent_service_returns_false() {
    let mut sup = Supervisor::new("sup", "t");
    assert!(!sup.start_service("ghost"));
}

#[test]
fn failure_with_budget_triggers_restart() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_permanent("svc-a"));
    sup.start_service("svc-a");

    let action = sup.report_failure("svc-a", "crash", 10).unwrap();
    assert_eq!(action, SupervisorAction::Restart);
    assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Running));
    assert_eq!(sup.restart_count("svc-a"), Some(1));
}

#[test]
fn multiple_restarts_within_budget() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_permanent("svc-a"));
    sup.start_service("svc-a");

    for i in 0..3 {
        let action = sup
            .report_failure("svc-a", &format!("crash-{i}"), (i + 1) * 10)
            .unwrap();
        assert_eq!(action, SupervisorAction::Restart);
    }
    assert_eq!(sup.restart_count("svc-a"), Some(3));
    assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Running));
}

// =========================================================================
// Section 4: Budget exhaustion and escalation
// =========================================================================

#[test]
fn budget_exhaustion_triggers_escalation() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_permanent("svc-a"));
    sup.start_service("svc-a");

    // Use up budget (3 restarts)
    sup.report_failure("svc-a", "c1", 10);
    sup.report_failure("svc-a", "c2", 20);
    sup.report_failure("svc-a", "c3", 30);

    // 4th failure: budget exhausted
    let action = sup.report_failure("svc-a", "c4", 40).unwrap();
    assert_eq!(action, SupervisorAction::Escalate);
    assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Isolated));
    assert!(sup.service_severity("svc-a").unwrap() >= Severity::Isolate);
}

#[test]
fn escalated_severity_propagates_to_supervisor() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_permanent("svc-a"));
    sup.start_service("svc-a");

    // Exhaust budget
    for i in 0..3 {
        sup.report_failure("svc-a", "crash", (i + 1) * 10);
    }
    assert!(sup.escalated_severity().is_none());

    // Trigger escalation
    sup.report_failure("svc-a", "crash", 40);
    assert!(sup.escalated_severity().is_some());
    assert!(sup.escalated_severity().unwrap() >= Severity::Isolate);
}

#[test]
fn budget_with_one_restart_escalates_after_second_failure() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("svc", RestartPolicy::Permanent, 1, 100));
    sup.start_service("svc");

    let action1 = sup.report_failure("svc", "crash", 10).unwrap();
    assert_eq!(action1, SupervisorAction::Restart);

    let action2 = sup.report_failure("svc", "crash", 20).unwrap();
    assert_eq!(action2, SupervisorAction::Escalate);
    assert_eq!(sup.service_state("svc"), Some(ServiceState::Isolated));
}

#[test]
fn zero_budget_escalates_on_first_failure() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("svc", RestartPolicy::Permanent, 0, 100));
    sup.start_service("svc");

    let action = sup.report_failure("svc", "crash", 10).unwrap();
    // Budget is 0, so immediately exhausted -> escalate (severity goes Restart -> Isolate,
    // and Isolate >= Isolate so the Escalate branch is taken)
    assert_eq!(action, SupervisorAction::Escalate);
    assert_eq!(sup.service_state("svc"), Some(ServiceState::Isolated));
}

// =========================================================================
// Section 5: Restart policies
// =========================================================================

#[test]
fn temporary_service_never_restarts() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("tmp", RestartPolicy::Temporary, 100, 1000));
    sup.start_service("tmp");

    let action = sup.report_failure("tmp", "crash", 10).unwrap();
    assert_eq!(action, SupervisorAction::Terminate);
    assert_eq!(sup.service_state("tmp"), Some(ServiceState::Terminated));
    // Budget should be irrelevant for Temporary
}

#[test]
fn transient_service_restarts_on_failure() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("trans", RestartPolicy::Transient, 3, 100));
    sup.start_service("trans");

    let action = sup.report_failure("trans", "unexpected", 10).unwrap();
    assert_eq!(action, SupervisorAction::Restart);
    assert_eq!(sup.service_state("trans"), Some(ServiceState::Running));
}

#[test]
fn transient_budget_exhaustion_escalates() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("trans", RestartPolicy::Transient, 2, 100));
    sup.start_service("trans");

    sup.report_failure("trans", "c1", 10);
    sup.report_failure("trans", "c2", 20);
    let action = sup.report_failure("trans", "c3", 30).unwrap();
    assert_eq!(action, SupervisorAction::Escalate);
}

// =========================================================================
// Section 6: Sliding window budget
// =========================================================================

#[test]
fn budget_resets_after_window_expires() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("svc", RestartPolicy::Permanent, 2, 100));
    sup.start_service("svc");

    // Two failures within window
    sup.report_failure("svc", "c1", 10);
    sup.report_failure("svc", "c2", 20);

    // Third failure at t=200, well outside window of 100
    let action = sup.report_failure("svc", "c3", 200).unwrap();
    assert_eq!(action, SupervisorAction::Restart);
    assert_eq!(sup.service_state("svc"), Some(ServiceState::Running));
}

#[test]
fn budget_partially_expired() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("svc", RestartPolicy::Permanent, 2, 50));
    sup.start_service("svc");

    // Failure at t=10
    sup.report_failure("svc", "c1", 10);
    // Failure at t=40 (both within 50-tick window from now)
    sup.report_failure("svc", "c2", 40);

    // At t=70, the first failure (t=10) is outside window (70-50=20, 10<20)
    // Only the t=40 failure remains in window
    let action = sup.report_failure("svc", "c3", 70).unwrap();
    assert_eq!(action, SupervisorAction::Restart);
}

#[test]
fn budget_window_zero_always_resets() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("svc", RestartPolicy::Permanent, 1, 0));
    sup.start_service("svc");

    // With window_ticks=0, window_start = now.saturating_sub(0) = now
    // Only failures at exactly `now` count. But the restart happens, then next failure...
    let action1 = sup.report_failure("svc", "c1", 10).unwrap();
    assert_eq!(action1, SupervisorAction::Restart);

    // At t=10 again, the previous restart was at t=10, window_start = 10-0 = 10, so t=10 >= 10 counts
    // That means budget=1 is exhausted
    let action2 = sup.report_failure("svc", "c2", 10).unwrap();
    // Budget exhausted at same tick
    assert!(
        action2 == SupervisorAction::Isolate || action2 == SupervisorAction::Escalate,
        "Expected escalation or isolation, got {action2:?}"
    );
}

#[test]
fn budget_large_window_accumulates_all() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("svc", RestartPolicy::Permanent, 3, u64::MAX));
    sup.start_service("svc");

    sup.report_failure("svc", "c1", 1);
    sup.report_failure("svc", "c2", 1_000_000);
    sup.report_failure("svc", "c3", u64::MAX - 1);

    // All 3 are within the window; 4th should escalate
    let action = sup.report_failure("svc", "c4", u64::MAX).unwrap();
    assert_eq!(action, SupervisorAction::Escalate);
}

// =========================================================================
// Section 7: Severity monotone escalation
// =========================================================================

#[test]
fn severity_ordering() {
    assert!(Severity::Restart < Severity::Isolate);
    assert!(Severity::Isolate < Severity::SubtreeRestart);
    assert!(Severity::SubtreeRestart < Severity::SubtreeTerminate);
    assert!(Severity::SubtreeTerminate < Severity::RootEscalation);
}

#[test]
fn severity_never_decreases_for_service() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("svc", RestartPolicy::Permanent, 1, 100));
    sup.start_service("svc");

    // First failure: restart (within budget)
    sup.report_failure("svc", "c1", 10);
    let sev1 = sup.service_severity("svc").unwrap();
    assert_eq!(sev1, Severity::Restart);

    // Second failure: budget exhausted -> escalate
    sup.report_failure("svc", "c2", 20);
    let sev2 = sup.service_severity("svc").unwrap();
    assert!(sev2 >= sev1, "Severity must not decrease");
    assert!(sev2 >= Severity::Isolate);
}

#[test]
fn severity_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(Severity::Restart);
    set.insert(Severity::RootEscalation);
    set.insert(Severity::Restart); // dup
    assert_eq!(set.len(), 2);
    assert_eq!(*set.iter().next().unwrap(), Severity::Restart);
    assert_eq!(*set.iter().last().unwrap(), Severity::RootEscalation);
}

// =========================================================================
// Section 8: Health status
// =========================================================================

#[test]
fn healthy_when_all_running() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_permanent("svc-a"));
    sup.add_service(make_permanent("svc-b"));
    sup.start_service("svc-a");
    sup.start_service("svc-b");
    assert_eq!(sup.health(), HealthStatus::Healthy);
}

#[test]
fn healthy_when_no_services() {
    let sup = Supervisor::new("sup", "t");
    assert_eq!(sup.health(), HealthStatus::Healthy);
}

#[test]
fn healthy_when_services_starting() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_permanent("svc-a"));
    // Not started yet => Starting state
    assert_eq!(sup.health(), HealthStatus::Healthy);
}

#[test]
fn critical_when_service_isolated() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_permanent("svc-a"));
    sup.start_service("svc-a");

    // Exhaust budget to get isolation
    for i in 0..4 {
        sup.report_failure("svc-a", "crash", (i + 1) * 10);
    }
    assert_eq!(sup.health(), HealthStatus::Critical);
}

#[test]
fn critical_when_service_terminated() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("tmp", RestartPolicy::Temporary, 5, 100));
    sup.start_service("tmp");

    sup.report_failure("tmp", "crash", 10);
    assert_eq!(sup.service_state("tmp"), Some(ServiceState::Terminated));
    assert_eq!(sup.health(), HealthStatus::Critical);
}

#[test]
fn health_status_ordering() {
    assert!(HealthStatus::Healthy < HealthStatus::Degraded);
    assert!(HealthStatus::Degraded < HealthStatus::Critical);
}

#[test]
fn mixed_health_critical_overrides_degraded() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_permanent("svc-a"));
    sup.add_service(make_config("tmp", RestartPolicy::Temporary, 5, 100));
    sup.start_service("svc-a");
    sup.start_service("tmp");

    // Terminate tmp -> isolated/terminated
    sup.report_failure("tmp", "crash", 10);
    // svc-a is still running
    assert_eq!(sup.health(), HealthStatus::Critical);
}

// =========================================================================
// Section 9: Shutdown ordering
// =========================================================================

#[test]
fn shutdown_order_highest_first() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(ServiceConfig {
        service_id: "low".to_string(),
        restart_policy: RestartPolicy::Permanent,
        restart_budget: RestartBudget::default(),
        shutdown_order: 1,
    });
    sup.add_service(ServiceConfig {
        service_id: "high".to_string(),
        restart_policy: RestartPolicy::Permanent,
        restart_budget: RestartBudget::default(),
        shutdown_order: 10,
    });
    sup.add_service(ServiceConfig {
        service_id: "mid".to_string(),
        restart_policy: RestartPolicy::Permanent,
        restart_budget: RestartBudget::default(),
        shutdown_order: 5,
    });

    let order = sup.shutdown_order();
    assert_eq!(order, vec!["high", "mid", "low"]);
}

#[test]
fn shutdown_order_empty_supervisor() {
    let sup = Supervisor::new("sup", "t");
    assert!(sup.shutdown_order().is_empty());
}

#[test]
fn shutdown_order_same_priority() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(ServiceConfig {
        service_id: "a".to_string(),
        restart_policy: RestartPolicy::Permanent,
        restart_budget: RestartBudget::default(),
        shutdown_order: 5,
    });
    sup.add_service(ServiceConfig {
        service_id: "b".to_string(),
        restart_policy: RestartPolicy::Permanent,
        restart_budget: RestartBudget::default(),
        shutdown_order: 5,
    });

    let order = sup.shutdown_order();
    assert_eq!(order.len(), 2);
    // Both have same priority, but ordering should be deterministic (BTreeMap key order)
}

#[test]
fn shutdown_order_single_service() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(ServiceConfig {
        service_id: "only".to_string(),
        restart_policy: RestartPolicy::Permanent,
        restart_budget: RestartBudget::default(),
        shutdown_order: 42,
    });
    let order = sup.shutdown_order();
    assert_eq!(order, vec!["only"]);
}

// =========================================================================
// Section 10: Events
// =========================================================================

#[test]
fn start_emits_event() {
    let mut sup = Supervisor::new("sup", "trace-1");
    sup.add_service(make_permanent("svc-a"));
    sup.start_service("svc-a");

    let events = sup.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, SupervisorAction::Start);
    assert_eq!(events[0].service_id, "svc-a");
    assert_eq!(events[0].trace_id, "trace-1");
    assert_eq!(events[0].reason, "initial_start");
    assert_eq!(events[0].severity, Severity::Restart);
}

#[test]
fn restart_emits_event_with_correct_fields() {
    let mut sup = Supervisor::new("sup", "trace-42");
    sup.add_service(make_permanent("svc-a"));
    sup.start_service("svc-a");

    sup.report_failure("svc-a", "test_crash", 10);

    let events = sup.drain_events();
    let restart_event = events
        .iter()
        .find(|e| e.action == SupervisorAction::Restart)
        .unwrap();
    assert_eq!(restart_event.trace_id, "trace-42");
    assert_eq!(restart_event.service_id, "svc-a");
    assert_eq!(restart_event.reason, "test_crash");
    assert_eq!(restart_event.restart_count, 1);
    assert_eq!(restart_event.severity, Severity::Restart);
    assert!(restart_event.budget_remaining > 0);
}

#[test]
fn escalation_emits_event() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("svc", RestartPolicy::Permanent, 1, 100));
    sup.start_service("svc");

    sup.report_failure("svc", "c1", 10);
    sup.report_failure("svc", "c2", 20);

    let events = sup.drain_events();
    let escalate_event = events
        .iter()
        .find(|e| e.action == SupervisorAction::Escalate)
        .unwrap();
    assert_eq!(escalate_event.budget_remaining, 0);
    assert!(escalate_event.severity >= Severity::Isolate);
    assert!(escalate_event.reason.contains("budget_exhausted"));
}

#[test]
fn terminate_emits_event() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("tmp", RestartPolicy::Temporary, 5, 100));
    sup.start_service("tmp");

    sup.report_failure("tmp", "done", 10);

    let events = sup.drain_events();
    let term_event = events
        .iter()
        .find(|e| e.action == SupervisorAction::Terminate)
        .unwrap();
    assert_eq!(term_event.service_id, "tmp");
    assert_eq!(term_event.reason, "done");
}

#[test]
fn drain_events_clears_buffer() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_permanent("svc-a"));
    sup.start_service("svc-a");

    let events1 = sup.drain_events();
    assert_eq!(events1.len(), 1);

    let events2 = sup.drain_events();
    assert!(events2.is_empty());
}

#[test]
fn event_counts_across_multiple_services() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_permanent("svc-a"));
    sup.add_service(make_permanent("svc-b"));
    sup.start_service("svc-a");
    sup.start_service("svc-b");

    sup.report_failure("svc-a", "crash", 10);
    sup.report_failure("svc-b", "crash", 10);

    let events = sup.drain_events();
    // 2 starts + 2 restarts = 4 events
    assert_eq!(events.len(), 4);
}

// =========================================================================
// Section 11: Nonexistent service operations
// =========================================================================

#[test]
fn report_failure_nonexistent_returns_none() {
    let mut sup = Supervisor::new("sup", "t");
    assert!(sup.report_failure("ghost", "crash", 10).is_none());
}

#[test]
fn service_state_nonexistent_returns_none() {
    let sup = Supervisor::new("sup", "t");
    assert!(sup.service_state("ghost").is_none());
}

#[test]
fn restart_count_nonexistent_returns_none() {
    let sup = Supervisor::new("sup", "t");
    assert!(sup.restart_count("ghost").is_none());
}

#[test]
fn service_severity_nonexistent_returns_none() {
    let sup = Supervisor::new("sup", "t");
    assert!(sup.service_severity("ghost").is_none());
}

// =========================================================================
// Section 12: Multiple services with independent budgets
// =========================================================================

#[test]
fn independent_budgets_across_services() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_permanent("svc-a"));
    sup.add_service(make_permanent("svc-b"));
    sup.start_service("svc-a");
    sup.start_service("svc-b");

    // Exhaust svc-a budget
    sup.report_failure("svc-a", "c1", 10);
    sup.report_failure("svc-a", "c2", 20);
    sup.report_failure("svc-a", "c3", 30);
    sup.report_failure("svc-a", "c4", 40);

    // svc-a is isolated, svc-b still operational
    assert_eq!(sup.service_state("svc-a"), Some(ServiceState::Isolated));
    assert_eq!(sup.service_state("svc-b"), Some(ServiceState::Running));

    let action = sup.report_failure("svc-b", "crash", 50).unwrap();
    assert_eq!(action, SupervisorAction::Restart);
}

#[test]
fn many_services_all_healthy() {
    let mut sup = Supervisor::new("sup", "t");
    for i in 0..20 {
        sup.add_service(make_permanent(&format!("svc-{i}")));
        sup.start_service(&format!("svc-{i}"));
    }
    assert_eq!(sup.service_count(), 20);
    assert_eq!(sup.health(), HealthStatus::Healthy);
}

#[test]
fn service_replaces_on_duplicate_id() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_permanent("svc"));
    sup.start_service("svc");
    sup.report_failure("svc", "c1", 10);
    assert_eq!(sup.restart_count("svc"), Some(1));

    // Adding same ID replaces the entry
    sup.add_service(make_permanent("svc"));
    assert_eq!(sup.restart_count("svc"), Some(0));
    assert_eq!(sup.service_state("svc"), Some(ServiceState::Starting));
}

// =========================================================================
// Section 13: Serde roundtrips
// =========================================================================

#[test]
fn severity_serde_roundtrip() {
    let variants = [
        Severity::Restart,
        Severity::Isolate,
        Severity::SubtreeRestart,
        Severity::SubtreeTerminate,
        Severity::RootEscalation,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let restored: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
    }
}

#[test]
fn restart_policy_serde_roundtrip() {
    let variants = [
        RestartPolicy::Permanent,
        RestartPolicy::Transient,
        RestartPolicy::Temporary,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let restored: RestartPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
    }
}

#[test]
fn restart_budget_serde_roundtrip() {
    let budget = RestartBudget {
        max_restarts: 10,
        window_ticks: 5_000,
    };
    let json = serde_json::to_string(&budget).unwrap();
    let restored: RestartBudget = serde_json::from_str(&json).unwrap();
    assert_eq!(budget, restored);
}

#[test]
fn service_state_serde_roundtrip() {
    let variants = [
        ServiceState::Starting,
        ServiceState::Running,
        ServiceState::Failed,
        ServiceState::Restarting,
        ServiceState::Isolated,
        ServiceState::Terminated,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let restored: ServiceState = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
    }
}

#[test]
fn health_status_serde_roundtrip() {
    let variants = [
        HealthStatus::Healthy,
        HealthStatus::Degraded,
        HealthStatus::Critical,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let restored: HealthStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
    }
}

#[test]
fn supervisor_action_serde_roundtrip() {
    let variants = [
        SupervisorAction::Start,
        SupervisorAction::Restart,
        SupervisorAction::Isolate,
        SupervisorAction::Terminate,
        SupervisorAction::Escalate,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let restored: SupervisorAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*variant, restored);
    }
}

#[test]
fn service_config_serde_roundtrip() {
    let config = ServiceConfig {
        service_id: "svc-test".to_string(),
        restart_policy: RestartPolicy::Transient,
        restart_budget: RestartBudget {
            max_restarts: 7,
            window_ticks: 12_000,
        },
        shutdown_order: 99,
    };
    let json = serde_json::to_string(&config).unwrap();
    let restored: ServiceConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn supervisor_event_serde_roundtrip() {
    let event = SupervisorEvent {
        trace_id: "trace-1".to_string(),
        service_id: "svc-1".to_string(),
        action: SupervisorAction::Restart,
        reason: "crash".to_string(),
        restart_count: 3,
        budget_remaining: 2,
        severity: Severity::Restart,
    };
    let json = serde_json::to_string(&event).unwrap();
    let restored: SupervisorEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, restored);
}

#[test]
fn supervisor_event_serde_roundtrip_all_actions() {
    for action in [
        SupervisorAction::Start,
        SupervisorAction::Restart,
        SupervisorAction::Isolate,
        SupervisorAction::Terminate,
        SupervisorAction::Escalate,
    ] {
        let event = SupervisorEvent {
            trace_id: "t".to_string(),
            service_id: "s".to_string(),
            action,
            reason: "r".to_string(),
            restart_count: 0,
            budget_remaining: 0,
            severity: Severity::Restart,
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: SupervisorEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }
}

// =========================================================================
// Section 14: Deterministic replay
// =========================================================================

#[test]
fn deterministic_event_sequence_simple() {
    let run = || -> Vec<SupervisorEvent> {
        let mut sup = Supervisor::new("sup", "t");
        sup.add_service(make_permanent("svc-a"));
        sup.start_service("svc-a");
        sup.report_failure("svc-a", "crash-1", 10);
        sup.report_failure("svc-a", "crash-2", 20);
        sup.drain_events()
    };

    assert_eq!(run(), run());
}

#[test]
fn deterministic_event_sequence_with_escalation() {
    let run = || -> Vec<SupervisorEvent> {
        let mut sup = Supervisor::new("sup", "t");
        sup.add_service(make_config("svc", RestartPolicy::Permanent, 2, 100));
        sup.start_service("svc");
        sup.report_failure("svc", "c1", 10);
        sup.report_failure("svc", "c2", 20);
        sup.report_failure("svc", "c3", 30);
        sup.drain_events()
    };

    assert_eq!(run(), run());
}

#[test]
fn deterministic_event_sequence_multi_service() {
    let run = || -> Vec<SupervisorEvent> {
        let mut sup = Supervisor::new("sup", "t");
        sup.add_service(make_permanent("svc-a"));
        sup.add_service(make_permanent("svc-b"));
        sup.start_service("svc-a");
        sup.start_service("svc-b");
        sup.report_failure("svc-a", "crash", 10);
        sup.report_failure("svc-b", "crash", 20);
        sup.drain_events()
    };

    assert_eq!(run(), run());
}

#[test]
fn deterministic_event_sequence_temporary_terminate() {
    let run = || -> Vec<SupervisorEvent> {
        let mut sup = Supervisor::new("sup", "t");
        sup.add_service(make_config("tmp", RestartPolicy::Temporary, 5, 100));
        sup.start_service("tmp");
        sup.report_failure("tmp", "crash", 10);
        sup.drain_events()
    };

    assert_eq!(run(), run());
}

// =========================================================================
// Section 15: Edge cases
// =========================================================================

#[test]
fn supervisor_with_empty_string_ids() {
    let mut sup = Supervisor::new("", "");
    sup.add_service(ServiceConfig {
        service_id: String::new(),
        restart_policy: RestartPolicy::Permanent,
        restart_budget: RestartBudget::default(),
        shutdown_order: 0,
    });
    assert!(sup.start_service(""));
    assert_eq!(sup.service_state(""), Some(ServiceState::Running));
}

#[test]
fn supervisor_with_unicode_ids() {
    let mut sup = Supervisor::new("sup-\u{1F600}", "trace-\u{4E16}");
    sup.add_service(ServiceConfig {
        service_id: "svc-\u{00E9}".to_string(),
        restart_policy: RestartPolicy::Permanent,
        restart_budget: RestartBudget::default(),
        shutdown_order: 0,
    });
    assert!(sup.start_service("svc-\u{00E9}"));
    assert_eq!(
        sup.service_state("svc-\u{00E9}"),
        Some(ServiceState::Running)
    );
}

#[test]
fn restart_budget_max_u32_restarts() {
    let budget = RestartBudget {
        max_restarts: u32::MAX,
        window_ticks: 100,
    };
    assert_eq!(budget.max_restarts, u32::MAX);
}

#[test]
fn restart_budget_max_u64_window() {
    let budget = RestartBudget {
        max_restarts: 5,
        window_ticks: u64::MAX,
    };
    assert_eq!(budget.window_ticks, u64::MAX);
}

#[test]
fn service_config_fields_accessible() {
    let config = ServiceConfig {
        service_id: "svc".to_string(),
        restart_policy: RestartPolicy::Transient,
        restart_budget: RestartBudget {
            max_restarts: 7,
            window_ticks: 500,
        },
        shutdown_order: 42,
    };
    assert_eq!(config.service_id, "svc");
    assert_eq!(config.restart_policy, RestartPolicy::Transient);
    assert_eq!(config.restart_budget.max_restarts, 7);
    assert_eq!(config.restart_budget.window_ticks, 500);
    assert_eq!(config.shutdown_order, 42);
}

#[test]
fn supervisor_event_fields_accessible() {
    let event = SupervisorEvent {
        trace_id: "t-1".to_string(),
        service_id: "svc-1".to_string(),
        action: SupervisorAction::Isolate,
        reason: "budget exhausted".to_string(),
        restart_count: 5,
        budget_remaining: 0,
        severity: Severity::Isolate,
    };
    assert_eq!(event.trace_id, "t-1");
    assert_eq!(event.service_id, "svc-1");
    assert_eq!(event.action, SupervisorAction::Isolate);
    assert_eq!(event.reason, "budget exhausted");
    assert_eq!(event.restart_count, 5);
    assert_eq!(event.budget_remaining, 0);
    assert_eq!(event.severity, Severity::Isolate);
}

#[test]
fn severity_is_copy() {
    let s1 = Severity::SubtreeRestart;
    let s2 = s1; // Copy
    let s3 = s1; // Still usable after copy
    assert_eq!(s1, s2);
    assert_eq!(s2, s3);
}

#[test]
fn health_status_is_copy() {
    let h1 = HealthStatus::Degraded;
    let h2 = h1; // Copy
    let h3 = h1; // Still usable
    assert_eq!(h1, h2);
    assert_eq!(h2, h3);
}

#[test]
fn service_state_is_copy() {
    let s1 = ServiceState::Restarting;
    let s2 = s1; // Copy
    let s3 = s1; // Still usable
    assert_eq!(s1, s2);
    assert_eq!(s2, s3);
}

#[test]
fn restart_policy_is_copy() {
    let p1 = RestartPolicy::Transient;
    let p2 = p1; // Copy
    let p3 = p1; // Still usable
    assert_eq!(p1, p2);
    assert_eq!(p2, p3);
}

#[test]
fn supervisor_action_is_copy() {
    let a1 = SupervisorAction::Escalate;
    let a2 = a1; // Copy
    let a3 = a1; // Still usable
    assert_eq!(a1, a2);
    assert_eq!(a2, a3);
}

// =========================================================================
// Section 16: Stress / boundary conditions
// =========================================================================

#[test]
fn rapid_failures_same_tick() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("svc", RestartPolicy::Permanent, 5, 100));
    sup.start_service("svc");

    // 5 failures all at tick 0
    for i in 0..5 {
        let action = sup.report_failure("svc", &format!("c{i}"), 0).unwrap();
        assert_eq!(action, SupervisorAction::Restart);
    }

    // 6th at same tick: budget exhausted
    let action = sup.report_failure("svc", "c5", 0).unwrap();
    assert!(
        action == SupervisorAction::Escalate || action == SupervisorAction::Isolate,
        "Expected escalation/isolation, got {action:?}"
    );
}

#[test]
fn restart_count_accumulates_correctly() {
    let mut sup = Supervisor::new("sup", "t");
    sup.add_service(make_config("svc", RestartPolicy::Permanent, 100, 10_000));
    sup.start_service("svc");

    for i in 0..50 {
        sup.report_failure("svc", "crash", i * 10);
    }
    assert_eq!(sup.restart_count("svc"), Some(50));
}
