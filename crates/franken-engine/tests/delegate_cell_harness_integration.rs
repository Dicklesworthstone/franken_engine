#![forbid(unsafe_code)]
//! Integration tests for the `delegate_cell_harness` module.
//!
//! Exercises the public API from outside the crate, covering lifecycle state
//! machine transitions, resource usage checking, invocation recording and
//! replay verification, capability checking, event emission, performance
//! metrics, log rotation, determinism, serde round-trips, and cross-concern
//! integration scenarios.

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

use std::collections::BTreeMap;

use frankenengine_engine::delegate_cell_harness::{
    CellLifecycle, DelegateCellError, DelegateCellHarness, HarnessEvent, HarnessEventType,
    InvocationOutcome, InvocationRecord, PerformanceMetrics, ReplayVerification, ResourceUsage,
    ResourceViolation,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{
    DelegateCellManifest, DelegateType, SandboxConfiguration,
};
use frankenengine_engine::slot_registry::{AuthorityEnvelope, SlotCapability, SlotId};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_slot_id() -> SlotId {
    SlotId::new("test-parser-slot").unwrap()
}

fn test_slot_id_alt() -> SlotId {
    SlotId::new("test-alt-slot").unwrap()
}

fn test_authority() -> AuthorityEnvelope {
    AuthorityEnvelope {
        required: vec![SlotCapability::ReadSource],
        permitted: vec![
            SlotCapability::ReadSource,
            SlotCapability::EmitIr,
            SlotCapability::EmitEvidence,
        ],
    }
}

fn test_sandbox() -> SandboxConfiguration {
    SandboxConfiguration {
        max_heap_bytes: 1_000_000,
        max_execution_ns: 100_000_000,
        max_hostcalls: 100,
        network_egress_allowed: false,
        filesystem_access_allowed: false,
    }
}

fn permissive_sandbox() -> SandboxConfiguration {
    SandboxConfiguration {
        max_heap_bytes: u64::MAX,
        max_execution_ns: u64::MAX,
        max_hostcalls: u64::MAX,
        network_egress_allowed: true,
        filesystem_access_allowed: true,
    }
}

fn test_harness() -> DelegateCellHarness {
    DelegateCellHarness::new(
        test_slot_id(),
        DelegateType::QuickJsBacked,
        test_sandbox(),
        test_authority(),
        [0xAB; 32],
    )
}

fn running_harness() -> DelegateCellHarness {
    let mut harness = test_harness();
    harness
        .transition_to(CellLifecycle::Starting, 1_000)
        .unwrap();
    harness
        .transition_to(CellLifecycle::Running, 2_000)
        .unwrap();
    harness
}

fn ok_usage() -> ResourceUsage {
    ResourceUsage {
        heap_bytes_used: 500_000,
        execution_ns: 50_000_000,
        hostcall_count: 10,
        network_egress_bytes: 0,
        filesystem_read_bytes: 0,
    }
}

// =========================================================================
// 1. CellLifecycle — enum variant construction, Display, serde round-trip
// =========================================================================

#[test]
fn cell_lifecycle_all_variants_display() {
    let expected = [
        (CellLifecycle::Created, "created"),
        (CellLifecycle::Starting, "starting"),
        (CellLifecycle::Running, "running"),
        (CellLifecycle::Suspended, "suspended"),
        (CellLifecycle::Stopping, "stopping"),
        (CellLifecycle::Terminated, "terminated"),
        (CellLifecycle::Quarantined, "quarantined"),
    ];
    for (variant, label) in expected {
        assert_eq!(variant.to_string(), label);
    }
}

#[test]
fn cell_lifecycle_serde_round_trip_all_variants() {
    let variants = [
        CellLifecycle::Created,
        CellLifecycle::Starting,
        CellLifecycle::Running,
        CellLifecycle::Suspended,
        CellLifecycle::Stopping,
        CellLifecycle::Terminated,
        CellLifecycle::Quarantined,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let decoded: CellLifecycle = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, decoded);
    }
}

#[test]
fn cell_lifecycle_can_invoke_only_in_running() {
    let non_running = [
        CellLifecycle::Created,
        CellLifecycle::Starting,
        CellLifecycle::Suspended,
        CellLifecycle::Stopping,
        CellLifecycle::Terminated,
        CellLifecycle::Quarantined,
    ];
    for state in non_running {
        assert!(
            !state.can_invoke(),
            "can_invoke should be false for {state}"
        );
    }
    assert!(CellLifecycle::Running.can_invoke());
}

#[test]
fn cell_lifecycle_is_terminal_only_for_terminated_and_quarantined() {
    let non_terminal = [
        CellLifecycle::Created,
        CellLifecycle::Starting,
        CellLifecycle::Running,
        CellLifecycle::Suspended,
        CellLifecycle::Stopping,
    ];
    for state in non_terminal {
        assert!(
            !state.is_terminal(),
            "is_terminal should be false for {state}"
        );
    }
    assert!(CellLifecycle::Terminated.is_terminal());
    assert!(CellLifecycle::Quarantined.is_terminal());
}

// =========================================================================
// 2. Lifecycle state machine transitions — valid and invalid
// =========================================================================

#[test]
fn lifecycle_valid_transitions_exhaustive() {
    // Created -> Starting, Terminated
    let created = CellLifecycle::Created;
    assert!(created.can_transition_to(CellLifecycle::Starting));
    assert!(created.can_transition_to(CellLifecycle::Terminated));
    assert!(!created.can_transition_to(CellLifecycle::Running));
    assert!(!created.can_transition_to(CellLifecycle::Suspended));
    assert!(!created.can_transition_to(CellLifecycle::Stopping));
    assert!(!created.can_transition_to(CellLifecycle::Quarantined));

    // Starting -> Running, Terminated
    let starting = CellLifecycle::Starting;
    assert!(starting.can_transition_to(CellLifecycle::Running));
    assert!(starting.can_transition_to(CellLifecycle::Terminated));
    assert!(!starting.can_transition_to(CellLifecycle::Suspended));
    assert!(!starting.can_transition_to(CellLifecycle::Stopping));

    // Running -> Suspended, Stopping, Quarantined
    let running = CellLifecycle::Running;
    assert!(running.can_transition_to(CellLifecycle::Suspended));
    assert!(running.can_transition_to(CellLifecycle::Stopping));
    assert!(running.can_transition_to(CellLifecycle::Quarantined));
    assert!(!running.can_transition_to(CellLifecycle::Created));
    assert!(!running.can_transition_to(CellLifecycle::Starting));
    assert!(!running.can_transition_to(CellLifecycle::Terminated));

    // Suspended -> Running, Stopping, Quarantined
    let suspended = CellLifecycle::Suspended;
    assert!(suspended.can_transition_to(CellLifecycle::Running));
    assert!(suspended.can_transition_to(CellLifecycle::Stopping));
    assert!(suspended.can_transition_to(CellLifecycle::Quarantined));
    assert!(!suspended.can_transition_to(CellLifecycle::Created));

    // Stopping -> Terminated
    let stopping = CellLifecycle::Stopping;
    assert!(stopping.can_transition_to(CellLifecycle::Terminated));
    assert!(!stopping.can_transition_to(CellLifecycle::Running));

    // Terminated -> nothing
    assert!(CellLifecycle::Terminated.valid_transitions().is_empty());

    // Quarantined -> nothing
    assert!(CellLifecycle::Quarantined.valid_transitions().is_empty());
}

#[test]
fn lifecycle_self_transition_is_never_valid() {
    let all = [
        CellLifecycle::Created,
        CellLifecycle::Starting,
        CellLifecycle::Running,
        CellLifecycle::Suspended,
        CellLifecycle::Stopping,
        CellLifecycle::Terminated,
        CellLifecycle::Quarantined,
    ];
    for state in all {
        assert!(
            !state.can_transition_to(state),
            "self-transition should be invalid for {state}"
        );
    }
}

// =========================================================================
// 3. ResourceUsage — construction, Default, limit checking
// =========================================================================

#[test]
fn resource_usage_default_is_zero() {
    let usage = ResourceUsage::default();
    assert_eq!(usage.heap_bytes_used, 0);
    assert_eq!(usage.execution_ns, 0);
    assert_eq!(usage.hostcall_count, 0);
    assert_eq!(usage.network_egress_bytes, 0);
    assert_eq!(usage.filesystem_read_bytes, 0);
}

#[test]
fn resource_usage_serde_round_trip() {
    let usage = ResourceUsage {
        heap_bytes_used: 42,
        execution_ns: 99,
        hostcall_count: 7,
        network_egress_bytes: 128,
        filesystem_read_bytes: 256,
    };
    let json = serde_json::to_string(&usage).unwrap();
    let decoded: ResourceUsage = serde_json::from_str(&json).unwrap();
    assert_eq!(usage, decoded);
}

#[test]
fn resource_usage_within_limits_returns_none() {
    let usage = ok_usage();
    assert!(usage.exceeds_limits(&test_sandbox()).is_none());
}

#[test]
fn resource_usage_heap_exceeded() {
    let usage = ResourceUsage {
        heap_bytes_used: 2_000_000,
        ..Default::default()
    };
    let violation = usage.exceeds_limits(&test_sandbox()).unwrap();
    match violation {
        ResourceViolation::HeapExceeded { used, limit } => {
            assert_eq!(used, 2_000_000);
            assert_eq!(limit, 1_000_000);
        }
        other => panic!("expected HeapExceeded, got {other}"),
    }
}

#[test]
fn resource_usage_execution_time_exceeded() {
    let usage = ResourceUsage {
        execution_ns: 200_000_000,
        ..Default::default()
    };
    let violation = usage.exceeds_limits(&test_sandbox()).unwrap();
    assert!(matches!(
        violation,
        ResourceViolation::ExecutionTimeExceeded { .. }
    ));
}

#[test]
fn resource_usage_hostcall_limit_exceeded() {
    let usage = ResourceUsage {
        hostcall_count: 200,
        ..Default::default()
    };
    let violation = usage.exceeds_limits(&test_sandbox()).unwrap();
    assert!(matches!(
        violation,
        ResourceViolation::HostcallLimitExceeded { .. }
    ));
}

#[test]
fn resource_usage_network_egress_denied() {
    let sandbox = test_sandbox();
    assert!(!sandbox.network_egress_allowed);
    let usage = ResourceUsage {
        network_egress_bytes: 1,
        ..Default::default()
    };
    let violation = usage.exceeds_limits(&sandbox).unwrap();
    match violation {
        ResourceViolation::NetworkEgressDenied { bytes } => {
            assert_eq!(bytes, 1);
        }
        other => panic!("expected NetworkEgressDenied, got {other}"),
    }
}

#[test]
fn resource_usage_filesystem_access_denied() {
    let sandbox = test_sandbox();
    assert!(!sandbox.filesystem_access_allowed);
    let usage = ResourceUsage {
        filesystem_read_bytes: 1,
        ..Default::default()
    };
    let violation = usage.exceeds_limits(&sandbox).unwrap();
    assert!(matches!(
        violation,
        ResourceViolation::FilesystemAccessDenied { bytes: 1 }
    ));
}

#[test]
fn resource_usage_network_allowed_when_sandbox_permits() {
    let usage = ResourceUsage {
        network_egress_bytes: 1000,
        ..Default::default()
    };
    assert!(usage.exceeds_limits(&permissive_sandbox()).is_none());
}

#[test]
fn resource_usage_filesystem_allowed_when_sandbox_permits() {
    let usage = ResourceUsage {
        filesystem_read_bytes: 1000,
        ..Default::default()
    };
    assert!(usage.exceeds_limits(&permissive_sandbox()).is_none());
}

#[test]
fn resource_usage_exactly_at_limit_is_ok() {
    let sandbox = test_sandbox();
    let usage = ResourceUsage {
        heap_bytes_used: sandbox.max_heap_bytes,
        execution_ns: sandbox.max_execution_ns,
        hostcall_count: sandbox.max_hostcalls,
        network_egress_bytes: 0,
        filesystem_read_bytes: 0,
    };
    assert!(usage.exceeds_limits(&sandbox).is_none());
}

#[test]
fn resource_usage_one_over_limit_triggers_violation() {
    let sandbox = test_sandbox();
    let usage = ResourceUsage {
        heap_bytes_used: sandbox.max_heap_bytes + 1,
        ..Default::default()
    };
    assert!(usage.exceeds_limits(&sandbox).is_some());
}

// =========================================================================
// 4. ResourceViolation — Display, serde round-trip
// =========================================================================

#[test]
fn resource_violation_display_all_variants() {
    let variants: Vec<(ResourceViolation, &str)> = vec![
        (
            ResourceViolation::HeapExceeded {
                used: 200,
                limit: 100,
            },
            "heap exceeded: 200 > 100 bytes",
        ),
        (
            ResourceViolation::ExecutionTimeExceeded {
                used_ns: 50,
                limit_ns: 40,
            },
            "execution time exceeded: 50 > 40 ns",
        ),
        (
            ResourceViolation::HostcallLimitExceeded {
                count: 15,
                limit: 10,
            },
            "hostcall limit exceeded: 15 > 10",
        ),
        (
            ResourceViolation::NetworkEgressDenied { bytes: 256 },
            "network egress denied: 256 bytes attempted",
        ),
        (
            ResourceViolation::FilesystemAccessDenied { bytes: 512 },
            "filesystem access denied: 512 bytes attempted",
        ),
    ];
    for (v, expected) in variants {
        assert_eq!(v.to_string(), expected);
    }
}

#[test]
fn resource_violation_serde_round_trip() {
    let variants = vec![
        ResourceViolation::HeapExceeded {
            used: 200,
            limit: 100,
        },
        ResourceViolation::ExecutionTimeExceeded {
            used_ns: 50,
            limit_ns: 40,
        },
        ResourceViolation::HostcallLimitExceeded {
            count: 15,
            limit: 10,
        },
        ResourceViolation::NetworkEgressDenied { bytes: 256 },
        ResourceViolation::FilesystemAccessDenied { bytes: 512 },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let decoded: ResourceViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, decoded);
    }
}

// =========================================================================
// 5. InvocationOutcome — Display, serde round-trip
// =========================================================================

#[test]
fn invocation_outcome_display_all_variants() {
    assert_eq!(InvocationOutcome::Success.to_string(), "success");
    assert_eq!(InvocationOutcome::Timeout.to_string(), "timeout");

    let error_outcome = InvocationOutcome::Error {
        code: 42,
        message: "test error".into(),
    };
    assert_eq!(error_outcome.to_string(), "error(42): test error");

    let violation_outcome = InvocationOutcome::ResourceViolation(ResourceViolation::HeapExceeded {
        used: 200,
        limit: 100,
    });
    assert!(violation_outcome.to_string().contains("resource_violation"));

    let cap_outcome = InvocationOutcome::CapabilityDenied {
        capability: SlotCapability::HeapAlloc,
    };
    assert!(cap_outcome.to_string().contains("capability_denied"));
}

#[test]
fn invocation_outcome_serde_round_trip_all_variants() {
    let outcomes = vec![
        InvocationOutcome::Success,
        InvocationOutcome::Timeout,
        InvocationOutcome::Error {
            code: 42,
            message: "test error".into(),
        },
        InvocationOutcome::ResourceViolation(ResourceViolation::HeapExceeded {
            used: 200,
            limit: 100,
        }),
        InvocationOutcome::CapabilityDenied {
            capability: SlotCapability::HeapAlloc,
        },
    ];
    for outcome in &outcomes {
        let json = serde_json::to_string(outcome).unwrap();
        let decoded: InvocationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*outcome, decoded);
    }
}

// =========================================================================
// 6. HarnessEventType — Display, serde round-trip
// =========================================================================

#[test]
fn harness_event_type_display_all_variants() {
    let expected = [
        (
            HarnessEventType::LifecycleTransition,
            "lifecycle_transition",
        ),
        (HarnessEventType::InvocationStarted, "invocation_started"),
        (
            HarnessEventType::InvocationCompleted,
            "invocation_completed",
        ),
        (HarnessEventType::CapabilityCheck, "capability_check"),
        (HarnessEventType::ResourceViolation, "resource_violation"),
        (HarnessEventType::ReplayVerification, "replay_verification"),
    ];
    for (variant, label) in expected {
        assert_eq!(variant.to_string(), label);
    }
}

#[test]
fn harness_event_type_serde_round_trip() {
    let variants = [
        HarnessEventType::LifecycleTransition,
        HarnessEventType::InvocationStarted,
        HarnessEventType::InvocationCompleted,
        HarnessEventType::CapabilityCheck,
        HarnessEventType::ResourceViolation,
        HarnessEventType::ReplayVerification,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let decoded: HarnessEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, decoded);
    }
}

// =========================================================================
// 7. HarnessEvent — construction, serde round-trip
// =========================================================================

#[test]
fn harness_event_construction_and_serde() {
    let mut fields = BTreeMap::new();
    fields.insert("key1".to_string(), "value1".to_string());
    fields.insert("key2".to_string(), "value2".to_string());
    let event = HarnessEvent {
        event_type: HarnessEventType::InvocationCompleted,
        cell_id: test_slot_id(),
        timestamp_ns: 42_000,
        fields,
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: HarnessEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, decoded);
    assert_eq!(decoded.timestamp_ns, 42_000);
    assert_eq!(decoded.fields.len(), 2);
}

// =========================================================================
// 8. PerformanceMetrics — Default, record, computed values, serde
// =========================================================================

#[test]
fn performance_metrics_default_all_zero() {
    let m = PerformanceMetrics::default();
    assert_eq!(m.total_invocations, 0);
    assert_eq!(m.successful_invocations, 0);
    assert_eq!(m.failed_invocations, 0);
    assert_eq!(m.total_duration_ns, 0);
    assert_eq!(m.min_duration_ns, 0);
    assert_eq!(m.max_duration_ns, 0);
    assert_eq!(m.total_heap_bytes, 0);
    assert_eq!(m.total_hostcalls, 0);
}

#[test]
fn performance_metrics_avg_duration_zero_invocations() {
    let m = PerformanceMetrics::default();
    assert_eq!(m.avg_duration_millionths(), 0);
}

#[test]
fn performance_metrics_success_rate_zero_invocations() {
    let m = PerformanceMetrics::default();
    assert_eq!(m.success_rate_millionths(), 0);
}

#[test]
fn performance_metrics_serde_round_trip() {
    let m = PerformanceMetrics {
        total_invocations: 10,
        successful_invocations: 8,
        failed_invocations: 2,
        total_duration_ns: 1_000_000,
        min_duration_ns: 50_000,
        max_duration_ns: 200_000,
        total_heap_bytes: 5_000_000,
        total_hostcalls: 80,
    };
    let json = serde_json::to_string(&m).unwrap();
    let decoded: PerformanceMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(m, decoded);
}

#[test]
fn performance_metrics_avg_duration_computed_correctly() {
    let mut harness = running_harness();
    // Record 2 invocations: 1_000_000 ns and 3_000_000 ns
    harness
        .record_invocation(b"a", b"b", 1, ok_usage(), 1_000_000, 10_000)
        .unwrap();
    harness
        .record_invocation(b"c", b"d", 2, ok_usage(), 3_000_000, 20_000)
        .unwrap();

    // Average = 2_000_000 ns, in millionths = 2_000_000 * 1_000_000 / 2 = 1_000_000_000_000
    // Wait, that's per invocation: total_duration_ns = 4_000_000, / 2 = 2_000_000, * 1_000_000
    assert_eq!(harness.metrics.avg_duration_millionths(), 2_000_000_000_000);
}

#[test]
fn performance_metrics_success_rate_mixed() {
    let mut harness = running_harness();
    // One success
    harness
        .record_invocation(b"a", b"b", 1, ok_usage(), 100, 10_000)
        .unwrap();
    // One failure (resource violation)
    let excessive = ResourceUsage {
        heap_bytes_used: 5_000_000,
        ..Default::default()
    };
    harness
        .record_invocation(b"c", b"d", 2, excessive, 200, 20_000)
        .unwrap();

    assert_eq!(harness.metrics.total_invocations, 2);
    assert_eq!(harness.metrics.successful_invocations, 1);
    assert_eq!(harness.metrics.failed_invocations, 1);
    assert_eq!(harness.metrics.success_rate_millionths(), 500_000); // 50%
}

#[test]
fn performance_metrics_all_failures() {
    let mut harness = running_harness();
    let excessive = ResourceUsage {
        heap_bytes_used: 5_000_000,
        ..Default::default()
    };
    for i in 0..5 {
        harness
            .record_invocation(b"x", b"y", i, excessive.clone(), 100, 10_000 + i * 1000)
            .unwrap();
    }
    assert_eq!(harness.metrics.total_invocations, 5);
    assert_eq!(harness.metrics.successful_invocations, 0);
    assert_eq!(harness.metrics.failed_invocations, 5);
    assert_eq!(harness.metrics.success_rate_millionths(), 0);
}

#[test]
fn performance_metrics_min_max_tracking() {
    let mut harness = running_harness();
    harness
        .record_invocation(b"a", b"b", 1, ok_usage(), 500, 10_000)
        .unwrap();
    harness
        .record_invocation(b"c", b"d", 2, ok_usage(), 100, 20_000)
        .unwrap();
    harness
        .record_invocation(b"e", b"f", 3, ok_usage(), 1000, 30_000)
        .unwrap();

    assert_eq!(harness.metrics.min_duration_ns, 100);
    assert_eq!(harness.metrics.max_duration_ns, 1000);
}

#[test]
fn performance_metrics_heap_and_hostcall_accumulation() {
    let mut harness = running_harness();
    let usage1 = ResourceUsage {
        heap_bytes_used: 100,
        hostcall_count: 5,
        ..Default::default()
    };
    let usage2 = ResourceUsage {
        heap_bytes_used: 200,
        hostcall_count: 10,
        ..Default::default()
    };
    harness
        .record_invocation(b"a", b"b", 1, usage1, 100, 10_000)
        .unwrap();
    harness
        .record_invocation(b"c", b"d", 2, usage2, 100, 20_000)
        .unwrap();

    assert_eq!(harness.metrics.total_heap_bytes, 300);
    assert_eq!(harness.metrics.total_hostcalls, 15);
}

// =========================================================================
// 9. ReplayVerification — serde round-trip
// =========================================================================

#[test]
fn replay_verification_match_serde_round_trip() {
    let rv = ReplayVerification::Match { sequence: 42 };
    let json = serde_json::to_string(&rv).unwrap();
    let decoded: ReplayVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(rv, decoded);
}

#[test]
fn replay_verification_mismatch_serde_round_trip() {
    let rv = ReplayVerification::Mismatch {
        sequence: 7,
        expected_hash: ContentHash::compute(b"expected"),
        actual_hash: ContentHash::compute(b"actual"),
    };
    let json = serde_json::to_string(&rv).unwrap();
    let decoded: ReplayVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(rv, decoded);
}

// =========================================================================
// 10. DelegateCellError — Display, serde round-trip
// =========================================================================

#[test]
fn delegate_cell_error_display_all_variants() {
    let err1 = DelegateCellError::InvalidTransition {
        from: CellLifecycle::Created,
        to: CellLifecycle::Running,
    };
    let display = err1.to_string();
    assert!(display.contains("invalid transition"));
    assert!(display.contains("created"));
    assert!(display.contains("running"));

    let err2 = DelegateCellError::NotRunning {
        state: CellLifecycle::Suspended,
    };
    assert!(err2.to_string().contains("not running"));
    assert!(err2.to_string().contains("suspended"));

    let err3 = DelegateCellError::CapabilityDenied {
        capability: SlotCapability::HeapAlloc,
    };
    assert!(err3.to_string().contains("capability denied"));

    let err4 = DelegateCellError::ResourceLimitExceeded(ResourceViolation::HeapExceeded {
        used: 200,
        limit: 100,
    });
    assert!(err4.to_string().contains("resource limit exceeded"));
}

#[test]
fn delegate_cell_error_serde_round_trip() {
    let errors = vec![
        DelegateCellError::InvalidTransition {
            from: CellLifecycle::Created,
            to: CellLifecycle::Running,
        },
        DelegateCellError::NotRunning {
            state: CellLifecycle::Suspended,
        },
        DelegateCellError::CapabilityDenied {
            capability: SlotCapability::HeapAlloc,
        },
        DelegateCellError::ResourceLimitExceeded(ResourceViolation::ExecutionTimeExceeded {
            used_ns: 999,
            limit_ns: 100,
        }),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let decoded: DelegateCellError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, decoded);
    }
}

#[test]
fn delegate_cell_error_is_std_error() {
    let err = DelegateCellError::NotRunning {
        state: CellLifecycle::Created,
    };
    let _: &dyn std::error::Error = &err;
}

// =========================================================================
// 11. DelegateCellHarness — construction
// =========================================================================

#[test]
fn harness_new_initial_state() {
    let harness = test_harness();
    assert_eq!(harness.lifecycle, CellLifecycle::Created);
    assert_eq!(harness.invocation_count(), 0);
    assert_eq!(harness.delegate_type, DelegateType::QuickJsBacked);
    assert_eq!(harness.current_epoch, SecurityEpoch::GENESIS);
    assert_eq!(harness.expected_behavior_hash, [0xAB; 32]);
    assert!(harness.invocation_log().is_empty());
    assert!(harness.events.is_empty());
}

#[test]
fn harness_new_with_different_delegate_types() {
    let types = [
        DelegateType::QuickJsBacked,
        DelegateType::WasmBacked,
        DelegateType::ExternalProcess,
    ];
    for dt in types {
        let harness = DelegateCellHarness::new(
            test_slot_id(),
            dt,
            test_sandbox(),
            test_authority(),
            [0; 32],
        );
        assert_eq!(harness.delegate_type, dt);
    }
}

#[test]
fn harness_from_manifest() {
    use frankenengine_engine::signature_preimage::{SIGNATURE_SENTINEL, Signature};

    let slot_id = test_slot_id();
    let behavior_hash = [0xCC; 32];
    let manifest_id = DelegateCellManifest::derive_manifest_id(
        &slot_id,
        DelegateType::WasmBacked,
        &behavior_hash,
        "test-zone",
    )
    .unwrap();

    let manifest = DelegateCellManifest {
        manifest_id,
        schema_version: frankenengine_engine::self_replacement::SchemaVersion::V1,
        slot_id: slot_id.clone(),
        delegate_type: DelegateType::WasmBacked,
        capability_envelope: test_authority(),
        sandbox: test_sandbox(),
        monitoring_hooks: vec![],
        expected_behavior_hash: behavior_hash,
        zone: "test-zone".to_string(),
        signature: Signature::from_bytes(SIGNATURE_SENTINEL),
    };

    let harness = DelegateCellHarness::from_manifest(&manifest);
    assert_eq!(harness.slot_id, slot_id);
    assert_eq!(harness.delegate_type, DelegateType::WasmBacked);
    assert_eq!(harness.lifecycle, CellLifecycle::Created);
    assert_eq!(harness.expected_behavior_hash, behavior_hash);
    assert_eq!(harness.current_epoch, SecurityEpoch::GENESIS);
}

// =========================================================================
// 12. DelegateCellHarness — lifecycle transitions
// =========================================================================

#[test]
fn harness_full_lifecycle_happy_path() {
    let mut harness = test_harness();
    harness
        .transition_to(CellLifecycle::Starting, 1_000)
        .unwrap();
    assert_eq!(harness.lifecycle, CellLifecycle::Starting);

    harness
        .transition_to(CellLifecycle::Running, 2_000)
        .unwrap();
    assert_eq!(harness.lifecycle, CellLifecycle::Running);

    harness
        .transition_to(CellLifecycle::Stopping, 3_000)
        .unwrap();
    assert_eq!(harness.lifecycle, CellLifecycle::Stopping);

    harness
        .transition_to(CellLifecycle::Terminated, 4_000)
        .unwrap();
    assert_eq!(harness.lifecycle, CellLifecycle::Terminated);
    assert!(harness.lifecycle.is_terminal());
}

#[test]
fn harness_lifecycle_created_to_terminated_directly() {
    let mut harness = test_harness();
    harness
        .transition_to(CellLifecycle::Terminated, 1_000)
        .unwrap();
    assert!(harness.lifecycle.is_terminal());
}

#[test]
fn harness_lifecycle_starting_to_terminated_on_init_failure() {
    let mut harness = test_harness();
    harness
        .transition_to(CellLifecycle::Starting, 1_000)
        .unwrap();
    harness
        .transition_to(CellLifecycle::Terminated, 2_000)
        .unwrap();
    assert!(harness.lifecycle.is_terminal());
}

#[test]
fn harness_lifecycle_quarantine_from_running() {
    let mut harness = running_harness();
    harness
        .transition_to(CellLifecycle::Quarantined, 10_000)
        .unwrap();
    assert!(harness.lifecycle.is_terminal());
}

#[test]
fn harness_lifecycle_quarantine_from_suspended() {
    let mut harness = running_harness();
    harness
        .transition_to(CellLifecycle::Suspended, 3_000)
        .unwrap();
    harness
        .transition_to(CellLifecycle::Quarantined, 4_000)
        .unwrap();
    assert!(harness.lifecycle.is_terminal());
}

#[test]
fn harness_lifecycle_suspend_resume_cycle() {
    let mut harness = running_harness();
    for i in 0..5 {
        let ts = 3_000 + i * 2_000;
        harness.transition_to(CellLifecycle::Suspended, ts).unwrap();
        harness
            .transition_to(CellLifecycle::Running, ts + 1_000)
            .unwrap();
    }
    assert_eq!(harness.lifecycle, CellLifecycle::Running);
}

#[test]
fn harness_lifecycle_invalid_transition_errors() {
    let mut harness = test_harness();
    // Created -> Running is invalid (must go through Starting)
    let err = harness
        .transition_to(CellLifecycle::Running, 1_000)
        .unwrap_err();
    match err {
        DelegateCellError::InvalidTransition { from, to } => {
            assert_eq!(from, CellLifecycle::Created);
            assert_eq!(to, CellLifecycle::Running);
        }
        other => panic!("expected InvalidTransition, got {other}"),
    }
}

#[test]
fn harness_lifecycle_no_transition_from_terminated() {
    let mut harness = test_harness();
    harness
        .transition_to(CellLifecycle::Terminated, 1_000)
        .unwrap();
    let err = harness
        .transition_to(CellLifecycle::Running, 2_000)
        .unwrap_err();
    assert!(matches!(err, DelegateCellError::InvalidTransition { .. }));
}

#[test]
fn harness_lifecycle_no_transition_from_quarantined() {
    let mut harness = running_harness();
    harness
        .transition_to(CellLifecycle::Quarantined, 10_000)
        .unwrap();
    let err = harness
        .transition_to(CellLifecycle::Running, 11_000)
        .unwrap_err();
    assert!(matches!(err, DelegateCellError::InvalidTransition { .. }));
}

#[test]
fn harness_lifecycle_emits_events() {
    let mut harness = test_harness();
    harness
        .transition_to(CellLifecycle::Starting, 1_000)
        .unwrap();
    harness
        .transition_to(CellLifecycle::Running, 2_000)
        .unwrap();

    let events = harness.events_of_type(&HarnessEventType::LifecycleTransition);
    assert_eq!(events.len(), 2);

    assert_eq!(events[0].fields.get("from").unwrap(), "created");
    assert_eq!(events[0].fields.get("to").unwrap(), "starting");
    assert_eq!(events[0].timestamp_ns, 1_000);

    assert_eq!(events[1].fields.get("from").unwrap(), "starting");
    assert_eq!(events[1].fields.get("to").unwrap(), "running");
    assert_eq!(events[1].timestamp_ns, 2_000);
}

// =========================================================================
// 13. DelegateCellHarness — capability checking
// =========================================================================

#[test]
fn harness_check_permitted_capability_ok() {
    let mut harness = test_harness();
    assert!(
        harness
            .check_capability(&SlotCapability::ReadSource, 1_000)
            .is_ok()
    );
    assert!(
        harness
            .check_capability(&SlotCapability::EmitIr, 2_000)
            .is_ok()
    );
    assert!(
        harness
            .check_capability(&SlotCapability::EmitEvidence, 3_000)
            .is_ok()
    );
}

#[test]
fn harness_check_denied_capability_error() {
    let mut harness = test_harness();
    let denied_caps = [
        SlotCapability::HeapAlloc,
        SlotCapability::ScheduleAsync,
        SlotCapability::InvokeHostcall,
        SlotCapability::ModuleAccess,
        SlotCapability::TriggerGc,
    ];
    for cap in &denied_caps {
        let err = harness.check_capability(cap, 1_000).unwrap_err();
        match err {
            DelegateCellError::CapabilityDenied { capability } => {
                assert_eq!(capability, *cap);
            }
            other => panic!("expected CapabilityDenied, got {other}"),
        }
    }
}

#[test]
fn harness_capability_check_emits_events() {
    let mut harness = test_harness();
    // Permitted check
    harness
        .check_capability(&SlotCapability::ReadSource, 1_000)
        .unwrap();
    // Denied check
    let _ = harness.check_capability(&SlotCapability::HeapAlloc, 2_000);

    let events = harness.events_of_type(&HarnessEventType::CapabilityCheck);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].fields.get("permitted").unwrap(), "true");
    assert_eq!(events[1].fields.get("permitted").unwrap(), "false");
}

#[test]
fn harness_empty_authority_denies_everything() {
    let empty_authority = AuthorityEnvelope {
        required: vec![],
        permitted: vec![],
    };
    let mut harness = DelegateCellHarness::new(
        test_slot_id(),
        DelegateType::QuickJsBacked,
        test_sandbox(),
        empty_authority,
        [0; 32],
    );
    let err = harness
        .check_capability(&SlotCapability::ReadSource, 1_000)
        .unwrap_err();
    assert!(matches!(err, DelegateCellError::CapabilityDenied { .. }));
}

// =========================================================================
// 14. DelegateCellHarness — invocation recording
// =========================================================================

#[test]
fn harness_invocation_requires_running_state() {
    let mut harness = test_harness();
    let err = harness
        .record_invocation(b"input", b"output", 42, ok_usage(), 1_000, 10_000)
        .unwrap_err();
    match err {
        DelegateCellError::NotRunning { state } => {
            assert_eq!(state, CellLifecycle::Created);
        }
        other => panic!("expected NotRunning, got {other}"),
    }
}

#[test]
fn harness_invocation_denied_in_suspended_state() {
    let mut harness = running_harness();
    harness
        .transition_to(CellLifecycle::Suspended, 5_000)
        .unwrap();
    let err = harness
        .record_invocation(b"input", b"output", 42, ok_usage(), 1_000, 10_000)
        .unwrap_err();
    assert!(matches!(
        err,
        DelegateCellError::NotRunning {
            state: CellLifecycle::Suspended
        }
    ));
}

#[test]
fn harness_invocation_denied_in_stopping_state() {
    let mut harness = running_harness();
    harness
        .transition_to(CellLifecycle::Stopping, 5_000)
        .unwrap();
    let err = harness
        .record_invocation(b"input", b"output", 42, ok_usage(), 1_000, 10_000)
        .unwrap_err();
    assert!(matches!(
        err,
        DelegateCellError::NotRunning {
            state: CellLifecycle::Stopping
        }
    ));
}

#[test]
fn harness_successful_invocation_records_correctly() {
    let mut harness = running_harness();
    let record = harness
        .record_invocation(b"input", b"output", 42, ok_usage(), 50_000, 10_000)
        .unwrap();

    assert_eq!(record.sequence, 1);
    assert_eq!(record.replay_seed, 42);
    assert_eq!(record.timestamp_ns, 10_000);
    assert_eq!(record.duration_ns, 50_000);
    assert_eq!(record.epoch, SecurityEpoch::GENESIS);
    assert!(matches!(record.outcome, InvocationOutcome::Success));
    assert_eq!(record.input_hash, ContentHash::compute(b"input"));
    assert_eq!(record.output_hash, ContentHash::compute(b"output"));
}

#[test]
fn harness_invocation_monotonic_sequence() {
    let mut harness = running_harness();
    let r1 = harness
        .record_invocation(b"a", b"b", 1, ok_usage(), 100, 10_000)
        .unwrap();
    let r2 = harness
        .record_invocation(b"c", b"d", 2, ok_usage(), 100, 20_000)
        .unwrap();
    let r3 = harness
        .record_invocation(b"e", b"f", 3, ok_usage(), 100, 30_000)
        .unwrap();

    assert_eq!(r1.sequence, 1);
    assert_eq!(r2.sequence, 2);
    assert_eq!(r3.sequence, 3);
    assert!(r1.sequence < r2.sequence);
    assert!(r2.sequence < r3.sequence);
}

#[test]
fn harness_invocation_count_tracks_total() {
    let mut harness = running_harness();
    assert_eq!(harness.invocation_count(), 0);

    for i in 0..10 {
        harness
            .record_invocation(b"x", b"y", i, ok_usage(), 100, 10_000 + i * 1000)
            .unwrap();
    }
    assert_eq!(harness.invocation_count(), 10);
}

#[test]
fn harness_invocation_resource_violation_detected() {
    let mut harness = running_harness();
    let excessive = ResourceUsage {
        heap_bytes_used: 5_000_000,
        ..Default::default()
    };
    let record = harness
        .record_invocation(b"in", b"out", 1, excessive, 100, 10_000)
        .unwrap();
    assert!(matches!(
        record.outcome,
        InvocationOutcome::ResourceViolation(ResourceViolation::HeapExceeded { .. })
    ));
}

#[test]
fn harness_invocation_with_network_violation() {
    let mut harness = running_harness();
    let usage = ResourceUsage {
        network_egress_bytes: 100,
        ..Default::default()
    };
    let record = harness
        .record_invocation(b"in", b"out", 1, usage, 100, 10_000)
        .unwrap();
    assert!(matches!(
        record.outcome,
        InvocationOutcome::ResourceViolation(ResourceViolation::NetworkEgressDenied { .. })
    ));
}

#[test]
fn harness_invocation_emits_completion_event() {
    let mut harness = running_harness();
    harness
        .record_invocation(b"a", b"b", 1, ok_usage(), 100, 10_000)
        .unwrap();

    let events = harness.events_of_type(&HarnessEventType::InvocationCompleted);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].fields.get("sequence").unwrap(), "1");
    assert_eq!(events[0].fields.get("outcome").unwrap(), "success");
    assert_eq!(events[0].fields.get("duration_ns").unwrap(), "100");
}

#[test]
fn harness_invocation_resource_violation_emits_both_events() {
    let mut harness = running_harness();
    let excessive = ResourceUsage {
        heap_bytes_used: 5_000_000,
        ..Default::default()
    };
    harness
        .record_invocation(b"x", b"y", 1, excessive, 100, 10_000)
        .unwrap();

    let violations = harness.events_of_type(&HarnessEventType::ResourceViolation);
    assert_eq!(violations.len(), 1);

    let completions = harness.events_of_type(&HarnessEventType::InvocationCompleted);
    assert_eq!(completions.len(), 1);
}

// =========================================================================
// 15. Invocation log and get_invocation
// =========================================================================

#[test]
fn harness_invocation_log_accessible() {
    let mut harness = running_harness();
    harness
        .record_invocation(b"a", b"b", 1, ok_usage(), 100, 10_000)
        .unwrap();
    harness
        .record_invocation(b"c", b"d", 2, ok_usage(), 200, 20_000)
        .unwrap();

    assert_eq!(harness.invocation_log().len(), 2);
}

#[test]
fn harness_get_invocation_by_sequence() {
    let mut harness = running_harness();
    harness
        .record_invocation(b"a", b"b", 1, ok_usage(), 100, 10_000)
        .unwrap();
    harness
        .record_invocation(b"c", b"d", 2, ok_usage(), 200, 20_000)
        .unwrap();

    let inv1 = harness.get_invocation(1).unwrap();
    assert_eq!(inv1.sequence, 1);
    assert_eq!(inv1.replay_seed, 1);

    let inv2 = harness.get_invocation(2).unwrap();
    assert_eq!(inv2.sequence, 2);
    assert_eq!(inv2.replay_seed, 2);

    assert!(harness.get_invocation(3).is_none());
    assert!(harness.get_invocation(0).is_none());
}

// =========================================================================
// 16. Replay verification
// =========================================================================

#[test]
fn harness_replay_match_same_output() {
    let mut harness = running_harness();
    let record = harness
        .record_invocation(b"input", b"output", 42, ok_usage(), 100, 10_000)
        .unwrap();
    let result = harness.verify_replay(&record, b"output", 20_000);
    match result {
        ReplayVerification::Match { sequence } => {
            assert_eq!(sequence, 1);
        }
        other => panic!("expected Match, got {other:?}"),
    }
}

#[test]
fn harness_replay_mismatch_different_output() {
    let mut harness = running_harness();
    let record = harness
        .record_invocation(b"input", b"output", 42, ok_usage(), 100, 10_000)
        .unwrap();
    let result = harness.verify_replay(&record, b"different-output", 20_000);
    match result {
        ReplayVerification::Mismatch {
            sequence,
            expected_hash,
            actual_hash,
        } => {
            assert_eq!(sequence, 1);
            assert_eq!(expected_hash, ContentHash::compute(b"output"));
            assert_eq!(actual_hash, ContentHash::compute(b"different-output"));
            assert_ne!(expected_hash, actual_hash);
        }
        other => panic!("expected Mismatch, got {other:?}"),
    }
}

#[test]
fn harness_replay_empty_output_also_works() {
    let mut harness = running_harness();
    let record = harness
        .record_invocation(b"input", b"", 42, ok_usage(), 100, 10_000)
        .unwrap();
    let result = harness.verify_replay(&record, b"", 20_000);
    assert!(matches!(result, ReplayVerification::Match { .. }));
}

#[test]
fn harness_replay_verification_emits_event() {
    let mut harness = running_harness();
    let record = harness
        .record_invocation(b"in", b"out", 1, ok_usage(), 100, 10_000)
        .unwrap();

    // Match replay
    harness.verify_replay(&record, b"out", 20_000);
    let events = harness.events_of_type(&HarnessEventType::ReplayVerification);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].fields.get("match").unwrap(), "true");
    assert_eq!(events[0].fields.get("sequence").unwrap(), "1");

    // Mismatch replay
    harness.verify_replay(&record, b"wrong", 30_000);
    let events = harness.events_of_type(&HarnessEventType::ReplayVerification);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].fields.get("match").unwrap(), "false");
}

// =========================================================================
// 17. Event emission and filtering
// =========================================================================

#[test]
fn harness_events_of_type_filters_correctly() {
    let mut harness = test_harness();
    // Generate lifecycle events
    harness
        .transition_to(CellLifecycle::Starting, 1_000)
        .unwrap();
    harness
        .transition_to(CellLifecycle::Running, 2_000)
        .unwrap();

    // Generate capability check event
    harness
        .check_capability(&SlotCapability::ReadSource, 3_000)
        .unwrap();

    // Generate invocation events
    harness
        .record_invocation(b"a", b"b", 1, ok_usage(), 100, 4_000)
        .unwrap();

    let lifecycle_events = harness.events_of_type(&HarnessEventType::LifecycleTransition);
    assert_eq!(lifecycle_events.len(), 2);

    let cap_events = harness.events_of_type(&HarnessEventType::CapabilityCheck);
    assert_eq!(cap_events.len(), 1);

    let inv_events = harness.events_of_type(&HarnessEventType::InvocationCompleted);
    assert_eq!(inv_events.len(), 1);

    let replay_events = harness.events_of_type(&HarnessEventType::ReplayVerification);
    assert!(replay_events.is_empty());
}

#[test]
fn harness_event_cell_id_matches_slot() {
    let mut harness = test_harness();
    harness
        .transition_to(CellLifecycle::Starting, 1_000)
        .unwrap();

    let event = &harness.events[0];
    assert_eq!(event.cell_id, test_slot_id());
}

#[test]
fn harness_event_timestamps_recorded() {
    let mut harness = test_harness();
    harness
        .transition_to(CellLifecycle::Starting, 42_000)
        .unwrap();
    harness
        .transition_to(CellLifecycle::Running, 99_000)
        .unwrap();

    assert_eq!(harness.events[0].timestamp_ns, 42_000);
    assert_eq!(harness.events[1].timestamp_ns, 99_000);
}

// =========================================================================
// 18. Log rotation behavior
// =========================================================================

#[test]
fn harness_invocation_log_rotation() {
    // Create a harness with a small log size to test rotation.
    // The default max_log_size is 100_000, so we use the standard constructor
    // and verify rotation behavior by filling up to the limit.
    // Since we can't set max_log_size directly from the public API,
    // we verify the log grows and that the harness doesn't panic.
    let mut harness = running_harness();
    for i in 0..50 {
        harness
            .record_invocation(
                format!("input-{i}").as_bytes(),
                format!("output-{i}").as_bytes(),
                i,
                ok_usage(),
                100,
                10_000 + i * 1000,
            )
            .unwrap();
    }
    assert_eq!(harness.invocation_log().len(), 50);
    assert_eq!(harness.invocation_count(), 50);
}

#[test]
fn harness_event_log_grows_with_operations() {
    let mut harness = test_harness();
    // Each transition emits an event
    harness
        .transition_to(CellLifecycle::Starting, 1_000)
        .unwrap();
    harness
        .transition_to(CellLifecycle::Running, 2_000)
        .unwrap();
    // Each capability check emits an event
    harness
        .check_capability(&SlotCapability::ReadSource, 3_000)
        .unwrap();
    // Each invocation emits at least one event (completion)
    harness
        .record_invocation(b"a", b"b", 1, ok_usage(), 100, 4_000)
        .unwrap();

    // 2 lifecycle + 1 capability + 1 invocation_completed = 4
    assert_eq!(harness.events.len(), 4);
}

// =========================================================================
// 19. Determinism: same inputs produce same outputs
// =========================================================================

#[test]
fn determinism_same_inputs_same_hashes() {
    let mut harness1 = running_harness();
    let mut harness2 = running_harness();

    let r1 = harness1
        .record_invocation(b"input-x", b"output-y", 42, ok_usage(), 500, 10_000)
        .unwrap();
    let r2 = harness2
        .record_invocation(b"input-x", b"output-y", 42, ok_usage(), 500, 10_000)
        .unwrap();

    assert_eq!(r1.input_hash, r2.input_hash);
    assert_eq!(r1.output_hash, r2.output_hash);
    assert_eq!(r1.sequence, r2.sequence);
}

#[test]
fn determinism_different_inputs_different_hashes() {
    let mut harness = running_harness();
    let r1 = harness
        .record_invocation(b"input-a", b"output-a", 1, ok_usage(), 100, 10_000)
        .unwrap();
    let r2 = harness
        .record_invocation(b"input-b", b"output-b", 2, ok_usage(), 100, 20_000)
        .unwrap();

    assert_ne!(r1.input_hash, r2.input_hash);
    assert_ne!(r1.output_hash, r2.output_hash);
}

#[test]
fn determinism_content_hash_is_stable() {
    let hash1 = ContentHash::compute(b"hello world");
    let hash2 = ContentHash::compute(b"hello world");
    assert_eq!(hash1, hash2);
}

#[test]
fn determinism_metrics_match_across_identical_runs() {
    let run = |_seed: u8| -> PerformanceMetrics {
        let mut harness = running_harness();
        harness
            .record_invocation(b"a", b"b", 1, ok_usage(), 1_000, 10_000)
            .unwrap();
        harness
            .record_invocation(b"c", b"d", 2, ok_usage(), 2_000, 20_000)
            .unwrap();
        harness.metrics.clone()
    };

    let m1 = run(1);
    let m2 = run(2);
    assert_eq!(m1, m2);
}

// =========================================================================
// 20. InvocationRecord — serde round-trip
// =========================================================================

#[test]
fn invocation_record_serde_round_trip() {
    let mut harness = running_harness();
    let record = harness
        .record_invocation(b"input", b"output", 42, ok_usage(), 500, 10_000)
        .unwrap();

    let json = serde_json::to_string(&record).unwrap();
    let decoded: InvocationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, decoded);
}

#[test]
fn invocation_record_with_violation_serde_round_trip() {
    let mut harness = running_harness();
    let excessive = ResourceUsage {
        heap_bytes_used: 5_000_000,
        ..Default::default()
    };
    let record = harness
        .record_invocation(b"in", b"out", 1, excessive, 100, 10_000)
        .unwrap();

    let json = serde_json::to_string(&record).unwrap();
    let decoded: InvocationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, decoded);
}

// =========================================================================
// 21. DelegateCellHarness — serde round-trip
// =========================================================================

#[test]
fn harness_serde_round_trip_empty() {
    let harness = test_harness();
    let json = serde_json::to_string(&harness).unwrap();
    let decoded: DelegateCellHarness = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.lifecycle, harness.lifecycle);
    assert_eq!(decoded.slot_id, harness.slot_id);
    assert_eq!(decoded.delegate_type, harness.delegate_type);
    assert_eq!(decoded.invocation_count(), 0);
}

#[test]
fn harness_serde_round_trip_with_invocations() {
    let mut harness = running_harness();
    harness
        .record_invocation(b"a", b"b", 1, ok_usage(), 100, 10_000)
        .unwrap();
    harness
        .record_invocation(b"c", b"d", 2, ok_usage(), 200, 20_000)
        .unwrap();

    let json = serde_json::to_string(&harness).unwrap();
    let decoded: DelegateCellHarness = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.invocation_log().len(), 2);
    assert_eq!(decoded.metrics, harness.metrics);
}

// =========================================================================
// 22. Cross-concern integration scenarios
// =========================================================================

#[test]
fn integration_full_lifecycle_with_invocations_and_replay() {
    let mut harness = test_harness();

    // Start the cell.
    harness
        .transition_to(CellLifecycle::Starting, 1_000)
        .unwrap();
    harness
        .transition_to(CellLifecycle::Running, 2_000)
        .unwrap();

    // Check capabilities.
    harness
        .check_capability(&SlotCapability::ReadSource, 3_000)
        .unwrap();
    assert!(
        harness
            .check_capability(&SlotCapability::HeapAlloc, 4_000)
            .is_err()
    );

    // Execute invocations.
    let r1 = harness
        .record_invocation(b"source-code", b"ir-output", 42, ok_usage(), 50_000, 5_000)
        .unwrap();
    assert!(matches!(r1.outcome, InvocationOutcome::Success));

    // Verify replay.
    let replay = harness.verify_replay(&r1, b"ir-output", 6_000);
    assert!(matches!(replay, ReplayVerification::Match { .. }));

    // Verify mismatch replay.
    let mismatch = harness.verify_replay(&r1, b"wrong-output", 7_000);
    assert!(matches!(mismatch, ReplayVerification::Mismatch { .. }));

    // Check metrics.
    assert_eq!(harness.metrics.total_invocations, 1);
    assert_eq!(harness.metrics.success_rate_millionths(), 1_000_000);

    // Suspend, resume, then stop.
    harness
        .transition_to(CellLifecycle::Suspended, 8_000)
        .unwrap();

    // Cannot invoke while suspended.
    assert!(
        harness
            .record_invocation(b"x", b"y", 99, ok_usage(), 100, 8_500)
            .is_err()
    );

    harness
        .transition_to(CellLifecycle::Running, 9_000)
        .unwrap();

    // Can invoke again.
    let r2 = harness
        .record_invocation(b"more-code", b"more-ir", 43, ok_usage(), 30_000, 9_500)
        .unwrap();
    assert!(matches!(r2.outcome, InvocationOutcome::Success));
    assert_eq!(harness.metrics.total_invocations, 2);

    harness
        .transition_to(CellLifecycle::Stopping, 10_000)
        .unwrap();
    harness
        .transition_to(CellLifecycle::Terminated, 11_000)
        .unwrap();

    // Count lifecycle events.
    let lifecycle_events = harness.events_of_type(&HarnessEventType::LifecycleTransition);
    // Starting, Running, Suspended, Running, Stopping, Terminated = 6
    assert_eq!(lifecycle_events.len(), 6);

    // Count all events.
    let total_events = harness.events.len();
    // 6 lifecycle + 2 capability + 2 invocation_completed + 2 replay = 12
    assert_eq!(total_events, 12);
}

#[test]
fn integration_resource_violations_affect_metrics() {
    let mut harness = running_harness();

    // 3 successes, 2 failures
    for i in 0..3 {
        harness
            .record_invocation(b"ok", b"ok", i, ok_usage(), 100, 10_000 + i * 1000)
            .unwrap();
    }
    let excessive = ResourceUsage {
        heap_bytes_used: 5_000_000,
        ..Default::default()
    };
    for i in 3..5 {
        harness
            .record_invocation(b"bad", b"bad", i, excessive.clone(), 100, 10_000 + i * 1000)
            .unwrap();
    }

    assert_eq!(harness.metrics.total_invocations, 5);
    assert_eq!(harness.metrics.successful_invocations, 3);
    assert_eq!(harness.metrics.failed_invocations, 2);
    // 600_000 = 3/5 * 1_000_000
    assert_eq!(harness.metrics.success_rate_millionths(), 600_000);
}

#[test]
fn integration_quarantine_after_violations() {
    let mut harness = running_harness();

    // Record a normal invocation.
    harness
        .record_invocation(b"a", b"b", 1, ok_usage(), 100, 10_000)
        .unwrap();

    // Record a violation.
    let excessive = ResourceUsage {
        heap_bytes_used: 5_000_000,
        ..Default::default()
    };
    let record = harness
        .record_invocation(b"c", b"d", 2, excessive, 100, 20_000)
        .unwrap();
    assert!(matches!(
        record.outcome,
        InvocationOutcome::ResourceViolation(_)
    ));

    // Quarantine after violation.
    harness
        .transition_to(CellLifecycle::Quarantined, 30_000)
        .unwrap();
    assert!(harness.lifecycle.is_terminal());

    // No more invocations possible.
    let err = harness
        .record_invocation(b"e", b"f", 3, ok_usage(), 100, 40_000)
        .unwrap_err();
    assert!(matches!(err, DelegateCellError::NotRunning { .. }));
}

#[test]
fn integration_different_delegate_types_same_behavior() {
    let types = [
        DelegateType::QuickJsBacked,
        DelegateType::WasmBacked,
        DelegateType::ExternalProcess,
    ];
    for dt in types {
        let mut harness = DelegateCellHarness::new(
            test_slot_id(),
            dt,
            test_sandbox(),
            test_authority(),
            [0xAB; 32],
        );
        harness
            .transition_to(CellLifecycle::Starting, 1_000)
            .unwrap();
        harness
            .transition_to(CellLifecycle::Running, 2_000)
            .unwrap();

        let record = harness
            .record_invocation(b"input", b"output", 42, ok_usage(), 100, 3_000)
            .unwrap();
        assert!(matches!(record.outcome, InvocationOutcome::Success));
        assert_eq!(harness.metrics.total_invocations, 1);
    }
}

#[test]
fn integration_multiple_replay_verifications_on_same_record() {
    let mut harness = running_harness();
    let record = harness
        .record_invocation(b"input", b"output", 42, ok_usage(), 100, 10_000)
        .unwrap();

    // Verify multiple times -- all should match.
    for i in 0..5 {
        let result = harness.verify_replay(&record, b"output", 20_000 + i * 1000);
        assert!(matches!(result, ReplayVerification::Match { .. }));
    }

    let replay_events = harness.events_of_type(&HarnessEventType::ReplayVerification);
    assert_eq!(replay_events.len(), 5);
}

#[test]
fn integration_epoch_is_preserved_in_invocation_record() {
    let mut harness = running_harness();
    harness.current_epoch = SecurityEpoch::from_raw(42);

    let record = harness
        .record_invocation(b"a", b"b", 1, ok_usage(), 100, 10_000)
        .unwrap();
    assert_eq!(record.epoch, SecurityEpoch::from_raw(42));
}

#[test]
fn integration_slot_id_preserved_across_operations() {
    let slot = test_slot_id_alt();
    let mut harness = DelegateCellHarness::new(
        slot.clone(),
        DelegateType::WasmBacked,
        test_sandbox(),
        test_authority(),
        [0; 32],
    );
    harness
        .transition_to(CellLifecycle::Starting, 1_000)
        .unwrap();

    // Verify slot_id is in the event.
    assert_eq!(harness.events[0].cell_id, slot);
    assert_eq!(harness.slot_id, slot);
}

#[test]
fn integration_harness_serialization_preserves_full_state() {
    let mut harness = running_harness();

    // Add some state.
    harness
        .check_capability(&SlotCapability::ReadSource, 3_000)
        .unwrap();
    harness
        .record_invocation(b"a", b"b", 1, ok_usage(), 100, 4_000)
        .unwrap();
    harness.current_epoch = SecurityEpoch::from_raw(7);

    let json = serde_json::to_string(&harness).unwrap();
    let decoded: DelegateCellHarness = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.lifecycle, CellLifecycle::Running);
    assert_eq!(decoded.invocation_count(), 1);
    assert_eq!(decoded.invocation_log().len(), 1);
    assert_eq!(decoded.current_epoch, SecurityEpoch::from_raw(7));
    assert_eq!(decoded.metrics.total_invocations, 1);
    assert_eq!(decoded.events.len(), harness.events.len());
}

#[test]
fn integration_first_violation_type_wins_priority() {
    // When multiple limits are exceeded, the first check wins.
    let sandbox = SandboxConfiguration {
        max_heap_bytes: 100,
        max_execution_ns: 100,
        max_hostcalls: 5,
        network_egress_allowed: false,
        filesystem_access_allowed: false,
    };
    let usage = ResourceUsage {
        heap_bytes_used: 200,       // exceeds
        execution_ns: 200,          // exceeds
        hostcall_count: 10,         // exceeds
        network_egress_bytes: 100,  // denied
        filesystem_read_bytes: 100, // denied
    };

    // Heap is checked first.
    let violation = usage.exceeds_limits(&sandbox).unwrap();
    assert!(matches!(violation, ResourceViolation::HeapExceeded { .. }));
}

#[test]
fn integration_suspended_to_stopping_is_valid() {
    let mut harness = running_harness();
    harness
        .transition_to(CellLifecycle::Suspended, 3_000)
        .unwrap();
    harness
        .transition_to(CellLifecycle::Stopping, 4_000)
        .unwrap();
    harness
        .transition_to(CellLifecycle::Terminated, 5_000)
        .unwrap();
    assert!(harness.lifecycle.is_terminal());
}

#[test]
fn integration_many_invocations_stress() {
    let mut harness = running_harness();
    let count = 500;
    for i in 0..count {
        harness
            .record_invocation(
                format!("in-{i}").as_bytes(),
                format!("out-{i}").as_bytes(),
                i,
                ok_usage(),
                100 + i % 50,
                10_000 + i * 100,
            )
            .unwrap();
    }
    assert_eq!(harness.invocation_count(), count);
    assert_eq!(harness.invocation_log().len(), count as usize);
    assert_eq!(harness.metrics.total_invocations, count);
    assert_eq!(harness.metrics.successful_invocations, count);
}

#[test]
fn integration_resource_violation_priority_execution_time() {
    // Only execution time exceeds.
    let sandbox = SandboxConfiguration {
        max_heap_bytes: u64::MAX,
        max_execution_ns: 100,
        max_hostcalls: u64::MAX,
        network_egress_allowed: true,
        filesystem_access_allowed: true,
    };
    let usage = ResourceUsage {
        heap_bytes_used: 0,
        execution_ns: 200,
        hostcall_count: 0,
        network_egress_bytes: 0,
        filesystem_read_bytes: 0,
    };
    let violation = usage.exceeds_limits(&sandbox).unwrap();
    match violation {
        ResourceViolation::ExecutionTimeExceeded { used_ns, limit_ns } => {
            assert_eq!(used_ns, 200);
            assert_eq!(limit_ns, 100);
        }
        other => panic!("expected ExecutionTimeExceeded, got {other}"),
    }
}

#[test]
fn integration_resource_violation_priority_hostcalls() {
    let sandbox = SandboxConfiguration {
        max_heap_bytes: u64::MAX,
        max_execution_ns: u64::MAX,
        max_hostcalls: 5,
        network_egress_allowed: true,
        filesystem_access_allowed: true,
    };
    let usage = ResourceUsage {
        hostcall_count: 10,
        ..Default::default()
    };
    let violation = usage.exceeds_limits(&sandbox).unwrap();
    assert!(matches!(
        violation,
        ResourceViolation::HostcallLimitExceeded {
            count: 10,
            limit: 5
        }
    ));
}

#[test]
fn integration_filesystem_violation_when_denied() {
    let sandbox = SandboxConfiguration {
        max_heap_bytes: u64::MAX,
        max_execution_ns: u64::MAX,
        max_hostcalls: u64::MAX,
        network_egress_allowed: true,
        filesystem_access_allowed: false,
    };
    let usage = ResourceUsage {
        filesystem_read_bytes: 42,
        ..Default::default()
    };
    let violation = usage.exceeds_limits(&sandbox).unwrap();
    assert!(matches!(
        violation,
        ResourceViolation::FilesystemAccessDenied { bytes: 42 }
    ));
}

#[test]
fn integration_zero_network_zero_filesystem_no_violation() {
    let sandbox = SandboxConfiguration {
        max_heap_bytes: u64::MAX,
        max_execution_ns: u64::MAX,
        max_hostcalls: u64::MAX,
        network_egress_allowed: false,
        filesystem_access_allowed: false,
    };
    let usage = ResourceUsage::default(); // all zeros
    assert!(usage.exceeds_limits(&sandbox).is_none());
}
