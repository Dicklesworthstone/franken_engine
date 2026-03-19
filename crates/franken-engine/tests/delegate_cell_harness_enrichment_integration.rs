#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

//! Enrichment integration tests for the delegate_cell_harness module.

use std::collections::BTreeSet;

use frankenengine_engine::delegate_cell_harness::{
    CellLifecycle, DelegateCellError, DelegateCellHarness, HarnessEventType, InvocationOutcome,
    InvocationRecord, PerformanceMetrics, ReplayVerification, ResourceUsage, ResourceViolation,
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

fn test_harness() -> DelegateCellHarness {
    DelegateCellHarness::new(
        test_slot_id(),
        DelegateType::QuickJsBacked,
        test_sandbox(),
        test_authority(),
        [0xABu8; 32],
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

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn cell_lifecycle_serde_all_variants() {
    let states = vec![
        CellLifecycle::Created,
        CellLifecycle::Starting,
        CellLifecycle::Running,
        CellLifecycle::Suspended,
        CellLifecycle::Stopping,
        CellLifecycle::Terminated,
        CellLifecycle::Quarantined,
    ];
    for s in &states {
        let json = serde_json::to_string(s).unwrap();
        let decoded: CellLifecycle = serde_json::from_str(&json).unwrap();
        assert_eq!(*s, decoded);
    }
}

#[test]
fn resource_usage_serde_roundtrip() {
    let usage = ok_usage();
    let json = serde_json::to_string(&usage).unwrap();
    let decoded: ResourceUsage = serde_json::from_str(&json).unwrap();
    assert_eq!(usage, decoded);
}

#[test]
fn resource_violation_serde_all_variants() {
    let violations = vec![
        ResourceViolation::HeapExceeded {
            used: 200,
            limit: 100,
        },
        ResourceViolation::ExecutionTimeExceeded {
            used_ns: 200,
            limit_ns: 100,
        },
        ResourceViolation::HostcallLimitExceeded {
            count: 200,
            limit: 100,
        },
        ResourceViolation::NetworkEgressDenied { bytes: 50 },
        ResourceViolation::FilesystemAccessDenied { bytes: 30 },
    ];
    for v in &violations {
        let json = serde_json::to_string(v).unwrap();
        let decoded: ResourceViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, decoded);
    }
}

#[test]
fn invocation_outcome_serde_all_variants() {
    let outcomes = vec![
        InvocationOutcome::Success,
        InvocationOutcome::Error {
            code: 42,
            message: "oops".to_string(),
        },
        InvocationOutcome::ResourceViolation(ResourceViolation::HeapExceeded { used: 2, limit: 1 }),
        InvocationOutcome::Timeout,
        InvocationOutcome::CapabilityDenied {
            capability: SlotCapability::ReadSource,
        },
    ];
    for o in &outcomes {
        let json = serde_json::to_string(o).unwrap();
        let decoded: InvocationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(*o, decoded);
    }
}

#[test]
fn invocation_record_serde_roundtrip() {
    let record = InvocationRecord {
        sequence: 1,
        input_hash: ContentHash::compute(b"input"),
        output_hash: ContentHash::compute(b"output"),
        replay_seed: 42,
        resource_usage: ok_usage(),
        outcome: InvocationOutcome::Success,
        timestamp_ns: 1_000_000,
        duration_ns: 500,
        epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&record).unwrap();
    let decoded: InvocationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(record, decoded);
}

#[test]
fn performance_metrics_serde_roundtrip() {
    let metrics = PerformanceMetrics::default();
    let json = serde_json::to_string(&metrics).unwrap();
    let decoded: PerformanceMetrics = serde_json::from_str(&json).unwrap();
    assert_eq!(metrics, decoded);
}

#[test]
fn harness_event_type_serde_all_variants() {
    let types = vec![
        HarnessEventType::LifecycleTransition,
        HarnessEventType::InvocationStarted,
        HarnessEventType::InvocationCompleted,
        HarnessEventType::CapabilityCheck,
        HarnessEventType::ResourceViolation,
        HarnessEventType::ReplayVerification,
    ];
    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        let decoded: HarnessEventType = serde_json::from_str(&json).unwrap();
        assert_eq!(*t, decoded);
    }
}

#[test]
fn replay_verification_serde_both_variants() {
    let v1 = ReplayVerification::Match { sequence: 1 };
    let v2 = ReplayVerification::Mismatch {
        sequence: 2,
        expected_hash: ContentHash::compute(b"a"),
        actual_hash: ContentHash::compute(b"b"),
    };
    for v in &[v1, v2] {
        let json = serde_json::to_string(v).unwrap();
        let decoded: ReplayVerification = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, decoded);
    }
}

#[test]
fn delegate_cell_error_serde_all_variants() {
    let errors = vec![
        DelegateCellError::InvalidTransition {
            from: CellLifecycle::Created,
            to: CellLifecycle::Running,
        },
        DelegateCellError::NotRunning {
            state: CellLifecycle::Created,
        },
        DelegateCellError::CapabilityDenied {
            capability: SlotCapability::ReadSource,
        },
        DelegateCellError::ResourceLimitExceeded(ResourceViolation::HeapExceeded {
            used: 2,
            limit: 1,
        }),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let decoded: DelegateCellError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, decoded);
    }
}

// ---------------------------------------------------------------------------
// Display distinctness
// ---------------------------------------------------------------------------

#[test]
fn cell_lifecycle_display_all_distinct() {
    let states = vec![
        CellLifecycle::Created,
        CellLifecycle::Starting,
        CellLifecycle::Running,
        CellLifecycle::Suspended,
        CellLifecycle::Stopping,
        CellLifecycle::Terminated,
        CellLifecycle::Quarantined,
    ];
    let displays: BTreeSet<String> = states.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), states.len());
}

#[test]
fn harness_event_type_display_all_distinct() {
    let types = vec![
        HarnessEventType::LifecycleTransition,
        HarnessEventType::InvocationStarted,
        HarnessEventType::InvocationCompleted,
        HarnessEventType::CapabilityCheck,
        HarnessEventType::ResourceViolation,
        HarnessEventType::ReplayVerification,
    ];
    let displays: BTreeSet<String> = types.iter().map(|t| t.to_string()).collect();
    assert_eq!(displays.len(), types.len());
}

#[test]
fn invocation_outcome_display_all_distinct() {
    let outcomes = vec![
        InvocationOutcome::Success,
        InvocationOutcome::Error {
            code: 1,
            message: "e".to_string(),
        },
        InvocationOutcome::ResourceViolation(ResourceViolation::HeapExceeded { used: 2, limit: 1 }),
        InvocationOutcome::Timeout,
        InvocationOutcome::CapabilityDenied {
            capability: SlotCapability::ReadSource,
        },
    ];
    let displays: BTreeSet<String> = outcomes.iter().map(|o| o.to_string()).collect();
    assert_eq!(displays.len(), outcomes.len());
}

#[test]
fn resource_violation_display_all_distinct() {
    let violations = vec![
        ResourceViolation::HeapExceeded {
            used: 200,
            limit: 100,
        },
        ResourceViolation::ExecutionTimeExceeded {
            used_ns: 200,
            limit_ns: 100,
        },
        ResourceViolation::HostcallLimitExceeded {
            count: 200,
            limit: 100,
        },
        ResourceViolation::NetworkEgressDenied { bytes: 50 },
        ResourceViolation::FilesystemAccessDenied { bytes: 30 },
    ];
    let displays: BTreeSet<String> = violations.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), violations.len());
}

#[test]
fn delegate_cell_error_display_all_distinct() {
    let errors = vec![
        DelegateCellError::InvalidTransition {
            from: CellLifecycle::Created,
            to: CellLifecycle::Running,
        },
        DelegateCellError::NotRunning {
            state: CellLifecycle::Suspended,
        },
        DelegateCellError::CapabilityDenied {
            capability: SlotCapability::ReadSource,
        },
        DelegateCellError::ResourceLimitExceeded(ResourceViolation::HeapExceeded {
            used: 2,
            limit: 1,
        }),
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), errors.len());
}

// ---------------------------------------------------------------------------
// CellLifecycle enrichment
// ---------------------------------------------------------------------------

#[test]
fn cell_lifecycle_can_invoke_only_running() {
    assert!(CellLifecycle::Running.can_invoke());
    for state in &[
        CellLifecycle::Created,
        CellLifecycle::Starting,
        CellLifecycle::Suspended,
        CellLifecycle::Stopping,
        CellLifecycle::Terminated,
        CellLifecycle::Quarantined,
    ] {
        assert!(!state.can_invoke());
    }
}

#[test]
fn cell_lifecycle_terminal_states() {
    assert!(CellLifecycle::Terminated.is_terminal());
    assert!(CellLifecycle::Quarantined.is_terminal());
    for state in &[
        CellLifecycle::Created,
        CellLifecycle::Starting,
        CellLifecycle::Running,
        CellLifecycle::Suspended,
        CellLifecycle::Stopping,
    ] {
        assert!(!state.is_terminal());
    }
}

#[test]
fn cell_lifecycle_valid_transitions_non_empty_for_non_terminal() {
    for state in &[
        CellLifecycle::Created,
        CellLifecycle::Starting,
        CellLifecycle::Running,
        CellLifecycle::Suspended,
        CellLifecycle::Stopping,
    ] {
        assert!(!state.valid_transitions().is_empty());
    }
}

#[test]
fn cell_lifecycle_terminal_has_no_transitions() {
    assert!(CellLifecycle::Terminated.valid_transitions().is_empty());
    assert!(CellLifecycle::Quarantined.valid_transitions().is_empty());
}

// ---------------------------------------------------------------------------
// ResourceUsage enrichment
// ---------------------------------------------------------------------------

#[test]
fn resource_usage_default_is_within_any_reasonable_sandbox() {
    let usage = ResourceUsage::default();
    let sandbox = test_sandbox();
    assert!(usage.exceeds_limits(&sandbox).is_none());
}

#[test]
fn resource_usage_network_egress_allowed_sandbox() {
    let mut sandbox = test_sandbox();
    sandbox.network_egress_allowed = true;
    let usage = ResourceUsage {
        network_egress_bytes: 100,
        ..Default::default()
    };
    assert!(usage.exceeds_limits(&sandbox).is_none());
}

#[test]
fn resource_usage_filesystem_allowed_sandbox() {
    let mut sandbox = test_sandbox();
    sandbox.filesystem_access_allowed = true;
    let usage = ResourceUsage {
        filesystem_read_bytes: 100,
        ..Default::default()
    };
    assert!(usage.exceeds_limits(&sandbox).is_none());
}

// ---------------------------------------------------------------------------
// PerformanceMetrics enrichment
// ---------------------------------------------------------------------------

#[test]
fn performance_metrics_default_values() {
    let metrics = PerformanceMetrics::default();
    assert_eq!(metrics.total_invocations, 0);
    assert_eq!(metrics.successful_invocations, 0);
    assert_eq!(metrics.failed_invocations, 0);
    assert_eq!(metrics.total_duration_ns, 0);
    assert_eq!(metrics.avg_duration_millionths(), 0);
    assert_eq!(metrics.success_rate_millionths(), 0);
}

#[test]
fn performance_metrics_record_updates_counts() {
    let mut metrics = PerformanceMetrics::default();
    let record = InvocationRecord {
        sequence: 1,
        input_hash: ContentHash::compute(b"i"),
        output_hash: ContentHash::compute(b"o"),
        replay_seed: 1,
        resource_usage: ok_usage(),
        outcome: InvocationOutcome::Success,
        timestamp_ns: 1000,
        duration_ns: 500,
        epoch: SecurityEpoch::from_raw(1),
    };
    metrics.record(&record);
    assert_eq!(metrics.total_invocations, 1);
    assert_eq!(metrics.successful_invocations, 1);
    assert_eq!(metrics.failed_invocations, 0);
    assert_eq!(metrics.min_duration_ns, 500);
    assert_eq!(metrics.max_duration_ns, 500);
}

#[test]
fn performance_metrics_success_rate_100_percent() {
    let mut metrics = PerformanceMetrics::default();
    let record = InvocationRecord {
        sequence: 1,
        input_hash: ContentHash::compute(b"i"),
        output_hash: ContentHash::compute(b"o"),
        replay_seed: 1,
        resource_usage: ok_usage(),
        outcome: InvocationOutcome::Success,
        timestamp_ns: 1000,
        duration_ns: 500,
        epoch: SecurityEpoch::from_raw(1),
    };
    metrics.record(&record);
    assert_eq!(metrics.success_rate_millionths(), 1_000_000);
}

#[test]
fn performance_metrics_tracks_min_max_duration() {
    let mut metrics = PerformanceMetrics::default();
    for (seq, dur) in [(1, 100), (2, 500), (3, 200)] {
        let record = InvocationRecord {
            sequence: seq,
            input_hash: ContentHash::compute(b"i"),
            output_hash: ContentHash::compute(b"o"),
            replay_seed: seq,
            resource_usage: ok_usage(),
            outcome: InvocationOutcome::Success,
            timestamp_ns: 1000 * seq,
            duration_ns: dur,
            epoch: SecurityEpoch::from_raw(1),
        };
        metrics.record(&record);
    }
    assert_eq!(metrics.min_duration_ns, 100);
    assert_eq!(metrics.max_duration_ns, 500);
}

// ---------------------------------------------------------------------------
// DelegateCellHarness enrichment
// ---------------------------------------------------------------------------

#[test]
fn harness_initial_state_is_created() {
    let harness = test_harness();
    assert_eq!(harness.lifecycle, CellLifecycle::Created);
    assert_eq!(harness.invocation_count(), 0);
    assert!(harness.events.is_empty());
}

#[test]
fn harness_transition_created_to_starting_to_running() {
    let harness = running_harness();
    assert_eq!(harness.lifecycle, CellLifecycle::Running);
}

#[test]
fn harness_invalid_transition_returns_error() {
    let mut harness = test_harness();
    let err = harness
        .transition_to(CellLifecycle::Running, 1000)
        .unwrap_err();
    assert!(matches!(err, DelegateCellError::InvalidTransition { .. }));
}

#[test]
fn harness_transition_emits_lifecycle_event() {
    let mut harness = test_harness();
    harness
        .transition_to(CellLifecycle::Starting, 1000)
        .unwrap();
    let events = harness.events_of_type(&HarnessEventType::LifecycleTransition);
    assert_eq!(events.len(), 1);
    assert!(events[0].fields.contains_key("from"));
    assert!(events[0].fields.contains_key("to"));
}

// ---------------------------------------------------------------------------
// Capability checking
// ---------------------------------------------------------------------------

#[test]
fn harness_check_permitted_capability_succeeds() {
    let mut harness = test_harness();
    harness
        .check_capability(&SlotCapability::ReadSource, 1000)
        .unwrap();
}

#[test]
fn harness_check_denied_capability_fails() {
    let mut harness = test_harness();
    let err = harness
        .check_capability(&SlotCapability::HeapAlloc, 1000)
        .unwrap_err();
    assert!(matches!(err, DelegateCellError::CapabilityDenied { .. }));
}

#[test]
fn harness_capability_check_emits_event() {
    let mut harness = test_harness();
    let _ = harness.check_capability(&SlotCapability::ReadSource, 1000);
    let events = harness.events_of_type(&HarnessEventType::CapabilityCheck);
    assert_eq!(events.len(), 1);
}

// ---------------------------------------------------------------------------
// Invocation recording
// ---------------------------------------------------------------------------

#[test]
fn harness_record_invocation_not_running_fails() {
    let mut harness = test_harness(); // Created state
    let err = harness
        .record_invocation(b"in", b"out", 1, ok_usage(), 100, 1000)
        .unwrap_err();
    assert!(matches!(err, DelegateCellError::NotRunning { .. }));
}

#[test]
fn harness_record_invocation_success() {
    let mut harness = running_harness();
    let record = harness
        .record_invocation(b"input", b"output", 42, ok_usage(), 500, 5000)
        .unwrap();
    assert_eq!(record.sequence, 1);
    assert_eq!(record.replay_seed, 42);
    assert!(matches!(record.outcome, InvocationOutcome::Success));
}

#[test]
fn harness_record_invocation_with_resource_violation() {
    let mut harness = running_harness();
    let usage = ResourceUsage {
        heap_bytes_used: 2_000_000, // exceeds limit
        ..Default::default()
    };
    let record = harness
        .record_invocation(b"in", b"out", 1, usage, 100, 1000)
        .unwrap();
    assert!(matches!(
        record.outcome,
        InvocationOutcome::ResourceViolation(_)
    ));
}

#[test]
fn harness_invocation_count_increments() {
    let mut harness = running_harness();
    for i in 0..5 {
        harness
            .record_invocation(b"in", b"out", i, ok_usage(), 100, 1000 * (i + 1))
            .unwrap();
    }
    assert_eq!(harness.invocation_count(), 5);
}

#[test]
fn harness_invocation_log_populated() {
    let mut harness = running_harness();
    harness
        .record_invocation(b"in", b"out", 1, ok_usage(), 100, 1000)
        .unwrap();
    assert_eq!(harness.invocation_log().len(), 1);
}

#[test]
fn harness_get_invocation_by_sequence() {
    let mut harness = running_harness();
    harness
        .record_invocation(b"in1", b"out1", 1, ok_usage(), 100, 1000)
        .unwrap();
    harness
        .record_invocation(b"in2", b"out2", 2, ok_usage(), 200, 2000)
        .unwrap();
    let record = harness.get_invocation(2).unwrap();
    assert_eq!(record.sequence, 2);
    assert!(harness.get_invocation(99).is_none());
}

// ---------------------------------------------------------------------------
// Replay verification
// ---------------------------------------------------------------------------

#[test]
fn harness_replay_match() {
    let mut harness = running_harness();
    let record = harness
        .record_invocation(b"in", b"out", 1, ok_usage(), 100, 1000)
        .unwrap();
    let result = harness.verify_replay(&record, b"out", 2000);
    assert!(matches!(result, ReplayVerification::Match { sequence: 1 }));
}

#[test]
fn harness_replay_mismatch() {
    let mut harness = running_harness();
    let record = harness
        .record_invocation(b"in", b"out", 1, ok_usage(), 100, 1000)
        .unwrap();
    let result = harness.verify_replay(&record, b"different", 2000);
    assert!(matches!(result, ReplayVerification::Mismatch { .. }));
}

#[test]
fn harness_replay_emits_verification_event() {
    let mut harness = running_harness();
    let record = harness
        .record_invocation(b"in", b"out", 1, ok_usage(), 100, 1000)
        .unwrap();
    harness.verify_replay(&record, b"out", 2000);
    let events = harness.events_of_type(&HarnessEventType::ReplayVerification);
    assert_eq!(events.len(), 1);
}

// ---------------------------------------------------------------------------
// DelegateCellHarness from_manifest
// ---------------------------------------------------------------------------

#[test]
fn harness_from_manifest_has_correct_initial_state() {
    let manifest = DelegateCellManifest {
        manifest_id: frankenengine_engine::engine_object_id::EngineObjectId([0; 32]),
        schema_version: frankenengine_engine::self_replacement::SchemaVersion::V1,
        slot_id: test_slot_id(),
        delegate_type: DelegateType::QuickJsBacked,
        sandbox: test_sandbox(),
        capability_envelope: test_authority(),
        monitoring_hooks: Vec::new(),
        expected_behavior_hash: [0xCDu8; 32],
        zone: "test".to_string(),
        signature: frankenengine_engine::signature_preimage::Signature {
            lower: [0; 32],
            upper: [0; 32],
        },
    };
    let harness = DelegateCellHarness::from_manifest(&manifest);
    assert_eq!(harness.lifecycle, CellLifecycle::Created);
    assert_eq!(harness.delegate_type, DelegateType::QuickJsBacked);
    assert_eq!(harness.expected_behavior_hash, [0xCDu8; 32]);
}

// ---------------------------------------------------------------------------
// Full lifecycle enrichment
// ---------------------------------------------------------------------------

#[test]
fn harness_full_lifecycle_created_to_terminated() {
    let mut harness = test_harness();
    harness.transition_to(CellLifecycle::Starting, 100).unwrap();
    harness.transition_to(CellLifecycle::Running, 200).unwrap();
    harness
        .record_invocation(b"in", b"out", 1, ok_usage(), 100, 300)
        .unwrap();
    harness.transition_to(CellLifecycle::Stopping, 400).unwrap();
    harness
        .transition_to(CellLifecycle::Terminated, 500)
        .unwrap();
    assert!(harness.lifecycle.is_terminal());
    assert_eq!(harness.invocation_count(), 1);
}

#[test]
fn harness_quarantine_from_running() {
    let mut harness = running_harness();
    harness
        .transition_to(CellLifecycle::Quarantined, 5000)
        .unwrap();
    assert!(harness.lifecycle.is_terminal());
}

// ---------------------------------------------------------------------------
// Deterministic: same inputs produce same output hashes
// ---------------------------------------------------------------------------

#[test]
fn harness_invocation_deterministic_50_times() {
    let mut hashes = BTreeSet::new();
    for _ in 0..50 {
        let mut harness = running_harness();
        let record = harness
            .record_invocation(b"input_data", b"output_data", 42, ok_usage(), 500, 5000)
            .unwrap();
        hashes.insert(format!("{:?}", record.output_hash));
    }
    assert_eq!(hashes.len(), 1, "output hashes should be deterministic");
}
