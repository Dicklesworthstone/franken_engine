#![forbid(unsafe_code)]

//! Integration tests for the `remote_capability_gate` module.
//!
//! Exercises the public API from outside the crate, covering:
//! - `RemoteOperationGate` permit/deny decisions for each profile
//! - Audit event emission (permitted and denied)
//! - Counter tracking (per-operation-type and totals)
//! - Drain semantics (events cleared after drain)
//! - Endpoint sanitization (credentials stripped, clean URLs preserved)
//! - `MockRemoteTransport` recording and failure injection
//! - Display impls for all public types
//! - Serde round-trips for all serializable types
//! - Deterministic replay: same inputs produce identical audit trails
//! - End-to-end workflows combining gate + mock transport

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

use frankenengine_engine::capability::{CapabilityProfile, ProfileKind, RuntimeCapability};
use frankenengine_engine::remote_capability_gate::{
    MockRemoteTransport, RemoteCapabilityDenied, RemoteGateEvent, RemoteOperationGate,
    RemoteOperationType, RemoteTransport, RemoteTransportError,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn remote_profile() -> CapabilityProfile {
    CapabilityProfile::remote()
}

fn compute_only_profile() -> CapabilityProfile {
    CapabilityProfile::compute_only()
}

fn engine_core_profile() -> CapabilityProfile {
    CapabilityProfile::engine_core()
}

fn policy_profile() -> CapabilityProfile {
    CapabilityProfile::policy()
}

fn full_profile() -> CapabilityProfile {
    CapabilityProfile::full()
}

// =========================================================================
// Section 1: RemoteOperationType Display
// =========================================================================

#[test]
fn operation_type_display_all_variants() {
    assert_eq!(RemoteOperationType::HttpRequest.to_string(), "http_request");
    assert_eq!(RemoteOperationType::GrpcCall.to_string(), "grpc_call");
    assert_eq!(
        RemoteOperationType::DnsResolution.to_string(),
        "dns_resolution"
    );
    assert_eq!(
        RemoteOperationType::DistributedStateMutation.to_string(),
        "distributed_state_mutation"
    );
    assert_eq!(
        RemoteOperationType::LeaseRenewal.to_string(),
        "lease_renewal"
    );
    assert_eq!(RemoteOperationType::RemoteIpc.to_string(), "remote_ipc");
}

#[test]
fn operation_type_ord() {
    // RemoteOperationType derives Ord; verify ordering is consistent.
    let ops = vec![
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall,
        RemoteOperationType::DnsResolution,
        RemoteOperationType::DistributedStateMutation,
        RemoteOperationType::LeaseRenewal,
        RemoteOperationType::RemoteIpc,
    ];
    let mut sorted = ops.clone();
    sorted.sort();
    // Just verify it doesn't panic and produces a deterministic result.
    let mut sorted2 = ops;
    sorted2.sort();
    assert_eq!(sorted, sorted2);
}

// =========================================================================
// Section 2: RemoteOperationGate — permit decisions
// =========================================================================

#[test]
fn gate_epoch_matches_constructor() {
    let epoch = SecurityEpoch::from_raw(100);
    let gate = RemoteOperationGate::new(epoch);
    assert_eq!(gate.epoch(), epoch);
    assert_eq!(gate.epoch().as_u64(), 100);
}

#[test]
fn remote_profile_permits_http_request() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "sync",
        "https://example.com/api",
        "trace-1",
        100,
    )
    .unwrap();
}

#[test]
fn remote_profile_permits_grpc_call() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::GrpcCall,
        "rpc",
        "grpc://node:50051",
        "trace-2",
        200,
    )
    .unwrap();
}

#[test]
fn remote_profile_permits_dns_resolution() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::DnsResolution,
        "resolver",
        "dns://8.8.8.8",
        "trace-3",
        300,
    )
    .unwrap();
}

#[test]
fn remote_profile_permits_distributed_state_mutation() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::DistributedStateMutation,
        "cluster",
        "internal://state-sync",
        "trace-4",
        400,
    )
    .unwrap();
}

#[test]
fn remote_profile_permits_lease_renewal() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::LeaseRenewal,
        "lease-mgr",
        "internal://lease-service",
        "trace-5",
        500,
    )
    .unwrap();
}

#[test]
fn remote_profile_permits_remote_ipc() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::RemoteIpc,
        "ipc-bridge",
        "ipc://remote-host",
        "trace-6",
        600,
    )
    .unwrap();
}

#[test]
fn full_profile_permits_all_operation_types() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let ops = vec![
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall,
        RemoteOperationType::DnsResolution,
        RemoteOperationType::DistributedStateMutation,
        RemoteOperationType::LeaseRenewal,
        RemoteOperationType::RemoteIpc,
    ];
    for op in ops {
        let op_str = op.to_string();
        gate.check(&full_profile(), op, "test", "endpoint", "t", 0)
            .unwrap_or_else(|_| panic!("full profile should permit {op_str}"));
    }
    assert_eq!(gate.total_permitted(), 6);
    assert_eq!(gate.total_denied(), 0);
}

// =========================================================================
// Section 3: RemoteOperationGate — deny decisions
// =========================================================================

#[test]
fn compute_only_denies_all_operations() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let ops = vec![
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall,
        RemoteOperationType::DnsResolution,
        RemoteOperationType::DistributedStateMutation,
        RemoteOperationType::LeaseRenewal,
        RemoteOperationType::RemoteIpc,
    ];
    for op in ops {
        let op_str = op.to_string();
        let err = gate
            .check(&compute_only_profile(), op, "compute", "endpoint", "t", 0)
            .unwrap_err();
        assert_eq!(
            err.held_profile,
            ProfileKind::ComputeOnly,
            "for op {op_str}"
        );
    }
    assert_eq!(gate.total_denied(), 6);
    assert_eq!(gate.total_permitted(), 0);
}

#[test]
fn engine_core_denies_all_remote_operations() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let ops = vec![
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall,
        RemoteOperationType::DnsResolution,
        RemoteOperationType::DistributedStateMutation,
        RemoteOperationType::LeaseRenewal,
        RemoteOperationType::RemoteIpc,
    ];
    for op in ops {
        assert!(
            gate.check(&engine_core_profile(), op.clone(), "engine", "ep", "t", 0)
                .is_err(),
            "engine core should deny {op}"
        );
    }
}

#[test]
fn policy_profile_denies_all_remote_operations() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let ops = vec![
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall,
        RemoteOperationType::DnsResolution,
        RemoteOperationType::DistributedStateMutation,
        RemoteOperationType::LeaseRenewal,
        RemoteOperationType::RemoteIpc,
    ];
    for op in ops {
        assert!(
            gate.check(&policy_profile(), op.clone(), "policy", "ep", "t", 0)
                .is_err(),
            "policy should deny {op}"
        );
    }
}

#[test]
fn denied_error_contains_correct_fields() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let err = gate
        .check(
            &compute_only_profile(),
            RemoteOperationType::HttpRequest,
            "my-component",
            "https://evil.example.com",
            "trace-deny-1",
            777,
        )
        .unwrap_err();

    assert_eq!(err.operation, RemoteOperationType::HttpRequest);
    assert_eq!(err.component, "my-component");
    assert_eq!(err.held_profile, ProfileKind::ComputeOnly);
    assert_eq!(err.trace_id, "trace-deny-1");
    assert!(!err.required_capabilities.is_empty());
    assert!(
        err.required_capabilities
            .contains(&RuntimeCapability::NetworkEgress)
    );
}

// =========================================================================
// Section 4: Audit event emission
// =========================================================================

#[test]
fn permitted_check_emits_event() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "sync",
        "https://example.com",
        "trace-evt-1",
        100,
    )
    .unwrap();

    let events = gate.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "permitted");
    assert_eq!(events[0].operation_type, "http_request");
    assert_eq!(events[0].trace_id, "trace-evt-1");
    assert_eq!(events[0].component, "sync");
    assert_eq!(events[0].epoch_id, 42);
    assert_eq!(events[0].timestamp_ticks, 100);
    assert_eq!(events[0].held_profile, "RemoteCaps");
}

#[test]
fn denied_check_emits_event() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let _ = gate.check(
        &compute_only_profile(),
        RemoteOperationType::GrpcCall,
        "bad-component",
        "grpc://host",
        "trace-evt-2",
        200,
    );

    let events = gate.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "denied");
    assert_eq!(events[0].operation_type, "grpc_call");
    assert_eq!(events[0].trace_id, "trace-evt-2");
    assert_eq!(events[0].component, "bad-component");
    assert_eq!(events[0].held_profile, "ComputeOnlyCaps");
}

#[test]
fn multiple_checks_accumulate_events() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "s",
        "e",
        "t1",
        0,
    )
    .unwrap();
    gate.check(
        &remote_profile(),
        RemoteOperationType::GrpcCall,
        "s",
        "e",
        "t2",
        0,
    )
    .unwrap();
    let _ = gate.check(
        &compute_only_profile(),
        RemoteOperationType::DnsResolution,
        "c",
        "e",
        "t3",
        0,
    );

    let events = gate.drain_events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].outcome, "permitted");
    assert_eq!(events[1].outcome, "permitted");
    assert_eq!(events[2].outcome, "denied");
}

#[test]
fn drain_events_clears_list() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "s",
        "e",
        "t",
        0,
    )
    .unwrap();

    let e1 = gate.drain_events();
    assert_eq!(e1.len(), 1);

    let e2 = gate.drain_events();
    assert!(e2.is_empty());
}

// =========================================================================
// Section 5: Counter tracking
// =========================================================================

#[test]
fn counters_track_permits_by_operation_type() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    for _ in 0..3 {
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "s",
            "e",
            "t",
            0,
        )
        .unwrap();
    }
    gate.check(
        &remote_profile(),
        RemoteOperationType::GrpcCall,
        "s",
        "e",
        "t",
        0,
    )
    .unwrap();

    assert_eq!(gate.total_permitted(), 4);
    assert_eq!(gate.permitted_counts().get("http_request"), Some(&3));
    assert_eq!(gate.permitted_counts().get("grpc_call"), Some(&1));
}

#[test]
fn counters_track_denials_by_operation_type() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    for _ in 0..2 {
        let _ = gate.check(
            &compute_only_profile(),
            RemoteOperationType::DnsResolution,
            "c",
            "e",
            "t",
            0,
        );
    }
    let _ = gate.check(
        &compute_only_profile(),
        RemoteOperationType::RemoteIpc,
        "c",
        "e",
        "t",
        0,
    );

    assert_eq!(gate.total_denied(), 3);
    assert_eq!(gate.denied_counts().get("dns_resolution"), Some(&2));
    assert_eq!(gate.denied_counts().get("remote_ipc"), Some(&1));
}

#[test]
fn counters_mixed_permits_and_denials() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "s",
        "e",
        "t1",
        0,
    )
    .unwrap();
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "s",
        "e",
        "t2",
        0,
    )
    .unwrap();
    let _ = gate.check(
        &compute_only_profile(),
        RemoteOperationType::GrpcCall,
        "c",
        "e",
        "t3",
        0,
    );

    assert_eq!(gate.total_permitted(), 2);
    assert_eq!(gate.total_denied(), 1);
    assert_eq!(gate.permitted_counts().get("http_request"), Some(&2));
    assert_eq!(gate.denied_counts().get("grpc_call"), Some(&1));
}

#[test]
fn counters_survive_drain() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "s",
        "e",
        "t",
        0,
    )
    .unwrap();
    gate.drain_events();

    // Counters should still be there after drain.
    assert_eq!(gate.total_permitted(), 1);
    assert_eq!(gate.permitted_counts().get("http_request"), Some(&1));
}

// =========================================================================
// Section 6: Endpoint sanitization
// =========================================================================

#[test]
fn sanitize_strips_credentials_from_url() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "s",
        "https://user:password@example.com/path",
        "t-san",
        0,
    )
    .unwrap();

    let events = gate.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].remote_endpoint, "https://***@example.com/path");
}

#[test]
fn sanitize_preserves_clean_url() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "s",
        "https://example.com/path",
        "t-clean",
        0,
    )
    .unwrap();

    let events = gate.drain_events();
    assert_eq!(events[0].remote_endpoint, "https://example.com/path");
}

#[test]
fn sanitize_preserves_non_url_endpoint() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::RemoteIpc,
        "s",
        "some-endpoint",
        "t-non-url",
        0,
    )
    .unwrap();

    let events = gate.drain_events();
    assert_eq!(events[0].remote_endpoint, "some-endpoint");
}

#[test]
fn sanitize_strips_userinfo_with_at_in_path() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "s",
        "https://admin:secret123@host.example.com:8443/api/v2",
        "t-complex",
        0,
    )
    .unwrap();

    let events = gate.drain_events();
    assert_eq!(
        events[0].remote_endpoint,
        "https://***@host.example.com:8443/api/v2"
    );
}

// =========================================================================
// Section 7: MockRemoteTransport
// =========================================================================

#[test]
fn mock_transport_records_operation() {
    let mut transport = MockRemoteTransport {
        response: b"response-body".to_vec(),
        ..Default::default()
    };

    let result = transport
        .execute(
            &RemoteOperationType::HttpRequest,
            "https://example.com/api",
            b"request-body",
        )
        .unwrap();

    assert_eq!(result, b"response-body");
    assert_eq!(transport.recorded.len(), 1);
    assert_eq!(
        transport.recorded[0].operation,
        RemoteOperationType::HttpRequest
    );
    assert_eq!(transport.recorded[0].endpoint, "https://example.com/api");
    assert_eq!(transport.recorded[0].payload, b"request-body");
}

#[test]
fn mock_transport_records_multiple_operations() {
    let mut transport = MockRemoteTransport {
        response: b"ok".to_vec(),
        ..Default::default()
    };

    transport
        .execute(&RemoteOperationType::HttpRequest, "ep1", b"p1")
        .unwrap();
    transport
        .execute(&RemoteOperationType::GrpcCall, "ep2", b"p2")
        .unwrap();
    transport
        .execute(&RemoteOperationType::DnsResolution, "ep3", b"p3")
        .unwrap();

    assert_eq!(transport.recorded.len(), 3);
    assert_eq!(
        transport.recorded[0].operation,
        RemoteOperationType::HttpRequest
    );
    assert_eq!(
        transport.recorded[1].operation,
        RemoteOperationType::GrpcCall
    );
    assert_eq!(
        transport.recorded[2].operation,
        RemoteOperationType::DnsResolution
    );
}

#[test]
fn mock_transport_fails_with_configured_error() {
    let mut transport = MockRemoteTransport {
        fail_with: Some(RemoteTransportError::Timeout {
            endpoint: "slow-host".to_string(),
            duration_ms: 5000,
        }),
        ..Default::default()
    };

    let err = transport
        .execute(&RemoteOperationType::HttpRequest, "slow-host", b"")
        .unwrap_err();
    assert!(matches!(err, RemoteTransportError::Timeout { .. }));

    // Still records the operation even on failure.
    assert_eq!(transport.recorded.len(), 1);
}

#[test]
fn mock_transport_connection_failed_error() {
    let mut transport = MockRemoteTransport {
        fail_with: Some(RemoteTransportError::ConnectionFailed {
            endpoint: "bad-host".to_string(),
            reason: "refused".to_string(),
        }),
        ..Default::default()
    };

    let err = transport
        .execute(&RemoteOperationType::GrpcCall, "bad-host", b"")
        .unwrap_err();
    if let RemoteTransportError::ConnectionFailed { endpoint, reason } = err {
        assert_eq!(endpoint, "bad-host");
        assert_eq!(reason, "refused");
    } else {
        panic!("expected ConnectionFailed");
    }
}

#[test]
fn mock_transport_remote_error() {
    let mut transport = MockRemoteTransport {
        fail_with: Some(RemoteTransportError::RemoteError {
            status: 503,
            message: "service unavailable".to_string(),
        }),
        ..Default::default()
    };

    let err = transport
        .execute(&RemoteOperationType::HttpRequest, "ep", b"")
        .unwrap_err();
    if let RemoteTransportError::RemoteError { status, message } = err {
        assert_eq!(status, 503);
        assert_eq!(message, "service unavailable");
    } else {
        panic!("expected RemoteError");
    }
}

#[test]
fn mock_transport_capability_denied_error() {
    let denied = RemoteCapabilityDenied {
        operation: RemoteOperationType::HttpRequest,
        component: "test".to_string(),
        held_profile: ProfileKind::ComputeOnly,
        required_capabilities: vec![RuntimeCapability::NetworkEgress],
        trace_id: "t".to_string(),
    };
    let mut transport = MockRemoteTransport {
        fail_with: Some(RemoteTransportError::CapabilityDenied(denied.clone())),
        ..Default::default()
    };

    let err = transport
        .execute(&RemoteOperationType::HttpRequest, "ep", b"")
        .unwrap_err();
    if let RemoteTransportError::CapabilityDenied(d) = err {
        assert_eq!(d, denied);
    } else {
        panic!("expected CapabilityDenied");
    }
}

#[test]
fn mock_transport_default_has_empty_response() {
    let mut transport = MockRemoteTransport::default();
    let result = transport
        .execute(&RemoteOperationType::HttpRequest, "ep", b"")
        .unwrap();
    assert!(result.is_empty());
}

// =========================================================================
// Section 8: Display impls
// =========================================================================

#[test]
fn remote_capability_denied_display() {
    let denied = RemoteCapabilityDenied {
        operation: RemoteOperationType::HttpRequest,
        component: "sync-service".to_string(),
        held_profile: ProfileKind::ComputeOnly,
        required_capabilities: vec![RuntimeCapability::NetworkEgress],
        trace_id: "trace-display-1".to_string(),
    };
    let msg = denied.to_string();
    assert!(msg.contains("http_request"));
    assert!(msg.contains("RemoteCaps"));
    assert!(msg.contains("ComputeOnlyCaps"));
    assert!(msg.contains("sync-service"));
    assert!(msg.contains("trace-display-1"));
}

#[test]
fn remote_transport_error_display_connection_failed() {
    let err = RemoteTransportError::ConnectionFailed {
        endpoint: "host.example.com".to_string(),
        reason: "refused".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("host.example.com"));
    assert!(msg.contains("refused"));
}

#[test]
fn remote_transport_error_display_remote_error() {
    let err = RemoteTransportError::RemoteError {
        status: 500,
        message: "internal server error".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("500"));
    assert!(msg.contains("internal server error"));
}

#[test]
fn remote_transport_error_display_timeout() {
    let err = RemoteTransportError::Timeout {
        endpoint: "slow-host".to_string(),
        duration_ms: 30000,
    };
    let msg = err.to_string();
    assert!(msg.contains("slow-host"));
    assert!(msg.contains("30000"));
}

#[test]
fn remote_transport_error_display_capability_denied() {
    let denied = RemoteCapabilityDenied {
        operation: RemoteOperationType::GrpcCall,
        component: "rpc".to_string(),
        held_profile: ProfileKind::EngineCore,
        required_capabilities: vec![RuntimeCapability::NetworkEgress],
        trace_id: "t-cap".to_string(),
    };
    let err = RemoteTransportError::CapabilityDenied(denied);
    let msg = err.to_string();
    assert!(msg.contains("grpc_call"));
    assert!(msg.contains("EngineCoreCaps"));
}

// =========================================================================
// Section 9: Serde round-trips
// =========================================================================

#[test]
fn remote_operation_type_serde_round_trip() {
    let ops = vec![
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall,
        RemoteOperationType::DnsResolution,
        RemoteOperationType::DistributedStateMutation,
        RemoteOperationType::LeaseRenewal,
        RemoteOperationType::RemoteIpc,
    ];
    for op in &ops {
        let json = serde_json::to_string(op).expect("serialize");
        let restored: RemoteOperationType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*op, restored);
    }
}

#[test]
fn remote_capability_denied_serde_round_trip() {
    let denied = RemoteCapabilityDenied {
        operation: RemoteOperationType::HttpRequest,
        component: "test".to_string(),
        held_profile: ProfileKind::ComputeOnly,
        required_capabilities: vec![
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::LeaseManagement,
        ],
        trace_id: "trace-serde-1".to_string(),
    };
    let json = serde_json::to_string(&denied).expect("serialize");
    let restored: RemoteCapabilityDenied = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(denied, restored);
}

#[test]
fn remote_gate_event_serde_round_trip() {
    let event = RemoteGateEvent {
        trace_id: "t-serde".to_string(),
        component: "c".to_string(),
        operation_type: "http_request".to_string(),
        remote_endpoint: "https://example.com".to_string(),
        epoch_id: 42,
        timestamp_ticks: 1000,
        outcome: "permitted".to_string(),
        held_profile: "RemoteCaps".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: RemoteGateEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn remote_transport_error_all_variants_serde_round_trip() {
    let denied = RemoteCapabilityDenied {
        operation: RemoteOperationType::DnsResolution,
        component: "resolver".to_string(),
        held_profile: ProfileKind::Policy,
        required_capabilities: vec![RuntimeCapability::NetworkEgress],
        trace_id: "t".to_string(),
    };
    let errors = vec![
        RemoteTransportError::ConnectionFailed {
            endpoint: "host".to_string(),
            reason: "refused".to_string(),
        },
        RemoteTransportError::RemoteError {
            status: 404,
            message: "not found".to_string(),
        },
        RemoteTransportError::Timeout {
            endpoint: "slow".to_string(),
            duration_ms: 10000,
        },
        RemoteTransportError::CapabilityDenied(denied),
    ];

    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let restored: RemoteTransportError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, restored);
    }
}

// =========================================================================
// Section 10: Deterministic replay
// =========================================================================

#[test]
fn deterministic_gate_check_produces_same_events() {
    let run = || {
        let mut gate = RemoteOperationGate::new(test_epoch());
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "sync",
            "https://example.com",
            "trace-replay",
            999,
        )
        .unwrap();
        let _ = gate.check(
            &compute_only_profile(),
            RemoteOperationType::GrpcCall,
            "compute",
            "grpc://host",
            "trace-replay-2",
            1000,
        );
        gate.drain_events()
    };

    let events1 = run();
    let events2 = run();
    assert_eq!(events1, events2);

    // Serde should also be identical.
    let json1 = serde_json::to_string(&events1).unwrap();
    let json2 = serde_json::to_string(&events2).unwrap();
    assert_eq!(json1, json2);
}

#[test]
fn deterministic_counters_across_runs() {
    let run = || {
        let mut gate = RemoteOperationGate::new(test_epoch());
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "s",
            "e",
            "t",
            0,
        )
        .unwrap();
        let _ = gate.check(
            &compute_only_profile(),
            RemoteOperationType::GrpcCall,
            "c",
            "e",
            "t",
            0,
        );
        (
            gate.total_permitted(),
            gate.total_denied(),
            gate.permitted_counts().clone(),
            gate.denied_counts().clone(),
        )
    };

    let r1 = run();
    let r2 = run();
    assert_eq!(r1, r2);
}

// =========================================================================
// Section 11: End-to-end gate + transport workflow
// =========================================================================

#[test]
fn gate_then_transport_permitted_workflow() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let mut transport = MockRemoteTransport {
        response: b"response-data".to_vec(),
        ..Default::default()
    };

    // Step 1: Check capability.
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "http-client",
        "https://api.example.com/data",
        "trace-e2e-1",
        100,
    )
    .unwrap();

    // Step 2: Execute transport (gate permitted).
    let result = transport
        .execute(
            &RemoteOperationType::HttpRequest,
            "https://api.example.com/data",
            b"GET /data",
        )
        .unwrap();

    assert_eq!(result, b"response-data");
    assert_eq!(gate.total_permitted(), 1);
    assert_eq!(transport.recorded.len(), 1);
}

#[test]
fn gate_denied_prevents_transport() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let transport = MockRemoteTransport {
        response: b"should-not-reach".to_vec(),
        ..Default::default()
    };

    // Step 1: Check capability (denied).
    let err = gate
        .check(
            &compute_only_profile(),
            RemoteOperationType::HttpRequest,
            "http-client",
            "https://api.example.com/data",
            "trace-e2e-2",
            200,
        )
        .unwrap_err();

    // Step 2: Wrap denial as transport error (no actual network call).
    let _transport_err = RemoteTransportError::CapabilityDenied(err);

    // Transport should NOT have been called.
    assert!(transport.recorded.is_empty());
    assert_eq!(gate.total_denied(), 1);
}

#[test]
fn multi_operation_workflow_with_event_audit() {
    let mut gate = RemoteOperationGate::new(SecurityEpoch::from_raw(7));
    let mut transport = MockRemoteTransport {
        response: b"ok".to_vec(),
        ..Default::default()
    };

    // Permitted HTTP request.
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "http",
        "https://service-a.local",
        "t-1",
        10,
    )
    .unwrap();
    transport
        .execute(
            &RemoteOperationType::HttpRequest,
            "https://service-a.local",
            b"req-1",
        )
        .unwrap();

    // Permitted gRPC call.
    gate.check(
        &remote_profile(),
        RemoteOperationType::GrpcCall,
        "grpc",
        "grpc://service-b.local:50051",
        "t-2",
        20,
    )
    .unwrap();
    transport
        .execute(
            &RemoteOperationType::GrpcCall,
            "grpc://service-b.local:50051",
            b"req-2",
        )
        .unwrap();

    // Denied DNS resolution from compute_only.
    let _ = gate.check(
        &compute_only_profile(),
        RemoteOperationType::DnsResolution,
        "resolver",
        "dns://8.8.8.8",
        "t-3",
        30,
    );

    // Verify state.
    assert_eq!(gate.total_permitted(), 2);
    assert_eq!(gate.total_denied(), 1);
    assert_eq!(transport.recorded.len(), 2);

    let events = gate.drain_events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].outcome, "permitted");
    assert_eq!(events[1].outcome, "permitted");
    assert_eq!(events[2].outcome, "denied");
}

// =========================================================================
// Section 12: SecurityEpoch binding
// =========================================================================

#[test]
fn gate_records_epoch_in_events() {
    let epoch = SecurityEpoch::from_raw(999);
    let mut gate = RemoteOperationGate::new(epoch);
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "s",
        "e",
        "t",
        0,
    )
    .unwrap();

    let events = gate.drain_events();
    assert_eq!(events[0].epoch_id, 999);
}

#[test]
fn gate_with_genesis_epoch() {
    let mut gate = RemoteOperationGate::new(SecurityEpoch::GENESIS);
    assert_eq!(gate.epoch().as_u64(), 0);

    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "s",
        "e",
        "t",
        0,
    )
    .unwrap();

    let events = gate.drain_events();
    assert_eq!(events[0].epoch_id, 0);
}

// =========================================================================
// Section 13: Edge cases
// =========================================================================

#[test]
fn gate_empty_strings_accepted() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "",
        "",
        "",
        0,
    )
    .unwrap();

    let events = gate.drain_events();
    assert_eq!(events[0].component, "");
    assert_eq!(events[0].remote_endpoint, "");
    assert_eq!(events[0].trace_id, "");
}

#[test]
fn gate_large_timestamp_ticks() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "s",
        "e",
        "t",
        u64::MAX,
    )
    .unwrap();

    let events = gate.drain_events();
    assert_eq!(events[0].timestamp_ticks, u64::MAX);
}

#[test]
fn gate_high_epoch_value() {
    let epoch = SecurityEpoch::from_raw(u64::MAX);
    let mut gate = RemoteOperationGate::new(epoch);
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "s",
        "e",
        "t",
        0,
    )
    .unwrap();

    let events = gate.drain_events();
    assert_eq!(events[0].epoch_id, u64::MAX);
}

#[test]
fn many_operations_stress_test() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    for i in 0u64..100 {
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "stress",
            "https://example.com",
            &format!("trace-{i}"),
            i,
        )
        .unwrap();
    }
    assert_eq!(gate.total_permitted(), 100);
    assert_eq!(gate.permitted_counts().get("http_request"), Some(&100));
    let events = gate.drain_events();
    assert_eq!(events.len(), 100);
}

#[test]
fn transport_empty_payload() {
    let mut transport = MockRemoteTransport {
        response: vec![],
        ..Default::default()
    };
    let result = transport
        .execute(&RemoteOperationType::HttpRequest, "ep", b"")
        .unwrap();
    assert!(result.is_empty());
    assert!(transport.recorded[0].payload.is_empty());
}

#[test]
fn transport_large_payload() {
    let payload = vec![0xAB; 65536];
    let mut transport = MockRemoteTransport {
        response: vec![0xCD; 128],
        ..Default::default()
    };
    let result = transport
        .execute(&RemoteOperationType::HttpRequest, "ep", &payload)
        .unwrap();
    assert_eq!(result.len(), 128);
    assert_eq!(transport.recorded[0].payload.len(), 65536);
}
