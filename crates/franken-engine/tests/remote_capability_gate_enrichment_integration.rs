#![forbid(unsafe_code)]
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

use frankenengine_engine::capability::{CapabilityProfile, ProfileKind, RuntimeCapability};
use frankenengine_engine::remote_capability_gate::{
    MockRemoteTransport, RemoteCapabilityDenied, RemoteGateEvent, RemoteOperationGate,
    RemoteOperationType, RemoteTransport, RemoteTransportError,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(42)
}

fn remote_profile() -> CapabilityProfile {
    CapabilityProfile::remote()
}

fn compute_only_profile() -> CapabilityProfile {
    CapabilityProfile::compute_only()
}

// =========================================================================
// A. BTreeSet ordering and dedup for RemoteOperationType (Ord)
// =========================================================================

#[test]
fn enrichment_operation_type_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(RemoteOperationType::HttpRequest);
    set.insert(RemoteOperationType::GrpcCall);
    set.insert(RemoteOperationType::DnsResolution);
    set.insert(RemoteOperationType::DistributedStateMutation);
    set.insert(RemoteOperationType::LeaseRenewal);
    set.insert(RemoteOperationType::RemoteIpc);
    set.insert(RemoteOperationType::HttpRequest); // duplicate
    set.insert(RemoteOperationType::RemoteIpc); // duplicate
    assert_eq!(set.len(), 6);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

// =========================================================================
// B. Display values are all distinct
// =========================================================================

#[test]
fn enrichment_operation_type_display_values_distinct() {
    let displays: BTreeSet<String> = [
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall,
        RemoteOperationType::DnsResolution,
        RemoteOperationType::DistributedStateMutation,
        RemoteOperationType::LeaseRenewal,
        RemoteOperationType::RemoteIpc,
    ]
    .iter()
    .map(|op| op.to_string())
    .collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_transport_error_display_values_distinct() {
    let denied = RemoteCapabilityDenied {
        operation: RemoteOperationType::HttpRequest,
        component: "test".to_string(),
        held_profile: ProfileKind::ComputeOnly,
        required_capabilities: vec![RuntimeCapability::NetworkEgress],
        trace_id: "t".to_string(),
    };
    let errors = [
        RemoteTransportError::ConnectionFailed {
            endpoint: "host".into(),
            reason: "refused".into(),
        },
        RemoteTransportError::RemoteError {
            status: 503,
            message: "unavailable".into(),
        },
        RemoteTransportError::Timeout {
            endpoint: "slow".into(),
            duration_ms: 5000,
        },
        RemoteTransportError::CapabilityDenied(denied),
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 4);
}

// =========================================================================
// C. Debug nonempty for all types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_operation_types() {
    assert!(!format!("{:?}", RemoteOperationType::HttpRequest).is_empty());
    assert!(!format!("{:?}", RemoteOperationType::GrpcCall).is_empty());
    assert!(!format!("{:?}", RemoteOperationType::DnsResolution).is_empty());
    assert!(!format!("{:?}", RemoteOperationType::DistributedStateMutation).is_empty());
    assert!(!format!("{:?}", RemoteOperationType::LeaseRenewal).is_empty());
    assert!(!format!("{:?}", RemoteOperationType::RemoteIpc).is_empty());
}

#[test]
fn enrichment_debug_nonempty_denied() {
    let denied = RemoteCapabilityDenied {
        operation: RemoteOperationType::HttpRequest,
        component: "c".to_string(),
        held_profile: ProfileKind::ComputeOnly,
        required_capabilities: vec![RuntimeCapability::NetworkEgress],
        trace_id: "t".to_string(),
    };
    assert!(!format!("{denied:?}").is_empty());
}

#[test]
fn enrichment_debug_nonempty_gate_event() {
    let event = RemoteGateEvent {
        trace_id: "t".to_string(),
        component: "c".to_string(),
        operation_type: "http_request".to_string(),
        remote_endpoint: "e".to_string(),
        epoch_id: 1,
        timestamp_ticks: 0,
        outcome: "permitted".to_string(),
        held_profile: "RemoteCaps".to_string(),
    };
    assert!(!format!("{event:?}").is_empty());
}

#[test]
fn enrichment_debug_nonempty_gate() {
    let gate = RemoteOperationGate::new(test_epoch());
    assert!(!format!("{gate:?}").is_empty());
}

#[test]
fn enrichment_debug_nonempty_transport_errors() {
    let err = RemoteTransportError::ConnectionFailed {
        endpoint: "h".into(),
        reason: "r".into(),
    };
    assert!(!format!("{err:?}").is_empty());
    let err = RemoteTransportError::RemoteError {
        status: 500,
        message: "m".into(),
    };
    assert!(!format!("{err:?}").is_empty());
    let err = RemoteTransportError::Timeout {
        endpoint: "h".into(),
        duration_ms: 100,
    };
    assert!(!format!("{err:?}").is_empty());
}

#[test]
fn enrichment_debug_nonempty_mock_transport() {
    let transport = MockRemoteTransport::default();
    assert!(!format!("{transport:?}").is_empty());
}

// =========================================================================
// D. Clone independence
// =========================================================================

#[test]
fn enrichment_clone_independence_denied() {
    let denied = RemoteCapabilityDenied {
        operation: RemoteOperationType::HttpRequest,
        component: "original".to_string(),
        held_profile: ProfileKind::ComputeOnly,
        required_capabilities: vec![RuntimeCapability::NetworkEgress],
        trace_id: "trace-orig".to_string(),
    };
    let mut cloned = denied.clone();
    cloned.component = "modified".to_string();
    cloned.trace_id = "trace-mod".to_string();
    assert_eq!(denied.component, "original");
    assert_eq!(denied.trace_id, "trace-orig");
}

#[test]
fn enrichment_clone_independence_gate_event() {
    let event = RemoteGateEvent {
        trace_id: "t-orig".to_string(),
        component: "c".to_string(),
        operation_type: "http_request".to_string(),
        remote_endpoint: "e".to_string(),
        epoch_id: 1,
        timestamp_ticks: 0,
        outcome: "permitted".to_string(),
        held_profile: "RemoteCaps".to_string(),
    };
    let mut cloned = event.clone();
    cloned.trace_id = "t-mod".to_string();
    assert_eq!(event.trace_id, "t-orig");
}

#[test]
fn enrichment_clone_independence_transport_error() {
    let err = RemoteTransportError::ConnectionFailed {
        endpoint: "original-host".to_string(),
        reason: "refused".to_string(),
    };
    let mut cloned = err.clone();
    if let RemoteTransportError::ConnectionFailed {
        ref mut endpoint, ..
    } = cloned
    {
        *endpoint = "modified-host".to_string();
    }
    if let RemoteTransportError::ConnectionFailed { endpoint, .. } = &err {
        assert_eq!(endpoint, "original-host");
    }
}

// =========================================================================
// E. Error trait implementations
// =========================================================================

#[test]
fn enrichment_denied_is_error_trait() {
    let denied = RemoteCapabilityDenied {
        operation: RemoteOperationType::HttpRequest,
        component: "test".to_string(),
        held_profile: ProfileKind::ComputeOnly,
        required_capabilities: vec![RuntimeCapability::NetworkEgress],
        trace_id: "t".to_string(),
    };
    // RemoteCapabilityDenied implements std::error::Error
    let err: &dyn std::error::Error = &denied;
    assert!(!err.to_string().is_empty());
    // No source for this error type
    assert!(err.source().is_none());
}

#[test]
fn enrichment_transport_error_is_error_trait() {
    let err = RemoteTransportError::Timeout {
        endpoint: "host".into(),
        duration_ms: 1000,
    };
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

// =========================================================================
// F. LeaseRenewal requires two capabilities (NetworkEgress + LeaseManagement)
// =========================================================================

#[test]
fn enrichment_lease_renewal_required_capabilities() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let err = gate
        .check(
            &compute_only_profile(),
            RemoteOperationType::LeaseRenewal,
            "lease-mgr",
            "internal://lease",
            "trace-lease",
            100,
        )
        .unwrap_err();
    // LeaseRenewal requires both NetworkEgress and LeaseManagement
    assert!(
        err.required_capabilities
            .contains(&RuntimeCapability::NetworkEgress)
    );
    assert!(
        err.required_capabilities
            .contains(&RuntimeCapability::LeaseManagement)
    );
    assert!(err.required_capabilities.len() >= 2);
}

// =========================================================================
// G. RemoteGateEvent serde with denied outcome
// =========================================================================

#[test]
fn enrichment_gate_event_denied_serde_roundtrip() {
    let event = RemoteGateEvent {
        trace_id: "t-denied".to_string(),
        component: "compute-worker".to_string(),
        operation_type: "grpc_call".to_string(),
        remote_endpoint: "grpc://host:50051".to_string(),
        epoch_id: 42,
        timestamp_ticks: 999,
        outcome: "denied".to_string(),
        held_profile: "ComputeOnlyCaps".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: RemoteGateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(back.outcome, "denied");
}

// =========================================================================
// H. Endpoint sanitization edge cases
// =========================================================================

#[test]
fn enrichment_sanitize_userinfo_only_username() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "s",
        "https://admin@example.com/path",
        "t",
        0,
    )
    .unwrap();
    let events = gate.drain_events();
    // The @ triggers sanitization even with just a username
    assert_eq!(events[0].remote_endpoint, "https://***@example.com/path");
}

#[test]
fn enrichment_sanitize_no_scheme_with_at() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::RemoteIpc,
        "s",
        "user@host",
        "t",
        0,
    )
    .unwrap();
    let events = gate.drain_events();
    // No "://" so no sanitization
    assert_eq!(events[0].remote_endpoint, "user@host");
}

// =========================================================================
// I. Counters are zero on fresh gate
// =========================================================================

#[test]
fn enrichment_fresh_gate_counters_zero() {
    let gate = RemoteOperationGate::new(test_epoch());
    assert_eq!(gate.total_permitted(), 0);
    assert_eq!(gate.total_denied(), 0);
    assert!(gate.permitted_counts().is_empty());
    assert!(gate.denied_counts().is_empty());
}

// =========================================================================
// J. MockRemoteTransport with multiple failures then success
// =========================================================================

#[test]
fn enrichment_mock_transport_change_failure_mode() {
    let mut transport = MockRemoteTransport {
        fail_with: Some(RemoteTransportError::Timeout {
            endpoint: "host".into(),
            duration_ms: 5000,
        }),
        ..Default::default()
    };

    // First call fails
    let err = transport
        .execute(&RemoteOperationType::HttpRequest, "host", b"req1")
        .unwrap_err();
    assert!(matches!(err, RemoteTransportError::Timeout { .. }));

    // Clear failure mode
    transport.fail_with = None;
    transport.response = b"success".to_vec();

    // Second call succeeds
    let result = transport
        .execute(&RemoteOperationType::HttpRequest, "host", b"req2")
        .unwrap();
    assert_eq!(result, b"success");

    // Both operations were recorded
    assert_eq!(transport.recorded.len(), 2);
}

// =========================================================================
// K. Denied error required_capabilities for different operation types
// =========================================================================

#[test]
fn enrichment_required_capabilities_per_operation_type() {
    let mut gate = RemoteOperationGate::new(test_epoch());

    // HTTP requires only NetworkEgress
    let err_http = gate
        .check(
            &compute_only_profile(),
            RemoteOperationType::HttpRequest,
            "c",
            "e",
            "t",
            0,
        )
        .unwrap_err();
    assert_eq!(err_http.required_capabilities.len(), 1);
    assert_eq!(
        err_http.required_capabilities[0],
        RuntimeCapability::NetworkEgress
    );

    // LeaseRenewal requires NetworkEgress + LeaseManagement
    let err_lease = gate
        .check(
            &compute_only_profile(),
            RemoteOperationType::LeaseRenewal,
            "c",
            "e",
            "t",
            0,
        )
        .unwrap_err();
    assert_eq!(err_lease.required_capabilities.len(), 2);
}

// =========================================================================
// L. Gate events record sanitized endpoint, not raw
// =========================================================================

#[test]
fn enrichment_events_contain_sanitized_not_raw_endpoint() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let _ = gate.check(
        &compute_only_profile(),
        RemoteOperationType::HttpRequest,
        "c",
        "https://secret:password@api.example.com",
        "t",
        0,
    );
    let events = gate.drain_events();
    assert_eq!(events[0].remote_endpoint, "https://***@api.example.com");
    // Verify credentials are NOT present
    assert!(!events[0].remote_endpoint.contains("secret"));
    assert!(!events[0].remote_endpoint.contains("password"));
}

// =========================================================================
// M. Serde roundtrip for RemoteCapabilityDenied with multiple capabilities
// =========================================================================

#[test]
fn enrichment_denied_multiple_capabilities_serde() {
    let denied = RemoteCapabilityDenied {
        operation: RemoteOperationType::LeaseRenewal,
        component: "lease-service".to_string(),
        held_profile: ProfileKind::ComputeOnly,
        required_capabilities: vec![
            RuntimeCapability::NetworkEgress,
            RuntimeCapability::LeaseManagement,
        ],
        trace_id: "t-lease-serde".to_string(),
    };
    let json = serde_json::to_string(&denied).unwrap();
    let back: RemoteCapabilityDenied = serde_json::from_str(&json).unwrap();
    assert_eq!(denied, back);
    assert_eq!(back.required_capabilities.len(), 2);
}

// =========================================================================
// N. RecordedOperation fields match execute parameters
// =========================================================================

#[test]
fn enrichment_recorded_operation_matches_parameters() {
    let mut transport = MockRemoteTransport {
        response: b"ok".to_vec(),
        ..Default::default()
    };
    let payload = b"hello world";
    transport
        .execute(
            &RemoteOperationType::DistributedStateMutation,
            "internal://state-sync/node-7",
            payload,
        )
        .unwrap();
    assert_eq!(transport.recorded.len(), 1);
    assert_eq!(
        transport.recorded[0].operation,
        RemoteOperationType::DistributedStateMutation
    );
    assert_eq!(
        transport.recorded[0].endpoint,
        "internal://state-sync/node-7"
    );
    assert_eq!(transport.recorded[0].payload, payload);
}

// ===== PearlTower enrichment =====

// =========================================================================
// O. Serde roundtrip for RemoteOperationType
// =========================================================================

#[test]
fn enrichment_serde_roundtrip_remote_operation_type_all_variants() {
    let variants = [
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall,
        RemoteOperationType::DnsResolution,
        RemoteOperationType::DistributedStateMutation,
        RemoteOperationType::LeaseRenewal,
        RemoteOperationType::RemoteIpc,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let back: RemoteOperationType = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, &back, "roundtrip failed for {variant:?}");
    }
}

// =========================================================================
// P. Serde roundtrip for RemoteTransportError all variants
// =========================================================================

#[test]
fn enrichment_serde_roundtrip_transport_error_connection_failed() {
    let err = RemoteTransportError::ConnectionFailed {
        endpoint: "https://unreachable.internal:9000".to_string(),
        reason: "connection refused".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: RemoteTransportError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_serde_roundtrip_transport_error_remote_error() {
    let err = RemoteTransportError::RemoteError {
        status: 404,
        message: "not found".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: RemoteTransportError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_serde_roundtrip_transport_error_timeout() {
    let err = RemoteTransportError::Timeout {
        endpoint: "grpc://slow-node:50051".to_string(),
        duration_ms: 30_000,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: RemoteTransportError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

#[test]
fn enrichment_serde_roundtrip_transport_error_capability_denied() {
    let denied = RemoteCapabilityDenied {
        operation: RemoteOperationType::GrpcCall,
        component: "rpc-caller".to_string(),
        held_profile: ProfileKind::EngineCore,
        required_capabilities: vec![RuntimeCapability::NetworkEgress],
        trace_id: "trace-rte-serde".to_string(),
    };
    let err = RemoteTransportError::CapabilityDenied(denied);
    let json = serde_json::to_string(&err).unwrap();
    let back: RemoteTransportError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// =========================================================================
// Q. Event logging: epoch_id matches gate's epoch
// =========================================================================

#[test]
fn enrichment_event_epoch_id_matches_gate_epoch() {
    let epoch = SecurityEpoch::from_raw(999);
    let mut gate = RemoteOperationGate::new(epoch);
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "component-a",
        "https://api.example.com",
        "trace-epoch-check",
        77,
    )
    .unwrap();
    let events = gate.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].epoch_id, 999);
    assert_eq!(events[0].timestamp_ticks, 77);
}

// =========================================================================
// R. Event logging: denied operations still emit events with "denied" outcome
// =========================================================================

#[test]
fn enrichment_denied_operation_emits_event_with_denied_outcome() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let _ = gate.check(
        &compute_only_profile(),
        RemoteOperationType::DnsResolution,
        "dns-client",
        "dns://8.8.8.8",
        "trace-deny-event",
        50,
    );
    let events = gate.drain_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "denied");
    assert_eq!(events[0].component, "dns-client");
    assert_eq!(events[0].trace_id, "trace-deny-event");
    assert_eq!(events[0].timestamp_ticks, 50);
    // held profile string for compute-only
    assert_eq!(events[0].held_profile, "ComputeOnlyCaps");
}

// =========================================================================
// S. Edge case: multiple drain_events calls clear the buffer each time
// =========================================================================

#[test]
fn enrichment_drain_events_clears_buffer() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::RemoteIpc,
        "ipc-sender",
        "ipc://peer-node",
        "trace-drain-1",
        10,
    )
    .unwrap();
    let first_drain = gate.drain_events();
    assert_eq!(first_drain.len(), 1);
    // Second drain should be empty
    let second_drain = gate.drain_events();
    assert!(second_drain.is_empty());
}

// =========================================================================
// T. Edge case: epoch boundary — epoch zero and max u64 are valid
// =========================================================================

#[test]
fn enrichment_epoch_boundary_zero_and_max() {
    let gate_zero = RemoteOperationGate::new(SecurityEpoch::from_raw(0));
    assert_eq!(gate_zero.epoch().as_u64(), 0);

    let gate_max = RemoteOperationGate::new(SecurityEpoch::from_raw(u64::MAX));
    assert_eq!(gate_max.epoch().as_u64(), u64::MAX);
}

// =========================================================================
// U. Edge case: empty component and trace_id strings are recorded faithfully
// =========================================================================

#[test]
fn enrichment_empty_component_and_trace_id_recorded() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::GrpcCall,
        "",
        "grpc://host:50051",
        "",
        0,
    )
    .unwrap();
    let events = gate.drain_events();
    assert_eq!(events[0].component, "");
    assert_eq!(events[0].trace_id, "");
}

// =========================================================================
// V. Counter accumulation across multiple permitted operations
// =========================================================================

#[test]
fn enrichment_counters_accumulate_across_multiple_permitted_ops() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    // Permit 3 HTTP requests
    for i in 0..3u64 {
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "client",
            "https://api.example.com",
            &format!("trace-{i}"),
            i,
        )
        .unwrap();
    }
    // Permit 2 gRPC calls
    for i in 0..2u64 {
        gate.check(
            &remote_profile(),
            RemoteOperationType::GrpcCall,
            "rpc-client",
            "grpc://svc:50051",
            &format!("grpc-trace-{i}"),
            i,
        )
        .unwrap();
    }
    assert_eq!(gate.total_permitted(), 5);
    assert_eq!(gate.total_denied(), 0);
    let http_key = RemoteOperationType::HttpRequest.to_string();
    let grpc_key = RemoteOperationType::GrpcCall.to_string();
    assert_eq!(gate.permitted_counts()[&http_key], 3);
    assert_eq!(gate.permitted_counts()[&grpc_key], 2);
}

// =========================================================================
// W. Counter accumulation across mixed permitted and denied operations
// =========================================================================

#[test]
fn enrichment_counters_mixed_permitted_and_denied() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    // 2 permitted
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "c",
        "https://ok.example.com",
        "t1",
        1,
    )
    .unwrap();
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "c",
        "https://ok2.example.com",
        "t2",
        2,
    )
    .unwrap();
    // 1 denied
    let _ = gate.check(
        &compute_only_profile(),
        RemoteOperationType::HttpRequest,
        "c",
        "https://bad.example.com",
        "t3",
        3,
    );
    assert_eq!(gate.total_permitted(), 2);
    assert_eq!(gate.total_denied(), 1);
    let http_key = RemoteOperationType::HttpRequest.to_string();
    assert_eq!(gate.permitted_counts()[&http_key], 2);
    assert_eq!(gate.denied_counts()[&http_key], 1);
}

// =========================================================================
// X. Clone/Debug derive: RecordedOperation clone independence
// =========================================================================

#[test]
fn enrichment_recorded_operation_clone_independence() {
    let mut transport = MockRemoteTransport {
        response: b"pong".to_vec(),
        ..Default::default()
    };
    transport
        .execute(
            &RemoteOperationType::LeaseRenewal,
            "internal://lease-server",
            b"renew",
        )
        .unwrap();
    assert_eq!(transport.recorded.len(), 1);
    let cloned = transport.recorded[0].clone();
    assert_eq!(cloned.operation, RemoteOperationType::LeaseRenewal);
    assert_eq!(cloned.endpoint, "internal://lease-server");
    assert_eq!(cloned.payload, b"renew");
    // Verify Debug is implemented (non-empty)
    assert!(!format!("{:?}", transport.recorded[0]).is_empty());
}

// =========================================================================
// Y. PartialEq on RemoteOperationType
// =========================================================================

#[test]
fn test_remote_operation_type_partial_eq_same_variants() {
    assert_eq!(
        RemoteOperationType::HttpRequest,
        RemoteOperationType::HttpRequest
    );
    assert_eq!(RemoteOperationType::GrpcCall, RemoteOperationType::GrpcCall);
    assert_eq!(
        RemoteOperationType::DnsResolution,
        RemoteOperationType::DnsResolution
    );
    assert_eq!(
        RemoteOperationType::DistributedStateMutation,
        RemoteOperationType::DistributedStateMutation
    );
    assert_eq!(
        RemoteOperationType::LeaseRenewal,
        RemoteOperationType::LeaseRenewal
    );
    assert_eq!(
        RemoteOperationType::RemoteIpc,
        RemoteOperationType::RemoteIpc
    );
}

#[test]
fn test_remote_operation_type_partial_eq_different_variants() {
    assert_ne!(
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall
    );
    assert_ne!(
        RemoteOperationType::DnsResolution,
        RemoteOperationType::LeaseRenewal
    );
    assert_ne!(
        RemoteOperationType::RemoteIpc,
        RemoteOperationType::DistributedStateMutation
    );
}

// =========================================================================
// Z. Display strings match expected values
// =========================================================================

#[test]
fn test_remote_operation_type_display_strings() {
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

// =========================================================================
// AA. Full profile permits all remote operation types
// =========================================================================

#[test]
fn test_full_profile_permits_all_operation_types() {
    use frankenengine_engine::capability::CapabilityProfile;
    let full = CapabilityProfile::full();
    let mut gate = RemoteOperationGate::new(SecurityEpoch::from_raw(10));
    let ops = [
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall,
        RemoteOperationType::DnsResolution,
        RemoteOperationType::DistributedStateMutation,
        RemoteOperationType::LeaseRenewal,
        RemoteOperationType::RemoteIpc,
    ];
    for op in ops {
        let result = gate.check(
            &full,
            op.clone(),
            "full-component",
            "https://example.com",
            "trace-full",
            0,
        );
        assert!(result.is_ok(), "full profile should permit {op:?}");
    }
    assert_eq!(gate.total_permitted(), 6);
    assert_eq!(gate.total_denied(), 0);
}

// =========================================================================
// AB. Engine-core profile denies all remote operations
// =========================================================================

#[test]
fn test_engine_core_profile_denies_all_remote_ops() {
    use frankenengine_engine::capability::CapabilityProfile;
    let ec = CapabilityProfile::engine_core();
    let mut gate = RemoteOperationGate::new(SecurityEpoch::from_raw(5));
    let ops = [
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall,
        RemoteOperationType::DnsResolution,
        RemoteOperationType::DistributedStateMutation,
        RemoteOperationType::LeaseRenewal,
        RemoteOperationType::RemoteIpc,
    ];
    for op in ops {
        let result = gate.check(
            &ec,
            op.clone(),
            "ec-component",
            "https://example.com",
            "trace-ec",
            0,
        );
        assert!(result.is_err(), "engine_core profile should deny {op:?}");
    }
    assert_eq!(gate.total_permitted(), 0);
    assert_eq!(gate.total_denied(), 6);
}

// =========================================================================
// AC. Policy profile denies all remote operations
// =========================================================================

#[test]
fn test_policy_profile_denies_all_remote_ops() {
    use frankenengine_engine::capability::CapabilityProfile;
    let pol = CapabilityProfile::policy();
    let mut gate = RemoteOperationGate::new(SecurityEpoch::from_raw(7));
    let ops = [
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall,
        RemoteOperationType::DnsResolution,
        RemoteOperationType::DistributedStateMutation,
        RemoteOperationType::LeaseRenewal,
        RemoteOperationType::RemoteIpc,
    ];
    for op in ops {
        let result = gate.check(
            &pol,
            op.clone(),
            "pol-component",
            "https://example.com",
            "trace-pol",
            0,
        );
        assert!(result.is_err(), "policy profile should deny {op:?}");
    }
    assert_eq!(gate.total_denied(), 6);
}

// =========================================================================
// AD. RemoteCapabilityDenied Display contains key fields
// =========================================================================

#[test]
fn test_denied_display_contains_operation_component_trace() {
    let denied = RemoteCapabilityDenied {
        operation: RemoteOperationType::GrpcCall,
        component: "my-component".to_string(),
        held_profile: ProfileKind::ComputeOnly,
        required_capabilities: vec![RuntimeCapability::NetworkEgress],
        trace_id: "trace-display-test".to_string(),
    };
    let s = denied.to_string();
    assert!(
        s.contains("grpc_call"),
        "display should contain operation name"
    );
    assert!(
        s.contains("my-component"),
        "display should contain component"
    );
    assert!(
        s.contains("trace-display-test"),
        "display should contain trace_id"
    );
}

// =========================================================================
// AE. RemoteTransportError::CapabilityDenied Display delegates to inner
// =========================================================================

#[test]
fn test_transport_error_capability_denied_display_delegates() {
    let denied = RemoteCapabilityDenied {
        operation: RemoteOperationType::HttpRequest,
        component: "inner-component".to_string(),
        held_profile: ProfileKind::EngineCore,
        required_capabilities: vec![RuntimeCapability::NetworkEgress],
        trace_id: "trace-inner".to_string(),
    };
    let err = RemoteTransportError::CapabilityDenied(denied.clone());
    let err_str = err.to_string();
    let denied_str = denied.to_string();
    assert_eq!(
        err_str, denied_str,
        "CapabilityDenied display should delegate to inner denied"
    );
}

// =========================================================================
// AF. Event operation_type field matches Display of RemoteOperationType
// =========================================================================

#[test]
fn test_event_operation_type_field_matches_display() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let ops_and_expected = [
        (RemoteOperationType::HttpRequest, "http_request"),
        (RemoteOperationType::GrpcCall, "grpc_call"),
        (RemoteOperationType::DnsResolution, "dns_resolution"),
        (
            RemoteOperationType::DistributedStateMutation,
            "distributed_state_mutation",
        ),
        (RemoteOperationType::LeaseRenewal, "lease_renewal"),
        (RemoteOperationType::RemoteIpc, "remote_ipc"),
    ];
    for (op, expected) in ops_and_expected {
        gate.check(&remote_profile(), op, "comp", "https://example.com", "t", 0)
            .unwrap();
        let events = gate.drain_events();
        assert_eq!(events[0].operation_type, expected);
    }
}

// =========================================================================
// AG. Endpoint with scheme but no userinfo is not modified
// =========================================================================

#[test]
fn test_sanitize_endpoint_no_userinfo_unchanged() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "c",
        "https://plain.example.com/api/v1",
        "t",
        0,
    )
    .unwrap();
    let events = gate.drain_events();
    assert_eq!(
        events[0].remote_endpoint,
        "https://plain.example.com/api/v1"
    );
}

// =========================================================================
// AH. Endpoint with user:pass@host is sanitized
// =========================================================================

#[test]
fn test_sanitize_endpoint_user_pass_at_host() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    gate.check(
        &remote_profile(),
        RemoteOperationType::GrpcCall,
        "c",
        "grpc://user:secret@internal.svc:50051",
        "t",
        0,
    )
    .unwrap();
    let events = gate.drain_events();
    assert_eq!(events[0].remote_endpoint, "grpc://***@internal.svc:50051");
    assert!(!events[0].remote_endpoint.contains("secret"));
    assert!(!events[0].remote_endpoint.contains("user"));
}

// =========================================================================
// AI. RemoteGateEvent serde roundtrip for permitted outcome
// =========================================================================

#[test]
fn test_gate_event_permitted_serde_roundtrip() {
    let event = RemoteGateEvent {
        trace_id: "t-permitted".to_string(),
        component: "sync-service".to_string(),
        operation_type: "http_request".to_string(),
        remote_endpoint: "https://api.example.com".to_string(),
        epoch_id: 77,
        timestamp_ticks: 1234,
        outcome: "permitted".to_string(),
        held_profile: "RemoteCaps".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: RemoteGateEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
    assert_eq!(back.outcome, "permitted");
    assert_eq!(back.epoch_id, 77);
    assert_eq!(back.timestamp_ticks, 1234);
}

// =========================================================================
// AJ. MockRemoteTransport default has empty recorded and empty response
// =========================================================================

#[test]
fn test_mock_transport_default_state() {
    let transport = MockRemoteTransport::default();
    assert!(transport.recorded.is_empty());
    assert!(transport.response.is_empty());
    assert!(transport.fail_with.is_none());
}

// =========================================================================
// AK. MockRemoteTransport records all operation types without failure
// =========================================================================

#[test]
fn test_mock_transport_records_all_operation_types() {
    let mut transport = MockRemoteTransport {
        response: b"ok".to_vec(),
        ..Default::default()
    };
    let ops = [
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall,
        RemoteOperationType::DnsResolution,
        RemoteOperationType::DistributedStateMutation,
        RemoteOperationType::LeaseRenewal,
        RemoteOperationType::RemoteIpc,
    ];
    for op in &ops {
        transport
            .execute(op, "https://example.com", b"payload")
            .unwrap();
    }
    assert_eq!(transport.recorded.len(), 6);
    for (i, op) in ops.iter().enumerate() {
        assert_eq!(&transport.recorded[i].operation, op);
        assert_eq!(transport.recorded[i].endpoint, "https://example.com");
        assert_eq!(transport.recorded[i].payload, b"payload");
    }
}

// =========================================================================
// AL. Gate held_profile string in event matches ProfileKind display
// =========================================================================

#[test]
fn test_event_held_profile_string_for_all_profile_kinds() {
    use frankenengine_engine::capability::CapabilityProfile;
    let profiles: &[(CapabilityProfile, &str)] = &[
        (CapabilityProfile::remote(), "RemoteCaps"),
        (CapabilityProfile::compute_only(), "ComputeOnlyCaps"),
        (CapabilityProfile::engine_core(), "EngineCoreCaps"),
        (CapabilityProfile::full(), "FullCaps"),
    ];
    for (profile, expected_kind_str) in profiles {
        let mut gate = RemoteOperationGate::new(SecurityEpoch::from_raw(1));
        // Use HttpRequest — permitted only for Remote/Full, denied for others
        let _ = gate.check(
            profile,
            RemoteOperationType::HttpRequest,
            "comp",
            "https://example.com",
            "t",
            0,
        );
        let events = gate.drain_events();
        assert_eq!(
            events[0].held_profile, *expected_kind_str,
            "held_profile for {:?} should be {}",
            profile.kind, expected_kind_str
        );
    }
}

// =========================================================================
// AM. Denied error fields are fully populated
// =========================================================================

#[test]
fn test_denied_error_fields_populated() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let err = gate
        .check(
            &compute_only_profile(),
            RemoteOperationType::DnsResolution,
            "dns-resolver",
            "dns://1.1.1.1",
            "trace-dns-deny",
            55,
        )
        .unwrap_err();
    assert_eq!(err.operation, RemoteOperationType::DnsResolution);
    assert_eq!(err.component, "dns-resolver");
    assert_eq!(err.held_profile, ProfileKind::ComputeOnly);
    assert_eq!(err.trace_id, "trace-dns-deny");
    assert!(!err.required_capabilities.is_empty());
}

// =========================================================================
// AN. Remote profile denies LeaseRenewal if only NetworkEgress present
//     (LeaseRenewal requires both NetworkEgress AND LeaseManagement)
//     Remote profile actually has both — this tests that remote permits it
// =========================================================================

#[test]
fn test_remote_profile_permits_lease_renewal() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let result = gate.check(
        &remote_profile(),
        RemoteOperationType::LeaseRenewal,
        "lease-client",
        "internal://lease-node",
        "trace-lease-permit",
        100,
    );
    assert!(
        result.is_ok(),
        "remote profile has both NetworkEgress and LeaseManagement"
    );
    assert_eq!(gate.total_permitted(), 1);
}

// =========================================================================
// AO. Counters tracked separately per operation type after denials
// =========================================================================

#[test]
fn test_denied_counts_tracked_per_operation_type() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    // Deny HTTP twice
    for i in 0..2u64 {
        let _ = gate.check(
            &compute_only_profile(),
            RemoteOperationType::HttpRequest,
            "c",
            "https://x.example.com",
            &format!("t-http-{i}"),
            i,
        );
    }
    // Deny DNS once
    let _ = gate.check(
        &compute_only_profile(),
        RemoteOperationType::DnsResolution,
        "c",
        "dns://8.8.8.8",
        "t-dns",
        99,
    );
    assert_eq!(gate.total_denied(), 3);
    assert_eq!(gate.total_permitted(), 0);
    let http_key = RemoteOperationType::HttpRequest.to_string();
    let dns_key = RemoteOperationType::DnsResolution.to_string();
    assert_eq!(gate.denied_counts()[&http_key], 2);
    assert_eq!(gate.denied_counts()[&dns_key], 1);
    assert!(
        !gate
            .denied_counts()
            .contains_key(&RemoteOperationType::GrpcCall.to_string())
    );
}

// =========================================================================
// AP. BTreeMap ordering of permitted_counts / denied_counts keys
// =========================================================================

#[test]
fn test_counts_map_keys_are_sorted() {
    use std::collections::BTreeMap;
    let mut gate = RemoteOperationGate::new(test_epoch());
    let ops = [
        RemoteOperationType::RemoteIpc,
        RemoteOperationType::HttpRequest,
        RemoteOperationType::GrpcCall,
    ];
    for op in &ops {
        gate.check(
            &remote_profile(),
            op.clone(),
            "c",
            "https://example.com",
            "t",
            0,
        )
        .unwrap();
    }
    let counts: &BTreeMap<String, u64> = gate.permitted_counts();
    let keys: Vec<&String> = counts.keys().collect();
    // BTreeMap keys must be in ascending lexicographic order
    for i in 1..keys.len() {
        assert!(
            keys[i - 1] < keys[i],
            "permitted_counts keys must be sorted"
        );
    }
}

// =========================================================================
// AQ. RecordedOperation PartialEq
// =========================================================================

#[test]
fn test_recorded_operation_partial_eq() {
    use frankenengine_engine::remote_capability_gate::RecordedOperation;
    let r1 = RecordedOperation {
        operation: RemoteOperationType::HttpRequest,
        endpoint: "https://example.com".to_string(),
        payload: b"data".to_vec(),
    };
    let r2 = RecordedOperation {
        operation: RemoteOperationType::HttpRequest,
        endpoint: "https://example.com".to_string(),
        payload: b"data".to_vec(),
    };
    let r3 = RecordedOperation {
        operation: RemoteOperationType::GrpcCall,
        endpoint: "https://example.com".to_string(),
        payload: b"data".to_vec(),
    };
    assert_eq!(r1, r2);
    assert_ne!(r1, r3);
}

// =========================================================================
// AR. MockRemoteTransport: failure with RemoteError variant
// =========================================================================

#[test]
fn test_mock_transport_fails_with_remote_error_variant() {
    let mut transport = MockRemoteTransport {
        fail_with: Some(RemoteTransportError::RemoteError {
            status: 500,
            message: "internal server error".to_string(),
        }),
        ..Default::default()
    };
    let err = transport
        .execute(&RemoteOperationType::GrpcCall, "grpc://host:50051", b"req")
        .unwrap_err();
    assert!(matches!(
        err,
        RemoteTransportError::RemoteError { status: 500, .. }
    ));
    // Operation is still recorded even on failure
    assert_eq!(transport.recorded.len(), 1);
}

// =========================================================================
// AS. MockRemoteTransport: failure with ConnectionFailed variant
// =========================================================================

#[test]
fn test_mock_transport_fails_with_connection_failed_variant() {
    let mut transport = MockRemoteTransport {
        fail_with: Some(RemoteTransportError::ConnectionFailed {
            endpoint: "unreachable.internal:9000".to_string(),
            reason: "connection refused".to_string(),
        }),
        ..Default::default()
    };
    let err = transport
        .execute(
            &RemoteOperationType::HttpRequest,
            "unreachable.internal:9000",
            b"hello",
        )
        .unwrap_err();
    assert!(matches!(err, RemoteTransportError::ConnectionFailed { .. }));
    assert_eq!(transport.recorded.len(), 1);
}

// =========================================================================
// AT. Multiple events accumulate before drain
// =========================================================================

#[test]
fn test_multiple_events_accumulate_before_drain() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    // Emit 4 events (2 permitted, 2 denied) without draining
    gate.check(
        &remote_profile(),
        RemoteOperationType::HttpRequest,
        "c",
        "https://a.example.com",
        "t1",
        1,
    )
    .unwrap();
    gate.check(
        &remote_profile(),
        RemoteOperationType::GrpcCall,
        "c",
        "grpc://b:50051",
        "t2",
        2,
    )
    .unwrap();
    let _ = gate.check(
        &compute_only_profile(),
        RemoteOperationType::DnsResolution,
        "c",
        "dns://8.8.8.8",
        "t3",
        3,
    );
    let _ = gate.check(
        &compute_only_profile(),
        RemoteOperationType::RemoteIpc,
        "c",
        "ipc://peer",
        "t4",
        4,
    );
    let events = gate.drain_events();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].outcome, "permitted");
    assert_eq!(events[1].outcome, "permitted");
    assert_eq!(events[2].outcome, "denied");
    assert_eq!(events[3].outcome, "denied");
    // Timestamps are preserved in order
    assert_eq!(events[0].timestamp_ticks, 1);
    assert_eq!(events[1].timestamp_ticks, 2);
    assert_eq!(events[2].timestamp_ticks, 3);
    assert_eq!(events[3].timestamp_ticks, 4);
}

// =========================================================================
// AU. RemoteTransportError Display messages are non-empty and informative
// =========================================================================

#[test]
fn test_transport_error_display_contains_endpoint_or_status() {
    let conn_err = RemoteTransportError::ConnectionFailed {
        endpoint: "myhost:9000".to_string(),
        reason: "refused".to_string(),
    };
    assert!(conn_err.to_string().contains("myhost:9000"));
    assert!(conn_err.to_string().contains("refused"));

    let remote_err = RemoteTransportError::RemoteError {
        status: 503,
        message: "service unavailable".to_string(),
    };
    assert!(remote_err.to_string().contains("503"));
    assert!(remote_err.to_string().contains("service unavailable"));

    let timeout_err = RemoteTransportError::Timeout {
        endpoint: "slow-node:50051".to_string(),
        duration_ms: 10_000,
    };
    assert!(timeout_err.to_string().contains("10000"));
    assert!(timeout_err.to_string().contains("slow-node:50051"));
}

// =========================================================================
// AV. Gate epoch() accessor returns original epoch value
// =========================================================================

#[test]
fn test_gate_epoch_accessor_roundtrip() {
    let expected_raw = 123_456_789u64;
    let epoch = SecurityEpoch::from_raw(expected_raw);
    let gate = RemoteOperationGate::new(epoch);
    assert_eq!(gate.epoch().as_u64(), expected_raw);
}

// =========================================================================
// AW. DistributedStateMutation requires only NetworkEgress (not LeaseManagement)
// =========================================================================

#[test]
fn test_distributed_state_mutation_requires_only_network_egress() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let err = gate
        .check(
            &compute_only_profile(),
            RemoteOperationType::DistributedStateMutation,
            "state-syncer",
            "internal://anti-entropy",
            "trace-dsm",
            0,
        )
        .unwrap_err();
    assert_eq!(err.required_capabilities.len(), 1);
    assert_eq!(
        err.required_capabilities[0],
        RuntimeCapability::NetworkEgress
    );
}

// =========================================================================
// AX. RemoteIpc requires only NetworkEgress
// =========================================================================

#[test]
fn test_remote_ipc_requires_only_network_egress() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let err = gate
        .check(
            &compute_only_profile(),
            RemoteOperationType::RemoteIpc,
            "ipc-client",
            "ipc://peer-node",
            "trace-ipc",
            0,
        )
        .unwrap_err();
    assert_eq!(err.required_capabilities.len(), 1);
    assert_eq!(
        err.required_capabilities[0],
        RuntimeCapability::NetworkEgress
    );
}

// =========================================================================
// AY. GrpcCall requires only NetworkEgress
// =========================================================================

#[test]
fn test_grpc_call_requires_only_network_egress() {
    let mut gate = RemoteOperationGate::new(test_epoch());
    let err = gate
        .check(
            &compute_only_profile(),
            RemoteOperationType::GrpcCall,
            "grpc-client",
            "grpc://svc:50051",
            "trace-grpc",
            0,
        )
        .unwrap_err();
    assert_eq!(err.required_capabilities.len(), 1);
    assert_eq!(
        err.required_capabilities[0],
        RuntimeCapability::NetworkEgress
    );
}
