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
