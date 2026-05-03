//! Remote operation capability gate — no implicit network side effects.
//!
//! All remote operations (HTTP, gRPC, DNS, distributed state mutations,
//! lease renewal, cross-process IPC) must pass through `RemoteOperationGate`
//! which verifies the caller holds `RemoteCaps` before dispatching.
//!
//! Rejection emits a typed `RemoteCapabilityDenied` error and a structured
//! evidence event. Permitted operations also emit audit events.
//!
//! Plan references: Section 10.11 item 20, 9G.7 (remote-effects contract).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityProfile, ProfileKind, RuntimeCapability};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// RemoteOperationType — classification of remote operations
// ---------------------------------------------------------------------------

/// Classification of remote operations subject to capability gating.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RemoteOperationType {
    /// Outbound HTTP/HTTPS request.
    HttpRequest,
    /// gRPC call.
    GrpcCall,
    /// DNS resolution (potential covert channel).
    DnsResolution,
    /// Distributed state mutation (anti-entropy sync, revocation propagation).
    DistributedStateMutation,
    /// Lease renewal or liveness check.
    LeaseRenewal,
    /// Cross-process IPC to a remote endpoint.
    RemoteIpc,
}

impl fmt::Display for RemoteOperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpRequest => write!(f, "http_request"),
            Self::GrpcCall => write!(f, "grpc_call"),
            Self::DnsResolution => write!(f, "dns_resolution"),
            Self::DistributedStateMutation => write!(f, "distributed_state_mutation"),
            Self::LeaseRenewal => write!(f, "lease_renewal"),
            Self::RemoteIpc => write!(f, "remote_ipc"),
        }
    }
}

// ---------------------------------------------------------------------------
// RemoteCapabilityDenied — denial error
// ---------------------------------------------------------------------------

/// Error when a remote operation is attempted without `RemoteCaps`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCapabilityDenied {
    /// The operation that was attempted.
    pub operation: RemoteOperationType,
    /// The component that attempted the operation.
    pub component: String,
    /// The capability profile held by the caller.
    pub held_profile: ProfileKind,
    /// Specific capabilities that were required.
    pub required_capabilities: Vec<RuntimeCapability>,
    /// Trace identifier for the denied request.
    pub trace_id: String,
}

impl fmt::Display for RemoteCapabilityDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "remote capability denied: {} requires RemoteCaps but held profile {} does not grant it (component: {}, trace: {})",
            self.operation, self.held_profile, self.component, self.trace_id
        )
    }
}

impl std::error::Error for RemoteCapabilityDenied {}

// ---------------------------------------------------------------------------
// RemoteGateEvent — structured audit event
// ---------------------------------------------------------------------------

/// Structured event emitted for remote operation gate decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteGateEvent {
    /// Trace identifier for correlation.
    pub trace_id: String,
    /// Component that requested the operation.
    pub component: String,
    /// Type of remote operation.
    pub operation_type: String,
    /// Sanitized remote endpoint (no credentials, IPs may be masked).
    pub remote_endpoint: String,
    /// Security epoch at time of decision.
    pub epoch_id: u64,
    /// Virtual timestamp.
    pub timestamp_ticks: u64,
    /// Outcome: "permitted" or "denied".
    pub outcome: String,
    /// Held profile kind.
    pub held_profile: String,
}

// ---------------------------------------------------------------------------
// RemoteOperationGate
// ---------------------------------------------------------------------------

/// Gate that enforces `RemoteCaps` before any remote operation.
///
/// All network-touching code must route through this gate. Attempts
/// without the required capability are rejected and logged.
#[derive(Debug)]
pub struct RemoteOperationGate {
    /// Current security epoch (remote ops must hold an epoch guard).
    current_epoch: SecurityEpoch,
    /// Accumulated audit events.
    events: Vec<RemoteGateEvent>,
    /// Counters by operation type.
    permitted_counts: BTreeMap<String, u64>,
    denied_counts: BTreeMap<String, u64>,
}

impl RemoteOperationGate {
    /// Create a new gate bound to the given security epoch.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            current_epoch: epoch,
            events: Vec::new(),
            permitted_counts: BTreeMap::new(),
            denied_counts: BTreeMap::new(),
        }
    }

    /// Current epoch this gate is bound to.
    pub fn epoch(&self) -> SecurityEpoch {
        self.current_epoch
    }

    /// Check whether a remote operation is permitted under the given profile.
    ///
    /// Returns `Ok(())` if the profile grants all required remote capabilities,
    /// or `Err(RemoteCapabilityDenied)` otherwise.
    pub fn check(
        &mut self,
        profile: &CapabilityProfile,
        operation: RemoteOperationType,
        component: &str,
        remote_endpoint: &str,
        trace_id: &str,
        timestamp_ticks: u64,
    ) -> Result<(), RemoteCapabilityDenied> {
        let required = required_capabilities(&operation);
        let all_granted = required.iter().all(|cap| profile.has(*cap));

        let op_str = operation.to_string();
        let sanitized_endpoint = sanitize_endpoint(remote_endpoint);

        if all_granted {
            *self.permitted_counts.entry(op_str.clone()).or_insert(0) += 1;
            self.events.push(RemoteGateEvent {
                trace_id: trace_id.to_string(),
                component: component.to_string(),
                operation_type: op_str,
                remote_endpoint: sanitized_endpoint,
                epoch_id: self.current_epoch.as_u64(),
                timestamp_ticks,
                outcome: "permitted".to_string(),
                held_profile: profile.kind().to_string(),
            });
            Ok(())
        } else {
            *self.denied_counts.entry(op_str.clone()).or_insert(0) += 1;
            self.events.push(RemoteGateEvent {
                trace_id: trace_id.to_string(),
                component: component.to_string(),
                operation_type: op_str,
                remote_endpoint: sanitized_endpoint,
                epoch_id: self.current_epoch.as_u64(),
                timestamp_ticks,
                outcome: "denied".to_string(),
                held_profile: profile.kind().to_string(),
            });
            Err(RemoteCapabilityDenied {
                operation,
                component: component.to_string(),
                held_profile: profile.kind(),
                required_capabilities: required,
                trace_id: trace_id.to_string(),
            })
        }
    }

    /// Drain accumulated audit events.
    pub fn drain_events(&mut self) -> Vec<RemoteGateEvent> {
        std::mem::take(&mut self.events)
    }

    /// Total number of permitted operations.
    pub fn total_permitted(&self) -> u64 {
        self.permitted_counts.values().sum()
    }

    /// Total number of denied operations.
    pub fn total_denied(&self) -> u64 {
        self.denied_counts.values().sum()
    }

    /// Per-operation-type permitted counts.
    pub fn permitted_counts(&self) -> &BTreeMap<String, u64> {
        &self.permitted_counts
    }

    /// Per-operation-type denied counts.
    pub fn denied_counts(&self) -> &BTreeMap<String, u64> {
        &self.denied_counts
    }
}

// ---------------------------------------------------------------------------
// RemoteTransport — trait for network operations
// ---------------------------------------------------------------------------

/// Trait for remote transport operations. All network-touching code must
/// implement this trait and pass through a `RemoteOperationGate`.
///
/// Implementations must not perform any network I/O outside of this trait's
/// methods.
pub trait RemoteTransport {
    /// Execute a remote operation, returning the response as bytes.
    ///
    /// The gate check must be performed before calling this method.
    fn execute(
        &mut self,
        operation: &RemoteOperationType,
        endpoint: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, RemoteTransportError>;
}

/// Error from remote transport execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteTransportError {
    /// Connection refused or unreachable.
    ConnectionFailed { endpoint: String, reason: String },
    /// Remote endpoint returned an error.
    RemoteError { status: u32, message: String },
    /// Operation timed out.
    Timeout { endpoint: String, duration_ms: u64 },
    /// Capability gate denied the operation.
    CapabilityDenied(RemoteCapabilityDenied),
}

impl fmt::Display for RemoteTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionFailed { endpoint, reason } => {
                write!(f, "connection failed to {endpoint}: {reason}")
            }
            Self::RemoteError { status, message } => {
                write!(f, "remote error {status}: {message}")
            }
            Self::Timeout {
                endpoint,
                duration_ms,
            } => write!(f, "timeout after {duration_ms}ms to {endpoint}"),
            Self::CapabilityDenied(denied) => write!(f, "{denied}"),
        }
    }
}

impl std::error::Error for RemoteTransportError {}

// ---------------------------------------------------------------------------
// MockRemoteTransport — test double
// ---------------------------------------------------------------------------

/// Mock transport that records operations without actual network I/O.
#[derive(Debug, Default)]
pub struct MockRemoteTransport {
    /// Recorded operations.
    pub recorded: Vec<RecordedOperation>,
    /// Canned response to return for all operations.
    pub response: Vec<u8>,
    /// If set, all operations will fail with this error.
    pub fail_with: Option<RemoteTransportError>,
}

/// A recorded operation from the mock transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedOperation {
    pub operation: RemoteOperationType,
    pub endpoint: String,
    pub payload: Vec<u8>,
}

impl RemoteTransport for MockRemoteTransport {
    fn execute(
        &mut self,
        operation: &RemoteOperationType,
        endpoint: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, RemoteTransportError> {
        self.recorded.push(RecordedOperation {
            operation: operation.clone(),
            endpoint: endpoint.to_string(),
            payload: payload.to_vec(),
        });

        if let Some(ref err) = self.fail_with {
            return Err(err.clone());
        }

        Ok(self.response.clone())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Determine which capabilities are required for a given operation type.
fn required_capabilities(operation: &RemoteOperationType) -> Vec<RuntimeCapability> {
    match operation {
        RemoteOperationType::HttpRequest | RemoteOperationType::GrpcCall => {
            vec![RuntimeCapability::NetworkEgress]
        }
        RemoteOperationType::DnsResolution => {
            vec![RuntimeCapability::NetworkEgress]
        }
        RemoteOperationType::DistributedStateMutation => {
            vec![RuntimeCapability::NetworkEgress]
        }
        RemoteOperationType::LeaseRenewal => {
            vec![
                RuntimeCapability::NetworkEgress,
                RuntimeCapability::LeaseManagement,
            ]
        }
        RemoteOperationType::RemoteIpc => {
            vec![RuntimeCapability::NetworkEgress]
        }
    }
}

/// Sanitize a remote endpoint for logging (remove credentials, mask IPs).
fn sanitize_endpoint(endpoint: &str) -> String {
    // Strip userinfo from URLs (scheme://user:pass@host -> scheme://***@host).
    if let Some(scheme_end) = endpoint.find("://") {
        let after_scheme = &endpoint[scheme_end + 3..];
        if let Some(at_pos) = after_scheme.find('@') {
            let host_part = &after_scheme[at_pos..];
            return format!("{}://***{host_part}", &endpoint[..scheme_end]);
        }
    }
    endpoint.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::CapabilityProfile;

    fn remote_profile() -> CapabilityProfile {
        CapabilityProfile::remote()
    }

    fn compute_only_profile() -> CapabilityProfile {
        CapabilityProfile::compute_only()
    }

    fn engine_core_profile() -> CapabilityProfile {
        CapabilityProfile::engine_core()
    }

    fn full_profile() -> CapabilityProfile {
        CapabilityProfile::full()
    }

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    // -- Gate permits with RemoteCaps --

    #[test]
    fn remote_profile_permits_http() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        assert!(
            gate.check(
                &remote_profile(),
                RemoteOperationType::HttpRequest,
                "sync",
                "https://example.com/api",
                "trace-1",
                100
            )
            .is_ok()
        );
    }

    #[test]
    fn remote_profile_permits_grpc() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        assert!(
            gate.check(
                &remote_profile(),
                RemoteOperationType::GrpcCall,
                "rpc",
                "grpc://node:50051",
                "trace-2",
                200
            )
            .is_ok()
        );
    }

    #[test]
    fn remote_profile_permits_dns() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        assert!(
            gate.check(
                &remote_profile(),
                RemoteOperationType::DnsResolution,
                "resolver",
                "dns://8.8.8.8",
                "trace-3",
                300
            )
            .is_ok()
        );
    }

    #[test]
    fn full_profile_permits_all_remote_ops() {
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
                gate.check(&full_profile(), op.clone(), "test", "endpoint", "t", 0)
                    .is_ok(),
                "full profile should permit {op}"
            );
        }
    }

    // -- Gate denies without RemoteCaps --

    #[test]
    fn compute_only_denies_http() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let err = gate
            .check(
                &compute_only_profile(),
                RemoteOperationType::HttpRequest,
                "compute",
                "https://evil.com",
                "trace-x",
                100,
            )
            .unwrap_err();
        assert_eq!(err.operation, RemoteOperationType::HttpRequest);
        assert_eq!(err.held_profile, ProfileKind::ComputeOnly);
    }

    #[test]
    fn engine_core_denies_grpc() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let err = gate
            .check(
                &engine_core_profile(),
                RemoteOperationType::GrpcCall,
                "engine",
                "grpc://host",
                "trace-y",
                200,
            )
            .unwrap_err();
        assert_eq!(err.operation, RemoteOperationType::GrpcCall);
        assert_eq!(err.held_profile, ProfileKind::EngineCore);
    }

    #[test]
    fn compute_only_denies_dns() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        assert!(
            gate.check(
                &compute_only_profile(),
                RemoteOperationType::DnsResolution,
                "resolver",
                "dns://8.8.8.8",
                "trace-z",
                300
            )
            .is_err()
        );
    }

    #[test]
    fn compute_only_denies_all_remote_ops() {
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
                gate.check(
                    &compute_only_profile(),
                    op.clone(),
                    "test",
                    "endpoint",
                    "t",
                    0
                )
                .is_err(),
                "compute-only should deny {op}"
            );
        }
    }

    // -- Audit events --

    #[test]
    fn permitted_emits_event() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "sync",
            "https://example.com",
            "trace-1",
            100,
        )
        .expect("serde deserialization should succeed");

        let events = gate.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "permitted");
        assert_eq!(events[0].operation_type, "http_request");
        assert_eq!(events[0].trace_id, "trace-1");
    }

    #[test]
    fn denied_emits_event() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let _ = gate.check(
            &compute_only_profile(),
            RemoteOperationType::HttpRequest,
            "compute",
            "https://evil.com",
            "trace-x",
            200,
        );

        let events = gate.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, "denied");
        assert_eq!(events[0].held_profile, "ComputeOnlyCaps");
    }

    #[test]
    fn drain_events_clears() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "s",
            "e",
            "t",
            0,
        )
        .expect("serde deserialization should succeed");
        let e1 = gate.drain_events();
        assert_eq!(e1.len(), 1);
        let e2 = gate.drain_events();
        assert!(e2.is_empty());
    }

    // -- Counters --

    #[test]
    fn counters_track_permits_and_denials() {
        let mut gate = RemoteOperationGate::new(test_epoch());

        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "s",
            "e",
            "t1",
            0,
        )
        .expect("serde deserialization should succeed");
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "s",
            "e",
            "t2",
            0,
        )
        .expect("serde deserialization should succeed");
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

    // -- Endpoint sanitization --

    #[test]
    fn sanitize_strips_credentials() {
        assert_eq!(
            sanitize_endpoint("https://user:password@example.com/path"),
            "https://***@example.com/path"
        );
    }

    #[test]
    fn sanitize_preserves_clean_url() {
        assert_eq!(
            sanitize_endpoint("https://example.com/path"),
            "https://example.com/path"
        );
    }

    #[test]
    fn sanitize_preserves_non_url() {
        assert_eq!(sanitize_endpoint("some-endpoint"), "some-endpoint");
    }

    // -- Mock transport --

    #[test]
    fn mock_transport_records_operations() {
        let mut transport = MockRemoteTransport {
            response: b"ok".to_vec(),
            ..Default::default()
        };

        let result = transport
            .execute(
                &RemoteOperationType::HttpRequest,
                "https://example.com",
                b"payload",
            )
            .expect("serde deserialization should succeed");

        assert_eq!(result, b"ok");
        assert_eq!(transport.recorded.len(), 1);
        assert_eq!(
            transport.recorded[0].operation,
            RemoteOperationType::HttpRequest
        );
        assert_eq!(transport.recorded[0].endpoint, "https://example.com");
    }

    #[test]
    fn mock_transport_can_fail() {
        let mut transport = MockRemoteTransport {
            fail_with: Some(RemoteTransportError::Timeout {
                endpoint: "x".to_string(),
                duration_ms: 5000,
            }),
            ..Default::default()
        };

        let err = transport
            .execute(&RemoteOperationType::HttpRequest, "x", b"")
            .unwrap_err();
        assert!(matches!(err, RemoteTransportError::Timeout { .. }));
    }

    // -- Required capabilities --

    #[test]
    fn lease_renewal_requires_two_capabilities() {
        let caps = required_capabilities(&RemoteOperationType::LeaseRenewal);
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&RuntimeCapability::NetworkEgress));
        assert!(caps.contains(&RuntimeCapability::LeaseManagement));
    }

    #[test]
    fn http_requires_network_egress() {
        let caps = required_capabilities(&RemoteOperationType::HttpRequest);
        assert_eq!(caps, vec![RuntimeCapability::NetworkEgress]);
    }

    // -- Serialization --

    #[test]
    fn denied_error_serialization_round_trip() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::HttpRequest,
            component: "test".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "trace-1".to_string(),
        };
        let json = serde_json::to_string(&denied).expect("serde deserialization should succeed");
        let restored: RemoteCapabilityDenied =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(denied, restored);
    }

    #[test]
    fn gate_event_serialization_round_trip() {
        let event = RemoteGateEvent {
            trace_id: "t".to_string(),
            component: "c".to_string(),
            operation_type: "http_request".to_string(),
            remote_endpoint: "e".to_string(),
            epoch_id: 1,
            timestamp_ticks: 100,
            outcome: "permitted".to_string(),
            held_profile: "RemoteCaps".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let restored: RemoteGateEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, restored);
    }

    #[test]
    fn transport_error_serialization_round_trip() {
        let errors = vec![
            RemoteTransportError::ConnectionFailed {
                endpoint: "x".to_string(),
                reason: "refused".to_string(),
            },
            RemoteTransportError::Timeout {
                endpoint: "y".to_string(),
                duration_ms: 5000,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serde deserialization should succeed");
            let restored: RemoteTransportError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*err, restored);
        }
    }

    // -- Display --

    #[test]
    fn denied_error_display() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::HttpRequest,
            component: "sync".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "trace-1".to_string(),
        };
        let msg = denied.to_string();
        assert!(msg.contains("http_request"));
        assert!(msg.contains("ComputeOnlyCaps"));
        assert!(msg.contains("sync"));
    }

    // -- Enrichment: serde, std::error --

    #[test]
    fn remote_operation_type_serde_all_variants() {
        let all = [
            RemoteOperationType::HttpRequest,
            RemoteOperationType::GrpcCall,
            RemoteOperationType::DnsResolution,
            RemoteOperationType::DistributedStateMutation,
            RemoteOperationType::LeaseRenewal,
            RemoteOperationType::RemoteIpc,
        ];
        for op in &all {
            let json = serde_json::to_string(op).expect("serde deserialization should succeed");
            let restored: RemoteOperationType =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*op, restored);
        }
    }

    #[test]
    fn remote_transport_error_implements_std_error() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::HttpRequest,
            component: "test".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "t-1".to_string(),
        };
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(RemoteTransportError::ConnectionFailed {
                endpoint: "http://localhost".into(),
                reason: "refused".into(),
            }),
            Box::new(RemoteTransportError::RemoteError {
                status: 500,
                message: "internal".into(),
            }),
            Box::new(RemoteTransportError::Timeout {
                endpoint: "http://localhost".into(),
                duration_ms: 5000,
            }),
            Box::new(RemoteTransportError::CapabilityDenied(denied)),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 variants produce distinct messages"
        );
    }

    #[test]
    fn operation_type_display() {
        assert_eq!(RemoteOperationType::HttpRequest.to_string(), "http_request");
        assert_eq!(
            RemoteOperationType::DistributedStateMutation.to_string(),
            "distributed_state_mutation"
        );
    }

    // -- Enrichment: gate starts empty --

    #[test]
    fn gate_starts_empty() {
        let gate = RemoteOperationGate::new(test_epoch());
        assert_eq!(gate.total_permitted(), 0);
        assert_eq!(gate.total_denied(), 0);
        assert!(gate.permitted_counts().is_empty());
        assert!(gate.denied_counts().is_empty());
    }

    #[test]
    fn gate_epoch_accessor() {
        let epoch = SecurityEpoch::from_raw(42);
        let gate = RemoteOperationGate::new(epoch);
        assert_eq!(gate.epoch(), epoch);
    }

    // -- Enrichment: transport error display all variants --

    #[test]
    fn transport_error_display_all_variants() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::HttpRequest,
            component: "test".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "t".to_string(),
        };
        let errors: Vec<RemoteTransportError> = vec![
            RemoteTransportError::ConnectionFailed {
                endpoint: "http://host".to_string(),
                reason: "refused".to_string(),
            },
            RemoteTransportError::RemoteError {
                status: 503,
                message: "service unavailable".to_string(),
            },
            RemoteTransportError::Timeout {
                endpoint: "http://host".to_string(),
                duration_ms: 3000,
            },
            RemoteTransportError::CapabilityDenied(denied),
        ];
        assert_eq!(
            errors.len(),
            4,
            "must cover all RemoteTransportError variants"
        );
        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty());
        }
        assert!(errors[0].to_string().contains("refused"));
        assert!(errors[1].to_string().contains("503"));
        assert!(errors[2].to_string().contains("3000"));
        assert!(errors[3].to_string().contains("http_request"));
    }

    // -- Enrichment: denied error is std::error --

    #[test]
    fn remote_capability_denied_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(RemoteCapabilityDenied {
            operation: RemoteOperationType::GrpcCall,
            component: "test".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "t".to_string(),
        });
        assert!(!err.to_string().is_empty());
    }

    // -- Enrichment: mock transport default --

    #[test]
    fn mock_remote_transport_default_empty() {
        let transport = MockRemoteTransport::default();
        assert!(transport.recorded.is_empty());
        assert!(transport.response.is_empty());
        assert!(transport.fail_with.is_none());
    }

    // -- Enrichment: operation type ordering --

    #[test]
    fn operation_type_ordering_deterministic() {
        let mut ops = [
            RemoteOperationType::RemoteIpc,
            RemoteOperationType::HttpRequest,
            RemoteOperationType::DnsResolution,
        ];
        ops.sort();
        // HttpRequest < DnsResolution < RemoteIpc (derived Ord)
        assert_eq!(ops[0], RemoteOperationType::HttpRequest);
    }

    // -- Enrichment: display all operation types --

    #[test]
    fn operation_type_display_all_variants() {
        let all = [
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
        for (op, expected) in all {
            assert_eq!(op.to_string(), expected);
        }
    }

    // -- Enrichment: remote error serde --

    #[test]
    fn remote_error_serde_roundtrip() {
        let err = RemoteTransportError::RemoteError {
            status: 500,
            message: "internal server error".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        let restored: RemoteTransportError =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(err, restored);
    }

    // -- Enrichment: sanitize no credentials --

    #[test]
    fn sanitize_no_at_sign_in_url() {
        assert_eq!(
            sanitize_endpoint("https://example.com:8080/path"),
            "https://example.com:8080/path"
        );
    }

    // -- Enrichment: counters per-type tracking --

    #[test]
    fn counters_track_multiple_operation_types() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "s",
            "e",
            "t1",
            0,
        )
        .expect("serde deserialization should succeed");
        gate.check(
            &remote_profile(),
            RemoteOperationType::GrpcCall,
            "s",
            "e",
            "t2",
            0,
        )
        .expect("serde deserialization should succeed");
        gate.check(
            &remote_profile(),
            RemoteOperationType::DnsResolution,
            "s",
            "e",
            "t3",
            0,
        )
        .expect("serde deserialization should succeed");

        assert_eq!(gate.total_permitted(), 3);
        assert_eq!(gate.permitted_counts().len(), 3);
        assert_eq!(gate.permitted_counts().get("http_request"), Some(&1));
        assert_eq!(gate.permitted_counts().get("grpc_call"), Some(&1));
        assert_eq!(gate.permitted_counts().get("dns_resolution"), Some(&1));
    }

    // -- Enrichment batch 2: Display uniqueness, boundary, error --

    #[test]
    fn operation_type_display_uniqueness_btreeset() {
        use std::collections::BTreeSet;
        let all = [
            RemoteOperationType::HttpRequest,
            RemoteOperationType::GrpcCall,
            RemoteOperationType::DnsResolution,
            RemoteOperationType::DistributedStateMutation,
            RemoteOperationType::LeaseRenewal,
            RemoteOperationType::RemoteIpc,
        ];
        let set: BTreeSet<String> = all.iter().map(|o| o.to_string()).collect();
        assert_eq!(
            set.len(),
            all.len(),
            "all RemoteOperationType Display strings must be unique"
        );
    }

    #[test]
    fn remote_capability_denied_display_contains_trace_id() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::DnsResolution,
            component: "resolver".to_string(),
            held_profile: ProfileKind::EngineCore,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "trace-unique-456".to_string(),
        };
        let msg = denied.to_string();
        assert!(msg.contains("trace-unique-456"));
        assert!(msg.contains("dns_resolution"));
        assert!(msg.contains("resolver"));
    }

    #[test]
    fn sanitize_endpoint_handles_multiple_at_signs() {
        // Only the first @ should be used for stripping credentials.
        let result = sanitize_endpoint("https://user:pass@host@extra/path");
        assert_eq!(result, "https://***@host@extra/path");
    }

    #[test]
    fn sanitize_endpoint_empty_string() {
        assert_eq!(sanitize_endpoint(""), "");
    }

    #[test]
    fn gate_event_sanitized_endpoint_recorded() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "sync",
            "https://user:pw@host.com/api",
            "t-1",
            100,
        )
        .expect("serde deserialization should succeed");

        let events = gate.drain_events();
        assert_eq!(events[0].remote_endpoint, "https://***@host.com/api");
    }

    #[test]
    fn gate_event_epoch_id_matches() {
        let epoch = SecurityEpoch::from_raw(77);
        let mut gate = RemoteOperationGate::new(epoch);
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "s",
            "e",
            "t",
            500,
        )
        .expect("serde deserialization should succeed");

        let events = gate.drain_events();
        assert_eq!(events[0].epoch_id, 77);
        assert_eq!(events[0].timestamp_ticks, 500);
    }

    #[test]
    fn transport_error_capability_denied_variant_serde() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::GrpcCall,
            component: "rpc".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "t".to_string(),
        };
        let err = RemoteTransportError::CapabilityDenied(denied);
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        let restored: RemoteTransportError =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(err, restored);
    }

    #[test]
    fn mock_transport_records_multiple_operations() {
        let mut transport = MockRemoteTransport {
            response: b"ok".to_vec(),
            ..Default::default()
        };

        transport
            .execute(&RemoteOperationType::HttpRequest, "http://a", b"1")
            .expect("serde deserialization should succeed");
        transport
            .execute(&RemoteOperationType::GrpcCall, "grpc://b", b"2")
            .expect("serde deserialization should succeed");
        transport
            .execute(&RemoteOperationType::DnsResolution, "dns://c", b"3")
            .expect("serde deserialization should succeed");

        assert_eq!(transport.recorded.len(), 3);
        assert_eq!(transport.recorded[0].payload, b"1");
        assert_eq!(transport.recorded[1].endpoint, "grpc://b");
        assert_eq!(
            transport.recorded[2].operation,
            RemoteOperationType::DnsResolution
        );
    }

    // -- Enrichment batch 3: counters, serde, clone, display, edge cases --

    #[test]
    fn gate_new_has_zero_counters() {
        let gate = RemoteOperationGate::new(test_epoch());
        assert_eq!(gate.total_permitted(), 0);
        assert_eq!(gate.total_denied(), 0);
        assert!(gate.permitted_counts().is_empty());
        assert!(gate.denied_counts().is_empty());
    }

    #[test]
    fn gate_epoch_accessor_value_preserved() {
        let gate = RemoteOperationGate::new(SecurityEpoch::from_raw(99));
        assert_eq!(gate.epoch(), SecurityEpoch::from_raw(99));
    }

    #[test]
    fn gate_permitted_count_increments() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        for _ in 0..5 {
            gate.check(
                &remote_profile(),
                RemoteOperationType::HttpRequest,
                "c",
                "e",
                "t",
                0,
            )
            .expect("serde deserialization should succeed");
        }
        assert_eq!(gate.total_permitted(), 5);
        assert_eq!(gate.permitted_counts().get("http_request"), Some(&5));
    }

    #[test]
    fn gate_denied_count_increments() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let compute_only = CapabilityProfile::compute_only();
        for _ in 0..3 {
            let _ = gate.check(
                &compute_only,
                RemoteOperationType::GrpcCall,
                "c",
                "e",
                "t",
                0,
            );
        }
        assert_eq!(gate.total_denied(), 3);
        assert_eq!(gate.denied_counts().get("grpc_call"), Some(&3));
    }

    #[test]
    fn gate_mixed_operations_counts_per_type() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let profile = remote_profile();
        gate.check(&profile, RemoteOperationType::HttpRequest, "c", "e", "t", 0)
            .expect("serde deserialization should succeed");
        gate.check(&profile, RemoteOperationType::GrpcCall, "c", "e", "t", 0)
            .expect("serde deserialization should succeed");
        gate.check(&profile, RemoteOperationType::HttpRequest, "c", "e", "t", 0)
            .expect("serde deserialization should succeed");
        assert_eq!(gate.permitted_counts().get("http_request"), Some(&2));
        assert_eq!(gate.permitted_counts().get("grpc_call"), Some(&1));
        assert_eq!(gate.total_permitted(), 3);
    }

    #[test]
    fn drain_events_clears_buffer() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        gate.check(
            &remote_profile(),
            RemoteOperationType::DnsResolution,
            "c",
            "e",
            "t",
            0,
        )
        .expect("serde deserialization should succeed");
        let events = gate.drain_events();
        assert_eq!(events.len(), 1);
        let events2 = gate.drain_events();
        assert!(events2.is_empty());
    }

    #[test]
    fn remote_operation_type_display_all_unique() {
        use std::collections::BTreeSet;
        let ops = [
            RemoteOperationType::HttpRequest,
            RemoteOperationType::GrpcCall,
            RemoteOperationType::DnsResolution,
            RemoteOperationType::DistributedStateMutation,
            RemoteOperationType::LeaseRenewal,
            RemoteOperationType::RemoteIpc,
        ];
        let set: BTreeSet<String> = ops.iter().map(|o| o.to_string()).collect();
        assert_eq!(
            set.len(),
            6,
            "all RemoteOperationType displays must be unique"
        );
    }

    #[test]
    fn remote_operation_type_serde_all_six_variants() {
        let ops = [
            RemoteOperationType::HttpRequest,
            RemoteOperationType::GrpcCall,
            RemoteOperationType::DnsResolution,
            RemoteOperationType::DistributedStateMutation,
            RemoteOperationType::LeaseRenewal,
            RemoteOperationType::RemoteIpc,
        ];
        for op in &ops {
            let json = serde_json::to_string(op).expect("serde deserialization should succeed");
            let back: RemoteOperationType =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*op, back);
        }
    }

    #[test]
    fn remote_capability_denied_clone_eq() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::LeaseRenewal,
            component: "comp".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "t".to_string(),
        };
        let cloned = denied.clone();
        assert_eq!(denied, cloned);
    }

    #[test]
    fn remote_capability_denied_display_contains_fields() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::HttpRequest,
            component: "my_comp".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "trace-42".to_string(),
        };
        let s = denied.to_string();
        assert!(s.contains("http_request"));
        assert!(s.contains("my_comp"));
        assert!(s.contains("trace-42"));
    }

    #[test]
    fn remote_capability_denied_implements_std_error() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::HttpRequest,
            component: "c".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![],
            trace_id: "t".to_string(),
        };
        let _: &dyn std::error::Error = &denied;
    }

    #[test]
    fn remote_gate_event_serde_roundtrip() {
        let event = RemoteGateEvent {
            trace_id: "t".to_string(),
            component: "c".to_string(),
            operation_type: "http_request".to_string(),
            remote_endpoint: "https://host/api".to_string(),
            epoch_id: 5,
            timestamp_ticks: 100,
            outcome: "permitted".to_string(),
            held_profile: "Remote".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let back: RemoteGateEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, back);
    }

    #[test]
    fn remote_gate_event_json_field_presence() {
        let event = RemoteGateEvent {
            trace_id: "t".to_string(),
            component: "c".to_string(),
            operation_type: "http_request".to_string(),
            remote_endpoint: "ep".to_string(),
            epoch_id: 1,
            timestamp_ticks: 0,
            outcome: "denied".to_string(),
            held_profile: "ComputeOnly".to_string(),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"operation_type\""));
        assert!(json.contains("\"remote_endpoint\""));
        assert!(json.contains("\"epoch_id\""));
        assert!(json.contains("\"outcome\""));
    }

    #[test]
    fn gate_denied_event_outcome_is_denied() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let _ = gate.check(
            &CapabilityProfile::compute_only(),
            RemoteOperationType::HttpRequest,
            "c",
            "e",
            "t",
            0,
        );
        let events = gate.drain_events();
        assert_eq!(events[0].outcome, "denied");
    }

    #[test]
    fn gate_permitted_event_outcome_is_permitted() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        gate.check(
            &remote_profile(),
            RemoteOperationType::HttpRequest,
            "c",
            "e",
            "t",
            0,
        )
        .expect("serde deserialization should succeed");
        let events = gate.drain_events();
        assert_eq!(events[0].outcome, "permitted");
    }

    // -- Enrichment batch 4 --

    #[test]
    fn enrichment_policy_profile_denies_all_remote_ops() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let policy = CapabilityProfile::policy();
        let ops = [
            RemoteOperationType::HttpRequest,
            RemoteOperationType::GrpcCall,
            RemoteOperationType::DnsResolution,
            RemoteOperationType::DistributedStateMutation,
            RemoteOperationType::LeaseRenewal,
            RemoteOperationType::RemoteIpc,
        ];
        for op in ops {
            let result = gate.check(&policy, op.clone(), "policy_comp", "ep", "t", 0);
            assert!(result.is_err(), "PolicyCaps should deny {op}");
            let err = result.unwrap_err();
            assert_eq!(err.held_profile, ProfileKind::Policy);
        }
        assert_eq!(gate.total_denied(), 6);
        assert_eq!(gate.total_permitted(), 0);
    }

    #[test]
    fn enrichment_remote_operation_type_clone_eq() {
        let original = RemoteOperationType::DistributedStateMutation;
        let cloned = original.clone();
        assert_eq!(original, cloned);
        // Different variant is not equal
        assert_ne!(
            RemoteOperationType::HttpRequest,
            RemoteOperationType::GrpcCall
        );
    }

    #[test]
    fn enrichment_denied_json_field_presence() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::RemoteIpc,
            component: "ipc_handler".to_string(),
            held_profile: ProfileKind::EngineCore,
            required_capabilities: vec![RuntimeCapability::NetworkEgress],
            trace_id: "trace-json-check".to_string(),
        };
        let json = serde_json::to_string(&denied).expect("serde deserialization should succeed");
        assert!(json.contains("\"operation\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"held_profile\""));
        assert!(json.contains("\"required_capabilities\""));
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("ipc_handler"));
        assert!(json.contains("trace-json-check"));
    }

    #[test]
    fn enrichment_transport_error_clone_eq() {
        let err1 = RemoteTransportError::ConnectionFailed {
            endpoint: "http://a".to_string(),
            reason: "refused".to_string(),
        };
        let err2 = err1.clone();
        assert_eq!(err1, err2);

        let err3 = RemoteTransportError::RemoteError {
            status: 404,
            message: "not found".to_string(),
        };
        assert_ne!(err1, err3);
    }

    #[test]
    fn enrichment_recorded_operation_clone_eq() {
        let op = RecordedOperation {
            operation: RemoteOperationType::DnsResolution,
            endpoint: "dns://1.1.1.1".to_string(),
            payload: vec![1, 2, 3],
        };
        let cloned = op.clone();
        assert_eq!(op, cloned);

        let different = RecordedOperation {
            operation: RemoteOperationType::DnsResolution,
            endpoint: "dns://8.8.8.8".to_string(),
            payload: vec![1, 2, 3],
        };
        assert_ne!(op, different);
    }

    #[test]
    fn enrichment_remote_gate_event_clone_eq() {
        let event = RemoteGateEvent {
            trace_id: "t1".to_string(),
            component: "sync".to_string(),
            operation_type: "grpc_call".to_string(),
            remote_endpoint: "grpc://node".to_string(),
            epoch_id: 10,
            timestamp_ticks: 999,
            outcome: "permitted".to_string(),
            held_profile: "RemoteCaps".to_string(),
        };
        let cloned = event.clone();
        assert_eq!(event, cloned);
    }

    #[test]
    fn enrichment_sanitize_ftp_scheme_with_credentials() {
        assert_eq!(
            sanitize_endpoint("ftp://admin:secret@ftp.example.com/pub"),
            "ftp://***@ftp.example.com/pub"
        );
    }

    #[test]
    fn enrichment_sanitize_scheme_only_no_host() {
        // "abc://" has no '@', so returned as-is.
        assert_eq!(sanitize_endpoint("abc://"), "abc://");
    }

    #[test]
    fn enrichment_sanitize_no_scheme_with_at_sign() {
        // No "://" means the at-sign is not treated as userinfo separator.
        assert_eq!(sanitize_endpoint("user@host"), "user@host");
    }

    #[test]
    fn enrichment_gate_interleaved_permit_deny_events_ordering() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let remote = remote_profile();
        let compute = compute_only_profile();

        gate.check(
            &remote,
            RemoteOperationType::HttpRequest,
            "a",
            "e",
            "t1",
            10,
        )
        .expect("serde deserialization should succeed");
        let _ = gate.check(&compute, RemoteOperationType::GrpcCall, "b", "e", "t2", 20);
        gate.check(
            &remote,
            RemoteOperationType::DnsResolution,
            "c",
            "e",
            "t3",
            30,
        )
        .expect("serde deserialization should succeed");
        let _ = gate.check(
            &compute,
            RemoteOperationType::LeaseRenewal,
            "d",
            "e",
            "t4",
            40,
        );

        let events = gate.drain_events();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].outcome, "permitted");
        assert_eq!(events[0].trace_id, "t1");
        assert_eq!(events[1].outcome, "denied");
        assert_eq!(events[1].trace_id, "t2");
        assert_eq!(events[2].outcome, "permitted");
        assert_eq!(events[2].trace_id, "t3");
        assert_eq!(events[3].outcome, "denied");
        assert_eq!(events[3].trace_id, "t4");
    }

    #[test]
    fn enrichment_mock_transport_records_before_failing() {
        let mut transport = MockRemoteTransport {
            fail_with: Some(RemoteTransportError::ConnectionFailed {
                endpoint: "ep".to_string(),
                reason: "reset".to_string(),
            }),
            ..Default::default()
        };

        let _ = transport.execute(&RemoteOperationType::RemoteIpc, "ep", b"data");
        // Even on failure, the operation should be recorded.
        assert_eq!(transport.recorded.len(), 1);
        assert_eq!(
            transport.recorded[0].operation,
            RemoteOperationType::RemoteIpc
        );
        assert_eq!(transport.recorded[0].payload, b"data");
    }

    #[test]
    fn enrichment_required_capabilities_all_six_types() {
        let cases: Vec<(RemoteOperationType, usize)> = vec![
            (RemoteOperationType::HttpRequest, 1),
            (RemoteOperationType::GrpcCall, 1),
            (RemoteOperationType::DnsResolution, 1),
            (RemoteOperationType::DistributedStateMutation, 1),
            (RemoteOperationType::LeaseRenewal, 2),
            (RemoteOperationType::RemoteIpc, 1),
        ];
        for (op, expected_count) in cases {
            let caps = required_capabilities(&op);
            assert_eq!(
                caps.len(),
                expected_count,
                "{op} should require {expected_count} capabilities"
            );
            // All operations require NetworkEgress.
            assert!(
                caps.contains(&RuntimeCapability::NetworkEgress),
                "{op} must require NetworkEgress"
            );
        }
    }

    #[test]
    fn enrichment_denied_error_with_empty_required_capabilities() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::HttpRequest,
            component: "empty_caps".to_string(),
            held_profile: ProfileKind::ComputeOnly,
            required_capabilities: vec![],
            trace_id: "t-empty".to_string(),
        };
        let json = serde_json::to_string(&denied).expect("serde deserialization should succeed");
        let back: RemoteCapabilityDenied =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back.required_capabilities.len(), 0);
        // Display still works fine with empty capabilities.
        let msg = denied.to_string();
        assert!(msg.contains("http_request"));
    }

    #[test]
    fn enrichment_gate_event_component_field_matches_input() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        gate.check(
            &remote_profile(),
            RemoteOperationType::DistributedStateMutation,
            "anti_entropy_sync",
            "https://peer.local/sync",
            "t-comp",
            42,
        )
        .expect("serde deserialization should succeed");

        let events = gate.drain_events();
        assert_eq!(events[0].component, "anti_entropy_sync");
        assert_eq!(events[0].operation_type, "distributed_state_mutation");
    }

    #[test]
    fn enrichment_transport_error_connection_failed_serde() {
        let err = RemoteTransportError::ConnectionFailed {
            endpoint: "https://unreachable.example.com".to_string(),
            reason: "connection timed out".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serde deserialization should succeed");
        let back: RemoteTransportError =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(err, back);
        assert!(json.contains("unreachable.example.com"));
        assert!(json.contains("connection timed out"));
    }

    #[test]
    fn enrichment_multiple_denied_types_in_counters() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let compute = compute_only_profile();

        let _ = gate.check(&compute, RemoteOperationType::HttpRequest, "c", "e", "t", 0);
        let _ = gate.check(&compute, RemoteOperationType::HttpRequest, "c", "e", "t", 0);
        let _ = gate.check(&compute, RemoteOperationType::GrpcCall, "c", "e", "t", 0);
        let _ = gate.check(
            &compute,
            RemoteOperationType::DnsResolution,
            "c",
            "e",
            "t",
            0,
        );

        assert_eq!(gate.total_denied(), 4);
        assert_eq!(gate.denied_counts().get("http_request"), Some(&2));
        assert_eq!(gate.denied_counts().get("grpc_call"), Some(&1));
        assert_eq!(gate.denied_counts().get("dns_resolution"), Some(&1));
        assert_eq!(gate.total_permitted(), 0);
    }

    #[test]
    fn enrichment_denied_error_eq_reflexive() {
        let denied = RemoteCapabilityDenied {
            operation: RemoteOperationType::LeaseRenewal,
            component: "lease_mgr".to_string(),
            held_profile: ProfileKind::EngineCore,
            required_capabilities: vec![
                RuntimeCapability::NetworkEgress,
                RuntimeCapability::LeaseManagement,
            ],
            trace_id: "ref-check".to_string(),
        };
        assert_eq!(denied, denied.clone());
    }

    #[test]
    fn enrichment_gate_events_accumulate_across_checks() {
        let mut gate = RemoteOperationGate::new(test_epoch());
        let remote = remote_profile();
        let compute = compute_only_profile();

        // 3 permitted + 2 denied = 5 events total before drain.
        gate.check(&remote, RemoteOperationType::HttpRequest, "a", "e", "t1", 0)
            .expect("serde deserialization should succeed");
        gate.check(&remote, RemoteOperationType::GrpcCall, "a", "e", "t2", 0)
            .expect("serde deserialization should succeed");
        let _ = gate.check(
            &compute,
            RemoteOperationType::DnsResolution,
            "b",
            "e",
            "t3",
            0,
        );
        gate.check(&remote, RemoteOperationType::RemoteIpc, "a", "e", "t4", 0)
            .expect("serde deserialization should succeed");
        let _ = gate.check(
            &compute,
            RemoteOperationType::LeaseRenewal,
            "b",
            "e",
            "t5",
            0,
        );

        let events = gate.drain_events();
        assert_eq!(events.len(), 5);
        assert_eq!(gate.total_permitted(), 3);
        assert_eq!(gate.total_denied(), 2);
        // Counters persist after drain, only events buffer is cleared.
        assert_eq!(gate.total_permitted(), 3);
    }

    #[test]
    fn enrichment_operation_type_ord_all_pairs_comparable() {
        let ops = [
            RemoteOperationType::HttpRequest,
            RemoteOperationType::GrpcCall,
            RemoteOperationType::DnsResolution,
            RemoteOperationType::DistributedStateMutation,
            RemoteOperationType::LeaseRenewal,
            RemoteOperationType::RemoteIpc,
        ];
        // Verify Ord is total: every pair produces a defined ordering.
        for (i, a) in ops.iter().enumerate() {
            for (j, b) in ops.iter().enumerate() {
                let ord = a.cmp(b);
                if i == j {
                    assert_eq!(ord, std::cmp::Ordering::Equal);
                } else {
                    assert_ne!(ord, std::cmp::Ordering::Equal);
                }
            }
        }
    }
}
