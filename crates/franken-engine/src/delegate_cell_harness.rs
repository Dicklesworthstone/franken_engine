//! Delegate-cell runtime harness for not-yet-native slots.
//!
//! Provides the execution environment that treats delegate cells exactly like
//! untrusted extensions: capability-bounded, sentinel-monitored,
//! evidence-emitting, replay-audited.
//!
//! Key invariants:
//! - Delegate cells receive only capabilities declared in their authority
//!   envelope (no ambient authority).
//! - Resource limits (CPU, memory, I/O) are enforced per invocation.
//! - All inputs/outputs are captured for deterministic replay.
//! - Fault isolation: delegate failures never propagate to the host.
//! - Lifecycle follows the same protocol as extensions.
//!
//! All collections use `BTreeMap`/`BTreeSet` for deterministic iteration.
//! Fixed-point millionths (1_000_000 = 1.0) for deterministic arithmetic.
//!
//! Plan references: Section 10.15 item 2 (9I.6), bd-3ciq.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::self_replacement::{DelegateCellManifest, DelegateType, SandboxConfiguration};
use crate::slot_registry::{AuthorityEnvelope, SlotCapability, SlotId};

// ---------------------------------------------------------------------------
// CellLifecycle — lifecycle state machine
// ---------------------------------------------------------------------------

/// Lifecycle state of a delegate cell, mirroring extension lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CellLifecycle {
    /// Cell created but not yet started.
    Created,
    /// Cell is starting up (loading code, initializing).
    Starting,
    /// Cell is running and accepting invocations.
    Running,
    /// Cell is suspended (paused, not accepting invocations).
    Suspended,
    /// Cell is shutting down.
    Stopping,
    /// Cell has terminated (normal or error exit).
    Terminated,
    /// Cell is quarantined (security containment).
    Quarantined,
}

impl CellLifecycle {
    /// Whether the cell can accept new invocations.
    pub fn can_invoke(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Whether the cell is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminated | Self::Quarantined)
    }

    /// Valid transitions from current state.
    pub fn valid_transitions(&self) -> &'static [CellLifecycle] {
        match self {
            Self::Created => &[Self::Starting, Self::Terminated],
            Self::Starting => &[Self::Running, Self::Terminated],
            Self::Running => &[Self::Suspended, Self::Stopping, Self::Quarantined],
            Self::Suspended => &[Self::Running, Self::Stopping, Self::Quarantined],
            Self::Stopping => &[Self::Terminated],
            Self::Terminated => &[],
            Self::Quarantined => &[],
        }
    }

    /// Whether transitioning to `target` is valid.
    pub fn can_transition_to(&self, target: Self) -> bool {
        self.valid_transitions().contains(&target)
    }
}

impl fmt::Display for CellLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => f.write_str("created"),
            Self::Starting => f.write_str("starting"),
            Self::Running => f.write_str("running"),
            Self::Suspended => f.write_str("suspended"),
            Self::Stopping => f.write_str("stopping"),
            Self::Terminated => f.write_str("terminated"),
            Self::Quarantined => f.write_str("quarantined"),
        }
    }
}

// ---------------------------------------------------------------------------
// ResourceUsage — resource consumption tracking
// ---------------------------------------------------------------------------

/// Tracked resource consumption for a single invocation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Heap bytes allocated during invocation.
    pub heap_bytes_used: u64,
    /// Execution wall time in nanoseconds.
    pub execution_ns: u64,
    /// Number of hostcalls made.
    pub hostcall_count: u64,
    /// Bytes sent over network (if allowed).
    pub network_egress_bytes: u64,
    /// Bytes read from filesystem (if allowed).
    pub filesystem_read_bytes: u64,
}

impl ResourceUsage {
    /// Check whether usage exceeds the given sandbox limits.
    pub fn exceeds_limits(&self, sandbox: &SandboxConfiguration) -> Option<ResourceViolation> {
        if self.heap_bytes_used > sandbox.max_heap_bytes {
            return Some(ResourceViolation::HeapExceeded {
                used: self.heap_bytes_used,
                limit: sandbox.max_heap_bytes,
            });
        }
        if self.execution_ns > sandbox.max_execution_ns {
            return Some(ResourceViolation::ExecutionTimeExceeded {
                used_ns: self.execution_ns,
                limit_ns: sandbox.max_execution_ns,
            });
        }
        if self.hostcall_count > sandbox.max_hostcalls {
            return Some(ResourceViolation::HostcallLimitExceeded {
                count: self.hostcall_count,
                limit: sandbox.max_hostcalls,
            });
        }
        if !sandbox.network_egress_allowed && self.network_egress_bytes > 0 {
            return Some(ResourceViolation::NetworkEgressDenied {
                bytes: self.network_egress_bytes,
            });
        }
        if !sandbox.filesystem_access_allowed && self.filesystem_read_bytes > 0 {
            return Some(ResourceViolation::FilesystemAccessDenied {
                bytes: self.filesystem_read_bytes,
            });
        }
        None
    }
}

/// Specific resource violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceViolation {
    HeapExceeded { used: u64, limit: u64 },
    ExecutionTimeExceeded { used_ns: u64, limit_ns: u64 },
    HostcallLimitExceeded { count: u64, limit: u64 },
    NetworkEgressDenied { bytes: u64 },
    FilesystemAccessDenied { bytes: u64 },
}

impl fmt::Display for ResourceViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeapExceeded { used, limit } => {
                write!(f, "heap exceeded: {used} > {limit} bytes")
            }
            Self::ExecutionTimeExceeded { used_ns, limit_ns } => {
                write!(f, "execution time exceeded: {used_ns} > {limit_ns} ns")
            }
            Self::HostcallLimitExceeded { count, limit } => {
                write!(f, "hostcall limit exceeded: {count} > {limit}")
            }
            Self::NetworkEgressDenied { bytes } => {
                write!(f, "network egress denied: {bytes} bytes attempted")
            }
            Self::FilesystemAccessDenied { bytes } => {
                write!(f, "filesystem access denied: {bytes} bytes attempted")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// InvocationRecord — replay-auditable invocation record
// ---------------------------------------------------------------------------

/// Complete record of a delegate cell invocation for replay.
///
/// Contains everything needed to deterministically reproduce the invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationRecord {
    /// Monotonic invocation sequence number.
    pub sequence: u64,
    /// Input hash (content-addressed).
    pub input_hash: ContentHash,
    /// Output hash (content-addressed).
    pub output_hash: ContentHash,
    /// Deterministic seed used for this invocation.
    pub replay_seed: u64,
    /// Resource consumption.
    pub resource_usage: ResourceUsage,
    /// Outcome of the invocation.
    pub outcome: InvocationOutcome,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Duration (nanoseconds).
    pub duration_ns: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
}

/// Outcome of a delegate cell invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvocationOutcome {
    /// Invocation completed successfully.
    Success,
    /// Invocation failed with an error.
    Error { code: u32, message: String },
    /// Invocation exceeded resource limits.
    ResourceViolation(ResourceViolation),
    /// Invocation timed out.
    Timeout,
    /// Capability check failed.
    CapabilityDenied { capability: SlotCapability },
}

impl fmt::Display for InvocationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => f.write_str("success"),
            Self::Error { code, message } => write!(f, "error({code}): {message}"),
            Self::ResourceViolation(v) => write!(f, "resource_violation: {v}"),
            Self::Timeout => f.write_str("timeout"),
            Self::CapabilityDenied { capability } => {
                write!(f, "capability_denied: {capability:?}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PerformanceMetrics — instrumentation for delegate vs native comparison
// ---------------------------------------------------------------------------

/// Aggregated performance metrics for a delegate cell.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Total invocations.
    pub total_invocations: u64,
    /// Successful invocations.
    pub successful_invocations: u64,
    /// Failed invocations.
    pub failed_invocations: u64,
    /// Sum of all invocation durations (nanoseconds).
    pub total_duration_ns: u64,
    /// Minimum invocation duration (nanoseconds).
    pub min_duration_ns: u64,
    /// Maximum invocation duration (nanoseconds).
    pub max_duration_ns: u64,
    /// Sum of heap bytes used across invocations.
    pub total_heap_bytes: u64,
    /// Sum of hostcalls across invocations.
    pub total_hostcalls: u64,
}

impl PerformanceMetrics {
    /// Record an invocation's metrics.
    pub fn record(&mut self, record: &InvocationRecord) {
        self.total_invocations = self.total_invocations.saturating_add(1);
        match &record.outcome {
            InvocationOutcome::Success => {
                self.successful_invocations = self.successful_invocations.saturating_add(1);
            }
            _ => {
                self.failed_invocations = self.failed_invocations.saturating_add(1);
            }
        }
        self.total_duration_ns = self.total_duration_ns.saturating_add(record.duration_ns);
        if self.total_invocations == 1 && self.min_duration_ns == 0 {
            // First record on a fresh (default-initialized) struct.
            self.min_duration_ns = record.duration_ns;
            self.max_duration_ns = record.duration_ns;
        } else {
            if record.duration_ns < self.min_duration_ns || self.min_duration_ns == 0 {
                self.min_duration_ns = record.duration_ns;
            }
            if record.duration_ns > self.max_duration_ns {
                self.max_duration_ns = record.duration_ns;
            }
        }
        self.total_heap_bytes = self
            .total_heap_bytes
            .saturating_add(record.resource_usage.heap_bytes_used);
        self.total_hostcalls = self
            .total_hostcalls
            .saturating_add(record.resource_usage.hostcall_count);
    }

    /// Average invocation duration in nanoseconds (millionths for precision).
    pub fn avg_duration_millionths(&self) -> u64 {
        if self.total_invocations == 0 {
            return 0;
        }
        (self.total_duration_ns as u128 * 1_000_000 / self.total_invocations as u128) as u64
    }

    /// Success rate in millionths (1_000_000 = 100%).
    pub fn success_rate_millionths(&self) -> u64 {
        if self.total_invocations == 0 {
            return 0;
        }
        (self.successful_invocations as u128 * 1_000_000 / self.total_invocations as u128) as u64
    }
}

// ---------------------------------------------------------------------------
// HarnessEvent — structured telemetry for delegate cell operations
// ---------------------------------------------------------------------------

/// Structured event emitted by the delegate cell harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessEvent {
    /// Event type.
    pub event_type: HarnessEventType,
    /// Cell identifier (slot_id).
    pub cell_id: SlotId,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Structured fields.
    pub fields: BTreeMap<String, String>,
}

/// Types of harness events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HarnessEventType {
    /// Cell lifecycle transition.
    LifecycleTransition,
    /// Invocation started.
    InvocationStarted,
    /// Invocation completed.
    InvocationCompleted,
    /// Capability check performed.
    CapabilityCheck,
    /// Resource limit violation.
    ResourceViolation,
    /// Replay verification result.
    ReplayVerification,
}

impl fmt::Display for HarnessEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LifecycleTransition => f.write_str("lifecycle_transition"),
            Self::InvocationStarted => f.write_str("invocation_started"),
            Self::InvocationCompleted => f.write_str("invocation_completed"),
            Self::CapabilityCheck => f.write_str("capability_check"),
            Self::ResourceViolation => f.write_str("resource_violation"),
            Self::ReplayVerification => f.write_str("replay_verification"),
        }
    }
}

// ---------------------------------------------------------------------------
// DelegateCellHarness — main runtime harness
// ---------------------------------------------------------------------------

/// Runtime harness for a delegate cell.
///
/// Manages the full lifecycle of a delegate cell: capability enforcement,
/// resource tracking, replay recording, and performance instrumentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateCellHarness {
    /// Slot this delegate occupies.
    pub slot_id: SlotId,
    /// Delegate type.
    pub delegate_type: DelegateType,
    /// Current lifecycle state.
    pub lifecycle: CellLifecycle,
    /// Sandbox configuration.
    pub sandbox: SandboxConfiguration,
    /// Authority envelope (capability bounds).
    pub authority: AuthorityEnvelope,
    /// Invocation records for replay.
    invocation_log: Vec<InvocationRecord>,
    /// Maximum invocation log size before rotation.
    max_log_size: usize,
    /// Performance metrics.
    pub metrics: PerformanceMetrics,
    /// Monotonic invocation counter.
    invocation_counter: u64,
    /// Current security epoch.
    pub current_epoch: SecurityEpoch,
    /// Event log.
    pub events: Vec<HarnessEvent>,
    /// Maximum events to retain.
    max_events: usize,
    /// Expected behavior hash for replay verification.
    pub expected_behavior_hash: [u8; 32],
}

impl DelegateCellHarness {
    /// Create a harness from a delegate cell manifest.
    pub fn from_manifest(manifest: &DelegateCellManifest) -> Self {
        Self {
            slot_id: manifest.slot_id.clone(),
            delegate_type: manifest.delegate_type,
            lifecycle: CellLifecycle::Created,
            sandbox: manifest.sandbox.clone(),
            authority: manifest.capability_envelope.clone(),
            invocation_log: Vec::new(),
            max_log_size: 100_000,
            metrics: PerformanceMetrics::default(),
            invocation_counter: 0,
            current_epoch: SecurityEpoch::GENESIS,
            events: Vec::new(),
            max_events: 10_000,
            expected_behavior_hash: manifest.expected_behavior_hash,
        }
    }

    /// Create a harness with explicit parameters.
    pub fn new(
        slot_id: SlotId,
        delegate_type: DelegateType,
        sandbox: SandboxConfiguration,
        authority: AuthorityEnvelope,
        expected_behavior_hash: [u8; 32],
    ) -> Self {
        Self {
            slot_id,
            delegate_type,
            lifecycle: CellLifecycle::Created,
            sandbox,
            authority,
            invocation_log: Vec::new(),
            max_log_size: 100_000,
            metrics: PerformanceMetrics::default(),
            invocation_counter: 0,
            current_epoch: SecurityEpoch::GENESIS,
            events: Vec::new(),
            max_events: 10_000,
            expected_behavior_hash,
        }
    }

    fn emit_event(
        &mut self,
        event_type: HarnessEventType,
        timestamp_ns: u64,
        fields: BTreeMap<String, String>,
    ) {
        let event = HarnessEvent {
            event_type,
            cell_id: self.slot_id.clone(),
            timestamp_ns,
            fields,
        };
        self.events.push(event);
        if self.events.len() > self.max_events {
            self.events.remove(0);
        }
    }

    /// Transition the cell to a new lifecycle state.
    pub fn transition_to(
        &mut self,
        target: CellLifecycle,
        timestamp_ns: u64,
    ) -> Result<(), DelegateCellError> {
        if !self.lifecycle.can_transition_to(target) {
            return Err(DelegateCellError::InvalidTransition {
                from: self.lifecycle,
                to: target,
            });
        }

        let mut fields = BTreeMap::new();
        fields.insert("from".into(), self.lifecycle.to_string());
        fields.insert("to".into(), target.to_string());
        self.emit_event(HarnessEventType::LifecycleTransition, timestamp_ns, fields);

        self.lifecycle = target;
        Ok(())
    }

    /// Check whether a specific capability is permitted.
    pub fn check_capability(
        &mut self,
        capability: &SlotCapability,
        timestamp_ns: u64,
    ) -> Result<(), DelegateCellError> {
        let permitted = self.authority.permitted.contains(capability);

        let mut fields = BTreeMap::new();
        fields.insert("capability".into(), format!("{capability:?}"));
        fields.insert("permitted".into(), permitted.to_string());
        self.emit_event(HarnessEventType::CapabilityCheck, timestamp_ns, fields);

        if permitted {
            Ok(())
        } else {
            Err(DelegateCellError::CapabilityDenied {
                capability: *capability,
            })
        }
    }

    /// Record an invocation and check resource limits.
    ///
    /// Returns `Ok(())` if the invocation is within limits, or
    /// `Err(ResourceViolation)` if any limit was exceeded.
    pub fn record_invocation(
        &mut self,
        input: &[u8],
        output: &[u8],
        replay_seed: u64,
        resource_usage: ResourceUsage,
        duration_ns: u64,
        timestamp_ns: u64,
    ) -> Result<InvocationRecord, DelegateCellError> {
        if !self.lifecycle.can_invoke() {
            return Err(DelegateCellError::NotRunning {
                state: self.lifecycle,
            });
        }

        self.invocation_counter = self.invocation_counter.saturating_add(1);

        // Check resource limits.
        let outcome = if let Some(violation) = resource_usage.exceeds_limits(&self.sandbox) {
            let mut fields = BTreeMap::new();
            fields.insert("violation".into(), violation.to_string());
            self.emit_event(HarnessEventType::ResourceViolation, timestamp_ns, fields);
            InvocationOutcome::ResourceViolation(violation)
        } else {
            InvocationOutcome::Success
        };

        let record = InvocationRecord {
            sequence: self.invocation_counter,
            input_hash: ContentHash::compute(input),
            output_hash: ContentHash::compute(output),
            replay_seed,
            resource_usage,
            outcome,
            timestamp_ns,
            duration_ns,
            epoch: self.current_epoch,
        };

        // Update metrics.
        self.metrics.record(&record);

        // Emit completion event.
        let mut fields = BTreeMap::new();
        fields.insert("sequence".into(), record.sequence.to_string());
        fields.insert("outcome".into(), record.outcome.to_string());
        fields.insert("duration_ns".into(), duration_ns.to_string());
        self.emit_event(HarnessEventType::InvocationCompleted, timestamp_ns, fields);

        // Append to log with rotation.
        self.invocation_log.push(record.clone());
        if self.invocation_log.len() > self.max_log_size {
            self.invocation_log.remove(0);
        }

        Ok(record)
    }

    /// Verify replay: given the same inputs and seed, the output hash matches.
    pub fn verify_replay(
        &mut self,
        original: &InvocationRecord,
        replay_output: &[u8],
        timestamp_ns: u64,
    ) -> ReplayVerification {
        let replay_hash = ContentHash::compute(replay_output);
        let matches = replay_hash == original.output_hash;

        let mut fields = BTreeMap::new();
        fields.insert("sequence".into(), original.sequence.to_string());
        fields.insert("match".into(), matches.to_string());
        self.emit_event(HarnessEventType::ReplayVerification, timestamp_ns, fields);

        if matches {
            ReplayVerification::Match {
                sequence: original.sequence,
            }
        } else {
            ReplayVerification::Mismatch {
                sequence: original.sequence,
                expected_hash: original.output_hash,
                actual_hash: replay_hash,
            }
        }
    }

    /// Get the invocation log for replay.
    pub fn invocation_log(&self) -> &[InvocationRecord] {
        &self.invocation_log
    }

    /// Get invocation record by sequence number.
    pub fn get_invocation(&self, sequence: u64) -> Option<&InvocationRecord> {
        self.invocation_log.iter().find(|r| r.sequence == sequence)
    }

    /// Total invocations executed.
    pub fn invocation_count(&self) -> u64 {
        self.invocation_counter
    }

    /// Events of a specific type.
    pub fn events_of_type(&self, event_type: &HarnessEventType) -> Vec<&HarnessEvent> {
        self.events
            .iter()
            .filter(|e| &e.event_type == event_type)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ReplayVerification — result of replay check
// ---------------------------------------------------------------------------

/// Result of verifying a delegate cell replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayVerification {
    /// Replay output matches the original.
    Match { sequence: u64 },
    /// Replay output differs from the original.
    Mismatch {
        sequence: u64,
        expected_hash: ContentHash,
        actual_hash: ContentHash,
    },
}

// ---------------------------------------------------------------------------
// DelegateCellError — harness errors
// ---------------------------------------------------------------------------

/// Errors from delegate cell harness operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegateCellError {
    /// Invalid lifecycle state transition.
    InvalidTransition {
        from: CellLifecycle,
        to: CellLifecycle,
    },
    /// Cell is not in a running state for invocation.
    NotRunning { state: CellLifecycle },
    /// Requested capability is not in the authority envelope.
    CapabilityDenied { capability: SlotCapability },
    /// Resource limit violation during invocation.
    ResourceLimitExceeded(ResourceViolation),
}

impl fmt::Display for DelegateCellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid transition: {from} -> {to}")
            }
            Self::NotRunning { state } => {
                write!(f, "cell not running (state: {state})")
            }
            Self::CapabilityDenied { capability } => {
                write!(f, "capability denied: {capability:?}")
            }
            Self::ResourceLimitExceeded(v) => {
                write!(f, "resource limit exceeded: {v}")
            }
        }
    }
}

impl std::error::Error for DelegateCellError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    // -- Test helpers --

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

    // -- CellLifecycle tests --

    #[test]
    fn lifecycle_created_can_start() {
        let state = CellLifecycle::Created;
        assert!(state.can_transition_to(CellLifecycle::Starting));
        assert!(state.can_transition_to(CellLifecycle::Terminated));
        assert!(!state.can_transition_to(CellLifecycle::Running));
    }

    #[test]
    fn lifecycle_running_transitions() {
        let state = CellLifecycle::Running;
        assert!(state.can_invoke());
        assert!(state.can_transition_to(CellLifecycle::Suspended));
        assert!(state.can_transition_to(CellLifecycle::Stopping));
        assert!(state.can_transition_to(CellLifecycle::Quarantined));
        assert!(!state.can_transition_to(CellLifecycle::Created));
    }

    #[test]
    fn lifecycle_terminal_states() {
        assert!(CellLifecycle::Terminated.is_terminal());
        assert!(CellLifecycle::Quarantined.is_terminal());
        assert!(!CellLifecycle::Running.is_terminal());
        assert!(!CellLifecycle::Suspended.is_terminal());
    }

    #[test]
    fn lifecycle_terminal_no_transitions() {
        assert!(CellLifecycle::Terminated.valid_transitions().is_empty());
        assert!(CellLifecycle::Quarantined.valid_transitions().is_empty());
    }

    #[test]
    fn lifecycle_display() {
        assert_eq!(CellLifecycle::Created.to_string(), "created");
        assert_eq!(CellLifecycle::Running.to_string(), "running");
        assert_eq!(CellLifecycle::Quarantined.to_string(), "quarantined");
    }

    #[test]
    fn lifecycle_serde_round_trip() {
        for state in [
            CellLifecycle::Created,
            CellLifecycle::Starting,
            CellLifecycle::Running,
            CellLifecycle::Suspended,
            CellLifecycle::Stopping,
            CellLifecycle::Terminated,
            CellLifecycle::Quarantined,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let decoded: CellLifecycle = serde_json::from_str(&json).unwrap();
            assert_eq!(state, decoded);
        }
    }

    // -- ResourceUsage tests --

    #[test]
    fn resource_usage_within_limits() {
        let usage = ok_usage();
        let sandbox = test_sandbox();
        assert!(usage.exceeds_limits(&sandbox).is_none());
    }

    #[test]
    fn resource_usage_heap_exceeded() {
        let usage = ResourceUsage {
            heap_bytes_used: 2_000_000,
            ..Default::default()
        };
        let sandbox = test_sandbox();
        let violation = usage.exceeds_limits(&sandbox).unwrap();
        assert!(matches!(violation, ResourceViolation::HeapExceeded { .. }));
    }

    #[test]
    fn resource_usage_execution_time_exceeded() {
        let usage = ResourceUsage {
            execution_ns: 200_000_000,
            ..Default::default()
        };
        let sandbox = test_sandbox();
        let violation = usage.exceeds_limits(&sandbox).unwrap();
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
        let sandbox = test_sandbox();
        let violation = usage.exceeds_limits(&sandbox).unwrap();
        assert!(matches!(
            violation,
            ResourceViolation::HostcallLimitExceeded { .. }
        ));
    }

    #[test]
    fn resource_usage_network_denied() {
        let usage = ResourceUsage {
            network_egress_bytes: 100,
            ..Default::default()
        };
        let sandbox = test_sandbox();
        assert!(!sandbox.network_egress_allowed);
        let violation = usage.exceeds_limits(&sandbox).unwrap();
        assert!(matches!(
            violation,
            ResourceViolation::NetworkEgressDenied { .. }
        ));
    }

    #[test]
    fn resource_usage_filesystem_denied() {
        let usage = ResourceUsage {
            filesystem_read_bytes: 100,
            ..Default::default()
        };
        let sandbox = test_sandbox();
        let violation = usage.exceeds_limits(&sandbox).unwrap();
        assert!(matches!(
            violation,
            ResourceViolation::FilesystemAccessDenied { .. }
        ));
    }

    #[test]
    fn resource_violation_display() {
        let v = ResourceViolation::HeapExceeded {
            used: 200,
            limit: 100,
        };
        assert!(v.to_string().contains("200"));
    }

    // -- DelegateCellHarness lifecycle tests --

    #[test]
    fn harness_initial_state() {
        let harness = test_harness();
        assert_eq!(harness.lifecycle, CellLifecycle::Created);
        assert_eq!(harness.invocation_count(), 0);
    }

    #[test]
    fn harness_valid_lifecycle_transitions() {
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
            .transition_to(CellLifecycle::Suspended, 3_000)
            .unwrap();
        assert_eq!(harness.lifecycle, CellLifecycle::Suspended);

        harness
            .transition_to(CellLifecycle::Running, 4_000)
            .unwrap();
        assert_eq!(harness.lifecycle, CellLifecycle::Running);

        harness
            .transition_to(CellLifecycle::Stopping, 5_000)
            .unwrap();
        harness
            .transition_to(CellLifecycle::Terminated, 6_000)
            .unwrap();
        assert!(harness.lifecycle.is_terminal());
    }

    #[test]
    fn harness_invalid_transition_error() {
        let mut harness = test_harness();
        let err = harness
            .transition_to(CellLifecycle::Running, 1_000)
            .unwrap_err();
        assert!(matches!(err, DelegateCellError::InvalidTransition { .. }));
    }

    #[test]
    fn harness_quarantine_transition() {
        let mut harness = running_harness();
        harness
            .transition_to(CellLifecycle::Quarantined, 10_000)
            .unwrap();
        assert!(harness.lifecycle.is_terminal());
    }

    // -- DelegateCellHarness capability tests --

    #[test]
    fn harness_check_permitted_capability() {
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
    }

    #[test]
    fn harness_check_denied_capability() {
        let mut harness = test_harness();
        let err = harness
            .check_capability(&SlotCapability::HeapAlloc, 1_000)
            .unwrap_err();
        assert!(matches!(err, DelegateCellError::CapabilityDenied { .. }));
    }

    #[test]
    fn harness_capability_events_emitted() {
        let mut harness = test_harness();
        harness
            .check_capability(&SlotCapability::ReadSource, 1_000)
            .unwrap();
        let events = harness.events_of_type(&HarnessEventType::CapabilityCheck);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fields.get("permitted").unwrap(), "true");
    }

    // -- DelegateCellHarness invocation tests --

    #[test]
    fn harness_invocation_requires_running() {
        let mut harness = test_harness();
        let err = harness
            .record_invocation(b"input", b"output", 42, ok_usage(), 1_000, 10_000)
            .unwrap_err();
        assert!(matches!(err, DelegateCellError::NotRunning { .. }));
    }

    #[test]
    fn harness_successful_invocation() {
        let mut harness = running_harness();
        let record = harness
            .record_invocation(b"input", b"output", 42, ok_usage(), 50_000, 10_000)
            .unwrap();

        assert_eq!(record.sequence, 1);
        assert_eq!(record.replay_seed, 42);
        assert!(matches!(record.outcome, InvocationOutcome::Success));
        assert_eq!(harness.invocation_count(), 1);
    }

    #[test]
    fn harness_invocation_monotonic_sequence() {
        let mut harness = running_harness();
        let r1 = harness
            .record_invocation(b"a", b"b", 1, ok_usage(), 100, 10_000)
            .unwrap();
        let r2 = harness
            .record_invocation(b"c", b"d", 2, ok_usage(), 200, 20_000)
            .unwrap();
        assert!(r2.sequence > r1.sequence);
    }

    #[test]
    fn harness_invocation_resource_violation_detected() {
        let mut harness = running_harness();
        let excessive = ResourceUsage {
            heap_bytes_used: 5_000_000, // Exceeds 1_000_000 limit.
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
    fn harness_invocation_log_accessible() {
        let mut harness = running_harness();
        harness
            .record_invocation(b"a", b"b", 1, ok_usage(), 100, 10_000)
            .unwrap();
        harness
            .record_invocation(b"c", b"d", 2, ok_usage(), 200, 20_000)
            .unwrap();

        assert_eq!(harness.invocation_log().len(), 2);
        assert!(harness.get_invocation(1).is_some());
        assert!(harness.get_invocation(2).is_some());
        assert!(harness.get_invocation(3).is_none());
    }

    // -- Replay verification tests --

    #[test]
    fn harness_replay_match() {
        let mut harness = running_harness();
        let record = harness
            .record_invocation(b"input", b"output", 42, ok_usage(), 100, 10_000)
            .unwrap();

        let result = harness.verify_replay(&record, b"output", 20_000);
        assert!(matches!(result, ReplayVerification::Match { .. }));
    }

    #[test]
    fn harness_replay_mismatch() {
        let mut harness = running_harness();
        let record = harness
            .record_invocation(b"input", b"output", 42, ok_usage(), 100, 10_000)
            .unwrap();

        let result = harness.verify_replay(&record, b"different-output", 20_000);
        assert!(matches!(result, ReplayVerification::Mismatch { .. }));
    }

    #[test]
    fn harness_replay_verification_emits_event() {
        let mut harness = running_harness();
        let record = harness
            .record_invocation(b"in", b"out", 1, ok_usage(), 100, 10_000)
            .unwrap();
        harness.verify_replay(&record, b"out", 20_000);

        let events = harness.events_of_type(&HarnessEventType::ReplayVerification);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].fields.get("match").unwrap(), "true");
    }

    // -- PerformanceMetrics tests --

    #[test]
    fn metrics_initially_empty() {
        let metrics = PerformanceMetrics::default();
        assert_eq!(metrics.total_invocations, 0);
        assert_eq!(metrics.avg_duration_millionths(), 0);
        assert_eq!(metrics.success_rate_millionths(), 0);
    }

    #[test]
    fn metrics_record_updates() {
        let mut harness = running_harness();
        harness
            .record_invocation(b"a", b"b", 1, ok_usage(), 1_000_000, 10_000)
            .unwrap();
        harness
            .record_invocation(b"c", b"d", 2, ok_usage(), 3_000_000, 20_000)
            .unwrap();

        assert_eq!(harness.metrics.total_invocations, 2);
        assert_eq!(harness.metrics.successful_invocations, 2);
        assert_eq!(harness.metrics.total_duration_ns, 4_000_000);
        assert_eq!(harness.metrics.min_duration_ns, 1_000_000);
        assert_eq!(harness.metrics.max_duration_ns, 3_000_000);
        // Avg: 2_000_000 ns -> 2_000_000 * 1_000_000 / 2 = 1_000_000_000_000
        assert_eq!(harness.metrics.avg_duration_millionths(), 2_000_000_000_000);
        assert_eq!(harness.metrics.success_rate_millionths(), 1_000_000);
    }

    #[test]
    fn metrics_failure_tracking() {
        let mut harness = running_harness();
        // One success.
        harness
            .record_invocation(b"a", b"b", 1, ok_usage(), 100, 10_000)
            .unwrap();
        // One resource violation (failure).
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
    fn metrics_serde_round_trip() {
        let metrics = PerformanceMetrics {
            total_invocations: 10,
            successful_invocations: 8,
            failed_invocations: 2,
            total_duration_ns: 1_000_000,
            min_duration_ns: 50_000,
            max_duration_ns: 200_000,
            total_heap_bytes: 5_000_000,
            total_hostcalls: 80,
        };
        let json = serde_json::to_string(&metrics).unwrap();
        let decoded: PerformanceMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(metrics, decoded);
    }

    // -- InvocationOutcome tests --

    #[test]
    fn invocation_outcome_display() {
        assert_eq!(InvocationOutcome::Success.to_string(), "success");
        assert_eq!(InvocationOutcome::Timeout.to_string(), "timeout");
    }

    #[test]
    fn invocation_outcome_serde_round_trip() {
        let outcomes = vec![
            InvocationOutcome::Success,
            InvocationOutcome::Error {
                code: 42,
                message: "test error".into(),
            },
            InvocationOutcome::Timeout,
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

    // -- DelegateCellError tests --

    #[test]
    fn error_display() {
        let err = DelegateCellError::InvalidTransition {
            from: CellLifecycle::Created,
            to: CellLifecycle::Running,
        };
        assert!(err.to_string().contains("created"));
        assert!(err.to_string().contains("running"));
    }

    #[test]
    fn error_serde_round_trip() {
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
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let decoded: DelegateCellError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, decoded);
        }
    }

    // -- ReplayVerification serde --

    #[test]
    fn replay_verification_serde_round_trip() {
        let rv = ReplayVerification::Match { sequence: 42 };
        let json = serde_json::to_string(&rv).unwrap();
        let decoded: ReplayVerification = serde_json::from_str(&json).unwrap();
        assert_eq!(rv, decoded);
    }

    // -- HarnessEvent serde --

    #[test]
    fn harness_event_serde_round_trip() {
        let event = HarnessEvent {
            event_type: HarnessEventType::InvocationCompleted,
            cell_id: test_slot_id(),
            timestamp_ns: 10_000,
            fields: {
                let mut m = BTreeMap::new();
                m.insert("key".into(), "value".into());
                m
            },
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: HarnessEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, decoded);
    }

    #[test]
    fn harness_event_type_display() {
        assert_eq!(
            HarnessEventType::LifecycleTransition.to_string(),
            "lifecycle_transition"
        );
        assert_eq!(
            HarnessEventType::InvocationCompleted.to_string(),
            "invocation_completed"
        );
    }

    // -- Integration tests --

    #[test]
    fn integration_full_lifecycle_with_invocations() {
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

        // Check metrics.
        assert_eq!(harness.metrics.total_invocations, 1);
        assert_eq!(harness.metrics.success_rate_millionths(), 1_000_000);

        // Suspend, resume, then stop.
        harness
            .transition_to(CellLifecycle::Suspended, 7_000)
            .unwrap();
        harness
            .transition_to(CellLifecycle::Running, 8_000)
            .unwrap();
        harness
            .transition_to(CellLifecycle::Stopping, 9_000)
            .unwrap();
        harness
            .transition_to(CellLifecycle::Terminated, 10_000)
            .unwrap();

        // Verify lifecycle events were emitted.
        let lifecycle_events = harness.events_of_type(&HarnessEventType::LifecycleTransition);
        assert_eq!(lifecycle_events.len(), 6); // Starting, Running, Suspended, Running, Stopping, Terminated
    }

    #[test]
    fn integration_resource_violation_triggers_failure() {
        let mut harness = running_harness();

        // Normal invocation.
        let r1 = harness
            .record_invocation(b"a", b"b", 1, ok_usage(), 100, 10_000)
            .unwrap();
        assert!(matches!(r1.outcome, InvocationOutcome::Success));

        // Excessive resource usage.
        let excessive = ResourceUsage {
            heap_bytes_used: 5_000_000,
            execution_ns: 200_000_000,
            hostcall_count: 200,
            network_egress_bytes: 0,
            filesystem_read_bytes: 0,
        };
        let r2 = harness
            .record_invocation(b"c", b"d", 2, excessive, 200_000_000, 20_000)
            .unwrap();
        assert!(matches!(
            r2.outcome,
            InvocationOutcome::ResourceViolation(_)
        ));

        // Resource violation events emitted.
        let violations = harness.events_of_type(&HarnessEventType::ResourceViolation);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn integration_deterministic_replay_contract() {
        let mut harness = running_harness();

        // Record two invocations with same inputs but different seeds.
        let r1 = harness
            .record_invocation(b"input-x", b"output-a", 100, ok_usage(), 100, 10_000)
            .unwrap();
        let r2 = harness
            .record_invocation(b"input-x", b"output-a", 200, ok_usage(), 100, 20_000)
            .unwrap();

        // Same output should verify against both.
        assert!(matches!(
            harness.verify_replay(&r1, b"output-a", 30_000),
            ReplayVerification::Match { .. }
        ));
        assert!(matches!(
            harness.verify_replay(&r2, b"output-a", 40_000),
            ReplayVerification::Match { .. }
        ));

        // Different output should fail.
        assert!(matches!(
            harness.verify_replay(&r1, b"output-b", 50_000),
            ReplayVerification::Mismatch { .. }
        ));
    }

    // -- Enrichment: Display uniqueness, serde, boundary, defaults --

    #[test]
    fn cell_lifecycle_display_all_unique() {
        let states = [
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
    fn harness_event_type_display_all_unique() {
        let types = [
            HarnessEventType::LifecycleTransition,
            HarnessEventType::InvocationCompleted,
            HarnessEventType::CapabilityCheck,
            HarnessEventType::ResourceViolation,
            HarnessEventType::ReplayVerification,
        ];
        let displays: BTreeSet<String> = types.iter().map(|t| t.to_string()).collect();
        assert_eq!(displays.len(), types.len());
    }

    #[test]
    fn delegate_cell_error_std_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(DelegateCellError::NotRunning {
            state: CellLifecycle::Suspended,
        });
        assert!(!err.to_string().is_empty());
    }

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
    fn resource_usage_serde_roundtrip() {
        let usage = ok_usage();
        let json = serde_json::to_string(&usage).unwrap();
        let back: ResourceUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(usage, back);
    }

    #[test]
    fn sandbox_configuration_serde_roundtrip() {
        let sandbox = test_sandbox();
        let json = serde_json::to_string(&sandbox).unwrap();
        let back: SandboxConfiguration = serde_json::from_str(&json).unwrap();
        assert_eq!(sandbox, back);
    }

    #[test]
    fn lifecycle_valid_transitions_non_empty_for_non_terminal() {
        for state in [
            CellLifecycle::Created,
            CellLifecycle::Starting,
            CellLifecycle::Running,
            CellLifecycle::Suspended,
            CellLifecycle::Stopping,
        ] {
            assert!(
                !state.valid_transitions().is_empty(),
                "{state} should have valid transitions"
            );
        }
    }

    #[test]
    fn harness_events_of_type_empty_for_unmatched() {
        let harness = test_harness();
        let events = harness.events_of_type(&HarnessEventType::ResourceViolation);
        assert!(events.is_empty());
    }

    // -- Enrichment: clone equality (5 tests) --

    #[test]
    fn enrichment_clone_eq_cell_lifecycle() {
        let a = CellLifecycle::Quarantined;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_resource_violation() {
        let a = ResourceViolation::HeapExceeded {
            used: 999,
            limit: 500,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_invocation_outcome() {
        let a = InvocationOutcome::Error {
            code: 7,
            message: "oops".into(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_harness_event() {
        let a = HarnessEvent {
            event_type: HarnessEventType::CapabilityCheck,
            cell_id: test_slot_id(),
            timestamp_ns: 42,
            fields: BTreeMap::new(),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn enrichment_clone_eq_replay_verification() {
        let a = ReplayVerification::Match { sequence: 17 };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- Enrichment: JSON field presence (3 tests) --

    #[test]
    fn enrichment_json_fields_resource_usage() {
        let usage = ok_usage();
        let json = serde_json::to_string(&usage).unwrap();
        assert!(json.contains("heap_bytes_used"));
        assert!(json.contains("execution_ns"));
        assert!(json.contains("hostcall_count"));
        assert!(json.contains("network_egress_bytes"));
        assert!(json.contains("filesystem_read_bytes"));
    }

    #[test]
    fn enrichment_json_fields_performance_metrics() {
        let metrics = PerformanceMetrics {
            total_invocations: 5,
            successful_invocations: 4,
            failed_invocations: 1,
            total_duration_ns: 100_000,
            min_duration_ns: 10_000,
            max_duration_ns: 50_000,
            total_heap_bytes: 2_000_000,
            total_hostcalls: 25,
        };
        let json = serde_json::to_string(&metrics).unwrap();
        assert!(json.contains("total_invocations"));
        assert!(json.contains("successful_invocations"));
        assert!(json.contains("min_duration_ns"));
        assert!(json.contains("total_hostcalls"));
    }

    #[test]
    fn enrichment_json_fields_harness_event() {
        let mut fields = BTreeMap::new();
        fields.insert("key1".into(), "val1".into());
        let event = HarnessEvent {
            event_type: HarnessEventType::InvocationStarted,
            cell_id: test_slot_id(),
            timestamp_ns: 999,
            fields,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("event_type"));
        assert!(json.contains("cell_id"));
        assert!(json.contains("timestamp_ns"));
        assert!(json.contains("key1"));
    }

    // -- Enrichment: serde roundtrip (1 test) --

    #[test]
    fn enrichment_serde_roundtrip_delegate_cell_harness() {
        let harness = test_harness();
        let json = serde_json::to_string(&harness).unwrap();
        let decoded: DelegateCellHarness = serde_json::from_str(&json).unwrap();
        assert_eq!(harness.slot_id, decoded.slot_id);
        assert_eq!(harness.lifecycle, decoded.lifecycle);
        assert_eq!(harness.metrics, decoded.metrics);
        assert_eq!(
            harness.expected_behavior_hash,
            decoded.expected_behavior_hash
        );
    }

    // -- Enrichment: Display uniqueness (1 test) --

    #[test]
    fn enrichment_resource_violation_display_all_unique() {
        let violations = [
            ResourceViolation::HeapExceeded { used: 1, limit: 0 },
            ResourceViolation::ExecutionTimeExceeded {
                used_ns: 1,
                limit_ns: 0,
            },
            ResourceViolation::HostcallLimitExceeded { count: 1, limit: 0 },
            ResourceViolation::NetworkEgressDenied { bytes: 1 },
            ResourceViolation::FilesystemAccessDenied { bytes: 1 },
        ];
        let displays: BTreeSet<String> = violations.iter().map(|v| v.to_string()).collect();
        assert_eq!(displays.len(), violations.len());
    }

    // -- Enrichment: boundary condition (1 test) --

    #[test]
    fn enrichment_boundary_resource_exactly_at_limit() {
        let sandbox = test_sandbox();
        // Usage exactly at every limit should NOT violate.
        let usage = ResourceUsage {
            heap_bytes_used: sandbox.max_heap_bytes,
            execution_ns: sandbox.max_execution_ns,
            hostcall_count: sandbox.max_hostcalls,
            network_egress_bytes: 0,
            filesystem_read_bytes: 0,
        };
        assert!(usage.exceeds_limits(&sandbox).is_none());
    }

    // -- Enrichment: Error source (1 test) --

    #[test]
    fn enrichment_delegate_cell_error_source_is_none() {
        use std::error::Error;
        let err = DelegateCellError::ResourceLimitExceeded(ResourceViolation::HeapExceeded {
            used: 10,
            limit: 5,
        });
        assert!(err.source().is_none());
    }

    // -- Enrichment batch 2: Hash, Copy, Ord, edge cases, serde variants --

    #[test]
    fn enrichment_cell_lifecycle_copy_semantics() {
        let a = CellLifecycle::Running;
        let b = a; // Copy
        let c = a; // still usable after copy
        assert_eq!(b, c);
        assert_eq!(a, CellLifecycle::Running);
    }

    #[test]
    fn enrichment_cell_lifecycle_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        CellLifecycle::Running.hash(&mut h1);
        CellLifecycle::Running.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn enrichment_cell_lifecycle_ord_ordering() {
        // Ord is derived, so variant declaration order determines ordering.
        assert!(CellLifecycle::Created < CellLifecycle::Starting);
        assert!(CellLifecycle::Starting < CellLifecycle::Running);
        assert!(CellLifecycle::Running < CellLifecycle::Suspended);
        assert!(CellLifecycle::Suspended < CellLifecycle::Stopping);
        assert!(CellLifecycle::Stopping < CellLifecycle::Terminated);
        assert!(CellLifecycle::Terminated < CellLifecycle::Quarantined);
    }

    #[test]
    fn enrichment_cell_lifecycle_can_invoke_only_running() {
        for state in [
            CellLifecycle::Created,
            CellLifecycle::Starting,
            CellLifecycle::Suspended,
            CellLifecycle::Stopping,
            CellLifecycle::Terminated,
            CellLifecycle::Quarantined,
        ] {
            assert!(!state.can_invoke(), "{state} should not allow invocation");
        }
        assert!(CellLifecycle::Running.can_invoke());
    }

    #[test]
    fn enrichment_suspended_can_resume_or_stop_or_quarantine() {
        let state = CellLifecycle::Suspended;
        assert!(state.can_transition_to(CellLifecycle::Running));
        assert!(state.can_transition_to(CellLifecycle::Stopping));
        assert!(state.can_transition_to(CellLifecycle::Quarantined));
        assert!(!state.can_transition_to(CellLifecycle::Created));
        assert!(!state.can_transition_to(CellLifecycle::Starting));
        assert!(!state.can_transition_to(CellLifecycle::Suspended));
    }

    #[test]
    fn enrichment_stopping_can_only_terminate() {
        let state = CellLifecycle::Stopping;
        assert_eq!(state.valid_transitions(), &[CellLifecycle::Terminated]);
        assert!(!state.is_terminal());
        assert!(!state.can_invoke());
    }

    #[test]
    fn enrichment_resource_violation_serde_all_variants() {
        let violations = vec![
            ResourceViolation::HeapExceeded {
                used: 2_000_000,
                limit: 1_000_000,
            },
            ResourceViolation::ExecutionTimeExceeded {
                used_ns: 500,
                limit_ns: 100,
            },
            ResourceViolation::HostcallLimitExceeded {
                count: 300,
                limit: 100,
            },
            ResourceViolation::NetworkEgressDenied { bytes: 4096 },
            ResourceViolation::FilesystemAccessDenied { bytes: 8192 },
        ];
        for v in &violations {
            let json = serde_json::to_string(v).unwrap();
            let decoded: ResourceViolation = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, decoded);
        }
    }

    #[test]
    fn enrichment_resource_violation_display_contains_numbers() {
        let v = ResourceViolation::ExecutionTimeExceeded {
            used_ns: 999,
            limit_ns: 100,
        };
        let s = v.to_string();
        assert!(s.contains("999"));
        assert!(s.contains("100"));

        let v2 = ResourceViolation::HostcallLimitExceeded {
            count: 55,
            limit: 10,
        };
        let s2 = v2.to_string();
        assert!(s2.contains("55"));
        assert!(s2.contains("10"));

        let v3 = ResourceViolation::NetworkEgressDenied { bytes: 777 };
        assert!(v3.to_string().contains("777"));

        let v4 = ResourceViolation::FilesystemAccessDenied { bytes: 333 };
        assert!(v4.to_string().contains("333"));
    }

    #[test]
    fn enrichment_invocation_outcome_display_error_variant() {
        let outcome = InvocationOutcome::Error {
            code: 42,
            message: "test error".into(),
        };
        let s = outcome.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("test error"));
    }

    #[test]
    fn enrichment_invocation_outcome_display_resource_violation() {
        let outcome = InvocationOutcome::ResourceViolation(ResourceViolation::HeapExceeded {
            used: 200,
            limit: 100,
        });
        let s = outcome.to_string();
        assert!(s.contains("resource_violation"));
        assert!(s.contains("200"));
    }

    #[test]
    fn enrichment_invocation_outcome_display_capability_denied() {
        let outcome = InvocationOutcome::CapabilityDenied {
            capability: SlotCapability::HeapAlloc,
        };
        let s = outcome.to_string();
        assert!(s.contains("capability_denied"));
    }

    #[test]
    fn enrichment_error_display_not_running() {
        let err = DelegateCellError::NotRunning {
            state: CellLifecycle::Created,
        };
        let s = err.to_string();
        assert!(s.contains("not running"));
        assert!(s.contains("created"));
    }

    #[test]
    fn enrichment_error_display_capability_denied() {
        let err = DelegateCellError::CapabilityDenied {
            capability: SlotCapability::TriggerGc,
        };
        let s = err.to_string();
        assert!(s.contains("capability denied"));
    }

    #[test]
    fn enrichment_error_display_resource_limit_exceeded() {
        let err =
            DelegateCellError::ResourceLimitExceeded(ResourceViolation::NetworkEgressDenied {
                bytes: 42,
            });
        let s = err.to_string();
        assert!(s.contains("resource limit exceeded"));
        assert!(s.contains("42"));
    }

    #[test]
    fn enrichment_harness_event_type_display_invocation_started() {
        assert_eq!(
            HarnessEventType::InvocationStarted.to_string(),
            "invocation_started"
        );
    }

    #[test]
    fn enrichment_harness_serde_roundtrip_with_invocations() {
        let mut harness = running_harness();
        harness
            .record_invocation(b"input1", b"output1", 42, ok_usage(), 5_000, 10_000)
            .unwrap();
        harness
            .record_invocation(b"input2", b"output2", 43, ok_usage(), 6_000, 20_000)
            .unwrap();

        let json = serde_json::to_string(&harness).unwrap();
        let decoded: DelegateCellHarness = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.invocation_log().len(), 2);
        assert_eq!(decoded.invocation_count(), 2);
        assert_eq!(decoded.metrics.total_invocations, 2);
        assert_eq!(decoded.metrics.successful_invocations, 2);
        assert_eq!(decoded.lifecycle, CellLifecycle::Running);
    }

    #[test]
    fn enrichment_replay_mismatch_contains_hashes() {
        let mut harness = running_harness();
        let record = harness
            .record_invocation(b"in", b"out", 1, ok_usage(), 100, 10_000)
            .unwrap();

        let result = harness.verify_replay(&record, b"wrong", 20_000);
        match result {
            ReplayVerification::Mismatch {
                sequence,
                expected_hash,
                actual_hash,
            } => {
                assert_eq!(sequence, 1);
                assert_eq!(expected_hash, ContentHash::compute(b"out"));
                assert_eq!(actual_hash, ContentHash::compute(b"wrong"));
                assert_ne!(expected_hash, actual_hash);
            }
            _ => panic!("expected Mismatch"),
        }
    }

    #[test]
    fn enrichment_metrics_heap_and_hostcall_accumulation() {
        let mut harness = running_harness();
        let usage1 = ResourceUsage {
            heap_bytes_used: 100_000,
            hostcall_count: 5,
            ..Default::default()
        };
        let usage2 = ResourceUsage {
            heap_bytes_used: 200_000,
            hostcall_count: 15,
            ..Default::default()
        };
        harness
            .record_invocation(b"a", b"b", 1, usage1, 100, 10_000)
            .unwrap();
        harness
            .record_invocation(b"c", b"d", 2, usage2, 200, 20_000)
            .unwrap();

        assert_eq!(harness.metrics.total_heap_bytes, 300_000);
        assert_eq!(harness.metrics.total_hostcalls, 20);
    }
}
