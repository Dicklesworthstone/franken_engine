//! Hostcall telemetry schema and recorder.
//!
//! Records every hostcall made by extensions with sufficient detail for
//! the Probabilistic Guardplane to use as evidence in its Bayesian
//! inference loop.  The recorder captures, timestamps, and persists
//! records with deterministic ordering guarantees.
//!
//! Plan reference: Section 10.5, item 3.
//! Cross-refs: 9A.2 (Probabilistic Guardplane), 9E.9 (normative
//! observability), 9C.2 (Bayesian decision loop).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::capability::RuntimeCapability;
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

const TELEMETRY_SCHEMA_DEF: &[u8] = b"hostcall-telemetry-schema-v1";

/// Default bounded channel capacity.
const DEFAULT_CHANNEL_CAPACITY: usize = 8192;

// ---------------------------------------------------------------------------
// HostcallType — categorisation of hostcall kinds
// ---------------------------------------------------------------------------

/// Enumeration of hostcall categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HostcallType {
    FsRead,
    FsWrite,
    NetworkSend,
    NetworkRecv,
    ProcessSpawn,
    EnvRead,
    MemAlloc,
    TimerCreate,
    CryptoOp,
    IpcSend,
    IpcRecv,
}

impl fmt::Display for HostcallType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::FsRead => "fs-read",
            Self::FsWrite => "fs-write",
            Self::NetworkSend => "network-send",
            Self::NetworkRecv => "network-recv",
            Self::ProcessSpawn => "process-spawn",
            Self::EnvRead => "env-read",
            Self::MemAlloc => "mem-alloc",
            Self::TimerCreate => "timer-create",
            Self::CryptoOp => "crypto-op",
            Self::IpcSend => "ipc-send",
            Self::IpcRecv => "ipc-recv",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// HostcallResult — outcome of a hostcall
// ---------------------------------------------------------------------------

/// Outcome of a single hostcall invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostcallResult {
    Success,
    Denied { reason: String },
    Error { code: u32 },
    Timeout,
}

impl fmt::Display for HostcallResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => f.write_str("success"),
            Self::Denied { reason } => write!(f, "denied: {reason}"),
            Self::Error { code } => write!(f, "error: {code}"),
            Self::Timeout => f.write_str("timeout"),
        }
    }
}

// ---------------------------------------------------------------------------
// ResourceDelta — resource usage change from a hostcall
// ---------------------------------------------------------------------------

/// Change in resource usage resulting from a single hostcall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ResourceDelta {
    /// Bytes allocated (positive) or freed (negative).
    pub memory_bytes: i64,
    /// File descriptors opened (positive) or closed (negative).
    pub fd_count: i32,
    /// Network bytes sent (positive) or received (negative).
    pub network_bytes: i64,
}

// ---------------------------------------------------------------------------
// FlowLabel — IFC label at hostcall time
// ---------------------------------------------------------------------------

/// Information Flow Control label active at the time of the hostcall.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowLabel {
    /// Label class name (e.g., "public", "secret", "top-secret").
    pub label_class: String,
    /// Clearance class name.
    pub clearance_class: String,
}

impl FlowLabel {
    pub fn new(label_class: impl Into<String>, clearance_class: impl Into<String>) -> Self {
        Self {
            label_class: label_class.into(),
            clearance_class: clearance_class.into(),
        }
    }
}

impl fmt::Display for FlowLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.label_class, self.clearance_class)
    }
}

// ---------------------------------------------------------------------------
// HostcallTelemetryRecord — a single hostcall event
// ---------------------------------------------------------------------------

/// A single structured telemetry record for one hostcall invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostcallTelemetryRecord {
    /// Monotonically increasing record identifier.
    pub record_id: u64,
    /// Monotonic nanosecond timestamp.
    pub timestamp_ns: u64,
    /// Extension that made the hostcall.
    pub extension_id: String,
    /// Category of hostcall.
    pub hostcall_type: HostcallType,
    /// Capability exercised by this hostcall.
    pub capability_used: RuntimeCapability,
    /// SHA-256 hash of the call arguments (privacy-preserving).
    pub arguments_hash: ContentHash,
    /// Result of the hostcall.
    pub result_status: HostcallResult,
    /// Duration of the hostcall in nanoseconds.
    pub duration_ns: u64,
    /// Resource usage change.
    pub resource_delta: ResourceDelta,
    /// IFC label active at call time.
    pub flow_label: FlowLabel,
    /// Optional decision ID if a security decision was triggered.
    pub decision_id: Option<String>,
    /// Security epoch at recording time.
    pub epoch: SecurityEpoch,
    /// Content hash of this record (computed from all fields above).
    pub content_hash: ContentHash,
}

impl HostcallTelemetryRecord {
    /// Compute canonical bytes for hashing (all fields except content_hash).
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&self.record_id.to_le_bytes());
        buf.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        buf.extend_from_slice(self.extension_id.as_bytes());
        buf.extend_from_slice(self.hostcall_type.to_string().as_bytes());
        buf.extend_from_slice(format!("{:?}", self.capability_used).as_bytes());
        buf.extend_from_slice(self.arguments_hash.as_bytes());
        buf.extend_from_slice(self.result_status.to_string().as_bytes());
        buf.extend_from_slice(&self.duration_ns.to_le_bytes());
        buf.extend_from_slice(&self.resource_delta.memory_bytes.to_le_bytes());
        buf.extend_from_slice(&self.resource_delta.fd_count.to_le_bytes());
        buf.extend_from_slice(&self.resource_delta.network_bytes.to_le_bytes());
        buf.extend_from_slice(self.flow_label.to_string().as_bytes());
        if let Some(ref did) = self.decision_id {
            buf.push(1);
            buf.extend_from_slice(did.as_bytes());
        } else {
            buf.push(0);
        }
        buf.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        buf
    }

    /// Verify that content_hash matches the record's fields.
    pub fn verify_integrity(&self) -> bool {
        let computed = ContentHash::compute(&self.canonical_bytes());
        self.content_hash == computed
    }
}

// ---------------------------------------------------------------------------
// TelemetryError
// ---------------------------------------------------------------------------

/// Errors from the telemetry subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TelemetryError {
    /// Channel is full; backpressure applied.
    ChannelFull,
    /// Monotonicity invariant violated.
    MonotonicityViolation {
        field: String,
        previous: u64,
        attempted: u64,
    },
    /// Empty extension ID.
    EmptyExtensionId,
    /// Snapshot index out of range.
    SnapshotOutOfRange { requested: u64, max: u64 },
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChannelFull => f.write_str("telemetry channel full"),
            Self::MonotonicityViolation {
                field,
                previous,
                attempted,
            } => write!(
                f,
                "monotonicity violation on {field}: previous={previous}, attempted={attempted}"
            ),
            Self::EmptyExtensionId => f.write_str("empty extension id"),
            Self::SnapshotOutOfRange { requested, max } => {
                write!(f, "snapshot index {requested} out of range (max {max})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RecordInput — builder-style input for recording
// ---------------------------------------------------------------------------

/// Input for recording a new hostcall telemetry event.
/// The recorder assigns `record_id`, `timestamp_ns`, and `content_hash`.
#[derive(Debug, Clone)]
pub struct RecordInput {
    pub extension_id: String,
    pub hostcall_type: HostcallType,
    pub capability_used: RuntimeCapability,
    pub arguments_hash: ContentHash,
    pub result_status: HostcallResult,
    pub duration_ns: u64,
    pub resource_delta: ResourceDelta,
    pub flow_label: FlowLabel,
    pub decision_id: Option<String>,
}

// ---------------------------------------------------------------------------
// TelemetrySnapshot — checkpoint for replay alignment
// ---------------------------------------------------------------------------

/// A snapshot of the recorder state at a given point for replay alignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// Record ID at snapshot time (None if empty).
    pub record_id_at_snapshot: Option<u64>,
    /// Number of records in the log at snapshot time.
    pub record_count: u64,
    /// Content hash of all records up to this point (rolling hash).
    pub rolling_hash: ContentHash,
    /// Security epoch at snapshot time.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// TelemetryRecorder — the recorder engine
// ---------------------------------------------------------------------------

/// Configuration for the telemetry recorder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecorderConfig {
    /// Maximum number of records before backpressure.
    pub channel_capacity: usize,
    /// Initial security epoch.
    pub epoch: SecurityEpoch,
    /// Whether to compute rolling hashes for deterministic replay.
    pub enable_rolling_hash: bool,
}

impl Default for RecorderConfig {
    fn default() -> Self {
        Self {
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            epoch: SecurityEpoch::GENESIS,
            enable_rolling_hash: true,
        }
    }
}

/// In-memory telemetry recorder with deterministic ordering guarantees.
///
/// Guarantees:
/// - `record_id` is strictly monotonically increasing.
/// - `timestamp_ns` is monotonically non-decreasing.
/// - Append-only log with bounded capacity (backpressure on full).
/// - Supports snapshot/checkpoint for replay alignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryRecorder {
    config: RecorderConfig,
    records: Vec<HostcallTelemetryRecord>,
    next_record_id: u64,
    last_timestamp_ns: u64,
    rolling_hash: ContentHash,
    snapshots: Vec<TelemetrySnapshot>,
    current_epoch: SecurityEpoch,
}

impl TelemetryRecorder {
    /// Create a new recorder with the given configuration.
    pub fn new(config: RecorderConfig) -> Self {
        Self {
            current_epoch: config.epoch,
            config,
            records: Vec::new(),
            next_record_id: 0,
            last_timestamp_ns: 0,
            rolling_hash: ContentHash::compute(TELEMETRY_SCHEMA_DEF),
            snapshots: Vec::new(),
        }
    }

    /// Record a new hostcall event.
    ///
    /// Assigns `record_id`, validates monotonicity, and appends to log.
    /// Returns the assigned `record_id` on success.
    pub fn record(&mut self, timestamp_ns: u64, input: RecordInput) -> Result<u64, TelemetryError> {
        // Validate extension ID.
        if input.extension_id.is_empty() {
            return Err(TelemetryError::EmptyExtensionId);
        }

        // Validate timestamp monotonicity.
        if timestamp_ns < self.last_timestamp_ns {
            return Err(TelemetryError::MonotonicityViolation {
                field: "timestamp_ns".to_string(),
                previous: self.last_timestamp_ns,
                attempted: timestamp_ns,
            });
        }

        // Backpressure check.
        if self.records.len() >= self.config.channel_capacity {
            return Err(TelemetryError::ChannelFull);
        }

        let record_id = self.next_record_id;
        self.next_record_id += 1;
        self.last_timestamp_ns = timestamp_ns;

        // Build the record.
        let mut record = HostcallTelemetryRecord {
            record_id,
            timestamp_ns,
            extension_id: input.extension_id,
            hostcall_type: input.hostcall_type,
            capability_used: input.capability_used,
            arguments_hash: input.arguments_hash,
            result_status: input.result_status,
            duration_ns: input.duration_ns,
            resource_delta: input.resource_delta,
            flow_label: input.flow_label,
            decision_id: input.decision_id,
            epoch: self.current_epoch,
            content_hash: ContentHash::compute(b"placeholder"),
        };

        // Compute content hash.
        record.content_hash = ContentHash::compute(&record.canonical_bytes());

        // Update rolling hash.
        if self.config.enable_rolling_hash {
            let mut rolling_input = Vec::new();
            rolling_input.extend_from_slice(self.rolling_hash.as_bytes());
            rolling_input.extend_from_slice(record.content_hash.as_bytes());
            self.rolling_hash = ContentHash::compute(&rolling_input);
        }

        self.records.push(record);
        Ok(record_id)
    }

    /// Take a snapshot of current state for replay alignment.
    pub fn snapshot(&mut self) -> TelemetrySnapshot {
        let snap = TelemetrySnapshot {
            record_id_at_snapshot: if self.next_record_id > 0 {
                Some(self.next_record_id - 1)
            } else {
                None
            },
            record_count: self.records.len() as u64,
            rolling_hash: self.rolling_hash,
            epoch: self.current_epoch,
        };
        self.snapshots.push(snap.clone());
        snap
    }

    /// Update the current security epoch.
    pub fn set_epoch(&mut self, epoch: SecurityEpoch) {
        self.current_epoch = epoch;
    }

    /// Number of recorded events.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the recorder has no events.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Remaining capacity before backpressure.
    pub fn remaining_capacity(&self) -> usize {
        self.config
            .channel_capacity
            .saturating_sub(self.records.len())
    }

    /// Access all recorded events.
    pub fn records(&self) -> &[HostcallTelemetryRecord] {
        &self.records
    }

    /// Get a record by its ID.
    pub fn get(&self, record_id: u64) -> Option<&HostcallTelemetryRecord> {
        self.records.iter().find(|r| r.record_id == record_id)
    }

    /// Current rolling hash.
    pub fn rolling_hash(&self) -> &ContentHash {
        &self.rolling_hash
    }

    /// All snapshots taken.
    pub fn snapshots(&self) -> &[TelemetrySnapshot] {
        &self.snapshots
    }

    /// Compute the overall content hash of all records.
    /// Records are sorted by record_id for insertion-order independence.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        let mut sorted: Vec<_> = self.records.iter().collect();
        sorted.sort_by_key(|r| r.record_id);
        for record in &sorted {
            buf.extend_from_slice(&record.record_id.to_le_bytes());
            buf.extend_from_slice(record.content_hash.as_bytes());
        }
        ContentHash::compute(&buf)
    }

    /// Verify all records' integrity.
    pub fn verify_all_integrity(&self) -> Vec<u64> {
        let mut tampered = Vec::new();
        for record in &self.records {
            if !record.verify_integrity() {
                tampered.push(record.record_id);
            }
        }
        tampered
    }
}

// ---------------------------------------------------------------------------
// TelemetryQuery — query interface for the Guardplane
// ---------------------------------------------------------------------------

/// Query interface over recorded telemetry for the Probabilistic Guardplane.
pub struct TelemetryQuery<'a> {
    records: &'a [HostcallTelemetryRecord],
}

impl<'a> TelemetryQuery<'a> {
    /// Create a query interface over a recorder's records.
    pub fn new(records: &'a [HostcallTelemetryRecord]) -> Self {
        Self { records }
    }

    /// Records from a specific extension within a time window (inclusive).
    pub fn recent_by_extension(
        &self,
        extension_id: &str,
        window_start_ns: u64,
        window_end_ns: u64,
    ) -> Vec<&'a HostcallTelemetryRecord> {
        self.records
            .iter()
            .filter(|r| {
                r.extension_id == extension_id
                    && r.timestamp_ns >= window_start_ns
                    && r.timestamp_ns <= window_end_ns
            })
            .collect()
    }

    /// Records of a specific hostcall type within a time window.
    pub fn recent_by_type(
        &self,
        hostcall_type: HostcallType,
        window_start_ns: u64,
        window_end_ns: u64,
    ) -> Vec<&'a HostcallTelemetryRecord> {
        self.records
            .iter()
            .filter(|r| {
                r.hostcall_type == hostcall_type
                    && r.timestamp_ns >= window_start_ns
                    && r.timestamp_ns <= window_end_ns
            })
            .collect()
    }

    /// Records that resulted in denied or error outcomes.
    pub fn anomaly_candidates(
        &self,
        window_start_ns: u64,
        window_end_ns: u64,
    ) -> Vec<&'a HostcallTelemetryRecord> {
        self.records
            .iter()
            .filter(|r| {
                r.timestamp_ns >= window_start_ns
                    && r.timestamp_ns <= window_end_ns
                    && !matches!(r.result_status, HostcallResult::Success)
            })
            .collect()
    }

    /// Extension-level summary statistics within a time window.
    pub fn extension_summary(
        &self,
        extension_id: &str,
        window_start_ns: u64,
        window_end_ns: u64,
    ) -> ExtensionSummary {
        let mut summary = ExtensionSummary::default();
        for record in self.records {
            if record.extension_id != extension_id
                || record.timestamp_ns < window_start_ns
                || record.timestamp_ns > window_end_ns
            {
                continue;
            }
            summary.total_calls += 1;
            match &record.result_status {
                HostcallResult::Success => summary.success_count += 1,
                HostcallResult::Denied { .. } => summary.denied_count += 1,
                HostcallResult::Error { .. } => summary.error_count += 1,
                HostcallResult::Timeout => summary.timeout_count += 1,
            }
            summary.total_duration_ns += record.duration_ns;
            *summary.type_counts.entry(record.hostcall_type).or_insert(0) += 1;
        }
        summary
    }

    /// Count of records by hostcall type within a window.
    pub fn type_distribution(
        &self,
        window_start_ns: u64,
        window_end_ns: u64,
    ) -> BTreeMap<HostcallType, u64> {
        let mut counts = BTreeMap::new();
        for record in self.records {
            if record.timestamp_ns >= window_start_ns && record.timestamp_ns <= window_end_ns {
                *counts.entry(record.hostcall_type).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Records with duration exceeding a threshold (ns).
    pub fn slow_calls(
        &self,
        threshold_ns: u64,
        window_start_ns: u64,
        window_end_ns: u64,
    ) -> Vec<&'a HostcallTelemetryRecord> {
        self.records
            .iter()
            .filter(|r| {
                r.duration_ns > threshold_ns
                    && r.timestamp_ns >= window_start_ns
                    && r.timestamp_ns <= window_end_ns
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// ExtensionSummary — per-extension aggregate statistics
// ---------------------------------------------------------------------------

/// Aggregate statistics for a single extension within a time window.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionSummary {
    pub total_calls: u64,
    pub success_count: u64,
    pub denied_count: u64,
    pub error_count: u64,
    pub timeout_count: u64,
    pub total_duration_ns: u64,
    pub type_counts: BTreeMap<HostcallType, u64>,
}

impl ExtensionSummary {
    /// Average duration per call in nanoseconds (0 if no calls).
    pub fn avg_duration_ns(&self) -> u64 {
        self.total_duration_ns
            .checked_div(self.total_calls)
            .unwrap_or(0)
    }

    /// Denial rate in millionths (1_000_000 = 100%).
    pub fn denial_rate_millionths(&self) -> u64 {
        self.denied_count
            .saturating_mul(1_000_000)
            .checked_div(self.total_calls)
            .unwrap_or(0)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    fn default_flow_label() -> FlowLabel {
        FlowLabel::new("public", "public")
    }

    fn test_input(ext_id: &str, htype: HostcallType) -> RecordInput {
        RecordInput {
            extension_id: ext_id.to_string(),
            hostcall_type: htype,
            capability_used: RuntimeCapability::FsRead,
            arguments_hash: ContentHash::compute(b"test-args"),
            result_status: HostcallResult::Success,
            duration_ns: 1_000,
            resource_delta: ResourceDelta::default(),
            flow_label: default_flow_label(),
            decision_id: None,
        }
    }

    fn test_recorder() -> TelemetryRecorder {
        TelemetryRecorder::new(RecorderConfig::default())
    }

    fn small_recorder(capacity: usize) -> TelemetryRecorder {
        TelemetryRecorder::new(RecorderConfig {
            channel_capacity: capacity,
            epoch: SecurityEpoch::GENESIS,
            enable_rolling_hash: true,
        })
    }

    // -----------------------------------------------------------------------
    // HostcallType tests
    // -----------------------------------------------------------------------

    #[test]
    fn hostcall_type_display() {
        assert_eq!(HostcallType::FsRead.to_string(), "fs-read");
        assert_eq!(HostcallType::FsWrite.to_string(), "fs-write");
        assert_eq!(HostcallType::NetworkSend.to_string(), "network-send");
        assert_eq!(HostcallType::NetworkRecv.to_string(), "network-recv");
        assert_eq!(HostcallType::ProcessSpawn.to_string(), "process-spawn");
        assert_eq!(HostcallType::EnvRead.to_string(), "env-read");
        assert_eq!(HostcallType::MemAlloc.to_string(), "mem-alloc");
        assert_eq!(HostcallType::TimerCreate.to_string(), "timer-create");
        assert_eq!(HostcallType::CryptoOp.to_string(), "crypto-op");
        assert_eq!(HostcallType::IpcSend.to_string(), "ipc-send");
        assert_eq!(HostcallType::IpcRecv.to_string(), "ipc-recv");
    }

    #[test]
    fn hostcall_type_serde_roundtrip() {
        for htype in [
            HostcallType::FsRead,
            HostcallType::FsWrite,
            HostcallType::NetworkSend,
            HostcallType::NetworkRecv,
            HostcallType::ProcessSpawn,
            HostcallType::EnvRead,
            HostcallType::MemAlloc,
            HostcallType::TimerCreate,
            HostcallType::CryptoOp,
            HostcallType::IpcSend,
            HostcallType::IpcRecv,
        ] {
            let json = serde_json::to_string(&htype).unwrap();
            let restored: HostcallType = serde_json::from_str(&json).unwrap();
            assert_eq!(htype, restored);
        }
    }

    // -----------------------------------------------------------------------
    // HostcallResult tests
    // -----------------------------------------------------------------------

    #[test]
    fn hostcall_result_display() {
        assert_eq!(HostcallResult::Success.to_string(), "success");
        assert_eq!(
            HostcallResult::Denied {
                reason: "no cap".to_string()
            }
            .to_string(),
            "denied: no cap"
        );
        assert_eq!(HostcallResult::Error { code: 42 }.to_string(), "error: 42");
        assert_eq!(HostcallResult::Timeout.to_string(), "timeout");
    }

    #[test]
    fn hostcall_result_serde_roundtrip() {
        for result in [
            HostcallResult::Success,
            HostcallResult::Denied {
                reason: "policy".to_string(),
            },
            HostcallResult::Error { code: 99 },
            HostcallResult::Timeout,
        ] {
            let json = serde_json::to_string(&result).unwrap();
            let restored: HostcallResult = serde_json::from_str(&json).unwrap();
            assert_eq!(result, restored);
        }
    }

    // -----------------------------------------------------------------------
    // FlowLabel tests
    // -----------------------------------------------------------------------

    #[test]
    fn flow_label_display() {
        let fl = FlowLabel::new("secret", "top-secret");
        assert_eq!(fl.to_string(), "secret:top-secret");
    }

    #[test]
    fn flow_label_serde_roundtrip() {
        let fl = FlowLabel::new("public", "public");
        let json = serde_json::to_string(&fl).unwrap();
        let restored: FlowLabel = serde_json::from_str(&json).unwrap();
        assert_eq!(fl, restored);
    }

    // -----------------------------------------------------------------------
    // ResourceDelta tests
    // -----------------------------------------------------------------------

    #[test]
    fn resource_delta_default() {
        let rd = ResourceDelta::default();
        assert_eq!(rd.memory_bytes, 0);
        assert_eq!(rd.fd_count, 0);
        assert_eq!(rd.network_bytes, 0);
    }

    #[test]
    fn resource_delta_serde_roundtrip() {
        let rd = ResourceDelta {
            memory_bytes: 4096,
            fd_count: 2,
            network_bytes: -1024,
        };
        let json = serde_json::to_string(&rd).unwrap();
        let restored: ResourceDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(rd, restored);
    }

    // -----------------------------------------------------------------------
    // TelemetryError tests
    // -----------------------------------------------------------------------

    #[test]
    fn telemetry_error_display() {
        assert_eq!(
            TelemetryError::ChannelFull.to_string(),
            "telemetry channel full"
        );
        assert_eq!(
            TelemetryError::EmptyExtensionId.to_string(),
            "empty extension id"
        );
        let mv = TelemetryError::MonotonicityViolation {
            field: "timestamp_ns".to_string(),
            previous: 100,
            attempted: 50,
        };
        assert!(mv.to_string().contains("monotonicity"));
        let sor = TelemetryError::SnapshotOutOfRange {
            requested: 10,
            max: 5,
        };
        assert!(sor.to_string().contains("out of range"));
    }

    // -----------------------------------------------------------------------
    // Record creation and monotonicity
    // -----------------------------------------------------------------------

    #[test]
    fn record_basic() {
        let mut recorder = test_recorder();
        let rid = recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        assert_eq!(rid, 0);
        assert_eq!(recorder.len(), 1);
        assert!(!recorder.is_empty());
    }

    #[test]
    fn record_id_monotonic() {
        let mut recorder = test_recorder();
        let r0 = recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let r1 = recorder
            .record(2000, test_input("ext-001", HostcallType::FsWrite))
            .unwrap();
        let r2 = recorder
            .record(3000, test_input("ext-002", HostcallType::NetworkSend))
            .unwrap();
        assert_eq!(r0, 0);
        assert_eq!(r1, 1);
        assert_eq!(r2, 2);
    }

    #[test]
    fn timestamp_monotonic_allows_equal() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        // Same timestamp is allowed (non-decreasing).
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsWrite))
            .unwrap();
        assert_eq!(recorder.len(), 2);
    }

    #[test]
    fn timestamp_backward_rejected() {
        let mut recorder = test_recorder();
        recorder
            .record(2000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let err = recorder
            .record(1000, test_input("ext-001", HostcallType::FsWrite))
            .unwrap_err();
        assert!(matches!(err, TelemetryError::MonotonicityViolation { .. }));
    }

    #[test]
    fn empty_extension_id_rejected() {
        let mut recorder = test_recorder();
        let err = recorder
            .record(1000, test_input("", HostcallType::FsRead))
            .unwrap_err();
        assert_eq!(err, TelemetryError::EmptyExtensionId);
    }

    // -----------------------------------------------------------------------
    // Backpressure
    // -----------------------------------------------------------------------

    #[test]
    fn channel_full_backpressure() {
        let mut recorder = small_recorder(3);
        recorder
            .record(100, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        recorder
            .record(200, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        recorder
            .record(300, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let err = recorder
            .record(400, test_input("ext-001", HostcallType::FsRead))
            .unwrap_err();
        assert_eq!(err, TelemetryError::ChannelFull);
    }

    #[test]
    fn remaining_capacity_decreases() {
        let mut recorder = small_recorder(5);
        assert_eq!(recorder.remaining_capacity(), 5);
        recorder
            .record(100, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        assert_eq!(recorder.remaining_capacity(), 4);
        recorder
            .record(200, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        assert_eq!(recorder.remaining_capacity(), 3);
    }

    // -----------------------------------------------------------------------
    // Content hash and integrity
    // -----------------------------------------------------------------------

    #[test]
    fn record_integrity_passes() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let record = &recorder.records()[0];
        assert!(record.verify_integrity());
    }

    #[test]
    fn record_integrity_detects_tampering() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let mut record = recorder.records()[0].clone();
        record.duration_ns = 999_999;
        assert!(!record.verify_integrity());
    }

    #[test]
    fn verify_all_integrity_clean() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        recorder
            .record(2000, test_input("ext-002", HostcallType::FsWrite))
            .unwrap();
        assert!(recorder.verify_all_integrity().is_empty());
    }

    // -----------------------------------------------------------------------
    // Determinism
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_recording() {
        let mut r1 = test_recorder();
        let mut r2 = test_recorder();

        let input = test_input("ext-001", HostcallType::FsRead);
        r1.record(1000, input.clone()).unwrap();
        r2.record(1000, input).unwrap();

        assert_eq!(r1.records()[0].content_hash, r2.records()[0].content_hash);
        assert_eq!(r1.rolling_hash(), r2.rolling_hash());
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn different_inputs_different_hashes() {
        let mut r1 = test_recorder();
        let mut r2 = test_recorder();

        r1.record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        r2.record(1000, test_input("ext-002", HostcallType::FsRead))
            .unwrap();

        assert_ne!(r1.records()[0].content_hash, r2.records()[0].content_hash);
    }

    // -----------------------------------------------------------------------
    // Snapshots
    // -----------------------------------------------------------------------

    #[test]
    fn snapshot_captures_state() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let snap = recorder.snapshot();
        assert_eq!(snap.record_count, 1);
        assert_eq!(snap.record_id_at_snapshot, Some(0));
        assert_eq!(snap.epoch, SecurityEpoch::GENESIS);
    }

    #[test]
    fn multiple_snapshots() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let s1 = recorder.snapshot();
        recorder
            .record(2000, test_input("ext-001", HostcallType::FsWrite))
            .unwrap();
        let s2 = recorder.snapshot();

        assert_eq!(s1.record_count, 1);
        assert_eq!(s2.record_count, 2);
        assert_ne!(s1.rolling_hash, s2.rolling_hash);
        assert_eq!(recorder.snapshots().len(), 2);
    }

    // -----------------------------------------------------------------------
    // Epoch tracking
    // -----------------------------------------------------------------------

    #[test]
    fn epoch_stamped_on_records() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        assert_eq!(recorder.records()[0].epoch, SecurityEpoch::GENESIS);

        recorder.set_epoch(SecurityEpoch::from_raw(5));
        recorder
            .record(2000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        assert_eq!(recorder.records()[1].epoch, SecurityEpoch::from_raw(5));
    }

    // -----------------------------------------------------------------------
    // Decision ID linkage
    // -----------------------------------------------------------------------

    #[test]
    fn record_with_decision_id() {
        let mut recorder = test_recorder();
        let mut input = test_input("ext-001", HostcallType::ProcessSpawn);
        input.decision_id = Some("dec-001".to_string());
        recorder.record(1000, input).unwrap();
        assert_eq!(
            recorder.records()[0].decision_id,
            Some("dec-001".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // Result variants
    // -----------------------------------------------------------------------

    #[test]
    fn record_denied_result() {
        let mut recorder = test_recorder();
        let mut input = test_input("ext-001", HostcallType::FsWrite);
        input.result_status = HostcallResult::Denied {
            reason: "no write cap".to_string(),
        };
        recorder.record(1000, input).unwrap();
        assert!(matches!(
            recorder.records()[0].result_status,
            HostcallResult::Denied { .. }
        ));
    }

    #[test]
    fn record_error_result() {
        let mut recorder = test_recorder();
        let mut input = test_input("ext-001", HostcallType::NetworkSend);
        input.result_status = HostcallResult::Error { code: 500 };
        recorder.record(1000, input).unwrap();
        assert_eq!(
            recorder.records()[0].result_status,
            HostcallResult::Error { code: 500 }
        );
    }

    #[test]
    fn record_timeout_result() {
        let mut recorder = test_recorder();
        let mut input = test_input("ext-001", HostcallType::NetworkRecv);
        input.result_status = HostcallResult::Timeout;
        recorder.record(1000, input).unwrap();
        assert_eq!(recorder.records()[0].result_status, HostcallResult::Timeout);
    }

    // -----------------------------------------------------------------------
    // Resource delta
    // -----------------------------------------------------------------------

    #[test]
    fn record_with_resource_delta() {
        let mut recorder = test_recorder();
        let mut input = test_input("ext-001", HostcallType::MemAlloc);
        input.resource_delta = ResourceDelta {
            memory_bytes: 65536,
            fd_count: 0,
            network_bytes: 0,
        };
        recorder.record(1000, input).unwrap();
        assert_eq!(recorder.records()[0].resource_delta.memory_bytes, 65536);
    }

    // -----------------------------------------------------------------------
    // Serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn record_serde_roundtrip() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let record = &recorder.records()[0];
        let json = serde_json::to_string(record).unwrap();
        let restored: HostcallTelemetryRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record.record_id, restored.record_id);
        assert_eq!(record.content_hash, restored.content_hash);
        assert_eq!(record.hostcall_type, restored.hostcall_type);
    }

    #[test]
    fn recorder_serde_roundtrip() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        recorder.snapshot();
        let json = serde_json::to_string(&recorder).unwrap();
        let restored: TelemetryRecorder = serde_json::from_str(&json).unwrap();
        assert_eq!(recorder.len(), restored.len());
        assert_eq!(recorder.rolling_hash(), restored.rolling_hash());
        assert_eq!(recorder.snapshots().len(), restored.snapshots().len());
    }

    #[test]
    fn snapshot_serde_roundtrip() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let snap = recorder.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let restored: TelemetrySnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, restored);
    }

    // -----------------------------------------------------------------------
    // TelemetryQuery tests
    // -----------------------------------------------------------------------

    fn populate_recorder() -> TelemetryRecorder {
        let mut recorder = test_recorder();
        // ext-001: 3 FsRead (1 denied), 1 NetworkSend
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        recorder
            .record(2000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let mut denied_input = test_input("ext-001", HostcallType::FsRead);
        denied_input.result_status = HostcallResult::Denied {
            reason: "policy".to_string(),
        };
        recorder.record(3000, denied_input).unwrap();
        recorder
            .record(4000, test_input("ext-001", HostcallType::NetworkSend))
            .unwrap();
        // ext-002: 2 FsWrite, 1 Error
        recorder
            .record(5000, test_input("ext-002", HostcallType::FsWrite))
            .unwrap();
        let mut err_input = test_input("ext-002", HostcallType::FsWrite);
        err_input.result_status = HostcallResult::Error { code: 13 };
        recorder.record(6000, err_input).unwrap();
        recorder
    }

    #[test]
    fn query_recent_by_extension() {
        let recorder = populate_recorder();
        let query = TelemetryQuery::new(recorder.records());
        let results = query.recent_by_extension("ext-001", 0, 10_000);
        assert_eq!(results.len(), 4);
        let results = query.recent_by_extension("ext-002", 0, 10_000);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn query_recent_by_extension_windowed() {
        let recorder = populate_recorder();
        let query = TelemetryQuery::new(recorder.records());
        let results = query.recent_by_extension("ext-001", 2000, 3000);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn query_recent_by_type() {
        let recorder = populate_recorder();
        let query = TelemetryQuery::new(recorder.records());
        let results = query.recent_by_type(HostcallType::FsRead, 0, 10_000);
        assert_eq!(results.len(), 3);
        let results = query.recent_by_type(HostcallType::FsWrite, 0, 10_000);
        assert_eq!(results.len(), 2);
        let results = query.recent_by_type(HostcallType::NetworkSend, 0, 10_000);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn query_anomaly_candidates() {
        let recorder = populate_recorder();
        let query = TelemetryQuery::new(recorder.records());
        let anomalies = query.anomaly_candidates(0, 10_000);
        // 1 denied + 1 error = 2 anomalies
        assert_eq!(anomalies.len(), 2);
    }

    #[test]
    fn query_extension_summary() {
        let recorder = populate_recorder();
        let query = TelemetryQuery::new(recorder.records());
        let summary = query.extension_summary("ext-001", 0, 10_000);
        assert_eq!(summary.total_calls, 4);
        assert_eq!(summary.success_count, 3);
        assert_eq!(summary.denied_count, 1);
        assert_eq!(summary.error_count, 0);
        assert_eq!(summary.timeout_count, 0);
    }

    #[test]
    fn query_type_distribution() {
        let recorder = populate_recorder();
        let query = TelemetryQuery::new(recorder.records());
        let dist = query.type_distribution(0, 10_000);
        assert_eq!(dist.get(&HostcallType::FsRead), Some(&3));
        assert_eq!(dist.get(&HostcallType::FsWrite), Some(&2));
        assert_eq!(dist.get(&HostcallType::NetworkSend), Some(&1));
    }

    #[test]
    fn query_slow_calls() {
        let mut recorder = test_recorder();
        let mut input = test_input("ext-001", HostcallType::FsRead);
        input.duration_ns = 500;
        recorder.record(1000, input).unwrap();

        let mut slow_input = test_input("ext-001", HostcallType::FsWrite);
        slow_input.duration_ns = 10_000;
        recorder.record(2000, slow_input).unwrap();

        let query = TelemetryQuery::new(recorder.records());
        let slow = query.slow_calls(5_000, 0, 10_000);
        assert_eq!(slow.len(), 1);
        assert_eq!(slow[0].hostcall_type, HostcallType::FsWrite);
    }

    // -----------------------------------------------------------------------
    // ExtensionSummary tests
    // -----------------------------------------------------------------------

    #[test]
    fn extension_summary_avg_duration() {
        let summary = ExtensionSummary {
            total_calls: 4,
            total_duration_ns: 4000,
            ..Default::default()
        };
        assert_eq!(summary.avg_duration_ns(), 1000);
    }

    #[test]
    fn extension_summary_avg_duration_zero() {
        let summary = ExtensionSummary::default();
        assert_eq!(summary.avg_duration_ns(), 0);
    }

    #[test]
    fn extension_summary_denial_rate() {
        let summary = ExtensionSummary {
            total_calls: 4,
            denied_count: 1,
            ..Default::default()
        };
        assert_eq!(summary.denial_rate_millionths(), 250_000); // 25%
    }

    #[test]
    fn extension_summary_denial_rate_zero() {
        let summary = ExtensionSummary::default();
        assert_eq!(summary.denial_rate_millionths(), 0);
    }

    #[test]
    fn extension_summary_serde_roundtrip() {
        let recorder = populate_recorder();
        let query = TelemetryQuery::new(recorder.records());
        let summary = query.extension_summary("ext-001", 0, 10_000);
        let json = serde_json::to_string(&summary).unwrap();
        let restored: ExtensionSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, restored);
    }

    // -----------------------------------------------------------------------
    // Rolling hash
    // -----------------------------------------------------------------------

    #[test]
    fn rolling_hash_changes_per_record() {
        let mut recorder = test_recorder();
        let h0 = *recorder.rolling_hash();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let h1 = *recorder.rolling_hash();
        recorder
            .record(2000, test_input("ext-001", HostcallType::FsWrite))
            .unwrap();
        let h2 = *recorder.rolling_hash();

        assert_ne!(h0, h1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn rolling_hash_disabled() {
        let mut recorder = TelemetryRecorder::new(RecorderConfig {
            channel_capacity: 100,
            epoch: SecurityEpoch::GENESIS,
            enable_rolling_hash: false,
        });
        let h0 = *recorder.rolling_hash();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let h1 = *recorder.rolling_hash();
        // Rolling hash should not change when disabled.
        assert_eq!(h0, h1);
    }

    // -----------------------------------------------------------------------
    // Get by record ID
    // -----------------------------------------------------------------------

    #[test]
    fn get_by_record_id() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        recorder
            .record(2000, test_input("ext-002", HostcallType::FsWrite))
            .unwrap();

        assert!(recorder.get(0).is_some());
        assert_eq!(recorder.get(0).unwrap().extension_id, "ext-001");
        assert!(recorder.get(1).is_some());
        assert_eq!(recorder.get(1).unwrap().extension_id, "ext-002");
        assert!(recorder.get(99).is_none());
    }

    // -----------------------------------------------------------------------
    // Capability tracking
    // -----------------------------------------------------------------------

    #[test]
    fn capability_recorded() {
        let mut recorder = test_recorder();
        let mut input = test_input("ext-001", HostcallType::FsWrite);
        input.capability_used = RuntimeCapability::FsWrite;
        recorder.record(1000, input).unwrap();
        assert_eq!(
            recorder.records()[0].capability_used,
            RuntimeCapability::FsWrite
        );
    }

    // -----------------------------------------------------------------------
    // Flow label tracking
    // -----------------------------------------------------------------------

    #[test]
    fn flow_label_recorded() {
        let mut recorder = test_recorder();
        let mut input = test_input("ext-001", HostcallType::FsRead);
        input.flow_label = FlowLabel::new("secret", "top-secret");
        recorder.record(1000, input).unwrap();
        assert_eq!(
            recorder.records()[0].flow_label,
            FlowLabel::new("secret", "top-secret")
        );
    }

    // -----------------------------------------------------------------------
    // Config defaults
    // -----------------------------------------------------------------------

    #[test]
    fn config_default() {
        let config = RecorderConfig::default();
        assert_eq!(config.channel_capacity, DEFAULT_CHANNEL_CAPACITY);
        assert_eq!(config.epoch, SecurityEpoch::GENESIS);
        assert!(config.enable_rolling_hash);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = RecorderConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let restored: RecorderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.channel_capacity, config.channel_capacity);
    }

    // -----------------------------------------------------------------------
    // Empty recorder
    // -----------------------------------------------------------------------

    // -- Enrichment: Ord --

    #[test]
    fn hostcall_type_ordering() {
        assert!(HostcallType::FsRead < HostcallType::FsWrite);
        assert!(HostcallType::FsWrite < HostcallType::NetworkSend);
        assert!(HostcallType::NetworkSend < HostcallType::NetworkRecv);
        assert!(HostcallType::NetworkRecv < HostcallType::ProcessSpawn);
        assert!(HostcallType::ProcessSpawn < HostcallType::EnvRead);
        assert!(HostcallType::EnvRead < HostcallType::MemAlloc);
        assert!(HostcallType::MemAlloc < HostcallType::TimerCreate);
        assert!(HostcallType::TimerCreate < HostcallType::CryptoOp);
        assert!(HostcallType::CryptoOp < HostcallType::IpcSend);
        assert!(HostcallType::IpcSend < HostcallType::IpcRecv);
    }

    #[test]
    fn empty_recorder() {
        let recorder = test_recorder();
        assert!(recorder.is_empty());
        assert_eq!(recorder.len(), 0);
        assert!(recorder.verify_all_integrity().is_empty());
        assert!(recorder.snapshots().is_empty());
    }

    // ── Enrichment: Display uniqueness ──────────────────────────

    #[test]
    fn hostcall_type_display_all_unique() {
        let displays: std::collections::BTreeSet<String> = [
            HostcallType::FsRead,
            HostcallType::FsWrite,
            HostcallType::NetworkSend,
            HostcallType::NetworkRecv,
            HostcallType::ProcessSpawn,
            HostcallType::EnvRead,
            HostcallType::MemAlloc,
            HostcallType::TimerCreate,
            HostcallType::CryptoOp,
            HostcallType::IpcSend,
            HostcallType::IpcRecv,
        ]
        .iter()
        .map(|t| t.to_string())
        .collect();
        assert_eq!(displays.len(), 11);
    }

    #[test]
    fn hostcall_result_display_all_unique() {
        let displays: std::collections::BTreeSet<String> = [
            HostcallResult::Success,
            HostcallResult::Denied {
                reason: "no cap".to_string(),
            },
            HostcallResult::Error { code: 1 },
            HostcallResult::Timeout,
        ]
        .iter()
        .map(|r| r.to_string())
        .collect();
        assert_eq!(displays.len(), 4);
    }

    // ── Enrichment: TelemetryError serde roundtrip ──────────────

    #[test]
    fn telemetry_error_serde_all_variants() {
        let errors = vec![
            TelemetryError::ChannelFull,
            TelemetryError::EmptyExtensionId,
            TelemetryError::MonotonicityViolation {
                field: "ts".to_string(),
                previous: 100,
                attempted: 50,
            },
            TelemetryError::SnapshotOutOfRange {
                requested: 10,
                max: 5,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: TelemetryError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    // ── Enrichment: TelemetryError Display all distinct ─────────

    #[test]
    fn telemetry_error_display_all_distinct() {
        let errors = [
            TelemetryError::ChannelFull,
            TelemetryError::MonotonicityViolation {
                field: "timestamp".into(),
                previous: 10,
                attempted: 5,
            },
            TelemetryError::EmptyExtensionId,
            TelemetryError::SnapshotOutOfRange {
                requested: 99,
                max: 50,
            },
        ];
        let displays: std::collections::BTreeSet<String> =
            errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(displays.len(), 4, "all 4 variants produce distinct Display");
    }

    // ── Enrichment: content_hash determinism ────────────────────

    #[test]
    fn recorder_content_hash_changes_after_record() {
        let mut recorder = test_recorder();
        let h1 = recorder.content_hash();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let h2 = recorder.content_hash();
        assert_ne!(h1, h2);
    }

    // ── Enrichment: snapshot at specific record count ────────────

    #[test]
    fn snapshot_records_correct_id() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        recorder
            .record(2000, test_input("ext-001", HostcallType::FsWrite))
            .unwrap();
        recorder
            .record(3000, test_input("ext-002", HostcallType::NetworkSend))
            .unwrap();
        let snap = recorder.snapshot();
        assert_eq!(snap.record_count, 3);
        assert_eq!(snap.record_id_at_snapshot, Some(2)); // last record_id is 2 (0-indexed)
    }

    // ── Enrichment: extension summary zero calls ────────────────

    #[test]
    fn extension_summary_unknown_extension_all_zeros() {
        let recorder = populate_recorder();
        let query = TelemetryQuery::new(recorder.records());
        let summary = query.extension_summary("nonexistent", 0, 10_000);
        assert_eq!(summary.total_calls, 0);
        assert_eq!(summary.success_count, 0);
        assert_eq!(summary.denied_count, 0);
        assert_eq!(summary.error_count, 0);
        assert_eq!(summary.timeout_count, 0);
    }

    // ── Enrichment: FlowLabel with empty strings ────────────────

    #[test]
    fn flow_label_empty_strings_display() {
        let fl = FlowLabel::new("", "");
        assert_eq!(fl.to_string(), ":");
    }

    // ── Enrichment: ResourceDelta serde with negatives ──────────

    #[test]
    fn resource_delta_negative_values_serde() {
        let rd = ResourceDelta {
            memory_bytes: -4096,
            fd_count: -1,
            network_bytes: -2048,
        };
        let json = serde_json::to_string(&rd).unwrap();
        let back: ResourceDelta = serde_json::from_str(&json).unwrap();
        assert_eq!(rd, back);
    }

    // ── Enrichment: HostcallType Copy and Hash ──────────────────

    #[test]
    fn enrichment_hostcall_type_copy_semantics() {
        let a = HostcallType::CryptoOp;
        let b = a; // Copy
        assert_eq!(a, b);
        // a is still usable after copy
        assert_eq!(a.to_string(), "crypto-op");
    }

    #[test]
    fn enrichment_hostcall_type_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        HostcallType::IpcSend.hash(&mut h1);
        HostcallType::IpcSend.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
        // Different variants produce different hashes (overwhelmingly likely).
        let mut h3 = DefaultHasher::new();
        HostcallType::IpcRecv.hash(&mut h3);
        assert_ne!(h1.finish(), h3.finish());
    }

    // ── Enrichment: HostcallResult clone equality edge cases ────

    #[test]
    fn enrichment_hostcall_result_clone_eq() {
        let denied = HostcallResult::Denied {
            reason: "sandbox violation".to_string(),
        };
        let cloned = denied.clone();
        assert_eq!(denied, cloned);
        // Ensure deep clone — different allocation.
        if let HostcallResult::Denied { reason } = &cloned {
            assert_eq!(reason, "sandbox violation");
        } else {
            panic!("expected Denied variant");
        }
    }

    #[test]
    fn enrichment_hostcall_result_error_code_zero() {
        let err = HostcallResult::Error { code: 0 };
        assert_eq!(err.to_string(), "error: 0");
        let json = serde_json::to_string(&err).unwrap();
        let back: HostcallResult = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // ── Enrichment: FlowLabel Ord ──────────────────────────────

    #[test]
    fn enrichment_flow_label_ord() {
        let public = FlowLabel::new("public", "public");
        let secret = FlowLabel::new("secret", "secret");
        // "public" < "secret" lexicographically
        assert!(public < secret);
        let a = FlowLabel::new("alpha", "beta");
        let b = FlowLabel::new("alpha", "gamma");
        // Same label_class, clearance_class compared
        assert!(a < b);
    }

    // ── Enrichment: ResourceDelta Copy ──────────────────────────

    #[test]
    fn enrichment_resource_delta_copy_semantics() {
        let rd = ResourceDelta {
            memory_bytes: 1024,
            fd_count: 3,
            network_bytes: 512,
        };
        let rd2 = rd; // Copy
        assert_eq!(rd, rd2);
        assert_eq!(rd.memory_bytes, 1024);
    }

    // ── Enrichment: ResourceDelta JSON field check ──────────────

    #[test]
    fn enrichment_resource_delta_json_fields() {
        let rd = ResourceDelta {
            memory_bytes: 8192,
            fd_count: -2,
            network_bytes: 0,
        };
        let json = serde_json::to_string(&rd).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["memory_bytes"], 8192);
        assert_eq!(v["fd_count"], -2);
        assert_eq!(v["network_bytes"], 0);
    }

    // ── Enrichment: TelemetrySnapshot clone ─────────────────────

    #[test]
    fn enrichment_snapshot_clone_eq() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        let snap = recorder.snapshot();
        let cloned = snap.clone();
        assert_eq!(snap, cloned);
        assert_eq!(snap.record_count, cloned.record_count);
        assert_eq!(snap.rolling_hash, cloned.rolling_hash);
    }

    // ── Enrichment: snapshot on empty recorder ──────────────────

    #[test]
    fn enrichment_snapshot_empty_recorder() {
        let mut recorder = test_recorder();
        let snap = recorder.snapshot();
        assert_eq!(snap.record_count, 0);
        assert_eq!(snap.record_id_at_snapshot, None);
        assert_eq!(snap.epoch, SecurityEpoch::GENESIS);
    }

    // ── Enrichment: recorder serde with rolling hash disabled ───

    #[test]
    fn enrichment_recorder_serde_rolling_hash_disabled() {
        let mut recorder = TelemetryRecorder::new(RecorderConfig {
            channel_capacity: 100,
            epoch: SecurityEpoch::from_raw(7),
            enable_rolling_hash: false,
        });
        recorder
            .record(500, test_input("ext-x", HostcallType::EnvRead))
            .unwrap();
        recorder
            .record(600, test_input("ext-x", HostcallType::MemAlloc))
            .unwrap();
        let json = serde_json::to_string(&recorder).unwrap();
        let restored: TelemetryRecorder = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(restored.rolling_hash(), recorder.rolling_hash());
    }

    // ── Enrichment: query with empty records ────────────────────

    #[test]
    fn enrichment_query_empty_records() {
        let recorder = test_recorder();
        let query = TelemetryQuery::new(recorder.records());
        assert!(query.recent_by_extension("ext-001", 0, u64::MAX).is_empty());
        assert!(
            query
                .recent_by_type(HostcallType::FsRead, 0, u64::MAX)
                .is_empty()
        );
        assert!(query.anomaly_candidates(0, u64::MAX).is_empty());
        assert!(query.slow_calls(0, 0, u64::MAX).is_empty());
        let dist = query.type_distribution(0, u64::MAX);
        assert!(dist.is_empty());
    }

    // ── Enrichment: query boundary — exact timestamp match ──────

    #[test]
    fn enrichment_query_exact_timestamp_boundary() {
        let mut recorder = test_recorder();
        recorder
            .record(1000, test_input("ext-a", HostcallType::FsRead))
            .unwrap();
        recorder
            .record(2000, test_input("ext-a", HostcallType::FsWrite))
            .unwrap();
        recorder
            .record(3000, test_input("ext-a", HostcallType::NetworkSend))
            .unwrap();
        let query = TelemetryQuery::new(recorder.records());
        // Exact window [2000, 2000] should return only the single record at ts=2000.
        let results = query.recent_by_extension("ext-a", 2000, 2000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].hostcall_type, HostcallType::FsWrite);
    }

    // ── Enrichment: extension summary type_counts ───────────────

    #[test]
    fn enrichment_extension_summary_type_counts() {
        let recorder = populate_recorder();
        let query = TelemetryQuery::new(recorder.records());
        let summary = query.extension_summary("ext-001", 0, 10_000);
        assert_eq!(summary.type_counts.get(&HostcallType::FsRead), Some(&3));
        assert_eq!(
            summary.type_counts.get(&HostcallType::NetworkSend),
            Some(&1)
        );
        assert_eq!(summary.type_counts.get(&HostcallType::FsWrite), None);
    }

    // ── Enrichment: extension summary with timeout ──────────────

    #[test]
    fn enrichment_extension_summary_timeout_counted() {
        let mut recorder = test_recorder();
        let mut input = test_input("ext-t", HostcallType::TimerCreate);
        input.result_status = HostcallResult::Timeout;
        recorder.record(100, input).unwrap();
        recorder
            .record(200, test_input("ext-t", HostcallType::FsRead))
            .unwrap();
        let query = TelemetryQuery::new(recorder.records());
        let summary = query.extension_summary("ext-t", 0, 1000);
        assert_eq!(summary.total_calls, 2);
        assert_eq!(summary.timeout_count, 1);
        assert_eq!(summary.success_count, 1);
    }

    // ── Enrichment: content_hash empty recorder ─────────────────

    #[test]
    fn enrichment_content_hash_empty_recorder_deterministic() {
        let r1 = test_recorder();
        let r2 = test_recorder();
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    // ── Enrichment: decision_id affects content hash ────────────

    #[test]
    fn enrichment_decision_id_affects_content_hash() {
        let mut r1 = test_recorder();
        let mut r2 = test_recorder();
        let input1 = test_input("ext-001", HostcallType::FsRead);
        let mut input2 = test_input("ext-001", HostcallType::FsRead);
        input2.decision_id = Some("dec-999".to_string());
        r1.record(1000, input1).unwrap();
        r2.record(1000, input2).unwrap();
        // Different decision_id => different content hash
        assert_ne!(r1.records()[0].content_hash, r2.records()[0].content_hash);
    }

    // ── Enrichment: slow_calls boundary threshold ───────────────

    #[test]
    fn enrichment_slow_calls_boundary_threshold() {
        let mut recorder = test_recorder();
        let mut input_exact = test_input("ext-001", HostcallType::FsRead);
        input_exact.duration_ns = 5000; // Exactly at threshold
        recorder.record(100, input_exact).unwrap();
        let mut input_over = test_input("ext-001", HostcallType::FsWrite);
        input_over.duration_ns = 5001; // Over threshold
        recorder.record(200, input_over).unwrap();
        let query = TelemetryQuery::new(recorder.records());
        // slow_calls uses > threshold (not >=)
        let slow = query.slow_calls(5000, 0, 1000);
        assert_eq!(slow.len(), 1);
        assert_eq!(slow[0].hostcall_type, HostcallType::FsWrite);
    }

    // ── Enrichment: anomaly_candidates includes timeout ─────────

    #[test]
    fn enrichment_anomaly_candidates_includes_timeout() {
        let mut recorder = test_recorder();
        recorder
            .record(100, test_input("ext-001", HostcallType::FsRead))
            .unwrap(); // Success
        let mut timeout_input = test_input("ext-001", HostcallType::NetworkRecv);
        timeout_input.result_status = HostcallResult::Timeout;
        recorder.record(200, timeout_input).unwrap();
        let query = TelemetryQuery::new(recorder.records());
        let anomalies = query.anomaly_candidates(0, 1000);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].result_status, HostcallResult::Timeout);
    }

    // ── Enrichment: record JSON field check ─────────────────────

    #[test]
    fn enrichment_record_json_fields() {
        let mut recorder = test_recorder();
        recorder
            .record(42_000, test_input("ext-json", HostcallType::CryptoOp))
            .unwrap();
        let record = &recorder.records()[0];
        let json = serde_json::to_string(record).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["record_id"], 0);
        assert_eq!(v["timestamp_ns"], 42_000);
        assert_eq!(v["extension_id"], "ext-json");
        assert_eq!(v["hostcall_type"], "CryptoOp");
        assert_eq!(v["duration_ns"], 1_000);
        assert_eq!(v["decision_id"], serde_json::Value::Null);
    }

    // ── Enrichment: multiple epochs in single recorder ──────────

    #[test]
    fn enrichment_multiple_epochs_across_records() {
        let mut recorder = test_recorder();
        recorder
            .record(100, test_input("ext-001", HostcallType::FsRead))
            .unwrap();
        recorder.set_epoch(SecurityEpoch::from_raw(10));
        recorder
            .record(200, test_input("ext-001", HostcallType::FsWrite))
            .unwrap();
        recorder.set_epoch(SecurityEpoch::from_raw(20));
        recorder
            .record(300, test_input("ext-001", HostcallType::NetworkSend))
            .unwrap();
        assert_eq!(recorder.records()[0].epoch, SecurityEpoch::GENESIS);
        assert_eq!(recorder.records()[1].epoch, SecurityEpoch::from_raw(10));
        assert_eq!(recorder.records()[2].epoch, SecurityEpoch::from_raw(20));
        // Snapshot captures latest epoch
        let snap = recorder.snapshot();
        assert_eq!(snap.epoch, SecurityEpoch::from_raw(20));
    }
}
