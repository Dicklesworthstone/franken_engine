#![forbid(unsafe_code)]

//! Native-Addon Safety Membrane and Fast-Path Routing — RGC-407B
//!
//! Bead: bd-1lsy.5.9.2
//!
//! Implements the native-addon membrane, handle discipline,
//! crash-containment behavior, and fast-path versus fallback routing
//! over the hostcall session channel.  The membrane is a safety layer
//! ensuring native addons cannot escape capability confinement.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for native-addon membrane artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.native-addon-membrane.v1";
/// Component name used in evidence records and receipts.
pub const COMPONENT: &str = "native_addon_membrane";
/// Bead identifier originating this module.
pub const BEAD_ID: &str = "bd-1lsy.5.9.2";
/// Policy reference.
pub const POLICY_ID: &str = "RGC-407B";

/// Fixed-point unit: 1.0 in millionths.
pub const MILLIONTHS: u64 = 1_000_000;

/// Default maximum active handles per membrane.
pub const DEFAULT_MAX_ACTIVE_HANDLES: u64 = 4096;
/// Default maximum handle age in microseconds (60 seconds).
pub const DEFAULT_MAX_HANDLE_AGE_MICROS: u64 = 60_000_000;
/// Default crash containment mode.
pub const DEFAULT_CRASH_CONTAINMENT: CrashContainmentMode = CrashContainmentMode::Isolate;
/// Default fast-path max latency in microseconds (1 ms).
pub const DEFAULT_FAST_PATH_MAX_LATENCY_MICROS: u64 = 1_000;
/// Default fallback threshold failures.
pub const DEFAULT_FALLBACK_THRESHOLD_FAILURES: u64 = 5;
/// Crash count threshold to move to Shutdown verdict.
pub const CRASH_SHUTDOWN_THRESHOLD: u64 = 10;
/// Crash count threshold to move to Breached verdict.
pub const CRASH_BREACHED_THRESHOLD: u64 = 3;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn append_str(buf: &mut Vec<u8>, val: &str) {
    let bytes = val.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn compute_digest(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

// ---------------------------------------------------------------------------
// AddonAbi
// ---------------------------------------------------------------------------

/// ABI surface a native addon speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddonAbi {
    /// Node-API (napi) stable ABI.
    NodeApi,
    /// WASI preview-1 ABI.
    WasiPreview1,
    /// Native ES module ABI.
    NativeEsm,
    /// Custom FFI surface.
    CustomFfi,
}

impl AddonAbi {
    /// All ABI variants.
    pub const ALL: &[Self] = &[
        Self::NodeApi,
        Self::WasiPreview1,
        Self::NativeEsm,
        Self::CustomFfi,
    ];

    /// String label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NodeApi => "node_api",
            Self::WasiPreview1 => "wasi_preview1",
            Self::NativeEsm => "native_esm",
            Self::CustomFfi => "custom_ffi",
        }
    }
}

impl fmt::Display for AddonAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// HandleKind
// ---------------------------------------------------------------------------

/// Kind of handle managed by the membrane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleKind {
    /// Opaque JS value handle.
    ValueHandle,
    /// Buffer / ArrayBuffer backing.
    BufferHandle,
    /// Callback reference.
    CallbackHandle,
    /// Externally-owned resource.
    ExternalHandle,
    /// TypedArray view handle.
    TypedArrayHandle,
}

impl HandleKind {
    pub const ALL: &[Self] = &[
        Self::ValueHandle,
        Self::BufferHandle,
        Self::CallbackHandle,
        Self::ExternalHandle,
        Self::TypedArrayHandle,
    ];

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ValueHandle => "value_handle",
            Self::BufferHandle => "buffer_handle",
            Self::CallbackHandle => "callback_handle",
            Self::ExternalHandle => "external_handle",
            Self::TypedArrayHandle => "typed_array_handle",
        }
    }
}

impl fmt::Display for HandleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// HandleState
// ---------------------------------------------------------------------------

/// Lifecycle state of a membrane handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleState {
    /// Handle is live and reachable.
    Active,
    /// Handle has been explicitly revoked.
    Revoked,
    /// Handle escaped capability containment.
    Escaped,
    /// Handle has been finalized and cannot be used.
    Finalized,
}

impl HandleState {
    pub const ALL: &[Self] = &[Self::Active, Self::Revoked, Self::Escaped, Self::Finalized];

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Escaped => "escaped",
            Self::Finalized => "finalized",
        }
    }

    /// Whether this state means the handle is still usable.
    #[must_use]
    pub const fn is_live(&self) -> bool {
        matches!(self, Self::Active)
    }
}

impl fmt::Display for HandleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CrashContainmentMode
// ---------------------------------------------------------------------------

/// Strategy for containing crashes in native addons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashContainmentMode {
    /// Terminate the entire host process.
    Terminate,
    /// Isolate the crashing addon; other addons continue.
    Isolate,
    /// Route to a fallback implementation.
    Fallback,
    /// Log the crash and continue execution.
    LogAndContinue,
}

impl CrashContainmentMode {
    pub const ALL: &[Self] = &[
        Self::Terminate,
        Self::Isolate,
        Self::Fallback,
        Self::LogAndContinue,
    ];

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Terminate => "terminate",
            Self::Isolate => "isolate",
            Self::Fallback => "fallback",
            Self::LogAndContinue => "log_and_continue",
        }
    }
}

impl fmt::Display for CrashContainmentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RouteDecision
// ---------------------------------------------------------------------------

/// Routing decision for an addon invocation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteDecision {
    /// Use the fast path (direct hostcall channel).
    FastPath,
    /// Use the slow path (checked channel).
    SlowPath,
    /// Route to a fallback implementation.
    Fallback,
    /// Deny the invocation entirely.
    Deny {
        /// Reason for denial.
        reason: String,
    },
}

impl RouteDecision {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::FastPath => "fast_path",
            Self::SlowPath => "slow_path",
            Self::Fallback => "fallback",
            Self::Deny { .. } => "deny",
        }
    }

    /// Whether the call is allowed (not denied).
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        !matches!(self, Self::Deny { .. })
    }

    /// Whether this is the fast path.
    #[must_use]
    pub const fn is_fast_path(&self) -> bool {
        matches!(self, Self::FastPath)
    }
}

impl fmt::Display for RouteDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deny { reason } => write!(f, "deny: {reason}"),
            other => f.write_str(other.as_str()),
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilityKind
// ---------------------------------------------------------------------------

/// Capability a native addon may request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    /// Filesystem read.
    ReadFs,
    /// Filesystem write.
    WriteFs,
    /// Network access.
    Network,
    /// Process spawning.
    Process,
    /// Cryptographic operations.
    Crypto,
    /// Timer / scheduling.
    Timer,
    /// Console I/O.
    Console,
    /// Buffer allocation.
    Buffer,
}

impl CapabilityKind {
    pub const ALL: &[Self] = &[
        Self::ReadFs,
        Self::WriteFs,
        Self::Network,
        Self::Process,
        Self::Crypto,
        Self::Timer,
        Self::Console,
        Self::Buffer,
    ];

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ReadFs => "read_fs",
            Self::WriteFs => "write_fs",
            Self::Network => "network",
            Self::Process => "process",
            Self::Crypto => "crypto",
            Self::Timer => "timer",
            Self::Console => "console",
            Self::Buffer => "buffer",
        }
    }
}

impl fmt::Display for CapabilityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ViolationKind
// ---------------------------------------------------------------------------

/// Kind of membrane violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// Active handle count exceeds policy limit.
    HandleLimitExceeded,
    /// A handle escaped capability containment.
    HandleEscaped,
    /// Addon used a capability it wasn't granted.
    UnauthorizedCapability,
    /// Addon process crashed.
    CrashDetected,
    /// Addon declared one ABI but used another.
    AbiMismatch,
    /// Addon was not registered with the membrane.
    UnregisteredAddon,
}

impl ViolationKind {
    pub const ALL: &[Self] = &[
        Self::HandleLimitExceeded,
        Self::HandleEscaped,
        Self::UnauthorizedCapability,
        Self::CrashDetected,
        Self::AbiMismatch,
        Self::UnregisteredAddon,
    ];

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::HandleLimitExceeded => "handle_limit_exceeded",
            Self::HandleEscaped => "handle_escaped",
            Self::UnauthorizedCapability => "unauthorized_capability",
            Self::CrashDetected => "crash_detected",
            Self::AbiMismatch => "abi_mismatch",
            Self::UnregisteredAddon => "unregistered_addon",
        }
    }
}

impl fmt::Display for ViolationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MembraneVerdict
// ---------------------------------------------------------------------------

/// Overall membrane health verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembraneVerdict {
    /// All invariants satisfied; no violations.
    Healthy,
    /// Minor violations detected but containment holds.
    Degraded,
    /// Capability containment has been breached.
    Breached,
    /// Membrane must shut down due to unrecoverable state.
    Shutdown,
}

impl MembraneVerdict {
    pub const ALL: &[Self] = &[
        Self::Healthy,
        Self::Degraded,
        Self::Breached,
        Self::Shutdown,
    ];

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Breached => "breached",
            Self::Shutdown => "shutdown",
        }
    }

    /// Whether the membrane is still operational.
    #[must_use]
    pub const fn is_operational(&self) -> bool {
        matches!(self, Self::Healthy | Self::Degraded)
    }
}

impl fmt::Display for MembraneVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// HandleRecord
// ---------------------------------------------------------------------------

/// A single handle tracked by the membrane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleRecord {
    /// Unique handle identifier.
    pub id: u64,
    /// Handle kind.
    pub kind: HandleKind,
    /// Current lifecycle state.
    pub state: HandleState,
    /// Scope that owns this handle.
    pub owner_scope: String,
    /// Security epoch at creation.
    pub creation_epoch: SecurityEpoch,
    /// Content hash for integrity.
    pub content_hash: ContentHash,
}

impl HandleRecord {
    /// Create a new active handle record.
    #[must_use]
    pub fn new(
        id: u64,
        kind: HandleKind,
        owner_scope: &str,
        creation_epoch: SecurityEpoch,
    ) -> Self {
        let mut buf = Vec::new();
        append_u64(&mut buf, id);
        append_str(&mut buf, kind.as_str());
        append_str(&mut buf, owner_scope);
        append_u64(&mut buf, creation_epoch.as_u64());
        let content_hash = compute_digest(&buf);
        Self {
            id,
            kind,
            state: HandleState::Active,
            owner_scope: owner_scope.to_string(),
            creation_epoch,
            content_hash,
        }
    }

    /// Seal (recompute) the content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_u64(&mut buf, self.id);
        append_str(&mut buf, self.kind.as_str());
        append_str(&mut buf, self.state.as_str());
        append_str(&mut buf, &self.owner_scope);
        append_u64(&mut buf, self.creation_epoch.as_u64());
        self.content_hash = compute_digest(&buf);
    }
}

// ---------------------------------------------------------------------------
// MembranePolicy
// ---------------------------------------------------------------------------

/// Configuration for the membrane enforcement policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembranePolicy {
    /// Maximum number of concurrently active handles.
    pub max_active_handles: u64,
    /// Maximum handle age in microseconds before forced revocation.
    pub max_handle_age_micros: u64,
    /// Whether external handles (raw resource) are allowed.
    pub allow_external_handles: bool,
    /// Whether callbacks may escape scope.
    pub allow_callback_escape: bool,
    /// Strategy for crash containment.
    pub crash_containment_mode: CrashContainmentMode,
}

impl Default for MembranePolicy {
    fn default() -> Self {
        Self {
            max_active_handles: DEFAULT_MAX_ACTIVE_HANDLES,
            max_handle_age_micros: DEFAULT_MAX_HANDLE_AGE_MICROS,
            allow_external_handles: false,
            allow_callback_escape: false,
            crash_containment_mode: DEFAULT_CRASH_CONTAINMENT,
        }
    }
}

// ---------------------------------------------------------------------------
// RoutingConfig
// ---------------------------------------------------------------------------

/// Configuration for fast-path / slow-path routing decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Maximum latency (microseconds) for a call to qualify for fast path.
    pub fast_path_max_latency_micros: u64,
    /// Set of ABIs allowed on the fast path.
    pub fast_path_allowed_abis: BTreeSet<AddonAbi>,
    /// Number of recent failures before triggering fallback.
    pub fallback_threshold_failures: u64,
    /// Whether to deny invocations from unregistered addons.
    pub deny_unregistered: bool,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        let mut allowed = BTreeSet::new();
        allowed.insert(AddonAbi::NodeApi);
        allowed.insert(AddonAbi::WasiPreview1);
        Self {
            fast_path_max_latency_micros: DEFAULT_FAST_PATH_MAX_LATENCY_MICROS,
            fast_path_allowed_abis: allowed,
            fallback_threshold_failures: DEFAULT_FALLBACK_THRESHOLD_FAILURES,
            deny_unregistered: true,
        }
    }
}

// ---------------------------------------------------------------------------
// AddonRegistration
// ---------------------------------------------------------------------------

/// Registration entry for a native addon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddonRegistration {
    /// Unique addon identifier.
    pub addon_id: String,
    /// ABI the addon speaks.
    pub abi: AddonAbi,
    /// Content hash of the addon binary.
    pub content_hash: ContentHash,
    /// Capabilities granted to this addon.
    pub capabilities: BTreeSet<CapabilityKind>,
    /// Epoch at which the addon was registered.
    pub registered_epoch: SecurityEpoch,
}

impl AddonRegistration {
    /// Create a new registration.
    #[must_use]
    pub fn new(
        addon_id: &str,
        abi: AddonAbi,
        content_hash: ContentHash,
        capabilities: BTreeSet<CapabilityKind>,
        registered_epoch: SecurityEpoch,
    ) -> Self {
        Self {
            addon_id: addon_id.to_string(),
            abi,
            content_hash,
            capabilities,
            registered_epoch,
        }
    }
}

// ---------------------------------------------------------------------------
// Violation
// ---------------------------------------------------------------------------

/// A recorded membrane violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    /// Category of violation.
    pub kind: ViolationKind,
    /// Addon that caused the violation (empty if unknown).
    pub addon_id: String,
    /// Human-readable detail.
    pub detail: String,
    /// When the violation occurred (microseconds since epoch).
    pub timestamp_micros: u64,
}

impl Violation {
    /// Create a new violation record.
    #[must_use]
    pub fn new(kind: ViolationKind, addon_id: &str, detail: &str, timestamp_micros: u64) -> Self {
        Self {
            kind,
            addon_id: addon_id.to_string(),
            detail: detail.to_string(),
            timestamp_micros,
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Auditable receipt for a membrane evaluation decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Component label.
    pub component: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Security epoch of the evaluation.
    pub epoch: SecurityEpoch,
    /// Hash of the inputs considered.
    pub input_hash: ContentHash,
    /// Hash of the verdict.
    pub verdict_hash: ContentHash,
    /// Timestamp in microseconds.
    pub timestamp_micros: u64,
}

impl DecisionReceipt {
    /// Seal the receipt by recomputing content hashes.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.schema_version);
        append_str(&mut buf, &self.component);
        append_str(&mut buf, &self.bead_id);
        append_str(&mut buf, &self.policy_id);
        append_u64(&mut buf, self.epoch.as_u64());
        buf.extend_from_slice(self.input_hash.as_bytes());
        append_u64(&mut buf, self.timestamp_micros);
        self.verdict_hash = compute_digest(&buf);
    }
}

// ---------------------------------------------------------------------------
// MembraneReport
// ---------------------------------------------------------------------------

/// Report produced by membrane evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembraneReport {
    /// Number of registered addons.
    pub registered_addon_count: usize,
    /// Number of currently active handles.
    pub active_handles: u64,
    /// Number of revoked handles.
    pub revoked_handles: u64,
    /// Number of escaped handles.
    pub escaped_handles: u64,
    /// Total crash count.
    pub crash_count: u64,
    /// Routing statistics: total calls.
    pub total_calls: u64,
    /// Routing statistics: fast-path calls.
    pub fast_path_calls: u64,
    /// Routing statistics: slow-path calls.
    pub slow_path_calls: u64,
    /// Routing statistics: fallback calls.
    pub fallback_calls: u64,
    /// Routing statistics: denied calls.
    pub denied_calls: u64,
    /// Overall verdict.
    pub verdict: MembraneVerdict,
    /// List of violations detected.
    pub violations: Vec<Violation>,
    /// Decision receipt.
    pub receipt: DecisionReceipt,
}

// ---------------------------------------------------------------------------
// MembraneError
// ---------------------------------------------------------------------------

/// Error conditions in the membrane module.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembraneError {
    /// Handle limit exceeded.
    #[error("handle limit exceeded: {detail}")]
    HandleLimitExceeded {
        /// Details about the exceeded limit.
        detail: String,
    },
    /// Handle not found.
    #[error("handle not found: id={handle_id}")]
    HandleNotFound {
        /// The handle ID that was not found.
        handle_id: u64,
    },
    /// Handle already revoked.
    #[error("handle already revoked: id={handle_id}")]
    HandleAlreadyRevoked {
        /// The handle ID.
        handle_id: u64,
    },
    /// Handle already finalized.
    #[error("handle already finalized: id={handle_id}")]
    HandleAlreadyFinalized {
        /// The handle ID.
        handle_id: u64,
    },
    /// Addon not registered.
    #[error("addon not registered: {addon_id}")]
    AddonNotRegistered {
        /// The addon identifier.
        addon_id: String,
    },
    /// Addon already registered.
    #[error("addon already registered: {addon_id}")]
    AddonAlreadyRegistered {
        /// The addon identifier.
        addon_id: String,
    },
    /// External handles not allowed by policy.
    #[error("external handles not allowed by policy")]
    ExternalHandlesNotAllowed,
    /// Callback escape not allowed by policy.
    #[error("callback escape not allowed by policy")]
    CallbackEscapeNotAllowed,
    /// Membrane is shut down.
    #[error("membrane is shut down")]
    MembraneShutDown,
}

// ---------------------------------------------------------------------------
// MembraneState
// ---------------------------------------------------------------------------

/// Mutable membrane state tracking registrations, handles, and statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembraneState {
    /// Registered addons.
    pub registrations: Vec<AddonRegistration>,
    /// Handle table.
    pub handle_table: Vec<HandleRecord>,
    /// Number of currently active handles.
    pub active_handles: u64,
    /// Number of revoked handles.
    pub revoked_handles: u64,
    /// Cumulative crash count.
    pub crash_count: u64,
    /// Total calls routed through the membrane.
    pub total_calls: u64,
    /// Calls that went through the fast path.
    pub fast_path_calls: u64,
    /// Calls that went through the slow path.
    pub slow_path_calls: u64,
    /// Calls that fell back.
    pub fallback_calls: u64,
    /// Calls that were denied.
    pub denied_calls: u64,
    /// Violations recorded.
    pub violations: Vec<Violation>,
    /// Next handle ID to allocate.
    next_handle_id: u64,
    /// Whether the membrane is shut down.
    is_shutdown: bool,
    /// Per-addon recent failure counts (addon_id, failure_count).
    addon_failure_counts: Vec<(String, u64)>,
}

impl MembraneState {
    /// Create a new empty membrane state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registrations: Vec::new(),
            handle_table: Vec::new(),
            active_handles: 0,
            revoked_handles: 0,
            crash_count: 0,
            total_calls: 0,
            fast_path_calls: 0,
            slow_path_calls: 0,
            fallback_calls: 0,
            denied_calls: 0,
            violations: Vec::new(),
            next_handle_id: 1,
            is_shutdown: false,
            addon_failure_counts: Vec::new(),
        }
    }

    /// Whether the membrane is in shutdown state.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.is_shutdown
    }

    /// Register a native addon with the membrane.
    pub fn register_addon(&mut self, registration: AddonRegistration) -> Result<(), MembraneError> {
        if self.is_shutdown {
            return Err(MembraneError::MembraneShutDown);
        }
        if self
            .registrations
            .iter()
            .any(|r| r.addon_id == registration.addon_id)
        {
            return Err(MembraneError::AddonAlreadyRegistered {
                addon_id: registration.addon_id,
            });
        }
        self.registrations.push(registration);
        Ok(())
    }

    /// Look up a registration by addon ID.
    #[must_use]
    pub fn find_registration(&self, addon_id: &str) -> Option<&AddonRegistration> {
        self.registrations.iter().find(|r| r.addon_id == addon_id)
    }

    /// Allocate a new handle, returning its ID.
    pub fn allocate_handle(
        &mut self,
        addon_id: &str,
        kind: HandleKind,
        epoch: SecurityEpoch,
        policy: &MembranePolicy,
    ) -> Result<u64, MembraneError> {
        if self.is_shutdown {
            return Err(MembraneError::MembraneShutDown);
        }
        // Verify addon is registered.
        if !self.registrations.iter().any(|r| r.addon_id == addon_id) {
            return Err(MembraneError::AddonNotRegistered {
                addon_id: addon_id.to_string(),
            });
        }
        // Check policy: external handles.
        if kind == HandleKind::ExternalHandle && !policy.allow_external_handles {
            return Err(MembraneError::ExternalHandlesNotAllowed);
        }
        // Check active handle limit.
        if self.active_handles >= policy.max_active_handles {
            return Err(MembraneError::HandleLimitExceeded {
                detail: format!(
                    "active={}, max={}",
                    self.active_handles, policy.max_active_handles
                ),
            });
        }
        let id = self.next_handle_id;
        self.next_handle_id += 1;
        let record = HandleRecord::new(id, kind, addon_id, epoch);
        self.handle_table.push(record);
        self.active_handles += 1;
        Ok(id)
    }

    /// Revoke an active handle.
    pub fn revoke_handle(&mut self, handle_id: u64) -> Result<(), MembraneError> {
        if self.is_shutdown {
            return Err(MembraneError::MembraneShutDown);
        }
        let record = self
            .handle_table
            .iter_mut()
            .find(|r| r.id == handle_id)
            .ok_or(MembraneError::HandleNotFound { handle_id })?;
        match record.state {
            HandleState::Active => {
                record.state = HandleState::Revoked;
                record.seal();
                self.active_handles = self.active_handles.saturating_sub(1);
                self.revoked_handles += 1;
                Ok(())
            }
            HandleState::Revoked => Err(MembraneError::HandleAlreadyRevoked { handle_id }),
            HandleState::Finalized => Err(MembraneError::HandleAlreadyFinalized { handle_id }),
            HandleState::Escaped => {
                // Escaped handles can be revoked to contain them.
                record.state = HandleState::Revoked;
                record.seal();
                self.revoked_handles += 1;
                Ok(())
            }
        }
    }

    /// Finalize an active or revoked handle (terminal state).
    pub fn finalize_handle(&mut self, handle_id: u64) -> Result<(), MembraneError> {
        if self.is_shutdown {
            return Err(MembraneError::MembraneShutDown);
        }
        let record = self
            .handle_table
            .iter_mut()
            .find(|r| r.id == handle_id)
            .ok_or(MembraneError::HandleNotFound { handle_id })?;
        match record.state {
            HandleState::Finalized => Err(MembraneError::HandleAlreadyFinalized { handle_id }),
            HandleState::Active => {
                record.state = HandleState::Finalized;
                record.seal();
                self.active_handles = self.active_handles.saturating_sub(1);
                Ok(())
            }
            HandleState::Revoked | HandleState::Escaped => {
                record.state = HandleState::Finalized;
                record.seal();
                Ok(())
            }
        }
    }

    /// Mark a handle as escaped (capability breach).
    pub fn mark_handle_escaped(
        &mut self,
        handle_id: u64,
        timestamp_micros: u64,
    ) -> Result<(), MembraneError> {
        if self.is_shutdown {
            return Err(MembraneError::MembraneShutDown);
        }
        let record = self
            .handle_table
            .iter_mut()
            .find(|r| r.id == handle_id)
            .ok_or(MembraneError::HandleNotFound { handle_id })?;
        if record.state == HandleState::Finalized {
            return Err(MembraneError::HandleAlreadyFinalized { handle_id });
        }
        let addon_id = record.owner_scope.clone();
        if record.state == HandleState::Active {
            self.active_handles = self.active_handles.saturating_sub(1);
        }
        record.state = HandleState::Escaped;
        record.seal();
        self.violations.push(Violation::new(
            ViolationKind::HandleEscaped,
            &addon_id,
            &format!("handle {handle_id} escaped containment"),
            timestamp_micros,
        ));
        Ok(())
    }

    /// Route a call for the given addon through the membrane.
    pub fn route_call(&mut self, addon_id: &str, config: &RoutingConfig) -> RouteDecision {
        self.total_calls += 1;

        // Check registration.
        let registration = match self.find_registration(addon_id) {
            Some(r) => r.clone(),
            None => {
                if config.deny_unregistered {
                    self.denied_calls += 1;
                    return RouteDecision::Deny {
                        reason: format!("unregistered addon: {addon_id}"),
                    };
                }
                // Unregistered but not denied: slow path.
                self.slow_path_calls += 1;
                return RouteDecision::SlowPath;
            }
        };

        // Check failure count for fallback.
        let failure_count = self
            .addon_failure_counts
            .iter()
            .find(|(id, _)| id == addon_id)
            .map(|(_, c)| *c)
            .unwrap_or(0);
        if failure_count >= config.fallback_threshold_failures {
            self.fallback_calls += 1;
            return RouteDecision::Fallback;
        }

        // Check if ABI is allowed on fast path.
        if config.fast_path_allowed_abis.contains(&registration.abi) {
            self.fast_path_calls += 1;
            RouteDecision::FastPath
        } else {
            self.slow_path_calls += 1;
            RouteDecision::SlowPath
        }
    }

    /// Record a crash for the given addon.
    pub fn record_crash(&mut self, addon_id: &str, detail: &str, timestamp_micros: u64) {
        self.crash_count += 1;
        self.violations.push(Violation::new(
            ViolationKind::CrashDetected,
            addon_id,
            detail,
            timestamp_micros,
        ));
        // Increment failure count.
        if let Some(entry) = self
            .addon_failure_counts
            .iter_mut()
            .find(|(id, _)| id == addon_id)
        {
            entry.1 += 1;
        } else {
            self.addon_failure_counts.push((addon_id.to_string(), 1));
        }
    }

    /// Record a violation.
    pub fn record_violation(&mut self, violation: Violation) {
        self.violations.push(violation);
    }

    /// Get the failure count for a given addon.
    #[must_use]
    pub fn addon_failure_count(&self, addon_id: &str) -> u64 {
        self.addon_failure_counts
            .iter()
            .find(|(id, _)| id == addon_id)
            .map(|(_, c)| *c)
            .unwrap_or(0)
    }

    /// Count handles in a given state.
    #[must_use]
    pub fn count_handles_in_state(&self, state: HandleState) -> u64 {
        self.handle_table
            .iter()
            .filter(|h| h.state == state)
            .count() as u64
    }

    /// Get a handle record by ID.
    #[must_use]
    pub fn get_handle(&self, handle_id: u64) -> Option<&HandleRecord> {
        self.handle_table.iter().find(|h| h.id == handle_id)
    }

    /// Get all handles owned by a specific addon.
    #[must_use]
    pub fn handles_for_addon(&self, addon_id: &str) -> Vec<&HandleRecord> {
        self.handle_table
            .iter()
            .filter(|h| h.owner_scope == addon_id)
            .collect()
    }

    /// Mark the membrane as shut down.
    pub fn shutdown(&mut self) {
        self.is_shutdown = true;
    }

    /// Reset failure count for an addon (e.g., after recovery).
    pub fn reset_failure_count(&mut self, addon_id: &str) {
        if let Some(entry) = self
            .addon_failure_counts
            .iter_mut()
            .find(|(id, _)| id == addon_id)
        {
            entry.1 = 0;
        }
    }

    /// Total number of handles (all states).
    #[must_use]
    pub fn total_handle_count(&self) -> usize {
        self.handle_table.len()
    }
}

impl Default for MembraneState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// evaluate_membrane
// ---------------------------------------------------------------------------

/// Evaluate the membrane state against the given policy, producing a report.
#[must_use]
pub fn evaluate_membrane(
    state: &MembraneState,
    policy: &MembranePolicy,
    epoch: &SecurityEpoch,
    timestamp_micros: u64,
) -> MembraneReport {
    let mut violations: Vec<Violation> = state.violations.clone();

    // Check handle limit.
    if state.active_handles > policy.max_active_handles {
        violations.push(Violation::new(
            ViolationKind::HandleLimitExceeded,
            "",
            &format!(
                "active handles {} exceed limit {}",
                state.active_handles, policy.max_active_handles
            ),
            timestamp_micros,
        ));
    }

    // Check for escaped handles.
    let escaped = state.count_handles_in_state(HandleState::Escaped);

    // Check external handles policy.
    if !policy.allow_external_handles {
        let external_active = state
            .handle_table
            .iter()
            .filter(|h| h.kind == HandleKind::ExternalHandle && h.state == HandleState::Active)
            .count() as u64;
        if external_active > 0 {
            violations.push(Violation::new(
                ViolationKind::UnauthorizedCapability,
                "",
                &format!("{external_active} active external handles violate policy"),
                timestamp_micros,
            ));
        }
    }

    // Determine verdict.
    let verdict = if state.crash_count >= CRASH_SHUTDOWN_THRESHOLD {
        MembraneVerdict::Shutdown
    } else if escaped > 0 || state.crash_count >= CRASH_BREACHED_THRESHOLD {
        MembraneVerdict::Breached
    } else if state.active_handles > policy.max_active_handles || !state.violations.is_empty() {
        MembraneVerdict::Degraded
    } else {
        MembraneVerdict::Healthy
    };

    // Compute input hash over state summary.
    let input_hash = {
        let mut buf = Vec::new();
        append_u64(&mut buf, state.active_handles);
        append_u64(&mut buf, state.revoked_handles);
        append_u64(&mut buf, state.crash_count);
        append_u64(&mut buf, state.total_calls);
        append_u64(&mut buf, escaped);
        append_u64(&mut buf, state.registrations.len() as u64);
        compute_digest(&buf)
    };

    let receipt = compute_receipt(epoch, &input_hash, verdict, timestamp_micros);

    MembraneReport {
        registered_addon_count: state.registrations.len(),
        active_handles: state.active_handles,
        revoked_handles: state.revoked_handles,
        escaped_handles: escaped,
        crash_count: state.crash_count,
        total_calls: state.total_calls,
        fast_path_calls: state.fast_path_calls,
        slow_path_calls: state.slow_path_calls,
        fallback_calls: state.fallback_calls,
        denied_calls: state.denied_calls,
        verdict,
        violations,
        receipt,
    }
}

// ---------------------------------------------------------------------------
// compute_receipt
// ---------------------------------------------------------------------------

/// Build a decision receipt for the membrane evaluation.
#[must_use]
pub fn compute_receipt(
    epoch: &SecurityEpoch,
    input_hash: &ContentHash,
    verdict: MembraneVerdict,
    timestamp_micros: u64,
) -> DecisionReceipt {
    let verdict_data = {
        let mut buf = Vec::new();
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, COMPONENT);
        append_str(&mut buf, BEAD_ID);
        append_str(&mut buf, POLICY_ID);
        append_u64(&mut buf, epoch.as_u64());
        buf.extend_from_slice(input_hash.as_bytes());
        append_str(&mut buf, verdict.as_str());
        append_u64(&mut buf, timestamp_micros);
        compute_digest(&buf)
    };

    DecisionReceipt {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        epoch: *epoch,
        input_hash: input_hash.clone(),
        verdict_hash: verdict_data,
        timestamp_micros,
    }
}

// ---------------------------------------------------------------------------
// Capability checking helpers
// ---------------------------------------------------------------------------

/// Check whether an addon has a specific capability.
#[must_use]
pub fn addon_has_capability(state: &MembraneState, addon_id: &str, cap: CapabilityKind) -> bool {
    state
        .find_registration(addon_id)
        .map(|r| r.capabilities.contains(&cap))
        .unwrap_or(false)
}

/// Validate that an addon only uses capabilities it was granted.
#[must_use]
pub fn validate_capabilities(
    state: &MembraneState,
    addon_id: &str,
    requested: &BTreeSet<CapabilityKind>,
) -> Vec<CapabilityKind> {
    let granted = state
        .find_registration(addon_id)
        .map(|r| &r.capabilities)
        .cloned()
        .unwrap_or_default();
    requested.difference(&granted).copied().collect()
}

/// Revoke all active handles for a given addon.
pub fn revoke_all_handles_for_addon(state: &mut MembraneState, addon_id: &str) -> Vec<u64> {
    let ids: Vec<u64> = state
        .handle_table
        .iter()
        .filter(|h| h.owner_scope == addon_id && h.state == HandleState::Active)
        .map(|h| h.id)
        .collect();
    let mut revoked = Vec::new();
    for id in ids {
        if state.revoke_handle(id).is_ok() {
            revoked.push(id);
        }
    }
    revoked
}

/// Count registrations by ABI.
#[must_use]
pub fn count_registrations_by_abi(state: &MembraneState, abi: AddonAbi) -> usize {
    state.registrations.iter().filter(|r| r.abi == abi).count()
}

/// Compute a summary content hash over the entire membrane state.
#[must_use]
pub fn compute_state_hash(state: &MembraneState) -> ContentHash {
    let mut buf = Vec::new();
    append_u64(&mut buf, state.active_handles);
    append_u64(&mut buf, state.revoked_handles);
    append_u64(&mut buf, state.crash_count);
    append_u64(&mut buf, state.total_calls);
    append_u64(&mut buf, state.fast_path_calls);
    append_u64(&mut buf, state.slow_path_calls);
    append_u64(&mut buf, state.fallback_calls);
    append_u64(&mut buf, state.denied_calls);
    append_u64(&mut buf, state.registrations.len() as u64);
    append_u64(&mut buf, state.handle_table.len() as u64);
    for reg in &state.registrations {
        append_str(&mut buf, &reg.addon_id);
        append_str(&mut buf, reg.abi.as_str());
    }
    for handle in &state.handle_table {
        append_u64(&mut buf, handle.id);
        append_str(&mut buf, handle.kind.as_str());
        append_str(&mut buf, handle.state.as_str());
    }
    compute_digest(&buf)
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn default_policy() -> MembranePolicy {
        MembranePolicy::default()
    }

    fn default_routing() -> RoutingConfig {
        RoutingConfig::default()
    }

    fn make_registration(
        addon_id: &str,
        abi: AddonAbi,
        caps: &[CapabilityKind],
    ) -> AddonRegistration {
        AddonRegistration::new(
            addon_id,
            abi,
            ContentHash::compute(addon_id.as_bytes()),
            caps.iter().copied().collect(),
            epoch(1),
        )
    }

    fn make_state_with_addon(addon_id: &str) -> MembraneState {
        let mut state = MembraneState::new();
        let reg = make_registration(addon_id, AddonAbi::NodeApi, &[CapabilityKind::Buffer]);
        state.register_addon(reg).unwrap();
        state
    }

    // -- AddonAbi --

    #[test]
    fn addon_abi_as_str() {
        assert_eq!(AddonAbi::NodeApi.as_str(), "node_api");
        assert_eq!(AddonAbi::WasiPreview1.as_str(), "wasi_preview1");
        assert_eq!(AddonAbi::NativeEsm.as_str(), "native_esm");
        assert_eq!(AddonAbi::CustomFfi.as_str(), "custom_ffi");
    }

    #[test]
    fn addon_abi_display() {
        assert_eq!(format!("{}", AddonAbi::NodeApi), "node_api");
        assert_eq!(format!("{}", AddonAbi::CustomFfi), "custom_ffi");
    }

    #[test]
    fn addon_abi_all_count() {
        assert_eq!(AddonAbi::ALL.len(), 4);
    }

    #[test]
    fn addon_abi_serde_roundtrip() {
        for abi in AddonAbi::ALL {
            let json = serde_json::to_string(abi).unwrap();
            let back: AddonAbi = serde_json::from_str(&json).unwrap();
            assert_eq!(*abi, back);
        }
    }

    #[test]
    fn addon_abi_ordering() {
        assert!(AddonAbi::NodeApi < AddonAbi::WasiPreview1);
        assert!(AddonAbi::WasiPreview1 < AddonAbi::NativeEsm);
        assert!(AddonAbi::NativeEsm < AddonAbi::CustomFfi);
    }

    // -- HandleKind --

    #[test]
    fn handle_kind_as_str() {
        assert_eq!(HandleKind::ValueHandle.as_str(), "value_handle");
        assert_eq!(HandleKind::BufferHandle.as_str(), "buffer_handle");
        assert_eq!(HandleKind::CallbackHandle.as_str(), "callback_handle");
        assert_eq!(HandleKind::ExternalHandle.as_str(), "external_handle");
        assert_eq!(HandleKind::TypedArrayHandle.as_str(), "typed_array_handle");
    }

    #[test]
    fn handle_kind_display() {
        assert_eq!(format!("{}", HandleKind::ValueHandle), "value_handle");
    }

    #[test]
    fn handle_kind_all_count() {
        assert_eq!(HandleKind::ALL.len(), 5);
    }

    #[test]
    fn handle_kind_serde_roundtrip() {
        for kind in HandleKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: HandleKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    // -- HandleState --

    #[test]
    fn handle_state_as_str() {
        assert_eq!(HandleState::Active.as_str(), "active");
        assert_eq!(HandleState::Revoked.as_str(), "revoked");
        assert_eq!(HandleState::Escaped.as_str(), "escaped");
        assert_eq!(HandleState::Finalized.as_str(), "finalized");
    }

    #[test]
    fn handle_state_is_live() {
        assert!(HandleState::Active.is_live());
        assert!(!HandleState::Revoked.is_live());
        assert!(!HandleState::Escaped.is_live());
        assert!(!HandleState::Finalized.is_live());
    }

    #[test]
    fn handle_state_display() {
        assert_eq!(format!("{}", HandleState::Escaped), "escaped");
    }

    #[test]
    fn handle_state_serde_roundtrip() {
        for st in HandleState::ALL {
            let json = serde_json::to_string(st).unwrap();
            let back: HandleState = serde_json::from_str(&json).unwrap();
            assert_eq!(*st, back);
        }
    }

    // -- CrashContainmentMode --

    #[test]
    fn crash_containment_as_str() {
        assert_eq!(CrashContainmentMode::Terminate.as_str(), "terminate");
        assert_eq!(CrashContainmentMode::Isolate.as_str(), "isolate");
        assert_eq!(CrashContainmentMode::Fallback.as_str(), "fallback");
        assert_eq!(
            CrashContainmentMode::LogAndContinue.as_str(),
            "log_and_continue"
        );
    }

    #[test]
    fn crash_containment_display() {
        assert_eq!(format!("{}", CrashContainmentMode::Isolate), "isolate");
    }

    #[test]
    fn crash_containment_serde_roundtrip() {
        for mode in CrashContainmentMode::ALL {
            let json = serde_json::to_string(mode).unwrap();
            let back: CrashContainmentMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*mode, back);
        }
    }

    // -- RouteDecision --

    #[test]
    fn route_decision_as_str() {
        assert_eq!(RouteDecision::FastPath.as_str(), "fast_path");
        assert_eq!(RouteDecision::SlowPath.as_str(), "slow_path");
        assert_eq!(RouteDecision::Fallback.as_str(), "fallback");
        assert_eq!(RouteDecision::Deny { reason: "x".into() }.as_str(), "deny");
    }

    #[test]
    fn route_decision_is_allowed() {
        assert!(RouteDecision::FastPath.is_allowed());
        assert!(RouteDecision::SlowPath.is_allowed());
        assert!(RouteDecision::Fallback.is_allowed());
        assert!(!RouteDecision::Deny { reason: "x".into() }.is_allowed());
    }

    #[test]
    fn route_decision_is_fast_path() {
        assert!(RouteDecision::FastPath.is_fast_path());
        assert!(!RouteDecision::SlowPath.is_fast_path());
    }

    #[test]
    fn route_decision_display() {
        assert_eq!(format!("{}", RouteDecision::FastPath), "fast_path");
        assert_eq!(
            format!(
                "{}",
                RouteDecision::Deny {
                    reason: "bad".into()
                }
            ),
            "deny: bad"
        );
    }

    #[test]
    fn route_decision_serde_roundtrip() {
        let decisions = vec![
            RouteDecision::FastPath,
            RouteDecision::SlowPath,
            RouteDecision::Fallback,
            RouteDecision::Deny {
                reason: "test".into(),
            },
        ];
        for d in &decisions {
            let json = serde_json::to_string(d).unwrap();
            let back: RouteDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(*d, back);
        }
    }

    // -- CapabilityKind --

    #[test]
    fn capability_kind_as_str() {
        assert_eq!(CapabilityKind::ReadFs.as_str(), "read_fs");
        assert_eq!(CapabilityKind::WriteFs.as_str(), "write_fs");
        assert_eq!(CapabilityKind::Network.as_str(), "network");
        assert_eq!(CapabilityKind::Process.as_str(), "process");
        assert_eq!(CapabilityKind::Crypto.as_str(), "crypto");
        assert_eq!(CapabilityKind::Timer.as_str(), "timer");
        assert_eq!(CapabilityKind::Console.as_str(), "console");
        assert_eq!(CapabilityKind::Buffer.as_str(), "buffer");
    }

    #[test]
    fn capability_kind_all_count() {
        assert_eq!(CapabilityKind::ALL.len(), 8);
    }

    #[test]
    fn capability_kind_display() {
        assert_eq!(format!("{}", CapabilityKind::Network), "network");
    }

    #[test]
    fn capability_kind_serde_roundtrip() {
        for cap in CapabilityKind::ALL {
            let json = serde_json::to_string(cap).unwrap();
            let back: CapabilityKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*cap, back);
        }
    }

    // -- ViolationKind --

    #[test]
    fn violation_kind_as_str() {
        assert_eq!(
            ViolationKind::HandleLimitExceeded.as_str(),
            "handle_limit_exceeded"
        );
        assert_eq!(ViolationKind::HandleEscaped.as_str(), "handle_escaped");
        assert_eq!(
            ViolationKind::UnauthorizedCapability.as_str(),
            "unauthorized_capability"
        );
        assert_eq!(ViolationKind::CrashDetected.as_str(), "crash_detected");
        assert_eq!(ViolationKind::AbiMismatch.as_str(), "abi_mismatch");
        assert_eq!(
            ViolationKind::UnregisteredAddon.as_str(),
            "unregistered_addon"
        );
    }

    #[test]
    fn violation_kind_all_count() {
        assert_eq!(ViolationKind::ALL.len(), 6);
    }

    #[test]
    fn violation_kind_serde_roundtrip() {
        for kind in ViolationKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: ViolationKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    // -- MembraneVerdict --

    #[test]
    fn membrane_verdict_as_str() {
        assert_eq!(MembraneVerdict::Healthy.as_str(), "healthy");
        assert_eq!(MembraneVerdict::Degraded.as_str(), "degraded");
        assert_eq!(MembraneVerdict::Breached.as_str(), "breached");
        assert_eq!(MembraneVerdict::Shutdown.as_str(), "shutdown");
    }

    #[test]
    fn membrane_verdict_is_operational() {
        assert!(MembraneVerdict::Healthy.is_operational());
        assert!(MembraneVerdict::Degraded.is_operational());
        assert!(!MembraneVerdict::Breached.is_operational());
        assert!(!MembraneVerdict::Shutdown.is_operational());
    }

    #[test]
    fn membrane_verdict_display() {
        assert_eq!(format!("{}", MembraneVerdict::Breached), "breached");
    }

    #[test]
    fn membrane_verdict_serde_roundtrip() {
        for v in MembraneVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: MembraneVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // -- HandleRecord --

    #[test]
    fn handle_record_new_is_active() {
        let rec = HandleRecord::new(1, HandleKind::ValueHandle, "addon-a", epoch(1));
        assert_eq!(rec.state, HandleState::Active);
        assert_eq!(rec.id, 1);
        assert_eq!(rec.kind, HandleKind::ValueHandle);
        assert_eq!(rec.owner_scope, "addon-a");
    }

    #[test]
    fn handle_record_seal_changes_hash() {
        let mut rec = HandleRecord::new(1, HandleKind::ValueHandle, "addon-a", epoch(1));
        let h1 = rec.content_hash;
        rec.state = HandleState::Revoked;
        rec.seal();
        assert_ne!(h1, rec.content_hash);
    }

    #[test]
    fn handle_record_serde_roundtrip() {
        let rec = HandleRecord::new(42, HandleKind::BufferHandle, "test", epoch(5));
        let json = serde_json::to_string(&rec).unwrap();
        let back: HandleRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
    }

    // -- MembranePolicy --

    #[test]
    fn membrane_policy_default() {
        let p = MembranePolicy::default();
        assert_eq!(p.max_active_handles, DEFAULT_MAX_ACTIVE_HANDLES);
        assert_eq!(p.max_handle_age_micros, DEFAULT_MAX_HANDLE_AGE_MICROS);
        assert!(!p.allow_external_handles);
        assert!(!p.allow_callback_escape);
        assert_eq!(p.crash_containment_mode, CrashContainmentMode::Isolate);
    }

    #[test]
    fn membrane_policy_serde_roundtrip() {
        let p = MembranePolicy::default();
        let json = serde_json::to_string(&p).unwrap();
        let back: MembranePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // -- RoutingConfig --

    #[test]
    fn routing_config_default() {
        let r = RoutingConfig::default();
        assert_eq!(
            r.fast_path_max_latency_micros,
            DEFAULT_FAST_PATH_MAX_LATENCY_MICROS
        );
        assert!(r.fast_path_allowed_abis.contains(&AddonAbi::NodeApi));
        assert!(r.fast_path_allowed_abis.contains(&AddonAbi::WasiPreview1));
        assert_eq!(
            r.fallback_threshold_failures,
            DEFAULT_FALLBACK_THRESHOLD_FAILURES
        );
        assert!(r.deny_unregistered);
    }

    #[test]
    fn routing_config_serde_roundtrip() {
        let r = RoutingConfig::default();
        let json = serde_json::to_string(&r).unwrap();
        let back: RoutingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // -- AddonRegistration --

    #[test]
    fn addon_registration_creation() {
        let caps: BTreeSet<CapabilityKind> = [CapabilityKind::ReadFs, CapabilityKind::Crypto]
            .into_iter()
            .collect();
        let reg = AddonRegistration::new(
            "my-addon",
            AddonAbi::NodeApi,
            ContentHash::compute(b"test"),
            caps.clone(),
            epoch(1),
        );
        assert_eq!(reg.addon_id, "my-addon");
        assert_eq!(reg.abi, AddonAbi::NodeApi);
        assert_eq!(reg.capabilities, caps);
    }

    #[test]
    fn addon_registration_serde_roundtrip() {
        let reg = make_registration("test", AddonAbi::WasiPreview1, &[CapabilityKind::Network]);
        let json = serde_json::to_string(&reg).unwrap();
        let back: AddonRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, back);
    }

    // -- Violation --

    #[test]
    fn violation_new() {
        let v = Violation::new(ViolationKind::CrashDetected, "addon-x", "segfault", 1000);
        assert_eq!(v.kind, ViolationKind::CrashDetected);
        assert_eq!(v.addon_id, "addon-x");
        assert_eq!(v.detail, "segfault");
        assert_eq!(v.timestamp_micros, 1000);
    }

    #[test]
    fn violation_serde_roundtrip() {
        let v = Violation::new(ViolationKind::AbiMismatch, "a", "b", 42);
        let json = serde_json::to_string(&v).unwrap();
        let back: Violation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // -- MembraneState --

    #[test]
    fn membrane_state_new_is_empty() {
        let s = MembraneState::new();
        assert_eq!(s.registrations.len(), 0);
        assert_eq!(s.handle_table.len(), 0);
        assert_eq!(s.active_handles, 0);
        assert_eq!(s.crash_count, 0);
        assert_eq!(s.total_calls, 0);
        assert!(!s.is_shutdown());
    }

    #[test]
    fn membrane_state_default_eq_new() {
        assert_eq!(MembraneState::default(), MembraneState::new());
    }

    #[test]
    fn register_addon_success() {
        let mut s = MembraneState::new();
        let reg = make_registration("a", AddonAbi::NodeApi, &[]);
        assert!(s.register_addon(reg).is_ok());
        assert_eq!(s.registrations.len(), 1);
    }

    #[test]
    fn register_addon_duplicate_error() {
        let mut s = MembraneState::new();
        let reg = make_registration("a", AddonAbi::NodeApi, &[]);
        s.register_addon(reg).unwrap();
        let reg2 = make_registration("a", AddonAbi::WasiPreview1, &[]);
        assert!(matches!(
            s.register_addon(reg2),
            Err(MembraneError::AddonAlreadyRegistered { .. })
        ));
    }

    #[test]
    fn register_addon_when_shutdown() {
        let mut s = MembraneState::new();
        s.shutdown();
        let reg = make_registration("a", AddonAbi::NodeApi, &[]);
        assert!(matches!(
            s.register_addon(reg),
            Err(MembraneError::MembraneShutDown)
        ));
    }

    #[test]
    fn find_registration() {
        let s = make_state_with_addon("foo");
        assert!(s.find_registration("foo").is_some());
        assert!(s.find_registration("bar").is_none());
    }

    #[test]
    fn allocate_handle_success() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        assert_eq!(id, 1);
        assert_eq!(s.active_handles, 1);
        assert_eq!(s.handle_table.len(), 1);
    }

    #[test]
    fn allocate_handle_increments_id() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id1 = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        let id2 = s
            .allocate_handle("a", HandleKind::BufferHandle, epoch(1), &policy)
            .unwrap();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn allocate_handle_unregistered_addon() {
        let mut s = MembraneState::new();
        let policy = default_policy();
        assert!(matches!(
            s.allocate_handle("nonexistent", HandleKind::ValueHandle, epoch(1), &policy),
            Err(MembraneError::AddonNotRegistered { .. })
        ));
    }

    #[test]
    fn allocate_handle_external_denied() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy(); // allow_external_handles = false
        assert!(matches!(
            s.allocate_handle("a", HandleKind::ExternalHandle, epoch(1), &policy),
            Err(MembraneError::ExternalHandlesNotAllowed)
        ));
    }

    #[test]
    fn allocate_handle_external_allowed() {
        let mut s = make_state_with_addon("a");
        let mut policy = default_policy();
        policy.allow_external_handles = true;
        let id = s
            .allocate_handle("a", HandleKind::ExternalHandle, epoch(1), &policy)
            .unwrap();
        assert!(id > 0);
    }

    #[test]
    fn allocate_handle_limit_exceeded() {
        let mut s = make_state_with_addon("a");
        let mut policy = default_policy();
        policy.max_active_handles = 2;
        s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        assert!(matches!(
            s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy),
            Err(MembraneError::HandleLimitExceeded { .. })
        ));
    }

    #[test]
    fn allocate_handle_when_shutdown() {
        let mut s = make_state_with_addon("a");
        s.shutdown();
        let policy = default_policy();
        assert!(matches!(
            s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy),
            Err(MembraneError::MembraneShutDown)
        ));
    }

    #[test]
    fn revoke_handle_success() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        assert!(s.revoke_handle(id).is_ok());
        assert_eq!(s.active_handles, 0);
        assert_eq!(s.revoked_handles, 1);
        assert_eq!(s.get_handle(id).unwrap().state, HandleState::Revoked);
    }

    #[test]
    fn revoke_handle_not_found() {
        let mut s = MembraneState::new();
        assert!(matches!(
            s.revoke_handle(999),
            Err(MembraneError::HandleNotFound { .. })
        ));
    }

    #[test]
    fn revoke_handle_already_revoked() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.revoke_handle(id).unwrap();
        assert!(matches!(
            s.revoke_handle(id),
            Err(MembraneError::HandleAlreadyRevoked { .. })
        ));
    }

    #[test]
    fn revoke_handle_already_finalized() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.finalize_handle(id).unwrap();
        assert!(matches!(
            s.revoke_handle(id),
            Err(MembraneError::HandleAlreadyFinalized { .. })
        ));
    }

    #[test]
    fn finalize_active_handle() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        assert!(s.finalize_handle(id).is_ok());
        assert_eq!(s.active_handles, 0);
        assert_eq!(s.get_handle(id).unwrap().state, HandleState::Finalized);
    }

    #[test]
    fn finalize_revoked_handle() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.revoke_handle(id).unwrap();
        assert!(s.finalize_handle(id).is_ok());
        assert_eq!(s.get_handle(id).unwrap().state, HandleState::Finalized);
    }

    #[test]
    fn finalize_already_finalized() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.finalize_handle(id).unwrap();
        assert!(matches!(
            s.finalize_handle(id),
            Err(MembraneError::HandleAlreadyFinalized { .. })
        ));
    }

    #[test]
    fn mark_handle_escaped() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        assert!(s.mark_handle_escaped(id, 1000).is_ok());
        assert_eq!(s.get_handle(id).unwrap().state, HandleState::Escaped);
        assert_eq!(s.active_handles, 0);
        assert_eq!(s.violations.len(), 1);
        assert_eq!(s.violations[0].kind, ViolationKind::HandleEscaped);
    }

    #[test]
    fn mark_handle_escaped_creates_violation() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::CallbackHandle, epoch(1), &policy)
            .unwrap();
        s.mark_handle_escaped(id, 5000).unwrap();
        assert_eq!(s.violations.len(), 1);
        assert_eq!(s.violations[0].addon_id, "a");
        assert_eq!(s.violations[0].timestamp_micros, 5000);
    }

    #[test]
    fn revoke_escaped_handle() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.mark_handle_escaped(id, 1000).unwrap();
        assert!(s.revoke_handle(id).is_ok());
        assert_eq!(s.get_handle(id).unwrap().state, HandleState::Revoked);
    }

    #[test]
    fn route_call_fast_path() {
        let mut s = make_state_with_addon("a");
        let config = default_routing();
        let decision = s.route_call("a", &config);
        assert_eq!(decision, RouteDecision::FastPath);
        assert_eq!(s.fast_path_calls, 1);
        assert_eq!(s.total_calls, 1);
    }

    #[test]
    fn route_call_slow_path_non_fast_abi() {
        let mut s = MembraneState::new();
        let reg = make_registration("a", AddonAbi::CustomFfi, &[]);
        s.register_addon(reg).unwrap();
        let config = default_routing();
        let decision = s.route_call("a", &config);
        assert_eq!(decision, RouteDecision::SlowPath);
        assert_eq!(s.slow_path_calls, 1);
    }

    #[test]
    fn route_call_unregistered_denied() {
        let mut s = MembraneState::new();
        let config = default_routing(); // deny_unregistered = true
        let decision = s.route_call("nonexistent", &config);
        assert!(matches!(decision, RouteDecision::Deny { .. }));
        assert_eq!(s.denied_calls, 1);
    }

    #[test]
    fn route_call_unregistered_allowed() {
        let mut s = MembraneState::new();
        let mut config = default_routing();
        config.deny_unregistered = false;
        let decision = s.route_call("nonexistent", &config);
        assert_eq!(decision, RouteDecision::SlowPath);
    }

    #[test]
    fn route_call_fallback_on_failures() {
        let mut s = make_state_with_addon("a");
        let config = default_routing();
        for _ in 0..DEFAULT_FALLBACK_THRESHOLD_FAILURES {
            s.record_crash("a", "crash", 100);
        }
        let decision = s.route_call("a", &config);
        assert_eq!(decision, RouteDecision::Fallback);
        assert_eq!(s.fallback_calls, 1);
    }

    #[test]
    fn record_crash_increments_count() {
        let mut s = make_state_with_addon("a");
        s.record_crash("a", "crash1", 100);
        s.record_crash("a", "crash2", 200);
        assert_eq!(s.crash_count, 2);
        assert_eq!(s.addon_failure_count("a"), 2);
        assert_eq!(s.violations.len(), 2);
    }

    #[test]
    fn reset_failure_count() {
        let mut s = make_state_with_addon("a");
        s.record_crash("a", "crash", 100);
        assert_eq!(s.addon_failure_count("a"), 1);
        s.reset_failure_count("a");
        assert_eq!(s.addon_failure_count("a"), 0);
    }

    #[test]
    fn count_handles_in_state() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id1 = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        let _id2 = s
            .allocate_handle("a", HandleKind::BufferHandle, epoch(1), &policy)
            .unwrap();
        assert_eq!(s.count_handles_in_state(HandleState::Active), 2);
        s.revoke_handle(id1).unwrap();
        assert_eq!(s.count_handles_in_state(HandleState::Active), 1);
        assert_eq!(s.count_handles_in_state(HandleState::Revoked), 1);
    }

    #[test]
    fn handles_for_addon() {
        let mut s = MembraneState::new();
        let reg_a = make_registration("a", AddonAbi::NodeApi, &[]);
        let reg_b = make_registration("b", AddonAbi::NodeApi, &[]);
        s.register_addon(reg_a).unwrap();
        s.register_addon(reg_b).unwrap();
        let policy = default_policy();
        s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.allocate_handle("b", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.allocate_handle("a", HandleKind::BufferHandle, epoch(1), &policy)
            .unwrap();
        assert_eq!(s.handles_for_addon("a").len(), 2);
        assert_eq!(s.handles_for_addon("b").len(), 1);
    }

    #[test]
    fn total_handle_count() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        assert_eq!(s.total_handle_count(), 2);
    }

    #[test]
    fn shutdown_prevents_operations() {
        let mut s = make_state_with_addon("a");
        s.shutdown();
        assert!(s.is_shutdown());
        let policy = default_policy();
        assert!(matches!(
            s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy),
            Err(MembraneError::MembraneShutDown)
        ));
    }

    // -- evaluate_membrane --

    #[test]
    fn evaluate_healthy_state() {
        let s = MembraneState::new();
        let policy = default_policy();
        let report = evaluate_membrane(&s, &policy, &epoch(1), 1000);
        assert_eq!(report.verdict, MembraneVerdict::Healthy);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn evaluate_degraded_on_violations() {
        let mut s = MembraneState::new();
        s.record_violation(Violation::new(
            ViolationKind::AbiMismatch,
            "x",
            "mismatch",
            100,
        ));
        let policy = default_policy();
        let report = evaluate_membrane(&s, &policy, &epoch(1), 1000);
        assert_eq!(report.verdict, MembraneVerdict::Degraded);
    }

    #[test]
    fn evaluate_breached_on_escaped_handles() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.mark_handle_escaped(id, 100).unwrap();
        let report = evaluate_membrane(&s, &policy, &epoch(1), 1000);
        assert_eq!(report.verdict, MembraneVerdict::Breached);
    }

    #[test]
    fn evaluate_breached_on_crash_threshold() {
        let mut s = make_state_with_addon("a");
        for i in 0..CRASH_BREACHED_THRESHOLD {
            s.record_crash("a", &format!("crash-{i}"), i * 100);
        }
        let policy = default_policy();
        let report = evaluate_membrane(&s, &policy, &epoch(1), 1000);
        assert_eq!(report.verdict, MembraneVerdict::Breached);
    }

    #[test]
    fn evaluate_shutdown_on_high_crash_count() {
        let mut s = make_state_with_addon("a");
        for i in 0..CRASH_SHUTDOWN_THRESHOLD {
            s.record_crash("a", &format!("crash-{i}"), i * 100);
        }
        let policy = default_policy();
        let report = evaluate_membrane(&s, &policy, &epoch(1), 1000);
        assert_eq!(report.verdict, MembraneVerdict::Shutdown);
    }

    #[test]
    fn evaluate_report_statistics() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let config = default_routing();
        s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.route_call("a", &config);
        s.route_call("a", &config);
        let report = evaluate_membrane(&s, &policy, &epoch(1), 1000);
        assert_eq!(report.active_handles, 1);
        assert_eq!(report.total_calls, 2);
        assert_eq!(report.fast_path_calls, 2);
    }

    #[test]
    fn evaluate_receipt_fields() {
        let s = MembraneState::new();
        let policy = default_policy();
        let report = evaluate_membrane(&s, &policy, &epoch(5), 2000);
        assert_eq!(report.receipt.schema_version, SCHEMA_VERSION);
        assert_eq!(report.receipt.component, COMPONENT);
        assert_eq!(report.receipt.bead_id, BEAD_ID);
        assert_eq!(report.receipt.policy_id, POLICY_ID);
        assert_eq!(report.receipt.epoch, epoch(5));
        assert_eq!(report.receipt.timestamp_micros, 2000);
    }

    // -- compute_receipt --

    #[test]
    fn compute_receipt_deterministic() {
        let ih = ContentHash::compute(b"test");
        let r1 = compute_receipt(&epoch(1), &ih, MembraneVerdict::Healthy, 1000);
        let r2 = compute_receipt(&epoch(1), &ih, MembraneVerdict::Healthy, 1000);
        assert_eq!(r1, r2);
    }

    #[test]
    fn compute_receipt_different_epoch() {
        let ih = ContentHash::compute(b"test");
        let r1 = compute_receipt(&epoch(1), &ih, MembraneVerdict::Healthy, 1000);
        let r2 = compute_receipt(&epoch(2), &ih, MembraneVerdict::Healthy, 1000);
        assert_ne!(r1.verdict_hash, r2.verdict_hash);
    }

    #[test]
    fn compute_receipt_different_verdict() {
        let ih = ContentHash::compute(b"test");
        let r1 = compute_receipt(&epoch(1), &ih, MembraneVerdict::Healthy, 1000);
        let r2 = compute_receipt(&epoch(1), &ih, MembraneVerdict::Breached, 1000);
        assert_ne!(r1.verdict_hash, r2.verdict_hash);
    }

    #[test]
    fn decision_receipt_seal() {
        let ih = ContentHash::compute(b"test");
        let mut r = compute_receipt(&epoch(1), &ih, MembraneVerdict::Healthy, 1000);
        let original_hash = r.verdict_hash.clone();
        r.seal();
        // seal recomputes based on fields, should produce a stable hash
        let mut r2 = r.clone();
        r2.seal();
        assert_eq!(r.verdict_hash, r2.verdict_hash);
        // but different from the original since seal uses different computation
        // (it doesn't include the verdict string)
        assert_ne!(original_hash, r.verdict_hash);
    }

    // -- Helper functions --

    #[test]
    fn addon_has_capability_positive() {
        let s = make_state_with_addon("a"); // has Buffer
        assert!(addon_has_capability(&s, "a", CapabilityKind::Buffer));
    }

    #[test]
    fn addon_has_capability_negative() {
        let s = make_state_with_addon("a"); // has Buffer
        assert!(!addon_has_capability(&s, "a", CapabilityKind::Network));
    }

    #[test]
    fn addon_has_capability_unregistered() {
        let s = MembraneState::new();
        assert!(!addon_has_capability(&s, "x", CapabilityKind::Buffer));
    }

    #[test]
    fn validate_capabilities_all_granted() {
        let s = make_state_with_addon("a"); // has Buffer
        let requested: BTreeSet<CapabilityKind> = [CapabilityKind::Buffer].into_iter().collect();
        let denied = validate_capabilities(&s, "a", &requested);
        assert!(denied.is_empty());
    }

    #[test]
    fn validate_capabilities_some_denied() {
        let s = make_state_with_addon("a"); // has Buffer only
        let requested: BTreeSet<CapabilityKind> = [CapabilityKind::Buffer, CapabilityKind::Network]
            .into_iter()
            .collect();
        let denied = validate_capabilities(&s, "a", &requested);
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0], CapabilityKind::Network);
    }

    #[test]
    fn revoke_all_handles_for_addon_test() {
        let mut s = MembraneState::new();
        let reg_a = make_registration("a", AddonAbi::NodeApi, &[]);
        let reg_b = make_registration("b", AddonAbi::NodeApi, &[]);
        s.register_addon(reg_a).unwrap();
        s.register_addon(reg_b).unwrap();
        let policy = default_policy();
        s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.allocate_handle("a", HandleKind::BufferHandle, epoch(1), &policy)
            .unwrap();
        s.allocate_handle("b", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        let revoked = revoke_all_handles_for_addon(&mut s, "a");
        assert_eq!(revoked.len(), 2);
        assert_eq!(s.active_handles, 1); // only b's handle
    }

    #[test]
    fn count_registrations_by_abi_test() {
        let mut s = MembraneState::new();
        s.register_addon(make_registration("a", AddonAbi::NodeApi, &[]))
            .unwrap();
        s.register_addon(make_registration("b", AddonAbi::NodeApi, &[]))
            .unwrap();
        s.register_addon(make_registration("c", AddonAbi::CustomFfi, &[]))
            .unwrap();
        assert_eq!(count_registrations_by_abi(&s, AddonAbi::NodeApi), 2);
        assert_eq!(count_registrations_by_abi(&s, AddonAbi::CustomFfi), 1);
        assert_eq!(count_registrations_by_abi(&s, AddonAbi::WasiPreview1), 0);
    }

    #[test]
    fn compute_state_hash_deterministic() {
        let s = MembraneState::new();
        let h1 = compute_state_hash(&s);
        let h2 = compute_state_hash(&s);
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_state_hash_changes_with_state() {
        let mut s = MembraneState::new();
        let h1 = compute_state_hash(&s);
        s.register_addon(make_registration("a", AddonAbi::NodeApi, &[]))
            .unwrap();
        let h2 = compute_state_hash(&s);
        assert_ne!(h1, h2);
    }

    // -- MembraneError --

    #[test]
    fn membrane_error_display() {
        let e = MembraneError::HandleNotFound { handle_id: 42 };
        assert!(format!("{e}").contains("42"));
    }

    #[test]
    fn membrane_error_serde_roundtrip() {
        let e = MembraneError::HandleLimitExceeded {
            detail: "full".into(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: MembraneError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // -- MembraneReport serde --

    #[test]
    fn membrane_report_serde_roundtrip() {
        let s = MembraneState::new();
        let policy = default_policy();
        let report = evaluate_membrane(&s, &policy, &epoch(1), 1000);
        let json = serde_json::to_string(&report).unwrap();
        let back: MembraneReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // -- Constants --

    #[test]
    fn constants_non_empty() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!COMPONENT.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!POLICY_ID.is_empty());
    }

    #[test]
    fn constants_values() {
        assert_eq!(BEAD_ID, "bd-1lsy.5.9.2");
        assert_eq!(POLICY_ID, "RGC-407B");
    }

    #[test]
    fn millionths_constant() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // -- Edge cases --

    #[test]
    fn finalize_escaped_handle() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.mark_handle_escaped(id, 100).unwrap();
        assert!(s.finalize_handle(id).is_ok());
        assert_eq!(s.get_handle(id).unwrap().state, HandleState::Finalized);
    }

    #[test]
    fn mark_finalized_handle_escaped_error() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.finalize_handle(id).unwrap();
        assert!(matches!(
            s.mark_handle_escaped(id, 100),
            Err(MembraneError::HandleAlreadyFinalized { .. })
        ));
    }

    #[test]
    fn multiple_addons_independent_routing() {
        let mut s = MembraneState::new();
        s.register_addon(make_registration("fast", AddonAbi::NodeApi, &[]))
            .unwrap();
        s.register_addon(make_registration("slow", AddonAbi::CustomFfi, &[]))
            .unwrap();
        let config = default_routing();
        let d1 = s.route_call("fast", &config);
        let d2 = s.route_call("slow", &config);
        assert_eq!(d1, RouteDecision::FastPath);
        assert_eq!(d2, RouteDecision::SlowPath);
    }

    #[test]
    fn crash_isolation_per_addon() {
        let mut s = MembraneState::new();
        s.register_addon(make_registration("a", AddonAbi::NodeApi, &[]))
            .unwrap();
        s.register_addon(make_registration("b", AddonAbi::NodeApi, &[]))
            .unwrap();
        for _ in 0..DEFAULT_FALLBACK_THRESHOLD_FAILURES {
            s.record_crash("a", "crash", 100);
        }
        let config = default_routing();
        let da = s.route_call("a", &config);
        let db = s.route_call("b", &config);
        assert_eq!(da, RouteDecision::Fallback);
        assert_eq!(db, RouteDecision::FastPath);
    }

    #[test]
    fn revoke_handle_when_shutdown() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.shutdown();
        assert!(matches!(
            s.revoke_handle(id),
            Err(MembraneError::MembraneShutDown)
        ));
    }

    #[test]
    fn finalize_handle_when_shutdown() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.shutdown();
        assert!(matches!(
            s.finalize_handle(id),
            Err(MembraneError::MembraneShutDown)
        ));
    }

    #[test]
    fn mark_escape_when_shutdown() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        let id = s
            .allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.shutdown();
        assert!(matches!(
            s.mark_handle_escaped(id, 100),
            Err(MembraneError::MembraneShutDown)
        ));
    }

    #[test]
    fn membrane_state_serde_roundtrip() {
        let mut s = make_state_with_addon("a");
        let policy = default_policy();
        s.allocate_handle("a", HandleKind::ValueHandle, epoch(1), &policy)
            .unwrap();
        s.record_crash("a", "boom", 100);
        let json = serde_json::to_string(&s).unwrap();
        let back: MembraneState = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn record_violation_directly() {
        let mut s = MembraneState::new();
        let v = Violation::new(ViolationKind::UnregisteredAddon, "x", "details", 99);
        s.record_violation(v.clone());
        assert_eq!(s.violations.len(), 1);
        assert_eq!(s.violations[0], v);
    }

    #[test]
    fn addon_failure_count_unknown_addon() {
        let s = MembraneState::new();
        assert_eq!(s.addon_failure_count("nonexistent"), 0);
    }
}
