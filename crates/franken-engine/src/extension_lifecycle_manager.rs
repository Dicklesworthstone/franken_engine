//! Extension lifecycle state machine with compile-active transition guards.
//!
//! Governs every extension from load through termination with explicit
//! preconditions at each transition.  States:
//! `Unloaded → Validating → Loading → Starting → Running → Suspending →
//!  Suspended → Resuming → Terminating → Terminated → Quarantined`.
//!
//! Each transition emits a structured [`LifecycleManagerEvent`] for the
//! telemetry pipeline and is recorded in an append-only transition log for
//! deterministic replay.
//!
//! Plan reference: Section 10.5 item 2, bd-1hu.
//! Cross-refs: 9A.8 (resource budgets), 9G.2 (cancellation protocol),
//!             9A.1 (capability-typed execution model).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default cooperative shutdown grace period (nanoseconds): 5 seconds.
const DEFAULT_GRACE_PERIOD_NS: u64 = 5_000_000_000;

/// Maximum grace period operators may configure (nanoseconds): 30 seconds.
const MAX_GRACE_PERIOD_NS: u64 = 30_000_000_000;

/// Minimum resource budget that allows a `Starting` transition (millionths).
const MIN_START_BUDGET_MILLIONTHS: u64 = 1_000; // 0.001

// ---------------------------------------------------------------------------
// ExtensionState — the 11-state lifecycle
// ---------------------------------------------------------------------------

/// Full lifecycle state for a managed extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExtensionState {
    /// Not loaded; initial or post-termination state.
    Unloaded,
    /// Manifest is being validated against policy.
    Validating,
    /// Code and resources are being loaded into an execution cell.
    Loading,
    /// Initialization callbacks are executing.
    Starting,
    /// Fully operational; accepting hostcalls.
    Running,
    /// Cooperative pause in progress; draining in-flight work.
    Suspending,
    /// Paused; state preserved but no new work accepted.
    Suspended,
    /// Resuming from suspended state.
    Resuming,
    /// Shutdown in progress; cooperative or forced.
    Terminating,
    /// Shutdown complete; resources released.
    Terminated,
    /// Terminated with forensic snapshot; isolated for analysis.
    Quarantined,
}

impl ExtensionState {
    /// Whether the extension is considered alive (can do useful work or is
    /// transitioning toward being alive).
    pub fn is_alive(&self) -> bool {
        matches!(
            self,
            Self::Running | Self::Starting | Self::Resuming | Self::Loading | Self::Validating
        )
    }

    /// Whether the extension is in a terminal state (will not run again).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminated | Self::Quarantined | Self::Unloaded)
    }

    /// Whether the extension is actively executing code.
    pub fn is_executing(&self) -> bool {
        matches!(self, Self::Running | Self::Starting | Self::Resuming)
    }

    /// Stable string tag for structured logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unloaded => "unloaded",
            Self::Validating => "validating",
            Self::Loading => "loading",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Suspending => "suspending",
            Self::Suspended => "suspended",
            Self::Resuming => "resuming",
            Self::Terminating => "terminating",
            Self::Terminated => "terminated",
            Self::Quarantined => "quarantined",
        }
    }
}

impl fmt::Display for ExtensionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// LifecycleTransition — named transition triggers
// ---------------------------------------------------------------------------

/// Named triggers that drive state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LifecycleTransition {
    /// Begin manifest validation (`Unloaded → Validating`).
    Validate,
    /// Manifest validated; start loading (`Validating → Loading`).
    Load,
    /// Loading complete; start initialization (`Loading → Starting`).
    Start,
    /// Initialization complete; enter running state (`Starting → Running`).
    Activate,
    /// Begin cooperative pause (`Running → Suspending`).
    Suspend,
    /// Drain complete; enter suspended state (`Suspending → Suspended`).
    Freeze,
    /// Begin resumption (`Suspended → Resuming`).
    Resume,
    /// Resumption complete; return to running (`Resuming → Running`).
    Reactivate,
    /// Begin shutdown (from any alive state → `Terminating`).
    Terminate,
    /// Shutdown complete (`Terminating → Terminated`).
    Finalize,
    /// Quarantine with forensic snapshot (`Terminating → Quarantined`,
    /// or `Running/Suspending/Suspended → Quarantined` for emergency isolation).
    Quarantine,
    /// Validation failed; return to unloaded (`Validating → Unloaded`).
    RejectManifest,
    /// Loading failed; return to unloaded (`Loading → Unloaded`).
    LoadFailed,
    /// Starting failed; teardown to unloaded (`Starting → Unloaded`).
    StartFailed,
}

impl LifecycleTransition {
    /// Stable string tag for structured logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Validate => "validate",
            Self::Load => "load",
            Self::Start => "start",
            Self::Activate => "activate",
            Self::Suspend => "suspend",
            Self::Freeze => "freeze",
            Self::Resume => "resume",
            Self::Reactivate => "reactivate",
            Self::Terminate => "terminate",
            Self::Finalize => "finalize",
            Self::Quarantine => "quarantine",
            Self::RejectManifest => "reject_manifest",
            Self::LoadFailed => "load_failed",
            Self::StartFailed => "start_failed",
        }
    }

    /// Whether this transition is an error/failure path.
    pub fn is_failure(&self) -> bool {
        matches!(
            self,
            Self::RejectManifest | Self::LoadFailed | Self::StartFailed
        )
    }
}

impl fmt::Display for LifecycleTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// LifecycleError
// ---------------------------------------------------------------------------

/// Errors from lifecycle transition attempts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleError {
    /// Transition not valid from current state.
    InvalidTransition {
        extension_id: String,
        current_state: ExtensionState,
        attempted: LifecycleTransition,
    },
    /// Extension not found in the manager.
    ExtensionNotFound { extension_id: String },
    /// Extension already registered.
    ExtensionAlreadyExists { extension_id: String },
    /// Resource budget insufficient for transition.
    BudgetExhausted {
        extension_id: String,
        remaining_millionths: u64,
        required_millionths: u64,
    },
    /// Grace period expired during cooperative shutdown.
    GracePeriodExpired {
        extension_id: String,
        elapsed_ns: u64,
        budget_ns: u64,
    },
    /// Manifest validation rejected.
    ManifestRejected {
        extension_id: String,
        reason: String,
    },
    /// Internal error.
    Internal { detail: String },
}

impl LifecycleError {
    /// Stable error code for structured logging.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidTransition { .. } => "LIFECYCLE_INVALID_TRANSITION",
            Self::ExtensionNotFound { .. } => "LIFECYCLE_EXTENSION_NOT_FOUND",
            Self::ExtensionAlreadyExists { .. } => "LIFECYCLE_EXTENSION_EXISTS",
            Self::BudgetExhausted { .. } => "LIFECYCLE_BUDGET_EXHAUSTED",
            Self::GracePeriodExpired { .. } => "LIFECYCLE_GRACE_EXPIRED",
            Self::ManifestRejected { .. } => "LIFECYCLE_MANIFEST_REJECTED",
            Self::Internal { .. } => "LIFECYCLE_INTERNAL",
        }
    }
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition {
                extension_id,
                current_state,
                attempted,
            } => write!(
                f,
                "invalid transition: {extension_id} in state {current_state}, \
                 attempted {attempted}"
            ),
            Self::ExtensionNotFound { extension_id } => {
                write!(f, "extension not found: {extension_id}")
            }
            Self::ExtensionAlreadyExists { extension_id } => {
                write!(f, "extension already exists: {extension_id}")
            }
            Self::BudgetExhausted {
                extension_id,
                remaining_millionths,
                required_millionths,
            } => write!(
                f,
                "budget exhausted for {extension_id}: \
                 remaining={remaining_millionths}, required={required_millionths}"
            ),
            Self::GracePeriodExpired {
                extension_id,
                elapsed_ns,
                budget_ns,
            } => write!(
                f,
                "grace period expired for {extension_id}: \
                 elapsed={elapsed_ns}ns, budget={budget_ns}ns"
            ),
            Self::ManifestRejected {
                extension_id,
                reason,
            } => write!(f, "manifest rejected for {extension_id}: {reason}"),
            Self::Internal { detail } => write!(f, "internal error: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// ResourceBudget — per-extension resource budget
// ---------------------------------------------------------------------------

/// Per-extension resource budget tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudget {
    /// CPU time budget remaining (millionths; 1_000_000 = 1 unit).
    pub cpu_remaining_millionths: u64,
    /// Memory budget remaining (bytes).
    pub memory_remaining_bytes: u64,
    /// Hostcall count budget remaining.
    pub hostcall_remaining: u64,
    /// Total CPU budget allocated (for reporting).
    pub cpu_total_millionths: u64,
    /// Total memory budget allocated (for reporting).
    pub memory_total_bytes: u64,
    /// Total hostcall budget allocated (for reporting).
    pub hostcall_total: u64,
}

impl ResourceBudget {
    /// Create a new budget with the given limits.
    pub fn new(cpu_millionths: u64, memory_bytes: u64, hostcalls: u64) -> Self {
        Self {
            cpu_remaining_millionths: cpu_millionths,
            memory_remaining_bytes: memory_bytes,
            hostcall_remaining: hostcalls,
            cpu_total_millionths: cpu_millionths,
            memory_total_bytes: memory_bytes,
            hostcall_total: hostcalls,
        }
    }

    /// Whether any budget dimension is exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.cpu_remaining_millionths == 0
            || self.memory_remaining_bytes == 0
            || self.hostcall_remaining == 0
    }

    /// Consume CPU budget.  Returns `false` if insufficient.
    pub fn consume_cpu(&mut self, amount_millionths: u64) -> bool {
        if self.cpu_remaining_millionths >= amount_millionths {
            self.cpu_remaining_millionths -= amount_millionths;
            true
        } else {
            false
        }
    }

    /// Consume memory budget.  Returns `false` if insufficient.
    pub fn consume_memory(&mut self, amount_bytes: u64) -> bool {
        if self.memory_remaining_bytes >= amount_bytes {
            self.memory_remaining_bytes -= amount_bytes;
            true
        } else {
            false
        }
    }

    /// Consume one hostcall slot.  Returns `false` if none remain.
    pub fn consume_hostcall(&mut self) -> bool {
        if self.hostcall_remaining > 0 {
            self.hostcall_remaining -= 1;
            true
        } else {
            false
        }
    }

    /// CPU utilization ratio (millionths).
    pub fn cpu_utilization_millionths(&self) -> u64 {
        if self.cpu_total_millionths == 0 {
            return 0;
        }
        let used = self.cpu_total_millionths - self.cpu_remaining_millionths;
        used.saturating_mul(1_000_000)
            .checked_div(self.cpu_total_millionths)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// ManifestRef — validated manifest reference
// ---------------------------------------------------------------------------

/// Reference to a validated extension manifest.
///
/// The lifecycle manager holds this opaque reference; full manifest validation
/// is performed by the manifest validation module (bd-xq7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRef {
    /// Extension identifier from the manifest.
    pub extension_id: String,
    /// Declared capability set (opaque strings for now).
    pub capabilities: Vec<String>,
    /// Maximum extension lifetime (nanoseconds).  0 means unlimited.
    pub max_lifetime_ns: u64,
    /// Schema version of the manifest format.
    pub schema_version: u32,
}

// ---------------------------------------------------------------------------
// CancellationConfig — cooperative shutdown parameters
// ---------------------------------------------------------------------------

/// Configuration for cooperative shutdown protocol per 9G.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationConfig {
    /// Grace period for cooperative shutdown (nanoseconds).
    /// Clamped to [0, MAX_GRACE_PERIOD_NS].
    pub grace_period_ns: u64,
    /// Whether to force-kill after grace period expiry.
    pub force_on_timeout: bool,
    /// Whether to propagate cancellation to child cells/tasks.
    pub propagate_to_children: bool,
}

impl Default for CancellationConfig {
    fn default() -> Self {
        Self {
            grace_period_ns: DEFAULT_GRACE_PERIOD_NS,
            force_on_timeout: true,
            propagate_to_children: true,
        }
    }
}

impl CancellationConfig {
    /// Clamp the grace period to the allowed range.
    pub fn clamped(mut self) -> Self {
        if self.grace_period_ns > MAX_GRACE_PERIOD_NS {
            self.grace_period_ns = MAX_GRACE_PERIOD_NS;
        }
        self
    }
}

// ---------------------------------------------------------------------------
// TransitionRecord — append-only transition log entry
// ---------------------------------------------------------------------------

/// Single entry in the append-only transition log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionRecord {
    /// Monotonic sequence number.
    pub sequence: u64,
    /// Monotonic timestamp (nanoseconds since epoch).
    pub timestamp_ns: u64,
    /// State before transition.
    pub from_state: ExtensionState,
    /// State after transition.
    pub to_state: ExtensionState,
    /// Trigger that caused the transition.
    pub transition: LifecycleTransition,
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Optional decision ID (if triggered by Guardplane decision).
    pub decision_id: Option<String>,
}

// ---------------------------------------------------------------------------
// LifecycleManagerEvent — structured telemetry event
// ---------------------------------------------------------------------------

/// Structured event emitted at each lifecycle transition for the telemetry
/// pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleManagerEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub extension_id: String,
    pub from_state: Option<String>,
    pub to_state: Option<String>,
    pub transition: Option<String>,
}

// ---------------------------------------------------------------------------
// Transition table — valid (from_state, trigger) → to_state mappings
// ---------------------------------------------------------------------------

/// Compute the target state for a given (current_state, transition) pair.
/// Returns `None` if the transition is invalid from the current state.
fn target_state(
    current: ExtensionState,
    transition: LifecycleTransition,
) -> Option<ExtensionState> {
    use ExtensionState as S;
    use LifecycleTransition as T;
    match (current, transition) {
        // Happy path
        (S::Unloaded, T::Validate) => Some(S::Validating),
        (S::Validating, T::Load) => Some(S::Loading),
        (S::Loading, T::Start) => Some(S::Starting),
        (S::Starting, T::Activate) => Some(S::Running),
        (S::Running, T::Suspend) => Some(S::Suspending),
        (S::Suspending, T::Freeze) => Some(S::Suspended),
        (S::Suspended, T::Resume) => Some(S::Resuming),
        (S::Resuming, T::Reactivate) => Some(S::Running),

        // Failure paths
        (S::Validating, T::RejectManifest) => Some(S::Unloaded),
        (S::Loading, T::LoadFailed) => Some(S::Unloaded),
        (S::Starting, T::StartFailed) => Some(S::Unloaded),

        // Terminate from any alive or suspending/suspended state
        (S::Running, T::Terminate)
        | (S::Suspending, T::Terminate)
        | (S::Suspended, T::Terminate)
        | (S::Resuming, T::Terminate)
        | (S::Starting, T::Terminate)
        | (S::Loading, T::Terminate)
        | (S::Validating, T::Terminate) => Some(S::Terminating),

        // Finalize completes shutdown
        (S::Terminating, T::Finalize) => Some(S::Terminated),

        // Quarantine from alive, suspending, suspended, or terminating
        (S::Running, T::Quarantine)
        | (S::Suspending, T::Quarantine)
        | (S::Suspended, T::Quarantine)
        | (S::Resuming, T::Quarantine)
        | (S::Terminating, T::Quarantine)
        | (S::Starting, T::Quarantine)
        | (S::Loading, T::Quarantine)
        | (S::Validating, T::Quarantine) => Some(S::Quarantined),

        _ => None,
    }
}

/// Returns all valid transitions from a given state.
pub fn valid_transitions(state: ExtensionState) -> Vec<LifecycleTransition> {
    use LifecycleTransition as T;
    let candidates = [
        T::Validate,
        T::Load,
        T::Start,
        T::Activate,
        T::Suspend,
        T::Freeze,
        T::Resume,
        T::Reactivate,
        T::Terminate,
        T::Finalize,
        T::Quarantine,
        T::RejectManifest,
        T::LoadFailed,
        T::StartFailed,
    ];
    candidates
        .iter()
        .copied()
        .filter(|t| target_state(state, *t).is_some())
        .collect()
}

// ---------------------------------------------------------------------------
// ExtensionRecord — per-extension tracking
// ---------------------------------------------------------------------------

/// Internal record for a managed extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExtensionRecord {
    extension_id: String,
    state: ExtensionState,
    manifest: Option<ManifestRef>,
    budget: ResourceBudget,
    cancellation_config: CancellationConfig,
    transition_log: Vec<TransitionRecord>,
    next_sequence: u64,
    created_ns: u64,
}

// ---------------------------------------------------------------------------
// ExtensionLifecycleManager
// ---------------------------------------------------------------------------

/// Manages the lifecycle of all extensions with deterministic transitions
/// and resource budget enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionLifecycleManager {
    /// Per-extension records, keyed by extension_id.
    extensions: BTreeMap<String, ExtensionRecord>,
    /// Structured events for telemetry pipeline.
    events: Vec<LifecycleManagerEvent>,
    /// Monotonic clock counter for deterministic timestamps.
    clock_ns: u64,
}

impl Default for ExtensionLifecycleManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtensionLifecycleManager {
    /// Create a new lifecycle manager.
    pub fn new() -> Self {
        Self {
            extensions: BTreeMap::new(),
            events: Vec::new(),
            clock_ns: 0,
        }
    }

    /// Advance the monotonic clock and return the new timestamp.
    pub fn advance_clock(&mut self, delta_ns: u64) -> u64 {
        self.clock_ns = self.clock_ns.saturating_add(delta_ns);
        self.clock_ns
    }

    /// Current clock value.
    pub fn clock_ns(&self) -> u64 {
        self.clock_ns
    }

    /// Register a new extension in `Unloaded` state with the given budget.
    pub fn register(
        &mut self,
        extension_id: &str,
        budget: ResourceBudget,
        cancellation_config: CancellationConfig,
    ) -> Result<(), LifecycleError> {
        if self.extensions.contains_key(extension_id) {
            return Err(LifecycleError::ExtensionAlreadyExists {
                extension_id: extension_id.to_string(),
            });
        }
        let record = ExtensionRecord {
            extension_id: extension_id.to_string(),
            state: ExtensionState::Unloaded,
            manifest: None,
            budget,
            cancellation_config: cancellation_config.clamped(),
            transition_log: Vec::new(),
            next_sequence: 0,
            created_ns: self.clock_ns,
        };
        self.extensions.insert(extension_id.to_string(), record);
        self.emit_event(extension_id, "register", "ok", None, None, None, None);
        Ok(())
    }

    /// Unregister an extension that is in a terminal state.
    pub fn unregister(&mut self, extension_id: &str) -> Result<(), LifecycleError> {
        let record =
            self.extensions
                .get(extension_id)
                .ok_or_else(|| LifecycleError::ExtensionNotFound {
                    extension_id: extension_id.to_string(),
                })?;
        if !record.state.is_terminal() {
            return Err(LifecycleError::InvalidTransition {
                extension_id: extension_id.to_string(),
                current_state: record.state,
                attempted: LifecycleTransition::Terminate,
            });
        }
        self.extensions.remove(extension_id);
        self.emit_event(extension_id, "unregister", "ok", None, None, None, None);
        Ok(())
    }

    /// Get the current state of an extension.
    pub fn state(&self, extension_id: &str) -> Result<ExtensionState, LifecycleError> {
        self.extensions
            .get(extension_id)
            .map(|r| r.state)
            .ok_or_else(|| LifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            })
    }

    /// Get the manifest reference for an extension (if set).
    pub fn manifest(&self, extension_id: &str) -> Result<Option<&ManifestRef>, LifecycleError> {
        self.extensions
            .get(extension_id)
            .map(|r| r.manifest.as_ref())
            .ok_or_else(|| LifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            })
    }

    /// Get the resource budget for an extension.
    pub fn budget(&self, extension_id: &str) -> Result<&ResourceBudget, LifecycleError> {
        self.extensions
            .get(extension_id)
            .map(|r| &r.budget)
            .ok_or_else(|| LifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            })
    }

    /// Get the transition log for an extension.
    pub fn transition_log(
        &self,
        extension_id: &str,
    ) -> Result<&[TransitionRecord], LifecycleError> {
        self.extensions
            .get(extension_id)
            .map(|r| r.transition_log.as_slice())
            .ok_or_else(|| LifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            })
    }

    /// Drain all pending telemetry events.
    pub fn drain_events(&mut self) -> Vec<LifecycleManagerEvent> {
        std::mem::take(&mut self.events)
    }

    /// List all extension IDs.
    pub fn extension_ids(&self) -> Vec<&str> {
        self.extensions.keys().map(String::as_str).collect()
    }

    /// Count extensions in a given state.
    pub fn count_in_state(&self, state: ExtensionState) -> usize {
        self.extensions
            .values()
            .filter(|r| r.state == state)
            .count()
    }

    // -----------------------------------------------------------------------
    // Transition methods
    // -----------------------------------------------------------------------

    /// Execute a lifecycle transition.
    ///
    /// Validates the transition against the current state, enforces resource
    /// budget preconditions, records the transition, and emits a telemetry
    /// event.
    pub fn transition(
        &mut self,
        extension_id: &str,
        transition: LifecycleTransition,
        trace_id: &str,
        decision_id: Option<&str>,
    ) -> Result<ExtensionState, LifecycleError> {
        let record =
            self.extensions
                .get(extension_id)
                .ok_or_else(|| LifecycleError::ExtensionNotFound {
                    extension_id: extension_id.to_string(),
                })?;

        let from_state = record.state;
        let to_state = target_state(from_state, transition).ok_or_else(|| {
            LifecycleError::InvalidTransition {
                extension_id: extension_id.to_string(),
                current_state: from_state,
                attempted: transition,
            }
        })?;

        // Budget precondition: Starting requires minimum budget.
        if to_state == ExtensionState::Starting
            && record.budget.cpu_remaining_millionths < MIN_START_BUDGET_MILLIONTHS
        {
            return Err(LifecycleError::BudgetExhausted {
                extension_id: extension_id.to_string(),
                remaining_millionths: record.budget.cpu_remaining_millionths,
                required_millionths: MIN_START_BUDGET_MILLIONTHS,
            });
        }

        // Record the transition.
        let record = self.extensions.get_mut(extension_id).ok_or_else(|| {
            LifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            }
        })?;
        let seq = record.next_sequence;
        record.next_sequence += 1;
        record.transition_log.push(TransitionRecord {
            sequence: seq,
            timestamp_ns: self.clock_ns,
            from_state,
            to_state,
            transition,
            trace_id: trace_id.to_string(),
            decision_id: decision_id.map(str::to_string),
        });
        record.state = to_state;

        // Emit telemetry event.
        self.emit_event(
            extension_id,
            transition.as_str(),
            "ok",
            None,
            Some(from_state.as_str()),
            Some(to_state.as_str()),
            Some(transition.as_str()),
        );

        Ok(to_state)
    }

    /// Set the manifest reference for an extension (after validation passes).
    pub fn set_manifest(
        &mut self,
        extension_id: &str,
        manifest: ManifestRef,
    ) -> Result<(), LifecycleError> {
        let record = self.extensions.get_mut(extension_id).ok_or_else(|| {
            LifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            }
        })?;
        record.manifest = Some(manifest);
        Ok(())
    }

    /// Consume CPU budget for an extension.  Returns an error if the
    /// extension has insufficient budget.
    pub fn consume_cpu(
        &mut self,
        extension_id: &str,
        amount_millionths: u64,
    ) -> Result<(), LifecycleError> {
        let record = self.extensions.get_mut(extension_id).ok_or_else(|| {
            LifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            }
        })?;
        if !record.budget.consume_cpu(amount_millionths) {
            return Err(LifecycleError::BudgetExhausted {
                extension_id: extension_id.to_string(),
                remaining_millionths: record.budget.cpu_remaining_millionths,
                required_millionths: amount_millionths,
            });
        }
        Ok(())
    }

    /// Consume one hostcall slot for an extension.
    pub fn consume_hostcall(&mut self, extension_id: &str) -> Result<(), LifecycleError> {
        let record = self.extensions.get_mut(extension_id).ok_or_else(|| {
            LifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            }
        })?;
        if !record.budget.consume_hostcall() {
            return Err(LifecycleError::BudgetExhausted {
                extension_id: extension_id.to_string(),
                remaining_millionths: 0,
                required_millionths: 1,
            });
        }
        Ok(())
    }

    /// Get cancellation config for an extension.
    pub fn cancellation_config(
        &self,
        extension_id: &str,
    ) -> Result<&CancellationConfig, LifecycleError> {
        self.extensions
            .get(extension_id)
            .map(|r| &r.cancellation_config)
            .ok_or_else(|| LifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            })
    }

    /// Execute cooperative shutdown protocol per 9G.2.
    ///
    /// Transitions: current → Terminating → Terminated (or Quarantined if
    /// `quarantine_on_timeout` is set).
    ///
    /// The `elapsed_ns` parameter represents how much time has passed since
    /// the shutdown was initiated (for deterministic testing).
    pub fn cooperative_shutdown(
        &mut self,
        extension_id: &str,
        trace_id: &str,
        elapsed_ns: u64,
        quarantine_on_timeout: bool,
    ) -> Result<ExtensionState, LifecycleError> {
        let record =
            self.extensions
                .get(extension_id)
                .ok_or_else(|| LifecycleError::ExtensionNotFound {
                    extension_id: extension_id.to_string(),
                })?;

        let grace = record.cancellation_config.grace_period_ns;
        let current = record.state;

        // If not yet terminating, initiate termination first.
        if current != ExtensionState::Terminating {
            self.transition(extension_id, LifecycleTransition::Terminate, trace_id, None)?;
        }

        // Check grace period.
        if elapsed_ns <= grace {
            // Cooperative shutdown succeeded within grace period.
            return self.transition(extension_id, LifecycleTransition::Finalize, trace_id, None);
        }

        // Grace period expired.
        let record =
            self.extensions
                .get(extension_id)
                .ok_or_else(|| LifecycleError::ExtensionNotFound {
                    extension_id: extension_id.to_string(),
                })?;
        if record.cancellation_config.force_on_timeout {
            // Force shutdown.
            self.emit_event(
                extension_id,
                "grace_period_expired",
                "forced",
                Some("LIFECYCLE_GRACE_EXPIRED"),
                Some(ExtensionState::Terminating.as_str()),
                None,
                None,
            );
            if quarantine_on_timeout {
                self.transition(
                    extension_id,
                    LifecycleTransition::Quarantine,
                    trace_id,
                    None,
                )
            } else {
                self.transition(extension_id, LifecycleTransition::Finalize, trace_id, None)
            }
        } else {
            Err(LifecycleError::GracePeriodExpired {
                extension_id: extension_id.to_string(),
                elapsed_ns,
                budget_ns: grace,
            })
        }
    }

    /// Check all extensions for budget exhaustion and trigger automatic
    /// containment.  Returns the list of extensions that were auto-contained.
    pub fn enforce_budgets(&mut self, trace_id: &str) -> Vec<(String, ExtensionState)> {
        let exhausted: Vec<String> = self
            .extensions
            .iter()
            .filter(|(_, r)| r.state.is_executing() && r.budget.is_exhausted())
            .map(|(id, _)| id.clone())
            .collect();

        let mut results = Vec::new();
        for ext_id in exhausted {
            if let Ok(new_state) = self.transition(
                &ext_id,
                LifecycleTransition::Terminate,
                trace_id,
                Some("budget_enforcement"),
            ) {
                results.push((ext_id, new_state));
            }
        }
        results
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn emit_event(
        &mut self,
        extension_id: &str,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
        from_state: Option<&str>,
        to_state: Option<&str>,
        transition: Option<&str>,
    ) {
        self.events.push(LifecycleManagerEvent {
            trace_id: String::new(),
            decision_id: String::new(),
            policy_id: String::new(),
            component: "extension_lifecycle_manager".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(str::to_string),
            extension_id: extension_id.to_string(),
            from_state: from_state.map(str::to_string),
            to_state: to_state.map(str::to_string),
            transition: transition.map(str::to_string),
        });
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_budget() -> ResourceBudget {
        ResourceBudget::new(1_000_000, 64 * 1024 * 1024, 10_000)
    }

    fn make_manager() -> ExtensionLifecycleManager {
        ExtensionLifecycleManager::new()
    }

    fn register_ext(mgr: &mut ExtensionLifecycleManager, id: &str) {
        mgr.register(id, default_budget(), CancellationConfig::default())
            .expect("serde deserialization should succeed");
    }

    /// Drive an extension through the full happy path: Unloaded → Running.
    fn advance_to_running(mgr: &mut ExtensionLifecycleManager, id: &str) {
        mgr.transition(id, LifecycleTransition::Validate, "t1", None)
            .expect("serde deserialization should succeed");
        mgr.transition(id, LifecycleTransition::Load, "t1", None)
            .expect("serde deserialization should succeed");
        mgr.transition(id, LifecycleTransition::Start, "t1", None)
            .expect("serde deserialization should succeed");
        mgr.transition(id, LifecycleTransition::Activate, "t1", None)
            .expect("serde deserialization should succeed");
    }

    // -----------------------------------------------------------------------
    // State enum tests
    // -----------------------------------------------------------------------

    #[test]
    fn state_is_alive_for_operational_states() {
        assert!(ExtensionState::Running.is_alive());
        assert!(ExtensionState::Starting.is_alive());
        assert!(ExtensionState::Resuming.is_alive());
        assert!(ExtensionState::Loading.is_alive());
        assert!(ExtensionState::Validating.is_alive());
        assert!(!ExtensionState::Terminated.is_alive());
        assert!(!ExtensionState::Quarantined.is_alive());
        assert!(!ExtensionState::Suspended.is_alive());
    }

    #[test]
    fn state_is_terminal_for_dead_states() {
        assert!(ExtensionState::Terminated.is_terminal());
        assert!(ExtensionState::Quarantined.is_terminal());
        assert!(ExtensionState::Unloaded.is_terminal());
        assert!(!ExtensionState::Running.is_terminal());
    }

    #[test]
    fn state_is_executing_for_active_states() {
        assert!(ExtensionState::Running.is_executing());
        assert!(ExtensionState::Starting.is_executing());
        assert!(ExtensionState::Resuming.is_executing());
        assert!(!ExtensionState::Suspended.is_executing());
        assert!(!ExtensionState::Suspending.is_executing());
        assert!(!ExtensionState::Loading.is_executing());
    }

    #[test]
    fn state_as_str_roundtrip() {
        let all = [
            ExtensionState::Unloaded,
            ExtensionState::Validating,
            ExtensionState::Loading,
            ExtensionState::Starting,
            ExtensionState::Running,
            ExtensionState::Suspending,
            ExtensionState::Suspended,
            ExtensionState::Resuming,
            ExtensionState::Terminating,
            ExtensionState::Terminated,
            ExtensionState::Quarantined,
        ];
        for s in &all {
            assert!(!s.as_str().is_empty());
            assert_eq!(s.to_string(), s.as_str());
        }
        assert_eq!(all.len(), 11, "must have all 11 states");
    }

    // -----------------------------------------------------------------------
    // Transition enum tests
    // -----------------------------------------------------------------------

    #[test]
    fn transition_as_str_is_stable() {
        assert_eq!(LifecycleTransition::Validate.as_str(), "validate");
        assert_eq!(LifecycleTransition::Quarantine.as_str(), "quarantine");
        assert_eq!(
            LifecycleTransition::RejectManifest.as_str(),
            "reject_manifest"
        );
    }

    #[test]
    fn transition_is_failure_identifies_error_paths() {
        assert!(LifecycleTransition::RejectManifest.is_failure());
        assert!(LifecycleTransition::LoadFailed.is_failure());
        assert!(LifecycleTransition::StartFailed.is_failure());
        assert!(!LifecycleTransition::Activate.is_failure());
        assert!(!LifecycleTransition::Terminate.is_failure());
    }

    // -----------------------------------------------------------------------
    // Transition table tests
    // -----------------------------------------------------------------------

    #[test]
    fn happy_path_transition_chain() {
        assert_eq!(
            target_state(ExtensionState::Unloaded, LifecycleTransition::Validate),
            Some(ExtensionState::Validating)
        );
        assert_eq!(
            target_state(ExtensionState::Validating, LifecycleTransition::Load),
            Some(ExtensionState::Loading)
        );
        assert_eq!(
            target_state(ExtensionState::Loading, LifecycleTransition::Start),
            Some(ExtensionState::Starting)
        );
        assert_eq!(
            target_state(ExtensionState::Starting, LifecycleTransition::Activate),
            Some(ExtensionState::Running)
        );
    }

    #[test]
    fn suspend_resume_cycle() {
        assert_eq!(
            target_state(ExtensionState::Running, LifecycleTransition::Suspend),
            Some(ExtensionState::Suspending)
        );
        assert_eq!(
            target_state(ExtensionState::Suspending, LifecycleTransition::Freeze),
            Some(ExtensionState::Suspended)
        );
        assert_eq!(
            target_state(ExtensionState::Suspended, LifecycleTransition::Resume),
            Some(ExtensionState::Resuming)
        );
        assert_eq!(
            target_state(ExtensionState::Resuming, LifecycleTransition::Reactivate),
            Some(ExtensionState::Running)
        );
    }

    #[test]
    fn terminate_from_any_alive_state() {
        let alive_states = [
            ExtensionState::Validating,
            ExtensionState::Loading,
            ExtensionState::Starting,
            ExtensionState::Running,
            ExtensionState::Suspending,
            ExtensionState::Suspended,
            ExtensionState::Resuming,
        ];
        for state in &alive_states {
            assert_eq!(
                target_state(*state, LifecycleTransition::Terminate),
                Some(ExtensionState::Terminating),
                "Terminate should be valid from {state}"
            );
        }
    }

    #[test]
    fn quarantine_from_any_non_terminal_state() {
        let non_terminal = [
            ExtensionState::Validating,
            ExtensionState::Loading,
            ExtensionState::Starting,
            ExtensionState::Running,
            ExtensionState::Suspending,
            ExtensionState::Suspended,
            ExtensionState::Resuming,
            ExtensionState::Terminating,
        ];
        for state in &non_terminal {
            assert_eq!(
                target_state(*state, LifecycleTransition::Quarantine),
                Some(ExtensionState::Quarantined),
                "Quarantine should be valid from {state}"
            );
        }
    }

    #[test]
    fn invalid_transitions_return_none() {
        // Cannot validate from Running
        assert_eq!(
            target_state(ExtensionState::Running, LifecycleTransition::Validate),
            None
        );
        // Cannot activate from Suspended
        assert_eq!(
            target_state(ExtensionState::Suspended, LifecycleTransition::Activate),
            None
        );
        // Cannot terminate from Terminated
        assert_eq!(
            target_state(ExtensionState::Terminated, LifecycleTransition::Terminate),
            None
        );
        // Cannot resume from Running
        assert_eq!(
            target_state(ExtensionState::Running, LifecycleTransition::Resume),
            None
        );
    }

    #[test]
    fn failure_paths_return_to_unloaded() {
        assert_eq!(
            target_state(
                ExtensionState::Validating,
                LifecycleTransition::RejectManifest
            ),
            Some(ExtensionState::Unloaded)
        );
        assert_eq!(
            target_state(ExtensionState::Loading, LifecycleTransition::LoadFailed),
            Some(ExtensionState::Unloaded)
        );
        assert_eq!(
            target_state(ExtensionState::Starting, LifecycleTransition::StartFailed),
            Some(ExtensionState::Unloaded)
        );
    }

    #[test]
    fn valid_transitions_from_running_is_exhaustive() {
        let valid = valid_transitions(ExtensionState::Running);
        assert!(valid.contains(&LifecycleTransition::Suspend));
        assert!(valid.contains(&LifecycleTransition::Terminate));
        assert!(valid.contains(&LifecycleTransition::Quarantine));
        assert!(!valid.contains(&LifecycleTransition::Validate));
        assert!(!valid.contains(&LifecycleTransition::Load));
    }

    #[test]
    fn valid_transitions_from_terminated_is_empty() {
        let valid = valid_transitions(ExtensionState::Terminated);
        assert!(valid.is_empty(), "no transitions from Terminated");
    }

    // -----------------------------------------------------------------------
    // ResourceBudget tests
    // -----------------------------------------------------------------------

    #[test]
    fn budget_consume_cpu_subtracts() {
        let mut b = ResourceBudget::new(1_000_000, 1024, 100);
        assert!(b.consume_cpu(500_000));
        assert_eq!(b.cpu_remaining_millionths, 500_000);
        assert!(!b.consume_cpu(600_000));
        assert_eq!(b.cpu_remaining_millionths, 500_000);
    }

    #[test]
    fn budget_consume_hostcall_decrements() {
        let mut b = ResourceBudget::new(1_000, 1024, 2);
        assert!(b.consume_hostcall());
        assert_eq!(b.hostcall_remaining, 1);
        assert!(b.consume_hostcall());
        assert!(!b.consume_hostcall());
    }

    #[test]
    fn budget_is_exhausted_any_dimension() {
        let mut b = ResourceBudget::new(1_000, 1024, 100);
        assert!(!b.is_exhausted());
        b.cpu_remaining_millionths = 0;
        assert!(b.is_exhausted());
        b.cpu_remaining_millionths = 1;
        b.memory_remaining_bytes = 0;
        assert!(b.is_exhausted());
    }

    #[test]
    fn budget_utilization_ratio() {
        let mut b = ResourceBudget::new(1_000_000, 1024, 100);
        assert_eq!(b.cpu_utilization_millionths(), 0);
        b.consume_cpu(500_000);
        assert_eq!(b.cpu_utilization_millionths(), 500_000);
        b.consume_cpu(500_000);
        assert_eq!(b.cpu_utilization_millionths(), 1_000_000);
    }

    #[test]
    fn budget_zero_total_utilization_is_zero() {
        let b = ResourceBudget::new(0, 0, 0);
        assert_eq!(b.cpu_utilization_millionths(), 0);
    }

    // -----------------------------------------------------------------------
    // CancellationConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn cancellation_config_clamps_grace_period() {
        let cfg = CancellationConfig {
            grace_period_ns: 999_000_000_000, // way over max
            force_on_timeout: true,
            propagate_to_children: true,
        }
        .clamped();
        assert_eq!(cfg.grace_period_ns, MAX_GRACE_PERIOD_NS);
    }

    #[test]
    fn cancellation_config_default_values() {
        let cfg = CancellationConfig::default();
        assert_eq!(cfg.grace_period_ns, DEFAULT_GRACE_PERIOD_NS);
        assert!(cfg.force_on_timeout);
        assert!(cfg.propagate_to_children);
    }

    // -----------------------------------------------------------------------
    // Manager registration tests
    // -----------------------------------------------------------------------

    #[test]
    fn register_creates_extension_in_unloaded_state() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        assert_eq!(
            mgr.state("ext-a")
                .expect("serde deserialization should succeed"),
            ExtensionState::Unloaded
        );
    }

    #[test]
    fn register_duplicate_fails() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        let err = mgr
            .register("ext-a", default_budget(), CancellationConfig::default())
            .unwrap_err();
        assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_EXISTS");
    }

    #[test]
    fn state_not_found_returns_error() {
        let mgr = make_manager();
        let err = mgr.state("nonexistent").unwrap_err();
        assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
    }

    #[test]
    fn unregister_terminal_state_succeeds() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        // Unloaded is terminal
        mgr.unregister("ext-a")
            .expect("serde deserialization should succeed");
        assert!(mgr.state("ext-a").is_err());
    }

    #[test]
    fn unregister_non_terminal_fails() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        advance_to_running(&mut mgr, "ext-a");
        let err = mgr.unregister("ext-a").unwrap_err();
        assert_eq!(err.error_code(), "LIFECYCLE_INVALID_TRANSITION");
    }

    // -----------------------------------------------------------------------
    // Full lifecycle transition tests
    // -----------------------------------------------------------------------

    #[test]
    fn full_happy_path_lifecycle() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");

        // Unloaded → Running
        advance_to_running(&mut mgr, "ext-a");
        assert_eq!(
            mgr.state("ext-a")
                .expect("serde deserialization should succeed"),
            ExtensionState::Running
        );

        // Running → Suspending → Suspended
        mgr.transition("ext-a", LifecycleTransition::Suspend, "t2", None)
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.state("ext-a")
                .expect("serde deserialization should succeed"),
            ExtensionState::Suspending
        );
        mgr.transition("ext-a", LifecycleTransition::Freeze, "t2", None)
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.state("ext-a")
                .expect("serde deserialization should succeed"),
            ExtensionState::Suspended
        );

        // Suspended → Resuming → Running
        mgr.transition("ext-a", LifecycleTransition::Resume, "t3", None)
            .expect("serde deserialization should succeed");
        mgr.transition("ext-a", LifecycleTransition::Reactivate, "t3", None)
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.state("ext-a")
                .expect("serde deserialization should succeed"),
            ExtensionState::Running
        );

        // Running → Terminating → Terminated
        mgr.transition("ext-a", LifecycleTransition::Terminate, "t4", None)
            .expect("serde deserialization should succeed");
        mgr.transition("ext-a", LifecycleTransition::Finalize, "t4", None)
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.state("ext-a")
                .expect("serde deserialization should succeed"),
            ExtensionState::Terminated
        );
    }

    #[test]
    fn invalid_transition_from_running_is_rejected() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        advance_to_running(&mut mgr, "ext-a");

        let err = mgr
            .transition("ext-a", LifecycleTransition::Validate, "t5", None)
            .unwrap_err();
        assert_eq!(err.error_code(), "LIFECYCLE_INVALID_TRANSITION");
    }

    #[test]
    fn transition_on_missing_extension_fails() {
        let mut mgr = make_manager();
        let err = mgr
            .transition("ghost", LifecycleTransition::Validate, "t0", None)
            .unwrap_err();
        assert_eq!(err.error_code(), "LIFECYCLE_EXTENSION_NOT_FOUND");
    }

    #[test]
    fn failure_path_reject_manifest_returns_to_unloaded() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        mgr.transition("ext-a", LifecycleTransition::Validate, "t1", None)
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.state("ext-a")
                .expect("serde deserialization should succeed"),
            ExtensionState::Validating
        );
        mgr.transition("ext-a", LifecycleTransition::RejectManifest, "t1", None)
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.state("ext-a")
                .expect("serde deserialization should succeed"),
            ExtensionState::Unloaded
        );
    }

    #[test]
    fn failure_path_load_failed_returns_to_unloaded() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        mgr.transition("ext-a", LifecycleTransition::Validate, "t1", None)
            .expect("serde deserialization should succeed");
        mgr.transition("ext-a", LifecycleTransition::Load, "t1", None)
            .expect("serde deserialization should succeed");
        mgr.transition("ext-a", LifecycleTransition::LoadFailed, "t1", None)
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.state("ext-a")
                .expect("serde deserialization should succeed"),
            ExtensionState::Unloaded
        );
    }

    #[test]
    fn quarantine_from_running_goes_to_quarantined() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        advance_to_running(&mut mgr, "ext-a");
        mgr.transition("ext-a", LifecycleTransition::Quarantine, "t1", None)
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.state("ext-a")
                .expect("serde deserialization should succeed"),
            ExtensionState::Quarantined
        );
    }

    // -----------------------------------------------------------------------
    // Transition log tests
    // -----------------------------------------------------------------------

    #[test]
    fn transition_log_records_all_transitions() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        advance_to_running(&mut mgr, "ext-a");
        let log = mgr
            .transition_log("ext-a")
            .expect("serde deserialization should succeed");
        assert_eq!(log.len(), 4); // Validate, Load, Start, Activate
        assert_eq!(log[0].from_state, ExtensionState::Unloaded);
        assert_eq!(log[0].to_state, ExtensionState::Validating);
        assert_eq!(log[0].transition, LifecycleTransition::Validate);
        assert_eq!(log[0].sequence, 0);
        assert_eq!(log[3].from_state, ExtensionState::Starting);
        assert_eq!(log[3].to_state, ExtensionState::Running);
        assert_eq!(log[3].sequence, 3);
    }

    #[test]
    fn transition_log_includes_decision_id() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        mgr.transition(
            "ext-a",
            LifecycleTransition::Validate,
            "trace-1",
            Some("decision-1"),
        )
        .expect("serde deserialization should succeed");
        let log = mgr
            .transition_log("ext-a")
            .expect("serde deserialization should succeed");
        assert_eq!(log[0].trace_id, "trace-1");
        assert_eq!(log[0].decision_id.as_deref(), Some("decision-1"));
    }

    // -----------------------------------------------------------------------
    // Budget enforcement tests
    // -----------------------------------------------------------------------

    #[test]
    fn start_fails_with_insufficient_budget() {
        let mut mgr = make_manager();
        let tiny_budget = ResourceBudget::new(0, 1024, 100);
        mgr.register("ext-a", tiny_budget, CancellationConfig::default())
            .expect("serde deserialization should succeed");
        mgr.transition("ext-a", LifecycleTransition::Validate, "t1", None)
            .expect("serde deserialization should succeed");
        mgr.transition("ext-a", LifecycleTransition::Load, "t1", None)
            .expect("serde deserialization should succeed");
        let err = mgr
            .transition("ext-a", LifecycleTransition::Start, "t1", None)
            .unwrap_err();
        assert_eq!(err.error_code(), "LIFECYCLE_BUDGET_EXHAUSTED");
    }

    #[test]
    fn consume_cpu_reduces_budget() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        mgr.consume_cpu("ext-a", 100_000)
            .expect("serde deserialization should succeed");
        let b = mgr
            .budget("ext-a")
            .expect("serde deserialization should succeed");
        assert_eq!(b.cpu_remaining_millionths, 900_000);
    }

    #[test]
    fn consume_cpu_fails_on_exhaustion() {
        let mut mgr = make_manager();
        let small = ResourceBudget::new(100, 1024, 100);
        mgr.register("ext-a", small, CancellationConfig::default())
            .expect("serde deserialization should succeed");
        let err = mgr.consume_cpu("ext-a", 200).unwrap_err();
        assert_eq!(err.error_code(), "LIFECYCLE_BUDGET_EXHAUSTED");
    }

    #[test]
    fn enforce_budgets_terminates_exhausted_extensions() {
        let mut mgr = make_manager();
        let tiny = ResourceBudget::new(MIN_START_BUDGET_MILLIONTHS, 0, 100);
        mgr.register("ext-a", tiny, CancellationConfig::default())
            .expect("serde deserialization should succeed");
        advance_to_running(&mut mgr, "ext-a");
        let contained = mgr.enforce_budgets("trace-budget");
        assert_eq!(contained.len(), 1);
        assert_eq!(contained[0].0, "ext-a");
        assert_eq!(
            mgr.state("ext-a")
                .expect("serde deserialization should succeed"),
            ExtensionState::Terminating
        );
    }

    // -----------------------------------------------------------------------
    // Cooperative shutdown tests
    // -----------------------------------------------------------------------

    #[test]
    fn cooperative_shutdown_within_grace_period() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        advance_to_running(&mut mgr, "ext-a");
        let state = mgr
            .cooperative_shutdown("ext-a", "t-shutdown", 1_000_000_000, false)
            .expect("serde deserialization should succeed");
        assert_eq!(state, ExtensionState::Terminated);
    }

    #[test]
    fn cooperative_shutdown_quarantine_on_timeout() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        advance_to_running(&mut mgr, "ext-a");
        // Succeeds within grace period -> Terminated, ignores quarantine_on_timeout
        let state = mgr
            .cooperative_shutdown("ext-a", "t-shutdown", 1_000_000_000, true)
            .expect("serde deserialization should succeed");
        assert_eq!(state, ExtensionState::Terminated);

        // Fails to succeed within grace period -> Quarantined
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-b");
        advance_to_running(&mut mgr, "ext-b");
        let state = mgr
            .cooperative_shutdown("ext-b", "t-shutdown", 6_000_000_000, true)
            .expect("serde deserialization should succeed");
        assert_eq!(state, ExtensionState::Quarantined);
    }

    #[test]
    fn cooperative_shutdown_force_on_grace_expiry() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        advance_to_running(&mut mgr, "ext-a");
        // Grace period is 5s; elapsed > 5s
        let state = mgr
            .cooperative_shutdown("ext-a", "t-shutdown", 6_000_000_000, false)
            .expect("serde deserialization should succeed");
        assert_eq!(state, ExtensionState::Terminated);
    }

    #[test]
    fn cooperative_shutdown_no_force_returns_error() {
        let mut mgr = make_manager();
        let cfg = CancellationConfig {
            grace_period_ns: DEFAULT_GRACE_PERIOD_NS,
            force_on_timeout: false,
            propagate_to_children: true,
        };
        mgr.register("ext-a", default_budget(), cfg)
            .expect("serde deserialization should succeed");
        advance_to_running(&mut mgr, "ext-a");
        let err = mgr
            .cooperative_shutdown("ext-a", "t-shutdown", 6_000_000_000, false)
            .unwrap_err();
        assert_eq!(err.error_code(), "LIFECYCLE_GRACE_EXPIRED");
    }

    // -----------------------------------------------------------------------
    // Event emission tests
    // -----------------------------------------------------------------------

    #[test]
    fn transition_emits_event() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        mgr.drain_events(); // clear registration event
        mgr.transition("ext-a", LifecycleTransition::Validate, "t1", None)
            .expect("serde deserialization should succeed");
        let events = mgr.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].component, "extension_lifecycle_manager");
        assert_eq!(events[0].event, "validate");
        assert_eq!(events[0].outcome, "ok");
        assert_eq!(events[0].extension_id, "ext-a");
        assert_eq!(events[0].from_state.as_deref(), Some("unloaded"));
        assert_eq!(events[0].to_state.as_deref(), Some("validating"));
    }

    #[test]
    fn drain_events_clears_buffer() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        assert!(!mgr.drain_events().is_empty());
        assert!(mgr.drain_events().is_empty());
    }

    // -----------------------------------------------------------------------
    // Manifest and utility tests
    // -----------------------------------------------------------------------

    #[test]
    fn set_manifest_stores_reference() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        let manifest = ManifestRef {
            extension_id: "ext-a".to_string(),
            capabilities: vec!["fs.read".to_string(), "net.send".to_string()],
            max_lifetime_ns: 3_600_000_000_000,
            schema_version: 1,
        };
        mgr.set_manifest("ext-a", manifest.clone())
            .expect("serde deserialization should succeed");
        let stored = mgr
            .manifest("ext-a")
            .expect("serde deserialization should succeed")
            .expect("serde deserialization should succeed");
        assert_eq!(stored.capabilities.len(), 2);
        assert_eq!(stored.schema_version, 1);
    }

    #[test]
    fn extension_ids_returns_all_registered() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-b");
        register_ext(&mut mgr, "ext-a");
        register_ext(&mut mgr, "ext-c");
        let ids = mgr.extension_ids();
        assert_eq!(ids, vec!["ext-a", "ext-b", "ext-c"]); // BTreeMap sorted
    }

    #[test]
    fn count_in_state_counts_correctly() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        register_ext(&mut mgr, "ext-b");
        register_ext(&mut mgr, "ext-c");
        assert_eq!(mgr.count_in_state(ExtensionState::Unloaded), 3);
        advance_to_running(&mut mgr, "ext-a");
        advance_to_running(&mut mgr, "ext-b");
        assert_eq!(mgr.count_in_state(ExtensionState::Running), 2);
        assert_eq!(mgr.count_in_state(ExtensionState::Unloaded), 1);
    }

    #[test]
    fn clock_advances_monotonically() {
        let mut mgr = make_manager();
        assert_eq!(mgr.clock_ns(), 0);
        mgr.advance_clock(1_000);
        assert_eq!(mgr.clock_ns(), 1_000);
        mgr.advance_clock(2_000);
        assert_eq!(mgr.clock_ns(), 3_000);
    }

    // -----------------------------------------------------------------------
    // Serde roundtrip tests
    // -----------------------------------------------------------------------

    #[test]
    fn extension_state_serde_roundtrip() {
        let state = ExtensionState::Running;
        let json = serde_json::to_string(&state).expect("serialize derived Serialize");
        let back: ExtensionState =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, state);
    }

    #[test]
    fn lifecycle_error_serde_roundtrip() {
        let err = LifecycleError::InvalidTransition {
            extension_id: "ext-a".to_string(),
            current_state: ExtensionState::Running,
            attempted: LifecycleTransition::Validate,
        };
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        let back: LifecycleError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, err);
    }

    #[test]
    fn transition_record_serde_roundtrip() {
        let rec = TransitionRecord {
            sequence: 42,
            timestamp_ns: 1_000_000,
            from_state: ExtensionState::Running,
            to_state: ExtensionState::Suspending,
            transition: LifecycleTransition::Suspend,
            trace_id: "trace-1".to_string(),
            decision_id: Some("dec-1".to_string()),
        };
        let json = serde_json::to_string(&rec).expect("serialize derived Serialize");
        let back: TransitionRecord =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, rec);
    }

    #[test]
    fn lifecycle_manager_event_serde_roundtrip() {
        let evt = LifecycleManagerEvent {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: "extension_lifecycle_manager".to_string(),
            event: "validate".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            extension_id: "ext-a".to_string(),
            from_state: Some("unloaded".to_string()),
            to_state: Some("validating".to_string()),
            transition: Some("validate".to_string()),
        };
        let json = serde_json::to_string(&evt).expect("serialize derived Serialize");
        let back: LifecycleManagerEvent =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, evt);
    }

    #[test]
    fn resource_budget_serde_roundtrip() {
        let b = ResourceBudget::new(500_000, 1024, 50);
        let json = serde_json::to_string(&b).expect("serialize derived Serialize");
        let back: ResourceBudget =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, b);
    }

    // -----------------------------------------------------------------------
    // Determinism / replay tests
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_replay_produces_identical_logs() {
        let run = |_seed: u64| -> Vec<TransitionRecord> {
            let mut mgr = make_manager();
            register_ext(&mut mgr, "ext-a");
            advance_to_running(&mut mgr, "ext-a");
            mgr.transition("ext-a", LifecycleTransition::Suspend, "t2", None)
                .expect("serde deserialization should succeed");
            mgr.transition("ext-a", LifecycleTransition::Freeze, "t2", None)
                .expect("serde deserialization should succeed");
            mgr.transition("ext-a", LifecycleTransition::Resume, "t3", None)
                .expect("serde deserialization should succeed");
            mgr.transition("ext-a", LifecycleTransition::Reactivate, "t3", None)
                .expect("serde deserialization should succeed");
            mgr.transition("ext-a", LifecycleTransition::Terminate, "t4", None)
                .expect("serde deserialization should succeed");
            mgr.transition("ext-a", LifecycleTransition::Finalize, "t4", None)
                .expect("serde deserialization should succeed");
            mgr.transition_log("ext-a")
                .expect("serde deserialization should succeed")
                .to_vec()
        };

        let log1 = run(1);
        let log2 = run(2);
        assert_eq!(log1, log2, "replay must produce identical transition logs");
    }

    #[test]
    fn deterministic_replay_produces_identical_events() {
        let run = || -> Vec<LifecycleManagerEvent> {
            let mut mgr = make_manager();
            register_ext(&mut mgr, "ext-a");
            advance_to_running(&mut mgr, "ext-a");
            mgr.drain_events()
        };
        let e1 = run();
        let e2 = run();
        assert_eq!(e1, e2, "replay must produce identical events");
    }

    // -----------------------------------------------------------------------
    // Error code stability tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_codes_are_stable_strings() {
        let cases: Vec<(LifecycleError, &str)> = vec![
            (
                LifecycleError::InvalidTransition {
                    extension_id: "x".to_string(),
                    current_state: ExtensionState::Running,
                    attempted: LifecycleTransition::Validate,
                },
                "LIFECYCLE_INVALID_TRANSITION",
            ),
            (
                LifecycleError::ExtensionNotFound {
                    extension_id: "x".to_string(),
                },
                "LIFECYCLE_EXTENSION_NOT_FOUND",
            ),
            (
                LifecycleError::ExtensionAlreadyExists {
                    extension_id: "x".to_string(),
                },
                "LIFECYCLE_EXTENSION_EXISTS",
            ),
            (
                LifecycleError::BudgetExhausted {
                    extension_id: "x".to_string(),
                    remaining_millionths: 0,
                    required_millionths: 1,
                },
                "LIFECYCLE_BUDGET_EXHAUSTED",
            ),
            (
                LifecycleError::GracePeriodExpired {
                    extension_id: "x".to_string(),
                    elapsed_ns: 0,
                    budget_ns: 0,
                },
                "LIFECYCLE_GRACE_EXPIRED",
            ),
            (
                LifecycleError::ManifestRejected {
                    extension_id: "x".to_string(),
                    reason: "bad".to_string(),
                },
                "LIFECYCLE_MANIFEST_REJECTED",
            ),
            (
                LifecycleError::Internal {
                    detail: "err".to_string(),
                },
                "LIFECYCLE_INTERNAL",
            ),
        ];
        for (err, expected_code) in &cases {
            assert_eq!(
                err.error_code(),
                *expected_code,
                "error code mismatch for {:?}",
                err
            );
        }
    }

    // -----------------------------------------------------------------------
    // Multiple extension concurrency (logical) tests
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_extensions_independent_lifecycles() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        register_ext(&mut mgr, "ext-b");

        advance_to_running(&mut mgr, "ext-a");
        assert_eq!(
            mgr.state("ext-a")
                .expect("serde deserialization should succeed"),
            ExtensionState::Running
        );
        assert_eq!(
            mgr.state("ext-b")
                .expect("serde deserialization should succeed"),
            ExtensionState::Unloaded
        );

        advance_to_running(&mut mgr, "ext-b");
        mgr.transition("ext-a", LifecycleTransition::Terminate, "t", None)
            .expect("serde deserialization should succeed");
        assert_eq!(
            mgr.state("ext-a")
                .expect("serde deserialization should succeed"),
            ExtensionState::Terminating
        );
        assert_eq!(
            mgr.state("ext-b")
                .expect("serde deserialization should succeed"),
            ExtensionState::Running
        );
    }

    #[test]
    fn budget_enforcement_only_affects_exhausted_extensions() {
        let mut mgr = make_manager();
        let exhausted_budget = ResourceBudget::new(MIN_START_BUDGET_MILLIONTHS, 0, 100);
        let healthy_budget = default_budget();
        mgr.register(
            "ext-exhausted",
            exhausted_budget,
            CancellationConfig::default(),
        )
        .expect("serde deserialization should succeed");
        mgr.register("ext-healthy", healthy_budget, CancellationConfig::default())
            .expect("serde deserialization should succeed");
        advance_to_running(&mut mgr, "ext-exhausted");
        advance_to_running(&mut mgr, "ext-healthy");

        let contained = mgr.enforce_budgets("trace-enforce");
        assert_eq!(contained.len(), 1);
        assert_eq!(contained[0].0, "ext-exhausted");
        assert_eq!(
            mgr.state("ext-healthy")
                .expect("serde deserialization should succeed"),
            ExtensionState::Running
        );
    }

    // -----------------------------------------------------------------------
    // Manifest and cancellation config tests
    // -----------------------------------------------------------------------

    #[test]
    fn manifest_ref_not_set_initially() {
        let mut mgr = make_manager();
        register_ext(&mut mgr, "ext-a");
        assert!(
            mgr.manifest("ext-a")
                .expect("serde deserialization should succeed")
                .is_none()
        );
    }

    #[test]
    fn cancellation_config_retrievable() {
        let mut mgr = make_manager();
        let cfg = CancellationConfig {
            grace_period_ns: 10_000_000_000,
            force_on_timeout: false,
            propagate_to_children: false,
        };
        mgr.register("ext-a", default_budget(), cfg.clone())
            .expect("serde deserialization should succeed");
        let stored = mgr
            .cancellation_config("ext-a")
            .expect("serde deserialization should succeed");
        assert_eq!(stored.grace_period_ns, 10_000_000_000);
        assert!(!stored.force_on_timeout);
    }

    // -----------------------------------------------------------------------
    // Error Display tests
    // -----------------------------------------------------------------------

    #[test]
    fn lifecycle_error_display_is_human_readable() {
        let err = LifecycleError::InvalidTransition {
            extension_id: "ext-a".to_string(),
            current_state: ExtensionState::Running,
            attempted: LifecycleTransition::Validate,
        };
        let msg = format!("{err}");
        assert!(msg.contains("ext-a"));
        assert!(msg.contains("running"));
        assert!(msg.contains("validate"));
    }

    #[test]
    fn extension_state_ord() {
        assert!(ExtensionState::Unloaded < ExtensionState::Validating);
        assert!(ExtensionState::Validating < ExtensionState::Loading);
        assert!(ExtensionState::Loading < ExtensionState::Starting);
        assert!(ExtensionState::Starting < ExtensionState::Running);
        assert!(ExtensionState::Running < ExtensionState::Suspending);
        assert!(ExtensionState::Suspended < ExtensionState::Resuming);
        assert!(ExtensionState::Terminating < ExtensionState::Terminated);
        assert!(ExtensionState::Terminated < ExtensionState::Quarantined);
    }

    #[test]
    fn lifecycle_transition_ord() {
        assert!(LifecycleTransition::Validate < LifecycleTransition::Load);
        assert!(LifecycleTransition::Load < LifecycleTransition::Start);
        assert!(LifecycleTransition::Start < LifecycleTransition::Activate);
        assert!(LifecycleTransition::Terminate < LifecycleTransition::Finalize);
        assert!(LifecycleTransition::Finalize < LifecycleTransition::Quarantine);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn extension_state_serde_roundtrip_all_variants() {
        let variants = [
            ExtensionState::Unloaded,
            ExtensionState::Validating,
            ExtensionState::Loading,
            ExtensionState::Starting,
            ExtensionState::Running,
            ExtensionState::Suspending,
            ExtensionState::Suspended,
            ExtensionState::Resuming,
            ExtensionState::Terminating,
            ExtensionState::Terminated,
            ExtensionState::Quarantined,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            let back: ExtensionState =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 11);
    }

    #[test]
    fn lifecycle_transition_serde_roundtrip_all_variants() {
        let variants = [
            LifecycleTransition::Validate,
            LifecycleTransition::Load,
            LifecycleTransition::Start,
            LifecycleTransition::Activate,
            LifecycleTransition::Suspend,
            LifecycleTransition::Freeze,
            LifecycleTransition::Resume,
            LifecycleTransition::Reactivate,
            LifecycleTransition::Terminate,
            LifecycleTransition::Finalize,
            LifecycleTransition::Quarantine,
            LifecycleTransition::RejectManifest,
            LifecycleTransition::LoadFailed,
            LifecycleTransition::StartFailed,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            let back: LifecycleTransition =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 14);
    }

    #[test]
    fn extension_state_as_str_all_distinct() {
        let variants = [
            ExtensionState::Unloaded,
            ExtensionState::Validating,
            ExtensionState::Loading,
            ExtensionState::Starting,
            ExtensionState::Running,
            ExtensionState::Suspending,
            ExtensionState::Suspended,
            ExtensionState::Resuming,
            ExtensionState::Terminating,
            ExtensionState::Terminated,
            ExtensionState::Quarantined,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            assert!(seen.insert(v.as_str()), "duplicate as_str: {}", v.as_str());
        }
        assert_eq!(seen.len(), 11);
    }

    #[test]
    fn lifecycle_transition_as_str_all_distinct() {
        let variants = [
            LifecycleTransition::Validate,
            LifecycleTransition::Load,
            LifecycleTransition::Start,
            LifecycleTransition::Activate,
            LifecycleTransition::Suspend,
            LifecycleTransition::Freeze,
            LifecycleTransition::Resume,
            LifecycleTransition::Reactivate,
            LifecycleTransition::Terminate,
            LifecycleTransition::Finalize,
            LifecycleTransition::Quarantine,
            LifecycleTransition::RejectManifest,
            LifecycleTransition::LoadFailed,
            LifecycleTransition::StartFailed,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            assert!(seen.insert(v.as_str()), "duplicate as_str: {}", v.as_str());
        }
        assert_eq!(seen.len(), 14);
    }

    #[test]
    fn lifecycle_transition_is_failure_correct() {
        assert!(LifecycleTransition::RejectManifest.is_failure());
        assert!(LifecycleTransition::LoadFailed.is_failure());
        assert!(LifecycleTransition::StartFailed.is_failure());
        assert!(!LifecycleTransition::Validate.is_failure());
        assert!(!LifecycleTransition::Activate.is_failure());
        assert!(!LifecycleTransition::Quarantine.is_failure());
    }

    #[test]
    fn lifecycle_error_invalid_transition_serde_stable() {
        let err = LifecycleError::InvalidTransition {
            extension_id: "ext-a".to_string(),
            current_state: ExtensionState::Running,
            attempted: LifecycleTransition::Validate,
        };
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        let back: LifecycleError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, err);
    }

    #[test]
    fn extension_state_predicates_comprehensive() {
        // is_alive: Validating, Loading, Starting, Running, Resuming
        assert!(ExtensionState::Running.is_alive());
        assert!(ExtensionState::Starting.is_alive());
        assert!(!ExtensionState::Suspended.is_alive());
        assert!(!ExtensionState::Terminated.is_alive());

        // is_terminal: Terminated, Quarantined, Unloaded
        assert!(ExtensionState::Terminated.is_terminal());
        assert!(ExtensionState::Quarantined.is_terminal());
        assert!(ExtensionState::Unloaded.is_terminal());
        assert!(!ExtensionState::Running.is_terminal());

        // is_executing: Running, Starting, Resuming
        assert!(ExtensionState::Running.is_executing());
        assert!(ExtensionState::Starting.is_executing());
        assert!(ExtensionState::Resuming.is_executing());
        assert!(!ExtensionState::Loading.is_executing());
    }
}
