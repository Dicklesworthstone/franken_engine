//! Thread `Cx` through all effectful extension-host APIs.
//!
//! Every effectful operation in the extension-host subsystem must accept a
//! `ContextAdapter` (the adapter-layer wrapper over `franken_kernel::Cx`) as
//! its first parameter.  This module provides the gateway types and dispatch
//! functions that enforce this invariant for four API categories:
//!
//! 1. **Hostcall gateways** — extension → host function calls
//! 2. **Policy checks** — pre-call, post-call, resource-limit evaluation
//! 3. **Lifecycle transitions** — load, start, suspend, resume, unload, …
//! 4. **Telemetry emitters** — metric emission, trace spans, evidence logging
//!
//! Each gateway validates budget availability before executing the operation,
//! consumes an appropriate budget quantum, and emits a structured
//! `AdapterEvent` recording the trace/decision/policy context.
//!
//! Plan references: Section 10.13 item 5, bd-2ygl.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::control_plane::ContextAdapter;

// ---------------------------------------------------------------------------
// Budget cost constants (in milliseconds)
// ---------------------------------------------------------------------------

/// Budget cost for a single hostcall gateway dispatch.
pub const HOSTCALL_BUDGET_COST_MS: u64 = 1;

/// Budget cost for a policy check evaluation.
pub const POLICY_CHECK_BUDGET_COST_MS: u64 = 2;

/// Budget cost for a lifecycle transition.
pub const LIFECYCLE_TRANSITION_BUDGET_COST_MS: u64 = 3;

/// Budget cost for a telemetry emission.
pub const TELEMETRY_EMIT_BUDGET_COST_MS: u64 = 1;

// ---------------------------------------------------------------------------
// CxThreadingError
// ---------------------------------------------------------------------------

/// Errors returned by Cx-threaded effectful operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CxThreadingError {
    /// Budget exhausted before the operation could execute.
    BudgetExhausted {
        operation: String,
        requested_ms: u64,
        remaining_ms: u64,
    },
    /// Hostcall gateway rejected the call.
    HostcallRejected {
        hostcall_name: String,
        reason: String,
    },
    /// Policy check denied the operation.
    PolicyDenied { check_name: String, verdict: String },
    /// Lifecycle transition violated ordering.
    LifecycleViolation {
        from: LifecyclePhase,
        to: LifecyclePhase,
        reason: String,
    },
    /// Telemetry emission failed.
    TelemetryFailed { emitter: String, reason: String },
    /// The operation was cancelled via the Cx cancellation token.
    Cancelled { operation: String },
}

impl fmt::Display for CxThreadingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BudgetExhausted {
                operation,
                requested_ms,
                remaining_ms,
            } => write!(
                f,
                "budget exhausted for {operation}: need {requested_ms}ms, have {remaining_ms}ms"
            ),
            Self::HostcallRejected {
                hostcall_name,
                reason,
            } => write!(f, "hostcall {hostcall_name} rejected: {reason}"),
            Self::PolicyDenied {
                check_name,
                verdict,
            } => write!(f, "policy check {check_name} denied: {verdict}"),
            Self::LifecycleViolation { from, to, reason } => {
                write!(f, "lifecycle violation {from} -> {to}: {reason}")
            }
            Self::TelemetryFailed { emitter, reason } => {
                write!(f, "telemetry emission failed ({emitter}): {reason}")
            }
            Self::Cancelled { operation } => write!(f, "operation cancelled: {operation}"),
        }
    }
}

impl std::error::Error for CxThreadingError {}

impl CxThreadingError {
    /// Stable error code for structured logging.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::BudgetExhausted { .. } => "cx_budget_exhausted",
            Self::HostcallRejected { .. } => "cx_hostcall_rejected",
            Self::PolicyDenied { .. } => "cx_policy_denied",
            Self::LifecycleViolation { .. } => "cx_lifecycle_violation",
            Self::TelemetryFailed { .. } => "cx_telemetry_failed",
            Self::Cancelled { .. } => "cx_cancelled",
        }
    }
}

// ---------------------------------------------------------------------------
// EffectCategory — classifies the effectful API category
// ---------------------------------------------------------------------------

/// Category of effectful extension-host API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EffectCategory {
    /// Extension → host function call.
    Hostcall,
    /// Pre/post-call or resource-limit policy evaluation.
    PolicyCheck,
    /// Load, start, suspend, resume, unload, quarantine, terminate, revoke.
    LifecycleTransition,
    /// Metric emission, trace span creation, evidence logging.
    TelemetryEmit,
}

impl EffectCategory {
    /// Default budget cost for this category.
    pub fn budget_cost_ms(self) -> u64 {
        match self {
            Self::Hostcall => HOSTCALL_BUDGET_COST_MS,
            Self::PolicyCheck => POLICY_CHECK_BUDGET_COST_MS,
            Self::LifecycleTransition => LIFECYCLE_TRANSITION_BUDGET_COST_MS,
            Self::TelemetryEmit => TELEMETRY_EMIT_BUDGET_COST_MS,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Hostcall => "hostcall",
            Self::PolicyCheck => "policy_check",
            Self::LifecycleTransition => "lifecycle_transition",
            Self::TelemetryEmit => "telemetry_emit",
        }
    }
}

impl fmt::Display for EffectCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// LifecyclePhase — lifecycle state for Cx-threaded transitions
// ---------------------------------------------------------------------------

/// Lifecycle phases for extension execution cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LifecyclePhase {
    /// Not yet loaded.
    Unloaded,
    /// Extension loaded into memory, not yet started.
    Loaded,
    /// Extension is actively executing.
    Running,
    /// Execution suspended (budget hold or operator action).
    Suspended,
    /// Quarantined after a policy violation.
    Quarantined,
    /// Graceful unload in progress.
    Unloading,
    /// Terminated (final state).
    Terminated,
}

impl LifecyclePhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unloaded => "unloaded",
            Self::Loaded => "loaded",
            Self::Running => "running",
            Self::Suspended => "suspended",
            Self::Quarantined => "quarantined",
            Self::Unloading => "unloading",
            Self::Terminated => "terminated",
        }
    }

    /// Returns whether this phase is a terminal state (no further transitions).
    pub fn is_terminal(self) -> bool {
        self == Self::Terminated
    }
}

impl fmt::Display for LifecyclePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Allowed lifecycle transitions
// ---------------------------------------------------------------------------

fn is_valid_transition(from: LifecyclePhase, to: LifecyclePhase) -> bool {
    use LifecyclePhase::*;
    matches!(
        (from, to),
        (Unloaded, Loaded)
            | (Loaded, Running)
            | (Loaded, Unloading)
            | (Loaded, Terminated)
            | (Running, Suspended)
            | (Suspended, Running)
            | (Running, Quarantined)
            | (Running, Unloading)
            | (Suspended, Unloading)
            | (Suspended, Terminated)
            | (Quarantined, Unloading)
            | (Unloading, Terminated)
            | (Running, Terminated)
            | (Quarantined, Terminated)
    )
}

// ---------------------------------------------------------------------------
// HostcallDescriptor — describes a hostcall for gateway dispatch
// ---------------------------------------------------------------------------

/// Describes a hostcall for Cx-threaded dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostcallDescriptor {
    /// Unique hostcall name (e.g. "fs_read", "net_egress", "kv_get").
    pub name: String,
    /// Extension identifier making the call.
    pub extension_id: String,
    /// Optional custom budget cost override (milliseconds).
    pub budget_cost_override_ms: Option<u64>,
}

impl HostcallDescriptor {
    pub fn new(name: impl Into<String>, extension_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            extension_id: extension_id.into(),
            budget_cost_override_ms: None,
        }
    }

    pub fn with_budget_cost(mut self, cost_ms: u64) -> Self {
        self.budget_cost_override_ms = Some(cost_ms);
        self
    }

    #[allow(dead_code)]
    fn effective_budget_cost_ms(&self) -> u64 {
        self.budget_cost_override_ms
            .unwrap_or(HOSTCALL_BUDGET_COST_MS)
    }
}

// ---------------------------------------------------------------------------
// PolicyCheckDescriptor — describes a policy check
// ---------------------------------------------------------------------------

/// Describes a policy check for Cx-threaded evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCheckDescriptor {
    /// Name of the policy check (e.g. "pre_hostcall", "resource_limit").
    pub check_name: String,
    /// Policy identifier governing this check.
    pub policy_id: String,
    /// Scope of the check (e.g. extension ID, region ID).
    pub scope: String,
}

impl PolicyCheckDescriptor {
    pub fn new(
        check_name: impl Into<String>,
        policy_id: impl Into<String>,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            check_name: check_name.into(),
            policy_id: policy_id.into(),
            scope: scope.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// TelemetryDescriptor — describes a telemetry emission
// ---------------------------------------------------------------------------

/// Describes a telemetry emission for Cx-threaded dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryDescriptor {
    /// Emitter component name.
    pub emitter: String,
    /// Event name being emitted.
    pub event_name: String,
    /// Severity level.
    pub level: TelemetryLevel,
}

impl TelemetryDescriptor {
    pub fn new(
        emitter: impl Into<String>,
        event_name: impl Into<String>,
        level: TelemetryLevel,
    ) -> Self {
        Self {
            emitter: emitter.into(),
            event_name: event_name.into(),
            level,
        }
    }
}

/// Telemetry severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TelemetryLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl TelemetryLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for TelemetryLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CxThreadedEvent — unified event type for all Cx-threaded operations
// ---------------------------------------------------------------------------

/// Structured event emitted by every Cx-threaded effectful operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CxThreadedEvent {
    pub trace_id: String,
    pub category: EffectCategory,
    pub component: String,
    pub operation: String,
    pub outcome: String,
    pub budget_consumed_ms: u64,
    pub budget_remaining_ms: u64,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// CxThreadedGateway — the unified gateway for all effectful operations
// ---------------------------------------------------------------------------

/// Gateway that enforces Cx threading for all effectful extension-host APIs.
///
/// Every effectful operation must route through this gateway, which:
/// 1. Validates budget availability via the `ContextAdapter`
/// 2. Consumes the appropriate budget quantum
/// 3. Emits a structured `CxThreadedEvent` with full trace context
///
/// The gateway is generic over the `ContextAdapter` implementation, allowing
/// both real `KernelContext<Cx>` and test `MockCx` to be used.
#[derive(Debug)]
pub struct CxThreadedGateway<C: ContextAdapter> {
    cx: C,
    lifecycle_phase: LifecyclePhase,
    events: Vec<CxThreadedEvent>,
    hostcall_registry: BTreeMap<String, HostcallRegistration>,
    policy_check_count: u64,
    hostcall_count: u64,
    lifecycle_transition_count: u64,
    telemetry_count: u64,
}

/// Registration entry for a hostcall in the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostcallRegistration {
    /// The hostcall name.
    pub name: String,
    /// Budget cost override for this hostcall (None = use default).
    pub budget_cost_override_ms: Option<u64>,
    /// Whether the hostcall is currently enabled.
    pub enabled: bool,
}

impl<C: ContextAdapter> CxThreadedGateway<C> {
    /// Create a new gateway with the given context adapter.
    ///
    /// The gateway starts in `Unloaded` lifecycle phase.
    pub fn new(cx: C) -> Self {
        Self {
            cx,
            lifecycle_phase: LifecyclePhase::Unloaded,
            events: Vec::new(),
            hostcall_registry: BTreeMap::new(),
            policy_check_count: 0,
            hostcall_count: 0,
            lifecycle_transition_count: 0,
            telemetry_count: 0,
        }
    }

    /// Access the underlying context adapter (immutable).
    pub fn cx(&self) -> &C {
        &self.cx
    }

    /// Access the underlying context adapter (mutable).
    pub fn cx_mut(&mut self) -> &mut C {
        &mut self.cx
    }

    /// Current lifecycle phase.
    pub fn lifecycle_phase(&self) -> LifecyclePhase {
        self.lifecycle_phase
    }

    /// All emitted events.
    pub fn events(&self) -> &[CxThreadedEvent] {
        &self.events
    }

    /// Total hostcalls dispatched.
    pub fn hostcall_count(&self) -> u64 {
        self.hostcall_count
    }

    /// Total policy checks evaluated.
    pub fn policy_check_count(&self) -> u64 {
        self.policy_check_count
    }

    /// Total lifecycle transitions performed.
    pub fn lifecycle_transition_count(&self) -> u64 {
        self.lifecycle_transition_count
    }

    /// Total telemetry emissions.
    pub fn telemetry_count(&self) -> u64 {
        self.telemetry_count
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<CxThreadedEvent> {
        std::mem::take(&mut self.events)
    }

    // -----------------------------------------------------------------------
    // Hostcall gateway
    // -----------------------------------------------------------------------

    /// Register a hostcall in the gateway.
    pub fn register_hostcall(
        &mut self,
        name: impl Into<String>,
        budget_cost_override_ms: Option<u64>,
    ) {
        let name = name.into();
        self.hostcall_registry.insert(
            name.clone(),
            HostcallRegistration {
                name,
                budget_cost_override_ms,
                enabled: true,
            },
        );
    }

    /// Disable a registered hostcall (subsequent dispatch will be rejected).
    pub fn disable_hostcall(&mut self, name: &str) -> bool {
        if let Some(reg) = self.hostcall_registry.get_mut(name) {
            reg.enabled = false;
            true
        } else {
            false
        }
    }

    /// Dispatch a hostcall through the Cx-threaded gateway.
    ///
    /// This is the primary entry point for extension → host calls. It:
    /// 1. Validates the hostcall is registered and enabled
    /// 2. Validates budget availability
    /// 3. Consumes the budget quantum
    /// 4. Emits a structured event
    pub fn dispatch_hostcall(
        &mut self,
        desc: &HostcallDescriptor,
    ) -> Result<HostcallReceipt, CxThreadingError> {
        // Check registration
        let reg = match self.hostcall_registry.get(&desc.name) {
            Some(r) => r,
            None => {
                let err = CxThreadingError::HostcallRejected {
                    hostcall_name: desc.name.clone(),
                    reason: "hostcall not registered".to_string(),
                };
                self.emit_event(
                    EffectCategory::Hostcall,
                    &desc.name,
                    "rejected",
                    Some(err.error_code()),
                    0,
                );
                return Err(err);
            }
        };

        if !reg.enabled {
            let err = CxThreadingError::HostcallRejected {
                hostcall_name: desc.name.clone(),
                reason: "hostcall disabled".to_string(),
            };
            self.emit_event(
                EffectCategory::Hostcall,
                &desc.name,
                "rejected",
                Some(err.error_code()),
                0,
            );
            return Err(err);
        }

        let cost_ms = desc
            .budget_cost_override_ms
            .or(reg.budget_cost_override_ms)
            .unwrap_or(HOSTCALL_BUDGET_COST_MS);
        self.consume_budget(EffectCategory::Hostcall, &desc.name, cost_ms)?;

        self.hostcall_count += 1;
        self.emit_event(
            EffectCategory::Hostcall,
            &desc.name,
            "dispatched",
            None,
            cost_ms,
        );

        Ok(HostcallReceipt {
            hostcall_name: desc.name.clone(),
            extension_id: desc.extension_id.clone(),
            trace_id: self.cx.trace_id().to_string(),
            budget_consumed_ms: cost_ms,
            sequence_number: self.hostcall_count,
        })
    }

    // -----------------------------------------------------------------------
    // Policy check gateway
    // -----------------------------------------------------------------------

    /// Evaluate a policy check through the Cx-threaded gateway.
    ///
    /// Returns a `PolicyCheckResult` with the verdict. The caller supplies
    /// a closure that receives the policy descriptor and returns the raw
    /// verdict.
    pub fn evaluate_policy_check(
        &mut self,
        desc: &PolicyCheckDescriptor,
        check_fn: impl FnOnce(&PolicyCheckDescriptor) -> PolicyVerdict,
    ) -> Result<PolicyCheckResult, CxThreadingError> {
        let cost_ms = POLICY_CHECK_BUDGET_COST_MS;
        self.consume_budget(EffectCategory::PolicyCheck, &desc.check_name, cost_ms)?;

        let verdict = check_fn(desc);
        self.policy_check_count += 1;

        let outcome = match verdict {
            PolicyVerdict::Allow => "allow",
            PolicyVerdict::Deny { .. } => "deny",
            PolicyVerdict::Escalate { .. } => "escalate",
        };
        self.emit_event(
            EffectCategory::PolicyCheck,
            &desc.check_name,
            outcome,
            None,
            cost_ms,
        );

        if let PolicyVerdict::Deny { reason } = &verdict {
            return Err(CxThreadingError::PolicyDenied {
                check_name: desc.check_name.clone(),
                verdict: reason.clone(),
            });
        }

        Ok(PolicyCheckResult {
            check_name: desc.check_name.clone(),
            policy_id: desc.policy_id.clone(),
            verdict,
            trace_id: self.cx.trace_id().to_string(),
            budget_consumed_ms: cost_ms,
            sequence_number: self.policy_check_count,
        })
    }

    // -----------------------------------------------------------------------
    // Lifecycle transition gateway
    // -----------------------------------------------------------------------

    /// Execute a lifecycle transition through the Cx-threaded gateway.
    ///
    /// Validates that the transition from the current phase to the target
    /// phase is legal, consumes budget, and updates the internal state.
    pub fn transition_lifecycle(
        &mut self,
        target: LifecyclePhase,
    ) -> Result<LifecycleReceipt, CxThreadingError> {
        let from = self.lifecycle_phase;

        if from.is_terminal() {
            return Err(CxThreadingError::LifecycleViolation {
                from,
                to: target,
                reason: "current phase is terminal".to_string(),
            });
        }

        if !is_valid_transition(from, target) {
            return Err(CxThreadingError::LifecycleViolation {
                from,
                to: target,
                reason: format!("transition {from} -> {target} is not allowed"),
            });
        }

        let cost_ms = LIFECYCLE_TRANSITION_BUDGET_COST_MS;
        self.consume_budget(
            EffectCategory::LifecycleTransition,
            &format!("{from}->{target}"),
            cost_ms,
        )?;

        self.lifecycle_phase = target;
        self.lifecycle_transition_count += 1;

        self.emit_event(
            EffectCategory::LifecycleTransition,
            &format!("{from}->{target}"),
            "transitioned",
            None,
            cost_ms,
        );

        Ok(LifecycleReceipt {
            from,
            to: target,
            trace_id: self.cx.trace_id().to_string(),
            budget_consumed_ms: cost_ms,
            sequence_number: self.lifecycle_transition_count,
        })
    }

    // -----------------------------------------------------------------------
    // Telemetry emission gateway
    // -----------------------------------------------------------------------

    /// Emit telemetry through the Cx-threaded gateway.
    ///
    /// All telemetry emission (metrics, trace spans, evidence) must route
    /// through this method to ensure budget accounting and trace context.
    pub fn emit_telemetry(
        &mut self,
        desc: &TelemetryDescriptor,
        payload: &str,
    ) -> Result<TelemetryReceipt, CxThreadingError> {
        let cost_ms = TELEMETRY_EMIT_BUDGET_COST_MS;
        self.consume_budget(EffectCategory::TelemetryEmit, &desc.event_name, cost_ms)?;

        self.telemetry_count += 1;

        self.emit_event(
            EffectCategory::TelemetryEmit,
            &desc.event_name,
            "emitted",
            None,
            cost_ms,
        );

        Ok(TelemetryReceipt {
            emitter: desc.emitter.clone(),
            event_name: desc.event_name.clone(),
            level: desc.level,
            payload_len: payload.len(),
            trace_id: self.cx.trace_id().to_string(),
            budget_consumed_ms: cost_ms,
            sequence_number: self.telemetry_count,
        })
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn consume_budget(
        &mut self,
        category: EffectCategory,
        operation: &str,
        cost_ms: u64,
    ) -> Result<(), CxThreadingError> {
        let remaining = self.cx.budget().remaining_ms();
        self.cx.consume_budget(cost_ms).map_err(|_| {
            let err = CxThreadingError::BudgetExhausted {
                operation: operation.to_string(),
                requested_ms: cost_ms,
                remaining_ms: remaining,
            };
            self.emit_event(
                category,
                operation,
                "budget_exhausted",
                Some(err.error_code()),
                0,
            );
            err
        })
    }

    fn emit_event(
        &mut self,
        category: EffectCategory,
        operation: &str,
        outcome: &str,
        error_code: Option<&str>,
        cost_ms: u64,
    ) {
        self.events.push(CxThreadedEvent {
            trace_id: self.cx.trace_id().to_string(),
            category,
            component: "cx_threading".to_string(),
            operation: operation.to_string(),
            outcome: outcome.to_string(),
            budget_consumed_ms: cost_ms,
            budget_remaining_ms: self.cx.budget().remaining_ms(),
            error_code: error_code.map(String::from),
        });
    }
}

// ---------------------------------------------------------------------------
// PolicyVerdict — result of a policy check evaluation
// ---------------------------------------------------------------------------

/// Verdict from a Cx-threaded policy check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyVerdict {
    /// Operation is allowed.
    Allow,
    /// Operation is denied with reason.
    Deny { reason: String },
    /// Operation requires escalation (human review or higher-authority check).
    Escalate { reason: String },
}

impl fmt::Display for PolicyVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny { reason } => write!(f, "deny: {reason}"),
            Self::Escalate { reason } => write!(f, "escalate: {reason}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Receipt types — returned by each gateway dispatch
// ---------------------------------------------------------------------------

/// Receipt for a successfully dispatched hostcall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostcallReceipt {
    pub hostcall_name: String,
    pub extension_id: String,
    pub trace_id: String,
    pub budget_consumed_ms: u64,
    pub sequence_number: u64,
}

/// Receipt for a successfully evaluated policy check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCheckResult {
    pub check_name: String,
    pub policy_id: String,
    pub verdict: PolicyVerdict,
    pub trace_id: String,
    pub budget_consumed_ms: u64,
    pub sequence_number: u64,
}

/// Receipt for a successfully executed lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleReceipt {
    pub from: LifecyclePhase,
    pub to: LifecyclePhase,
    pub trace_id: String,
    pub budget_consumed_ms: u64,
    pub sequence_number: u64,
}

/// Receipt for a successfully emitted telemetry event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryReceipt {
    pub emitter: String,
    pub event_name: String,
    pub level: TelemetryLevel,
    pub payload_len: usize,
    pub trace_id: String,
    pub budget_consumed_ms: u64,
    pub sequence_number: u64,
}

// ---------------------------------------------------------------------------
// EffectAuditLog — aggregated audit of all Cx-threaded operations
// ---------------------------------------------------------------------------

/// Aggregated audit log summarizing all Cx-threaded operations for a
/// gateway instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectAuditLog {
    pub trace_id: String,
    pub total_events: u64,
    pub hostcall_count: u64,
    pub policy_check_count: u64,
    pub lifecycle_transition_count: u64,
    pub telemetry_count: u64,
    pub total_budget_consumed_ms: u64,
    pub final_lifecycle_phase: LifecyclePhase,
    pub events: Vec<CxThreadedEvent>,
}

impl<C: ContextAdapter> CxThreadedGateway<C> {
    /// Produce an audit log summarizing all operations routed through this
    /// gateway instance.
    pub fn audit_log(&self) -> EffectAuditLog {
        let total_budget_consumed_ms = self
            .events
            .iter()
            .filter(|e| e.error_code.is_none())
            .map(|e| e.budget_consumed_ms)
            .sum();

        EffectAuditLog {
            trace_id: self.cx.trace_id().to_string(),
            total_events: self.events.len() as u64,
            hostcall_count: self.hostcall_count,
            policy_check_count: self.policy_check_count,
            lifecycle_transition_count: self.lifecycle_transition_count,
            telemetry_count: self.telemetry_count,
            total_budget_consumed_ms,
            final_lifecycle_phase: self.lifecycle_phase,
            events: self.events.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Full-lifecycle scenario runner (integration helper)
// ---------------------------------------------------------------------------

/// Run a full extension lifecycle through the Cx-threaded gateway:
/// Unloaded → Loaded → Running → (hostcalls + policy checks + telemetry) →
/// Unloading → Terminated.
///
/// Returns the audit log or the first error encountered.
pub fn run_full_lifecycle<C: ContextAdapter>(
    gateway: &mut CxThreadedGateway<C>,
    hostcalls: &[HostcallDescriptor],
    policy_checks: &[PolicyCheckDescriptor],
    telemetry: &[TelemetryDescriptor],
) -> Result<EffectAuditLog, CxThreadingError> {
    // Phase 1: Load
    gateway.transition_lifecycle(LifecyclePhase::Loaded)?;

    // Phase 2: Start
    gateway.transition_lifecycle(LifecyclePhase::Running)?;

    // Phase 3: Execute hostcalls
    for desc in hostcalls {
        gateway.dispatch_hostcall(desc)?;
    }

    // Phase 4: Run policy checks
    for desc in policy_checks {
        gateway.evaluate_policy_check(desc, |_| PolicyVerdict::Allow)?;
    }

    // Phase 5: Emit telemetry
    for desc in telemetry {
        gateway.emit_telemetry(desc, "lifecycle_checkpoint")?;
    }

    // Phase 6: Unload
    gateway.transition_lifecycle(LifecyclePhase::Unloading)?;

    // Phase 7: Terminate
    gateway.transition_lifecycle(LifecyclePhase::Terminated)?;

    Ok(gateway.audit_log())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};

    fn make_cx(seed: u64, budget_ms: u64) -> MockCx {
        MockCx::new(trace_id_from_seed(seed), MockBudget::new(budget_ms))
    }

    fn make_gateway(seed: u64, budget_ms: u64) -> CxThreadedGateway<MockCx> {
        CxThreadedGateway::new(make_cx(seed, budget_ms))
    }

    fn hostcall(name: &str) -> HostcallDescriptor {
        HostcallDescriptor::new(name, "test-ext-001")
    }

    fn policy_check(name: &str) -> PolicyCheckDescriptor {
        PolicyCheckDescriptor::new(name, "test-policy-001", "ext-scope")
    }

    fn telemetry(event_name: &str) -> TelemetryDescriptor {
        TelemetryDescriptor::new("test-emitter", event_name, TelemetryLevel::Info)
    }

    // -----------------------------------------------------------------------
    // Effect category tests
    // -----------------------------------------------------------------------

    #[test]
    fn effect_category_budget_costs_are_consistent() {
        assert_eq!(
            EffectCategory::Hostcall.budget_cost_ms(),
            HOSTCALL_BUDGET_COST_MS
        );
        assert_eq!(
            EffectCategory::PolicyCheck.budget_cost_ms(),
            POLICY_CHECK_BUDGET_COST_MS
        );
        assert_eq!(
            EffectCategory::LifecycleTransition.budget_cost_ms(),
            LIFECYCLE_TRANSITION_BUDGET_COST_MS
        );
        assert_eq!(
            EffectCategory::TelemetryEmit.budget_cost_ms(),
            TELEMETRY_EMIT_BUDGET_COST_MS
        );
    }

    #[test]
    fn effect_category_display_matches_as_str() {
        for cat in [
            EffectCategory::Hostcall,
            EffectCategory::PolicyCheck,
            EffectCategory::LifecycleTransition,
            EffectCategory::TelemetryEmit,
        ] {
            assert_eq!(cat.to_string(), cat.as_str());
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle phase tests
    // -----------------------------------------------------------------------

    #[test]
    fn lifecycle_phase_terminal_detection() {
        assert!(!LifecyclePhase::Unloaded.is_terminal());
        assert!(!LifecyclePhase::Loaded.is_terminal());
        assert!(!LifecyclePhase::Running.is_terminal());
        assert!(!LifecyclePhase::Suspended.is_terminal());
        assert!(!LifecyclePhase::Quarantined.is_terminal());
        assert!(!LifecyclePhase::Unloading.is_terminal());
        assert!(LifecyclePhase::Terminated.is_terminal());
    }

    #[test]
    fn lifecycle_phase_display() {
        assert_eq!(LifecyclePhase::Running.to_string(), "running");
        assert_eq!(LifecyclePhase::Quarantined.to_string(), "quarantined");
        assert_eq!(LifecyclePhase::Terminated.to_string(), "terminated");
    }

    #[test]
    fn valid_lifecycle_transitions() {
        use LifecyclePhase::*;
        let valid = [
            (Unloaded, Loaded),
            (Loaded, Running),
            (Running, Suspended),
            (Suspended, Running),
            (Running, Quarantined),
            (Running, Unloading),
            (Suspended, Unloading),
            (Quarantined, Unloading),
            (Unloading, Terminated),
            (Running, Terminated),
            (Quarantined, Terminated),
        ];
        for (from, to) in valid {
            assert!(
                is_valid_transition(from, to),
                "expected valid: {from} -> {to}"
            );
        }
    }

    #[test]
    fn invalid_lifecycle_transitions() {
        use LifecyclePhase::*;
        let invalid = [
            (Unloaded, Running),
            (Loaded, Suspended),
            (Terminated, Unloaded),
            (Running, Loaded),
            (Suspended, Quarantined),
            (Unloading, Running),
        ];
        for (from, to) in invalid {
            assert!(
                !is_valid_transition(from, to),
                "expected invalid: {from} -> {to}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Gateway creation tests
    // -----------------------------------------------------------------------

    #[test]
    fn gateway_starts_in_unloaded_phase() {
        let gw = make_gateway(1, 100);
        assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Unloaded);
        assert_eq!(gw.hostcall_count(), 0);
        assert_eq!(gw.policy_check_count(), 0);
        assert_eq!(gw.lifecycle_transition_count(), 0);
        assert_eq!(gw.telemetry_count(), 0);
        assert!(gw.events().is_empty());
    }

    #[test]
    fn gateway_exposes_cx_accessors() {
        let gw = make_gateway(42, 500);
        let tid = trace_id_from_seed(42);
        assert_eq!(gw.cx().trace_id(), tid);
        assert_eq!(gw.cx().budget().remaining_ms(), 500);
    }

    // -----------------------------------------------------------------------
    // Hostcall dispatch tests
    // -----------------------------------------------------------------------

    #[test]
    fn hostcall_dispatch_consumes_budget_and_increments_counter() {
        let mut gw = make_gateway(1, 100);
        gw.register_hostcall("fs_read", None);
        let desc = hostcall("fs_read");
        let receipt = gw.dispatch_hostcall(&desc).expect("dispatch");
        assert_eq!(receipt.hostcall_name, "fs_read");
        assert_eq!(receipt.extension_id, "test-ext-001");
        assert_eq!(receipt.budget_consumed_ms, HOSTCALL_BUDGET_COST_MS);
        assert_eq!(receipt.sequence_number, 1);
        assert_eq!(gw.hostcall_count(), 1);
        assert_eq!(
            gw.cx().budget().remaining_ms(),
            100 - HOSTCALL_BUDGET_COST_MS
        );
    }

    #[test]
    fn hostcall_dispatch_with_custom_budget_cost() {
        let mut gw = make_gateway(2, 100);
        gw.register_hostcall("net_egress", None);
        let desc = hostcall("net_egress").with_budget_cost(10);
        let receipt = gw.dispatch_hostcall(&desc).expect("dispatch");
        assert_eq!(receipt.budget_consumed_ms, 10);
        assert_eq!(gw.cx().budget().remaining_ms(), 90);
    }

    #[test]
    fn hostcall_dispatch_fails_on_budget_exhaustion() {
        let mut gw = make_gateway(3, 0);
        gw.register_hostcall("fs_read", None);
        let desc = hostcall("fs_read");
        let err = gw.dispatch_hostcall(&desc).expect_err("should fail");
        assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
        assert_eq!(err.error_code(), "cx_budget_exhausted");
    }

    #[test]
    fn hostcall_dispatch_emits_event() {
        let mut gw = make_gateway(4, 100);
        gw.register_hostcall("kv_get", None);
        gw.dispatch_hostcall(&hostcall("kv_get")).expect("dispatch");
        assert_eq!(gw.events().len(), 1);
        assert_eq!(gw.events()[0].category, EffectCategory::Hostcall);
        assert_eq!(gw.events()[0].operation, "kv_get");
        assert_eq!(gw.events()[0].outcome, "dispatched");
        assert!(gw.events()[0].error_code.is_none());
    }

    #[test]
    fn registered_hostcall_can_be_disabled() {
        let mut gw = make_gateway(5, 100);
        gw.register_hostcall("dangerous_op", Some(5));
        let desc = hostcall("dangerous_op");

        // Dispatch should work initially
        gw.dispatch_hostcall(&desc).expect("dispatch");
        assert_eq!(gw.hostcall_count(), 1);

        // Disable and dispatch again
        assert!(gw.disable_hostcall("dangerous_op"));
        let err = gw.dispatch_hostcall(&desc).expect_err("should fail");
        assert!(matches!(err, CxThreadingError::HostcallRejected { .. }));
        assert_eq!(err.error_code(), "cx_hostcall_rejected");
    }

    #[test]
    fn disable_nonexistent_hostcall_returns_false() {
        let mut gw = make_gateway(6, 100);
        assert!(!gw.disable_hostcall("nonexistent"));
    }

    #[test]
    fn multiple_hostcalls_consume_cumulative_budget() {
        let mut gw = make_gateway(7, 10);
        for i in 0..5 {
            let name = format!("op_{i}");
            gw.register_hostcall(&name, None);
            let desc = hostcall(&name);
            gw.dispatch_hostcall(&desc).expect("dispatch");
        }
        assert_eq!(gw.hostcall_count(), 5);
        assert_eq!(
            gw.cx().budget().remaining_ms(),
            10 - 5 * HOSTCALL_BUDGET_COST_MS
        );
    }

    // -----------------------------------------------------------------------
    // Policy check tests
    // -----------------------------------------------------------------------

    #[test]
    fn policy_check_allow_consumes_budget_and_returns_result() {
        let mut gw = make_gateway(10, 100);
        let desc = policy_check("pre_hostcall");
        let result = gw
            .evaluate_policy_check(&desc, |_| PolicyVerdict::Allow)
            .expect("check");
        assert_eq!(result.check_name, "pre_hostcall");
        assert_eq!(result.verdict, PolicyVerdict::Allow);
        assert_eq!(result.budget_consumed_ms, POLICY_CHECK_BUDGET_COST_MS);
        assert_eq!(gw.policy_check_count(), 1);
    }

    #[test]
    fn policy_check_deny_returns_error() {
        let mut gw = make_gateway(11, 100);
        let desc = policy_check("resource_limit");
        let err = gw
            .evaluate_policy_check(&desc, |_| PolicyVerdict::Deny {
                reason: "over limit".to_string(),
            })
            .expect_err("should deny");
        assert!(matches!(err, CxThreadingError::PolicyDenied { .. }));
        // Budget is still consumed even on deny
        assert_eq!(
            gw.cx().budget().remaining_ms(),
            100 - POLICY_CHECK_BUDGET_COST_MS
        );
    }

    #[test]
    fn policy_check_escalate_returns_ok() {
        let mut gw = make_gateway(12, 100);
        let desc = policy_check("escalation_check");
        let result = gw
            .evaluate_policy_check(&desc, |_| PolicyVerdict::Escalate {
                reason: "needs human review".to_string(),
            })
            .expect("escalation is ok");
        assert!(matches!(result.verdict, PolicyVerdict::Escalate { .. }));
    }

    #[test]
    fn policy_check_emits_event() {
        let mut gw = make_gateway(13, 100);
        gw.evaluate_policy_check(&policy_check("audit_check"), |_| PolicyVerdict::Allow)
            .expect("check");
        assert_eq!(gw.events().len(), 1);
        assert_eq!(gw.events()[0].category, EffectCategory::PolicyCheck);
        assert_eq!(gw.events()[0].outcome, "allow");
    }

    #[test]
    fn policy_check_budget_exhaustion() {
        let mut gw = make_gateway(14, 1);
        let err = gw
            .evaluate_policy_check(&policy_check("expensive_check"), |_| PolicyVerdict::Allow)
            .expect_err("budget too low");
        assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
    }

    // -----------------------------------------------------------------------
    // Lifecycle transition tests
    // -----------------------------------------------------------------------

    #[test]
    fn lifecycle_unloaded_to_loaded_succeeds() {
        let mut gw = make_gateway(20, 100);
        let receipt = gw
            .transition_lifecycle(LifecyclePhase::Loaded)
            .expect("transition");
        assert_eq!(receipt.from, LifecyclePhase::Unloaded);
        assert_eq!(receipt.to, LifecyclePhase::Loaded);
        assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Loaded);
        assert_eq!(gw.lifecycle_transition_count(), 1);
    }

    #[test]
    fn lifecycle_full_happy_path() {
        let mut gw = make_gateway(21, 100);
        gw.transition_lifecycle(LifecyclePhase::Loaded)
            .expect("load");
        gw.transition_lifecycle(LifecyclePhase::Running)
            .expect("run");
        gw.transition_lifecycle(LifecyclePhase::Unloading)
            .expect("unload");
        gw.transition_lifecycle(LifecyclePhase::Terminated)
            .expect("terminate");
        assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Terminated);
        assert_eq!(gw.lifecycle_transition_count(), 4);
    }

    #[test]
    fn lifecycle_suspend_and_resume() {
        let mut gw = make_gateway(22, 100);
        gw.transition_lifecycle(LifecyclePhase::Loaded)
            .expect("load");
        gw.transition_lifecycle(LifecyclePhase::Running)
            .expect("run");
        gw.transition_lifecycle(LifecyclePhase::Suspended)
            .expect("suspend");
        gw.transition_lifecycle(LifecyclePhase::Running)
            .expect("resume");
        assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Running);
    }

    #[test]
    fn lifecycle_quarantine_path() {
        let mut gw = make_gateway(23, 100);
        gw.transition_lifecycle(LifecyclePhase::Loaded)
            .expect("load");
        gw.transition_lifecycle(LifecyclePhase::Running)
            .expect("run");
        gw.transition_lifecycle(LifecyclePhase::Quarantined)
            .expect("quarantine");
        gw.transition_lifecycle(LifecyclePhase::Unloading)
            .expect("unload");
        gw.transition_lifecycle(LifecyclePhase::Terminated)
            .expect("terminate");
        assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Terminated);
    }

    #[test]
    fn lifecycle_invalid_transition_rejected() {
        let mut gw = make_gateway(24, 100);
        let err = gw
            .transition_lifecycle(LifecyclePhase::Running)
            .expect_err("invalid");
        assert!(matches!(err, CxThreadingError::LifecycleViolation { .. }));
    }

    #[test]
    fn lifecycle_terminal_state_blocks_further_transitions() {
        let mut gw = make_gateway(25, 100);
        gw.transition_lifecycle(LifecyclePhase::Loaded)
            .expect("load");
        gw.transition_lifecycle(LifecyclePhase::Running)
            .expect("run");
        gw.transition_lifecycle(LifecyclePhase::Terminated)
            .expect("terminate");
        let err = gw
            .transition_lifecycle(LifecyclePhase::Running)
            .expect_err("terminal");
        assert!(matches!(
            err,
            CxThreadingError::LifecycleViolation {
                from: LifecyclePhase::Terminated,
                ..
            }
        ));
    }

    #[test]
    fn lifecycle_budget_exhaustion_blocks_transition() {
        let mut gw = make_gateway(26, 2);
        let err = gw
            .transition_lifecycle(LifecyclePhase::Loaded)
            .expect_err("budget too low for lifecycle cost");
        assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
        // Phase should not change on failure
        assert_eq!(gw.lifecycle_phase(), LifecyclePhase::Unloaded);
    }

    #[test]
    fn lifecycle_emits_events() {
        let mut gw = make_gateway(27, 100);
        gw.transition_lifecycle(LifecyclePhase::Loaded)
            .expect("load");
        assert_eq!(gw.events().len(), 1);
        assert_eq!(gw.events()[0].category, EffectCategory::LifecycleTransition);
        assert_eq!(gw.events()[0].outcome, "transitioned");
    }

    // -----------------------------------------------------------------------
    // Telemetry emission tests
    // -----------------------------------------------------------------------

    #[test]
    fn telemetry_emission_consumes_budget() {
        let mut gw = make_gateway(30, 100);
        let desc = telemetry("metric_checkpoint");
        let receipt = gw.emit_telemetry(&desc, "payload data").expect("emit");
        assert_eq!(receipt.emitter, "test-emitter");
        assert_eq!(receipt.event_name, "metric_checkpoint");
        assert_eq!(receipt.level, TelemetryLevel::Info);
        assert_eq!(receipt.payload_len, 12); // "payload data"
        assert_eq!(receipt.budget_consumed_ms, TELEMETRY_EMIT_BUDGET_COST_MS);
        assert_eq!(gw.telemetry_count(), 1);
    }

    #[test]
    fn telemetry_emission_budget_exhaustion() {
        let mut gw = make_gateway(31, 0);
        let err = gw
            .emit_telemetry(&telemetry("should_fail"), "")
            .expect_err("budget");
        assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
    }

    #[test]
    fn telemetry_emits_event() {
        let mut gw = make_gateway(32, 100);
        gw.emit_telemetry(&telemetry("evidence_log"), "data")
            .expect("emit");
        assert_eq!(gw.events().len(), 1);
        assert_eq!(gw.events()[0].category, EffectCategory::TelemetryEmit);
        assert_eq!(gw.events()[0].outcome, "emitted");
    }

    #[test]
    fn telemetry_level_display() {
        assert_eq!(TelemetryLevel::Debug.to_string(), "debug");
        assert_eq!(TelemetryLevel::Info.to_string(), "info");
        assert_eq!(TelemetryLevel::Warn.to_string(), "warn");
        assert_eq!(TelemetryLevel::Error.to_string(), "error");
    }

    // -----------------------------------------------------------------------
    // Audit log tests
    // -----------------------------------------------------------------------

    #[test]
    fn audit_log_reflects_all_operations() {
        let mut gw = make_gateway(40, 200);
        gw.transition_lifecycle(LifecyclePhase::Loaded)
            .expect("load");
        gw.transition_lifecycle(LifecyclePhase::Running)
            .expect("run");
        gw.register_hostcall("fs_read", None);
        gw.register_hostcall("kv_get", None);
        gw.dispatch_hostcall(&hostcall("fs_read")).expect("hc1");
        gw.dispatch_hostcall(&hostcall("kv_get")).expect("hc2");
        gw.evaluate_policy_check(&policy_check("limit"), |_| PolicyVerdict::Allow)
            .expect("pc");
        gw.emit_telemetry(&telemetry("metric"), "data")
            .expect("tel");
        gw.transition_lifecycle(LifecyclePhase::Unloading)
            .expect("unload");
        gw.transition_lifecycle(LifecyclePhase::Terminated)
            .expect("term");

        let log = gw.audit_log();
        assert_eq!(log.hostcall_count, 2);
        assert_eq!(log.policy_check_count, 1);
        assert_eq!(log.lifecycle_transition_count, 4);
        assert_eq!(log.telemetry_count, 1);
        assert_eq!(log.final_lifecycle_phase, LifecyclePhase::Terminated);
        assert_eq!(log.events.len(), 8); // 4 lifecycle + 2 hostcall + 1 policy + 1 telemetry
    }

    #[test]
    fn audit_log_trace_id_consistency() {
        let seed = 41;
        let mut gw = make_gateway(seed, 100);
        let tid = trace_id_from_seed(seed);
        gw.register_hostcall("op", None);
        gw.dispatch_hostcall(&hostcall("op")).expect("hc");
        let log = gw.audit_log();
        assert_eq!(log.trace_id, tid.to_string());
        for event in &log.events {
            assert_eq!(event.trace_id, tid.to_string());
        }
    }

    // -----------------------------------------------------------------------
    // Full lifecycle integration test
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle_happy_path() {
        let mut gw = make_gateway(50, 500);
        gw.register_hostcall("fs_read", None);
        gw.register_hostcall("kv_get", Some(2));

        let hostcalls = vec![hostcall("fs_read"), hostcall("kv_get")];
        let policy_checks = vec![policy_check("pre_call"), policy_check("post_call")];
        let telemetry_descs = vec![telemetry("evidence"), telemetry("metric")];

        let log = run_full_lifecycle(&mut gw, &hostcalls, &policy_checks, &telemetry_descs)
            .expect("full lifecycle");

        assert_eq!(log.final_lifecycle_phase, LifecyclePhase::Terminated);
        assert_eq!(log.hostcall_count, 2);
        assert_eq!(log.policy_check_count, 2);
        assert_eq!(log.lifecycle_transition_count, 4); // load, run, unload, terminate
        assert_eq!(log.telemetry_count, 2);
    }

    #[test]
    fn full_lifecycle_budget_exhaustion_mid_flight() {
        // Budget only enough for load + run transitions (2 * 3ms = 6ms) + 1 hostcall (1ms) = 7ms
        let mut gw = make_gateway(51, 8);
        gw.register_hostcall("op1", None);
        gw.register_hostcall("op2", None);
        gw.register_hostcall("op3", None);

        let hostcalls = vec![hostcall("op1"), hostcall("op2"), hostcall("op3")];
        let err = run_full_lifecycle(&mut gw, &hostcalls, &[], &[]).expect_err("budget");
        // Should fail during the third hostcall or later
        assert!(matches!(err, CxThreadingError::BudgetExhausted { .. }));
    }

    // -----------------------------------------------------------------------
    // Error type tests
    // -----------------------------------------------------------------------

    #[test]
    fn cx_threading_error_display() {
        let err = CxThreadingError::BudgetExhausted {
            operation: "test_op".to_string(),
            requested_ms: 10,
            remaining_ms: 5,
        };
        assert!(err.to_string().contains("budget exhausted"));
        assert!(err.to_string().contains("test_op"));

        let err = CxThreadingError::HostcallRejected {
            hostcall_name: "fs_write".to_string(),
            reason: "capability denied".to_string(),
        };
        assert!(err.to_string().contains("fs_write"));
        assert!(err.to_string().contains("capability denied"));
    }

    #[test]
    fn cx_threading_error_codes_are_stable() {
        let errors: Vec<CxThreadingError> = vec![
            CxThreadingError::BudgetExhausted {
                operation: "x".to_string(),
                requested_ms: 1,
                remaining_ms: 0,
            },
            CxThreadingError::HostcallRejected {
                hostcall_name: "x".to_string(),
                reason: "y".to_string(),
            },
            CxThreadingError::PolicyDenied {
                check_name: "x".to_string(),
                verdict: "y".to_string(),
            },
            CxThreadingError::LifecycleViolation {
                from: LifecyclePhase::Running,
                to: LifecyclePhase::Loaded,
                reason: "y".to_string(),
            },
            CxThreadingError::TelemetryFailed {
                emitter: "x".to_string(),
                reason: "y".to_string(),
            },
            CxThreadingError::Cancelled {
                operation: "x".to_string(),
            },
        ];
        let expected_codes = [
            "cx_budget_exhausted",
            "cx_hostcall_rejected",
            "cx_policy_denied",
            "cx_lifecycle_violation",
            "cx_telemetry_failed",
            "cx_cancelled",
        ];
        for (err, code) in errors.iter().zip(expected_codes.iter()) {
            assert_eq!(err.error_code(), *code);
        }
    }

    // -----------------------------------------------------------------------
    // Descriptor tests
    // -----------------------------------------------------------------------

    #[test]
    fn hostcall_descriptor_default_and_custom_budget() {
        let desc = HostcallDescriptor::new("fs_read", "ext-001");
        assert_eq!(desc.effective_budget_cost_ms(), HOSTCALL_BUDGET_COST_MS);

        let custom = desc.with_budget_cost(50);
        assert_eq!(custom.effective_budget_cost_ms(), 50);
    }

    #[test]
    fn policy_check_descriptor_construction() {
        let desc = PolicyCheckDescriptor::new("pre_call", "policy-001", "ext-scope");
        assert_eq!(desc.check_name, "pre_call");
        assert_eq!(desc.policy_id, "policy-001");
        assert_eq!(desc.scope, "ext-scope");
    }

    #[test]
    fn telemetry_descriptor_construction() {
        let desc = TelemetryDescriptor::new("emitter", "event", TelemetryLevel::Warn);
        assert_eq!(desc.emitter, "emitter");
        assert_eq!(desc.event_name, "event");
        assert_eq!(desc.level, TelemetryLevel::Warn);
    }

    // -----------------------------------------------------------------------
    // Policy verdict tests
    // -----------------------------------------------------------------------

    #[test]
    fn policy_verdict_display() {
        assert_eq!(PolicyVerdict::Allow.to_string(), "allow");
        assert_eq!(
            PolicyVerdict::Deny {
                reason: "rate limit".to_string()
            }
            .to_string(),
            "deny: rate limit"
        );
        assert_eq!(
            PolicyVerdict::Escalate {
                reason: "needs review".to_string()
            }
            .to_string(),
            "escalate: needs review"
        );
    }

    // -----------------------------------------------------------------------
    // Hostcall registration tests
    // -----------------------------------------------------------------------

    #[test]
    fn hostcall_registration_with_custom_cost() {
        let mut gw = make_gateway(60, 100);
        gw.register_hostcall("expensive_op", Some(25));
        let desc = hostcall("expensive_op");
        let receipt = gw.dispatch_hostcall(&desc).expect("dispatch");
        assert_eq!(receipt.budget_consumed_ms, 25);
    }

    // -----------------------------------------------------------------------
    // Mixed operation sequence tests
    // -----------------------------------------------------------------------

    #[test]
    fn interleaved_operations_track_correctly() {
        let mut gw = make_gateway(70, 500);
        gw.transition_lifecycle(LifecyclePhase::Loaded)
            .expect("load");
        gw.transition_lifecycle(LifecyclePhase::Running)
            .expect("run");

        gw.register_hostcall("op1", None);
        gw.register_hostcall("op2", None);
        gw.dispatch_hostcall(&hostcall("op1")).expect("hc1");
        gw.evaluate_policy_check(&policy_check("check1"), |_| PolicyVerdict::Allow)
            .expect("pc1");
        gw.emit_telemetry(&telemetry("metric1"), "data")
            .expect("tel1");
        gw.dispatch_hostcall(&hostcall("op2")).expect("hc2");

        assert_eq!(gw.hostcall_count(), 2);
        assert_eq!(gw.policy_check_count(), 1);
        assert_eq!(gw.lifecycle_transition_count(), 2);
        assert_eq!(gw.telemetry_count(), 1);
        assert_eq!(gw.events().len(), 6);
    }

    #[test]
    fn receipt_trace_ids_match_context() {
        let seed = 71;
        let mut gw = make_gateway(seed, 500);
        let tid = trace_id_from_seed(seed).to_string();

        gw.transition_lifecycle(LifecyclePhase::Loaded)
            .expect("load");
        gw.transition_lifecycle(LifecyclePhase::Running)
            .expect("run");

        gw.register_hostcall("op", None);
        let hc_receipt = gw.dispatch_hostcall(&hostcall("op")).expect("hc");
        assert_eq!(hc_receipt.trace_id, tid);

        let pc_result = gw
            .evaluate_policy_check(&policy_check("chk"), |_| PolicyVerdict::Allow)
            .expect("pc");
        assert_eq!(pc_result.trace_id, tid);

        let tel_receipt = gw.emit_telemetry(&telemetry("evt"), "data").expect("tel");
        assert_eq!(tel_receipt.trace_id, tid);
    }

    // -----------------------------------------------------------------------
    // Serde round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn cx_threaded_event_serde_round_trip() {
        let event = CxThreadedEvent {
            trace_id: "trace-001".to_string(),
            category: EffectCategory::Hostcall,
            component: "cx_threading".to_string(),
            operation: "fs_read".to_string(),
            outcome: "dispatched".to_string(),
            budget_consumed_ms: 1,
            budget_remaining_ms: 99,
            error_code: None,
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let deser: CxThreadedEvent = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(event, deser);
    }

    #[test]
    fn hostcall_receipt_serde_round_trip() {
        let receipt = HostcallReceipt {
            hostcall_name: "kv_get".to_string(),
            extension_id: "ext-001".to_string(),
            trace_id: "trace-001".to_string(),
            budget_consumed_ms: 1,
            sequence_number: 5,
        };
        let json = serde_json::to_string(&receipt).expect("serde deserialization should succeed");
        let deser: HostcallReceipt = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(receipt, deser);
    }

    #[test]
    fn lifecycle_receipt_serde_round_trip() {
        let receipt = LifecycleReceipt {
            from: LifecyclePhase::Running,
            to: LifecyclePhase::Suspended,
            trace_id: "trace-002".to_string(),
            budget_consumed_ms: 3,
            sequence_number: 2,
        };
        let json = serde_json::to_string(&receipt).expect("serde deserialization should succeed");
        let deser: LifecycleReceipt = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(receipt, deser);
    }

    #[test]
    fn effect_audit_log_serde_round_trip() {
        let log = EffectAuditLog {
            trace_id: "trace-003".to_string(),
            total_events: 3,
            hostcall_count: 1,
            policy_check_count: 1,
            lifecycle_transition_count: 1,
            telemetry_count: 0,
            total_budget_consumed_ms: 6,
            final_lifecycle_phase: LifecyclePhase::Running,
            events: vec![],
        };
        let json = serde_json::to_string(&log).expect("serde deserialization should succeed");
        let deser: EffectAuditLog = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(log, deser);
    }

    #[test]
    fn cx_threading_error_serde_round_trip() {
        let errors = vec![
            CxThreadingError::BudgetExhausted {
                operation: "op".to_string(),
                requested_ms: 5,
                remaining_ms: 2,
            },
            CxThreadingError::HostcallRejected {
                hostcall_name: "hc".to_string(),
                reason: "disabled".to_string(),
            },
            CxThreadingError::PolicyDenied {
                check_name: "chk".to_string(),
                verdict: "deny".to_string(),
            },
            CxThreadingError::LifecycleViolation {
                from: LifecyclePhase::Loaded,
                to: LifecyclePhase::Terminated,
                reason: "invalid".to_string(),
            },
            CxThreadingError::TelemetryFailed {
                emitter: "em".to_string(),
                reason: "sink full".to_string(),
            },
            CxThreadingError::Cancelled {
                operation: "op".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serde deserialization should succeed");
            let deser: CxThreadingError = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*err, deser);
        }
    }

    // -----------------------------------------------------------------------
    // Edge case: empty lifecycle run
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle_with_no_operations() {
        let mut gw = make_gateway(80, 500);
        let log = run_full_lifecycle(&mut gw, &[], &[], &[]).expect("empty lifecycle");
        assert_eq!(log.hostcall_count, 0);
        assert_eq!(log.policy_check_count, 0);
        assert_eq!(log.telemetry_count, 0);
        assert_eq!(log.lifecycle_transition_count, 4);
        assert_eq!(log.final_lifecycle_phase, LifecyclePhase::Terminated);
    }

    // -----------------------------------------------------------------------
    // Budget accounting precision test
    // -----------------------------------------------------------------------

    #[test]
    fn budget_accounting_is_precise() {
        // 4 lifecycle transitions × 3ms = 12ms
        // 3 hostcalls × 1ms = 3ms
        // 2 policy checks × 2ms = 4ms
        // 1 telemetry × 1ms = 1ms
        // Total = 20ms
        let mut gw = make_gateway(90, 20);

        gw.transition_lifecycle(LifecyclePhase::Loaded)
            .expect("load");
        gw.transition_lifecycle(LifecyclePhase::Running)
            .expect("run");
        for i in 0..3 {
            let name = format!("op_{i}");
            gw.register_hostcall(&name, None);
            gw.dispatch_hostcall(&hostcall(&name)).expect("hc");
        }
        for i in 0..2 {
            gw.evaluate_policy_check(&policy_check(&format!("chk_{i}")), |_| PolicyVerdict::Allow)
                .expect("pc");
        }
        gw.emit_telemetry(&telemetry("metric"), "data")
            .expect("tel");
        gw.transition_lifecycle(LifecyclePhase::Unloading)
            .expect("unload");
        gw.transition_lifecycle(LifecyclePhase::Terminated)
            .expect("term");

        assert_eq!(gw.cx().budget().remaining_ms(), 0);
        assert_eq!(gw.lifecycle_transition_count(), 4);
        assert_eq!(gw.hostcall_count(), 3);
        assert_eq!(gw.policy_check_count(), 2);
        assert_eq!(gw.telemetry_count(), 1);
    }

    #[test]
    fn cx_threading_error_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(CxThreadingError::BudgetExhausted {
                operation: "op".into(),
                requested_ms: 10,
                remaining_ms: 0,
            }),
            Box::new(CxThreadingError::HostcallRejected {
                hostcall_name: "fs_read".into(),
                reason: "denied".into(),
            }),
            Box::new(CxThreadingError::PolicyDenied {
                check_name: "ifc".into(),
                verdict: "no".into(),
            }),
            Box::new(CxThreadingError::LifecycleViolation {
                from: LifecyclePhase::Unloaded,
                to: LifecyclePhase::Running,
                reason: "skip".into(),
            }),
            Box::new(CxThreadingError::TelemetryFailed {
                emitter: "span".into(),
                reason: "full".into(),
            }),
            Box::new(CxThreadingError::Cancelled {
                operation: "gc".into(),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(format!("{v}"));
        }
        assert_eq!(displays.len(), 6);
    }

    #[test]
    fn effect_category_ord() {
        assert!(EffectCategory::Hostcall < EffectCategory::PolicyCheck);
        assert!(EffectCategory::PolicyCheck < EffectCategory::LifecycleTransition);
        assert!(EffectCategory::LifecycleTransition < EffectCategory::TelemetryEmit);
    }

    #[test]
    fn lifecycle_phase_ord() {
        assert!(LifecyclePhase::Unloaded < LifecyclePhase::Loaded);
        assert!(LifecyclePhase::Loaded < LifecyclePhase::Running);
        assert!(LifecyclePhase::Running < LifecyclePhase::Suspended);
        assert!(LifecyclePhase::Quarantined < LifecyclePhase::Unloading);
    }

    #[test]
    fn telemetry_level_ord() {
        assert!(TelemetryLevel::Debug < TelemetryLevel::Info);
        assert!(TelemetryLevel::Info < TelemetryLevel::Warn);
        assert!(TelemetryLevel::Warn < TelemetryLevel::Error);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn effect_category_serde_roundtrip_all_variants() {
        let variants = [
            EffectCategory::Hostcall,
            EffectCategory::PolicyCheck,
            EffectCategory::LifecycleTransition,
            EffectCategory::TelemetryEmit,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde deserialization should succeed");
            let back: EffectCategory = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn lifecycle_phase_serde_roundtrip_all_variants() {
        let variants = [
            LifecyclePhase::Unloaded,
            LifecyclePhase::Loaded,
            LifecyclePhase::Running,
            LifecyclePhase::Suspended,
            LifecyclePhase::Quarantined,
            LifecyclePhase::Unloading,
            LifecyclePhase::Terminated,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde deserialization should succeed");
            let back: LifecyclePhase = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn telemetry_level_serde_roundtrip_all_variants() {
        let variants = [
            TelemetryLevel::Debug,
            TelemetryLevel::Info,
            TelemetryLevel::Warn,
            TelemetryLevel::Error,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde deserialization should succeed");
            let back: TelemetryLevel = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn policy_verdict_serde_roundtrip_all_variants() {
        let variants = vec![
            PolicyVerdict::Allow,
            PolicyVerdict::Deny {
                reason: "blocked".into(),
            },
            PolicyVerdict::Escalate {
                reason: "review".into(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde deserialization should succeed");
            let back: PolicyVerdict = serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn lifecycle_phase_as_str_all_distinct() {
        let variants = [
            LifecyclePhase::Unloaded,
            LifecyclePhase::Loaded,
            LifecyclePhase::Running,
            LifecyclePhase::Suspended,
            LifecyclePhase::Quarantined,
            LifecyclePhase::Unloading,
            LifecyclePhase::Terminated,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn telemetry_level_as_str_all_distinct() {
        let variants = [
            TelemetryLevel::Debug,
            TelemetryLevel::Info,
            TelemetryLevel::Warn,
            TelemetryLevel::Error,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn policy_check_result_serde_roundtrip() {
        let result = PolicyCheckResult {
            check_name: "pre_hostcall".into(),
            policy_id: "pol-1".into(),
            verdict: PolicyVerdict::Allow,
            trace_id: "t-1".into(),
            budget_consumed_ms: 5,
            sequence_number: 1,
        };
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let back: PolicyCheckResult = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, back);
    }

    #[test]
    fn telemetry_receipt_serde_roundtrip() {
        let receipt = TelemetryReceipt {
            emitter: "span".into(),
            event_name: "metric".into(),
            level: TelemetryLevel::Info,
            payload_len: 42,
            trace_id: "t-2".into(),
            budget_consumed_ms: 1,
            sequence_number: 3,
        };
        let json = serde_json::to_string(&receipt).expect("serde deserialization should succeed");
        let back: TelemetryReceipt = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(receipt, back);
    }

    #[test]
    fn hostcall_descriptor_serde_roundtrip() {
        let desc = HostcallDescriptor {
            name: "fs_read".into(),
            extension_id: "ext-1".into(),
            budget_cost_override_ms: Some(10),
        };
        let json = serde_json::to_string(&desc).expect("serde deserialization should succeed");
        let back: HostcallDescriptor = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(desc, back);
    }

    #[test]
    fn policy_check_descriptor_serde_roundtrip() {
        let desc = PolicyCheckDescriptor::new("pre_hostcall", "pol-1", "ext-1");
        let json = serde_json::to_string(&desc).expect("serde deserialization should succeed");
        let back: PolicyCheckDescriptor = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(desc, back);
    }

    #[test]
    fn telemetry_descriptor_serde_roundtrip() {
        let desc = TelemetryDescriptor::new("span", "metric_emit", TelemetryLevel::Warn);
        let json = serde_json::to_string(&desc).expect("serde deserialization should succeed");
        let back: TelemetryDescriptor = serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(desc, back);
    }
}
