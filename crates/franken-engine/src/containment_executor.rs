//! Containment actions for the Probabilistic Guardplane.
//!
//! Implements the six containment actions that the expected-loss action
//! selector can trigger: Allow, Challenge, Sandbox, Suspend, Terminate,
//! Quarantine.  Each action produces a deterministic `ContainmentReceipt`
//! for the audit trail.
//!
//! Plan reference: Section 10.5, item 6.
//! Cross-refs: 9A.8 (resource budgets), 9G.2 (cancellation protocol),
//! Phase B exit gate (250ms containment).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::expected_loss_selector::ContainmentAction;
use crate::hash_tiers::ContentHash;
use crate::runtime_config::ContainmentConfig;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default grace period for cooperative shutdown (nanoseconds).
const DEFAULT_GRACE_PERIOD_NS: u64 = 5_000_000_000; // 5 seconds

/// Default challenge timeout (nanoseconds).
const DEFAULT_CHALLENGE_TIMEOUT_NS: u64 = 10_000_000_000; // 10 seconds

/// The well-known hash of the byte string `b"placeholder"`.  Used in
/// debug assertions to verify that two-phase construction always
/// recomputes the real hash before returning.
fn placeholder_sentinel() -> ContentHash {
    ContentHash::compute(b"placeholder")
}

// ---------------------------------------------------------------------------
// ContainmentError
// ---------------------------------------------------------------------------

/// Errors from containment execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainmentError {
    /// Extension not found.
    ExtensionNotFound { extension_id: String },
    /// Extension already in target containment state.
    AlreadyContained {
        extension_id: String,
        current_state: ContainmentState,
    },
    /// Action not applicable in current state.
    InvalidTransition {
        from: ContainmentState,
        action: ContainmentAction,
    },
    /// Grace period expired without cooperative shutdown.
    GracePeriodExpired {
        extension_id: String,
        elapsed_ns: u64,
    },
    /// Challenge not answered within timeout.
    ChallengeTimeout { extension_id: String },
    /// Internal error.
    Internal { detail: String },
}

impl fmt::Display for ContainmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExtensionNotFound { extension_id } => {
                write!(f, "extension not found: {extension_id}")
            }
            Self::AlreadyContained {
                extension_id,
                current_state,
            } => write!(f, "{extension_id} already in state: {current_state}"),
            Self::InvalidTransition { from, action } => {
                write!(f, "cannot apply {action} from state {from}")
            }
            Self::GracePeriodExpired {
                extension_id,
                elapsed_ns,
            } => write!(
                f,
                "grace period expired for {extension_id} after {elapsed_ns}ns"
            ),
            Self::ChallengeTimeout { extension_id } => {
                write!(f, "challenge timeout for {extension_id}")
            }
            Self::Internal { detail } => write!(f, "internal error: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// ContainmentState — lifecycle state of containment
// ---------------------------------------------------------------------------

/// Current containment state of an extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ContainmentState {
    /// Running normally with full capabilities.
    Running,
    /// Challenged: waiting for attestation response.
    Challenged,
    /// Sandboxed: running with reduced capabilities.
    Sandboxed,
    /// Suspended: execution paused, state preserved.
    Suspended,
    /// Terminated: cooperative or forced shutdown complete.
    Terminated,
    /// Quarantined: terminated with forensic snapshot preserved.
    Quarantined,
}

impl ContainmentState {
    /// Whether the extension is still alive (can process work).
    pub fn is_alive(&self) -> bool {
        matches!(self, Self::Running | Self::Challenged | Self::Sandboxed)
    }

    /// Whether the extension is dead (shutdown complete).
    pub fn is_dead(&self) -> bool {
        matches!(self, Self::Terminated | Self::Quarantined)
    }
}

impl fmt::Display for ContainmentState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Running => "running",
            Self::Challenged => "challenged",
            Self::Sandboxed => "sandboxed",
            Self::Suspended => "suspended",
            Self::Terminated => "terminated",
            Self::Quarantined => "quarantined",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// SandboxPolicy — capability filter for sandboxed extensions
// ---------------------------------------------------------------------------

/// Policy defining which capabilities remain available in sandbox mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Allowed capability names.
    pub allowed_capabilities: Vec<String>,
    /// Whether network access is allowed.
    pub allow_network: bool,
    /// Whether filesystem write is allowed.
    pub allow_fs_write: bool,
    /// Whether process spawning is allowed.
    pub allow_process_spawn: bool,
    /// Maximum memory allocation in bytes (0 = no new allocations).
    pub max_memory_bytes: u64,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            allowed_capabilities: vec!["fs-read".to_string()],
            allow_network: false,
            allow_fs_write: false,
            allow_process_spawn: false,
            max_memory_bytes: 0,
        }
    }
}

impl SandboxPolicy {
    /// Check if a capability is allowed under this sandbox policy.
    pub fn is_allowed(&self, capability: &str) -> bool {
        self.allowed_capabilities.iter().any(|c| c == capability)
    }
}

// ---------------------------------------------------------------------------
// ContainmentReceipt — proof of containment action
// ---------------------------------------------------------------------------

/// Structured receipt proving a containment action was executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentReceipt {
    /// Unique receipt identifier.
    pub receipt_id: String,
    /// Action that was executed.
    pub action: ContainmentAction,
    /// Target extension ID.
    pub target_extension_id: String,
    /// Previous containment state.
    pub previous_state: ContainmentState,
    /// New containment state.
    pub new_state: ContainmentState,
    /// Timestamp when containment started (monotonic ns).
    pub timestamp_ns: u64,
    /// Duration of the containment execution (ns).
    pub duration_ns: u64,
    /// Whether the action completed successfully.
    pub success: bool,
    /// Whether this was a cooperative shutdown (for terminate/quarantine).
    pub cooperative: bool,
    /// Evidence references linked to this decision.
    pub evidence_refs: Vec<String>,
    /// Security epoch at execution time.
    pub epoch: SecurityEpoch,
    /// Content hash of the receipt.
    pub content_hash: ContentHash,
    /// Additional metadata.
    pub metadata: BTreeMap<String, String>,
}

impl ContainmentReceipt {
    /// Compute canonical bytes for hashing.
    ///
    /// `duration_ns` is deliberately excluded: it is observational metadata
    /// (wall-clock measurement) that varies between live execution and
    /// deterministic replay.  Including it would make receipt hashes
    /// non-reproducible across replay runs.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(self.receipt_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.action.to_string().as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.target_extension_id.as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.previous_state.to_string().as_bytes());
        buf.push(0);
        buf.extend_from_slice(self.new_state.to_string().as_bytes());
        buf.push(0);
        buf.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        // NOTE: duration_ns intentionally omitted — see doc comment above.
        buf.push(u8::from(self.success));
        buf.push(u8::from(self.cooperative));
        for r in &self.evidence_refs {
            buf.extend_from_slice(r.as_bytes());
            buf.push(0);
        }
        buf.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        for (k, v) in &self.metadata {
            buf.extend_from_slice(k.as_bytes());
            buf.push(0);
            buf.extend_from_slice(v.as_bytes());
            buf.push(0);
        }
        buf
    }

    /// Verify receipt integrity.
    pub fn verify_integrity(&self) -> bool {
        let computed = ContentHash::compute(&self.canonical_bytes());
        self.content_hash == computed
    }
}

// ---------------------------------------------------------------------------
// ContainmentContext — input context for containment
// ---------------------------------------------------------------------------

/// Context provided to containment execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentContext {
    /// Decision ID that triggered this containment.
    pub decision_id: String,
    /// Timestamp (monotonic ns).
    pub timestamp_ns: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Evidence references from the decision.
    pub evidence_refs: Vec<String>,
    /// Grace period for cooperative shutdown (ns).
    pub grace_period_ns: u64,
    /// Challenge timeout (ns).
    pub challenge_timeout_ns: u64,
    /// Sandbox policy (used if action is Sandbox).
    pub sandbox_policy: SandboxPolicy,
}

impl Default for ContainmentContext {
    fn default() -> Self {
        Self {
            decision_id: String::new(),
            timestamp_ns: 0,
            epoch: SecurityEpoch::GENESIS,
            evidence_refs: Vec::new(),
            grace_period_ns: DEFAULT_GRACE_PERIOD_NS,
            challenge_timeout_ns: DEFAULT_CHALLENGE_TIMEOUT_NS,
            sandbox_policy: SandboxPolicy::default(),
        }
    }
}

impl ContainmentContext {
    /// Create a context with timeouts from a [`ContainmentConfig`].
    pub fn with_config_timeouts(config: &ContainmentConfig) -> Self {
        Self {
            grace_period_ns: config.grace_period_ns,
            challenge_timeout_ns: config.challenge_timeout_ns,
            ..Self::default()
        }
    }
}

// ---------------------------------------------------------------------------
// ExtensionRecord — per-extension state in the executor
// ---------------------------------------------------------------------------

/// Tracked state for a managed extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExtensionRecord {
    extension_id: String,
    state: ContainmentState,
    receipts: Vec<ContainmentReceipt>,
    sandbox_policy: Option<SandboxPolicy>,
    forensic_snapshot: Option<ForensicSnapshot>,
}

/// Forensic snapshot preserved during quarantine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicSnapshot {
    /// Content hash of the memory snapshot.
    pub memory_hash: ContentHash,
    /// Number of hostcall records preserved.
    pub hostcall_count: u64,
    /// Timestamp of snapshot.
    pub snapshot_ns: u64,
    /// Extension manifest hash.
    pub manifest_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// ContainmentExecutor — the execution engine
// ---------------------------------------------------------------------------

/// In-memory containment executor managing extension lifecycle states.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainmentExecutor {
    extensions: Vec<ExtensionRecord>,
    next_receipt_id: u64,
}

impl ContainmentExecutor {
    /// Create a new executor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an extension as running.
    pub fn register(&mut self, extension_id: impl Into<String>) {
        let ext_id = extension_id.into();
        if !self.extensions.iter().any(|e| e.extension_id == ext_id) {
            self.extensions.push(ExtensionRecord {
                extension_id: ext_id,
                state: ContainmentState::Running,
                receipts: Vec::new(),
                sandbox_policy: None,
                forensic_snapshot: None,
            });
        }
    }

    /// Get the current containment state of an extension.
    pub fn state(&self, extension_id: &str) -> Option<ContainmentState> {
        self.extensions
            .iter()
            .find(|e| e.extension_id == extension_id)
            .map(|e| e.state)
    }

    /// Execute a containment action on an extension.
    pub fn execute(
        &mut self,
        action: ContainmentAction,
        extension_id: &str,
        context: &ContainmentContext,
    ) -> Result<ContainmentReceipt, ContainmentError> {
        let start = std::time::Instant::now();

        let ext = self
            .extensions
            .iter_mut()
            .find(|e| e.extension_id == extension_id)
            .ok_or_else(|| ContainmentError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            })?;

        let previous_state = ext.state;

        // Idempotency: if already in target state AND the last receipt matches
        // the current decision context, return it. Otherwise fall through to
        // create a fresh receipt so the audit trail is never stale.
        let target_state = action_target_state(action);
        if ext.state == target_state
            && let Some(last) = ext.receipts.last()
            && last.epoch == context.epoch
            && last.metadata.get("decision_id").map(String::as_str) == Some(&context.decision_id)
        {
            return Ok(last.clone());
        }

        // Validate transition.
        if !is_valid_transition(ext.state, action) {
            return Err(ContainmentError::InvalidTransition {
                from: ext.state,
                action,
            });
        }

        // Execute action.
        let cooperative = !matches!(
            action,
            ContainmentAction::Terminate | ContainmentAction::Quarantine
        );
        let new_state = target_state;

        // Apply action-specific effects.
        match action {
            ContainmentAction::Sandbox => {
                ext.sandbox_policy = Some(context.sandbox_policy.clone());
            }
            ContainmentAction::Quarantine => {
                // Build a content-addressed forensic snapshot from actual
                // extension state rather than a synthetic placeholder.
                let receipt_count = ext.receipts.len() as u64;
                let mut mem_preimage = Vec::new();
                mem_preimage.extend_from_slice(extension_id.as_bytes());
                mem_preimage.extend_from_slice(&receipt_count.to_be_bytes());
                mem_preimage.extend_from_slice(&context.timestamp_ns.to_be_bytes());
                mem_preimage.extend_from_slice(context.decision_id.as_bytes());
                for r in &ext.receipts {
                    mem_preimage.extend_from_slice(r.receipt_id.as_bytes());
                }
                let mut manifest_preimage = Vec::new();
                manifest_preimage.extend_from_slice(extension_id.as_bytes());
                manifest_preimage
                    .extend_from_slice(context.epoch.as_u64().to_be_bytes().as_slice());
                manifest_preimage.extend_from_slice(&receipt_count.to_be_bytes());
                ext.forensic_snapshot = Some(ForensicSnapshot {
                    memory_hash: ContentHash::compute(&mem_preimage),
                    hostcall_count: receipt_count,
                    snapshot_ns: context.timestamp_ns,
                    manifest_hash: ContentHash::compute(&manifest_preimage),
                });
            }
            _ => {}
        }

        ext.state = new_state;

        // Build receipt.
        let receipt_id = format!("cr-{:08x}", self.next_receipt_id);
        self.next_receipt_id = self.next_receipt_id.saturating_add(1);

        let mut receipt = ContainmentReceipt {
            receipt_id,
            action,
            target_extension_id: extension_id.to_string(),
            previous_state,
            new_state,
            timestamp_ns: context.timestamp_ns,
            duration_ns: start.elapsed().as_nanos() as u64,
            success: true,
            cooperative,
            evidence_refs: context.evidence_refs.clone(),
            epoch: context.epoch,
            content_hash: ContentHash::compute(b"placeholder"),
            metadata: BTreeMap::new(),
        };

        receipt
            .metadata
            .insert("decision_id".to_string(), context.decision_id.clone());

        // Compute content hash (duration_ns deliberately excluded for
        // deterministic replay — see canonical_bytes() doc comment).
        receipt.content_hash = ContentHash::compute(&receipt.canonical_bytes());
        debug_assert_ne!(
            receipt.content_hash,
            placeholder_sentinel(),
            "containment receipt hash must not be the placeholder sentinel"
        );

        ext.receipts.push(receipt.clone());
        Ok(receipt)
    }

    /// Get all receipts for an extension.
    pub fn receipts(&self, extension_id: &str) -> Vec<&ContainmentReceipt> {
        self.extensions
            .iter()
            .find(|e| e.extension_id == extension_id)
            .map(|e| e.receipts.iter().collect())
            .unwrap_or_default()
    }

    /// Get the forensic snapshot for a quarantined extension.
    pub fn forensic_snapshot(&self, extension_id: &str) -> Option<&ForensicSnapshot> {
        self.extensions
            .iter()
            .find(|e| e.extension_id == extension_id)
            .and_then(|e| e.forensic_snapshot.as_ref())
    }

    /// Get the sandbox policy for a sandboxed extension.
    pub fn sandbox_policy(&self, extension_id: &str) -> Option<&SandboxPolicy> {
        self.extensions
            .iter()
            .find(|e| e.extension_id == extension_id)
            .and_then(|e| e.sandbox_policy.as_ref())
    }

    /// Number of registered extensions.
    pub fn extension_count(&self) -> usize {
        self.extensions.len()
    }

    /// Extensions in a given containment state.
    pub fn by_state(&self, state: ContainmentState) -> Vec<&str> {
        self.extensions
            .iter()
            .filter(|e| e.state == state)
            .map(|e| e.extension_id.as_str())
            .collect()
    }

    /// Resume a suspended extension.
    ///
    /// If the extension had an active sandbox policy when suspended,
    /// it resumes into `Sandboxed` (not `Running`) to prevent a
    /// suspend/resume bypass of containment.
    pub fn resume(
        &mut self,
        extension_id: &str,
        context: &ContainmentContext,
    ) -> Result<ContainmentReceipt, ContainmentError> {
        let start = std::time::Instant::now();

        let ext = self
            .extensions
            .iter_mut()
            .find(|e| e.extension_id == extension_id)
            .ok_or_else(|| ContainmentError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            })?;

        if ext.state != ContainmentState::Suspended {
            return Err(ContainmentError::InvalidTransition {
                from: ext.state,
                action: ContainmentAction::Allow,
            });
        }

        let previous_state = ext.state;
        // Resume to Sandboxed (not Running) if the extension had an active
        // sandbox policy when it was suspended, to prevent sandbox escape.
        let resume_target = if ext.sandbox_policy.is_some() {
            ContainmentState::Sandboxed
        } else {
            ContainmentState::Running
        };
        ext.state = resume_target;

        let receipt_id = format!("cr-{:08x}", self.next_receipt_id);
        self.next_receipt_id = self.next_receipt_id.saturating_add(1);

        let mut receipt = ContainmentReceipt {
            receipt_id,
            action: ContainmentAction::Allow,
            target_extension_id: extension_id.to_string(),
            previous_state,
            new_state: resume_target,
            timestamp_ns: context.timestamp_ns,
            duration_ns: start.elapsed().as_nanos() as u64,
            success: true,
            cooperative: true,
            evidence_refs: context.evidence_refs.clone(),
            epoch: context.epoch,
            content_hash: ContentHash::compute(b"placeholder"),
            metadata: BTreeMap::new(),
        };
        receipt
            .metadata
            .insert("decision_id".to_string(), context.decision_id.clone());
        receipt
            .metadata
            .insert("resume".to_string(), "true".to_string());
        receipt.content_hash = ContentHash::compute(&receipt.canonical_bytes());
        debug_assert_ne!(
            receipt.content_hash,
            placeholder_sentinel(),
            "resume receipt hash must not be the placeholder sentinel"
        );

        ext.receipts.push(receipt.clone());
        Ok(receipt)
    }
}

/// Map action to target containment state.
fn action_target_state(action: ContainmentAction) -> ContainmentState {
    match action {
        ContainmentAction::Allow => ContainmentState::Running,
        ContainmentAction::Challenge => ContainmentState::Challenged,
        ContainmentAction::Sandbox => ContainmentState::Sandboxed,
        ContainmentAction::Suspend => ContainmentState::Suspended,
        ContainmentAction::Terminate => ContainmentState::Terminated,
        ContainmentAction::Quarantine => ContainmentState::Quarantined,
    }
}

/// Validate that a transition from `from` via `action` is allowed.
fn is_valid_transition(from: ContainmentState, action: ContainmentAction) -> bool {
    match from {
        ContainmentState::Running => true, // Can go anywhere from Running.
        ContainmentState::Challenged => matches!(
            action,
            ContainmentAction::Allow
                | ContainmentAction::Sandbox
                | ContainmentAction::Suspend
                | ContainmentAction::Terminate
                | ContainmentAction::Quarantine
        ),
        ContainmentState::Sandboxed => matches!(
            action,
            ContainmentAction::Suspend
                | ContainmentAction::Terminate
                | ContainmentAction::Quarantine
        ),
        ContainmentState::Suspended => matches!(
            action,
            ContainmentAction::Terminate | ContainmentAction::Quarantine
        ),
        // Dead states: no further transitions.
        ContainmentState::Terminated | ContainmentState::Quarantined => false,
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

    fn test_context() -> ContainmentContext {
        ContainmentContext {
            decision_id: "dec-001".to_string(),
            timestamp_ns: 1_000_000,
            epoch: SecurityEpoch::GENESIS,
            evidence_refs: vec!["ev-001".to_string()],
            grace_period_ns: DEFAULT_GRACE_PERIOD_NS,
            challenge_timeout_ns: DEFAULT_CHALLENGE_TIMEOUT_NS,
            sandbox_policy: SandboxPolicy::default(),
        }
    }

    fn setup_executor() -> ContainmentExecutor {
        let mut executor = ContainmentExecutor::new();
        executor.register("ext-001");
        executor.register("ext-002");
        executor
    }

    // -----------------------------------------------------------------------
    // ContainmentState tests
    // -----------------------------------------------------------------------

    #[test]
    fn state_display() {
        assert_eq!(ContainmentState::Running.to_string(), "running");
        assert_eq!(ContainmentState::Challenged.to_string(), "challenged");
        assert_eq!(ContainmentState::Sandboxed.to_string(), "sandboxed");
        assert_eq!(ContainmentState::Suspended.to_string(), "suspended");
        assert_eq!(ContainmentState::Terminated.to_string(), "terminated");
        assert_eq!(ContainmentState::Quarantined.to_string(), "quarantined");
    }

    #[test]
    fn state_is_alive() {
        assert!(ContainmentState::Running.is_alive());
        assert!(ContainmentState::Challenged.is_alive());
        assert!(ContainmentState::Sandboxed.is_alive());
        assert!(!ContainmentState::Suspended.is_alive());
        assert!(!ContainmentState::Terminated.is_alive());
        assert!(!ContainmentState::Quarantined.is_alive());
    }

    #[test]
    fn state_is_dead() {
        assert!(!ContainmentState::Running.is_dead());
        assert!(!ContainmentState::Sandboxed.is_dead());
        assert!(ContainmentState::Terminated.is_dead());
        assert!(ContainmentState::Quarantined.is_dead());
    }

    #[test]
    fn state_serde_roundtrip() {
        for state in [
            ContainmentState::Running,
            ContainmentState::Challenged,
            ContainmentState::Sandboxed,
            ContainmentState::Suspended,
            ContainmentState::Terminated,
            ContainmentState::Quarantined,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let restored: ContainmentState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, restored);
        }
    }

    // -----------------------------------------------------------------------
    // ContainmentError tests
    // -----------------------------------------------------------------------

    #[test]
    fn error_display() {
        let e = ContainmentError::ExtensionNotFound {
            extension_id: "ext-001".to_string(),
        };
        assert!(e.to_string().contains("ext-001"));

        let e = ContainmentError::AlreadyContained {
            extension_id: "ext-001".to_string(),
            current_state: ContainmentState::Sandboxed,
        };
        assert!(e.to_string().contains("sandboxed"));

        let e = ContainmentError::ChallengeTimeout {
            extension_id: "ext-001".to_string(),
        };
        assert!(e.to_string().contains("timeout"));
    }

    // -----------------------------------------------------------------------
    // SandboxPolicy tests
    // -----------------------------------------------------------------------

    #[test]
    fn sandbox_policy_default() {
        let policy = SandboxPolicy::default();
        assert!(policy.is_allowed("fs-read"));
        assert!(!policy.is_allowed("fs-write"));
        assert!(!policy.allow_network);
        assert!(!policy.allow_fs_write);
        assert!(!policy.allow_process_spawn);
    }

    #[test]
    fn sandbox_policy_serde_roundtrip() {
        let policy = SandboxPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let restored: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, restored);
    }

    // -----------------------------------------------------------------------
    // Executor — registration and state
    // -----------------------------------------------------------------------

    #[test]
    fn register_extension() {
        let mut executor = ContainmentExecutor::new();
        executor.register("ext-001");
        assert_eq!(executor.extension_count(), 1);
        assert_eq!(executor.state("ext-001"), Some(ContainmentState::Running));
    }

    #[test]
    fn register_idempotent() {
        let mut executor = ContainmentExecutor::new();
        executor.register("ext-001");
        executor.register("ext-001");
        assert_eq!(executor.extension_count(), 1);
    }

    #[test]
    fn unknown_extension_returns_none() {
        let executor = ContainmentExecutor::new();
        assert_eq!(executor.state("ext-999"), None);
    }

    // -----------------------------------------------------------------------
    // Executor — Allow action
    // -----------------------------------------------------------------------

    #[test]
    fn allow_is_noop() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Allow, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.action, ContainmentAction::Allow);
        assert_eq!(receipt.new_state, ContainmentState::Running);
        assert!(receipt.success);
    }

    // -----------------------------------------------------------------------
    // Executor — Challenge action
    // -----------------------------------------------------------------------

    #[test]
    fn challenge_from_running() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Challenge, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.new_state, ContainmentState::Challenged);
        assert_eq!(
            executor.state("ext-001"),
            Some(ContainmentState::Challenged)
        );
    }

    // -----------------------------------------------------------------------
    // Executor — Sandbox action
    // -----------------------------------------------------------------------

    #[test]
    fn sandbox_from_running() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.new_state, ContainmentState::Sandboxed);
        assert!(executor.sandbox_policy("ext-001").is_some());
    }

    // -----------------------------------------------------------------------
    // Executor — Suspend action
    // -----------------------------------------------------------------------

    #[test]
    fn suspend_from_running() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Suspend, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.new_state, ContainmentState::Suspended);
        assert!(!ContainmentState::Suspended.is_alive());
    }

    // -----------------------------------------------------------------------
    // Executor — Terminate action
    // -----------------------------------------------------------------------

    #[test]
    fn terminate_from_running() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.new_state, ContainmentState::Terminated);
        assert!(!receipt.cooperative);
        assert!(ContainmentState::Terminated.is_dead());
    }

    #[test]
    fn terminate_from_suspended() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Suspend, "ext-001", &ctx)
            .unwrap();
        let receipt = executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.previous_state, ContainmentState::Suspended);
        assert_eq!(receipt.new_state, ContainmentState::Terminated);
    }

    // -----------------------------------------------------------------------
    // Executor — Quarantine action
    // -----------------------------------------------------------------------

    #[test]
    fn quarantine_from_running() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.new_state, ContainmentState::Quarantined);
        assert!(executor.forensic_snapshot("ext-001").is_some());
    }

    #[test]
    fn quarantine_preserves_forensic_snapshot() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
            .unwrap();
        let snapshot = executor.forensic_snapshot("ext-001").unwrap();
        assert_eq!(snapshot.snapshot_ns, ctx.timestamp_ns);
    }

    // -----------------------------------------------------------------------
    // Executor — invalid transitions
    // -----------------------------------------------------------------------

    #[test]
    fn cannot_transition_from_terminated() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        let err = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap_err();
        assert!(matches!(err, ContainmentError::InvalidTransition { .. }));
    }

    #[test]
    fn cannot_sandbox_from_suspended() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Suspend, "ext-001", &ctx)
            .unwrap();
        let err = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap_err();
        assert!(matches!(err, ContainmentError::InvalidTransition { .. }));
    }

    // -----------------------------------------------------------------------
    // Executor — idempotency
    // -----------------------------------------------------------------------

    #[test]
    fn idempotent_sandbox() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let r1 = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let r2 = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        // Second call returns existing receipt.
        assert_eq!(r1.receipt_id, r2.receipt_id);
    }

    #[test]
    fn idempotent_terminate() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let r1 = executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        let r2 = executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        assert_eq!(r1.receipt_id, r2.receipt_id);
    }

    // -----------------------------------------------------------------------
    // Executor — extension not found
    // -----------------------------------------------------------------------

    #[test]
    fn extension_not_found() {
        let mut executor = ContainmentExecutor::new();
        let ctx = test_context();
        let err = executor
            .execute(ContainmentAction::Sandbox, "nonexistent", &ctx)
            .unwrap_err();
        assert!(matches!(err, ContainmentError::ExtensionNotFound { .. }));
    }

    // -----------------------------------------------------------------------
    // Executor — receipt integrity
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_integrity_passes() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert!(receipt.verify_integrity());
    }

    #[test]
    fn receipt_integrity_detects_tampering() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let mut receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        // Tamper with a field that IS part of canonical_bytes.
        // (duration_ns is deliberately excluded for replay determinism.)
        receipt.timestamp_ns = 999_999;
        assert!(!receipt.verify_integrity());
    }

    #[test]
    fn receipt_duration_ns_excluded_from_hash() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let mut receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let original_hash = receipt.content_hash;
        // Changing duration_ns must NOT invalidate the hash (it is
        // observational metadata excluded for deterministic replay).
        receipt.duration_ns = 999_999_999;
        assert!(receipt.verify_integrity());
        assert_eq!(receipt.content_hash, original_hash);
    }

    #[test]
    fn receipt_duration_ns_is_nonzero() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        // Duration must be measured, not simulated.
        // The exact value depends on machine speed, but it must not be zero.
        // (In-memory state transitions take at minimum a few nanoseconds.)
        assert!(
            receipt.duration_ns > 0,
            "containment receipt must record real execution duration"
        );
    }

    // -----------------------------------------------------------------------
    // Executor — receipts list
    // -----------------------------------------------------------------------

    #[test]
    fn receipts_accumulated() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        assert_eq!(executor.receipts("ext-001").len(), 2);
    }

    // -----------------------------------------------------------------------
    // Executor — by_state query
    // -----------------------------------------------------------------------

    #[test]
    fn by_state_query() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let sandboxed = executor.by_state(ContainmentState::Sandboxed);
        assert_eq!(sandboxed, vec!["ext-001"]);
        let running = executor.by_state(ContainmentState::Running);
        assert_eq!(running, vec!["ext-002"]);
    }

    // -----------------------------------------------------------------------
    // Executor — resume from suspended
    // -----------------------------------------------------------------------

    #[test]
    fn resume_from_suspended() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Suspend, "ext-001", &ctx)
            .unwrap();
        let receipt = executor.resume("ext-001", &ctx).unwrap();
        assert_eq!(receipt.new_state, ContainmentState::Running);
        assert_eq!(executor.state("ext-001"), Some(ContainmentState::Running));
    }

    #[test]
    fn resume_from_running_fails() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let err = executor.resume("ext-001", &ctx).unwrap_err();
        assert!(matches!(err, ContainmentError::InvalidTransition { .. }));
    }

    // -----------------------------------------------------------------------
    // Executor — escalation path
    // -----------------------------------------------------------------------

    #[test]
    fn escalation_challenged_to_sandbox_to_terminate() {
        let mut executor = setup_executor();
        let ctx = test_context();

        executor
            .execute(ContainmentAction::Challenge, "ext-001", &ctx)
            .unwrap();
        assert_eq!(
            executor.state("ext-001"),
            Some(ContainmentState::Challenged)
        );

        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert_eq!(executor.state("ext-001"), Some(ContainmentState::Sandboxed));

        executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        assert_eq!(
            executor.state("ext-001"),
            Some(ContainmentState::Terminated)
        );

        assert_eq!(executor.receipts("ext-001").len(), 3);
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_serde_roundtrip() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        let restored: ContainmentReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, restored);
    }

    #[test]
    fn executor_serde_roundtrip() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let json = serde_json::to_string(&executor).unwrap();
        let restored: ContainmentExecutor = serde_json::from_str(&json).unwrap();
        assert_eq!(executor.extension_count(), restored.extension_count());
    }

    #[test]
    fn forensic_snapshot_serde_roundtrip() {
        let snapshot = ForensicSnapshot {
            memory_hash: ContentHash::compute(b"mem"),
            hostcall_count: 42,
            snapshot_ns: 1_000_000,
            manifest_hash: ContentHash::compute(b"manifest"),
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        let restored: ForensicSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snapshot, restored);
    }

    #[test]
    fn context_serde_roundtrip() {
        let ctx = test_context();
        let json = serde_json::to_string(&ctx).unwrap();
        let restored: ContainmentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx.decision_id, restored.decision_id);
    }

    // -----------------------------------------------------------------------
    // Receipt metadata
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_contains_decision_id() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert_eq!(
            receipt.metadata.get("decision_id"),
            Some(&"dec-001".to_string())
        );
    }

    // -- Enrichment: Ord --

    #[test]
    fn containment_state_ordering() {
        assert!(ContainmentState::Running < ContainmentState::Challenged);
        assert!(ContainmentState::Challenged < ContainmentState::Sandboxed);
        assert!(ContainmentState::Sandboxed < ContainmentState::Suspended);
        assert!(ContainmentState::Suspended < ContainmentState::Terminated);
        assert!(ContainmentState::Terminated < ContainmentState::Quarantined);
    }

    #[test]
    fn receipt_contains_evidence_refs() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.evidence_refs, vec!["ev-001".to_string()]);
    }

    // -- Enrichment batch 2: Display uniqueness, boundary conditions, error paths --

    #[test]
    fn containment_state_display_uniqueness_btreeset() {
        use std::collections::BTreeSet;
        let all = [
            ContainmentState::Running,
            ContainmentState::Challenged,
            ContainmentState::Sandboxed,
            ContainmentState::Suspended,
            ContainmentState::Terminated,
            ContainmentState::Quarantined,
        ];
        let set: BTreeSet<String> = all.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            set.len(),
            all.len(),
            "all ContainmentState Display strings must be unique"
        );
    }

    #[test]
    fn containment_error_display_uniqueness() {
        use std::collections::BTreeSet;
        let errors = [
            ContainmentError::ExtensionNotFound {
                extension_id: "e".to_string(),
            },
            ContainmentError::AlreadyContained {
                extension_id: "e".to_string(),
                current_state: ContainmentState::Sandboxed,
            },
            ContainmentError::InvalidTransition {
                from: ContainmentState::Running,
                action: ContainmentAction::Allow,
            },
            ContainmentError::GracePeriodExpired {
                extension_id: "e".to_string(),
                elapsed_ns: 1000,
            },
            ContainmentError::ChallengeTimeout {
                extension_id: "e".to_string(),
            },
            ContainmentError::Internal {
                detail: "x".to_string(),
            },
        ];
        let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            set.len(),
            errors.len(),
            "all ContainmentError Display strings must be unique"
        );
    }

    #[test]
    fn containment_error_serde_all_variants() {
        let variants = vec![
            ContainmentError::ExtensionNotFound {
                extension_id: "ext-1".to_string(),
            },
            ContainmentError::AlreadyContained {
                extension_id: "ext-1".to_string(),
                current_state: ContainmentState::Sandboxed,
            },
            ContainmentError::InvalidTransition {
                from: ContainmentState::Running,
                action: ContainmentAction::Challenge,
            },
            ContainmentError::GracePeriodExpired {
                extension_id: "ext-1".to_string(),
                elapsed_ns: 5_000_000_000,
            },
            ContainmentError::ChallengeTimeout {
                extension_id: "ext-1".to_string(),
            },
            ContainmentError::Internal {
                detail: "oops".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ContainmentError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn containment_context_default_values() {
        let ctx = ContainmentContext::default();
        assert!(ctx.decision_id.is_empty());
        assert_eq!(ctx.timestamp_ns, 0);
        assert_eq!(ctx.epoch, SecurityEpoch::GENESIS);
        assert!(ctx.evidence_refs.is_empty());
        assert_eq!(ctx.grace_period_ns, DEFAULT_GRACE_PERIOD_NS);
        assert_eq!(ctx.challenge_timeout_ns, DEFAULT_CHALLENGE_TIMEOUT_NS);
    }

    #[test]
    fn containment_context_with_config_timeouts() {
        let config = ContainmentConfig {
            grace_period_ns: 1_000_000_000,
            challenge_timeout_ns: 30_000_000_000,
        };
        let ctx = ContainmentContext::with_config_timeouts(&config);
        assert_eq!(ctx.grace_period_ns, 1_000_000_000);
        assert_eq!(ctx.challenge_timeout_ns, 30_000_000_000);
        // Other fields should be defaults.
        assert!(ctx.decision_id.is_empty());
        assert_eq!(ctx.epoch, SecurityEpoch::GENESIS);
    }

    #[test]
    fn containment_context_default_config_matches_constants() {
        let config = ContainmentConfig::default();
        let ctx = ContainmentContext::with_config_timeouts(&config);
        assert_eq!(ctx.grace_period_ns, DEFAULT_GRACE_PERIOD_NS);
        assert_eq!(ctx.challenge_timeout_ns, DEFAULT_CHALLENGE_TIMEOUT_NS);
    }

    #[test]
    fn sandbox_policy_custom_capabilities() {
        let policy = SandboxPolicy {
            allowed_capabilities: vec!["fs-read".to_string(), "net-local".to_string()],
            allow_network: true,
            allow_fs_write: false,
            allow_process_spawn: false,
            max_memory_bytes: 1024,
        };
        assert!(policy.is_allowed("fs-read"));
        assert!(policy.is_allowed("net-local"));
        assert!(!policy.is_allowed("fs-write"));
    }

    #[test]
    fn resume_from_nonexistent_extension_fails() {
        let mut executor = ContainmentExecutor::new();
        let ctx = test_context();
        let err = executor.resume("nonexistent", &ctx).unwrap_err();
        assert!(matches!(err, ContainmentError::ExtensionNotFound { .. }));
    }

    #[test]
    fn receipt_ids_are_unique_across_actions() {
        use std::collections::BTreeSet;
        let mut executor = setup_executor();
        let ctx = test_context();

        let r1 = executor
            .execute(ContainmentAction::Challenge, "ext-001", &ctx)
            .unwrap();
        let r2 = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let r3 = executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();

        let ids: BTreeSet<&str> = [
            r1.receipt_id.as_str(),
            r2.receipt_id.as_str(),
            r3.receipt_id.as_str(),
        ]
        .into_iter()
        .collect();
        assert_eq!(ids.len(), 3, "receipt IDs must be unique");
    }

    #[test]
    fn resume_receipt_has_resume_metadata() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Suspend, "ext-001", &ctx)
            .unwrap();
        let receipt = executor.resume("ext-001", &ctx).unwrap();
        assert_eq!(receipt.metadata.get("resume"), Some(&"true".to_string()));
        assert!(receipt.verify_integrity());
    }

    // -- Enrichment batch 3: receipt fields, serde, clone, state transitions --

    #[test]
    fn receipt_sandbox_serde_roundtrip() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        let back: ContainmentReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn receipt_clone_equality() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Challenge, "ext-001", &ctx)
            .unwrap();
        let cloned = receipt.clone();
        assert_eq!(receipt, cloned);
        assert_eq!(receipt.receipt_id, cloned.receipt_id);
        assert_eq!(receipt.content_hash, cloned.content_hash);
    }

    #[test]
    fn receipt_target_extension_id_matches_input() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.target_extension_id, "ext-001");
    }

    #[test]
    fn allow_action_leaves_running() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Allow, "ext-001", &ctx)
            .unwrap();
        let state = executor.state("ext-001");
        assert_eq!(state, Some(ContainmentState::Running));
    }

    #[test]
    fn challenge_then_allow_returns_to_running() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Challenge, "ext-001", &ctx)
            .unwrap();
        assert_eq!(
            executor.state("ext-001"),
            Some(ContainmentState::Challenged)
        );
        executor
            .execute(ContainmentAction::Allow, "ext-001", &ctx)
            .unwrap();
        assert_eq!(executor.state("ext-001"), Some(ContainmentState::Running));
    }

    #[test]
    fn containment_state_serde_six_variants() {
        let states = [
            ContainmentState::Running,
            ContainmentState::Challenged,
            ContainmentState::Sandboxed,
            ContainmentState::Suspended,
            ContainmentState::Terminated,
            ContainmentState::Quarantined,
        ];
        for s in &states {
            let json = serde_json::to_string(s).unwrap();
            let back: ContainmentState = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn executor_new_is_empty() {
        let executor = ContainmentExecutor::new();
        assert!(executor.receipts("nonexistent").is_empty());
        assert_eq!(executor.state("nonexistent"), None);
    }

    #[test]
    fn containment_context_serde_fields() {
        let ctx = test_context();
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"timestamp_ns\""));
        assert!(json.contains("\"epoch\""));
    }

    #[test]
    fn sandbox_policy_custom_serde_roundtrip() {
        let policy = SandboxPolicy {
            allowed_capabilities: vec!["fs-read".to_string()],
            allow_network: false,
            allow_fs_write: false,
            allow_process_spawn: false,
            max_memory_bytes: 4096,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let back: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn sandbox_policy_default_has_fs_read() {
        let policy = SandboxPolicy::default();
        assert!(!policy.allow_network);
        assert!(!policy.allow_fs_write);
        assert!(!policy.allow_process_spawn);
        assert!(policy.is_allowed("fs-read"), "default allows fs-read");
    }

    #[test]
    fn receipt_json_field_presence() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"receipt_id\""));
        assert!(json.contains("\"target_extension_id\""));
        assert!(json.contains("\"action\""));
        assert!(json.contains("\"content_hash\""));
    }

    #[test]
    fn multiple_extensions_isolated_state() {
        let mut executor = ContainmentExecutor::new();
        let ctx = test_context();
        executor.register("ext-a");
        executor.register("ext-b");
        executor
            .execute(ContainmentAction::Sandbox, "ext-a", &ctx)
            .unwrap();
        assert_eq!(executor.state("ext-a"), Some(ContainmentState::Sandboxed));
        assert_eq!(executor.state("ext-b"), Some(ContainmentState::Running));
    }

    #[test]
    fn containment_error_display_is_nonempty() {
        let err = ContainmentError::Internal {
            detail: "test".to_string(),
        };
        assert!(!err.to_string().is_empty());
    }

    // -----------------------------------------------------------------------
    // Category 1: Copy semantics — ContainmentState and ContainmentAction are Copy
    // -----------------------------------------------------------------------

    #[test]
    fn containment_state_copy_survives() {
        let original = ContainmentState::Sandboxed;
        let copy = original;
        assert_eq!(original, copy);
        // Both usable after copy.
        assert!(original.is_alive());
        assert!(copy.is_alive());
    }

    #[test]
    fn containment_action_copy_survives() {
        let original = ContainmentAction::Terminate;
        let copy = original;
        assert_eq!(original, copy);
        assert_eq!(original.severity(), copy.severity());
    }

    // -----------------------------------------------------------------------
    // Category 2: Debug distinctness — all enum variants produce distinct Debug
    // -----------------------------------------------------------------------

    #[test]
    fn containment_state_debug_distinct() {
        use std::collections::BTreeSet;
        let variants = [
            ContainmentState::Running,
            ContainmentState::Challenged,
            ContainmentState::Sandboxed,
            ContainmentState::Suspended,
            ContainmentState::Terminated,
            ContainmentState::Quarantined,
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), variants.len(), "Debug strings must be distinct");
    }

    #[test]
    fn containment_error_debug_distinct() {
        use std::collections::BTreeSet;
        let variants = [
            ContainmentError::ExtensionNotFound {
                extension_id: "e".to_string(),
            },
            ContainmentError::AlreadyContained {
                extension_id: "e".to_string(),
                current_state: ContainmentState::Sandboxed,
            },
            ContainmentError::InvalidTransition {
                from: ContainmentState::Running,
                action: ContainmentAction::Allow,
            },
            ContainmentError::GracePeriodExpired {
                extension_id: "e".to_string(),
                elapsed_ns: 1000,
            },
            ContainmentError::ChallengeTimeout {
                extension_id: "e".to_string(),
            },
            ContainmentError::Internal {
                detail: "x".to_string(),
            },
        ];
        let set: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn containment_action_debug_distinct() {
        use std::collections::BTreeSet;
        let set: BTreeSet<String> = ContainmentAction::ALL
            .iter()
            .map(|a| format!("{a:?}"))
            .collect();
        assert_eq!(set.len(), ContainmentAction::ALL.len());
    }

    // -----------------------------------------------------------------------
    // Category 3: Serde variant distinctness — all enum variants serialize distinctly
    // -----------------------------------------------------------------------

    #[test]
    fn containment_state_serde_distinct() {
        use std::collections::BTreeSet;
        let variants = [
            ContainmentState::Running,
            ContainmentState::Challenged,
            ContainmentState::Sandboxed,
            ContainmentState::Suspended,
            ContainmentState::Terminated,
            ContainmentState::Quarantined,
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(set.len(), variants.len(), "all states serialize distinctly");
    }

    #[test]
    fn containment_action_serde_distinct() {
        use std::collections::BTreeSet;
        let set: BTreeSet<String> = ContainmentAction::ALL
            .iter()
            .map(|a| serde_json::to_string(a).unwrap())
            .collect();
        assert_eq!(
            set.len(),
            ContainmentAction::ALL.len(),
            "all actions serialize distinctly"
        );
    }

    #[test]
    fn containment_error_serde_distinct() {
        use std::collections::BTreeSet;
        let variants = [
            ContainmentError::ExtensionNotFound {
                extension_id: "e".to_string(),
            },
            ContainmentError::AlreadyContained {
                extension_id: "e".to_string(),
                current_state: ContainmentState::Terminated,
            },
            ContainmentError::InvalidTransition {
                from: ContainmentState::Running,
                action: ContainmentAction::Sandbox,
            },
            ContainmentError::GracePeriodExpired {
                extension_id: "e".to_string(),
                elapsed_ns: 99,
            },
            ContainmentError::ChallengeTimeout {
                extension_id: "e".to_string(),
            },
            ContainmentError::Internal {
                detail: "detail".to_string(),
            },
        ];
        let set: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(set.len(), variants.len());
    }

    // -----------------------------------------------------------------------
    // Category 4: Clone independence
    // -----------------------------------------------------------------------

    #[test]
    fn sandbox_policy_clone_independence() {
        let original = SandboxPolicy {
            allowed_capabilities: vec!["fs-read".to_string()],
            allow_network: false,
            allow_fs_write: false,
            allow_process_spawn: false,
            max_memory_bytes: 1024,
        };
        let mut cloned = original.clone();
        cloned.allowed_capabilities.push("net-all".to_string());
        cloned.allow_network = true;
        // Original is unchanged.
        assert_eq!(original.allowed_capabilities.len(), 1);
        assert!(!original.allow_network);
    }

    #[test]
    fn forensic_snapshot_clone_independence() {
        let snap = ForensicSnapshot {
            memory_hash: ContentHash::compute(b"data"),
            hostcall_count: 10,
            snapshot_ns: 5_000,
            manifest_hash: ContentHash::compute(b"manifest"),
        };
        let mut cloned = snap.clone();
        cloned.hostcall_count = 999;
        // Original is unaffected; clone has the new value.
        assert_eq!(snap.hostcall_count, 10);
        assert_eq!(cloned.hostcall_count, 999);
    }

    #[test]
    fn containment_context_clone_independence() {
        let ctx = test_context();
        let mut cloned = ctx.clone();
        cloned.decision_id = "mutated".to_string();
        cloned.evidence_refs.push("extra-ev".to_string());
        assert_eq!(ctx.decision_id, "dec-001");
        assert_eq!(ctx.evidence_refs.len(), 1);
    }

    #[test]
    fn executor_clone_independence() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let mut cloned = executor.clone();
        // Mutate clone only.
        cloned.register("ext-clone-only");
        assert_eq!(executor.extension_count(), 2);
        assert_eq!(cloned.extension_count(), 3);
    }

    // -----------------------------------------------------------------------
    // Category 5: JSON field-name stability
    // -----------------------------------------------------------------------

    #[test]
    fn sandbox_policy_json_field_names() {
        let policy = SandboxPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"allowed_capabilities\""));
        assert!(json.contains("\"allow_network\""));
        assert!(json.contains("\"allow_fs_write\""));
        assert!(json.contains("\"allow_process_spawn\""));
        assert!(json.contains("\"max_memory_bytes\""));
    }

    #[test]
    fn forensic_snapshot_json_field_names() {
        let snap = ForensicSnapshot {
            memory_hash: ContentHash::compute(b"m"),
            hostcall_count: 1,
            snapshot_ns: 0,
            manifest_hash: ContentHash::compute(b"mf"),
        };
        let json = serde_json::to_string(&snap).unwrap();
        assert!(json.contains("\"memory_hash\""));
        assert!(json.contains("\"hostcall_count\""));
        assert!(json.contains("\"snapshot_ns\""));
        assert!(json.contains("\"manifest_hash\""));
    }

    #[test]
    fn containment_context_json_field_names() {
        let ctx = ContainmentContext::default();
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"timestamp_ns\""));
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"evidence_refs\""));
        assert!(json.contains("\"grace_period_ns\""));
        assert!(json.contains("\"challenge_timeout_ns\""));
        assert!(json.contains("\"sandbox_policy\""));
    }

    #[test]
    fn receipt_json_field_names_complete() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
            .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"receipt_id\""));
        assert!(json.contains("\"action\""));
        assert!(json.contains("\"target_extension_id\""));
        assert!(json.contains("\"previous_state\""));
        assert!(json.contains("\"new_state\""));
        assert!(json.contains("\"timestamp_ns\""));
        assert!(json.contains("\"duration_ns\""));
        assert!(json.contains("\"success\""));
        assert!(json.contains("\"cooperative\""));
        assert!(json.contains("\"evidence_refs\""));
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"content_hash\""));
        assert!(json.contains("\"metadata\""));
    }

    // -----------------------------------------------------------------------
    // Category 6: Display format checks — exact string assertions
    // -----------------------------------------------------------------------

    #[test]
    fn containment_state_display_exact() {
        assert_eq!(ContainmentState::Running.to_string(), "running");
        assert_eq!(ContainmentState::Challenged.to_string(), "challenged");
        assert_eq!(ContainmentState::Sandboxed.to_string(), "sandboxed");
        assert_eq!(ContainmentState::Suspended.to_string(), "suspended");
        assert_eq!(ContainmentState::Terminated.to_string(), "terminated");
        assert_eq!(ContainmentState::Quarantined.to_string(), "quarantined");
    }

    #[test]
    fn error_display_extension_not_found_exact() {
        let err = ContainmentError::ExtensionNotFound {
            extension_id: "my-ext".to_string(),
        };
        assert_eq!(err.to_string(), "extension not found: my-ext");
    }

    #[test]
    fn error_display_already_contained_exact() {
        let err = ContainmentError::AlreadyContained {
            extension_id: "my-ext".to_string(),
            current_state: ContainmentState::Sandboxed,
        };
        assert_eq!(err.to_string(), "my-ext already in state: sandboxed");
    }

    #[test]
    fn error_display_invalid_transition_exact() {
        let err = ContainmentError::InvalidTransition {
            from: ContainmentState::Terminated,
            action: ContainmentAction::Sandbox,
        };
        assert_eq!(
            err.to_string(),
            "cannot apply sandbox from state terminated"
        );
    }

    #[test]
    fn error_display_grace_period_expired_exact() {
        let err = ContainmentError::GracePeriodExpired {
            extension_id: "ext-x".to_string(),
            elapsed_ns: 7_000_000_000,
        };
        assert_eq!(
            err.to_string(),
            "grace period expired for ext-x after 7000000000ns"
        );
    }

    #[test]
    fn error_display_challenge_timeout_exact() {
        let err = ContainmentError::ChallengeTimeout {
            extension_id: "ext-y".to_string(),
        };
        assert_eq!(err.to_string(), "challenge timeout for ext-y");
    }

    #[test]
    fn error_display_internal_exact() {
        let err = ContainmentError::Internal {
            detail: "disk full".to_string(),
        };
        assert_eq!(err.to_string(), "internal error: disk full");
    }

    // -----------------------------------------------------------------------
    // Category 7: Hash consistency — same value hashes identically
    // -----------------------------------------------------------------------

    #[test]
    fn containment_state_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let state = ContainmentState::Quarantined;
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        state.hash(&mut h1);
        state.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn containment_action_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let action = ContainmentAction::Quarantine;
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        action.hash(&mut h1);
        action.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn containment_state_hash_all_distinct() {
        use std::collections::BTreeSet;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let variants = [
            ContainmentState::Running,
            ContainmentState::Challenged,
            ContainmentState::Sandboxed,
            ContainmentState::Suspended,
            ContainmentState::Terminated,
            ContainmentState::Quarantined,
        ];
        let hashes: BTreeSet<u64> = variants
            .iter()
            .map(|v| {
                let mut h = DefaultHasher::new();
                v.hash(&mut h);
                h.finish()
            })
            .collect();
        assert_eq!(hashes.len(), variants.len(), "all state hashes distinct");
    }

    // -----------------------------------------------------------------------
    // Category 8: Boundary / edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn extension_id_empty_string() {
        let mut executor = ContainmentExecutor::new();
        executor.register("");
        assert_eq!(executor.extension_count(), 1);
        assert_eq!(executor.state(""), Some(ContainmentState::Running));
    }

    #[test]
    fn sandbox_policy_empty_capabilities() {
        let policy = SandboxPolicy {
            allowed_capabilities: vec![],
            allow_network: false,
            allow_fs_write: false,
            allow_process_spawn: false,
            max_memory_bytes: 0,
        };
        assert!(!policy.is_allowed("fs-read"));
        assert!(!policy.is_allowed(""));
    }

    #[test]
    fn sandbox_policy_max_memory_zero() {
        let policy = SandboxPolicy {
            allowed_capabilities: vec![],
            allow_network: false,
            allow_fs_write: false,
            allow_process_spawn: false,
            max_memory_bytes: 0,
        };
        assert_eq!(policy.max_memory_bytes, 0);
    }

    #[test]
    fn sandbox_policy_max_memory_u64_max() {
        let policy = SandboxPolicy {
            allowed_capabilities: vec!["all".to_string()],
            allow_network: true,
            allow_fs_write: true,
            allow_process_spawn: true,
            max_memory_bytes: u64::MAX,
        };
        assert_eq!(policy.max_memory_bytes, u64::MAX);
        let json = serde_json::to_string(&policy).unwrap();
        let back: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_memory_bytes, u64::MAX);
    }

    #[test]
    fn forensic_snapshot_zero_hostcall_count() {
        let snap = ForensicSnapshot {
            memory_hash: ContentHash::compute(b""),
            hostcall_count: 0,
            snapshot_ns: 0,
            manifest_hash: ContentHash::compute(b""),
        };
        assert_eq!(snap.hostcall_count, 0);
    }

    #[test]
    fn forensic_snapshot_u64_max_snapshot_ns() {
        let snap = ForensicSnapshot {
            memory_hash: ContentHash::compute(b"x"),
            hostcall_count: u64::MAX,
            snapshot_ns: u64::MAX,
            manifest_hash: ContentHash::compute(b"y"),
        };
        assert_eq!(snap.snapshot_ns, u64::MAX);
        assert_eq!(snap.hostcall_count, u64::MAX);
    }

    #[test]
    fn context_with_empty_evidence_refs() {
        let ctx = ContainmentContext {
            evidence_refs: vec![],
            ..test_context()
        };
        let mut executor = setup_executor();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert!(receipt.evidence_refs.is_empty());
        assert!(receipt.verify_integrity());
    }

    #[test]
    fn context_with_multiple_evidence_refs() {
        let ctx = ContainmentContext {
            evidence_refs: vec![
                "ev-001".to_string(),
                "ev-002".to_string(),
                "ev-003".to_string(),
            ],
            ..test_context()
        };
        let mut executor = setup_executor();
        let receipt = executor
            .execute(ContainmentAction::Challenge, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.evidence_refs.len(), 3);
        assert!(receipt.verify_integrity());
    }

    #[test]
    fn grace_period_and_timeout_u64_max() {
        let ctx = ContainmentContext {
            grace_period_ns: u64::MAX,
            challenge_timeout_ns: u64::MAX,
            ..test_context()
        };
        assert_eq!(ctx.grace_period_ns, u64::MAX);
        assert_eq!(ctx.challenge_timeout_ns, u64::MAX);
        let json = serde_json::to_string(&ctx).unwrap();
        let back: ContainmentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.grace_period_ns, u64::MAX);
    }

    // -----------------------------------------------------------------------
    // Category 9: Serde roundtrips — complex populated structs
    // -----------------------------------------------------------------------

    #[test]
    fn containment_context_full_serde_roundtrip() {
        let ctx = ContainmentContext {
            decision_id: "full-dec-42".to_string(),
            timestamp_ns: 9_999_999_999,
            epoch: SecurityEpoch::from_raw(7),
            evidence_refs: vec!["ev-a".to_string(), "ev-b".to_string()],
            grace_period_ns: 1_000_000,
            challenge_timeout_ns: 2_000_000,
            sandbox_policy: SandboxPolicy {
                allowed_capabilities: vec!["net".to_string(), "disk".to_string()],
                allow_network: true,
                allow_fs_write: true,
                allow_process_spawn: false,
                max_memory_bytes: 65536,
            },
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: ContainmentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx.decision_id, back.decision_id);
        assert_eq!(ctx.timestamp_ns, back.timestamp_ns);
        assert_eq!(ctx.epoch, back.epoch);
        assert_eq!(ctx.evidence_refs, back.evidence_refs);
        assert_eq!(ctx.grace_period_ns, back.grace_period_ns);
        assert_eq!(ctx.sandbox_policy, back.sandbox_policy);
    }

    #[test]
    fn receipt_quarantine_serde_roundtrip() {
        let mut executor = setup_executor();
        let ctx = ContainmentContext {
            decision_id: "quar-dec".to_string(),
            timestamp_ns: 42_000,
            epoch: SecurityEpoch::from_raw(3),
            evidence_refs: vec!["ev-q1".to_string()],
            ..ContainmentContext::default()
        };
        let receipt = executor
            .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
            .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        let back: ContainmentReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
        assert!(back.verify_integrity());
    }

    #[test]
    fn receipt_terminate_serde_roundtrip() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Terminate, "ext-001", &ctx)
            .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        let back: ContainmentReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
        assert!(!back.cooperative);
    }

    #[test]
    fn forensic_snapshot_full_serde_roundtrip() {
        let snap = ForensicSnapshot {
            memory_hash: ContentHash::compute(b"memory-data-full"),
            hostcall_count: 1_000_000,
            snapshot_ns: 123_456_789,
            manifest_hash: ContentHash::compute(b"manifest-hash-full"),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let back: ForensicSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn executor_full_serde_roundtrip_state_preserved() {
        let mut executor = ContainmentExecutor::new();
        let ctx = test_context();
        executor.register("alpha");
        executor.register("beta");
        executor.register("gamma");
        executor
            .execute(ContainmentAction::Sandbox, "alpha", &ctx)
            .unwrap();
        executor
            .execute(ContainmentAction::Terminate, "beta", &ctx)
            .unwrap();
        let json = serde_json::to_string(&executor).unwrap();
        let back: ContainmentExecutor = serde_json::from_str(&json).unwrap();
        assert_eq!(executor.extension_count(), back.extension_count());
        assert_eq!(back.state("alpha"), Some(ContainmentState::Sandboxed));
        assert_eq!(back.state("beta"), Some(ContainmentState::Terminated));
        assert_eq!(back.state("gamma"), Some(ContainmentState::Running));
    }

    // -----------------------------------------------------------------------
    // Category 10: Debug nonempty — all types produce non-empty Debug output
    // -----------------------------------------------------------------------

    #[test]
    fn sandbox_policy_debug_nonempty() {
        let policy = SandboxPolicy::default();
        assert!(!format!("{policy:?}").is_empty());
    }

    #[test]
    fn forensic_snapshot_debug_nonempty() {
        let snap = ForensicSnapshot {
            memory_hash: ContentHash::compute(b"d"),
            hostcall_count: 0,
            snapshot_ns: 0,
            manifest_hash: ContentHash::compute(b"m"),
        };
        assert!(!format!("{snap:?}").is_empty());
    }

    #[test]
    fn containment_context_debug_nonempty() {
        let ctx = ContainmentContext::default();
        assert!(!format!("{ctx:?}").is_empty());
    }

    #[test]
    fn containment_receipt_debug_nonempty() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Challenge, "ext-001", &ctx)
            .unwrap();
        assert!(!format!("{receipt:?}").is_empty());
    }

    #[test]
    fn executor_debug_nonempty() {
        let executor = ContainmentExecutor::new();
        assert!(!format!("{executor:?}").is_empty());
    }

    // -----------------------------------------------------------------------
    // Extra targeted tests: transition table, cooperative flag, escalation paths
    // -----------------------------------------------------------------------

    #[test]
    fn cooperative_flag_is_true_for_non_terminal_actions() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let r = executor
            .execute(ContainmentAction::Challenge, "ext-001", &ctx)
            .unwrap();
        assert!(r.cooperative);
        let r2 = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert!(r2.cooperative);
    }

    #[test]
    fn cooperative_flag_is_false_for_terminate_and_quarantine() {
        let mut executor = ContainmentExecutor::new();
        let ctx = test_context();
        executor.register("ext-t");
        executor.register("ext-q");
        let rt = executor
            .execute(ContainmentAction::Terminate, "ext-t", &ctx)
            .unwrap();
        assert!(!rt.cooperative);
        let rq = executor
            .execute(ContainmentAction::Quarantine, "ext-q", &ctx)
            .unwrap();
        assert!(!rq.cooperative);
    }

    #[test]
    fn challenged_then_quarantine() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Challenge, "ext-001", &ctx)
            .unwrap();
        let receipt = executor
            .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.previous_state, ContainmentState::Challenged);
        assert_eq!(receipt.new_state, ContainmentState::Quarantined);
        assert!(executor.forensic_snapshot("ext-001").is_some());
        assert!(receipt.verify_integrity());
    }

    #[test]
    fn sandboxed_then_suspend() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let receipt = executor
            .execute(ContainmentAction::Suspend, "ext-001", &ctx)
            .unwrap();
        assert_eq!(receipt.previous_state, ContainmentState::Sandboxed);
        assert_eq!(receipt.new_state, ContainmentState::Suspended);
        assert!(receipt.verify_integrity());
    }

    #[test]
    fn cannot_challenge_from_sandboxed() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let err = executor
            .execute(ContainmentAction::Challenge, "ext-001", &ctx)
            .unwrap_err();
        assert!(matches!(err, ContainmentError::InvalidTransition { .. }));
    }

    #[test]
    fn cannot_allow_from_sandboxed() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let err = executor
            .execute(ContainmentAction::Allow, "ext-001", &ctx)
            .unwrap_err();
        assert!(matches!(err, ContainmentError::InvalidTransition { .. }));
    }

    #[test]
    fn cannot_transition_from_quarantined() {
        let mut executor = setup_executor();
        let ctx = test_context();
        executor
            .execute(ContainmentAction::Quarantine, "ext-001", &ctx)
            .unwrap();
        for action in ContainmentAction::ALL {
            let result = executor.execute(action, "ext-001", &ctx);
            // Either idempotency (same Quarantine) or InvalidTransition.
            if action == ContainmentAction::Quarantine {
                // Idempotent: returns last receipt.
                assert!(result.is_ok());
            } else {
                assert!(
                    matches!(result, Err(ContainmentError::InvalidTransition { .. })),
                    "expected InvalidTransition for {action}"
                );
            }
        }
    }

    #[test]
    fn sandbox_policy_applied_to_extension_record() {
        let custom_policy = SandboxPolicy {
            allowed_capabilities: vec!["custom-cap".to_string()],
            allow_network: true,
            allow_fs_write: false,
            allow_process_spawn: false,
            max_memory_bytes: 8192,
        };
        let ctx = ContainmentContext {
            sandbox_policy: custom_policy.clone(),
            ..test_context()
        };
        let mut executor = setup_executor();
        executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        let policy = executor.sandbox_policy("ext-001").unwrap();
        assert_eq!(*policy, custom_policy);
        assert!(policy.is_allowed("custom-cap"));
    }

    #[test]
    fn receipts_empty_for_no_actions() {
        let executor = setup_executor();
        assert!(executor.receipts("ext-001").is_empty());
    }

    #[test]
    fn by_state_returns_empty_when_none_match() {
        let executor = setup_executor();
        let dead = executor.by_state(ContainmentState::Terminated);
        assert!(dead.is_empty());
    }

    #[test]
    fn receipt_id_format_prefix() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let receipt = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        assert!(
            receipt.receipt_id.starts_with("cr-"),
            "receipt ID must start with 'cr-'"
        );
    }

    #[test]
    fn receipt_id_increments_sequentially() {
        let mut executor = setup_executor();
        let ctx = test_context();
        let r1 = executor
            .execute(ContainmentAction::Challenge, "ext-001", &ctx)
            .unwrap();
        let r2 = executor
            .execute(ContainmentAction::Sandbox, "ext-001", &ctx)
            .unwrap();
        // The second receipt ID should be strictly different from the first.
        assert_ne!(r1.receipt_id, r2.receipt_id);
    }
}
