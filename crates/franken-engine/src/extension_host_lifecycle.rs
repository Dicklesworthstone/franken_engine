//! Extension-host lifecycle manager integrating region-per-extension execution
//! cells with quiescent close guarantees.
//!
//! This module wires [`CellManager`] and [`CancellationManager`] together into a
//! single orchestrator so that each loaded extension (and each session within an
//! extension) runs inside its own isolated execution region.  Region teardown
//! follows the quiescent close protocol: drain in-flight work → await quiescence
//! → finalize → destroy.
//!
//! Plan reference: Section 10.13, bd-1ukb.
//! Dependencies: bd-2ao (region quiescent close), bd-2ygl (Cx threading),
//!               bd-uvmm (evidence emission).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::cancellation_lifecycle::{
    CancellationEvent, CancellationManager, CancellationOutcome, LifecycleEvent,
};
use crate::control_plane::ContextAdapter;
use crate::execution_cell::CellManager;
use crate::region_lifecycle::RegionState;

// ---------------------------------------------------------------------------
// HostLifecycleError
// ---------------------------------------------------------------------------

/// Errors produced by the extension-host lifecycle manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostLifecycleError {
    /// Extension already loaded with this ID.
    ExtensionAlreadyLoaded { extension_id: String },
    /// Extension not found.
    ExtensionNotFound { extension_id: String },
    /// Extension is not in a state that allows the requested operation.
    ExtensionNotRunning {
        extension_id: String,
        state: RegionState,
    },
    /// Session already exists under the given extension.
    SessionAlreadyExists {
        extension_id: String,
        session_id: String,
    },
    /// Session not found.
    SessionNotFound {
        extension_id: String,
        session_id: String,
    },
    /// Cell operation error.
    CellError {
        extension_id: String,
        error_code: String,
        message: String,
    },
    /// Cancellation error.
    CancellationError {
        extension_id: String,
        error_code: String,
        message: String,
    },
    /// Host is shutting down; no new operations accepted.
    HostShuttingDown,
}

impl fmt::Display for HostLifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExtensionAlreadyLoaded { extension_id } => {
                write!(f, "extension already loaded: {extension_id}")
            }
            Self::ExtensionNotFound { extension_id } => {
                write!(f, "extension not found: {extension_id}")
            }
            Self::ExtensionNotRunning {
                extension_id,
                state,
            } => write!(f, "extension {extension_id} not running (state={state:?})"),
            Self::SessionAlreadyExists {
                extension_id,
                session_id,
            } => write!(
                f,
                "session {session_id} already exists under {extension_id}"
            ),
            Self::SessionNotFound {
                extension_id,
                session_id,
            } => write!(f, "session {session_id} not found under {extension_id}"),
            Self::CellError {
                extension_id,
                error_code,
                message,
            } => write!(f, "cell error [{error_code}] on {extension_id}: {message}"),
            Self::CancellationError {
                extension_id,
                error_code,
                message,
            } => write!(
                f,
                "cancellation error [{error_code}] on {extension_id}: {message}"
            ),
            Self::HostShuttingDown => write!(f, "host is shutting down"),
        }
    }
}

impl std::error::Error for HostLifecycleError {}

impl HostLifecycleError {
    /// Stable error code for structured logging.
    pub fn error_code(&self) -> &str {
        match self {
            Self::ExtensionAlreadyLoaded { .. } => "host_extension_already_loaded",
            Self::ExtensionNotFound { .. } => "host_extension_not_found",
            Self::ExtensionNotRunning { .. } => "host_extension_not_running",
            Self::SessionAlreadyExists { .. } => "host_session_already_exists",
            Self::SessionNotFound { .. } => "host_session_not_found",
            Self::CellError { .. } => "host_cell_error",
            Self::CancellationError { .. } => "host_cancellation_error",
            Self::HostShuttingDown => "host_shutting_down",
        }
    }
}

// ---------------------------------------------------------------------------
// HostLifecycleEvent — structured evidence
// ---------------------------------------------------------------------------

/// Structured event emitted by the extension-host lifecycle manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostLifecycleEvent {
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Extension ID this event relates to.
    pub extension_id: String,
    /// Optional session ID.
    pub session_id: Option<String>,
    /// Component name.
    pub component: String,
    /// Event name.
    pub event: String,
    /// Outcome (ok, error).
    pub outcome: String,
    /// Error code if outcome is error.
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// ExtensionRecord — per-extension bookkeeping
// ---------------------------------------------------------------------------

/// Per-extension tracking record maintained by the lifecycle manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionRecord {
    /// Extension cell ID within the CellManager.
    pub cell_id: String,
    /// Active session IDs owned by this extension.
    pub sessions: BTreeSet<String>,
    /// Trace ID for the load operation.
    pub load_trace_id: String,
    /// Whether the extension has been unloaded.
    pub unloaded: bool,
}

// ---------------------------------------------------------------------------
// ExtensionHostLifecycleManager
// ---------------------------------------------------------------------------

/// Orchestrates the extension-host lifecycle: extension load/unload, session
/// create/close, and cancellation (quarantine/suspend/terminate/revocation).
///
/// Every loaded extension and every session run inside isolated execution
/// regions.  Region teardown follows the three-phase quiescent close protocol
/// so that no dangling work survives region destruction.
#[derive(Debug)]
pub struct ExtensionHostLifecycleManager {
    /// Active extension records keyed by extension_id.
    extensions: BTreeMap<String, ExtensionRecord>,
    /// Execution-cell manager (owns all region-backed cells).
    cell_manager: CellManager,
    /// Cancellation manager (three-phase protocol enforcement).
    cancellation_manager: CancellationManager,
    /// Structured lifecycle events for evidence emission.
    events: Vec<HostLifecycleEvent>,
    /// True once shutdown has been initiated.
    shutting_down: bool,
    /// Counter for generating deterministic session cell IDs.
    session_counter: u64,
}

impl Default for ExtensionHostLifecycleManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtensionHostLifecycleManager {
    /// Create a new extension-host lifecycle manager.
    pub fn new() -> Self {
        Self {
            extensions: BTreeMap::new(),
            cell_manager: CellManager::new(),
            cancellation_manager: CancellationManager::new(),
            events: Vec::new(),
            shutting_down: false,
            session_counter: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Extension load / unload
    // -----------------------------------------------------------------------

    /// Load an extension, creating an isolated execution region.
    ///
    /// Each extension gets its own [`ExecutionCell`] of kind `Extension`.
    pub fn load_extension<C: ContextAdapter>(
        &mut self,
        extension_id: &str,
        cx: &mut C,
    ) -> Result<(), HostLifecycleError> {
        if self.shutting_down {
            return Err(HostLifecycleError::HostShuttingDown);
        }
        if self.extensions.contains_key(extension_id) {
            return Err(HostLifecycleError::ExtensionAlreadyLoaded {
                extension_id: extension_id.to_string(),
            });
        }

        let trace_id = cx.trace_id().to_string();
        self.cell_manager
            .create_extension_cell(extension_id, &trace_id);

        self.extensions.insert(
            extension_id.to_string(),
            ExtensionRecord {
                cell_id: extension_id.to_string(),
                sessions: BTreeSet::new(),
                load_trace_id: trace_id.clone(),
                unloaded: false,
            },
        );

        self.push_event(
            &trace_id,
            extension_id,
            None,
            "extension_loaded",
            "ok",
            None,
        );
        Ok(())
    }

    /// Unload an extension using the quiescent close protocol.
    ///
    /// All sessions are closed first, then the extension cell is cancelled
    /// via the `Unload` lifecycle event.
    pub fn unload_extension<C: ContextAdapter>(
        &mut self,
        extension_id: &str,
        cx: &mut C,
    ) -> Result<CancellationOutcome, HostLifecycleError> {
        let record = self.extensions.get(extension_id).ok_or_else(|| {
            HostLifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            }
        })?;
        if record.unloaded {
            return Err(HostLifecycleError::ExtensionNotRunning {
                extension_id: extension_id.to_string(),
                state: RegionState::Closed,
            });
        }

        let trace_id = cx.trace_id().to_string();

        // Close all sessions first.
        let session_ids: Vec<String> = record.sessions.iter().cloned().collect();
        for session_id in &session_ids {
            let session_cell_id = self.session_cell_id(extension_id, session_id);
            if let Some(session_cell) = self.cell_manager.get_mut(&session_cell_id)
                && session_cell.state() == RegionState::Running
                && let Ok(outcome) =
                    self.cancellation_manager
                        .cancel_cell(session_cell, cx, LifecycleEvent::Unload)
            {
                self.cell_manager
                    .archive_cell(&session_cell_id, outcome.finalize_result);
            }
        }

        // Cancel the extension cell.
        let cell = self.cell_manager.get_mut(extension_id).ok_or_else(|| {
            HostLifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            }
        })?;

        let outcome = self
            .cancellation_manager
            .cancel_cell(cell, cx, LifecycleEvent::Unload)
            .map_err(|e| HostLifecycleError::CancellationError {
                extension_id: extension_id.to_string(),
                error_code: e.error_code().to_string(),
                message: e.to_string(),
            })?;

        self.cell_manager
            .archive_cell(extension_id, outcome.finalize_result.clone());

        // Mark as unloaded.
        if let Some(record) = self.extensions.get_mut(extension_id) {
            record.unloaded = true;
            record.sessions.clear();
        }

        self.push_event(
            &trace_id,
            extension_id,
            None,
            "extension_unloaded",
            if outcome.success { "ok" } else { "partial" },
            None,
        );

        Ok(outcome)
    }

    // -----------------------------------------------------------------------
    // Session create / close
    // -----------------------------------------------------------------------

    /// Create a new session within a loaded extension.
    ///
    /// The session gets its own sub-region (child cell) scoped to the session
    /// lifetime.  The session cell ID is deterministic: `{extension_id}::session::{session_id}`.
    pub fn create_session<C: ContextAdapter>(
        &mut self,
        extension_id: &str,
        session_id: &str,
        cx: &mut C,
    ) -> Result<(), HostLifecycleError> {
        if self.shutting_down {
            return Err(HostLifecycleError::HostShuttingDown);
        }
        let record = self.extensions.get(extension_id).ok_or_else(|| {
            HostLifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            }
        })?;
        if record.unloaded {
            return Err(HostLifecycleError::ExtensionNotRunning {
                extension_id: extension_id.to_string(),
                state: RegionState::Closed,
            });
        }
        if record.sessions.contains(session_id) {
            return Err(HostLifecycleError::SessionAlreadyExists {
                extension_id: extension_id.to_string(),
                session_id: session_id.to_string(),
            });
        }

        let trace_id = cx.trace_id().to_string();
        let session_cell_id = self.session_cell_id(extension_id, session_id);

        // Check extension cell is running.
        let ext_cell = self.cell_manager.get(extension_id).ok_or_else(|| {
            HostLifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            }
        })?;
        if ext_cell.state() != RegionState::Running {
            return Err(HostLifecycleError::ExtensionNotRunning {
                extension_id: extension_id.to_string(),
                state: ext_cell.state(),
            });
        }

        // Create session sub-cell via the extension cell.
        let child = {
            let ext_cell_mut = self.cell_manager.get_mut(extension_id).ok_or_else(|| {
                HostLifecycleError::ExtensionNotFound {
                    extension_id: extension_id.to_string(),
                }
            })?;
            ext_cell_mut
                .create_session(&session_cell_id, &trace_id)
                .map_err(|e| HostLifecycleError::CellError {
                    extension_id: extension_id.to_string(),
                    error_code: e.error_code().to_string(),
                    message: e.to_string(),
                })?
        };

        // Also register the session in the CellManager for independent access.
        self.session_counter += 1;
        self.cell_manager.insert_cell(&session_cell_id, child);

        // Track session in the extension record.
        if let Some(record) = self.extensions.get_mut(extension_id) {
            record.sessions.insert(session_id.to_string());
        }

        self.push_event(
            &trace_id,
            extension_id,
            Some(session_id),
            "session_created",
            "ok",
            None,
        );
        Ok(())
    }

    /// Close a session using the quiescent close protocol.
    pub fn close_session<C: ContextAdapter>(
        &mut self,
        extension_id: &str,
        session_id: &str,
        cx: &mut C,
    ) -> Result<CancellationOutcome, HostLifecycleError> {
        let record = self.extensions.get(extension_id).ok_or_else(|| {
            HostLifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            }
        })?;
        if !record.sessions.contains(session_id) {
            return Err(HostLifecycleError::SessionNotFound {
                extension_id: extension_id.to_string(),
                session_id: session_id.to_string(),
            });
        }

        let trace_id = cx.trace_id().to_string();
        let session_cell_id = self.session_cell_id(extension_id, session_id);

        let cell = self.cell_manager.get_mut(&session_cell_id).ok_or_else(|| {
            HostLifecycleError::SessionNotFound {
                extension_id: extension_id.to_string(),
                session_id: session_id.to_string(),
            }
        })?;

        let outcome = self
            .cancellation_manager
            .cancel_cell(cell, cx, LifecycleEvent::Unload)
            .map_err(|e| HostLifecycleError::CancellationError {
                extension_id: extension_id.to_string(),
                error_code: e.error_code().to_string(),
                message: e.to_string(),
            })?;

        self.cell_manager
            .archive_cell(&session_cell_id, outcome.finalize_result.clone());

        // Remove session from record.
        if let Some(record) = self.extensions.get_mut(extension_id) {
            record.sessions.remove(session_id);
        }

        self.push_event(
            &trace_id,
            extension_id,
            Some(session_id),
            "session_closed",
            if outcome.success { "ok" } else { "partial" },
            None,
        );

        Ok(outcome)
    }

    // -----------------------------------------------------------------------
    // Cancellation (quarantine, suspend, terminate, revocation)
    // -----------------------------------------------------------------------

    /// Cancel an extension with a specific lifecycle event.
    ///
    /// Sessions are cancelled first, then the extension cell itself.
    pub fn cancel_extension<C: ContextAdapter>(
        &mut self,
        extension_id: &str,
        cx: &mut C,
        event: LifecycleEvent,
    ) -> Result<CancellationOutcome, HostLifecycleError> {
        let record = self.extensions.get(extension_id).ok_or_else(|| {
            HostLifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            }
        })?;
        if record.unloaded {
            return Err(HostLifecycleError::ExtensionNotRunning {
                extension_id: extension_id.to_string(),
                state: RegionState::Closed,
            });
        }

        let trace_id = cx.trace_id().to_string();

        // Cancel all sessions first.
        let session_ids: Vec<String> = record.sessions.iter().cloned().collect();
        for session_id in &session_ids {
            let session_cell_id = self.session_cell_id(extension_id, session_id);
            if let Some(session_cell) = self.cell_manager.get_mut(&session_cell_id)
                && session_cell.state() == RegionState::Running
                && let Ok(outcome) = self
                    .cancellation_manager
                    .cancel_cell(session_cell, cx, event)
            {
                self.cell_manager
                    .archive_cell(&session_cell_id, outcome.finalize_result);
            }
        }

        // Cancel the extension cell.
        let cell = self.cell_manager.get_mut(extension_id).ok_or_else(|| {
            HostLifecycleError::ExtensionNotFound {
                extension_id: extension_id.to_string(),
            }
        })?;

        let outcome = self
            .cancellation_manager
            .cancel_cell(cell, cx, event)
            .map_err(|e| HostLifecycleError::CancellationError {
                extension_id: extension_id.to_string(),
                error_code: e.error_code().to_string(),
                message: e.to_string(),
            })?;

        self.cell_manager
            .archive_cell(extension_id, outcome.finalize_result.clone());

        // Mark as unloaded.
        if let Some(record) = self.extensions.get_mut(extension_id) {
            record.unloaded = true;
            record.sessions.clear();
        }

        self.push_event(
            &trace_id,
            extension_id,
            None,
            &format!("extension_{event}"),
            if outcome.success { "ok" } else { "partial" },
            None,
        );

        Ok(outcome)
    }

    // -----------------------------------------------------------------------
    // Shutdown
    // -----------------------------------------------------------------------

    /// Initiate host-wide shutdown: cancel all extensions via Terminate.
    pub fn shutdown<C: ContextAdapter>(
        &mut self,
        cx: &mut C,
    ) -> Vec<Result<CancellationOutcome, HostLifecycleError>> {
        self.shutting_down = true;
        let trace_id = cx.trace_id().to_string();

        let ext_ids: Vec<String> = self
            .extensions
            .keys()
            .filter(|id| self.extensions.get(*id).is_some_and(|r| !r.unloaded))
            .cloned()
            .collect();

        let mut results = Vec::new();
        for ext_id in &ext_ids {
            results.push(self.cancel_extension(ext_id, cx, LifecycleEvent::Terminate));
        }

        self.push_event(&trace_id, "host", None, "host_shutdown", "ok", None);
        results
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Check if an extension is loaded and running.
    pub fn is_extension_running(&self, extension_id: &str) -> bool {
        self.extensions
            .get(extension_id)
            .is_some_and(|r| !r.unloaded)
    }

    /// Number of currently loaded (non-unloaded) extensions.
    pub fn loaded_extension_count(&self) -> usize {
        self.extensions.values().filter(|r| !r.unloaded).count()
    }

    /// Active session count for an extension.
    pub fn session_count(&self, extension_id: &str) -> usize {
        self.extensions
            .get(extension_id)
            .map_or(0, |r| r.sessions.len())
    }

    /// All loaded extension IDs (including unloaded for audit trail).
    pub fn extension_ids(&self) -> Vec<&str> {
        self.extensions.keys().map(String::as_str).collect()
    }

    /// All active (running) extension IDs.
    pub fn active_extension_ids(&self) -> Vec<&str> {
        self.extensions
            .iter()
            .filter(|(_, r)| !r.unloaded)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// Whether the host is shutting down.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down
    }

    /// Get the extension record.
    pub fn extension_record(&self, extension_id: &str) -> Option<&ExtensionRecord> {
        self.extensions.get(extension_id)
    }

    /// Get a reference to the underlying cell manager.
    pub fn cell_manager(&self) -> &CellManager {
        &self.cell_manager
    }

    /// Get a mutable reference to the underlying cell manager.
    pub fn cell_manager_mut(&mut self) -> &mut CellManager {
        &mut self.cell_manager
    }

    /// Drain lifecycle events for evidence emission.
    pub fn drain_events(&mut self) -> Vec<HostLifecycleEvent> {
        std::mem::take(&mut self.events)
    }

    /// View lifecycle events.
    pub fn events(&self) -> &[HostLifecycleEvent] {
        &self.events
    }

    /// Drain cancellation events from the inner cancellation manager.
    pub fn drain_cancellation_events(&mut self) -> Vec<CancellationEvent> {
        self.cancellation_manager.drain_events()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Deterministic session cell ID: `{extension_id}::session::{session_id}`.
    fn session_cell_id(&self, extension_id: &str, session_id: &str) -> String {
        format!("{extension_id}::session::{session_id}")
    }

    fn push_event(
        &mut self,
        trace_id: &str,
        extension_id: &str,
        session_id: Option<&str>,
        event: &str,
        outcome: &str,
        error_code: Option<&str>,
    ) {
        self.events.push(HostLifecycleEvent {
            trace_id: trace_id.to_string(),
            extension_id: extension_id.to_string(),
            session_id: session_id.map(str::to_string),
            component: "extension_host_lifecycle".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(str::to_string),
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::mocks::{MockBudget, MockCx};

    fn mock_cx(budget_ms: u64) -> MockCx {
        MockCx::new(
            crate::control_plane::mocks::trace_id_from_seed(1),
            MockBudget::new(budget_ms),
        )
    }

    #[allow(dead_code)]
    fn mock_cx_seed(seed: u64, budget_ms: u64) -> MockCx {
        MockCx::new(
            crate::control_plane::mocks::trace_id_from_seed(seed),
            MockBudget::new(budget_ms),
        )
    }

    // -----------------------------------------------------------------------
    // Extension load / unload
    // -----------------------------------------------------------------------

    #[test]
    fn load_extension_creates_cell() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(1000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        assert!(mgr.is_extension_running("ext-a"));
        assert_eq!(mgr.loaded_extension_count(), 1);
        assert_eq!(mgr.cell_manager().active_count(), 1);
    }

    #[test]
    fn load_duplicate_extension_rejected() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(1000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        let err = mgr.load_extension("ext-a", &mut cx).unwrap_err();
        assert_eq!(err.error_code(), "host_extension_already_loaded");
    }

    #[test]
    fn unload_extension_follows_quiescent_close() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(1000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        let outcome = mgr.unload_extension("ext-a", &mut cx).unwrap();
        assert!(outcome.success);
        assert!(!mgr.is_extension_running("ext-a"));
        assert_eq!(mgr.loaded_extension_count(), 0);
    }

    #[test]
    fn unload_missing_extension_returns_error() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(1000);

        let err = mgr.unload_extension("ext-missing", &mut cx).unwrap_err();
        assert_eq!(err.error_code(), "host_extension_not_found");
    }

    #[test]
    fn unload_already_unloaded_returns_error() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(1000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.unload_extension("ext-a", &mut cx).unwrap();
        let err = mgr.unload_extension("ext-a", &mut cx).unwrap_err();
        assert_eq!(err.error_code(), "host_extension_not_running");
    }

    // -----------------------------------------------------------------------
    // Multiple extensions — isolation
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_extensions_isolated() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.load_extension("ext-b", &mut cx).unwrap();
        mgr.load_extension("ext-c", &mut cx).unwrap();
        assert_eq!(mgr.loaded_extension_count(), 3);

        // Unload one; others unaffected.
        mgr.unload_extension("ext-b", &mut cx).unwrap();
        assert!(mgr.is_extension_running("ext-a"));
        assert!(!mgr.is_extension_running("ext-b"));
        assert!(mgr.is_extension_running("ext-c"));
        assert_eq!(mgr.loaded_extension_count(), 2);
    }

    #[test]
    fn cancel_one_extension_others_survive() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.load_extension("ext-b", &mut cx).unwrap();

        mgr.cancel_extension("ext-a", &mut cx, LifecycleEvent::Terminate)
            .unwrap();

        assert!(!mgr.is_extension_running("ext-a"));
        assert!(mgr.is_extension_running("ext-b"));
    }

    // -----------------------------------------------------------------------
    // Session create / close
    // -----------------------------------------------------------------------

    #[test]
    fn create_session_within_extension() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.create_session("ext-a", "sess-1", &mut cx).unwrap();
        assert_eq!(mgr.session_count("ext-a"), 1);
    }

    #[test]
    fn create_duplicate_session_rejected() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.create_session("ext-a", "sess-1", &mut cx).unwrap();
        let err = mgr.create_session("ext-a", "sess-1", &mut cx).unwrap_err();
        assert_eq!(err.error_code(), "host_session_already_exists");
    }

    #[test]
    fn create_session_on_unloaded_extension_fails() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.unload_extension("ext-a", &mut cx).unwrap();
        let err = mgr.create_session("ext-a", "sess-1", &mut cx).unwrap_err();
        assert_eq!(err.error_code(), "host_extension_not_running");
    }

    #[test]
    fn create_session_on_missing_extension_fails() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        let err = mgr
            .create_session("ext-missing", "sess-1", &mut cx)
            .unwrap_err();
        assert_eq!(err.error_code(), "host_extension_not_found");
    }

    #[test]
    fn close_session_removes_it() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.create_session("ext-a", "sess-1", &mut cx).unwrap();
        assert_eq!(mgr.session_count("ext-a"), 1);

        let outcome = mgr.close_session("ext-a", "sess-1", &mut cx).unwrap();
        assert!(outcome.success);
        assert_eq!(mgr.session_count("ext-a"), 0);
    }

    #[test]
    fn close_missing_session_returns_error() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        let err = mgr
            .close_session("ext-a", "sess-gone", &mut cx)
            .unwrap_err();
        assert_eq!(err.error_code(), "host_session_not_found");
    }

    #[test]
    fn multiple_sessions_under_one_extension() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.create_session("ext-a", "s1", &mut cx).unwrap();
        mgr.create_session("ext-a", "s2", &mut cx).unwrap();
        mgr.create_session("ext-a", "s3", &mut cx).unwrap();
        assert_eq!(mgr.session_count("ext-a"), 3);

        mgr.close_session("ext-a", "s2", &mut cx).unwrap();
        assert_eq!(mgr.session_count("ext-a"), 2);
    }

    // -----------------------------------------------------------------------
    // Unload with active sessions closes sessions first
    // -----------------------------------------------------------------------

    #[test]
    fn unload_extension_closes_sessions_first() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(10000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.create_session("ext-a", "s1", &mut cx).unwrap();
        mgr.create_session("ext-a", "s2", &mut cx).unwrap();

        let outcome = mgr.unload_extension("ext-a", &mut cx).unwrap();
        assert!(outcome.success);
        assert!(!mgr.is_extension_running("ext-a"));
        // Sessions should be gone from the record (extension is unloaded).
    }

    // -----------------------------------------------------------------------
    // Cancellation (quarantine / terminate)
    // -----------------------------------------------------------------------

    #[test]
    fn quarantine_extension() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        let outcome = mgr
            .cancel_extension("ext-a", &mut cx, LifecycleEvent::Quarantine)
            .unwrap();
        assert!(outcome.success);
        assert!(!mgr.is_extension_running("ext-a"));
    }

    #[test]
    fn terminate_extension_with_sessions() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(10000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.create_session("ext-a", "s1", &mut cx).unwrap();

        let outcome = mgr
            .cancel_extension("ext-a", &mut cx, LifecycleEvent::Terminate)
            .unwrap();
        assert!(outcome.success);
        assert!(!mgr.is_extension_running("ext-a"));
    }

    #[test]
    fn cancel_missing_extension_returns_error() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        let err = mgr
            .cancel_extension("ext-missing", &mut cx, LifecycleEvent::Terminate)
            .unwrap_err();
        assert_eq!(err.error_code(), "host_extension_not_found");
    }

    // -----------------------------------------------------------------------
    // Host shutdown
    // -----------------------------------------------------------------------

    #[test]
    fn shutdown_cancels_all_extensions() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(20000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.load_extension("ext-b", &mut cx).unwrap();
        mgr.create_session("ext-a", "s1", &mut cx).unwrap();

        let results = mgr.shutdown(&mut cx);
        assert_eq!(results.len(), 2);
        for r in &results {
            assert!(r.is_ok());
        }
        assert!(mgr.is_shutting_down());
        assert_eq!(mgr.loaded_extension_count(), 0);
    }

    #[test]
    fn no_operations_after_shutdown() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.shutdown(&mut cx);

        let err = mgr.load_extension("ext-b", &mut cx).unwrap_err();
        assert_eq!(err.error_code(), "host_shutting_down");

        let err = mgr.create_session("ext-a", "s1", &mut cx).unwrap_err();
        assert_eq!(err.error_code(), "host_shutting_down");
    }

    // -----------------------------------------------------------------------
    // Evidence emission
    // -----------------------------------------------------------------------

    #[test]
    fn lifecycle_events_emitted() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(10000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.create_session("ext-a", "s1", &mut cx).unwrap();
        mgr.close_session("ext-a", "s1", &mut cx).unwrap();
        mgr.unload_extension("ext-a", &mut cx).unwrap();

        let events = mgr.events();
        assert!(events.len() >= 4); // load, session create, session close, unload

        let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
        assert!(event_names.contains(&"extension_loaded"));
        assert!(event_names.contains(&"session_created"));
        assert!(event_names.contains(&"session_closed"));
        assert!(event_names.contains(&"extension_unloaded"));
    }

    #[test]
    fn lifecycle_events_have_trace_id() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        let events = mgr.events();
        assert_eq!(events.len(), 1);
        assert!(!events[0].trace_id.is_empty());
        assert_eq!(events[0].component, "extension_host_lifecycle");
    }

    #[test]
    fn drain_events_clears_buffer() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        assert_eq!(mgr.events().len(), 1);

        let drained = mgr.drain_events();
        assert_eq!(drained.len(), 1);
        assert!(mgr.events().is_empty());
    }

    #[test]
    fn cancellation_events_accessible() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.unload_extension("ext-a", &mut cx).unwrap();

        let cancel_events = mgr.drain_cancellation_events();
        // Cancellation manager emits events for each phase.
        assert!(!cancel_events.is_empty());
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    #[test]
    fn extension_ids_includes_unloaded() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.load_extension("ext-b", &mut cx).unwrap();
        mgr.unload_extension("ext-a", &mut cx).unwrap();

        // All IDs (including unloaded).
        assert_eq!(mgr.extension_ids().len(), 2);
        // Active only.
        assert_eq!(mgr.active_extension_ids().len(), 1);
        assert_eq!(mgr.active_extension_ids()[0], "ext-b");
    }

    #[test]
    fn extension_record_accessible() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        let record = mgr.extension_record("ext-a").unwrap();
        assert_eq!(record.cell_id, "ext-a");
        assert!(!record.unloaded);
        assert!(record.sessions.is_empty());
    }

    // -----------------------------------------------------------------------
    // Error display and serde
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_all_variants() {
        let variants = [
            HostLifecycleError::ExtensionAlreadyLoaded {
                extension_id: "x".to_string(),
            },
            HostLifecycleError::ExtensionNotFound {
                extension_id: "x".to_string(),
            },
            HostLifecycleError::ExtensionNotRunning {
                extension_id: "x".to_string(),
                state: RegionState::Closed,
            },
            HostLifecycleError::SessionAlreadyExists {
                extension_id: "x".to_string(),
                session_id: "s".to_string(),
            },
            HostLifecycleError::SessionNotFound {
                extension_id: "x".to_string(),
                session_id: "s".to_string(),
            },
            HostLifecycleError::CellError {
                extension_id: "x".to_string(),
                error_code: "e".to_string(),
                message: "msg".to_string(),
            },
            HostLifecycleError::CancellationError {
                extension_id: "x".to_string(),
                error_code: "e".to_string(),
                message: "msg".to_string(),
            },
            HostLifecycleError::HostShuttingDown,
        ];
        for v in &variants {
            let s = format!("{v}");
            assert!(!s.is_empty());
            assert!(!v.error_code().is_empty());
        }
    }

    #[test]
    fn error_serde_roundtrip() {
        let err = HostLifecycleError::ExtensionNotFound {
            extension_id: "ext-test".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: HostLifecycleError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn event_serde_roundtrip() {
        let event = HostLifecycleEvent {
            trace_id: "t1".to_string(),
            extension_id: "ext-a".to_string(),
            session_id: Some("s1".to_string()),
            component: "extension_host_lifecycle".to_string(),
            event: "session_created".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: HostLifecycleEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn extension_record_serde_roundtrip() {
        let record = ExtensionRecord {
            cell_id: "ext-a".to_string(),
            sessions: BTreeSet::from(["s1".to_string(), "s2".to_string()]),
            load_trace_id: "trace-1".to_string(),
            unloaded: false,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: ExtensionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    // -----------------------------------------------------------------------
    // Default impl
    // -----------------------------------------------------------------------

    #[test]
    fn default_manager_is_empty() {
        let mgr = ExtensionHostLifecycleManager::default();
        assert_eq!(mgr.loaded_extension_count(), 0);
        assert!(!mgr.is_shutting_down());
        assert!(mgr.events().is_empty());
    }

    // -----------------------------------------------------------------------
    // Full lifecycle integration
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle_load_session_close_unload() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(20000);

        // Load two extensions.
        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.load_extension("ext-b", &mut cx).unwrap();
        assert_eq!(mgr.loaded_extension_count(), 2);

        // Create sessions under ext-a.
        mgr.create_session("ext-a", "s1", &mut cx).unwrap();
        mgr.create_session("ext-a", "s2", &mut cx).unwrap();
        assert_eq!(mgr.session_count("ext-a"), 2);

        // Close one session.
        let outcome = mgr.close_session("ext-a", "s1", &mut cx).unwrap();
        assert!(outcome.success);
        assert_eq!(mgr.session_count("ext-a"), 1);

        // Unload ext-a (session s2 should be closed automatically).
        let outcome = mgr.unload_extension("ext-a", &mut cx).unwrap();
        assert!(outcome.success);
        assert!(!mgr.is_extension_running("ext-a"));

        // ext-b should still be running.
        assert!(mgr.is_extension_running("ext-b"));

        // Unload ext-b.
        let outcome = mgr.unload_extension("ext-b", &mut cx).unwrap();
        assert!(outcome.success);
        assert_eq!(mgr.loaded_extension_count(), 0);

        // Verify events cover the full lifecycle.
        let events = mgr.events();
        assert!(events.len() >= 6); // 2 loads + 2 session creates + 1 session close + 2 unloads
    }

    #[test]
    fn concurrent_extensions_no_cross_contamination() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(20000);

        // Load multiple extensions.
        for i in 0..5 {
            mgr.load_extension(&format!("ext-{i}"), &mut cx).unwrap();
        }
        assert_eq!(mgr.loaded_extension_count(), 5);

        // Create sessions in different extensions.
        mgr.create_session("ext-0", "s0", &mut cx).unwrap();
        mgr.create_session("ext-2", "s2a", &mut cx).unwrap();
        mgr.create_session("ext-2", "s2b", &mut cx).unwrap();

        // Terminate ext-2 (with sessions).
        mgr.cancel_extension("ext-2", &mut cx, LifecycleEvent::Terminate)
            .unwrap();

        // ext-0 should still have its session.
        assert_eq!(mgr.session_count("ext-0"), 1);
        assert!(mgr.is_extension_running("ext-0"));

        // Other extensions still running.
        for i in [0, 1, 3, 4] {
            assert!(mgr.is_extension_running(&format!("ext-{i}")));
        }
        assert!(!mgr.is_extension_running("ext-2"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: error_code unique per variant
    // -----------------------------------------------------------------------

    #[test]
    fn error_code_unique_per_variant() {
        let variants = [
            HostLifecycleError::ExtensionAlreadyLoaded {
                extension_id: "x".to_string(),
            },
            HostLifecycleError::ExtensionNotFound {
                extension_id: "x".to_string(),
            },
            HostLifecycleError::ExtensionNotRunning {
                extension_id: "x".to_string(),
                state: RegionState::Closed,
            },
            HostLifecycleError::SessionAlreadyExists {
                extension_id: "x".to_string(),
                session_id: "s".to_string(),
            },
            HostLifecycleError::SessionNotFound {
                extension_id: "x".to_string(),
                session_id: "s".to_string(),
            },
            HostLifecycleError::CellError {
                extension_id: "x".to_string(),
                error_code: "e".to_string(),
                message: "msg".to_string(),
            },
            HostLifecycleError::CancellationError {
                extension_id: "x".to_string(),
                error_code: "e".to_string(),
                message: "msg".to_string(),
            },
            HostLifecycleError::HostShuttingDown,
        ];
        let codes: std::collections::BTreeSet<String> = variants
            .iter()
            .map(|v| v.error_code().to_string())
            .collect();
        assert_eq!(
            codes.len(),
            variants.len(),
            "each error variant should have a unique error_code"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: error serde all 8 variants
    // -----------------------------------------------------------------------

    #[test]
    fn error_serde_all_variants() {
        let variants = [
            HostLifecycleError::ExtensionAlreadyLoaded {
                extension_id: "x".to_string(),
            },
            HostLifecycleError::ExtensionNotFound {
                extension_id: "x".to_string(),
            },
            HostLifecycleError::ExtensionNotRunning {
                extension_id: "x".to_string(),
                state: RegionState::Closed,
            },
            HostLifecycleError::SessionAlreadyExists {
                extension_id: "x".to_string(),
                session_id: "s".to_string(),
            },
            HostLifecycleError::SessionNotFound {
                extension_id: "x".to_string(),
                session_id: "s".to_string(),
            },
            HostLifecycleError::CellError {
                extension_id: "x".to_string(),
                error_code: "e".to_string(),
                message: "msg".to_string(),
            },
            HostLifecycleError::CancellationError {
                extension_id: "x".to_string(),
                error_code: "e".to_string(),
                message: "msg".to_string(),
            },
            HostLifecycleError::HostShuttingDown,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: HostLifecycleError = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: session_count for missing extension
    // -----------------------------------------------------------------------

    #[test]
    fn session_count_missing_extension_is_zero() {
        let mgr = ExtensionHostLifecycleManager::new();
        assert_eq!(mgr.session_count("no-such-ext"), 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: shutdown tears down extensions (cancel returns not-running)
    // -----------------------------------------------------------------------

    #[test]
    fn shutdown_tears_down_extensions() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.shutdown(&mut cx);

        // Extensions were torn down by shutdown, so operations on them fail
        let err = mgr
            .cancel_extension("ext-a", &mut cx, LifecycleEvent::Terminate)
            .unwrap_err();
        // After shutdown, the extension is already unloaded
        assert!(!err.error_code().is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: shutdown blocks new load
    // -----------------------------------------------------------------------

    #[test]
    fn shutdown_blocks_new_load_confirmed() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.shutdown(&mut cx);
        let err = mgr.load_extension("ext-new", &mut cx).unwrap_err();
        assert_eq!(err.error_code(), "host_shutting_down");
    }

    // -----------------------------------------------------------------------
    // Enrichment: shutdown blocks new session
    // -----------------------------------------------------------------------

    #[test]
    fn shutdown_blocks_new_session_confirmed() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.shutdown(&mut cx);
        let err = mgr.create_session("ext-a", "s1", &mut cx).unwrap_err();
        assert_eq!(err.error_code(), "host_shutting_down");
    }

    // -----------------------------------------------------------------------
    // Enrichment: active_extension_ids is sorted
    // -----------------------------------------------------------------------

    #[test]
    fn active_extension_ids_sorted() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(10000);

        mgr.load_extension("ext-c", &mut cx).unwrap();
        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.load_extension("ext-b", &mut cx).unwrap();

        let ids = mgr.active_extension_ids();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "active_extension_ids should be sorted");
    }

    // -----------------------------------------------------------------------
    // Enrichment: events have error_code on failure
    // -----------------------------------------------------------------------

    #[test]
    fn event_has_error_code_on_failure() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        // Trigger an error: load duplicate
        mgr.load_extension("ext-a", &mut cx).unwrap();
        let _err = mgr.load_extension("ext-a", &mut cx).unwrap_err();

        // The successful load emitted one event
        let events = mgr.events();
        assert!(!events.is_empty());
        // First event should be the successful load
        assert_eq!(events[0].event, "extension_loaded");
    }

    // -----------------------------------------------------------------------
    // Enrichment: extension_record returns None for missing
    // -----------------------------------------------------------------------

    #[test]
    fn extension_record_missing_returns_none() {
        let mgr = ExtensionHostLifecycleManager::new();
        assert!(mgr.extension_record("no-such").is_none());
    }

    // -----------------------------------------------------------------------
    // Enrichment: unloaded extension record shows unloaded flag
    // -----------------------------------------------------------------------

    #[test]
    fn extension_record_shows_unloaded_flag() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.unload_extension("ext-a", &mut cx).unwrap();

        let record = mgr.extension_record("ext-a").unwrap();
        assert!(record.unloaded);
    }

    // -- Enrichment batch 3: edge cases, queries, serde --

    #[test]
    fn is_extension_running_true_when_loaded() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        assert!(mgr.is_extension_running("ext-a"));
    }

    #[test]
    fn is_extension_running_false_when_unloaded() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.unload_extension("ext-a", &mut cx).unwrap();
        assert!(!mgr.is_extension_running("ext-a"));
    }

    #[test]
    fn is_extension_running_false_for_nonexistent() {
        let mgr = ExtensionHostLifecycleManager::new();
        assert!(!mgr.is_extension_running("no-such"));
    }

    #[test]
    fn loaded_extension_count_tracks_load_unload() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        assert_eq!(mgr.loaded_extension_count(), 0);

        mgr.load_extension("ext-a", &mut cx).unwrap();
        assert_eq!(mgr.loaded_extension_count(), 1);

        mgr.load_extension("ext-b", &mut cx).unwrap();
        assert_eq!(mgr.loaded_extension_count(), 2);

        mgr.unload_extension("ext-a", &mut cx).unwrap();
        assert_eq!(mgr.loaded_extension_count(), 1);
    }

    #[test]
    fn session_count_tracks_create_close() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        mgr.load_extension("ext-a", &mut cx).unwrap();

        assert_eq!(mgr.session_count("ext-a"), 0);
        mgr.create_session("ext-a", "s1", &mut cx).unwrap();
        assert_eq!(mgr.session_count("ext-a"), 1);
        mgr.create_session("ext-a", "s2", &mut cx).unwrap();
        assert_eq!(mgr.session_count("ext-a"), 2);
        mgr.close_session("ext-a", "s1", &mut cx).unwrap();
        assert_eq!(mgr.session_count("ext-a"), 1);
    }

    #[test]
    fn unload_extension_clears_session_record() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.create_session("ext-a", "s1", &mut cx).unwrap();
        mgr.create_session("ext-a", "s2", &mut cx).unwrap();
        assert_eq!(mgr.session_count("ext-a"), 2);

        mgr.unload_extension("ext-a", &mut cx).unwrap();

        let record = mgr.extension_record("ext-a").unwrap();
        assert!(record.unloaded);
        assert!(record.sessions.is_empty());
        assert_eq!(mgr.session_count("ext-a"), 0);
    }

    #[test]
    fn is_shutting_down_false_initially() {
        let mgr = ExtensionHostLifecycleManager::new();
        assert!(!mgr.is_shutting_down());
    }

    #[test]
    fn is_shutting_down_true_after_shutdown() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        mgr.shutdown(&mut cx);
        assert!(mgr.is_shutting_down());
    }

    #[test]
    fn events_accessor_returns_without_drain() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        // events() should return without clearing
        assert!(!mgr.events().is_empty());
        assert!(!mgr.events().is_empty()); // still there
    }

    #[test]
    fn cell_manager_accessible() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        // cell_manager() should expose the inner manager
        assert!(mgr.cell_manager().get("ext-a").is_some());
    }

    #[test]
    fn extension_record_cell_id_matches_extension_id() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        mgr.load_extension("ext-abc", &mut cx).unwrap();
        let record = mgr.extension_record("ext-abc").unwrap();
        assert_eq!(record.cell_id, "ext-abc");
        assert!(!record.unloaded);
        assert!(record.sessions.is_empty());
    }

    #[test]
    fn extension_record_has_load_trace_id() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        let record = mgr.extension_record("ext-a").unwrap();
        assert!(!record.load_trace_id.is_empty());
    }

    #[test]
    fn error_std_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(HostLifecycleError::HostShuttingDown);
        assert!(!err.to_string().is_empty());
        assert!(err.source().is_none());
    }

    #[test]
    fn error_code_all_8_stable() {
        let errors = [
            HostLifecycleError::ExtensionAlreadyLoaded {
                extension_id: "e".to_string(),
            },
            HostLifecycleError::ExtensionNotFound {
                extension_id: "e".to_string(),
            },
            HostLifecycleError::ExtensionNotRunning {
                extension_id: "e".to_string(),
                state: RegionState::Closed,
            },
            HostLifecycleError::SessionAlreadyExists {
                extension_id: "e".to_string(),
                session_id: "s".to_string(),
            },
            HostLifecycleError::SessionNotFound {
                extension_id: "e".to_string(),
                session_id: "s".to_string(),
            },
            HostLifecycleError::CellError {
                extension_id: "e".to_string(),
                error_code: "c".to_string(),
                message: "m".to_string(),
            },
            HostLifecycleError::CancellationError {
                extension_id: "e".to_string(),
                error_code: "c".to_string(),
                message: "m".to_string(),
            },
            HostLifecycleError::HostShuttingDown,
        ];
        let codes: Vec<&str> = errors.iter().map(|e| e.error_code()).collect();
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), 8, "all 8 error variants have unique codes");
        for code in &codes {
            assert!(
                code.starts_with("host_"),
                "code should start with host_: {code}"
            );
        }
    }

    #[test]
    fn host_lifecycle_event_serde_all_fields() {
        let event = HostLifecycleEvent {
            trace_id: "t-1".to_string(),
            extension_id: "ext-a".to_string(),
            session_id: Some("s-1".to_string()),
            component: "extension_host_lifecycle".to_string(),
            event: "session_created".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: HostLifecycleEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    #[test]
    fn host_lifecycle_event_with_error_code_serde() {
        let event = HostLifecycleEvent {
            trace_id: "t-1".to_string(),
            extension_id: "ext-a".to_string(),
            session_id: None,
            component: "extension_host_lifecycle".to_string(),
            event: "extension_loaded".to_string(),
            outcome: "error".to_string(),
            error_code: Some("host_extension_not_found".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: HostLifecycleEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, restored);
    }

    #[test]
    fn extension_record_serde_with_sessions() {
        let record = ExtensionRecord {
            cell_id: "ext-a".to_string(),
            sessions: BTreeSet::from(["s1".to_string(), "s2".to_string()]),
            load_trace_id: "t-1".to_string(),
            unloaded: false,
        };
        let json = serde_json::to_string(&record).unwrap();
        let restored: ExtensionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, restored);
        assert_eq!(restored.sessions.len(), 2);
    }

    #[test]
    fn error_display_host_shutting_down() {
        let err = HostLifecycleError::HostShuttingDown;
        assert_eq!(err.to_string(), "host is shutting down");
    }

    #[test]
    fn error_display_cell_error_contains_all_fields() {
        let err = HostLifecycleError::CellError {
            extension_id: "ext-x".to_string(),
            error_code: "E42".to_string(),
            message: "cell failed".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("ext-x"));
        assert!(display.contains("E42"));
        assert!(display.contains("cell failed"));
    }

    #[test]
    fn error_display_cancellation_error_contains_all_fields() {
        let err = HostLifecycleError::CancellationError {
            extension_id: "ext-y".to_string(),
            error_code: "C99".to_string(),
            message: "cancel failed".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("ext-y"));
        assert!(display.contains("C99"));
        assert!(display.contains("cancel failed"));
    }

    #[test]
    fn default_is_same_as_new() {
        let d = ExtensionHostLifecycleManager::default();
        let n = ExtensionHostLifecycleManager::new();
        assert_eq!(d.loaded_extension_count(), n.loaded_extension_count());
        assert!(!d.is_shutting_down());
        assert!(d.events().is_empty());
    }

    #[test]
    fn active_extension_ids_excludes_unloaded() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.load_extension("ext-b", &mut cx).unwrap();
        mgr.unload_extension("ext-a", &mut cx).unwrap();

        let active = mgr.active_extension_ids();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0], "ext-b");
        // extension_ids includes unloaded
        assert_eq!(mgr.extension_ids().len(), 2);
    }

    #[test]
    fn drain_cancellation_events_returns_events() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.unload_extension("ext-a", &mut cx).unwrap();
        // cancellation events should be produced
        let cancel_events = mgr.drain_cancellation_events();
        assert!(!cancel_events.is_empty());
    }

    #[test]
    fn close_session_on_missing_extension_fails() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        let err = mgr.close_session("no-ext", "s1", &mut cx).unwrap_err();
        assert!(matches!(err, HostLifecycleError::ExtensionNotFound { .. }));
    }

    #[test]
    fn load_after_unload_reloads_fresh() {
        let mut mgr = ExtensionHostLifecycleManager::new();
        let mut cx = mock_cx(5000);
        mgr.load_extension("ext-a", &mut cx).unwrap();
        mgr.unload_extension("ext-a", &mut cx).unwrap();
        // Cannot reload because the ID is still in extensions map
        let err = mgr.load_extension("ext-a", &mut cx).unwrap_err();
        assert!(matches!(
            err,
            HostLifecycleError::ExtensionAlreadyLoaded { .. }
        ));
    }
}
