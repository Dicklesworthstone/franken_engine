#![forbid(unsafe_code)]

//! Promise-driven async-module settlement bridge.
//!
//! `module_async_evaluation` owns deterministic module dependency, suspension,
//! rejection, and live-binding semantics. `promise_model` owns Promise state and
//! microtask ordering. Historically those two state machines carried matching
//! `PromiseHandle`s without a shipped owner that observed the real
//! `PromiseStore` and advanced module evaluation when those Promises settled.
//!
//! This module is that narrow composition seam. It deliberately does not
//! execute JavaScript and it does not invent another scheduler. The interpreter
//! remains responsible for executing/resuming module bodies; this bridge owns
//! the transition from an actual module-evaluation Promise settlement to the
//! existing async-module state machine and returns dependency-ready modules to
//! the caller.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ifc_artifacts::Label;
use crate::module_async_evaluation::{
    AsyncEvalConfig, AsyncEvalError, AsyncModuleEvaluator, AsyncModulePhase, RejectionLinkage,
};
use crate::module_live_binding::LiveBindingMap;
use crate::object_model::JsValue;
use crate::promise_model::{MicrotaskQueue, PromiseError, PromiseHandle, PromiseState, PromiseStore};

/// Stable component label for runtime evidence and diagnostics.
pub const ASYNC_MODULE_PROMISE_BRIDGE_COMPONENT: &str = "async_module_promise_bridge";

/// The Promise state observed while synchronizing a module evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModulePromiseStatus {
    Pending,
    Fulfilled,
    Rejected,
}

/// Deterministic result of observing one module-evaluation Promise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModulePromiseUpdate {
    pub module_specifier: String,
    pub promise: PromiseHandle,
    pub status: ModulePromiseStatus,
    /// Modules whose declared async dependencies are all settled and whose body
    /// execution may therefore be resumed by the owning interpreter/module lane.
    pub dependency_ready: Vec<String>,
    /// Rejection lineage emitted when this settlement rejected the module.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_linkage: Option<RejectionLinkage>,
}

/// Errors at the Promise/module composition boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsyncModulePromiseBridgeError {
    UnknownModule { specifier: String },
    DuplicateModule { specifier: String },
    MissingEvaluationPromise { specifier: String },
    PromiseOperation {
        specifier: String,
        promise: PromiseHandle,
        detail: String,
    },
    ModuleEvaluation {
        specifier: String,
        detail: String,
    },
    InconsistentTerminalState {
        specifier: String,
        promise: PromiseHandle,
        promise_status: ModulePromiseStatus,
        module_phase: AsyncModulePhase,
    },
}

impl fmt::Display for AsyncModulePromiseBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownModule { specifier } => write!(f, "unknown async module: {specifier}"),
            Self::DuplicateModule { specifier } => {
                write!(f, "async module already registered: {specifier}")
            }
            Self::MissingEvaluationPromise { specifier } => {
                write!(f, "module has no evaluation Promise: {specifier}")
            }
            Self::PromiseOperation {
                specifier,
                promise,
                detail,
            } => write!(
                f,
                "Promise operation failed for {specifier} ({promise}): {detail}"
            ),
            Self::ModuleEvaluation { specifier, detail } => {
                write!(f, "async module evaluation failed for {specifier}: {detail}")
            }
            Self::InconsistentTerminalState {
                specifier,
                promise,
                promise_status,
                module_phase,
            } => write!(
                f,
                "inconsistent async-module settlement for {specifier} ({promise}): Promise is {promise_status:?} while module phase is {module_phase}"
            ),
        }
    }
}

impl std::error::Error for AsyncModulePromiseBridgeError {}

/// Owns the Promise and async-module state machines at their runtime boundary.
///
/// Module registration is deterministic: every top-level-await module receives
/// a real `PromiseStore` handle immediately, so there is no fabricated
/// `PromiseHandle(0)` sentinel. Registration order therefore determines handles
/// and is itself replayable.
pub struct AsyncModulePromiseBridge {
    evaluator: AsyncModuleEvaluator,
    promises: PromiseStore,
    microtasks: MicrotaskQueue,
    live_bindings: LiveBindingMap,
    module_promises: BTreeMap<String, PromiseHandle>,
}

impl AsyncModulePromiseBridge {
    pub fn new(config: AsyncEvalConfig) -> Self {
        Self {
            evaluator: AsyncModuleEvaluator::new(config),
            promises: PromiseStore::new(),
            microtasks: MicrotaskQueue::new(),
            live_bindings: LiveBindingMap::new(),
            module_promises: BTreeMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(AsyncEvalConfig::default())
    }

    /// Register a module and allocate its real evaluation Promise when needed.
    ///
    /// Dependencies should be registered before dependents, matching the
    /// topological registration contract of `AsyncModuleEvaluator`.
    pub fn register_module(
        &mut self,
        specifier: &str,
        has_top_level_await: bool,
        dependencies: &[String],
    ) -> Result<Option<PromiseHandle>, AsyncModulePromiseBridgeError> {
        if self.evaluator.states().contains_key(specifier) {
            return Err(AsyncModulePromiseBridgeError::DuplicateModule {
                specifier: specifier.to_string(),
            });
        }

        let evaluation_promise = has_top_level_await.then(|| self.promises.create());
        self.evaluator.register_module(
            specifier,
            has_top_level_await,
            dependencies,
            evaluation_promise,
        );
        if let Some(promise) = evaluation_promise {
            self.module_promises.insert(specifier.to_string(), promise);
        }
        Ok(evaluation_promise)
    }

    /// Return the real evaluation Promise allocated for a TLA module.
    pub fn module_promise(&self, specifier: &str) -> Option<PromiseHandle> {
        self.module_promises.get(specifier).copied()
    }

    /// Fulfill a module's real evaluation Promise and synchronize module state.
    pub fn fulfill_module(
        &mut self,
        specifier: &str,
        value: JsValue,
        label: Label,
    ) -> Result<ModulePromiseUpdate, AsyncModulePromiseBridgeError> {
        let promise = self.require_module_promise(specifier)?;
        self.promises
            .fulfill(promise, value, label, &mut self.microtasks)
            .map_err(|error| self.promise_error(specifier, promise, error))?;
        self.synchronize_module(specifier)
    }

    /// Reject a module's real evaluation Promise and synchronize rejection
    /// propagation through the declared module graph and live bindings.
    pub fn reject_module(
        &mut self,
        specifier: &str,
        reason: JsValue,
        label: Label,
    ) -> Result<ModulePromiseUpdate, AsyncModulePromiseBridgeError> {
        let promise = self.require_module_promise(specifier)?;
        self.promises
            .reject(promise, reason, label, &mut self.microtasks)
            .map_err(|error| self.promise_error(specifier, promise, error))?;
        self.synchronize_module(specifier)
    }

    /// Observe the real Promise state for one module and advance the existing
    /// async-module evaluator exactly once when a terminal settlement appears.
    pub fn synchronize_module(
        &mut self,
        specifier: &str,
    ) -> Result<ModulePromiseUpdate, AsyncModulePromiseBridgeError> {
        let promise = self.require_module_promise(specifier)?;
        let promise_state = self
            .promises
            .get(promise)
            .map_err(|error| self.promise_error(specifier, promise, error))?
            .state
            .clone();
        let module_phase = self
            .evaluator
            .states()
            .get(specifier)
            .ok_or_else(|| AsyncModulePromiseBridgeError::UnknownModule {
                specifier: specifier.to_string(),
            })?
            .phase;

        match promise_state {
            PromiseState::Pending => {
                if matches!(module_phase, AsyncModulePhase::Settled | AsyncModulePhase::Rejected) {
                    return Err(AsyncModulePromiseBridgeError::InconsistentTerminalState {
                        specifier: specifier.to_string(),
                        promise,
                        promise_status: ModulePromiseStatus::Pending,
                        module_phase,
                    });
                }
                Ok(ModulePromiseUpdate {
                    module_specifier: specifier.to_string(),
                    promise,
                    status: ModulePromiseStatus::Pending,
                    dependency_ready: Vec::new(),
                    rejection_linkage: None,
                })
            }
            PromiseState::Fulfilled(_) => {
                if module_phase == AsyncModulePhase::Rejected {
                    return Err(AsyncModulePromiseBridgeError::InconsistentTerminalState {
                        specifier: specifier.to_string(),
                        promise,
                        promise_status: ModulePromiseStatus::Fulfilled,
                        module_phase,
                    });
                }
                let dependency_ready = if module_phase == AsyncModulePhase::Settled {
                    Vec::new()
                } else {
                    self.evaluator
                        .settle_module(specifier)
                        .map_err(|error| self.module_error(specifier, error))?
                };
                Ok(ModulePromiseUpdate {
                    module_specifier: specifier.to_string(),
                    promise,
                    status: ModulePromiseStatus::Fulfilled,
                    dependency_ready,
                    rejection_linkage: None,
                })
            }
            PromiseState::Rejected(reason) => {
                if matches!(module_phase, AsyncModulePhase::Settled | AsyncModulePhase::Synchronous)
                {
                    return Err(AsyncModulePromiseBridgeError::InconsistentTerminalState {
                        specifier: specifier.to_string(),
                        promise,
                        promise_status: ModulePromiseStatus::Rejected,
                        module_phase,
                    });
                }
                let rejection_linkage = if module_phase == AsyncModulePhase::Rejected {
                    None
                } else {
                    Some(
                        self.evaluator
                            .reject_module(specifier, &reason, &mut self.live_bindings)
                            .map_err(|error| self.module_error(specifier, error))?,
                    )
                };
                Ok(ModulePromiseUpdate {
                    module_specifier: specifier.to_string(),
                    promise,
                    status: ModulePromiseStatus::Rejected,
                    dependency_ready: Vec::new(),
                    rejection_linkage,
                })
            }
        }
    }

    /// Synchronize every registered module-evaluation Promise in canonical
    /// module-specifier order. Pending Promises are reported but do not mutate
    /// module state.
    pub fn synchronize_all(
        &mut self,
    ) -> Result<Vec<ModulePromiseUpdate>, AsyncModulePromiseBridgeError> {
        let modules: Vec<String> = self.module_promises.keys().cloned().collect();
        modules
            .iter()
            .map(|specifier| self.synchronize_module(specifier))
            .collect()
    }

    /// Mark a non-TLA module body as complete after the interpreter executes it.
    /// This wakes declared dependents through the same evaluator path used by
    /// fulfilled async-module Promises.
    pub fn complete_synchronous_module(
        &mut self,
        specifier: &str,
    ) -> Result<Vec<String>, AsyncModulePromiseBridgeError> {
        let state = self
            .evaluator
            .states()
            .get(specifier)
            .ok_or_else(|| AsyncModulePromiseBridgeError::UnknownModule {
                specifier: specifier.to_string(),
            })?;
        if state.has_top_level_await {
            return Err(AsyncModulePromiseBridgeError::ModuleEvaluation {
                specifier: specifier.to_string(),
                detail: "top-level-await modules must complete by settling their evaluation Promise"
                    .to_string(),
            });
        }
        self.evaluator
            .settle_module(specifier)
            .map_err(|error| self.module_error(specifier, error))
    }

    pub fn evaluator(&self) -> &AsyncModuleEvaluator {
        &self.evaluator
    }

    pub fn promise_store(&self) -> &PromiseStore {
        &self.promises
    }

    pub fn microtasks(&self) -> &MicrotaskQueue {
        &self.microtasks
    }

    pub fn live_bindings(&self) -> &LiveBindingMap {
        &self.live_bindings
    }

    pub fn live_bindings_mut(&mut self) -> &mut LiveBindingMap {
        &mut self.live_bindings
    }

    fn require_module_promise(
        &self,
        specifier: &str,
    ) -> Result<PromiseHandle, AsyncModulePromiseBridgeError> {
        if !self.evaluator.states().contains_key(specifier) {
            return Err(AsyncModulePromiseBridgeError::UnknownModule {
                specifier: specifier.to_string(),
            });
        }
        self.module_promises.get(specifier).copied().ok_or_else(|| {
            AsyncModulePromiseBridgeError::MissingEvaluationPromise {
                specifier: specifier.to_string(),
            }
        })
    }

    fn promise_error(
        &self,
        specifier: &str,
        promise: PromiseHandle,
        error: PromiseError,
    ) -> AsyncModulePromiseBridgeError {
        AsyncModulePromiseBridgeError::PromiseOperation {
            specifier: specifier.to_string(),
            promise,
            detail: error.to_string(),
        }
    }

    fn module_error(
        &self,
        specifier: &str,
        error: AsyncEvalError,
    ) -> AsyncModulePromiseBridgeError {
        AsyncModulePromiseBridgeError::ModuleEvaluation {
            specifier: specifier.to_string(),
            detail: error.to_string(),
        }
    }
}

impl Default for AsyncModulePromiseBridge {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::esm_loader::BindingType;
    use crate::module_live_binding::{BindingCell, BindingCellState};

    fn public_label() -> Label {
        Label::Public
    }

    #[test]
    fn registers_real_evaluation_promise() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        let promise = bridge
            .register_module("a.mjs", true, &[])
            .expect("register")
            .expect("TLA promise");
        assert_eq!(promise, PromiseHandle(0));
        assert_eq!(bridge.module_promise("a.mjs"), Some(promise));
        assert!(bridge.promise_store().get(promise).is_ok());
    }

    #[test]
    fn synchronous_module_has_no_evaluation_promise() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        assert_eq!(bridge.register_module("a.mjs", false, &[]).unwrap(), None);
        assert_eq!(bridge.module_promise("a.mjs"), None);
    }

    #[test]
    fn duplicate_registration_is_rejected_without_allocating_promise() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        let first = bridge.register_module("a.mjs", true, &[]).unwrap().unwrap();
        let error = bridge.register_module("a.mjs", true, &[]).unwrap_err();
        assert!(matches!(error, AsyncModulePromiseBridgeError::DuplicateModule { .. }));
        assert_eq!(bridge.module_promise("a.mjs"), Some(first));
    }

    #[test]
    fn promise_handles_are_monotonic_and_replay_stable() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        let a = bridge.register_module("a.mjs", true, &[]).unwrap().unwrap();
        bridge.register_module("sync.mjs", false, &[]).unwrap();
        let b = bridge.register_module("b.mjs", true, &[]).unwrap().unwrap();
        assert_eq!(a, PromiseHandle(0));
        assert_eq!(b, PromiseHandle(1));
    }

    #[test]
    fn pending_promise_keeps_module_suspended() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        let update = bridge.synchronize_module("a.mjs").unwrap();
        assert_eq!(update.status, ModulePromiseStatus::Pending);
        assert_eq!(bridge.evaluator().states()["a.mjs"].phase, AsyncModulePhase::Suspended);
    }

    #[test]
    fn fulfilled_promise_settles_module() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        let update = bridge
            .fulfill_module("a.mjs", JsValue::Int(7), public_label())
            .unwrap();
        assert_eq!(update.status, ModulePromiseStatus::Fulfilled);
        assert_eq!(bridge.evaluator().states()["a.mjs"].phase, AsyncModulePhase::Settled);
    }

    #[test]
    fn rejected_promise_rejects_module() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        let update = bridge
            .reject_module("a.mjs", JsValue::Str("boom".into()), public_label())
            .unwrap();
        assert_eq!(update.status, ModulePromiseStatus::Rejected);
        assert!(update.rejection_linkage.is_some());
        assert_eq!(bridge.evaluator().states()["a.mjs"].phase, AsyncModulePhase::Rejected);
    }

    #[test]
    fn fulfilled_dependency_returns_waiting_consumer_as_ready() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("dep.mjs", true, &[]).unwrap();
        bridge
            .register_module("app.mjs", false, &["dep.mjs".into()])
            .unwrap();
        let update = bridge
            .fulfill_module("dep.mjs", JsValue::Undefined, public_label())
            .unwrap();
        assert_eq!(update.dependency_ready, vec!["app.mjs".to_string()]);
        assert!(bridge.evaluator().states()["app.mjs"].all_dependencies_settled());
    }

    #[test]
    fn rejection_propagates_through_declared_dependency_graph() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("root.mjs", true, &[]).unwrap();
        bridge
            .register_module("mid.mjs", true, &["root.mjs".into()])
            .unwrap();
        bridge
            .register_module("leaf.mjs", true, &["mid.mjs".into()])
            .unwrap();
        let update = bridge
            .reject_module("root.mjs", JsValue::Str("boom".into()), public_label())
            .unwrap();
        let linkage = update.rejection_linkage.expect("linkage");
        assert!(linkage.transitive_closure.contains("mid.mjs"));
        assert!(linkage.transitive_closure.contains("leaf.mjs"));
        assert_eq!(bridge.evaluator().states()["leaf.mjs"].phase, AsyncModulePhase::Rejected);
    }

    #[test]
    fn rejection_marks_live_bindings_dead() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("bad.mjs", true, &[]).unwrap();
        let binding = bridge.live_bindings_mut().register_cell(BindingCell::new(
            "bad.mjs",
            "answer",
            "answer",
            BindingType::Direct,
        ));
        bridge
            .reject_module("bad.mjs", JsValue::Str("boom".into()), public_label())
            .unwrap();
        assert_eq!(
            bridge.live_bindings().get_cell(&binding).map(|cell| cell.state),
            Some(BindingCellState::Dead)
        );
    }

    #[test]
    fn synchronize_all_uses_canonical_module_order() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("z.mjs", true, &[]).unwrap();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        let updates = bridge.synchronize_all().unwrap();
        assert_eq!(
            updates.iter().map(|u| u.module_specifier.as_str()).collect::<Vec<_>>(),
            vec!["a.mjs", "z.mjs"]
        );
    }

    #[test]
    fn synchronization_is_idempotent_after_fulfillment() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        bridge
            .fulfill_module("a.mjs", JsValue::Undefined, public_label())
            .unwrap();
        let event_count = bridge.evaluator().witness_events().len();
        let update = bridge.synchronize_module("a.mjs").unwrap();
        assert_eq!(update.status, ModulePromiseStatus::Fulfilled);
        assert!(update.dependency_ready.is_empty());
        assert_eq!(bridge.evaluator().witness_events().len(), event_count);
    }

    #[test]
    fn synchronization_is_idempotent_after_rejection() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        bridge
            .reject_module("a.mjs", JsValue::Str("boom".into()), public_label())
            .unwrap();
        let event_count = bridge.evaluator().witness_events().len();
        let update = bridge.synchronize_module("a.mjs").unwrap();
        assert_eq!(update.status, ModulePromiseStatus::Rejected);
        assert!(update.rejection_linkage.is_none());
        assert_eq!(bridge.evaluator().witness_events().len(), event_count);
    }

    #[test]
    fn unknown_module_fails_closed() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        assert!(matches!(
            bridge.synchronize_module("ghost.mjs").unwrap_err(),
            AsyncModulePromiseBridgeError::UnknownModule { .. }
        ));
    }

    #[test]
    fn synchronous_module_cannot_be_synchronized_as_promise() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("sync.mjs", false, &[]).unwrap();
        assert!(matches!(
            bridge.synchronize_module("sync.mjs").unwrap_err(),
            AsyncModulePromiseBridgeError::MissingEvaluationPromise { .. }
        ));
    }

    #[test]
    fn complete_synchronous_module_wakes_dependents() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("dep.mjs", false, &[]).unwrap();
        bridge
            .register_module("app.mjs", false, &["dep.mjs".into()])
            .unwrap();
        let ready = bridge.complete_synchronous_module("dep.mjs").unwrap();
        assert!(ready.is_empty());
        assert!(bridge.evaluator().states()["app.mjs"].all_dependencies_settled());
    }

    #[test]
    fn top_level_await_module_cannot_use_sync_completion_path() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        assert!(matches!(
            bridge.complete_synchronous_module("a.mjs").unwrap_err(),
            AsyncModulePromiseBridgeError::ModuleEvaluation { .. }
        ));
    }

    #[test]
    fn second_promise_settlement_is_rejected_by_promise_store() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        bridge
            .fulfill_module("a.mjs", JsValue::Int(1), public_label())
            .unwrap();
        let error = bridge
            .fulfill_module("a.mjs", JsValue::Int(2), public_label())
            .unwrap_err();
        assert!(matches!(error, AsyncModulePromiseBridgeError::PromiseOperation { .. }));
    }

    #[test]
    fn update_serde_roundtrip() {
        let update = ModulePromiseUpdate {
            module_specifier: "a.mjs".into(),
            promise: PromiseHandle(3),
            status: ModulePromiseStatus::Pending,
            dependency_ready: vec!["b.mjs".into()],
            rejection_linkage: None,
        };
        let json = serde_json::to_string(&update).unwrap();
        let decoded: ModulePromiseUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, update);
    }

    #[test]
    fn error_display_preserves_module_and_promise() {
        let error = AsyncModulePromiseBridgeError::PromiseOperation {
            specifier: "a.mjs".into(),
            promise: PromiseHandle(9),
            detail: "already settled".into(),
        };
        let text = error.to_string();
        assert!(text.contains("a.mjs"));
        assert!(text.contains("Promise(9)"));
    }

    #[test]
    fn component_name_is_stable() {
        assert_eq!(
            ASYNC_MODULE_PROMISE_BRIDGE_COMPONENT,
            "async_module_promise_bridge"
        );
    }
}
