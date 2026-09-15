#![forbid(unsafe_code)]

//! Promise-driven async-module settlement and top-level-await bridge.
//!
//! `module_async_evaluation` owns deterministic module dependency, suspension,
//! rejection, and live-binding semantics. `promise_model` owns Promise state and
//! microtask ordering. Historically those state machines carried matching
//! `PromiseHandle`s without a shipped owner that observed the real
//! `PromiseStore` and advanced module evaluation when Promises settled.
//!
//! This module is that narrow composition seam. It does not execute JavaScript
//! and it does not invent another scheduler. The interpreter remains responsible
//! for running and resuming module bodies; this bridge owns the transitions from
//! real Promise settlement to the existing async-module state machine and hands
//! deterministic resumable-module sets back to the caller.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ifc_artifacts::Label;
use crate::module_async_evaluation::{
    AsyncEvalConfig, AsyncEvalError, AsyncModuleEvaluator, AsyncModulePhase, RejectionLinkage,
};
use crate::module_live_binding::LiveBindingMap;
use crate::object_model::JsValue;
use crate::promise_model::{MicrotaskQueue, PromiseError, PromiseHandle, PromiseState, PromiseStore};

pub const ASYNC_MODULE_PROMISE_BRIDGE_COMPONENT: &str = "async_module_promise_bridge";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModulePromiseStatus {
    Pending,
    Fulfilled,
    Rejected,
}

impl ModulePromiseStatus {
    fn from_state(state: &PromiseState) -> Self {
        match state {
            PromiseState::Pending => Self::Pending,
            PromiseState::Fulfilled(_) => Self::Fulfilled,
            PromiseState::Rejected(_) => Self::Rejected,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModulePromiseUpdate {
    pub module_specifier: String,
    pub promise: PromiseHandle,
    pub status: ModulePromiseStatus,
    pub dependency_ready: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_linkage: Option<RejectionLinkage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsyncModulePromiseBridgeError {
    UnknownModule { specifier: String },
    DuplicateModule { specifier: String },
    MissingEvaluationPromise { specifier: String },
    ModuleNotTopLevelAwait { specifier: String },
    ModuleStillAwaiting {
        specifier: String,
        promise: PromiseHandle,
    },
    SelfAwait {
        specifier: String,
        promise: PromiseHandle,
    },
    AwaitPromiseNotPending {
        promise: PromiseHandle,
        status: ModulePromiseStatus,
    },
    EvaluationPromiseRoleMismatch { promise: PromiseHandle },
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
            Self::ModuleNotTopLevelAwait { specifier } => {
                write!(f, "module cannot suspend on top-level await: {specifier}")
            }
            Self::ModuleStillAwaiting { specifier, promise } => write!(
                f,
                "module {specifier} is still suspended on {promise}"
            ),
            Self::SelfAwait { specifier, promise } => write!(
                f,
                "module {specifier} cannot await its own evaluation Promise {promise}"
            ),
            Self::AwaitPromiseNotPending { promise, status } => write!(
                f,
                "awaited Promise {promise} is not pending (status={status:?})"
            ),
            Self::EvaluationPromiseRoleMismatch { promise } => write!(
                f,
                "evaluation Promise {promise} must be settled through the module-evaluation path"
            ),
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

/// Owns Promise and async-module state at their runtime boundary.
///
/// Every top-level-await module receives a real `PromiseStore` evaluation
/// Promise. Inner pending Promises are tracked separately from evaluation
/// Promises so a caller cannot accidentally settle one through the wrong role.
pub struct AsyncModulePromiseBridge {
    evaluator: AsyncModuleEvaluator,
    promises: PromiseStore,
    microtasks: MicrotaskQueue,
    live_bindings: LiveBindingMap,
    module_promises: BTreeMap<String, PromiseHandle>,
    active_awaits_by_module: BTreeMap<String, PromiseHandle>,
    awaiters_by_promise: BTreeMap<PromiseHandle, BTreeSet<String>>,
}

impl AsyncModulePromiseBridge {
    pub fn new(config: AsyncEvalConfig) -> Self {
        Self {
            evaluator: AsyncModuleEvaluator::new(config),
            promises: PromiseStore::new(),
            microtasks: MicrotaskQueue::new(),
            live_bindings: LiveBindingMap::new(),
            module_promises: BTreeMap::new(),
            active_awaits_by_module: BTreeMap::new(),
            awaiters_by_promise: BTreeMap::new(),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(AsyncEvalConfig::default())
    }

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

    pub fn module_promise(&self, specifier: &str) -> Option<PromiseHandle> {
        self.module_promises.get(specifier).copied()
    }

    /// Allocate a real pending Promise that a running module may await.
    pub fn create_pending_promise(&mut self) -> PromiseHandle {
        self.promises.create()
    }

    pub fn active_await(&self, specifier: &str) -> Option<PromiseHandle> {
        self.active_awaits_by_module.get(specifier).copied()
    }

    /// Suspend a running TLA module on a real pending Promise.
    ///
    /// Only one active top-level await is allowed per module continuation. The
    /// caller must resume execution after this bridge returns the module from
    /// `fulfill_awaited_promise` before registering the next await.
    pub fn suspend_module_on_promise(
        &mut self,
        specifier: &str,
        promise: PromiseHandle,
    ) -> Result<(), AsyncModulePromiseBridgeError> {
        let state = self
            .evaluator
            .states()
            .get(specifier)
            .ok_or_else(|| AsyncModulePromiseBridgeError::UnknownModule {
                specifier: specifier.to_string(),
            })?;
        if !state.has_top_level_await || state.phase.is_terminal() {
            return Err(AsyncModulePromiseBridgeError::ModuleNotTopLevelAwait {
                specifier: specifier.to_string(),
            });
        }
        if !state.pending_dependencies.is_empty() {
            return Err(AsyncModulePromiseBridgeError::ModuleEvaluation {
                specifier: specifier.to_string(),
                detail: "module body cannot reach top-level await before async dependencies settle"
                    .to_string(),
            });
        }
        if let Some(active) = self.active_await(specifier) {
            return Err(AsyncModulePromiseBridgeError::ModuleStillAwaiting {
                specifier: specifier.to_string(),
                promise: active,
            });
        }
        let evaluation_promise = self.require_module_promise(specifier)?;
        if evaluation_promise == promise {
            return Err(AsyncModulePromiseBridgeError::SelfAwait {
                specifier: specifier.to_string(),
                promise,
            });
        }
        let promise_state = &self
            .promises
            .get(promise)
            .map_err(|error| self.promise_error(specifier, promise, error))?
            .state;
        if !matches!(promise_state, PromiseState::Pending) {
            return Err(AsyncModulePromiseBridgeError::AwaitPromiseNotPending {
                promise,
                status: ModulePromiseStatus::from_state(promise_state),
            });
        }
        self.evaluator
            .suspend_at_top_level_await(specifier, promise)
            .map_err(|error| self.module_error(specifier, error))?;
        self.active_awaits_by_module
            .insert(specifier.to_string(), promise);
        self.awaiters_by_promise
            .entry(promise)
            .or_default()
            .insert(specifier.to_string());
        Ok(())
    }

    /// Fulfill an inner pending Promise and return modules whose suspended body
    /// continuation may now be resumed by the interpreter.
    pub fn fulfill_awaited_promise(
        &mut self,
        promise: PromiseHandle,
        value: JsValue,
        label: Label,
    ) -> Result<Vec<String>, AsyncModulePromiseBridgeError> {
        self.ensure_inner_pending_promise(promise)?;
        let awaiters = self.awaiters_by_promise.get(&promise).cloned().unwrap_or_default();
        self.preflight_awaiters(promise, &awaiters)?;
        self.promises
            .fulfill(promise, value, label, &mut self.microtasks)
            .map_err(|error| self.promise_error("<awaited-promise>", promise, error))?;
        self.awaiters_by_promise.remove(&promise);
        let mut resumable = Vec::with_capacity(awaiters.len());
        for specifier in awaiters {
            self.active_awaits_by_module.remove(&specifier);
            self.evaluator
                .resume_evaluation(&specifier)
                .map_err(|error| self.module_error(&specifier, error))?;
            resumable.push(specifier);
        }
        Ok(resumable)
    }

    /// Reject an inner pending Promise. Every module suspended on it has its
    /// own evaluation Promise rejected with the same reason, then the existing
    /// evaluator propagates rejection through module dependencies and bindings.
    pub fn reject_awaited_promise(
        &mut self,
        promise: PromiseHandle,
        reason: JsValue,
        label: Label,
    ) -> Result<Vec<ModulePromiseUpdate>, AsyncModulePromiseBridgeError> {
        self.ensure_inner_pending_promise(promise)?;
        let awaiters = self.awaiters_by_promise.get(&promise).cloned().unwrap_or_default();
        self.preflight_awaiters(promise, &awaiters)?;
        for specifier in &awaiters {
            let evaluation_promise = self.require_module_promise(specifier)?;
            let state = &self
                .promises
                .get(evaluation_promise)
                .map_err(|error| self.promise_error(specifier, evaluation_promise, error))?
                .state;
            if !matches!(state, PromiseState::Pending) {
                return Err(AsyncModulePromiseBridgeError::InconsistentTerminalState {
                    specifier: specifier.clone(),
                    promise: evaluation_promise,
                    promise_status: ModulePromiseStatus::from_state(state),
                    module_phase: self.evaluator.states()[specifier].phase,
                });
            }
        }
        self.promises
            .reject(promise, reason.clone(), label.clone(), &mut self.microtasks)
            .map_err(|error| self.promise_error("<awaited-promise>", promise, error))?;
        self.awaiters_by_promise.remove(&promise);
        let mut updates = Vec::with_capacity(awaiters.len());
        for specifier in awaiters {
            self.active_awaits_by_module.remove(&specifier);
            let evaluation_promise = self.require_module_promise(&specifier)?;
            self.promises
                .reject(
                    evaluation_promise,
                    reason.clone(),
                    label.clone(),
                    &mut self.microtasks,
                )
                .map_err(|error| self.promise_error(&specifier, evaluation_promise, error))?;
            updates.push(self.synchronize_module(&specifier)?);
        }
        Ok(updates)
    }

    pub fn fulfill_module(
        &mut self,
        specifier: &str,
        value: JsValue,
        label: Label,
    ) -> Result<ModulePromiseUpdate, AsyncModulePromiseBridgeError> {
        if let Some(promise) = self.active_await(specifier) {
            return Err(AsyncModulePromiseBridgeError::ModuleStillAwaiting {
                specifier: specifier.to_string(),
                promise,
            });
        }
        let promise = self.require_module_promise(specifier)?;
        self.promises
            .fulfill(promise, value, label, &mut self.microtasks)
            .map_err(|error| self.promise_error(specifier, promise, error))?;
        self.synchronize_module(specifier)
    }

    pub fn reject_module(
        &mut self,
        specifier: &str,
        reason: JsValue,
        label: Label,
    ) -> Result<ModulePromiseUpdate, AsyncModulePromiseBridgeError> {
        self.detach_active_await(specifier);
        let promise = self.require_module_promise(specifier)?;
        self.promises
            .reject(promise, reason, label, &mut self.microtasks)
            .map_err(|error| self.promise_error(specifier, promise, error))?;
        self.synchronize_module(specifier)
    }

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

    pub fn synchronize_all(
        &mut self,
    ) -> Result<Vec<ModulePromiseUpdate>, AsyncModulePromiseBridgeError> {
        let modules: Vec<String> = self.module_promises.keys().cloned().collect();
        modules
            .iter()
            .map(|specifier| self.synchronize_module(specifier))
            .collect()
    }

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

    fn is_evaluation_promise(&self, promise: PromiseHandle) -> bool {
        self.module_promises.values().any(|candidate| *candidate == promise)
    }

    fn ensure_inner_pending_promise(
        &self,
        promise: PromiseHandle,
    ) -> Result<(), AsyncModulePromiseBridgeError> {
        if self.is_evaluation_promise(promise) {
            return Err(AsyncModulePromiseBridgeError::EvaluationPromiseRoleMismatch { promise });
        }
        let state = &self
            .promises
            .get(promise)
            .map_err(|error| self.promise_error("<awaited-promise>", promise, error))?
            .state;
        if matches!(state, PromiseState::Pending) {
            Ok(())
        } else {
            Err(AsyncModulePromiseBridgeError::AwaitPromiseNotPending {
                promise,
                status: ModulePromiseStatus::from_state(state),
            })
        }
    }

    fn preflight_awaiters(
        &self,
        promise: PromiseHandle,
        awaiters: &BTreeSet<String>,
    ) -> Result<(), AsyncModulePromiseBridgeError> {
        for specifier in awaiters {
            if self.active_await(specifier) != Some(promise) {
                return Err(AsyncModulePromiseBridgeError::ModuleEvaluation {
                    specifier: specifier.clone(),
                    detail: format!("await index is inconsistent for {promise}"),
                });
            }
            let state = self
                .evaluator
                .states()
                .get(specifier)
                .ok_or_else(|| AsyncModulePromiseBridgeError::UnknownModule {
                    specifier: specifier.clone(),
                })?;
            if state.phase.is_terminal() {
                return Err(AsyncModulePromiseBridgeError::ModuleEvaluation {
                    specifier: specifier.clone(),
                    detail: format!("terminal module remained indexed as awaiting {promise}"),
                });
            }
        }
        Ok(())
    }

    fn detach_active_await(&mut self, specifier: &str) {
        let Some(promise) = self.active_awaits_by_module.remove(specifier) else {
            return;
        };
        let remove_promise = self
            .awaiters_by_promise
            .get_mut(&promise)
            .is_some_and(|awaiters| {
                awaiters.remove(specifier);
                awaiters.is_empty()
            });
        if remove_promise {
            self.awaiters_by_promise.remove(&promise);
        }
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
    fn promise_handles_are_monotonic_and_replay_stable() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        let a = bridge.register_module("a.mjs", true, &[]).unwrap().unwrap();
        bridge.register_module("sync.mjs", false, &[]).unwrap();
        let inner = bridge.create_pending_promise();
        let b = bridge.register_module("b.mjs", true, &[]).unwrap().unwrap();
        assert_eq!(a, PromiseHandle(0));
        assert_eq!(inner, PromiseHandle(1));
        assert_eq!(b, PromiseHandle(2));
    }

    #[test]
    fn pending_inner_promise_suspends_then_resumes_module() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        let awaited = bridge.create_pending_promise();
        bridge.suspend_module_on_promise("a.mjs", awaited).unwrap();
        assert_eq!(bridge.active_await("a.mjs"), Some(awaited));
        assert!(
            !bridge.evaluator().states()["a.mjs"]
                .suspensions
                .last()
                .expect("suspension")
                .resolved
        );

        let resumable = bridge
            .fulfill_awaited_promise(awaited, JsValue::Int(7), public_label())
            .unwrap();
        assert_eq!(resumable, vec!["a.mjs".to_string()]);
        assert_eq!(bridge.active_await("a.mjs"), None);
        assert!(
            bridge.evaluator().states()["a.mjs"]
                .suspensions
                .last()
                .expect("suspension")
                .resolved
        );
        assert!(matches!(
            bridge
                .promise_store()
                .get(bridge.module_promise("a.mjs").unwrap())
                .unwrap()
                .state,
            PromiseState::Pending
        ));
    }

    #[test]
    fn rejected_inner_promise_rejects_module_and_dependents() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("root.mjs", true, &[]).unwrap();
        bridge
            .register_module("child.mjs", true, &["root.mjs".into()])
            .unwrap();
        let awaited = bridge.create_pending_promise();
        bridge.suspend_module_on_promise("root.mjs", awaited).unwrap();
        let updates = bridge
            .reject_awaited_promise(
                awaited,
                JsValue::Str("await rejected".into()),
                public_label(),
            )
            .unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].status, ModulePromiseStatus::Rejected);
        assert_eq!(bridge.evaluator().states()["root.mjs"].phase, AsyncModulePhase::Rejected);
        assert_eq!(bridge.evaluator().states()["child.mjs"].phase, AsyncModulePhase::Rejected);
    }

    #[test]
    fn module_cannot_complete_while_inner_await_is_pending() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        let awaited = bridge.create_pending_promise();
        bridge.suspend_module_on_promise("a.mjs", awaited).unwrap();
        assert!(matches!(
            bridge
                .fulfill_module("a.mjs", JsValue::Undefined, public_label())
                .unwrap_err(),
            AsyncModulePromiseBridgeError::ModuleStillAwaiting { .. }
        ));
    }

    #[test]
    fn module_cannot_register_second_concurrent_await() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        let first = bridge.create_pending_promise();
        let second = bridge.create_pending_promise();
        bridge.suspend_module_on_promise("a.mjs", first).unwrap();
        assert!(matches!(
            bridge.suspend_module_on_promise("a.mjs", second).unwrap_err(),
            AsyncModulePromiseBridgeError::ModuleStillAwaiting { promise, .. } if promise == first
        ));
    }

    #[test]
    fn module_cannot_await_its_own_evaluation_promise() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        let evaluation = bridge.register_module("a.mjs", true, &[]).unwrap().unwrap();
        assert!(matches!(
            bridge.suspend_module_on_promise("a.mjs", evaluation).unwrap_err(),
            AsyncModulePromiseBridgeError::SelfAwait { .. }
        ));
    }

    #[test]
    fn settled_inner_promise_cannot_be_registered_as_pending_await() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        let awaited = bridge.create_pending_promise();
        bridge
            .fulfill_awaited_promise(awaited, JsValue::Undefined, public_label())
            .unwrap();
        assert!(matches!(
            bridge.suspend_module_on_promise("a.mjs", awaited).unwrap_err(),
            AsyncModulePromiseBridgeError::AwaitPromiseNotPending {
                status: ModulePromiseStatus::Fulfilled,
                ..
            }
        ));
    }

    #[test]
    fn evaluation_promise_cannot_use_inner_promise_settlement_api() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        let evaluation = bridge.register_module("a.mjs", true, &[]).unwrap().unwrap();
        assert!(matches!(
            bridge
                .fulfill_awaited_promise(evaluation, JsValue::Undefined, public_label())
                .unwrap_err(),
            AsyncModulePromiseBridgeError::EvaluationPromiseRoleMismatch { .. }
        ));
    }

    #[test]
    fn pending_module_evaluation_promise_keeps_module_suspended() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        let update = bridge.synchronize_module("a.mjs").unwrap();
        assert_eq!(update.status, ModulePromiseStatus::Pending);
        assert_eq!(bridge.evaluator().states()["a.mjs"].phase, AsyncModulePhase::Suspended);
    }

    #[test]
    fn fulfilled_evaluation_promise_settles_module() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        let update = bridge
            .fulfill_module("a.mjs", JsValue::Int(7), public_label())
            .unwrap();
        assert_eq!(update.status, ModulePromiseStatus::Fulfilled);
        assert_eq!(bridge.evaluator().states()["a.mjs"].phase, AsyncModulePhase::Settled);
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
    fn top_level_await_module_cannot_use_sync_completion_path() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        assert!(matches!(
            bridge.complete_synchronous_module("a.mjs").unwrap_err(),
            AsyncModulePromiseBridgeError::ModuleEvaluation { .. }
        ));
    }

    #[test]
    fn second_evaluation_promise_settlement_is_rejected() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        bridge
            .fulfill_module("a.mjs", JsValue::Int(1), public_label())
            .unwrap();
        assert!(matches!(
            bridge
                .fulfill_module("a.mjs", JsValue::Int(2), public_label())
                .unwrap_err(),
            AsyncModulePromiseBridgeError::PromiseOperation { .. }
        ));
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
    fn component_name_is_stable() {
        assert_eq!(
            ASYNC_MODULE_PROMISE_BRIDGE_COMPONENT,
            "async_module_promise_bridge"
        );
    }
}
