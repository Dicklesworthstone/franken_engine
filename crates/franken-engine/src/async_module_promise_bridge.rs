#![forbid(unsafe_code)]

//! Promise-driven async-module settlement and top-level-await bridge.
//!
//! `module_async_evaluation` owns deterministic module dependency, suspension,
//! rejection, and live-binding semantics. `promise_model` owns Promise state and
//! microtask ordering. This module composes those state machines so every
//! top-level-await module has a real evaluation Promise, pending inner Promises
//! can suspend/resume module continuations, and graph rejection is reflected in
//! both evaluator state and every affected evaluation Promise.
//!
//! The bridge does not execute JavaScript and does not introduce a second
//! scheduler. The interpreter remains responsible for executing and resuming
//! module bodies; this bridge returns deterministic continuation/dependency
//! readiness and keeps Promise/module state coherent for replay.

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
    MissingRejectionReason { dependency: String },
    ModuleNotTopLevelAwait { specifier: String },
    ModuleStillAwaiting {
        specifier: String,
        promise: PromiseHandle,
    },
    ModuleStillWaitingOnDependencies { specifier: String },
    ModuleAlreadyRejected { specifier: String },
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
            Self::MissingRejectionReason { dependency } => write!(
                f,
                "rejected dependency {dependency} has no replayable rejection value"
            ),
            Self::ModuleNotTopLevelAwait { specifier } => {
                write!(f, "module cannot suspend on top-level await: {specifier}")
            }
            Self::ModuleStillAwaiting { specifier, promise } => {
                write!(f, "module {specifier} is still suspended on {promise}")
            }
            Self::ModuleStillWaitingOnDependencies { specifier } => write!(
                f,
                "module {specifier} cannot execute before async dependencies settle"
            ),
            Self::ModuleAlreadyRejected { specifier } => {
                write!(f, "module evaluation is already rejected: {specifier}")
            }
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

pub struct AsyncModulePromiseBridge {
    evaluator: AsyncModuleEvaluator,
    promises: PromiseStore,
    microtasks: MicrotaskQueue,
    live_bindings: LiveBindingMap,
    module_promises: BTreeMap<String, PromiseHandle>,
    active_awaits_by_module: BTreeMap<String, PromiseHandle>,
    awaiters_by_promise: BTreeMap<PromiseHandle, BTreeSet<String>>,
    /// Exact rejection values/labels are retained because the evaluator stores
    /// only a hash/description. Late-registered dependents must inherit the
    /// actual rejection value into their real evaluation Promise.
    module_rejections: BTreeMap<String, (JsValue, Label)>,
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
            module_rejections: BTreeMap::new(),
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

        // Match AsyncModuleEvaluator's registration-time rejection rule while
        // retaining the exact reason needed by the real evaluation Promise.
        let inherited_rejection = dependencies.iter().find_map(|dependency| {
            self.evaluator
                .states()
                .get(dependency)
                .filter(|state| state.phase == AsyncModulePhase::Rejected)
                .map(|_| dependency)
        });
        let inherited_rejection = if let Some(dependency) = inherited_rejection {
            Some(
                self.module_rejections
                    .get(dependency)
                    .cloned()
                    .ok_or_else(|| AsyncModulePromiseBridgeError::MissingRejectionReason {
                        dependency: dependency.clone(),
                    })?,
            )
        } else {
            None
        };

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

        if self
            .evaluator
            .states()
            .get(specifier)
            .is_some_and(|state| state.phase == AsyncModulePhase::Rejected)
        {
            let (reason, label) = inherited_rejection.ok_or_else(|| {
                AsyncModulePromiseBridgeError::ModuleEvaluation {
                    specifier: specifier.to_string(),
                    detail: "module was rejected during registration without a rejected dependency"
                        .to_string(),
                }
            })?;
            self.module_rejections
                .insert(specifier.to_string(), (reason.clone(), label.clone()));
            if self.module_promises.contains_key(specifier) {
                self.reject_evaluation_promise_if_pending(specifier, reason, label)?;
            }
        }

        Ok(evaluation_promise)
    }

    pub fn module_promise(&self, specifier: &str) -> Option<PromiseHandle> {
        self.module_promises.get(specifier).copied()
    }

    pub fn create_pending_promise(&mut self) -> PromiseHandle {
        self.promises.create()
    }

    pub fn active_await(&self, specifier: &str) -> Option<PromiseHandle> {
        self.active_awaits_by_module.get(specifier).copied()
    }

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
        if state.phase == AsyncModulePhase::Rejected {
            return Err(AsyncModulePromiseBridgeError::ModuleAlreadyRejected {
                specifier: specifier.to_string(),
            });
        }
        if !state.has_top_level_await || state.phase == AsyncModulePhase::Settled {
            return Err(AsyncModulePromiseBridgeError::ModuleNotTopLevelAwait {
                specifier: specifier.to_string(),
            });
        }
        if !state.pending_dependencies.is_empty() {
            return Err(
                AsyncModulePromiseBridgeError::ModuleStillWaitingOnDependencies {
                    specifier: specifier.to_string(),
                },
            );
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

    pub fn reject_awaited_promise(
        &mut self,
        promise: PromiseHandle,
        reason: JsValue,
        label: Label,
    ) -> Result<Vec<ModulePromiseUpdate>, AsyncModulePromiseBridgeError> {
        self.ensure_inner_pending_promise(promise)?;
        let awaiters = self.awaiters_by_promise.get(&promise).cloned().unwrap_or_default();
        self.preflight_awaiters(promise, &awaiters)?;

        // Preflight every evaluation Promise before the inner Promise is
        // irreversibly settled, so a contradictory terminal state fails closed
        // without leaving half-applied bridge state.
        for specifier in &awaiters {
            self.ensure_evaluation_promise_pending(specifier)?;
        }

        self.promises
            .reject(
                promise,
                reason.clone(),
                label.clone(),
                &mut self.microtasks,
            )
            .map_err(|error| self.promise_error("<awaited-promise>", promise, error))?;
        self.awaiters_by_promise.remove(&promise);

        // Reject all directly awaiting evaluation Promises first. Synchronizing
        // one module may reject another through dependency propagation, so this
        // up-front pass prevents iteration-order-dependent Promise state.
        for specifier in &awaiters {
            self.active_awaits_by_module.remove(specifier);
            self.reject_evaluation_promise_if_pending(
                specifier,
                reason.clone(),
                label.clone(),
            )?;
        }

        let mut updates = Vec::with_capacity(awaiters.len());
        for specifier in awaiters {
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
        let state = self
            .evaluator
            .states()
            .get(specifier)
            .ok_or_else(|| AsyncModulePromiseBridgeError::UnknownModule {
                specifier: specifier.to_string(),
            })?;
        if state.phase == AsyncModulePhase::Rejected {
            return Err(AsyncModulePromiseBridgeError::ModuleAlreadyRejected {
                specifier: specifier.to_string(),
            });
        }
        if !state.pending_dependencies.is_empty() {
            return Err(
                AsyncModulePromiseBridgeError::ModuleStillWaitingOnDependencies {
                    specifier: specifier.to_string(),
                },
            );
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
        self.reject_evaluation_promise_if_pending(specifier, reason, label)?;
        self.synchronize_module(specifier)
    }

    pub fn synchronize_module(
        &mut self,
        specifier: &str,
    ) -> Result<ModulePromiseUpdate, AsyncModulePromiseBridgeError> {
        let promise = self.require_module_promise(specifier)?;
        let record = self
            .promises
            .get(promise)
            .map_err(|error| self.promise_error(specifier, promise, error))?;
        let promise_state = record.state.clone();
        let promise_label = record.label.clone();
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
                self.module_rejections.insert(
                    specifier.to_string(),
                    (reason.clone(), promise_label.clone()),
                );
                let rejection_linkage = if module_phase == AsyncModulePhase::Rejected {
                    None
                } else {
                    let linkage = self
                        .evaluator
                        .reject_module(specifier, &reason, &mut self.live_bindings)
                        .map_err(|error| self.module_error(specifier, error))?;
                    self.propagate_runtime_rejection(
                        &linkage,
                        reason.clone(),
                        promise_label.clone(),
                    )?;
                    Some(linkage)
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
        if state.phase == AsyncModulePhase::Rejected {
            return Err(AsyncModulePromiseBridgeError::ModuleAlreadyRejected {
                specifier: specifier.to_string(),
            });
        }
        if !state.pending_dependencies.is_empty() {
            return Err(
                AsyncModulePromiseBridgeError::ModuleStillWaitingOnDependencies {
                    specifier: specifier.to_string(),
                },
            );
        }
        if state.phase == AsyncModulePhase::Settled {
            return Ok(Vec::new());
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

    fn ensure_evaluation_promise_pending(
        &self,
        specifier: &str,
    ) -> Result<(), AsyncModulePromiseBridgeError> {
        let promise = self.require_module_promise(specifier)?;
        let state = &self
            .promises
            .get(promise)
            .map_err(|error| self.promise_error(specifier, promise, error))?
            .state;
        if matches!(state, PromiseState::Pending) {
            Ok(())
        } else {
            Err(AsyncModulePromiseBridgeError::InconsistentTerminalState {
                specifier: specifier.to_string(),
                promise,
                promise_status: ModulePromiseStatus::from_state(state),
                module_phase: self.evaluator.states()[specifier].phase,
            })
        }
    }

    fn reject_evaluation_promise_if_pending(
        &mut self,
        specifier: &str,
        reason: JsValue,
        label: Label,
    ) -> Result<PromiseHandle, AsyncModulePromiseBridgeError> {
        let promise = self.require_module_promise(specifier)?;
        let state = self
            .promises
            .get(promise)
            .map_err(|error| self.promise_error(specifier, promise, error))?
            .state
            .clone();
        match state {
            PromiseState::Pending => {
                self.promises
                    .reject(
                        promise,
                        reason.clone(),
                        label.clone(),
                        &mut self.microtasks,
                    )
                    .map_err(|error| self.promise_error(specifier, promise, error))?;
                self.module_rejections
                    .insert(specifier.to_string(), (reason, label));
                Ok(promise)
            }
            PromiseState::Rejected(_) => {
                self.module_rejections
                    .entry(specifier.to_string())
                    .or_insert((reason, label));
                Ok(promise)
            }
            PromiseState::Fulfilled(_) => Err(
                AsyncModulePromiseBridgeError::InconsistentTerminalState {
                    specifier: specifier.to_string(),
                    promise,
                    promise_status: ModulePromiseStatus::Fulfilled,
                    module_phase: self.evaluator.states()[specifier].phase,
                },
            ),
        }
    }

    fn propagate_runtime_rejection(
        &mut self,
        linkage: &RejectionLinkage,
        reason: JsValue,
        label: Label,
    ) -> Result<(), AsyncModulePromiseBridgeError> {
        let affected: Vec<String> = linkage.transitive_closure.iter().cloned().collect();
        for specifier in affected {
            let rejected = self
                .evaluator
                .states()
                .get(&specifier)
                .is_some_and(|state| state.phase == AsyncModulePhase::Rejected);
            if !rejected {
                continue;
            }
            self.detach_active_await(&specifier);
            self.module_rejections
                .insert(specifier.clone(), (reason.clone(), label.clone()));
            if self.module_promises.contains_key(&specifier) {
                self.reject_evaluation_promise_if_pending(
                    &specifier,
                    reason.clone(),
                    label.clone(),
                )?;
            }
        }
        Ok(())
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
        let resumable = bridge
            .fulfill_awaited_promise(awaited, JsValue::Int(7), public_label())
            .unwrap();
        assert_eq!(resumable, vec!["a.mjs".to_string()]);
        assert_eq!(bridge.active_await("a.mjs"), None);
        assert!(
            !bridge
                .promise_store()
                .get(bridge.module_promise("a.mjs").unwrap())
                .unwrap()
                .state
                .is_settled()
        );
    }

    #[test]
    fn transitive_rejection_rejects_dependent_evaluation_promises() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("root.mjs", true, &[]).unwrap();
        let child_promise = bridge
            .register_module("child.mjs", true, &["root.mjs".into()])
            .unwrap()
            .unwrap();
        bridge
            .reject_module("root.mjs", JsValue::Str("boom".into()), public_label())
            .unwrap();
        assert!(bridge.promise_store().get(child_promise).unwrap().state.is_rejected());
        let child_update = bridge.synchronize_module("child.mjs").unwrap();
        assert_eq!(child_update.status, ModulePromiseStatus::Rejected);
        assert!(child_update.rejection_linkage.is_none());
    }

    #[test]
    fn upstream_rejection_detaches_dependent_active_await() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("root.mjs", true, &[]).unwrap();
        bridge
            .register_module("child.mjs", true, &["root.mjs".into()])
            .unwrap();
        // Resolve the dependency once so the child body can reach an await,
        // then suspend it on an inner Promise.
        bridge
            .fulfill_module("root.mjs", JsValue::Undefined, public_label())
            .unwrap();
        let inner = bridge.create_pending_promise();
        bridge.suspend_module_on_promise("child.mjs", inner).unwrap();
        assert_eq!(bridge.active_await("child.mjs"), Some(inner));
        // A later direct rejection of child must detach the stale await index.
        bridge
            .reject_module("child.mjs", JsValue::Str("cancel".into()), public_label())
            .unwrap();
        assert_eq!(bridge.active_await("child.mjs"), None);
    }

    #[test]
    fn late_registered_dependent_inherits_exact_rejection() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("root.mjs", true, &[]).unwrap();
        bridge
            .reject_module("root.mjs", JsValue::Str("boom".into()), Label::Secret)
            .unwrap();
        let late_promise = bridge
            .register_module("late.mjs", true, &["root.mjs".into()])
            .unwrap()
            .unwrap();
        let record = bridge.promise_store().get(late_promise).unwrap();
        assert_eq!(record.state, PromiseState::Rejected(JsValue::Str("boom".into())));
        assert_eq!(record.label, Label::Secret);
        assert_eq!(bridge.evaluator().states()["late.mjs"].phase, AsyncModulePhase::Rejected);
    }

    #[test]
    fn rejected_inner_promise_rejects_module_and_dependents() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("root.mjs", true, &[]).unwrap();
        let child_promise = bridge
            .register_module("child.mjs", true, &["root.mjs".into()])
            .unwrap()
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
        assert_eq!(bridge.evaluator().states()["child.mjs"].phase, AsyncModulePhase::Rejected);
        assert!(bridge.promise_store().get(child_promise).unwrap().state.is_rejected());
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
    fn module_cannot_complete_before_dependency_settles() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("dep.mjs", true, &[]).unwrap();
        bridge
            .register_module("app.mjs", true, &["dep.mjs".into()])
            .unwrap();
        assert!(matches!(
            bridge
                .fulfill_module("app.mjs", JsValue::Undefined, public_label())
                .unwrap_err(),
            AsyncModulePromiseBridgeError::ModuleStillWaitingOnDependencies { .. }
        ));
    }

    #[test]
    fn synchronous_module_cannot_complete_before_dependency_settles() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("dep.mjs", true, &[]).unwrap();
        bridge
            .register_module("app.mjs", false, &["dep.mjs".into()])
            .unwrap();
        assert!(matches!(
            bridge.complete_synchronous_module("app.mjs").unwrap_err(),
            AsyncModulePromiseBridgeError::ModuleStillWaitingOnDependencies { .. }
        ));
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
    fn shared_inner_promise_resumes_all_awaiters_deterministically() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("b.mjs", true, &[]).unwrap();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        let inner = bridge.create_pending_promise();
        bridge.suspend_module_on_promise("b.mjs", inner).unwrap();
        bridge.suspend_module_on_promise("a.mjs", inner).unwrap();
        let ready = bridge
            .fulfill_awaited_promise(inner, JsValue::Undefined, public_label())
            .unwrap();
        assert_eq!(ready, vec!["a.mjs".to_string(), "b.mjs".to_string()]);
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
    fn unknown_module_fails_closed() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        assert!(matches!(
            bridge.synchronize_module("ghost.mjs").unwrap_err(),
            AsyncModulePromiseBridgeError::UnknownModule { .. }
        ));
    }

    #[test]
    fn component_name_is_stable() {
        assert_eq!(
            ASYNC_MODULE_PROMISE_BRIDGE_COMPONENT,
            "async_module_promise_bridge"
        );
    }
}
