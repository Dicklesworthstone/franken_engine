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
    /// All newly runnable bodies/continuations, including modules explicitly
    /// awaiting this evaluation Promise, in canonical module-name order.
    /// The scheduler distinguishes Start from Resume using its started set.
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
    ModuleAlreadySettled { specifier: String },
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
            Self::ModuleAlreadySettled { specifier } => {
                write!(f, "module evaluation is already settled: {specifier}")
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

        let inherited_rejection_dependency = dependencies.iter().find_map(|dependency| {
            self.evaluator
                .states()
                .get(dependency)
                .filter(|state| state.phase == AsyncModulePhase::Rejected)
                .map(|_| dependency.clone())
        });
        let inherited_rejection = inherited_rejection_dependency
            .as_ref()
            .map(|dependency| {
                self.module_rejections
                    .get(dependency)
                    .cloned()
                    .ok_or_else(|| AsyncModulePromiseBridgeError::MissingRejectionReason {
                        dependency: dependency.clone(),
                    })
            })
            .transpose()?;

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
                    detail: "module was rejected during registration without a replayable rejected dependency"
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
        let state = self.module_state(specifier)?;
        if state.phase == AsyncModulePhase::Rejected {
            return Err(AsyncModulePromiseBridgeError::ModuleAlreadyRejected {
                specifier: specifier.to_string(),
            });
        }
        if state.phase == AsyncModulePhase::Settled {
            return Err(AsyncModulePromiseBridgeError::ModuleAlreadySettled {
                specifier: specifier.to_string(),
            });
        }
        if !state.has_top_level_await {
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
        self.resume_promise_awaiters(promise)
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
        let state = self.module_state(specifier)?;
        if state.phase == AsyncModulePhase::Rejected {
            return Err(AsyncModulePromiseBridgeError::ModuleAlreadyRejected {
                specifier: specifier.to_string(),
            });
        }
        if state.phase == AsyncModulePhase::Settled {
            return Err(AsyncModulePromiseBridgeError::ModuleAlreadySettled {
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
        // Evaluation Promises can themselves be awaited by other module
        // bodies. Validate their continuation indexes before settlement too.
        if let Some(awaiters) = self.awaiters_by_promise.get(&promise) {
            self.preflight_awaiters(promise, awaiters)?;
        }
        self.promises
            .fulfill(promise, value, label, &mut self.microtasks)
            .map_err(|error| self.promise_error(specifier, promise, error))?;
        self.synchronize_module(specifier)
    }

    /// Reject a Promise-backed top-level-await module and synchronize its graph.
    pub fn reject_module(
        &mut self,
        specifier: &str,
        reason: JsValue,
        label: Label,
    ) -> Result<ModulePromiseUpdate, AsyncModulePromiseBridgeError> {
        let state = self.module_state(specifier)?;
        if !state.has_top_level_await {
            return Err(AsyncModulePromiseBridgeError::ModuleEvaluation {
                specifier: specifier.to_string(),
                detail: "synchronous modules must reject through reject_synchronous_module"
                    .to_string(),
            });
        }
        self.detach_active_await(specifier);
        self.reject_evaluation_promise_if_pending(specifier, reason, label)?;
        self.synchronize_module(specifier)
    }

    /// Reject a synchronous module execution and propagate the exact failure to
    /// every transitive dependent. TLA dependents have their real evaluation
    /// Promises rejected with the same value and IFC label; synchronous
    /// dependents retain the exact rejection for replay and late registration.
    pub fn reject_synchronous_module(
        &mut self,
        specifier: &str,
        reason: JsValue,
        label: Label,
    ) -> Result<RejectionLinkage, AsyncModulePromiseBridgeError> {
        let state = self.module_state(specifier)?;
        if state.has_top_level_await {
            return Err(AsyncModulePromiseBridgeError::ModuleEvaluation {
                specifier: specifier.to_string(),
                detail: "top-level-await modules must reject through their evaluation Promise"
                    .to_string(),
            });
        }
        if state.phase == AsyncModulePhase::Rejected {
            return Err(AsyncModulePromiseBridgeError::ModuleAlreadyRejected {
                specifier: specifier.to_string(),
            });
        }
        if state.phase == AsyncModulePhase::Settled {
            return Err(AsyncModulePromiseBridgeError::ModuleAlreadySettled {
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

        self.detach_active_await(specifier);
        self.module_rejections
            .insert(specifier.to_string(), (reason.clone(), label.clone()));
        let linkage = self
            .evaluator
            .reject_module(specifier, &reason, &mut self.live_bindings)
            .map_err(|error| self.module_error(specifier, error))?;
        self.propagate_runtime_rejection(&linkage, reason, label)?;
        Ok(linkage)
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
        let module_phase = self.module_state(specifier)?.phase;

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
                let mut dependency_ready = if module_phase == AsyncModulePhase::Settled {
                    Vec::new()
                } else {
                    self.evaluator
                        .settle_module(specifier)
                        .map_err(|error| self.module_error(specifier, error))?
                };
                dependency_ready.extend(self.resume_promise_awaiters(promise)?);
                dependency_ready.sort();
                dependency_ready.dedup();
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
        let state = self.module_state(specifier)?;
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
        if state.phase == AsyncModulePhase::Settled {
            return Ok(Vec::new());
        }
        if !state.pending_dependencies.is_empty() {
            return Err(
                AsyncModulePromiseBridgeError::ModuleStillWaitingOnDependencies {
                    specifier: specifier.to_string(),
                },
            );
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

    fn module_state(
        &self,
        specifier: &str,
    ) -> Result<&crate::module_async_evaluation::AsyncModuleState, AsyncModulePromiseBridgeError> {
        self.evaluator.states().get(specifier).ok_or_else(|| {
            AsyncModulePromiseBridgeError::UnknownModule {
                specifier: specifier.to_string(),
            }
        })
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

    /// Consume each successful await edge once, independently of whether the
    /// settled Promise belongs to a host operation or another module. The
    /// resumed module's own evaluation Promise stays pending until its body
    /// completes; fulfillment must not shortcut the remaining continuation.
    fn resume_promise_awaiters(
        &mut self,
        promise: PromiseHandle,
    ) -> Result<Vec<String>, AsyncModulePromiseBridgeError> {
        if let Some(awaiters) = self.awaiters_by_promise.get(&promise) {
            self.preflight_awaiters(promise, awaiters)?;
        }
        let awaiters = self.awaiters_by_promise.remove(&promise).unwrap_or_default();
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
            let state = self.module_state(specifier)?;
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
    fn real_evaluation_promises_are_monotonic() {
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
    fn pending_inner_promise_resumes_without_settling_evaluation_promise() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        let awaited = bridge.create_pending_promise();
        bridge.suspend_module_on_promise("a.mjs", awaited).unwrap();
        assert_eq!(
            bridge
                .fulfill_awaited_promise(awaited, JsValue::Int(7), public_label())
                .unwrap(),
            vec!["a.mjs".to_string()]
        );
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
    fn synchronous_rejection_propagates_to_tla_dependent_promise() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("sync-root.mjs", false, &[]).unwrap();
        let dependent_promise = bridge
            .register_module("async-child.mjs", true, &["sync-root.mjs".into()])
            .unwrap()
            .unwrap();

        let linkage = bridge
            .reject_synchronous_module(
                "sync-root.mjs",
                JsValue::Str("sync throw".into()),
                Label::Secret,
            )
            .unwrap();
        assert!(linkage.transitive_closure.contains("async-child.mjs"));
        assert_eq!(
            bridge.evaluator().states()["sync-root.mjs"].phase,
            AsyncModulePhase::Rejected
        );
        assert_eq!(
            bridge.evaluator().states()["async-child.mjs"].phase,
            AsyncModulePhase::Rejected
        );
        let record = bridge.promise_store().get(dependent_promise).unwrap();
        assert_eq!(
            record.state,
            PromiseState::Rejected(JsValue::Str("sync throw".into()))
        );
        assert_eq!(record.label, Label::Secret);
    }

    #[test]
    fn late_tla_dependent_inherits_synchronous_rejection_exactly() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("sync-root.mjs", false, &[]).unwrap();
        bridge
            .reject_synchronous_module(
                "sync-root.mjs",
                JsValue::Str("boom".into()),
                Label::Confidential,
            )
            .unwrap();
        let late_promise = bridge
            .register_module("late.mjs", true, &["sync-root.mjs".into()])
            .unwrap()
            .unwrap();
        let record = bridge.promise_store().get(late_promise).unwrap();
        assert_eq!(record.state, PromiseState::Rejected(JsValue::Str("boom".into())));
        assert_eq!(record.label, Label::Confidential);
        assert_eq!(
            bridge.evaluator().states()["late.mjs"].phase,
            AsyncModulePhase::Rejected
        );
    }

    #[test]
    fn synchronous_rejection_marks_live_bindings_dead() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("sync-root.mjs", false, &[]).unwrap();
        let binding = bridge.live_bindings_mut().register_cell(BindingCell::new(
            "sync-root.mjs",
            "answer",
            "answer",
            BindingType::Direct,
        ));
        bridge
            .reject_synchronous_module(
                "sync-root.mjs",
                JsValue::Str("boom".into()),
                public_label(),
            )
            .unwrap();
        assert_eq!(
            bridge.live_bindings().get_cell(&binding).map(|cell| cell.state),
            Some(BindingCellState::Dead)
        );
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
        bridge
            .reject_awaited_promise(
                awaited,
                JsValue::Str("await rejected".into()),
                public_label(),
            )
            .unwrap();
        assert_eq!(
            bridge.evaluator().states()["child.mjs"].phase,
            AsyncModulePhase::Rejected
        );
        assert!(
            bridge
                .promise_store()
                .get(child_promise)
                .unwrap()
                .state
                .is_rejected()
        );
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
    fn shared_inner_promise_resumes_awaiters_deterministically() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        bridge.register_module("b.mjs", true, &[]).unwrap();
        bridge.register_module("a.mjs", true, &[]).unwrap();
        let inner = bridge.create_pending_promise();
        bridge.suspend_module_on_promise("b.mjs", inner).unwrap();
        bridge.suspend_module_on_promise("a.mjs", inner).unwrap();
        assert_eq!(
            bridge
                .fulfill_awaited_promise(inner, JsValue::Undefined, public_label())
                .unwrap(),
            vec!["a.mjs".to_string(), "b.mjs".to_string()]
        );
    }

    #[test]
    fn evaluation_promise_cannot_use_inner_settlement_api() {
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
    fn evaluation_fulfillment_resumes_older_waiter_exactly_once() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        let waiter = bridge.register_module("waiter", true, &[]).unwrap().unwrap();
        let provider = bridge.register_module("provider", true, &[]).unwrap().unwrap();
        assert!(waiter < provider);
        bridge.suspend_module_on_promise("waiter", provider).unwrap();

        let update = bridge.fulfill_module("provider", JsValue::Int(42), Label::Secret).unwrap();
        assert_eq!(update.dependency_ready, vec!["waiter"]);
        assert_eq!(bridge.active_await("waiter"), None);
        let suspension = &bridge.evaluator().states()["waiter"].suspensions[0];
        assert!(suspension.resolved);
        assert_eq!(suspension.awaiting_promise, provider);
        assert_eq!(bridge.promise_store().get(provider).unwrap().state,
            PromiseState::Fulfilled(JsValue::Int(42)));
        assert_eq!(bridge.promise_store().get(provider).unwrap().label, Label::Secret);
        assert_eq!(bridge.promise_store().get(waiter).unwrap().state, PromiseState::Pending);

        let events = bridge.evaluator().witness_events().to_vec();
        assert!(bridge.synchronize_module("provider").unwrap().dependency_ready.is_empty());
        assert_eq!(bridge.evaluator().witness_events(), events.as_slice());
        bridge.fulfill_module("waiter", JsValue::Int(43), Label::Secret).unwrap();
        assert_eq!(bridge.promise_store().get(waiter).unwrap().state,
            PromiseState::Fulfilled(JsValue::Int(43)));
    }

    #[test]
    fn evaluation_fulfillment_does_not_resurrect_detached_waiters() {
        let mut bridge = AsyncModulePromiseBridge::with_defaults();
        let provider = bridge.register_module("provider", true, &[]).unwrap().unwrap();
        let waiter = bridge.register_module("waiter", true, &[]).unwrap().unwrap();
        bridge.suspend_module_on_promise("waiter", provider).unwrap();
        bridge.reject_module("waiter", JsValue::Int(9), Label::Confidential).unwrap();
        let update = bridge.fulfill_module("provider", JsValue::Int(42), Label::Public).unwrap();
        assert!(update.dependency_ready.is_empty());
        assert!(bridge.awaiters_by_promise.is_empty());
        assert!(bridge.active_awaits_by_module.is_empty());
        assert_eq!(bridge.promise_store().get(waiter).unwrap().state,
            PromiseState::Rejected(JsValue::Int(9)));
        assert_eq!(bridge.promise_store().get(waiter).unwrap().label, Label::Confidential);
    }
}
