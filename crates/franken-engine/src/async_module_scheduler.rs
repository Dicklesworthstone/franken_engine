#![forbid(unsafe_code)]

//! Deterministic execution-ready scheduling for async ES modules.
//!
//! The Promise bridge owns Promise/module state coherence; this module owns the
//! next missing runtime responsibility: deciding exactly which module body or
//! continuation is runnable next. It never executes JavaScript itself. Instead
//! it issues generation-stamped [`ModuleTask`] leases to the interpreter and
//! accepts explicit complete/suspend/reject outcomes. Stale or duplicated task
//! completions fail closed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::async_module_promise_bridge::{
    AsyncModulePromiseBridge, AsyncModulePromiseBridgeError, ModulePromiseUpdate,
};
use crate::ifc_artifacts::Label;
use crate::module_async_evaluation::{AsyncEvalConfig, AsyncModulePhase};
use crate::object_model::JsValue;
use crate::promise_model::PromiseHandle;

pub const ASYNC_MODULE_SCHEDULER_COMPONENT: &str = "async_module_scheduler";
pub const ASYNC_MODULE_SCHEDULER_SCHEMA_VERSION: &str =
    "franken-engine.async-module-scheduler.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleTaskKind {
    Start,
    Resume,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ModuleTask {
    pub sequence: u64,
    pub generation: u64,
    pub module_specifier: String,
    pub kind: ModuleTaskKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AsyncModuleSchedulerConfig {
    pub evaluator: AsyncEvalConfig,
    pub max_registered_modules: usize,
    pub max_ready_tasks: usize,
    pub max_dispatched_tasks: u64,
}

impl Default for AsyncModuleSchedulerConfig {
    fn default() -> Self {
        Self {
            evaluator: AsyncEvalConfig::default(),
            max_registered_modules: 65_536,
            max_ready_tasks: 65_536,
            max_dispatched_tasks: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerSnapshot {
    pub registered_modules: usize,
    pub ready_tasks: usize,
    pub in_flight_tasks: usize,
    pub started_modules: usize,
    pub dispatched_tasks: u64,
    pub next_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsyncModuleSchedulerError {
    Bridge { detail: String },
    RegisteredModuleLimitExceeded { max: usize },
    ReadyQueueLimitExceeded { max: usize },
    DispatchBudgetExceeded { max: u64 },
    UnknownTask { module_specifier: String },
    StaleTask {
        module_specifier: String,
        expected_generation: u64,
        actual_generation: u64,
    },
    ModuleAlreadyInFlight { module_specifier: String },
    ModuleNotInFlight { module_specifier: String },
    ModuleTerminal {
        module_specifier: String,
        phase: AsyncModulePhase,
    },
    InvalidTaskKind {
        module_specifier: String,
        expected: ModuleTaskKind,
        actual: ModuleTaskKind,
    },
}

impl fmt::Display for AsyncModuleSchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bridge { detail } => write!(f, "async module bridge failed: {detail}"),
            Self::RegisteredModuleLimitExceeded { max } => {
                write!(f, "async module scheduler registration limit {max} exceeded")
            }
            Self::ReadyQueueLimitExceeded { max } => {
                write!(f, "async module scheduler ready-queue limit {max} exceeded")
            }
            Self::DispatchBudgetExceeded { max } => {
                write!(f, "async module scheduler dispatch budget {max} exhausted")
            }
            Self::UnknownTask { module_specifier } => {
                write!(f, "no scheduler state for module {module_specifier}")
            }
            Self::StaleTask {
                module_specifier,
                expected_generation,
                actual_generation,
            } => write!(
                f,
                "stale async module task for {module_specifier}: expected generation {expected_generation}, got {actual_generation}"
            ),
            Self::ModuleAlreadyInFlight { module_specifier } => {
                write!(f, "module {module_specifier} already has an in-flight task")
            }
            Self::ModuleNotInFlight { module_specifier } => {
                write!(f, "module {module_specifier} has no in-flight task")
            }
            Self::ModuleTerminal {
                module_specifier,
                phase,
            } => write!(f, "module {module_specifier} is already terminal ({phase})"),
            Self::InvalidTaskKind {
                module_specifier,
                expected,
                actual,
            } => write!(
                f,
                "module {module_specifier} task kind mismatch: expected {expected:?}, got {actual:?}"
            ),
        }
    }
}

impl std::error::Error for AsyncModuleSchedulerError {}

impl From<AsyncModulePromiseBridgeError> for AsyncModuleSchedulerError {
    fn from(value: AsyncModulePromiseBridgeError) -> Self {
        Self::Bridge {
            detail: value.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReadyKey {
    sequence: u64,
    module_specifier: String,
    generation: u64,
    kind: ModuleTaskKind,
}

fn runtime_terminal(phase: AsyncModulePhase) -> bool {
    matches!(phase, AsyncModulePhase::Settled | AsyncModulePhase::Rejected)
}

pub struct AsyncModuleScheduler {
    bridge: AsyncModulePromiseBridge,
    config: AsyncModuleSchedulerConfig,
    ready: BTreeSet<ReadyKey>,
    queued_by_module: BTreeMap<String, ReadyKey>,
    in_flight: BTreeMap<String, ModuleTask>,
    started: BTreeSet<String>,
    generations: BTreeMap<String, u64>,
    next_sequence: u64,
    dispatched_tasks: u64,
}

impl AsyncModuleScheduler {
    pub fn new(config: AsyncModuleSchedulerConfig) -> Self {
        Self {
            bridge: AsyncModulePromiseBridge::new(config.evaluator.clone()),
            config,
            ready: BTreeSet::new(),
            queued_by_module: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            started: BTreeSet::new(),
            generations: BTreeMap::new(),
            next_sequence: 0,
            dispatched_tasks: 0,
        }
    }

    pub fn register_module(
        &mut self,
        specifier: &str,
        has_top_level_await: bool,
        dependencies: &[String],
    ) -> Result<Option<PromiseHandle>, AsyncModuleSchedulerError> {
        if self.bridge.evaluator().states().contains_key(specifier) {
            return Err(AsyncModulePromiseBridgeError::DuplicateModule {
                specifier: specifier.to_string(),
            }
            .into());
        }
        if self.bridge.evaluator().states().len() >= self.config.max_registered_modules {
            return Err(AsyncModuleSchedulerError::RegisteredModuleLimitExceeded {
                max: self.config.max_registered_modules,
            });
        }
        // Match the evaluator's registration readiness before it creates a
        // Promise or emits events. Rejected dependencies produce a terminal
        // module and require no queue slot; pending dependencies defer it.
        let immediately_ready = dependencies.iter().all(|dependency| {
            self.bridge
                .evaluator()
                .states()
                .get(dependency)
                .is_none_or(|state| {
                    state.phase.is_terminal() && state.phase != AsyncModulePhase::Rejected
                })
        });
        if immediately_ready {
            self.ensure_ready_capacity(1)?;
        }
        let promise = self
            .bridge
            .register_module(specifier, has_top_level_await, dependencies)?;
        self.generations.entry(specifier.to_string()).or_insert(0);
        let state = &self.bridge.evaluator().states()[specifier];
        if !runtime_terminal(state.phase) && state.pending_dependencies.is_empty() {
            self.enqueue(specifier, ModuleTaskKind::Start)?;
        }
        Ok(promise)
    }

    pub fn create_pending_promise(&mut self) -> PromiseHandle {
        self.bridge.create_pending_promise()
    }

    pub fn next_task(&mut self) -> Result<Option<ModuleTask>, AsyncModuleSchedulerError> {
        let Some(key) = self.ready.iter().next().cloned() else {
            return Ok(None);
        };
        if self.dispatched_tasks >= self.config.max_dispatched_tasks {
            return Err(AsyncModuleSchedulerError::DispatchBudgetExceeded {
                max: self.config.max_dispatched_tasks,
            });
        }
        if self.in_flight.contains_key(&key.module_specifier) {
            return Err(AsyncModuleSchedulerError::ModuleAlreadyInFlight {
                module_specifier: key.module_specifier,
            });
        }
        self.ready.remove(&key);
        self.queued_by_module.remove(&key.module_specifier);
        let task = ModuleTask {
            sequence: key.sequence,
            generation: key.generation,
            module_specifier: key.module_specifier.clone(),
            kind: key.kind,
        };
        self.started.insert(task.module_specifier.clone());
        self.in_flight
            .insert(task.module_specifier.clone(), task.clone());
        self.dispatched_tasks = self.dispatched_tasks.saturating_add(1);
        Ok(Some(task))
    }

    pub fn suspend_task(
        &mut self,
        task: &ModuleTask,
        promise: PromiseHandle,
    ) -> Result<(), AsyncModuleSchedulerError> {
        self.validate_in_flight(task)?;
        self.bridge
            .suspend_module_on_promise(&task.module_specifier, promise)?;
        self.in_flight.remove(&task.module_specifier);
        Ok(())
    }

    pub fn complete_task(
        &mut self,
        task: &ModuleTask,
        value: JsValue,
        label: Label,
    ) -> Result<Option<ModulePromiseUpdate>, AsyncModuleSchedulerError> {
        self.validate_in_flight(task)?;
        // Settlement cannot be undone. Admit the entire newly ready batch
        // before changing the evaluator, Promise store, or in-flight lease.
        // The authoritative pending sets identify exactly those dependents
        // for which this completion removes the final outstanding dependency.
        self.preflight_ready_batch(
            self.bridge
                .evaluator()
                .states()
                .iter()
                .filter(|(_, state)| {
                    !runtime_terminal(state.phase)
                        && state.pending_dependencies.len() == 1
                        && state.pending_dependencies.contains(&task.module_specifier)
                })
                .map(|(specifier, _)| (specifier.as_str(), self.next_kind(specifier))),
        )?;
        let has_top_level_await = self.bridge.evaluator().states()[&task.module_specifier]
            .has_top_level_await;
        if has_top_level_await {
            let update = self
                .bridge
                .fulfill_module(&task.module_specifier, value, label)?;
            let ready = update.dependency_ready.clone();
            self.in_flight.remove(&task.module_specifier);
            self.enqueue_newly_ready(&ready)?;
            Ok(Some(update))
        } else {
            let ready = self
                .bridge
                .complete_synchronous_module(&task.module_specifier)?;
            self.in_flight.remove(&task.module_specifier);
            self.enqueue_newly_ready(&ready)?;
            Ok(None)
        }
    }

    pub fn reject_task(
        &mut self,
        task: &ModuleTask,
        reason: JsValue,
        label: Label,
    ) -> Result<Option<ModulePromiseUpdate>, AsyncModuleSchedulerError> {
        self.validate_in_flight(task)?;
        let has_top_level_await = self.bridge.evaluator().states()[&task.module_specifier]
            .has_top_level_await;
        let update = if has_top_level_await {
            Some(
                self.bridge
                    .reject_module(&task.module_specifier, reason, label)?,
            )
        } else {
            self.bridge
                .reject_synchronous_module(&task.module_specifier, reason, label)?;
            None
        };
        self.in_flight.remove(&task.module_specifier);
        self.purge_runtime_terminal_modules();
        Ok(update)
    }

    pub fn fulfill_awaited_promise(
        &mut self,
        promise: PromiseHandle,
        value: JsValue,
        label: Label,
    ) -> Result<Vec<String>, AsyncModuleSchedulerError> {
        // A shared Promise can wake many modules. Refusing after only part of
        // that batch was enqueued would strand the rest on an already-settled
        // Promise, so reserve all required slots before settling it.
        self.preflight_ready_batch(
            self.bridge
                .evaluator()
                .states()
                .keys()
                .filter(|specifier| self.bridge.active_await(specifier) == Some(promise))
                .map(|specifier| (specifier.as_str(), ModuleTaskKind::Resume)),
        )?;
        let resumable = self
            .bridge
            .fulfill_awaited_promise(promise, value, label)?;
        for specifier in &resumable {
            self.enqueue(specifier, ModuleTaskKind::Resume)?;
        }
        Ok(resumable)
    }

    pub fn reject_awaited_promise(
        &mut self,
        promise: PromiseHandle,
        reason: JsValue,
        label: Label,
    ) -> Result<Vec<ModulePromiseUpdate>, AsyncModuleSchedulerError> {
        let updates = self
            .bridge
            .reject_awaited_promise(promise, reason, label)?;
        self.purge_runtime_terminal_modules();
        Ok(updates)
    }

    pub fn snapshot(&self) -> SchedulerSnapshot {
        SchedulerSnapshot {
            registered_modules: self.bridge.evaluator().states().len(),
            ready_tasks: self.ready.len(),
            in_flight_tasks: self.in_flight.len(),
            started_modules: self.started.len(),
            dispatched_tasks: self.dispatched_tasks,
            next_sequence: self.next_sequence,
        }
    }

    pub fn bridge(&self) -> &AsyncModulePromiseBridge {
        &self.bridge
    }

    pub fn in_flight_task(&self, specifier: &str) -> Option<&ModuleTask> {
        self.in_flight.get(specifier)
    }

    fn next_kind(&self, specifier: &str) -> ModuleTaskKind {
        if self.started.contains(specifier) {
            ModuleTaskKind::Resume
        } else {
            ModuleTaskKind::Start
        }
    }

    fn ensure_ready_capacity(&self, additional: usize) -> Result<(), AsyncModuleSchedulerError> {
        if additional > self.config.max_ready_tasks.saturating_sub(self.ready.len()) {
            return Err(AsyncModuleSchedulerError::ReadyQueueLimitExceeded {
                max: self.config.max_ready_tasks,
            });
        }
        Ok(())
    }

    /// Whether admission needs a new slot. This is shared by preflight and
    /// enqueue so duplicate leases and conflicting task kinds cannot drift.
    fn enqueue_slot_required(
        &self,
        specifier: &str,
        kind: ModuleTaskKind,
    ) -> Result<bool, AsyncModuleSchedulerError> {
        if self.in_flight.contains_key(specifier) {
            return Err(AsyncModuleSchedulerError::ModuleAlreadyInFlight {
                module_specifier: specifier.to_string(),
            });
        }
        if let Some(existing) = self.queued_by_module.get(specifier) {
            if existing.kind == kind {
                return Ok(false);
            }
            return Err(AsyncModuleSchedulerError::InvalidTaskKind {
                module_specifier: specifier.to_string(),
                expected: existing.kind,
                actual: kind,
            });
        }
        Ok(true)
    }

    /// Callers traverse unique module keys from the authoritative state map.
    /// Pending dependencies are intentionally allowed here: the admitted
    /// transition clears them before enqueue. No state or sequence is changed.
    fn preflight_ready_batch<'a>(
        &self,
        modules: impl Iterator<Item = (&'a str, ModuleTaskKind)>,
    ) -> Result<(), AsyncModuleSchedulerError> {
        let mut additional = 0usize;
        for (specifier, kind) in modules {
            if self.enqueue_slot_required(specifier, kind)? {
                additional = additional.saturating_add(1);
            }
        }
        self.ensure_ready_capacity(additional)
    }

    fn enqueue_newly_ready(
        &mut self,
        modules: &[String],
    ) -> Result<(), AsyncModuleSchedulerError> {
        for specifier in modules {
            // Rejection may have made a pending dependency edge obsolete.
            // Resolving that edge must not resurrect its terminal dependent.
            if self
                .bridge
                .evaluator()
                .states()
                .get(specifier)
                .is_some_and(|state| runtime_terminal(state.phase))
            {
                continue;
            }
            self.enqueue(specifier, self.next_kind(specifier))?;
        }
        Ok(())
    }

    fn enqueue(
        &mut self,
        specifier: &str,
        kind: ModuleTaskKind,
    ) -> Result<(), AsyncModuleSchedulerError> {
        let state = self
            .bridge
            .evaluator()
            .states()
            .get(specifier)
            .ok_or_else(|| AsyncModuleSchedulerError::UnknownTask {
                module_specifier: specifier.to_string(),
            })?;
        if runtime_terminal(state.phase) {
            return Err(AsyncModuleSchedulerError::ModuleTerminal {
                module_specifier: specifier.to_string(),
                phase: state.phase,
            });
        }
        if !state.pending_dependencies.is_empty() {
            return Err(AsyncModuleSchedulerError::Bridge {
                detail: format!(
                    "module {specifier} was marked ready while dependencies remain pending"
                ),
            });
        }
        if !self.enqueue_slot_required(specifier, kind)? {
            return Ok(());
        }
        self.ensure_ready_capacity(1)?;
        let generation = self
            .generations
            .entry(specifier.to_string())
            .and_modify(|value| *value = value.saturating_add(1))
            .or_insert(1);
        let key = ReadyKey {
            sequence: self.next_sequence,
            module_specifier: specifier.to_string(),
            generation: *generation,
            kind,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.ready.insert(key.clone());
        self.queued_by_module.insert(specifier.to_string(), key);
        Ok(())
    }

    fn validate_in_flight(&self, task: &ModuleTask) -> Result<(), AsyncModuleSchedulerError> {
        let Some(current) = self.in_flight.get(&task.module_specifier) else {
            return Err(AsyncModuleSchedulerError::ModuleNotInFlight {
                module_specifier: task.module_specifier.clone(),
            });
        };
        if current.generation != task.generation {
            return Err(AsyncModuleSchedulerError::StaleTask {
                module_specifier: task.module_specifier.clone(),
                expected_generation: current.generation,
                actual_generation: task.generation,
            });
        }
        if current.kind != task.kind {
            return Err(AsyncModuleSchedulerError::InvalidTaskKind {
                module_specifier: task.module_specifier.clone(),
                expected: current.kind,
                actual: task.kind,
            });
        }
        Ok(())
    }

    fn purge_runtime_terminal_modules(&mut self) {
        let terminal: Vec<String> = self
            .bridge
            .evaluator()
            .states()
            .iter()
            .filter(|(_, state)| runtime_terminal(state.phase))
            .map(|(specifier, _)| specifier.clone())
            .collect();
        for specifier in terminal {
            if let Some(key) = self.queued_by_module.remove(&specifier) {
                self.ready.remove(&key);
            }
            self.in_flight.remove(&specifier);
        }
    }
}

impl Default for AsyncModuleScheduler {
    fn default() -> Self {
        Self::new(AsyncModuleSchedulerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public() -> Label {
        Label::Public
    }

    #[test]
    fn synchronous_root_is_runnable_then_settles() {
        let mut scheduler = AsyncModuleScheduler::default();
        scheduler.register_module("sync.mjs", false, &[]).unwrap();
        let task = scheduler.next_task().unwrap().expect("sync root ready");
        assert_eq!(task.kind, ModuleTaskKind::Start);
        assert_eq!(task.module_specifier, "sync.mjs");
        scheduler
            .complete_task(&task, JsValue::Undefined, public())
            .unwrap();
        assert_eq!(
            scheduler.bridge().evaluator().states()["sync.mjs"].phase,
            AsyncModulePhase::Settled
        );
        assert!(scheduler.next_task().unwrap().is_none());
    }

    #[test]
    fn synchronous_rejection_rejects_dependent_tla_promise() {
        let mut scheduler = AsyncModuleScheduler::default();
        scheduler.register_module("root.mjs", false, &[]).unwrap();
        let child_promise = scheduler
            .register_module("child.mjs", true, &["root.mjs".into()])
            .unwrap()
            .unwrap();
        let root = scheduler.next_task().unwrap().expect("root ready");
        let update = scheduler
            .reject_task(
                &root,
                JsValue::Str("sync throw".into()),
                Label::Secret,
            )
            .unwrap();
        assert!(update.is_none());
        assert_eq!(
            scheduler.bridge().evaluator().states()["root.mjs"].phase,
            AsyncModulePhase::Rejected
        );
        assert_eq!(
            scheduler.bridge().evaluator().states()["child.mjs"].phase,
            AsyncModulePhase::Rejected
        );
        assert!(
            scheduler
                .bridge()
                .promise_store()
                .get(child_promise)
                .unwrap()
                .state
                .is_rejected()
        );
        assert!(scheduler.next_task().unwrap().is_none());
    }

    #[test]
    fn dependency_order_is_enforced_without_manual_resume_calls() {
        let mut scheduler = AsyncModuleScheduler::default();
        scheduler.register_module("dep.mjs", true, &[]).unwrap();
        scheduler
            .register_module("app.mjs", false, &["dep.mjs".into()])
            .unwrap();

        let dep = scheduler.next_task().unwrap().expect("dep ready");
        assert_eq!(dep.module_specifier, "dep.mjs");
        assert_eq!(dep.kind, ModuleTaskKind::Start);
        assert!(scheduler.next_task().unwrap().is_none());

        scheduler
            .complete_task(&dep, JsValue::Undefined, public())
            .unwrap();
        let app = scheduler.next_task().unwrap().expect("app ready");
        assert_eq!(app.module_specifier, "app.mjs");
        assert_eq!(app.kind, ModuleTaskKind::Start);
    }

    #[test]
    fn pending_await_requeues_resume_continuation() {
        let mut scheduler = AsyncModuleScheduler::default();
        scheduler.register_module("app.mjs", true, &[]).unwrap();
        let task = scheduler.next_task().unwrap().unwrap();
        let pending = scheduler.create_pending_promise();
        scheduler.suspend_task(&task, pending).unwrap();
        assert!(scheduler.next_task().unwrap().is_none());

        let resumed = scheduler
            .fulfill_awaited_promise(pending, JsValue::Int(42), public())
            .unwrap();
        assert_eq!(resumed, vec!["app.mjs".to_string()]);
        let resume = scheduler.next_task().unwrap().unwrap();
        assert_eq!(resume.module_specifier, "app.mjs");
        assert_eq!(resume.kind, ModuleTaskKind::Resume);
        assert!(resume.generation > task.generation);
    }

    #[test]
    fn stale_task_completion_is_rejected() {
        let mut scheduler = AsyncModuleScheduler::default();
        scheduler.register_module("app.mjs", true, &[]).unwrap();
        let first = scheduler.next_task().unwrap().unwrap();
        let pending = scheduler.create_pending_promise();
        scheduler.suspend_task(&first, pending).unwrap();
        scheduler
            .fulfill_awaited_promise(pending, JsValue::Undefined, public())
            .unwrap();
        let second = scheduler.next_task().unwrap().unwrap();
        assert!(second.generation > first.generation);
        let error = scheduler
            .complete_task(&first, JsValue::Undefined, public())
            .unwrap_err();
        assert!(matches!(error, AsyncModuleSchedulerError::StaleTask { .. }));
    }

    #[test]
    fn await_rejection_purges_transitive_dependents() {
        let mut scheduler = AsyncModuleScheduler::default();
        scheduler.register_module("root.mjs", true, &[]).unwrap();
        scheduler
            .register_module("child.mjs", true, &["root.mjs".into()])
            .unwrap();
        let task = scheduler.next_task().unwrap().unwrap();
        let pending = scheduler.create_pending_promise();
        scheduler.suspend_task(&task, pending).unwrap();
        scheduler
            .reject_awaited_promise(pending, JsValue::Str("boom".into()), public())
            .unwrap();
        assert_eq!(
            scheduler.bridge().evaluator().states()["root.mjs"].phase,
            AsyncModulePhase::Rejected
        );
        assert_eq!(
            scheduler.bridge().evaluator().states()["child.mjs"].phase,
            AsyncModulePhase::Rejected
        );
        assert!(scheduler.next_task().unwrap().is_none());
    }

    #[test]
    fn deterministic_registration_order_drives_ready_order() {
        let mut scheduler = AsyncModuleScheduler::default();
        scheduler.register_module("z.mjs", false, &[]).unwrap();
        scheduler.register_module("a.mjs", false, &[]).unwrap();
        let first = scheduler.next_task().unwrap().unwrap();
        let second = scheduler.next_task().unwrap().unwrap();
        assert_eq!(first.module_specifier, "z.mjs");
        assert_eq!(second.module_specifier, "a.mjs");
        assert!(first.sequence < second.sequence);
    }

    #[test]
    fn dispatch_budget_is_fail_closed() {
        let mut scheduler = AsyncModuleScheduler::new(AsyncModuleSchedulerConfig {
            max_dispatched_tasks: 1,
            ..AsyncModuleSchedulerConfig::default()
        });
        scheduler.register_module("a.mjs", true, &[]).unwrap();
        scheduler.register_module("b.mjs", true, &[]).unwrap();
        assert!(scheduler.next_task().unwrap().is_some());
        assert!(matches!(
            scheduler.next_task().unwrap_err(),
            AsyncModuleSchedulerError::DispatchBudgetExceeded { max: 1 }
        ));
    }

    fn observable_state(scheduler: &AsyncModuleScheduler) -> serde_json::Value {
        serde_json::json!({
            "snapshot": scheduler.snapshot(),
            "modules": scheduler.bridge().evaluator().states(),
            "promises": scheduler.bridge().promise_store(),
            "microtasks": scheduler.bridge().microtasks(),
            "bindings": scheduler.bridge().live_bindings(),
            "in_flight": &scheduler.in_flight,
            "started": &scheduler.started,
            "generations": &scheduler.generations,
        })
    }

    fn bounded_scheduler(max_ready_tasks: usize) -> AsyncModuleScheduler {
        AsyncModuleScheduler::new(AsyncModuleSchedulerConfig {
            max_ready_tasks,
            ..AsyncModuleSchedulerConfig::default()
        })
    }

    #[test]
    fn registration_capacity_refusal_preserves_state_and_is_retryable() {
        let mut scheduler = bounded_scheduler(1);
        scheduler.register_module("occupied", false, &[]).unwrap();
        let before = observable_state(&scheduler);
        assert!(matches!(
            scheduler.register_module("new", true, &[]),
            Err(AsyncModuleSchedulerError::ReadyQueueLimitExceeded { max: 1 })
        ));
        assert_eq!(observable_state(&scheduler), before);
        scheduler.next_task().unwrap().unwrap();
        let promise = scheduler.register_module("new", true, &[]).unwrap().unwrap();
        assert_eq!(promise, PromiseHandle(0));
        let task = scheduler.next_task().unwrap().unwrap();
        assert_eq!(task.module_specifier, "new");
        assert_eq!(task.sequence, 1);
        assert_eq!(task.generation, 1);
    }

    #[test]
    fn zero_capacity_registration_creates_no_promise_or_module() {
        let mut scheduler = bounded_scheduler(0);
        let before = observable_state(&scheduler);
        for has_tla in [false, true] {
            assert!(matches!(
                scheduler.register_module("new", has_tla, &[]),
                Err(AsyncModuleSchedulerError::ReadyQueueLimitExceeded { max: 0 })
            ));
            assert_eq!(observable_state(&scheduler), before);
        }
        assert_eq!(scheduler.create_pending_promise(), PromiseHandle(0));
    }

    #[test]
    fn completion_fanout_refusal_preserves_lease_and_retries_whole_batch() {
        let mut scheduler = bounded_scheduler(2);
        let root_promise = scheduler.register_module("root", true, &[]).unwrap().unwrap();
        scheduler.register_module("occupied", false, &[]).unwrap();
        let root = scheduler.next_task().unwrap().unwrap();
        for child in ["a", "b"] {
            scheduler.register_module(child, true, &["root".into()]).unwrap();
        }
        let before = observable_state(&scheduler);
        assert!(matches!(
            scheduler.complete_task(&root, JsValue::Int(7), Label::Secret),
            Err(AsyncModuleSchedulerError::ReadyQueueLimitExceeded { max: 2 })
        ));
        assert_eq!(observable_state(&scheduler), before);
        assert_eq!(scheduler.in_flight_task("root"), Some(&root));
        assert_eq!(
            scheduler.bridge().promise_store().get(root_promise).unwrap().state,
            crate::promise_model::PromiseState::Pending
        );
        assert_eq!(scheduler.next_task().unwrap().unwrap().module_specifier, "occupied");
        let update = scheduler.complete_task(&root, JsValue::Int(7), Label::Secret)
            .unwrap().unwrap();
        assert_eq!(update.dependency_ready, vec!["a", "b"]);
        let a = scheduler.next_task().unwrap().unwrap();
        let b = scheduler.next_task().unwrap().unwrap();
        assert_eq!((a.module_specifier.as_str(), a.sequence), ("a", 2));
        assert_eq!((b.module_specifier.as_str(), b.sequence), ("b", 3));
        assert!(scheduler.next_task().unwrap().is_none());
        assert!(scheduler.complete_task(&root, JsValue::Undefined, public()).is_err());
    }

    #[test]
    fn shared_await_refusal_preserves_all_waiters_and_exact_settlement() {
        let mut scheduler = bounded_scheduler(2);
        for module in ["a", "b"] {
            scheduler.register_module(module, true, &[]).unwrap();
        }
        let a = scheduler.next_task().unwrap().unwrap();
        let b = scheduler.next_task().unwrap().unwrap();
        let promise = scheduler.create_pending_promise();
        scheduler.suspend_task(&a, promise).unwrap();
        scheduler.suspend_task(&b, promise).unwrap();
        scheduler.register_module("occupied", false, &[]).unwrap();
        let before = observable_state(&scheduler);
        assert!(matches!(
            scheduler.fulfill_awaited_promise(promise, JsValue::Int(42), Label::Secret),
            Err(AsyncModuleSchedulerError::ReadyQueueLimitExceeded { max: 2 })
        ));
        assert_eq!(observable_state(&scheduler), before);
        assert_eq!(scheduler.bridge().active_await("a"), Some(promise));
        assert_eq!(scheduler.bridge().active_await("b"), Some(promise));
        scheduler.next_task().unwrap().unwrap();
        assert_eq!(
            scheduler.fulfill_awaited_promise(promise, JsValue::Int(42), Label::Secret).unwrap(),
            vec!["a", "b"]
        );
        let record = scheduler.bridge().promise_store().get(promise).unwrap();
        assert_eq!(record.state, crate::promise_model::PromiseState::Fulfilled(JsValue::Int(42)));
        assert_eq!(record.label, Label::Secret);
        for expected in ["a", "b"] {
            let task = scheduler.next_task().unwrap().unwrap();
            assert_eq!(task.module_specifier, expected);
            assert_eq!(task.kind, ModuleTaskKind::Resume);
            assert_eq!(task.generation, 2);
        }
        assert!(scheduler.next_task().unwrap().is_none());
    }

    #[test]
    fn completion_reserves_only_dependents_losing_their_last_dependency() {
        let mut scheduler = bounded_scheduler(2);
        scheduler.register_module("x", true, &[]).unwrap();
        scheduler.register_module("y", true, &[]).unwrap();
        scheduler.register_module("both", true, &["x".into(), "y".into()]).unwrap();
        scheduler.register_module("only_x", true, &["x".into()]).unwrap();
        let x = scheduler.next_task().unwrap().unwrap();
        let y = scheduler.next_task().unwrap().unwrap();
        scheduler.register_module("occupied", false, &[]).unwrap();
        scheduler.complete_task(&x, JsValue::Undefined, public()).unwrap();
        assert_eq!(scheduler.snapshot().ready_tasks, 2);
        let before = observable_state(&scheduler);
        assert!(matches!(
            scheduler.complete_task(&y, JsValue::Undefined, public()),
            Err(AsyncModuleSchedulerError::ReadyQueueLimitExceeded { max: 2 })
        ));
        assert_eq!(observable_state(&scheduler), before);
        assert_eq!(scheduler.next_task().unwrap().unwrap().module_specifier, "occupied");
        scheduler.complete_task(&y, JsValue::Undefined, public()).unwrap();
        assert_eq!(scheduler.next_task().unwrap().unwrap().module_specifier, "only_x");
        assert_eq!(scheduler.next_task().unwrap().unwrap().module_specifier, "both");
        assert!(scheduler.next_task().unwrap().is_none());
    }

    #[test]
    fn unobserved_promise_can_settle_when_ready_queue_is_full() {
        let mut scheduler = bounded_scheduler(1);
        scheduler.register_module("occupied", false, &[]).unwrap();
        let promise = scheduler.create_pending_promise();
        let before = scheduler.snapshot();
        assert!(scheduler.fulfill_awaited_promise(promise, JsValue::Int(5), public())
            .unwrap().is_empty());
        assert_eq!(scheduler.snapshot(), before);
        assert_eq!(
            scheduler.bridge().promise_store().get(promise).unwrap().state,
            crate::promise_model::PromiseState::Fulfilled(JsValue::Int(5))
        );
    }

    #[test]
    fn capacity_refusal_does_not_prevent_rejection_cleanup() {
        let mut scheduler = bounded_scheduler(1);
        scheduler.register_module("root", true, &[]).unwrap();
        for child in ["a", "b"] {
            scheduler.register_module(child, true, &["root".into()]).unwrap();
        }
        let root = scheduler.next_task().unwrap().unwrap();
        assert!(matches!(
            scheduler.complete_task(&root, JsValue::Undefined, public()),
            Err(AsyncModuleSchedulerError::ReadyQueueLimitExceeded { max: 1 })
        ));
        scheduler.reject_task(&root, JsValue::Str("aborted".into()), Label::Secret).unwrap();
        for module in ["root", "a", "b"] {
            assert_eq!(scheduler.bridge().evaluator().states()[module].phase, AsyncModulePhase::Rejected);
            let promise = scheduler.bridge().module_promise(module).unwrap();
            let record = scheduler.bridge().promise_store().get(promise).unwrap();
            assert_eq!(record.state, crate::promise_model::PromiseState::Rejected(JsValue::Str("aborted".into())));
            assert_eq!(record.label, Label::Secret);
        }
        assert_eq!(scheduler.snapshot().ready_tasks, 0);
        assert_eq!(scheduler.snapshot().in_flight_tasks, 0);
    }
}
