#![forbid(unsafe_code)]

//! High-level async-module runtime boundary.
//!
//! This type deliberately owns the scheduler instead of exposing incremental
//! graph registration. Construction validates the complete module graph before
//! any runtime state escapes, then registers nodes dependency-first. Callers
//! receive only execution-task lifecycle operations after initialization.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::async_module_graph::{
    ModuleGraphError, ModuleGraphLimits, ModuleGraphNode, ModuleGraphPlan, register_module_graph,
};
use crate::async_module_promise_bridge::ModulePromiseUpdate;
use crate::async_module_scheduler::{
    AsyncModuleScheduler, AsyncModuleSchedulerConfig, AsyncModuleSchedulerError, ModuleTask,
    ModuleTaskKind, SchedulerSnapshot,
};
use crate::ifc_artifacts::Label;
use crate::module_async_evaluation::{AsyncModulePhase, SuspensionContext};
use crate::object_model::JsValue;
use crate::promise_model::{PromiseHandle, PromiseState};

pub const ASYNC_MODULE_RUNTIME_COMPONENT: &str = "async_module_runtime";
pub const ASYNC_MODULE_RUNTIME_SCHEMA_VERSION: &str = "franken-engine.async-module-runtime.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsyncModuleRuntimeMetadata {
    pub graph_plan: ModuleGraphPlan,
    pub evaluation_promises: BTreeMap<String, PromiseHandle>,
}

/// Input for the continuation after a successful top-level await. The label
/// must accompany the value into the interpreter's continuation registers/PC;
/// handing off only the value would lose the Promise's confidentiality floor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleAwaitInput {
    pub promise: PromiseHandle,
    pub value: JsValue,
    pub label: Label,
}

#[derive(Debug)]
pub struct AsyncModuleRuntime {
    scheduler: AsyncModuleScheduler,
    metadata: AsyncModuleRuntimeMetadata,
}

impl AsyncModuleRuntime {
    pub fn from_graph(
        nodes: &[ModuleGraphNode],
        graph_limits: &ModuleGraphLimits,
        scheduler_config: AsyncModuleSchedulerConfig,
    ) -> Result<Self, ModuleGraphError> {
        let mut scheduler = AsyncModuleScheduler::new(scheduler_config);
        let registered = register_module_graph(&mut scheduler, nodes, graph_limits)?;
        Ok(Self {
            scheduler,
            metadata: AsyncModuleRuntimeMetadata {
                graph_plan: registered.plan,
                evaluation_promises: registered.evaluation_promises,
            },
        })
    }

    pub fn with_defaults(nodes: &[ModuleGraphNode]) -> Result<Self, ModuleGraphError> {
        Self::from_graph(
            nodes,
            &ModuleGraphLimits::default(),
            AsyncModuleSchedulerConfig::default(),
        )
    }

    pub fn metadata(&self) -> &AsyncModuleRuntimeMetadata {
        &self.metadata
    }

    pub fn snapshot(&self) -> SchedulerSnapshot {
        self.scheduler.snapshot()
    }

    pub fn module_phases(&self) -> BTreeMap<String, AsyncModulePhase> {
        self.scheduler
            .bridge()
            .evaluator()
            .states()
            .iter()
            .map(|(specifier, state)| (specifier.clone(), state.phase))
            .collect()
    }

    pub fn create_pending_promise(&mut self) -> PromiseHandle {
        self.scheduler.create_pending_promise()
    }

    pub fn next_task(&mut self) -> Result<Option<ModuleTask>, AsyncModuleSchedulerError> {
        self.scheduler.next_task()
    }

    /// Read the authoritative value and label for a live continuation lease.
    ///
    /// Start tasks return None, not a fabricated `undefined` await result.
    /// Resume tasks use the latest resolved suspension, so repeated awaits and
    /// shared Promises cannot reuse another continuation's result. This lookup
    /// is read-only and repeatable until the task is suspended or completed.
    /// No parallel cache of guest values or Promise settlement is maintained.
    pub fn resume_input(
        &self,
        task: &ModuleTask,
    ) -> Result<Option<ModuleAwaitInput>, AsyncModuleSchedulerError> {
        let current = self
            .scheduler
            .in_flight_task(&task.module_specifier)
            .ok_or_else(|| AsyncModuleSchedulerError::ModuleNotInFlight {
                module_specifier: task.module_specifier.clone(),
            })?;
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
        if current.sequence != task.sequence {
            return Err(AsyncModuleSchedulerError::Bridge {
                detail: format!(
                    "module {} task sequence mismatch: expected {}, got {}",
                    task.module_specifier, current.sequence, task.sequence
                ),
            });
        }
        if task.kind == ModuleTaskKind::Start {
            return Ok(None);
        }
        let suspension = self
            .scheduler
            .bridge()
            .evaluator()
            .states()
            .get(&task.module_specifier)
            .and_then(|state| state.suspensions.last())
            .filter(|suspension| {
                suspension.resolved
                    && matches!(suspension.context, SuspensionContext::TopLevelAwait)
            })
            .ok_or_else(|| AsyncModuleSchedulerError::Bridge {
                detail: format!(
                    "module {} has a resume lease without a resolved top-level await",
                    task.module_specifier
                ),
            })?;
        let promise = suspension.awaiting_promise;
        let (state, label) = self.promise_result(promise)?;
        let PromiseState::Fulfilled(value) = state else {
            return Err(AsyncModuleSchedulerError::Bridge {
                detail: format!(
                    "module {} cannot resume from {promise} in state {state}",
                    task.module_specifier
                ),
            });
        };
        Ok(Some(ModuleAwaitInput {
            promise,
            value: value.clone(),
            label: label.clone(),
        }))
    }

    /// Inspect a host or evaluation Promise without exposing mutable Promise
    /// storage. Rejection reasons and their labels remain observable even when
    /// rejection has invalidated every affected task lease. Unknown handles
    /// fail explicitly; pending and fulfilled-undefined are distinct states.
    pub fn promise_result(
        &self,
        promise: PromiseHandle,
    ) -> Result<(&PromiseState, &Label), AsyncModuleSchedulerError> {
        let record = self
            .scheduler
            .bridge()
            .promise_store()
            .get(promise)
            .map_err(|error| AsyncModuleSchedulerError::Bridge {
                detail: format!("cannot inspect {promise}: {error}"),
            })?;
        Ok((&record.state, &record.label))
    }

    pub fn suspend_task(
        &mut self,
        task: &ModuleTask,
        promise: PromiseHandle,
    ) -> Result<(), AsyncModuleSchedulerError> {
        self.scheduler.suspend_task(task, promise)
    }

    pub fn complete_task(
        &mut self,
        task: &ModuleTask,
        value: JsValue,
        label: Label,
    ) -> Result<Option<ModulePromiseUpdate>, AsyncModuleSchedulerError> {
        self.scheduler.complete_task(task, value, label)
    }

    pub fn reject_task(
        &mut self,
        task: &ModuleTask,
        reason: JsValue,
        label: Label,
    ) -> Result<Option<ModulePromiseUpdate>, AsyncModuleSchedulerError> {
        self.scheduler.reject_task(task, reason, label)
    }

    pub fn fulfill_awaited_promise(
        &mut self,
        promise: PromiseHandle,
        value: JsValue,
        label: Label,
    ) -> Result<Vec<String>, AsyncModuleSchedulerError> {
        self.scheduler.fulfill_awaited_promise(promise, value, label)
    }

    pub fn reject_awaited_promise(
        &mut self,
        promise: PromiseHandle,
        reason: JsValue,
        label: Label,
    ) -> Result<Vec<ModulePromiseUpdate>, AsyncModuleSchedulerError> {
        self.scheduler.reject_awaited_promise(promise, reason, label)
    }

    pub fn evaluation_promise(&self, specifier: &str) -> Option<PromiseHandle> {
        self.metadata.evaluation_promises.get(specifier).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, tla: bool, dependencies: &[&str]) -> ModuleGraphNode {
        ModuleGraphNode {
            specifier: name.to_string(),
            has_top_level_await: tla,
            dependencies: dependencies.iter().map(|value| (*value).to_string()).collect(),
        }
    }

    #[test]
    fn construction_is_graph_safe_and_dependency_first() {
        let nodes = vec![
            node("app.mjs", false, &["dep.mjs"]),
            node("dep.mjs", true, &[]),
        ];
        let mut runtime = AsyncModuleRuntime::with_defaults(&nodes).unwrap();
        assert_eq!(
            runtime.metadata().graph_plan.registration_order,
            vec!["dep.mjs", "app.mjs"]
        );
        assert!(runtime.evaluation_promise("dep.mjs").is_some());
        assert!(runtime.evaluation_promise("app.mjs").is_none());
        assert_eq!(
            runtime.next_task().unwrap().unwrap().module_specifier,
            "dep.mjs"
        );
    }

    #[test]
    fn invalid_graph_never_returns_partial_runtime() {
        let nodes = vec![node("app.mjs", false, &["missing.mjs"])];
        assert!(matches!(
            AsyncModuleRuntime::with_defaults(&nodes).unwrap_err(),
            ModuleGraphError::UnknownDependency { .. }
        ));
    }

    #[test]
    fn pending_promise_roundtrip_requeues_resume_task() {
        let nodes = vec![node("app.mjs", true, &[])];
        let mut runtime = AsyncModuleRuntime::with_defaults(&nodes).unwrap();
        let start = runtime.next_task().unwrap().unwrap();
        let promise = runtime.create_pending_promise();
        runtime.suspend_task(&start, promise).unwrap();
        assert!(runtime.next_task().unwrap().is_none());
        runtime
            .fulfill_awaited_promise(promise, JsValue::Int(42), Label::Public)
            .unwrap();
        let resume = runtime.next_task().unwrap().unwrap();
        assert!(resume.generation > start.generation);
        runtime
            .complete_task(&resume, JsValue::Undefined, Label::Public)
            .unwrap();
        assert_eq!(
            runtime.module_phases()["app.mjs"],
            AsyncModulePhase::Settled
        );
    }

    #[test]
    fn await_handoff_preserves_value_label_and_live_lease() {
        let mut runtime =
            AsyncModuleRuntime::with_defaults(&[node("app", true, &[])]).unwrap();
        let start = runtime.next_task().unwrap().unwrap();
        assert_eq!(runtime.resume_input(&start).unwrap(), None);
        let promise = runtime.create_pending_promise();
        assert!(matches!(
            runtime.promise_result(promise).unwrap().0,
            PromiseState::Pending
        ));
        runtime.suspend_task(&start, promise).unwrap();
        assert!(runtime.resume_input(&start).is_err());
        runtime
            .fulfill_awaited_promise(promise, JsValue::Int(42), Label::Secret)
            .unwrap();
        let resume = runtime.next_task().unwrap().unwrap();
        let expected = Some(ModuleAwaitInput {
            promise,
            value: JsValue::Int(42),
            label: Label::Secret,
        });
        assert_eq!(runtime.resume_input(&resume).unwrap(), expected);
        assert_eq!(runtime.resume_input(&resume).unwrap(), expected);
        runtime
            .complete_task(&resume, JsValue::Int(42), Label::Secret)
            .unwrap();
        assert!(runtime.resume_input(&resume).is_err());
        let evaluation = runtime.evaluation_promise("app").unwrap();
        assert_eq!(
            runtime.promise_result(evaluation).unwrap(),
            (&PromiseState::Fulfilled(JsValue::Int(42)), &Label::Secret)
        );
    }

    #[test]
    fn repeated_awaits_select_the_latest_suspension() {
        let mut runtime =
            AsyncModuleRuntime::with_defaults(&[node("app", true, &[])]).unwrap();
        let mut task = runtime.next_task().unwrap().unwrap();
        for (value, label) in [
            (JsValue::Int(7), Label::Secret),
            (JsValue::Undefined, Label::Public),
        ] {
            let promise = runtime.create_pending_promise();
            runtime.suspend_task(&task, promise).unwrap();
            runtime
                .fulfill_awaited_promise(promise, value.clone(), label.clone())
                .unwrap();
            let next = runtime.next_task().unwrap().unwrap();
            assert!(runtime.resume_input(&task).is_err());
            assert_eq!(
                runtime.resume_input(&next).unwrap(),
                Some(ModuleAwaitInput { promise, value, label })
            );
            task = next;
        }
        runtime
            .complete_task(&task, JsValue::Undefined, Label::Secret)
            .unwrap();
    }

    #[test]
    fn shared_promise_handoff_is_not_consumed_by_the_first_waiter() {
        let mut runtime = AsyncModuleRuntime::with_defaults(&[
            node("a", true, &[]),
            node("b", true, &[]),
        ])
        .unwrap();
        let promise = runtime.create_pending_promise();
        for _ in 0..2 {
            let task = runtime.next_task().unwrap().unwrap();
            runtime.suspend_task(&task, promise).unwrap();
        }
        runtime
            .fulfill_awaited_promise(promise, JsValue::Int(9), Label::Secret)
            .unwrap();
        for name in ["a", "b"] {
            let task = runtime.next_task().unwrap().unwrap();
            assert_eq!(task.module_specifier, name);
            assert_eq!(
                runtime.resume_input(&task).unwrap(),
                Some(ModuleAwaitInput {
                    promise,
                    value: JsValue::Int(9),
                    label: Label::Secret,
                })
            );
            runtime
                .complete_task(&task, JsValue::Undefined, Label::Secret)
                .unwrap();
        }
        assert!(runtime.next_task().unwrap().is_none());
    }

    #[test]
    fn evaluation_promise_await_uses_the_same_handoff() {
        let mut runtime = AsyncModuleRuntime::with_defaults(&[
            node("producer", true, &[]),
            node("consumer", true, &[]),
        ])
        .unwrap();
        let consumer = runtime.next_task().unwrap().unwrap();
        assert_eq!(consumer.module_specifier, "consumer");
        let promise = runtime.evaluation_promise("producer").unwrap();
        runtime.suspend_task(&consumer, promise).unwrap();
        let producer = runtime.next_task().unwrap().unwrap();
        runtime
            .complete_task(&producer, JsValue::Int(21), Label::Secret)
            .unwrap();
        let resume = runtime.next_task().unwrap().unwrap();
        assert_eq!(
            runtime.resume_input(&resume).unwrap(),
            Some(ModuleAwaitInput {
                promise,
                value: JsValue::Int(21),
                label: Label::Secret,
            })
        );
    }

    #[test]
    fn forged_task_identity_cannot_read_a_continuation() {
        let mut runtime =
            AsyncModuleRuntime::with_defaults(&[node("app", true, &[])]).unwrap();
        let start = runtime.next_task().unwrap().unwrap();
        let promise = runtime.create_pending_promise();
        runtime.suspend_task(&start, promise).unwrap();
        runtime
            .fulfill_awaited_promise(promise, JsValue::Int(42), Label::Secret)
            .unwrap();
        let task = runtime.next_task().unwrap().unwrap();
        let mut forged = task.clone();
        forged.generation += 1;
        assert!(matches!(
            runtime.resume_input(&forged),
            Err(AsyncModuleSchedulerError::StaleTask { .. })
        ));
        forged = task.clone();
        forged.kind = ModuleTaskKind::Start;
        assert!(matches!(
            runtime.resume_input(&forged),
            Err(AsyncModuleSchedulerError::InvalidTaskKind { .. })
        ));
        forged = task.clone();
        forged.sequence += 1;
        assert!(runtime.resume_input(&forged).is_err());
        assert!(runtime.resume_input(&task).unwrap().is_some());
    }

    #[test]
    fn rejection_payload_remains_available_without_a_resume_lease() {
        let mut runtime =
            AsyncModuleRuntime::with_defaults(&[node("app", true, &[])]).unwrap();
        let task = runtime.next_task().unwrap().unwrap();
        let promise = runtime.create_pending_promise();
        runtime.suspend_task(&task, promise).unwrap();
        let reason = JsValue::Str("host failure".into());
        runtime
            .reject_awaited_promise(promise, reason.clone(), Label::Secret)
            .unwrap();
        assert!(runtime.next_task().unwrap().is_none());
        assert!(runtime.resume_input(&task).is_err());
        for handle in [promise, runtime.evaluation_promise("app").unwrap()] {
            assert_eq!(
                runtime.promise_result(handle).unwrap(),
                (&PromiseState::Rejected(reason.clone()), &Label::Secret)
            );
        }
        assert!(runtime.promise_result(PromiseHandle(u32::MAX)).is_err());
    }
}
