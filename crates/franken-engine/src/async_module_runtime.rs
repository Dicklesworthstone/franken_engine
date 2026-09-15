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
    SchedulerSnapshot,
};
use crate::ifc_artifacts::Label;
use crate::module_async_evaluation::AsyncModulePhase;
use crate::object_model::JsValue;
use crate::promise_model::PromiseHandle;

pub const ASYNC_MODULE_RUNTIME_COMPONENT: &str = "async_module_runtime";
pub const ASYNC_MODULE_RUNTIME_SCHEMA_VERSION: &str = "franken-engine.async-module-runtime.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsyncModuleRuntimeMetadata {
    pub graph_plan: ModuleGraphPlan,
    pub evaluation_promises: BTreeMap<String, PromiseHandle>,
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
}
