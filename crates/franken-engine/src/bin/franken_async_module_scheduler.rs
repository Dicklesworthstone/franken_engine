#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{self, Read};

use serde::{Deserialize, Serialize};

pub use frankenengine_engine::esm_loader;
pub use frankenengine_engine::ifc_artifacts;
pub use frankenengine_engine::module_async_evaluation;
pub use frankenengine_engine::module_live_binding;
pub use frankenengine_engine::object_model;
pub use frankenengine_engine::promise_model;

#[path = "../async_module_promise_bridge.rs"]
mod async_module_promise_bridge;
#[path = "../async_module_scheduler.rs"]
mod async_module_scheduler;

use async_module_scheduler::{
    ASYNC_MODULE_SCHEDULER_COMPONENT, ASYNC_MODULE_SCHEDULER_SCHEMA_VERSION,
    AsyncModuleScheduler, AsyncModuleSchedulerConfig, ModuleTask, SchedulerSnapshot,
};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::module_async_evaluation::AsyncModulePhase;
use frankenengine_engine::object_model::JsValue;
use frankenengine_engine::promise_model::PromiseHandle;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    #[serde(default)]
    config: Option<AsyncModuleSchedulerConfig>,
    modules: Vec<ScenarioModule>,
    #[serde(default)]
    pending_promises: Vec<String>,
    #[serde(default)]
    operations: Vec<Operation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioModule {
    specifier: String,
    #[serde(default)]
    has_top_level_await: bool,
    #[serde(default)]
    dependencies: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Operation {
    Dispatch { save_as: String },
    Complete {
        task: String,
        #[serde(default = "undefined_value")]
        value: JsValue,
        #[serde(default = "public_label")]
        label: Label,
    },
    Suspend { task: String, promise: String },
    Reject {
        task: String,
        reason: JsValue,
        #[serde(default = "public_label")]
        label: Label,
    },
    FulfillAwaited {
        promise: String,
        #[serde(default = "undefined_value")]
        value: JsValue,
        #[serde(default = "public_label")]
        label: Label,
    },
    RejectAwaited {
        promise: String,
        reason: JsValue,
        #[serde(default = "public_label")]
        label: Label,
    },
}

#[derive(Debug, Serialize)]
struct ScenarioOutput {
    component: &'static str,
    schema_version: &'static str,
    dispatched: Vec<ModuleTask>,
    named_promises: BTreeMap<String, PromiseHandle>,
    module_phases: BTreeMap<String, AsyncModulePhase>,
    snapshot: SchedulerSnapshot,
}

fn undefined_value() -> JsValue {
    JsValue::Undefined
}

fn public_label() -> Label {
    Label::Public
}

fn lookup_task(tasks: &BTreeMap<String, ModuleTask>, name: &str) -> Result<ModuleTask, String> {
    tasks
        .get(name)
        .cloned()
        .ok_or_else(|| format!("unknown task alias: {name}"))
}

fn lookup_promise(
    promises: &BTreeMap<String, PromiseHandle>,
    name: &str,
) -> Result<PromiseHandle, String> {
    promises
        .get(name)
        .copied()
        .ok_or_else(|| format!("unknown Promise alias: {name}"))
}

fn run_scenario(scenario: Scenario) -> Result<ScenarioOutput, String> {
    let mut scheduler = AsyncModuleScheduler::new(scenario.config.unwrap_or_default());
    for module in scenario.modules {
        scheduler
            .register_module(
                &module.specifier,
                module.has_top_level_await,
                &module.dependencies,
            )
            .map_err(|error| error.to_string())?;
    }

    let mut named_promises = BTreeMap::new();
    for name in scenario.pending_promises {
        if name.trim().is_empty() {
            return Err("pending Promise alias cannot be empty".to_string());
        }
        if named_promises.contains_key(&name) {
            return Err(format!("duplicate pending Promise alias: {name}"));
        }
        named_promises.insert(name, scheduler.create_pending_promise());
    }

    let mut task_aliases = BTreeMap::<String, ModuleTask>::new();
    let mut dispatched = Vec::new();
    for operation in scenario.operations {
        match operation {
            Operation::Dispatch { save_as } => {
                if save_as.trim().is_empty() {
                    return Err("task alias cannot be empty".to_string());
                }
                if task_aliases.contains_key(&save_as) {
                    return Err(format!("duplicate task alias: {save_as}"));
                }
                let task = scheduler
                    .next_task()
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "scheduler has no ready module task".to_string())?;
                task_aliases.insert(save_as, task.clone());
                dispatched.push(task);
            }
            Operation::Complete { task, value, label } => {
                let task = lookup_task(&task_aliases, &task)?;
                scheduler
                    .complete_task(&task, value, label)
                    .map_err(|error| error.to_string())?;
            }
            Operation::Suspend { task, promise } => {
                let task = lookup_task(&task_aliases, &task)?;
                let promise = lookup_promise(&named_promises, &promise)?;
                scheduler
                    .suspend_task(&task, promise)
                    .map_err(|error| error.to_string())?;
            }
            Operation::Reject {
                task,
                reason,
                label,
            } => {
                let task = lookup_task(&task_aliases, &task)?;
                scheduler
                    .reject_task(&task, reason, label)
                    .map_err(|error| error.to_string())?;
            }
            Operation::FulfillAwaited {
                promise,
                value,
                label,
            } => {
                let promise = lookup_promise(&named_promises, &promise)?;
                scheduler
                    .fulfill_awaited_promise(promise, value, label)
                    .map_err(|error| error.to_string())?;
            }
            Operation::RejectAwaited {
                promise,
                reason,
                label,
            } => {
                let promise = lookup_promise(&named_promises, &promise)?;
                scheduler
                    .reject_awaited_promise(promise, reason, label)
                    .map_err(|error| error.to_string())?;
            }
        }
    }

    let module_phases = scheduler
        .bridge()
        .evaluator()
        .states()
        .iter()
        .map(|(specifier, state)| (specifier.clone(), state.phase))
        .collect();
    Ok(ScenarioOutput {
        component: ASYNC_MODULE_SCHEDULER_COMPONENT,
        schema_version: ASYNC_MODULE_SCHEDULER_SCHEMA_VERSION,
        dispatched,
        named_promises,
        module_phases,
        snapshot: scheduler.snapshot(),
    })
}

fn main() {
    let mut input = String::new();
    if let Err(error) = io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read async scheduler scenario: {error}");
        std::process::exit(2);
    }
    let scenario: Scenario = match serde_json::from_str(&input) {
        Ok(scenario) => scenario,
        Err(error) => {
            eprintln!("invalid async scheduler scenario JSON: {error}");
            std::process::exit(2);
        }
    };
    let output = match run_scenario(scenario) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("async module scheduler failed: {error}");
            std::process::exit(1);
        }
    };
    match serde_json::to_string_pretty(&output) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("failed to encode async scheduler result: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synchronous_dependency_chain_runs_in_order() {
        let scenario: Scenario = serde_json::from_str(
            r#"{
                "modules": [
                    {"specifier":"dep.mjs"},
                    {"specifier":"app.mjs","dependencies":["dep.mjs"]}
                ],
                "operations": [
                    {"kind":"dispatch","save_as":"dep"},
                    {"kind":"complete","task":"dep"},
                    {"kind":"dispatch","save_as":"app"},
                    {"kind":"complete","task":"app"}
                ]
            }"#,
        )
        .expect("scenario");
        let output = run_scenario(scenario).expect("run");
        assert_eq!(output.dispatched[0].module_specifier, "dep.mjs");
        assert_eq!(output.dispatched[1].module_specifier, "app.mjs");
        assert_eq!(output.module_phases["dep.mjs"], AsyncModulePhase::Settled);
        assert_eq!(output.module_phases["app.mjs"], AsyncModulePhase::Settled);
    }

    #[test]
    fn pending_await_resumes_with_new_generation() {
        let scenario: Scenario = serde_json::from_str(
            r#"{
                "modules": [{"specifier":"app.mjs","has_top_level_await":true}],
                "pending_promises": ["inner"],
                "operations": [
                    {"kind":"dispatch","save_as":"start"},
                    {"kind":"suspend","task":"start","promise":"inner"},
                    {"kind":"fulfill_awaited","promise":"inner","value":{"Int":42}},
                    {"kind":"dispatch","save_as":"resume"},
                    {"kind":"complete","task":"resume"}
                ]
            }"#,
        )
        .expect("scenario");
        let output = run_scenario(scenario).expect("run");
        assert_eq!(output.dispatched.len(), 2);
        assert!(output.dispatched[1].generation > output.dispatched[0].generation);
        assert_eq!(output.module_phases["app.mjs"], AsyncModulePhase::Settled);
    }

    #[test]
    fn dispatch_without_ready_work_fails_closed() {
        let scenario: Scenario = serde_json::from_str(
            r#"{
                "modules": [
                    {"specifier":"dep.mjs","has_top_level_await":true},
                    {"specifier":"app.mjs","dependencies":["dep.mjs"]}
                ],
                "operations": [
                    {"kind":"dispatch","save_as":"dep"},
                    {"kind":"dispatch","save_as":"should-fail"}
                ]
            }"#,
        )
        .expect("scenario");
        let error = run_scenario(scenario).expect_err("no second ready task");
        assert!(error.contains("no ready module task"));
    }
}
