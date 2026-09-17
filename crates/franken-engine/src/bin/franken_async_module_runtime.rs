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
#[path = "../async_module_graph.rs"]
mod async_module_graph;

use async_module_graph::{
    ModuleGraphLimits, ModuleGraphNode, ModuleGraphPlan, register_module_graph,
};
use async_module_scheduler::{
    ASYNC_MODULE_SCHEDULER_SCHEMA_VERSION, AsyncModuleScheduler, AsyncModuleSchedulerConfig,
    ModuleTask, SchedulerSnapshot,
};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::module_async_evaluation::AsyncModulePhase;
use frankenengine_engine::object_model::JsValue;
use frankenengine_engine::promise_model::{PromiseHandle, PromiseState};

const COMPONENT: &str = "async_module_runtime";
const SCHEMA_VERSION: &str = "franken-engine.async-module-runtime.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    modules: Vec<ModuleGraphNode>,
    #[serde(default)]
    graph_limits: Option<ModuleGraphLimits>,
    #[serde(default)]
    scheduler_config: Option<AsyncModuleSchedulerConfig>,
    #[serde(default)]
    pending_promises: Vec<String>,
    /// Alias -> module specifier. These refer to the graph's real evaluation
    /// Promises; they do not allocate a second Promise or permit host settlement.
    #[serde(default)]
    evaluation_promise_aliases: BTreeMap<String, String>,
    #[serde(default)]
    operations: Vec<Operation>,
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
struct PromiseResult {
    state: PromiseState,
    label: Label,
}

#[derive(Debug, Serialize)]
struct Output {
    component: &'static str,
    schema_version: &'static str,
    scheduler_schema_version: &'static str,
    graph_plan: ModuleGraphPlan,
    evaluation_promises: BTreeMap<String, PromiseHandle>,
    named_promises: BTreeMap<String, PromiseHandle>,
    named_promise_results: BTreeMap<String, PromiseResult>,
    dispatched: Vec<ModuleTask>,
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

fn run(scenario: Scenario) -> Result<Output, String> {
    let mut scheduler = AsyncModuleScheduler::new(scenario.scheduler_config.unwrap_or_default());
    let registered = register_module_graph(
        &mut scheduler,
        &scenario.modules,
        &scenario.graph_limits.unwrap_or_default(),
    )
    .map_err(|error| error.to_string())?;

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
    for (alias, specifier) in scenario.evaluation_promise_aliases {
        if alias.trim().is_empty() {
            return Err("evaluation Promise alias cannot be empty".to_string());
        }
        if named_promises.contains_key(&alias) {
            return Err(format!("duplicate Promise alias: {alias}"));
        }
        let promise = registered.evaluation_promises.get(&specifier)
            .copied()
            .ok_or_else(|| format!("module has no evaluation Promise: {specifier}"))?;
        named_promises.insert(alias, promise);
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

    // Return actual settlement values and labels, not just opaque handles or
    // terminal phase names. Consumers can distinguish still-pending imports
    // from fulfilled imports and inspect the precise propagated failure.
    let mut named_promise_results = BTreeMap::new();
    for (alias, promise) in &named_promises {
        let record = scheduler.bridge().promise_store().get(*promise)
            .map_err(|error| error.to_string())?;
        named_promise_results.insert(alias.clone(), PromiseResult {
            state: record.state.clone(),
            label: record.label.clone(),
        });
    }
    let module_phases = scheduler
        .bridge()
        .evaluator()
        .states()
        .iter()
        .map(|(specifier, state)| (specifier.clone(), state.phase))
        .collect();
    Ok(Output {
        component: COMPONENT,
        schema_version: SCHEMA_VERSION,
        scheduler_schema_version: ASYNC_MODULE_SCHEDULER_SCHEMA_VERSION,
        graph_plan: registered.plan,
        evaluation_promises: registered.evaluation_promises,
        named_promises,
        named_promise_results,
        dispatched,
        module_phases,
        snapshot: scheduler.snapshot(),
    })
}

fn main() {
    let mut input = String::new();
    if let Err(error) = io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read async module runtime scenario: {error}");
        std::process::exit(2);
    }
    let scenario: Scenario = match serde_json::from_str(&input) {
        Ok(scenario) => scenario,
        Err(error) => {
            eprintln!("invalid async module runtime scenario JSON: {error}");
            std::process::exit(2);
        }
    };
    let output = match run(scenario) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("async module runtime failed: {error}");
            std::process::exit(1);
        }
    };
    match serde_json::to_string_pretty(&output) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("failed to encode async module runtime result: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn out_of_order_graph_executes_dependency_first() {
        let scenario: Scenario = serde_json::from_str(
            r#"{
                "modules": [
                    {"specifier":"app.mjs","dependencies":["dep.mjs"]},
                    {"specifier":"dep.mjs","has_top_level_await":true}
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
        let output = run(scenario).expect("run");
        assert_eq!(output.graph_plan.registration_order, vec!["dep.mjs", "app.mjs"]);
        assert_eq!(output.dispatched[0].module_specifier, "dep.mjs");
        assert_eq!(output.dispatched[1].module_specifier, "app.mjs");
        assert_eq!(output.module_phases["app.mjs"], AsyncModulePhase::Settled);
    }

    #[test]
    fn malformed_graph_fails_before_dispatch() {
        let scenario: Scenario = serde_json::from_str(
            r#"{
                "modules": [{"specifier":"app.mjs","dependencies":["missing.mjs"]}],
                "operations": [{"kind":"dispatch","save_as":"app"}]
            }"#,
        )
        .expect("scenario");
        let error = run(scenario).expect_err("unknown dependency must fail");
        assert!(error.contains("depends on unknown module"));
    }

    #[test]
    fn scenario_can_await_real_evaluation_promise_and_inspect_settlement() {
        let scenario: Scenario = serde_json::from_value(serde_json::json!({
            "modules": [
                {"specifier":"a-waiter", "has_top_level_await":true},
                {"specifier":"b-provider", "has_top_level_await":true}
            ],
            "evaluation_promise_aliases": {"imported":"b-provider", "same":"b-provider"},
            "operations": [
                {"kind":"dispatch", "save_as":"waiter"},
                {"kind":"suspend", "task":"waiter", "promise":"imported"},
                {"kind":"dispatch", "save_as":"provider"},
                {"kind":"complete", "task":"provider", "value":JsValue::Int(42), "label":Label::Secret},
                {"kind":"dispatch", "save_as":"resume"},
                {"kind":"complete", "task":"resume"}
            ]
        })).unwrap();
        let output = run(scenario).unwrap();
        assert_eq!(output.named_promises["imported"], output.evaluation_promises["b-provider"]);
        assert_eq!(output.named_promises["same"], output.named_promises["imported"]);
        assert_eq!(output.named_promise_results["imported"].state,
            PromiseState::Fulfilled(JsValue::Int(42)));
        assert_eq!(output.named_promise_results["imported"].label, Label::Secret);
        assert_eq!(output.dispatched.len(), 3);
        assert_eq!(output.dispatched[2].module_specifier, "a-waiter");
        assert_eq!(output.dispatched[2].kind, async_module_scheduler::ModuleTaskKind::Resume);
        assert_eq!(output.dispatched[2].generation, 2);
        assert!(output.module_phases.values().all(|phase| *phase == AsyncModulePhase::Settled));
        assert_eq!(output.snapshot.in_flight_tasks, 0);
        assert_eq!(output.snapshot.ready_tasks, 0);
        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["named_promise_results"]["imported"]["state"],
            serde_json::to_value(PromiseState::Fulfilled(JsValue::Int(42))).unwrap());
    }

    #[test]
    fn scenario_rejection_closes_cross_module_waits_and_keeps_unrelated_task() {
        let scenario: Scenario = serde_json::from_value(serde_json::json!({
            "modules": [
                {"specifier":"a-waiter", "has_top_level_await":true},
                {"specifier":"b-provider", "has_top_level_await":true},
                {"specifier":"c-importer", "dependencies":["a-waiter"]},
                {"specifier":"z-unrelated"}
            ],
            "evaluation_promise_aliases": {"imported":"b-provider", "waiter-result":"a-waiter"},
            "operations": [
                {"kind":"dispatch", "save_as":"waiter"},
                {"kind":"suspend", "task":"waiter", "promise":"imported"},
                {"kind":"dispatch", "save_as":"provider"},
                {"kind":"reject", "task":"provider", "reason":JsValue::Int(7), "label":Label::Secret},
                {"kind":"dispatch", "save_as":"unrelated"},
                {"kind":"complete", "task":"unrelated"}
            ]
        })).unwrap();
        let output = run(scenario).unwrap();
        for name in ["a-waiter", "b-provider", "c-importer"] {
            assert_eq!(output.module_phases[name], AsyncModulePhase::Rejected);
        }
        for alias in ["imported", "waiter-result"] {
            assert_eq!(output.named_promise_results[alias].state, PromiseState::Rejected(JsValue::Int(7)));
            assert_eq!(output.named_promise_results[alias].label, Label::Secret);
        }
        assert_eq!(output.dispatched[2].module_specifier, "z-unrelated");
        assert_eq!(output.module_phases["z-unrelated"], AsyncModulePhase::Settled);
        assert_eq!(output.snapshot.in_flight_tasks, 0);
        assert_eq!(output.snapshot.ready_tasks, 0);
    }

    #[test]
    fn evaluation_aliases_reject_unknown_modules_collisions_and_host_settlement() {
        for (aliases, pending) in [
            (serde_json::json!({"x":"missing"}), serde_json::json!([])),
            (serde_json::json!({"x":"sync"}), serde_json::json!([])),
            (serde_json::json!({"x":"async"}), serde_json::json!(["x"])),
            (serde_json::json!({" ":"async"}), serde_json::json!([])),
        ] {
            let scenario: Scenario = serde_json::from_value(serde_json::json!({
                "modules":[{"specifier":"async", "has_top_level_await":true}, {"specifier":"sync"}],
                "evaluation_promise_aliases":aliases,
                "pending_promises":pending
            })).unwrap();
            assert!(run(scenario).is_err());
        }
        let scenario: Scenario = serde_json::from_value(serde_json::json!({
            "modules":[{"specifier":"async", "has_top_level_await":true}],
            "evaluation_promise_aliases":{"x":"async"},
            "operations":[{"kind":"fulfill_awaited", "promise":"x"}]
        })).unwrap();
        assert!(run(scenario).unwrap_err().contains("must be settled through the module-evaluation path"));
    }
}
