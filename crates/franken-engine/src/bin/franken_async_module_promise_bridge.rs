#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
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

use async_module_promise_bridge::{AsyncModulePromiseBridge, ModulePromiseUpdate};
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::module_async_evaluation::{AsyncEvalConfig, AsyncModulePhase};
use frankenengine_engine::object_model::JsValue;
use frankenengine_engine::promise_model::PromiseHandle;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    #[serde(default)]
    config: Option<AsyncEvalConfig>,
    modules: Vec<ScenarioModule>,
    #[serde(default)]
    pending_promises: Vec<String>,
    #[serde(default)]
    settlements: Vec<Settlement>,
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
enum Settlement {
    Fulfill {
        module: String,
        value: JsValue,
        #[serde(default = "public_label")]
        label: Label,
    },
    Reject {
        module: String,
        reason: JsValue,
        #[serde(default = "public_label")]
        label: Label,
    },
    SuspendOnPromise {
        module: String,
        promise: String,
    },
    FulfillAwaited {
        promise: String,
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
    CompleteSynchronous { module: String },
    Synchronize { module: String },
    SynchronizeAll,
}

#[derive(Debug, Serialize)]
struct ScenarioOutput {
    updates: Vec<ModulePromiseUpdate>,
    dependency_ready: Vec<String>,
    continuation_ready: Vec<String>,
    named_promises: BTreeMap<String, PromiseHandle>,
    module_phases: BTreeMap<String, AsyncModulePhase>,
    active_awaits: BTreeMap<String, PromiseHandle>,
    witness_event_count: usize,
    pending_microtasks: usize,
}

fn public_label() -> Label {
    Label::Public
}

fn named_promise(
    promises: &BTreeMap<String, PromiseHandle>,
    name: &str,
) -> Result<PromiseHandle, String> {
    promises
        .get(name)
        .copied()
        .ok_or_else(|| format!("unknown named Promise: {name}"))
}

fn run_scenario(scenario: Scenario) -> Result<ScenarioOutput, String> {
    let mut bridge = AsyncModulePromiseBridge::new(scenario.config.unwrap_or_default());
    for module in scenario.modules {
        bridge
            .register_module(
                module.specifier.as_str(),
                module.has_top_level_await,
                &module.dependencies,
            )
            .map_err(|error| error.to_string())?;
    }

    let mut named_promises = BTreeMap::new();
    for name in scenario.pending_promises {
        if name.trim().is_empty() {
            return Err("pending Promise name cannot be empty".to_string());
        }
        if named_promises.contains_key(&name) {
            return Err(format!("duplicate pending Promise name: {name}"));
        }
        named_promises.insert(name, bridge.create_pending_promise());
    }

    let mut updates = Vec::new();
    let mut dependency_ready = BTreeSet::new();
    let mut continuation_ready = BTreeSet::new();
    for settlement in scenario.settlements {
        match settlement {
            Settlement::Fulfill {
                module,
                value,
                label,
            } => {
                let update = bridge
                    .fulfill_module(module.as_str(), value, label)
                    .map_err(|error| error.to_string())?;
                dependency_ready.extend(update.dependency_ready.iter().cloned());
                updates.push(update);
            }
            Settlement::Reject {
                module,
                reason,
                label,
            } => {
                let update = bridge
                    .reject_module(module.as_str(), reason, label)
                    .map_err(|error| error.to_string())?;
                updates.push(update);
            }
            Settlement::SuspendOnPromise { module, promise } => {
                let handle = named_promise(&named_promises, &promise)?;
                bridge
                    .suspend_module_on_promise(module.as_str(), handle)
                    .map_err(|error| error.to_string())?;
            }
            Settlement::FulfillAwaited {
                promise,
                value,
                label,
            } => {
                let handle = named_promise(&named_promises, &promise)?;
                continuation_ready.extend(
                    bridge
                        .fulfill_awaited_promise(handle, value, label)
                        .map_err(|error| error.to_string())?,
                );
            }
            Settlement::RejectAwaited {
                promise,
                reason,
                label,
            } => {
                let handle = named_promise(&named_promises, &promise)?;
                updates.extend(
                    bridge
                        .reject_awaited_promise(handle, reason, label)
                        .map_err(|error| error.to_string())?,
                );
            }
            Settlement::CompleteSynchronous { module } => {
                dependency_ready.extend(
                    bridge
                        .complete_synchronous_module(module.as_str())
                        .map_err(|error| error.to_string())?,
                );
            }
            Settlement::Synchronize { module } => {
                let update = bridge
                    .synchronize_module(module.as_str())
                    .map_err(|error| error.to_string())?;
                dependency_ready.extend(update.dependency_ready.iter().cloned());
                updates.push(update);
            }
            Settlement::SynchronizeAll => {
                for update in bridge.synchronize_all().map_err(|error| error.to_string())? {
                    dependency_ready.extend(update.dependency_ready.iter().cloned());
                    updates.push(update);
                }
            }
        }
    }

    let module_phases = bridge
        .evaluator()
        .states()
        .iter()
        .map(|(specifier, state)| (specifier.clone(), state.phase))
        .collect();
    let active_awaits = bridge
        .evaluator()
        .states()
        .keys()
        .filter_map(|specifier| {
            bridge
                .active_await(specifier)
                .map(|promise| (specifier.clone(), promise))
        })
        .collect();
    Ok(ScenarioOutput {
        updates,
        dependency_ready: dependency_ready.into_iter().collect(),
        continuation_ready: continuation_ready.into_iter().collect(),
        named_promises,
        module_phases,
        active_awaits,
        witness_event_count: bridge.evaluator().witness_events().len(),
        pending_microtasks: bridge.microtasks().pending_count(),
    })
}

fn main() {
    let mut input = String::new();
    if let Err(error) = io::stdin().read_to_string(&mut input) {
        eprintln!("failed to read async-module scenario from stdin: {error}");
        std::process::exit(2);
    }
    let scenario: Scenario = match serde_json::from_str(&input) {
        Ok(scenario) => scenario,
        Err(error) => {
            eprintln!("invalid async-module scenario JSON: {error}");
            std::process::exit(2);
        }
    };
    let output = match run_scenario(scenario) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("async-module Promise bridge failed: {error}");
            std::process::exit(1);
        }
    };
    match serde_json::to_string_pretty(&output) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("failed to encode async-module result: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_fulfillment_wakes_sync_dependent() {
        let scenario: Scenario = serde_json::from_str(
            r#"{
                "modules": [
                    {"specifier":"dep.mjs","has_top_level_await":true},
                    {"specifier":"app.mjs","dependencies":["dep.mjs"]}
                ],
                "settlements": [
                    {"kind":"fulfill","module":"dep.mjs","value":{"Int":42}}
                ]
            }"#,
        )
        .expect("scenario");
        let output = run_scenario(scenario).expect("run");
        assert_eq!(
            output.module_phases.get("dep.mjs"),
            Some(&AsyncModulePhase::Settled)
        );
        assert_eq!(output.dependency_ready, vec!["app.mjs".to_string()]);
    }

    #[test]
    fn scenario_pending_await_returns_continuation_ready() {
        let scenario: Scenario = serde_json::from_str(
            r#"{
                "modules": [
                    {"specifier":"app.mjs","has_top_level_await":true}
                ],
                "pending_promises": ["fetch-result"],
                "settlements": [
                    {"kind":"suspend_on_promise","module":"app.mjs","promise":"fetch-result"},
                    {"kind":"fulfill_awaited","promise":"fetch-result","value":{"Int":42}}
                ]
            }"#,
        )
        .expect("scenario");
        let output = run_scenario(scenario).expect("run");
        assert_eq!(output.continuation_ready, vec!["app.mjs".to_string()]);
        assert!(output.active_awaits.is_empty());
        assert_eq!(
            output.module_phases.get("app.mjs"),
            Some(&AsyncModulePhase::Suspended)
        );
    }

    #[test]
    fn scenario_await_rejection_propagates_to_dependents() {
        let scenario: Scenario = serde_json::from_str(
            r#"{
                "modules": [
                    {"specifier":"root.mjs","has_top_level_await":true},
                    {"specifier":"child.mjs","has_top_level_await":true,"dependencies":["root.mjs"]}
                ],
                "pending_promises": ["inner"],
                "settlements": [
                    {"kind":"suspend_on_promise","module":"root.mjs","promise":"inner"},
                    {"kind":"reject_awaited","promise":"inner","reason":{"Str":"boom"}}
                ]
            }"#,
        )
        .expect("scenario");
        let output = run_scenario(scenario).expect("run");
        assert_eq!(
            output.module_phases.get("root.mjs"),
            Some(&AsyncModulePhase::Rejected)
        );
        assert_eq!(
            output.module_phases.get("child.mjs"),
            Some(&AsyncModulePhase::Rejected)
        );
    }

    #[test]
    fn invalid_duplicate_module_fails_closed() {
        let scenario: Scenario = serde_json::from_str(
            r#"{
                "modules": [
                    {"specifier":"same.mjs"},
                    {"specifier":"same.mjs"}
                ]
            }"#,
        )
        .expect("scenario");
        let error = run_scenario(scenario).expect_err("duplicate must fail");
        assert!(error.contains("already registered"));
    }

    #[test]
    fn unknown_named_promise_fails_closed() {
        let scenario: Scenario = serde_json::from_str(
            r#"{
                "modules": [{"specifier":"app.mjs","has_top_level_await":true}],
                "settlements": [
                    {"kind":"suspend_on_promise","module":"app.mjs","promise":"missing"}
                ]
            }"#,
        )
        .expect("scenario");
        let error = run_scenario(scenario).expect_err("unknown promise must fail");
        assert!(error.contains("unknown named Promise"));
    }
}
