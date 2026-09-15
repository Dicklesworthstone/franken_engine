#![forbid(unsafe_code)]

//! Deterministic, fail-closed registration of complete async-module graphs.
//!
//! `AsyncModuleEvaluator::register_module` can only account for dependencies
//! that already exist. Feeding modules in arbitrary source-discovery order can
//! therefore make a dependent appear runnable before a later dependency has
//! been registered. This module validates the complete graph first and then
//! registers it in deterministic dependency-first order.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::async_module_scheduler::{AsyncModuleScheduler, AsyncModuleSchedulerError};
use crate::promise_model::PromiseHandle;

pub const ASYNC_MODULE_GRAPH_COMPONENT: &str = "async_module_graph";
pub const ASYNC_MODULE_GRAPH_SCHEMA_VERSION: &str = "franken-engine.async-module-graph.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleGraphNode {
    pub specifier: String,
    #[serde(default)]
    pub has_top_level_await: bool,
    #[serde(default)]
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModuleGraphLimits {
    pub max_modules: usize,
    pub max_edges: usize,
    pub max_specifier_bytes: usize,
}

impl Default for ModuleGraphLimits {
    fn default() -> Self {
        Self {
            max_modules: 65_536,
            max_edges: 1_048_576,
            max_specifier_bytes: 16 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleGraphPlan {
    pub registration_order: Vec<String>,
    pub module_count: usize,
    pub edge_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredModuleGraph {
    pub plan: ModuleGraphPlan,
    pub evaluation_promises: BTreeMap<String, PromiseHandle>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleGraphError {
    ModuleLimitExceeded { actual: usize, max: usize },
    EdgeLimitExceeded { actual: usize, max: usize },
    EmptySpecifier,
    SpecifierTooLong { specifier: String, actual: usize, max: usize },
    DuplicateModule { specifier: String },
    DuplicateDependency { module: String, dependency: String },
    UnknownDependency { module: String, dependency: String },
    SelfDependency { module: String },
    Cycle { modules: Vec<String> },
    Scheduler { module: String, detail: String },
}

impl fmt::Display for ModuleGraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModuleLimitExceeded { actual, max } => {
                write!(f, "module graph has {actual} modules; limit is {max}")
            }
            Self::EdgeLimitExceeded { actual, max } => {
                write!(f, "module graph has {actual} dependency edges; limit is {max}")
            }
            Self::EmptySpecifier => f.write_str("module graph contains an empty specifier"),
            Self::SpecifierTooLong {
                specifier,
                actual,
                max,
            } => write!(
                f,
                "module specifier {specifier:?} has {actual} bytes; limit is {max}"
            ),
            Self::DuplicateModule { specifier } => {
                write!(f, "duplicate module graph node: {specifier}")
            }
            Self::DuplicateDependency { module, dependency } => write!(
                f,
                "module {module} declares dependency {dependency} more than once"
            ),
            Self::UnknownDependency { module, dependency } => {
                write!(f, "module {module} depends on unknown module {dependency}")
            }
            Self::SelfDependency { module } => {
                write!(f, "module {module} cannot depend directly on itself")
            }
            Self::Cycle { modules } => {
                write!(f, "async module dependency cycle: {}", modules.join(", "))
            }
            Self::Scheduler { module, detail } => {
                write!(f, "failed to register module {module}: {detail}")
            }
        }
    }
}

impl std::error::Error for ModuleGraphError {}

pub fn plan_module_graph(
    nodes: &[ModuleGraphNode],
    limits: &ModuleGraphLimits,
) -> Result<ModuleGraphPlan, ModuleGraphError> {
    if nodes.len() > limits.max_modules {
        return Err(ModuleGraphError::ModuleLimitExceeded {
            actual: nodes.len(),
            max: limits.max_modules,
        });
    }

    let mut by_name = BTreeMap::<String, &ModuleGraphNode>::new();
    let mut edge_count = 0usize;
    for node in nodes {
        if node.specifier.is_empty() {
            return Err(ModuleGraphError::EmptySpecifier);
        }
        if node.specifier.len() > limits.max_specifier_bytes {
            return Err(ModuleGraphError::SpecifierTooLong {
                specifier: node.specifier.clone(),
                actual: node.specifier.len(),
                max: limits.max_specifier_bytes,
            });
        }
        if by_name.insert(node.specifier.clone(), node).is_some() {
            return Err(ModuleGraphError::DuplicateModule {
                specifier: node.specifier.clone(),
            });
        }
        edge_count = edge_count.saturating_add(node.dependencies.len());
        if edge_count > limits.max_edges {
            return Err(ModuleGraphError::EdgeLimitExceeded {
                actual: edge_count,
                max: limits.max_edges,
            });
        }
    }

    let mut indegree = BTreeMap::<String, usize>::new();
    let mut dependents = BTreeMap::<String, BTreeSet<String>>::new();
    for name in by_name.keys() {
        indegree.insert(name.clone(), 0);
        dependents.insert(name.clone(), BTreeSet::new());
    }
    for node in nodes {
        let mut unique = BTreeSet::new();
        for dependency in &node.dependencies {
            if dependency == &node.specifier {
                return Err(ModuleGraphError::SelfDependency {
                    module: node.specifier.clone(),
                });
            }
            if !by_name.contains_key(dependency) {
                return Err(ModuleGraphError::UnknownDependency {
                    module: node.specifier.clone(),
                    dependency: dependency.clone(),
                });
            }
            if !unique.insert(dependency.clone()) {
                return Err(ModuleGraphError::DuplicateDependency {
                    module: node.specifier.clone(),
                    dependency: dependency.clone(),
                });
            }
            *indegree
                .get_mut(&node.specifier)
                .expect("all graph nodes have indegree slots") += 1;
            dependents
                .get_mut(dependency)
                .expect("all graph nodes have dependent slots")
                .insert(node.specifier.clone());
        }
    }

    let mut ready: BTreeSet<String> = indegree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(name, _)| name.clone())
        .collect();
    let mut registration_order = Vec::with_capacity(nodes.len());
    while let Some(name) = ready.pop_first() {
        registration_order.push(name.clone());
        for dependent in dependents
            .get(&name)
            .expect("validated graph node has dependents slot")
        {
            let degree = indegree
                .get_mut(dependent)
                .expect("validated dependent has indegree slot");
            *degree = degree.saturating_sub(1);
            if *degree == 0 {
                ready.insert(dependent.clone());
            }
        }
    }

    if registration_order.len() != nodes.len() {
        let cyclic = indegree
            .into_iter()
            .filter(|(_, degree)| *degree != 0)
            .map(|(name, _)| name)
            .collect();
        return Err(ModuleGraphError::Cycle { modules: cyclic });
    }

    Ok(ModuleGraphPlan {
        registration_order,
        module_count: nodes.len(),
        edge_count,
    })
}

pub fn register_module_graph(
    scheduler: &mut AsyncModuleScheduler,
    nodes: &[ModuleGraphNode],
    limits: &ModuleGraphLimits,
) -> Result<RegisteredModuleGraph, ModuleGraphError> {
    // Validation and topology computation happen before the first scheduler
    // mutation, so malformed graphs cannot leave a partially registered runtime.
    let plan = plan_module_graph(nodes, limits)?;
    let by_name: BTreeMap<&str, &ModuleGraphNode> = nodes
        .iter()
        .map(|node| (node.specifier.as_str(), node))
        .collect();
    let mut evaluation_promises = BTreeMap::new();
    for specifier in &plan.registration_order {
        let node = by_name
            .get(specifier.as_str())
            .expect("plan only contains validated module names");
        let promise = scheduler
            .register_module(
                &node.specifier,
                node.has_top_level_await,
                &node.dependencies,
            )
            .map_err(|error: AsyncModuleSchedulerError| ModuleGraphError::Scheduler {
                module: node.specifier.clone(),
                detail: error.to_string(),
            })?;
        if let Some(promise) = promise {
            evaluation_promises.insert(node.specifier.clone(), promise);
        }
    }
    Ok(RegisteredModuleGraph {
        plan,
        evaluation_promises,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, deps: &[&str]) -> ModuleGraphNode {
        ModuleGraphNode {
            specifier: name.to_string(),
            has_top_level_await: false,
            dependencies: deps.iter().map(|dep| (*dep).to_string()).collect(),
        }
    }

    #[test]
    fn out_of_order_input_is_planned_dependency_first() {
        let nodes = vec![
            node("app.mjs", &["lib.mjs"]),
            node("lib.mjs", &["base.mjs"]),
            node("base.mjs", &[]),
        ];
        let plan = plan_module_graph(&nodes, &ModuleGraphLimits::default()).unwrap();
        assert_eq!(
            plan.registration_order,
            vec!["base.mjs", "lib.mjs", "app.mjs"]
        );
    }

    #[test]
    fn independent_roots_use_canonical_order() {
        let nodes = vec![node("z.mjs", &[]), node("a.mjs", &[])];
        let plan = plan_module_graph(&nodes, &ModuleGraphLimits::default()).unwrap();
        assert_eq!(plan.registration_order, vec!["a.mjs", "z.mjs"]);
    }

    #[test]
    fn missing_dependency_fails_before_scheduler_mutation() {
        let nodes = vec![node("app.mjs", &["missing.mjs"])];
        let mut scheduler = AsyncModuleScheduler::default();
        let error = register_module_graph(
            &mut scheduler,
            &nodes,
            &ModuleGraphLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error, ModuleGraphError::UnknownDependency { .. }));
        assert_eq!(scheduler.snapshot().registered_modules, 0);
    }

    #[test]
    fn cycle_fails_before_scheduler_mutation() {
        let nodes = vec![node("a.mjs", &["b.mjs"]), node("b.mjs", &["a.mjs"])];
        let mut scheduler = AsyncModuleScheduler::default();
        let error = register_module_graph(
            &mut scheduler,
            &nodes,
            &ModuleGraphLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error, ModuleGraphError::Cycle { .. }));
        assert_eq!(scheduler.snapshot().registered_modules, 0);
    }

    #[test]
    fn duplicate_dependency_is_rejected() {
        let nodes = vec![node("dep.mjs", &[]), node("app.mjs", &["dep.mjs", "dep.mjs"])];
        assert!(matches!(
            plan_module_graph(&nodes, &ModuleGraphLimits::default()).unwrap_err(),
            ModuleGraphError::DuplicateDependency { .. }
        ));
    }
}
