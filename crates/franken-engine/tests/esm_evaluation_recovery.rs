#![forbid(unsafe_code)]

//! Failure-atomic module-graph scheduling. No JavaScript bodies run in these
//! tests: a rejected schedule must not publish partial completion markers.
use frankenengine_engine::esm_loader::{
    EsmLoaderError, EsmModule, ImportEntry, ModuleGraph, ModuleStatus, TracePhase,
};
use frankenengine_engine::module_resolver::ModuleSyntax;

fn module(name: &str, dependencies: &[&str]) -> EsmModule {
    let mut module = EsmModule::new(name, "", ModuleSyntax::EsModule);
    for (index, dependency) in dependencies.iter().enumerate() {
        module.add_import(ImportEntry::namespace(*dependency, format!("ns{index}")));
    }
    module
}

fn linked_graph(modules: &[(&str, &[&str])]) -> ModuleGraph {
    let mut graph = ModuleGraph::new();
    for (name, dependencies) in modules {
        graph.add_module(module(name, dependencies)).unwrap();
    }
    graph.link().unwrap();
    graph
}

fn records(graph: &ModuleGraph) -> Vec<EsmModule> {
    graph.modules().cloned().collect()
}

#[test]
fn missing_dependency_never_turns_into_success_on_retry() {
    let mut graph = linked_graph(&[("root", &["child"]), ("child", &[])]);
    graph
        .get_module_mut("child")
        .unwrap()
        .dependencies
        .insert("missing".into());
    let before = records(&graph);
    for _ in 0..3 {
        assert_eq!(
            graph.evaluate().unwrap_err(),
            EsmLoaderError::ModuleNotFound("missing".into())
        );
        assert_eq!(records(&graph), before);
    }
    let mut missing = module("missing", &[]);
    missing.status = ModuleStatus::Linked;
    graph.add_module(missing).unwrap();
    let result = graph.evaluate().unwrap();
    assert_eq!(result.eval_order, ["missing", "child", "root"]);
    assert_eq!(result.evaluated_count, 3);
}

#[test]
fn invalid_dependency_state_restores_ancestors_and_is_repairable() {
    let mut graph = linked_graph(&[("root", &["child"]), ("child", &[])]);
    graph.get_module_mut("child").unwrap().status = ModuleStatus::Unlinked;
    let before = records(&graph);
    for _ in 0..2 {
        assert!(matches!(
            graph.evaluate(),
            Err(EsmLoaderError::InvalidStatus { .. })
        ));
        assert_eq!(records(&graph), before);
    }
    graph.get_module_mut("child").unwrap().status = ModuleStatus::Linked;
    assert_eq!(graph.evaluate().unwrap().eval_order, ["child", "root"]);
}

#[test]
fn completed_siblings_are_rolled_back_with_the_unpublished_schedule() {
    let mut graph = linked_graph(&[
        ("root", &["a", "z"]),
        ("a", &["shared"]),
        ("shared", &[]),
        ("z", &[]),
    ]);
    graph.get_module_mut("z").unwrap().status = ModuleStatus::Unlinked;
    // The rollback must preserve the exact pre-call records, even if a caller
    // has retained earlier scheduling metadata on a Linked record.
    graph.get_module_mut("a").unwrap().eval_order = Some(42);
    let before = records(&graph);
    graph.evaluate().unwrap_err();
    assert_eq!(records(&graph), before);
    graph.get_module_mut("z").unwrap().status = ModuleStatus::Linked;
    assert_eq!(
        graph.evaluate().unwrap().eval_order,
        ["shared", "a", "z", "root"]
    );
    assert_eq!(graph.get_module("a").unwrap().eval_order, Some(1));
}

#[test]
fn cyclic_member_completed_before_late_failure_is_also_restored() {
    let mut graph = linked_graph(&[("a", &["b", "z"]), ("b", &["a"]), ("z", &[])]);
    graph.get_module_mut("z").unwrap().status = ModuleStatus::Unlinked;
    let before = records(&graph);
    for _ in 0..2 {
        graph.evaluate().unwrap_err();
        assert_eq!(records(&graph), before);
    }
    graph.get_module_mut("z").unwrap().status = ModuleStatus::Linked;
    assert_eq!(graph.evaluate().unwrap().eval_order, ["b", "z", "a"]);
}

#[test]
fn preexisting_evaluated_and_failed_records_are_not_rewritten() {
    let mut graph = linked_graph(&[("root", &["a", "z"]), ("a", &[]), ("z", &[])]);
    let evaluated = graph.get_module_mut("a").unwrap();
    evaluated.status = ModuleStatus::Evaluated;
    evaluated.eval_order = Some(71);
    let failed = graph.get_module_mut("z").unwrap();
    failed.status = ModuleStatus::EvaluationError;
    failed.eval_order = Some(72);
    let before = records(&graph);
    for _ in 0..2 {
        assert_eq!(
            graph.evaluate().unwrap_err(),
            EsmLoaderError::EvaluationFailed {
                specifier: "z".into(),
                reason: "previous evaluation failed".into(),
            }
        );
        assert_eq!(records(&graph), before);
    }
}

#[test]
fn orphan_evaluating_state_is_not_a_cycle_or_success() {
    for orphan_name in ["root", "child"] {
        let mut graph = linked_graph(&[("root", &["child"]), ("child", &[])]);
        graph.get_module_mut(orphan_name).unwrap().status = ModuleStatus::Evaluating;
        let before = records(&graph);
        for _ in 0..2 {
            assert_eq!(
                graph.evaluate().unwrap_err(),
                EsmLoaderError::InvalidStatus {
                    specifier: orphan_name.into(),
                    expected: "evaluating module owned by the current traversal",
                    actual: "orphan evaluating state".into(),
                }
            );
            assert_eq!(records(&graph), before);
        }
    }
}

#[test]
fn owned_self_cycle_is_scheduled_once() {
    let mut graph = linked_graph(&[("self", &["self"])]);
    let result = graph.evaluate().unwrap();
    assert_eq!(result.eval_order, ["self"]);
    assert_eq!(result.evaluated_count, 1);
    let before = records(&graph);
    let events_before = graph.trace_events().len();
    assert_eq!(graph.evaluate().unwrap().evaluated_count, 0);
    assert_eq!(records(&graph), before);
    assert_eq!(graph.trace_events().len(), events_before);
}

#[test]
fn back_edge_at_the_depth_boundary_does_not_require_an_activation() {
    let mut graph = ModuleGraph::new();
    for index in 0..512 {
        let name = format!("m{index}");
        let next = format!("m{}", (index + 1) % 512);
        graph.add_module(module(&name, &[&next])).unwrap();
    }
    assert_eq!(graph.link().unwrap().linked_count, 512);
    let result = graph.evaluate().unwrap();
    assert_eq!(result.evaluated_count, 512);
    let expected: Vec<_> = (0..512).rev().map(|index| format!("m{index}")).collect();
    assert_eq!(result.eval_order, expected);
    assert!(
        graph
            .modules()
            .all(|module| module.status == ModuleStatus::Evaluated)
    );
}

#[test]
fn depth_refusal_restores_all_touched_records() {
    let mut graph = ModuleGraph::new();
    for index in 0..513 {
        let name = format!("m{index}");
        let next = format!("m{}", index + 1);
        let dependencies: Vec<&str> = if index < 512 { vec![&next] } else { vec![] };
        // Isolate the evaluation bound from the linker's independent bound.
        let mut module = module(&name, &dependencies);
        module.status = ModuleStatus::Linked;
        graph.add_module(module).unwrap();
    }
    let before = records(&graph);
    for _ in 0..2 {
        assert!(matches!(
            graph.evaluate(),
            Err(EsmLoaderError::DepthExceeded {
                depth: 512,
                limit: 512,
                ..
            })
        ));
        assert_eq!(records(&graph), before);
    }
    // Repair the input and prove the rejected invocation published no schedule.
    let tail = graph.get_module_mut("m511").unwrap();
    tail.dependencies.clear();
    tail.imports.clear();
    let result = graph.evaluate().unwrap();
    assert_eq!(result.evaluated_count, 512);
    assert_eq!(graph.get_module("m512").unwrap().status, ModuleStatus::Linked);
}

#[test]
fn completed_dependency_at_depth_boundary_does_not_consume_budget() {
    let mut graph = ModuleGraph::new();
    for index in 0..513 {
        let name = format!("m{index}");
        let next = format!("m{}", index + 1);
        let dependencies: Vec<&str> = if index < 512 { vec![&next] } else { vec![] };
        let mut module = module(&name, &dependencies);
        module.status = if index == 512 {
            ModuleStatus::Evaluated
        } else {
            ModuleStatus::Linked
        };
        graph.add_module(module).unwrap();
    }
    let before = graph.get_module("m512").unwrap().clone();
    assert_eq!(graph.evaluate().unwrap().evaluated_count, 512);
    assert_eq!(graph.get_module("m512"), Some(&before));
}

#[test]
fn failure_and_recovery_traces_are_deterministic_and_contiguous() {
    let mut first = linked_graph(&[("root", &["child"]), ("child", &[])]);
    first.get_module_mut("child").unwrap().status = ModuleStatus::Unlinked;
    let mut second = first.clone();
    for graph in [&mut first, &mut second] {
        graph.evaluate().unwrap_err();
        let failure = graph.trace_events().last().unwrap();
        assert_eq!(failure.phase, TracePhase::Evaluate);
        assert_eq!(failure.specifier, "root");
        assert!(failure.detail.contains("restored 1 modules"));
        graph.get_module_mut("child").unwrap().status = ModuleStatus::Linked;
        graph.evaluate().unwrap();
        for (index, event) in graph.trace_events().iter().enumerate() {
            assert_eq!(event.seq, index as u64);
        }
    }
    assert_eq!(records(&first), records(&second));
    assert_eq!(first.trace_events(), second.trace_events());
}

#[test]
fn successful_diamond_is_dependency_first_and_idempotent() {
    let mut graph = linked_graph(&[
        ("root", &["left", "right"]),
        ("left", &["shared"]),
        ("right", &["shared"]),
        ("shared", &[]),
    ]);
    let result = graph.evaluate().unwrap();
    assert_eq!(result.eval_order, ["shared", "left", "right", "root"]);
    for (index, specifier) in result.eval_order.iter().enumerate() {
        assert_eq!(
            graph.get_module(specifier).unwrap().eval_order,
            Some(index as u32)
        );
    }
    let before = records(&graph);
    let events_before = graph.trace_events().len();
    let repeated = graph.evaluate().unwrap();
    assert_eq!(repeated.evaluated_count, 0);
    assert!(repeated.eval_order.is_empty());
    assert_eq!(records(&graph), before);
    assert_eq!(graph.trace_events().len(), events_before);
}
