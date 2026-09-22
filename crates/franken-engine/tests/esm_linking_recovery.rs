#![forbid(unsafe_code)]

//! Linking lifecycle regressions. These exercise ModuleGraph, not a JS evaluator.
use frankenengine_engine::esm_loader::{
    EsmLoaderError, EsmModule, ImportEntry, ModuleGraph, ModuleStatus,
};
use frankenengine_engine::module_resolver::ModuleSyntax;

fn module(name: &str, dependencies: &[&str]) -> EsmModule {
    let mut module = EsmModule::new(name, "", ModuleSyntax::EsModule);
    for (index, dependency) in dependencies.iter().enumerate() {
        module.add_import(ImportEntry::namespace(*dependency, format!("ns{index}")));
    }
    module
}

fn graph(modules: &[(&str, &[&str])]) -> ModuleGraph {
    let mut graph = ModuleGraph::new();
    for (name, dependencies) in modules {
        graph.add_module(module(name, dependencies)).unwrap();
    }
    graph
}

fn assert_unlinked(graph: &ModuleGraph, names: &[&str]) {
    for name in names {
        let module = graph.get_module(name).unwrap();
        assert_eq!(module.status, ModuleStatus::Unlinked, "{name}");
        assert_eq!(module.dfs_index, None, "{name}");
        assert_eq!(module.dfs_ancestor_index, None, "{name}");
    }
}

#[test]
fn repeated_missing_dependency_never_becomes_a_successful_cycle() {
    let mut graph = graph(&[("root", &["missing"])]);
    let expected = EsmLoaderError::UnresolvedDependency {
        specifier: "root".into(),
        dependency: "missing".into(),
    };
    for _ in 0..3 {
        assert_eq!(graph.link().unwrap_err(), expected);
        assert_unlinked(&graph, &["root"]);
        assert!(graph.evaluate().is_err());
    }
    assert!(!graph.trace_events().iter().any(|event| {
        event.phase == frankenengine_engine::esm_loader::TracePhase::CycleDetected
    }));
}

#[test]
fn repaired_dependency_links_and_schedules_normally() {
    let mut graph = graph(&[("root", &["middle"]), ("middle", &["missing"])]);
    graph.link().unwrap_err();
    assert_unlinked(&graph, &["root", "middle"]);
    graph.add_module(module("missing", &[])).unwrap();
    assert_eq!(graph.link().unwrap().linked_count, 3);
    assert_eq!(
        graph.evaluate().unwrap().eval_order,
        ["missing", "middle", "root"]
    );
}

#[test]
fn failed_cycle_resets_every_unfinished_member() {
    let mut graph = graph(&[("a", &["b"]), ("b", &["a", "missing"])]);
    for _ in 0..2 {
        graph.link().unwrap_err();
        assert_unlinked(&graph, &["a", "b"]);
    }
    graph.add_module(module("missing", &[])).unwrap();
    let linked = graph.link().unwrap();
    assert_eq!(linked.linked_count, 3);
    assert_eq!(linked.cycle_count, 1);
    assert_eq!(
        graph.get_module("a").unwrap().dfs_ancestor_index,
        graph.get_module("b").unwrap().dfs_ancestor_index
    );
}

#[test]
fn completed_siblings_survive_a_later_failure_even_when_they_share_a_dependency() {
    let mut graph = graph(&[
        ("root", &["a", "b", "z-missing"]),
        ("a", &[]),
        ("b", &["a"]),
    ]);
    graph.link().unwrap_err();
    assert_unlinked(&graph, &["root"]);
    for name in ["a", "b"] {
        let module = graph.get_module(name).unwrap();
        assert_eq!(module.status, ModuleStatus::Linked, "{name}");
        assert_eq!(module.dfs_ancestor_index, module.dfs_index, "{name}");
    }
    let a = graph.get_module("a").unwrap().clone();
    let b = graph.get_module("b").unwrap().clone();
    graph.add_module(module("z-missing", &[])).unwrap();
    assert_eq!(graph.link().unwrap().linked_count, 4);
    assert_eq!(graph.get_module("a"), Some(&a));
    assert_eq!(graph.get_module("b"), Some(&b));
    assert_eq!(graph.evaluate().unwrap().evaluated_count, 4);
}

#[test]
fn diamond_dependencies_do_not_merge_distinct_components() {
    let mut graph = graph(&[
        ("root", &["left", "right"]),
        ("left", &["shared"]),
        ("right", &["shared"]),
        ("shared", &[]),
    ]);
    assert_eq!(graph.link().unwrap().cycle_count, 0);
    for name in ["root", "left", "right", "shared"] {
        let module = graph.get_module(name).unwrap();
        assert_eq!(module.dfs_ancestor_index, module.dfs_index, "{name}");
    }
}

#[test]
fn completed_external_component_does_not_capture_a_real_cycle() {
    let mut graph = graph(&[
        ("root", &["a", "b"]),
        ("a", &[]),
        ("b", &["c"]),
        ("c", &["a", "b"]),
    ]);
    assert_eq!(graph.link().unwrap().linked_count, 4);
    let a = graph.get_module("a").unwrap();
    let b = graph.get_module("b").unwrap();
    let c = graph.get_module("c").unwrap();
    assert_eq!(a.dfs_ancestor_index, a.dfs_index);
    assert_eq!(b.dfs_ancestor_index, b.dfs_index);
    assert_eq!(c.dfs_ancestor_index, b.dfs_index);
    assert_ne!(a.dfs_ancestor_index, b.dfs_ancestor_index);
}

#[test]
fn failed_cycle_keeps_its_completed_external_dependencies() {
    let mut graph = graph(&[
        ("root", &["a", "b"]),
        ("a", &[]),
        ("b", &["c"]),
        ("c", &["a", "b", "z-missing"]),
    ]);
    graph.link().unwrap_err();
    assert_unlinked(&graph, &["root", "b", "c"]);
    assert_eq!(graph.get_module("a").unwrap().status, ModuleStatus::Linked);
    graph.add_module(module("z-missing", &[])).unwrap();
    assert_eq!(graph.link().unwrap().linked_count, 5);
}

#[test]
fn orphan_linking_state_is_not_an_authorized_cycle() {
    let mut graph = graph(&[("root", &["orphan"]), ("orphan", &[])]);
    let orphan = graph.get_module_mut("orphan").unwrap();
    orphan.status = ModuleStatus::Linking;
    orphan.dfs_index = Some(0);
    orphan.dfs_ancestor_index = Some(0);
    let before = orphan.clone();
    for _ in 0..2 {
        assert!(matches!(
            graph.link(),
            Err(EsmLoaderError::InvalidStatus { .. })
        ));
        assert_unlinked(&graph, &["root"]);
        assert_eq!(graph.get_module("orphan"), Some(&before));
    }
}

#[test]
fn relinking_preserves_modules_that_have_started_or_failed_evaluation() {
    for state in [
        ModuleStatus::Evaluating,
        ModuleStatus::Evaluated,
        ModuleStatus::EvaluationError,
    ] {
        let mut graph = graph(&[("root", &["dependency"]), ("dependency", &[])]);
        graph.link().unwrap();
        let dependency = graph.get_module_mut("dependency").unwrap();
        dependency.status = state;
        dependency.eval_order = Some(27);
        let before = dependency.clone();
        // Model a new entry which reuses the already-linked dependency.
        let root = graph.get_module_mut("root").unwrap();
        root.status = ModuleStatus::Unlinked;
        root.dfs_index = None;
        root.dfs_ancestor_index = None;
        graph.link().unwrap();
        assert_eq!(graph.get_module("dependency"), Some(&before));
        let root = graph.get_module("root").unwrap();
        assert_eq!(root.status, ModuleStatus::Linked);
        assert_eq!(root.dfs_index, root.dfs_ancestor_index);
    }
}

#[test]
fn successful_relink_does_not_reassign_indices_or_emit_false_cycles() {
    let mut graph = graph(&[("a", &["b"]), ("b", &["a"])]);
    graph.link().unwrap();
    let before: Vec<_> = graph.modules().cloned().collect();
    let event_count = graph.trace_events().len();
    for _ in 0..3 {
        let linked = graph.link().unwrap();
        assert_eq!(linked.linked_count, 2);
        assert_eq!(linked.cycle_count, 0);
        assert_eq!(graph.modules().cloned().collect::<Vec<_>>(), before);
        assert_eq!(graph.trace_events().len(), event_count);
    }
}

#[test]
fn depth_refusal_is_recoverable_without_stale_linking_markers() {
    let mut graph = ModuleGraph::new();
    for index in 0..513 {
        let name = format!("m{index}");
        let next = format!("m{}", index + 1);
        let dependencies: Vec<&str> = if index < 512 { vec![&next] } else { vec![] };
        graph.add_module(module(&name, &dependencies)).unwrap();
    }
    assert!(matches!(
        graph.link(),
        Err(EsmLoaderError::DepthExceeded { depth: 512, .. })
    ));
    for module in graph.modules() {
        assert_eq!(module.status, ModuleStatus::Unlinked);
        assert_eq!(module.dfs_index, None);
        assert_eq!(module.dfs_ancestor_index, None);
    }
    let last = graph.get_module_mut("m511").unwrap();
    last.dependencies.clear();
    last.imports.clear();
    assert_eq!(graph.link().unwrap().linked_count, 512);
    assert_eq!(
        graph.get_module("m512").unwrap().status,
        ModuleStatus::Unlinked
    );
}

#[test]
fn back_edge_at_depth_boundary_does_not_consume_a_new_activation() {
    let mut graph = ModuleGraph::new();
    for index in 0..512 {
        let name = format!("m{index}");
        let next = format!("m{}", (index + 1) % 512);
        graph.add_module(module(&name, &[&next])).unwrap();
    }
    let result = graph.link().unwrap();
    assert_eq!(result.linked_count, 512);
    assert_eq!(result.cycle_count, 1);
    assert!(
        graph
            .modules()
            .all(|module| module.status == ModuleStatus::Linked)
    );
}
