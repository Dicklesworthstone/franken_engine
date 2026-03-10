//! Integration tests for the ESM loader module (bd-1lsy.5.1 / RGC-401).
//!
//! Covers: module graph construction, link phase (DFS, cycle detection),
//! evaluate phase (topological order), export resolution (direct, re-export,
//! star), cycle detection (Tarjan SCC), graph analysis, error taxonomy, serde
//! round-trips, and determinism.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::esm_loader::{
    BindingType, CycleInfo, EsmLoaderError, EsmModule, ExportEntry, ImportEntry, ModuleGraph,
    ModuleStatus, TraceEvent, TracePhase,
};
use frankenengine_engine::module_resolver::ModuleSyntax;

fn esm(spec: &str, source: &str) -> EsmModule {
    EsmModule::new(spec, source, ModuleSyntax::EsModule)
}

fn cjs(spec: &str, source: &str) -> EsmModule {
    EsmModule::new(spec, source, ModuleSyntax::CommonJs)
}

// ---------------------------------------------------------------------------
// ModuleGraph construction
// ---------------------------------------------------------------------------

#[test]
fn empty_graph() {
    let g = ModuleGraph::new();
    assert!(g.is_empty());
    assert_eq!(g.len(), 0);
    assert!(g.entry_point().is_none());
    assert_eq!(g.trace_events().len(), 0);
}

#[test]
fn default_graph_is_empty() {
    let g = ModuleGraph::default();
    assert!(g.is_empty());
}

#[test]
fn add_single_module_sets_entry_point() {
    let mut g = ModuleGraph::new();
    g.add_module(esm("./main.js", "export default 42")).unwrap();
    assert_eq!(g.len(), 1);
    assert_eq!(g.entry_point(), Some("./main.js"));
}

#[test]
fn first_module_becomes_entry_point() {
    let mut g = ModuleGraph::new();
    g.add_module(esm("./a.js", "")).unwrap();
    g.add_module(esm("./b.js", "")).unwrap();
    assert_eq!(g.entry_point(), Some("./a.js"));
}

#[test]
fn specifiers_are_deterministically_ordered() {
    let mut g = ModuleGraph::new();
    g.add_module(esm("./c.js", "")).unwrap();
    g.add_module(esm("./a.js", "")).unwrap();
    g.add_module(esm("./b.js", "")).unwrap();

    let specs: Vec<&str> = g.specifiers().collect();
    assert_eq!(specs, vec!["./a.js", "./b.js", "./c.js"]); // BTreeMap ordering
}

#[test]
fn get_module_returns_correct_module() {
    let mut g = ModuleGraph::new();
    g.add_module(esm("./main.js", "hello")).unwrap();

    let m = g.get_module("./main.js").unwrap();
    assert_eq!(m.specifier, "./main.js");
    assert_eq!(m.source, "hello");
    assert_eq!(m.syntax, ModuleSyntax::EsModule);
}

#[test]
fn get_module_returns_none_for_missing() {
    let g = ModuleGraph::new();
    assert!(g.get_module("./missing.js").is_none());
}

#[test]
fn get_module_mut_allows_modification() {
    let mut g = ModuleGraph::new();
    g.add_module(esm("./main.js", "")).unwrap();
    g.get_module_mut("./main.js").unwrap().status = ModuleStatus::Linked;
    assert_eq!(
        g.get_module("./main.js").unwrap().status,
        ModuleStatus::Linked
    );
}

// ---------------------------------------------------------------------------
// EsmModule construction
// ---------------------------------------------------------------------------

#[test]
fn esm_module_new_defaults() {
    let m = esm("./foo.js", "const x = 1");
    assert_eq!(m.specifier, "./foo.js");
    assert_eq!(m.source, "const x = 1");
    assert_eq!(m.syntax, ModuleSyntax::EsModule);
    assert_eq!(m.status, ModuleStatus::Unlinked);
    assert!(m.imports.is_empty());
    assert!(m.exports.is_empty());
    assert!(m.dependencies.is_empty());
    assert!(!m.has_default_export);
    assert!(m.dfs_index.is_none());
    assert!(m.dfs_ancestor_index.is_none());
    assert!(m.eval_order.is_none());
}

#[test]
fn cjs_module_syntax() {
    let m = cjs("./bar.js", "module.exports = {}");
    assert_eq!(m.syntax, ModuleSyntax::CommonJs);
}

#[test]
fn content_hash_computed_on_creation() {
    let m1 = esm("./a.js", "same");
    let m2 = esm("./b.js", "same");
    assert_eq!(m1.content_hash, m2.content_hash);

    let m3 = esm("./c.js", "different");
    assert_ne!(m1.content_hash, m3.content_hash);
}

// ---------------------------------------------------------------------------
// Import / Export entry construction
// ---------------------------------------------------------------------------

#[test]
fn add_import_tracks_dependency() {
    let mut m = esm("./main.js", "");
    m.add_import(ImportEntry::new("./dep.js", "foo", "foo"));
    assert_eq!(m.imports.len(), 1);
    assert!(m.dependencies.contains("./dep.js"));
}

#[test]
fn add_export_direct() {
    let mut m = esm("./main.js", "");
    m.add_export(ExportEntry::direct("x", "x"));
    assert_eq!(m.exports.len(), 1);
    assert!(!m.has_default_export);
}

#[test]
fn add_export_default_sets_flag() {
    let mut m = esm("./main.js", "");
    m.add_export(ExportEntry::direct("Comp", "default"));
    assert!(m.has_default_export);
}

#[test]
fn add_re_export_tracks_dependency() {
    let mut m = esm("./main.js", "");
    m.add_export(ExportEntry::re_export("foo", "./lib.js", "bar"));
    assert!(m.dependencies.contains("./lib.js"));
}

#[test]
fn add_star_re_export_tracks_dependency() {
    let mut m = esm("./main.js", "");
    m.add_export(ExportEntry::star_re_export("./utils.js"));
    assert!(m.dependencies.contains("./utils.js"));
    assert_eq!(m.exports[0].export_name, "*");
}

#[test]
fn namespace_import() {
    let entry = ImportEntry::namespace("./mod.js", "ns");
    assert_eq!(entry.import_name, "*");
    assert_eq!(entry.local_name, "ns");
}

// ---------------------------------------------------------------------------
// Link phase
// ---------------------------------------------------------------------------

#[test]
fn link_single_module() {
    let mut g = ModuleGraph::new();
    let mut m = esm("./main.js", "export const x = 1");
    m.add_export(ExportEntry::direct("x", "x"));
    g.add_module(m).unwrap();

    let result = g.link().unwrap();
    assert_eq!(result.linked_count, 1);
    assert_eq!(result.cycle_count, 0);
    assert_eq!(
        g.get_module("./main.js").unwrap().status,
        ModuleStatus::Linked
    );
}

#[test]
fn link_chain_a_imports_b() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "import { x } from './b.js'");
    a.add_import(ImportEntry::new("./b.js", "x", "x"));
    let mut b = esm("./b.js", "export const x = 1");
    b.add_export(ExportEntry::direct("x", "x"));

    g.add_module(a).unwrap();
    g.add_module(b).unwrap();

    let result = g.link().unwrap();
    assert_eq!(result.linked_count, 2);
    assert_eq!(result.cycle_count, 0);
}

#[test]
fn link_detects_cycle() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_import(ImportEntry::new("./b.js", "x", "x"));
    let mut b = esm("./b.js", "");
    b.add_import(ImportEntry::new("./a.js", "y", "y"));

    g.add_module(a).unwrap();
    g.add_module(b).unwrap();

    let result = g.link().unwrap();
    assert!(result.cycle_count > 0);
    // Both modules should still be Linked (cycles are handled per ES2020).
    assert_eq!(g.get_module("./a.js").unwrap().status, ModuleStatus::Linked);
    assert_eq!(g.get_module("./b.js").unwrap().status, ModuleStatus::Linked);
}

#[test]
fn link_diamond_dependency() {
    //   a -> b -> d
    //   a -> c -> d
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_import(ImportEntry::new("./b.js", "x", "x"));
    a.add_import(ImportEntry::new("./c.js", "y", "y"));

    let mut b = esm("./b.js", "");
    b.add_import(ImportEntry::new("./d.js", "z", "z"));

    let mut c = esm("./c.js", "");
    c.add_import(ImportEntry::new("./d.js", "z", "z"));

    let d = esm("./d.js", "export const z = 1");

    g.add_module(a).unwrap();
    g.add_module(b).unwrap();
    g.add_module(c).unwrap();
    g.add_module(d).unwrap();

    let result = g.link().unwrap();
    assert_eq!(result.linked_count, 4);
    assert_eq!(result.cycle_count, 0);
}

#[test]
fn link_unresolved_dependency_fails() {
    let mut g = ModuleGraph::new();
    let mut a = esm("./a.js", "");
    a.add_import(ImportEntry::new("./missing.js", "x", "x"));
    g.add_module(a).unwrap();

    let err = g.link().unwrap_err();
    assert_eq!(
        err,
        EsmLoaderError::UnresolvedDependency {
            specifier: "./a.js".into(),
            dependency: "./missing.js".into(),
        }
    );
}

#[test]
fn link_no_entry_point_fails() {
    let mut g = ModuleGraph::new();
    let err = g.link().unwrap_err();
    assert_eq!(err, EsmLoaderError::NoEntryPoint);
}

#[test]
fn link_emits_trace_events() {
    let mut g = ModuleGraph::new();
    g.add_module(esm("./main.js", "")).unwrap();
    g.link().unwrap();

    let events = g.trace_events();
    assert!(!events.is_empty());
    assert!(events.iter().any(|e| e.phase == TracePhase::Link));
}

#[test]
fn link_assigns_dfs_indices() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_import(ImportEntry::new("./b.js", "x", "x"));
    g.add_module(a).unwrap();
    g.add_module(esm("./b.js", "")).unwrap();

    g.link().unwrap();

    let a_mod = g.get_module("./a.js").unwrap();
    let b_mod = g.get_module("./b.js").unwrap();
    assert!(a_mod.dfs_index.is_some());
    assert!(b_mod.dfs_index.is_some());
}

// ---------------------------------------------------------------------------
// Evaluate phase
// ---------------------------------------------------------------------------

#[test]
fn evaluate_single_module() {
    let mut g = ModuleGraph::new();
    g.add_module(esm("./main.js", "")).unwrap();
    g.link().unwrap();

    let result = g.evaluate().unwrap();
    assert_eq!(result.evaluated_count, 1);
    assert_eq!(result.eval_order, vec!["./main.js"]);
    assert_eq!(
        g.get_module("./main.js").unwrap().status,
        ModuleStatus::Evaluated
    );
}

#[test]
fn evaluate_respects_topological_order() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_import(ImportEntry::new("./b.js", "x", "x"));
    let b = esm("./b.js", "");

    g.add_module(a).unwrap();
    g.add_module(b).unwrap();
    g.link().unwrap();

    let result = g.evaluate().unwrap();
    // b should be evaluated before a (dependency first)
    assert_eq!(result.eval_order, vec!["./b.js", "./a.js"]);
}

#[test]
fn evaluate_diamond_dependency_order() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_import(ImportEntry::new("./b.js", "x", "x"));
    a.add_import(ImportEntry::new("./c.js", "y", "y"));

    let mut b = esm("./b.js", "");
    b.add_import(ImportEntry::new("./d.js", "z", "z"));

    let mut c = esm("./c.js", "");
    c.add_import(ImportEntry::new("./d.js", "z", "z"));

    let d = esm("./d.js", "");

    g.add_module(a).unwrap();
    g.add_module(b).unwrap();
    g.add_module(c).unwrap();
    g.add_module(d).unwrap();
    g.link().unwrap();

    let result = g.evaluate().unwrap();
    assert_eq!(result.evaluated_count, 4);
    // d must be evaluated before both b and c, and a must be last
    let d_pos = result
        .eval_order
        .iter()
        .position(|s| s == "./d.js")
        .unwrap();
    let b_pos = result
        .eval_order
        .iter()
        .position(|s| s == "./b.js")
        .unwrap();
    let c_pos = result
        .eval_order
        .iter()
        .position(|s| s == "./c.js")
        .unwrap();
    let a_pos = result
        .eval_order
        .iter()
        .position(|s| s == "./a.js")
        .unwrap();
    assert!(d_pos < b_pos);
    assert!(d_pos < c_pos);
    assert!(b_pos < a_pos);
    assert!(c_pos < a_pos);
}

#[test]
fn evaluate_no_entry_point_fails() {
    let mut g = ModuleGraph::new();
    let err = g.evaluate().unwrap_err();
    assert_eq!(err, EsmLoaderError::NoEntryPoint);
}

#[test]
fn evaluate_unlinked_module_fails() {
    let mut g = ModuleGraph::new();
    g.add_module(esm("./main.js", "")).unwrap();
    // Don't call link() — module is Unlinked
    let err = g.evaluate().unwrap_err();
    assert!(matches!(err, EsmLoaderError::InvalidStatus { .. }));
}

#[test]
fn evaluate_emits_trace_events() {
    let mut g = ModuleGraph::new();
    g.add_module(esm("./main.js", "")).unwrap();
    g.link().unwrap();
    g.evaluate().unwrap();

    assert!(
        g.trace_events()
            .iter()
            .any(|e| e.phase == TracePhase::Evaluate)
    );
}

#[test]
fn evaluate_assigns_eval_order_index() {
    let mut g = ModuleGraph::new();
    g.add_module(esm("./main.js", "")).unwrap();
    g.link().unwrap();
    g.evaluate().unwrap();

    assert_eq!(g.get_module("./main.js").unwrap().eval_order, Some(0));
}

// ---------------------------------------------------------------------------
// Export resolution
// ---------------------------------------------------------------------------

#[test]
fn resolve_direct_export() {
    let mut g = ModuleGraph::new();
    let mut m = esm("./lib.js", "");
    m.add_export(ExportEntry::direct("foo", "foo"));
    g.add_module(m).unwrap();

    let binding = g.resolve_export("./lib.js", "foo").unwrap();
    assert_eq!(binding.module_specifier, "./lib.js");
    assert_eq!(binding.local_name, "foo");
    assert_eq!(binding.binding_type, BindingType::Direct);
}

#[test]
fn resolve_re_export() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_export(ExportEntry::re_export("foo", "./b.js", "bar"));

    let mut b = esm("./b.js", "");
    b.add_export(ExportEntry::direct("bar", "bar"));

    g.add_module(a).unwrap();
    g.add_module(b).unwrap();

    let binding = g.resolve_export("./a.js", "foo").unwrap();
    assert_eq!(binding.module_specifier, "./b.js");
    assert_eq!(binding.local_name, "bar");
}

#[test]
fn resolve_star_re_export() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_export(ExportEntry::star_re_export("./b.js"));

    let mut b = esm("./b.js", "");
    b.add_export(ExportEntry::direct("x", "x"));

    g.add_module(a).unwrap();
    g.add_module(b).unwrap();

    let binding = g.resolve_export("./a.js", "x").unwrap();
    assert_eq!(binding.module_specifier, "./b.js");
    assert_eq!(binding.local_name, "x");
}

#[test]
fn resolve_ambiguous_star_re_export_fails() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_export(ExportEntry::star_re_export("./b.js"));
    a.add_export(ExportEntry::star_re_export("./c.js"));

    let mut b = esm("./b.js", "");
    b.add_export(ExportEntry::direct("x", "x"));

    let mut c = esm("./c.js", "");
    c.add_export(ExportEntry::direct("x", "x"));

    g.add_module(a).unwrap();
    g.add_module(b).unwrap();
    g.add_module(c).unwrap();

    let err = g.resolve_export("./a.js", "x").unwrap_err();
    assert_eq!(
        err,
        EsmLoaderError::AmbiguousExport {
            specifier: "./a.js".into(),
            export_name: "x".into(),
        }
    );
}

#[test]
fn resolve_export_not_found() {
    let mut g = ModuleGraph::new();
    g.add_module(esm("./a.js", "")).unwrap();

    let err = g.resolve_export("./a.js", "missing").unwrap_err();
    assert_eq!(
        err,
        EsmLoaderError::ExportNotFound {
            specifier: "./a.js".into(),
            export_name: "missing".into(),
        }
    );
}

#[test]
fn resolve_export_module_not_found() {
    let g = ModuleGraph::new();
    let err = g.resolve_export("./nope.js", "x").unwrap_err();
    assert_eq!(err, EsmLoaderError::ModuleNotFound("./nope.js".into()));
}

// ---------------------------------------------------------------------------
// Cycle detection (Tarjan)
// ---------------------------------------------------------------------------

#[test]
fn find_cycles_no_cycles() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_import(ImportEntry::new("./b.js", "x", "x"));
    g.add_module(a).unwrap();
    g.add_module(esm("./b.js", "")).unwrap();

    let cycles = g.find_cycles();
    assert!(cycles.is_empty());
}

#[test]
fn find_cycles_simple_cycle() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_import(ImportEntry::new("./b.js", "x", "x"));
    let mut b = esm("./b.js", "");
    b.add_import(ImportEntry::new("./a.js", "y", "y"));

    g.add_module(a).unwrap();
    g.add_module(b).unwrap();

    let cycles = g.find_cycles();
    assert_eq!(cycles.len(), 1);
    assert_eq!(cycles[0].len(), 2);
}

#[test]
fn find_cycles_three_node_cycle() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_import(ImportEntry::new("./b.js", "x", "x"));
    let mut b = esm("./b.js", "");
    b.add_import(ImportEntry::new("./c.js", "y", "y"));
    let mut c = esm("./c.js", "");
    c.add_import(ImportEntry::new("./a.js", "z", "z"));

    g.add_module(a).unwrap();
    g.add_module(b).unwrap();
    g.add_module(c).unwrap();

    let cycles = g.find_cycles();
    assert_eq!(cycles.len(), 1);
    assert_eq!(cycles[0].len(), 3);
}

// ---------------------------------------------------------------------------
// Graph analysis
// ---------------------------------------------------------------------------

#[test]
fn topological_order_dependencies_first() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_import(ImportEntry::new("./b.js", "x", "x"));
    g.add_module(a).unwrap();
    g.add_module(esm("./b.js", "")).unwrap();

    let order = g.topological_order();
    let b_pos = order.iter().position(|s| s == "./b.js").unwrap();
    let a_pos = order.iter().position(|s| s == "./a.js").unwrap();
    assert!(b_pos < a_pos);
}

#[test]
fn find_exporters_returns_matching_modules() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_export(ExportEntry::direct("foo", "foo"));

    let mut b = esm("./b.js", "");
    b.add_export(ExportEntry::direct("foo", "foo"));

    let c = esm("./c.js", "");

    g.add_module(a).unwrap();
    g.add_module(b).unwrap();
    g.add_module(c).unwrap();

    let exporters = g.find_exporters("foo");
    assert_eq!(exporters.len(), 2);
    assert!(exporters.contains(&"./a.js".to_string()));
    assert!(exporters.contains(&"./b.js".to_string()));
}

#[test]
fn transitive_dependencies() {
    let mut g = ModuleGraph::new();

    let mut a = esm("./a.js", "");
    a.add_import(ImportEntry::new("./b.js", "x", "x"));
    let mut b = esm("./b.js", "");
    b.add_import(ImportEntry::new("./c.js", "y", "y"));
    let c = esm("./c.js", "");

    g.add_module(a).unwrap();
    g.add_module(b).unwrap();
    g.add_module(c).unwrap();

    let deps = g.transitive_dependencies("./a.js");
    assert!(deps.contains("./b.js"));
    assert!(deps.contains("./c.js"));
    assert!(!deps.contains("./a.js")); // self excluded
}

#[test]
fn transitive_dependencies_of_leaf() {
    let mut g = ModuleGraph::new();
    g.add_module(esm("./leaf.js", "")).unwrap();

    let deps = g.transitive_dependencies("./leaf.js");
    assert!(deps.is_empty());
}

// ---------------------------------------------------------------------------
// ModuleStatus
// ---------------------------------------------------------------------------

#[test]
fn module_status_display() {
    assert_eq!(ModuleStatus::Unlinked.to_string(), "unlinked");
    assert_eq!(ModuleStatus::Linking.to_string(), "linking");
    assert_eq!(ModuleStatus::Linked.to_string(), "linked");
    assert_eq!(ModuleStatus::Evaluating.to_string(), "evaluating");
    assert_eq!(ModuleStatus::Evaluated.to_string(), "evaluated");
    assert_eq!(
        ModuleStatus::EvaluationError.to_string(),
        "evaluation_error"
    );
}

#[test]
fn module_status_ordering() {
    assert!(ModuleStatus::Unlinked < ModuleStatus::Linking);
    assert!(ModuleStatus::Linking < ModuleStatus::Linked);
    assert!(ModuleStatus::Linked < ModuleStatus::Evaluating);
    assert!(ModuleStatus::Evaluating < ModuleStatus::Evaluated);
}

// ---------------------------------------------------------------------------
// TracePhase
// ---------------------------------------------------------------------------

#[test]
fn trace_phase_display() {
    assert_eq!(TracePhase::Resolve.to_string(), "resolve");
    assert_eq!(TracePhase::Link.to_string(), "link");
    assert_eq!(TracePhase::Evaluate.to_string(), "evaluate");
    assert_eq!(TracePhase::CycleDetected.to_string(), "cycle_detected");
}

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

#[test]
fn error_display_no_entry_point() {
    let err = EsmLoaderError::NoEntryPoint;
    assert_eq!(err.to_string(), "no entry point set");
}

#[test]
fn error_display_module_not_found() {
    let err = EsmLoaderError::ModuleNotFound("./x.js".into());
    assert_eq!(err.to_string(), "module not found: ./x.js");
}

#[test]
fn error_display_unresolved_dependency() {
    let err = EsmLoaderError::UnresolvedDependency {
        specifier: "./a.js".into(),
        dependency: "./b.js".into(),
    };
    assert_eq!(
        err.to_string(),
        "unresolved dependency: ./a.js imports ./b.js"
    );
}

#[test]
fn error_display_export_not_found() {
    let err = EsmLoaderError::ExportNotFound {
        specifier: "./a.js".into(),
        export_name: "x".into(),
    };
    assert_eq!(err.to_string(), "export 'x' not found in ./a.js");
}

#[test]
fn error_display_ambiguous_export() {
    let err = EsmLoaderError::AmbiguousExport {
        specifier: "./a.js".into(),
        export_name: "x".into(),
    };
    assert!(err.to_string().contains("ambiguous"));
}

#[test]
fn error_display_depth_exceeded() {
    let err = EsmLoaderError::DepthExceeded {
        specifier: "./deep.js".into(),
        depth: 600,
        limit: 512,
    };
    assert!(err.to_string().contains("600"));
    assert!(err.to_string().contains("512"));
}

#[test]
fn error_display_evaluation_failed() {
    let err = EsmLoaderError::EvaluationFailed {
        specifier: "./x.js".into(),
        reason: "type error".into(),
    };
    assert!(err.to_string().contains("type error"));
}

#[test]
fn error_display_invalid_status() {
    let err = EsmLoaderError::InvalidStatus {
        specifier: "./x.js".into(),
        expected: "linked",
        actual: "unlinked".into(),
    };
    assert!(err.to_string().contains("linked"));
    assert!(err.to_string().contains("unlinked"));
}

// ---------------------------------------------------------------------------
// Serde round-trips
// ---------------------------------------------------------------------------

#[test]
fn module_status_serde_roundtrip() {
    let statuses = vec![
        ModuleStatus::Unlinked,
        ModuleStatus::Linking,
        ModuleStatus::Linked,
        ModuleStatus::Evaluating,
        ModuleStatus::Evaluated,
        ModuleStatus::EvaluationError,
    ];
    for s in &statuses {
        let json = serde_json::to_string(s).unwrap();
        let back: ModuleStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, s);
    }
}

#[test]
fn trace_phase_serde_roundtrip() {
    let phases = vec![
        TracePhase::Resolve,
        TracePhase::Link,
        TracePhase::Evaluate,
        TracePhase::CycleDetected,
    ];
    for p in &phases {
        let json = serde_json::to_string(p).unwrap();
        let back: TracePhase = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, p);
    }
}

#[test]
fn esm_module_serde_roundtrip() {
    let mut m = esm("./main.js", "export const x = 1");
    m.add_import(ImportEntry::new("./dep.js", "y", "y"));
    m.add_export(ExportEntry::direct("x", "x"));

    let json = serde_json::to_string(&m).unwrap();
    let back: EsmModule = serde_json::from_str(&json).unwrap();
    assert_eq!(back.specifier, m.specifier);
    assert_eq!(back.source, m.source);
    assert_eq!(back.imports.len(), 1);
    assert_eq!(back.exports.len(), 1);
}

#[test]
fn module_graph_serde_roundtrip() {
    let mut g = ModuleGraph::new();
    let mut m = esm("./main.js", "");
    m.add_export(ExportEntry::direct("x", "x"));
    g.add_module(m).unwrap();
    g.link().unwrap();

    let json = serde_json::to_string(&g).unwrap();
    let back: ModuleGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back.entry_point(), Some("./main.js"));
}

#[test]
fn export_entry_serde_roundtrip() {
    let entries = vec![
        ExportEntry::direct("x", "x"),
        ExportEntry::re_export("foo", "./mod.js", "bar"),
        ExportEntry::star_re_export("./all.js"),
    ];
    for entry in &entries {
        let json = serde_json::to_string(entry).unwrap();
        let back: ExportEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, entry);
    }
}

#[test]
fn import_entry_serde_roundtrip() {
    let entries = vec![
        ImportEntry::new("./mod.js", "x", "x"),
        ImportEntry::namespace("./mod.js", "ns"),
    ];
    for entry in &entries {
        let json = serde_json::to_string(entry).unwrap();
        let back: ImportEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, entry);
    }
}

#[test]
fn cycle_info_serde_roundtrip() {
    let ci = CycleInfo {
        specifier: "./a.js".into(),
        stack_snapshot: vec!["./a.js".into(), "./b.js".into()],
    };
    let json = serde_json::to_string(&ci).unwrap();
    let back: CycleInfo = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ci);
}

#[test]
fn trace_event_serde_roundtrip() {
    let te = TraceEvent {
        phase: TracePhase::Link,
        specifier: "./main.js".into(),
        detail: "linking (dfs_index=0)".into(),
        seq: 0,
    };
    let json = serde_json::to_string(&te).unwrap();
    let back: TraceEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, te);
}

#[test]
fn binding_type_serde_roundtrip() {
    let types = vec![
        BindingType::Direct,
        BindingType::ReExport,
        BindingType::StarReExport,
    ];
    for bt in &types {
        let json = serde_json::to_string(bt).unwrap();
        let back: BindingType = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, bt);
    }
}

// ---------------------------------------------------------------------------
// Error serde
// ---------------------------------------------------------------------------

#[test]
fn esm_loader_error_serde_serialize() {
    // InvalidStatus has &'static str, so we only test serialization.
    let errors: Vec<EsmLoaderError> = vec![
        EsmLoaderError::NoEntryPoint,
        EsmLoaderError::ModuleNotFound("./x.js".into()),
        EsmLoaderError::GraphTooLarge { limit: 10_000 },
        EsmLoaderError::DepthExceeded {
            specifier: "./x.js".into(),
            depth: 600,
            limit: 512,
        },
        EsmLoaderError::UnresolvedDependency {
            specifier: "./a.js".into(),
            dependency: "./b.js".into(),
        },
        EsmLoaderError::ExportNotFound {
            specifier: "./a.js".into(),
            export_name: "x".into(),
        },
        EsmLoaderError::AmbiguousExport {
            specifier: "./a.js".into(),
            export_name: "x".into(),
        },
        EsmLoaderError::EvaluationFailed {
            specifier: "./a.js".into(),
            reason: "boom".into(),
        },
        EsmLoaderError::InvalidStatus {
            specifier: "./a.js".into(),
            expected: "linked",
            actual: "unlinked".into(),
        },
    ];

    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        assert!(!json.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn link_and_evaluate_deterministic_across_runs() {
    for _ in 0..3 {
        let mut g = ModuleGraph::new();

        let mut a = esm("./a.js", "");
        a.add_import(ImportEntry::new("./b.js", "x", "x"));
        a.add_import(ImportEntry::new("./c.js", "y", "y"));
        let b = esm("./b.js", "");
        let c = esm("./c.js", "");

        g.add_module(a).unwrap();
        g.add_module(b).unwrap();
        g.add_module(c).unwrap();

        let link_result = g.link().unwrap();
        assert_eq!(link_result.linked_count, 3);

        let eval_result = g.evaluate().unwrap();
        // Order should be deterministic due to BTreeMap/BTreeSet
        assert_eq!(eval_result.eval_order, vec!["./b.js", "./c.js", "./a.js"]);
    }
}

// ---------------------------------------------------------------------------
// Full pipeline: add -> link -> evaluate -> resolve
// ---------------------------------------------------------------------------

#[test]
fn full_pipeline_three_modules() {
    let mut g = ModuleGraph::new();

    let mut main = esm("./main.js", "import { render } from './lib.js'");
    main.add_import(ImportEntry::new("./lib.js", "render", "render"));

    let mut lib = esm(
        "./lib.js",
        "import { h } from './vdom.js'; export function render() {}",
    );
    lib.add_import(ImportEntry::new("./vdom.js", "h", "h"));
    lib.add_export(ExportEntry::direct("render", "render"));

    let mut vdom = esm("./vdom.js", "export function h() {}");
    vdom.add_export(ExportEntry::direct("h", "h"));

    g.add_module(main).unwrap();
    g.add_module(lib).unwrap();
    g.add_module(vdom).unwrap();

    // Link
    let link_result = g.link().unwrap();
    assert_eq!(link_result.linked_count, 3);
    assert_eq!(link_result.cycle_count, 0);

    // Evaluate
    let eval_result = g.evaluate().unwrap();
    assert_eq!(eval_result.evaluated_count, 3);
    // vdom first, then lib, then main
    assert_eq!(
        eval_result.eval_order,
        vec!["./vdom.js", "./lib.js", "./main.js"]
    );

    // Resolve export
    let binding = g.resolve_export("./lib.js", "render").unwrap();
    assert_eq!(binding.local_name, "render");
    assert_eq!(binding.binding_type, BindingType::Direct);

    // Transitive deps
    let deps = g.transitive_dependencies("./main.js");
    assert!(deps.contains("./lib.js"));
    assert!(deps.contains("./vdom.js"));
}
